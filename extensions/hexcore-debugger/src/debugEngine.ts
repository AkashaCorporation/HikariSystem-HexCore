/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Debug Engine
 *  Emulation-based debugger using Unicorn engine with PE/ELF loading
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import { UnicornWrapper, ArchitectureType, EmulationState } from './unicornWrapper';
import { MemoryManager } from './memoryManager';
import { PELoader, PEInfo } from './peLoader';
import { ELFLoader, ELFInfo } from './elfLoader';
import { WinApiHooks, ApiCallLog } from './winApiHooks';
import { LinuxApiHooks, ApiCallLog as LinuxApiCallLog } from './linuxApiHooks';
import { TraceManager } from './traceManager';

export interface RegisterState {
	rax: bigint;
	rbx: bigint;
	rcx: bigint;
	rdx: bigint;
	rsi: bigint;
	rdi: bigint;
	rbp: bigint;
	rsp: bigint;
	r8: bigint;
	r9: bigint;
	r10: bigint;
	r11: bigint;
	r12: bigint;
	r13: bigint;
	r14: bigint;
	r15: bigint;
	rip: bigint;
	rflags: bigint;
}

export interface MemoryRegion {
	address: bigint;
	size: number;
	permissions: string;
	name?: string;
}

export class DebugEngine {
	private targetPath?: string;
	private isRunning: boolean = false;
	private registers: Partial<RegisterState> = {};
	private listeners: Array<(event: string, data?: any) => void> = [];

	// Emulation components
	private emulator?: UnicornWrapper;
	private memoryManager?: MemoryManager;
	private peLoader?: PELoader;
	private elfLoader?: ELFLoader;
	private apiHooks?: WinApiHooks;
	private linuxApiHooks?: LinuxApiHooks;
	private emulationInitError?: string;
	private architecture: ArchitectureType = 'x64';
	private baseAddress: bigint = 0x400000n;
	private fileBuffer?: Buffer;
	private fileType: 'pe' | 'elf' | 'raw' = 'raw';

	// Centralized API/libc call trace manager
	private _traceManager: TraceManager = new TraceManager();

	// ARM64 mmap offset tracker for syscall-based memory allocation
	private _arm64MmapOffset: number = 0;
	// ARM64 full register set (extended data for UI beyond x86 mapping)
	private _arm64Registers: any = null;
	// Captured stdout from ARM64 direct syscalls (static binaries without PLT)
	private _arm64StdoutBuffer: string = '';
	// Tracks whether an ARM64 exit syscall was dispatched (for terminal detection)
	private _arm64ExitRequested: boolean = false;
	// ARM64 direct syscall call log (for headless output; not routed through linuxApiHooks)
	private _arm64SyscallLog: ApiCallLog[] = [];
	// ARM64 stdin buffer for read(2) syscall emulation
	private _arm64StdinBuffer: string = '';
	private _arm64StdinOffset: number = 0;

	async getEmulationAvailability(arch: ArchitectureType): Promise<{ available: boolean; error?: string }> {
		if (!this.emulator) {
			this.emulator = new UnicornWrapper();
		}

		try {
			await this.emulator.initialize(arch);
			this.emulationInitError = undefined;
			return { available: true };
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			this.emulationInitError = message;
			return { available: false, error: message };
		}
	}

	/**
	 * Start emulation for a binary file
	 */
	async startEmulation(filePath: string, arch?: ArchitectureType): Promise<void> {
		this.targetPath = filePath;

		// Reset ARM64 state for fresh emulation
		this._arm64ExitRequested = false;
		this._arm64SyscallLog = [];
		this._arm64StdoutBuffer = '';
		this._arm64StdinBuffer = '';
		this._arm64StdinOffset = 0;
		this._arm64MmapOffset = 0;

		// Clear trace for fresh emulation session
		this._traceManager.clear();

		// Read the file
		this.fileBuffer = fs.readFileSync(filePath);

		// Detect architecture if not specified
		this.architecture = arch || this.detectArchitecture();

		// Initialize emulator
		if (!this.emulator) {
			this.emulator = new UnicornWrapper();
		}

		try {
			await this.emulator.initialize(this.architecture);
			this.emulationInitError = undefined;
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			this.emulationInitError = message;
			throw new Error(message);
		}

		// Create memory manager with callback to the emulator
		this.memoryManager = new MemoryManager(
			(address, size, perms) => { this.emulator!.mapMemoryRaw(address, size, perms); },
			this.emulator.getPageSize()
		);

		// Set up memory fault handler for tracking.
		// The native InvalidMemHookCB auto-maps memory on the Unicorn thread.
		// This JS callback runs asynchronously for allocation tracking only.
		this.emulator.setMemoryFaultHandler((_type, address, size, _value) => {
			if (this.memoryManager) {
				const pageSize = BigInt(this.emulator!.getPageSize());
				const alignedAddr = (address / pageSize) * pageSize;
				const neededSize = Number(address - alignedAddr) + size;
				const alignedSize = Math.ceil(neededSize / Number(pageSize)) * Number(pageSize) || Number(pageSize);
				this.memoryManager.trackAllocation(alignedAddr, alignedSize, 7, 'fault-mapped');
			}
			return true;
		});

		// Detect file type and load accordingly
		this.fileType = this.detectFileType();

		if (this.fileType === 'pe') {
			await this.loadPE();
		} else if (this.fileType === 'elf') {
			await this.loadELF();
		} else {
			await this.loadRawBinary();
		}

		this.isRunning = true;
		this.emit('emulation-started', {
			entryPoint: this.baseAddress,
			architecture: this.architecture,
			fileType: this.fileType
		});

		console.log(`Emulation ready: ${this.architecture}, type=${this.fileType}`);
	}

	/**
	 * Load a PE file with full section mapping and import resolution
	 */
	private async loadPE(): Promise<void> {
		this.peLoader = new PELoader(this.emulator!, this.memoryManager!);
		const peInfo = this.peLoader.load(this.fileBuffer!, this.architecture);

		this.baseAddress = peInfo.entryPoint;

		// Create API hooks for Windows PE
		this.apiHooks = new WinApiHooks(this.emulator!, this.memoryManager!, this.architecture);
		this.apiHooks.setImageBase(peInfo.imageBase);
		this.apiHooks.setTraceManager(this._traceManager);

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		await this.emulator!.setupStack(stackBase);
		await this.setupArm64Stack();

		// Install API call interceptor via code hook
		this.installApiInterceptor();

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		await this.emulator!.setRegister(ipReg, peInfo.entryPoint);
		this.emulator!.setCurrentAddress(peInfo.entryPoint);

		// Activate PE32 worker mode to isolate emuStart from Extension Host heap.
		// This prevents STATUS_HEAP_CORRUPTION from Unicorn's JIT backend (TCG).
		// Follows the same pattern as setElfSyncMode in loadELF.
		if (this.architecture === 'x64' || this.architecture === 'x86') {
			const PE_STUB_BASE = 0x70000000n;
			const PE_STUB_END = PE_STUB_BASE + 0x100000n;

			await this.emulator!.setPe32WorkerMode(PE_STUB_BASE, PE_STUB_END, async (stubAddress: bigint) => {
				// Worker hit a WinAPI stub — dispatch on the host side.
				const importEntry = this.peLoader!.lookupStub(stubAddress);
				if (!importEntry) {
					return null;
				}

				const isX64 = this.architecture === 'x64';
				const emulator = this.emulator!;

				// Sync registers from worker → in-process Unicorn so
				// WinApiHooks.readArguments() (which uses getRegistersX64/X86
				// and readMemorySync) sees correct values.
				try {
					if (isX64) {
						const wr = await emulator.getRegistersX64Async();
						emulator.setRegisterSync('rax', wr.rax);
						emulator.setRegisterSync('rbx', wr.rbx);
						emulator.setRegisterSync('rcx', wr.rcx);
						emulator.setRegisterSync('rdx', wr.rdx);
						emulator.setRegisterSync('rsi', wr.rsi);
						emulator.setRegisterSync('rdi', wr.rdi);
						emulator.setRegisterSync('rbp', wr.rbp);
						emulator.setRegisterSync('rsp', wr.rsp);
						emulator.setRegisterSync('r8', wr.r8);
						emulator.setRegisterSync('r9', wr.r9);
						emulator.setRegisterSync('r10', wr.r10);
						emulator.setRegisterSync('r11', wr.r11);
						emulator.setRegisterSync('r12', wr.r12);
						emulator.setRegisterSync('r13', wr.r13);
						emulator.setRegisterSync('r14', wr.r14);
						emulator.setRegisterSync('r15', wr.r15);
						emulator.setRegisterSync('rip', wr.rip);
						emulator.setRegisterSync('rflags', wr.rflags);
					} else {
						const wr = await emulator.getRegistersX86Async();
						emulator.setRegisterSync('eax', wr.eax);
						emulator.setRegisterSync('ebx', wr.ebx);
						emulator.setRegisterSync('ecx', wr.ecx);
						emulator.setRegisterSync('edx', wr.edx);
						emulator.setRegisterSync('esi', wr.esi);
						emulator.setRegisterSync('edi', wr.edi);
						emulator.setRegisterSync('ebp', wr.ebp);
						emulator.setRegisterSync('esp', wr.esp);
						emulator.setRegisterSync('eip', wr.eip);
						emulator.setRegisterSync('eflags', wr.eflags);
					}
				} catch {
					// Best-effort register sync
				}

				// Sync stack memory from worker → in-process Unicorn so
				// stack-based argument reads work correctly.
				try {
					const sp = isX64
						? emulator.getRegistersX64().rsp
						: BigInt(emulator.getRegistersX86().esp);
					// Sync 256 bytes around the stack pointer (covers typical args)
					const syncBase = sp - 64n;
					const stackData = await emulator.readMemory(syncBase, 256);
					emulator.writeMemorySync(syncBase, stackData);
				} catch {
					// Best-effort stack sync
				}

				// Read return address from top of stack (pushed by CALL instruction).
				// The worker stopped AT the stub address, before executing it.
				let returnAddress: bigint;
				try {
					if (isX64) {
						const rsp = emulator.getRegistersX64().rsp;
						const retBuf = emulator.readMemorySync(rsp, 8);
						returnAddress = retBuf.readBigUInt64LE();
					} else {
						const esp = BigInt(emulator.getRegistersX86().esp);
						const retBuf = emulator.readMemorySync(esp, 4);
						returnAddress = BigInt(retBuf.readUInt32LE());
					}
				} catch {
					// Cannot read return address — abort dispatch
					return null;
				}

				// handleCall reads args from in-process Unicorn (now synced)
				const returnValue = this.apiHooks!.handleCall(importEntry.dll, importEntry.name);

				this.emit('api-call', {
					dll: importEntry.dll,
					name: importEntry.name,
					returnValue
				});

				// Pop return address: adjust RSP/ESP in the worker (add pointer size)
				try {
					if (isX64) {
						const rsp = emulator.getRegistersX64().rsp;
						await emulator.setRegister('rsp', rsp + 8n);
					} else {
						const esp = BigInt(emulator.getRegistersX86().esp);
						await emulator.setRegister('esp', esp + 4n);
					}
				} catch {
					// Best-effort RSP/ESP adjustment
				}

				return { returnValue, newPc: returnAddress };
			});
		}

		this.emit('pe-loaded', {
			imageBase: peInfo.imageBase,
			entryPoint: peInfo.entryPoint,
			sections: peInfo.sections.length,
			imports: peInfo.imports.length
		});

		console.log(`PE loaded: entry=0x${peInfo.entryPoint.toString(16)}, ${peInfo.sections.length} sections, ${peInfo.imports.length} imports`);
	}

	/**
	 * Load an ELF file with PLT stub creation and Linux API hooks
	 */
	private async loadELF(): Promise<void> {
		this.elfLoader = new ELFLoader(this.emulator!, this.memoryManager!);
		const elfInfo = this.elfLoader.load(this.fileBuffer!, this.architecture);

		this.baseAddress = elfInfo.entryPoint;

		// Create Linux API hooks
		this.linuxApiHooks = new LinuxApiHooks(this.emulator!, this.memoryManager!, this.architecture);
		this.linuxApiHooks.setImageBase(elfInfo.baseAddress);
		this.linuxApiHooks.setTraceManager(this._traceManager);
		const exitImport = elfInfo.imports.find(imp => imp.name === 'exit' || imp.name === '_exit');
		this.linuxApiHooks.setMainReturnAddress(exitImport?.stubAddress ?? null);

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		await this.emulator!.setupStack(stackBase);
		await this.setupArm64Stack();
		await this.initializeElfProcessStack();

		// Setup TLS (Thread Local Storage) region for fs:[0x28] stack canary access.
		await this.setupLinuxTLS();

		// Install ELF API interceptor (PLT stubs → libc hooks)
		this.installELFApiInterceptor();

		// Install syscall handler for direct syscalls
		this.installSyscallHandler();

		// Enable synchronous execution for x64/x86 ELF to avoid
		// STATUS_HEAP_CORRUPTION from emuStartAsync with multiple native hooks.
		// setElfSyncMode is now async: it starts the X64ElfWorkerClient and
		// migrates all memory regions and registers to the worker process.
		if (this.architecture === 'x64' || this.architecture === 'x86') {
			await this.emulator!.setElfSyncMode(true);
		}

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		await this.emulator!.setRegister(ipReg, elfInfo.entryPoint);
		this.emulator!.setCurrentAddress(elfInfo.entryPoint);

		this.emit('elf-loaded', {
			entryPoint: elfInfo.entryPoint,
			baseAddress: elfInfo.baseAddress,
			isPIE: elfInfo.isPIE,
			segments: elfInfo.programHeaders.length,
			imports: elfInfo.imports.length
		});

		console.log(`ELF loaded: entry=0x${elfInfo.entryPoint.toString(16)}, PIE=${elfInfo.isPIE}, ${elfInfo.imports.length} imports`);
	}

	/**
	 * Load a raw binary (shellcode, firmware, etc.)
	 */
	private async loadRawBinary(): Promise<void> {
		const loadBase = 0x400000n;
		await this.emulator!.loadCode(this.fileBuffer!, loadBase);
		this.baseAddress = loadBase;

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		await this.emulator!.setupStack(stackBase);
		await this.setupArm64Stack();

		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		await this.emulator!.setRegister(ipReg, loadBase);
		this.emulator!.setCurrentAddress(loadBase);
	}

	/**
	 * Configure ARM64-specific stack semantics after the base stack is mapped.
	 * ARM64 doesn't push return addresses to the stack — it uses the Link Register (X30/LR).
	 * Set LR to a sentinel value so a RET at the end of main stops emulation.
	 * Also ensure SP is 16-byte aligned as required by the AAPCS64 ABI.
	 */
	private async setupArm64Stack(): Promise<void> {
		if (!this.emulator || this.architecture !== 'arm64') {
			return;
		}

		try {
			// Set LR (X30) to sentinel return address so RET stops emulation
			await this.emulator.setRegister('lr', 0xDEAD0000n);

			// Read current SP and ensure 16-byte alignment (AAPCS64 requirement)
			const regs = await this.emulator.getRegistersArm64();
			const alignedSp = (regs.sp / 16n) * 16n;
			if (alignedSp !== regs.sp) {
				await this.emulator.setRegister('sp', alignedSp);
			}

			console.log(`ARM64 stack configured: LR=0xDEAD0000, SP=0x${alignedSp.toString(16)}`);
		} catch (e) {
			console.warn(`Failed to setup ARM64 stack: ${e}`);
		}
	}

	/**
	 * Setup Linux TLS (Thread Local Storage) region.
	 * On Linux x64, the FS segment register base points to the TLS block.
	 * fs:[0x28] holds the stack canary value used by GCC's -fstack-protector.
	 * Without this, any binary compiled with stack protection will crash on
	 * `mov rax, [fs:0x28]`.
	 */
	private async setupLinuxTLS(): Promise<void> {
		if (!this.emulator || !this.memoryManager) {
			return;
		}

		// Keep TLS below the default stack mapping (0x7FFF0000..0x800F0000).
		const TLS_BASE = 0x7FFEF000n;
		const TLS_SIZE = 0x1000;         // 4KB

		try {
			// Map TLS region as RW if it is not already mapped.
			try {
				await this.emulator.mapMemoryRaw(TLS_BASE, TLS_SIZE, 3); // PROT_READ | PROT_WRITE
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				// If the region is already mapped, we can still write the canary and set FS base.
				if (!/UC_ERR_MAP/.test(message)) {
					throw error;
				}
			}
			this.memoryManager.trackAllocation(TLS_BASE, TLS_SIZE, 3, 'tls');

			// Write stack canary at offset 0x28 (fs:[0x28])
			// Use a deterministic value for reproducible emulation
			const tls = Buffer.alloc(TLS_SIZE);
			if (this.architecture === 'x64') {
				tls.writeBigUInt64LE(0xDEADBEEFCAFEBABEn, 0x28); // stack canary
				// Self-pointer at offset 0x0 (some glibc versions expect this)
				tls.writeBigUInt64LE(TLS_BASE, 0x0);
			} else {
				tls.writeUInt32LE(0xDEADBEEF, 0x14); // x86 stack canary at gs:[0x14]
				tls.writeUInt32LE(Number(TLS_BASE & 0xFFFFFFFFn), 0x0);
			}

			await this.emulator.writeMemory(TLS_BASE, tls);

			// Set FS_BASE to point to TLS region
			if (this.architecture === 'x64') {
				await this.emulator.setRegister('fs_base', TLS_BASE);
			}

			console.log(`Linux TLS setup: base=0x${TLS_BASE.toString(16)}, canary at fs:[0x28]`);
		} catch (e) {
			console.warn(`Failed to setup Linux TLS: ${e}`);
		}
	}

	/**
	 * Build a minimal Linux process stack layout for ELF startup.
	 * _start expects: [argc][argv0][NULL][envp...]
	 */
	private async initializeElfProcessStack(): Promise<void> {
		if (!this.emulator) {
			return;
		}

		try {
			if (this.architecture === 'arm64') {
				// ARM64 ELF ABI: argc in X0, argv pointer in X1, envp pointer in X2
				// argv array and strings are still on the stack, but argc is passed via register
				const regs = await this.emulator.getRegistersArm64();
				let stackPtr = regs.sp - 0x80n;
				stackPtr = (stackPtr / 16n) * 16n; // 16-byte alignment (AAPCS64)

				// Write argv[0] string on the stack
				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x40n;
				await this.emulator.writeMemory(argv0Addr, argv0);

				// Build argv array on stack: [argv0_ptr, NULL]
				const argvArray = Buffer.alloc(16);
				argvArray.writeBigUInt64LE(argv0Addr, 0);  // argv[0]
				argvArray.writeBigUInt64LE(0n, 8);          // argv[1] = NULL (terminator)
				const argvAddr = stackPtr;
				await this.emulator.writeMemory(argvAddr, argvArray);

				// envp array on stack: [NULL]
				const envpArray = Buffer.alloc(8);
				envpArray.writeBigUInt64LE(0n, 0);          // envp[0] = NULL
				const envpAddr = stackPtr + 16n;
				await this.emulator.writeMemory(envpAddr, envpArray);

				// Set registers: X0 = argc, X1 = argv, X2 = envp
				await this.emulator.setRegister('x0', 1n);
				await this.emulator.setRegister('x1', argvAddr);
				await this.emulator.setRegister('x2', envpAddr);

				// Update SP
				await this.emulator.setRegister('sp', stackPtr - 0x40n);
				return;
			}

			if (this.architecture === 'x64') {
				const regs = this.emulator.getRegistersX64();
				let stackPtr = regs.rsp - 0x80n;
				stackPtr = (stackPtr / 16n) * 16n;

				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x40n;
				await this.emulator.writeMemory(argv0Addr, argv0);

				const layout = Buffer.alloc(32);
				layout.writeBigUInt64LE(1n, 0);      // argc
				layout.writeBigUInt64LE(argv0Addr, 8);  // argv[0]
				layout.writeBigUInt64LE(0n, 16);     // argv[1] = NULL
				layout.writeBigUInt64LE(0n, 24);     // envp = NULL
				await this.emulator.writeMemory(stackPtr, layout);
				await this.emulator.setRegister('rsp', stackPtr);
				return;
			}

			if (this.architecture === 'x86') {
				const regs = this.emulator.getRegistersX86();
				const stackPtr = BigInt(regs.esp - 0x60);
				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x20n;
				await this.emulator.writeMemory(argv0Addr, argv0);

				const layout = Buffer.alloc(16);
				layout.writeUInt32LE(1, 0); // argc
				layout.writeUInt32LE(Number(argv0Addr & 0xFFFFFFFFn), 4);
				layout.writeUInt32LE(0, 8); // argv[1] = NULL
				layout.writeUInt32LE(0, 12); // envp = NULL
				await this.emulator.writeMemory(stackPtr, layout);
				await this.emulator.setRegister('esp', Number(stackPtr & 0xFFFFFFFFn));
			}
		} catch (error: unknown) {
			const message = error instanceof Error ? error.message : String(error);
			console.warn(`[elf] Failed to initialize process stack: ${message}`);
		}
	}

	/**
	 * Install a code hook that intercepts API calls to stub addresses
	 */
	private installApiInterceptor(): void {
		if (!this.emulator || !this.peLoader || !this.apiHooks) {
			return;
		}

		this.emulator.onCodeExecute((address, _size) => {
			try {
				if (!this.peLoader!.isStubAddress(address)) {
					return;
				}

				// This address is in the API stub region - it's an API call
				const importEntry = this.peLoader!.lookupStub(address);
				if (!importEntry) {
					return;
				}

				// Handle the API call
				const returnValue = this.apiHooks!.handleCall(importEntry.dll, importEntry.name);

				// Set return value
				if (this.architecture === 'x64') {
					this.emulator!.setRegisterSync('rax', returnValue);
				} else {
					this.emulator!.setRegisterSync('eax', returnValue);
				}

				// Unicorn callback in this binding runs after the stub instruction executes.
				// For RET-based stubs, RIP/RSP are already advanced by Unicorn.
				// We only need to stop and apply queued register updates.
				this.emulator!.notifyApiRedirect();

				// Emit API call event for the UI
				this.emit('api-call', {
					dll: importEntry.dll,
					name: importEntry.name,
					returnValue
				});
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				console.warn(`[debugEngine] PE API hook failed at 0x${address.toString(16)}: ${message}`);
			}
		});
	}

	/**
	 * Install a code hook that intercepts ELF PLT stub calls via the ELF loader
	 */
	private installELFApiInterceptor(): void {
		if (!this.emulator || !this.elfLoader || !this.linuxApiHooks) {
			return;
		}

		this.emulator.onCodeExecute((address, _size) => {
			try {
				if (!this.elfLoader!.isStubAddress(address)) {
					return;
				}

				// This address is in the API stub region - it's a libc call
				const importEntry = this.elfLoader!.lookupStub(address);
				if (!importEntry) {
					return;
				}

				// Handle the libc call
				const returnValue = this.linuxApiHooks!.handleCall(importEntry.library, importEntry.name);
				const callName = importEntry.name.toLowerCase();
				const isTerminatingCall = callName === 'exit' || callName === '_exit' || callName === 'abort';

				if (!isTerminatingCall) {
					// Set return value in RAX (System V AMD64 ABI)
					if (this.architecture === 'x64') {
						this.emulator!.setRegisterSync('rax', returnValue);
					} else {
						this.emulator!.setRegisterSync('eax', returnValue);
					}
				}

				const redirectAddr = this.linuxApiHooks!.getRedirectAddress();
				if (!isTerminatingCall && redirectAddr !== null) {
					// Redirect execution to the handler-provided target (e.g. main()).
					// Keep caller return address on stack so the redirected function can return.
					if (this.architecture === 'x64') {
						this.emulator!.setRegisterSync('rip', redirectAddr);
						this.emulator!.setCurrentAddress(redirectAddr);
					} else {
						this.emulator!.setRegisterSync('eip', redirectAddr);
						this.emulator!.setCurrentAddress(redirectAddr);
					}
				} else if (!isTerminatingCall) {
					// Normal return. Because the manual loop stops BEFORE executing
					// the STUB_BASE instruction (the RET), we must manually simulate it.
					this.popReturnAddressSync();
				}

				// Stop current run and apply queued state changes before continuing.
				this.emulator!.notifyApiRedirect();

				// Emit API call event for the UI
				this.emit('api-call', {
					dll: importEntry.library,
					name: importEntry.name,
					returnValue
				});
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				console.warn(`[debugEngine] ELF API hook failed at 0x${address.toString(16)}: ${message}`);
			}
		});
	}

	/**
	 * Install interrupt handler for Linux syscalls (int 0x80 / syscall instruction)
	 */
	private installSyscallHandler(): void {
		if (!this.emulator || !this.linuxApiHooks) {
			return;
		}

		// For ARM64: install an async interrupt handler that can await
		// register reads/writes on the worker process.
		if (this.architecture === 'arm64') {
			this.emulator.setAsyncInterruptHandler(async (intno: number) => {
				if (intno === 2) {
					const regs = await this.emulator!.getRegistersArm64();
					const syscallNum = Number(regs.x8);
					const args = [regs.x0, regs.x1, regs.x2, regs.x3, regs.x4, regs.x5];

					const result = await this.dispatchArm64Syscall(syscallNum, args);

					await this.emulator!.setRegister('x0', result);

					this.emit('api-call', {
						dll: 'syscall',
						name: `sys_${syscallNum}`,
						returnValue: result
					});
				}
			});
			// Also set a sync handler as fallback (for in-process ARM64 path)
			this.emulator.setInterruptHandler((intno: number) => {
				// This path is used by startArm64Sync (in-process fallback)
				if (intno === 2) {
					// In sync mode, getRegistersArm64 returns a Promise but
					// the sync path (startArm64Sync) handles SVC directly.
					// This should not be reached in worker mode.
					console.warn('[debugEngine] Sync interrupt handler called for ARM64');
				}
			});
			return;
		}

		// For x64/x86 ELF with worker: install async interrupt handler
		// that reads/writes registers via IPC to the worker process.
		this.emulator.setAsyncInterruptHandler(async (intno: number) => {
			if (intno === 0x80 || intno === 2) {
				const result = this.linuxApiHooks!.handleSyscall();

				if (this.architecture === 'x64') {
					await this.emulator!.setRegister('rax', result);
				} else {
					await this.emulator!.setRegister('eax', result);
				}

				const regs = await this.emulator!.getRegistersX64Async();
				const sysNum = regs ? Number(regs.rax) : 0;

				this.emit('api-call', {
					dll: 'syscall',
					name: `sys_${sysNum}`,
					returnValue: result
				});
			}
		});

		// Sync handler as fallback (for non-worker paths like PE x86/x64)
		this.emulator.setInterruptHandler((intno: number) => {
			// int 0x80 on x86 or SYSCALL instruction generates interrupt 2 in Unicorn
			if (intno === 0x80 || intno === 2) {
				const result = this.linuxApiHooks!.handleSyscall();

				// Set return value in RAX
				if (this.architecture === 'x64') {
					this.emulator!.setRegisterSync('rax', result);
				} else {
					this.emulator!.setRegisterSync('eax', result);
				}

				// Emit syscall event for the UI
				const regs = this.architecture === 'x64'
					? this.emulator!.getRegistersX64()
					: null;
				const sysNum = regs ? Number(regs.rax) : 0;

				this.emit('api-call', {
					dll: 'syscall',
					name: `sys_${sysNum}`,
					returnValue: result
				});
			}
		});
	}

	/**
	 * Dispatch an ARM64 Linux syscall by number.
	 * ARM64 syscall numbers differ from x86/x64.
	 * Reference: https://arm64.syscall.sh/
	 */
	private async dispatchArm64Syscall(syscallNum: number, args: bigint[]): Promise<bigint> {
		const result = await this.dispatchArm64SyscallInner(syscallNum, args);

		// Log the syscall for headless output and terminal detection
		this._arm64SyscallLog.push({
			dll: 'syscall',
			name: `sys_${syscallNum}`,
			args,
			returnValue: result,
			timestamp: Date.now(),
			arguments: args.map(a => '0x' + a.toString(16)),
			pcAddress: 0n,
		});

		// Record in centralized TraceManager
		this._traceManager.record({
			functionName: `sys_${syscallNum}`,
			library: 'syscall',
			arguments: args.map(a => '0x' + a.toString(16)),
			returnValue: '0x' + result.toString(16),
			pcAddress: '0x0',
			timestamp: Date.now(),
		});

		return result;
	}

	private async dispatchArm64SyscallInner(syscallNum: number, args: bigint[]): Promise<bigint> {
		switch (syscallNum) {
			case 56: // openat
				return 3n; // Return a dummy fd
			case 57: // close
				return 0n;
			case 63: { // read(fd, buf, count)
				const fd = Number(args[0]);
				const bufAddr = args[1];
				const count = Number(args[2]);
				// Only serve stdin (fd 0) from the buffer
				if (fd === 0 && count > 0 && count < 0x10000 && this._arm64StdinBuffer.length > this._arm64StdinOffset) {
					const remaining = this._arm64StdinBuffer.slice(this._arm64StdinOffset);
					const toRead = remaining.slice(0, count);
					const data = Buffer.from(toRead, 'utf8');
					const bytesRead = Math.min(data.length, count);
					try {
						await this.emulator!.writeMemory(bufAddr, data.subarray(0, bytesRead));
						this._arm64StdinOffset += toRead.length;
						return BigInt(bytesRead);
					} catch {
						return BigInt(-14); // -EFAULT
					}
				}
				return 0n; // EOF
			}
			case 64: { // write(fd, buf, count)
				const count = Number(args[2]);
				if (count > 0 && count < 0x10000) {
					try {
						const data = await this.emulator!.readMemory(args[1], count);
						const fd = Number(args[0]);
						const str = (data as Buffer).toString('utf8');
						console.log(`[arm64 syscall write fd${fd}] ${str}`);
						if (fd === 1 || fd === 2) {
							this._arm64StdoutBuffer += str;
						}
						return BigInt(count);
					} catch {
						return BigInt(-14); // -EFAULT
					}
				}
				return 0n;
			}
			case 93: // exit
				console.log(`[arm64 syscall exit] code=${Number(args[0])}`);
				this._arm64ExitRequested = true;
				this.emulator!.stop();
				return 0n;
			case 94: // exit_group
				console.log(`[arm64 syscall exit_group] code=${Number(args[0])}`);
				this._arm64ExitRequested = true;
				this.emulator!.stop();
				return 0n;
			case 96: // set_tid_address
				return 0x1000n;
			case 98: // futex
				return 0n;
			case 113: // clock_gettime
				return 0n;
			case 124: // sched_yield
				return 0n;
			case 131: // tgkill
				return 0n;
			case 160: // uname
				return 0n;
			case 172: // getpid
				return 0x1000n;
			case 174: // getuid
				return 1000n;
			case 175: // geteuid
				return 1000n;
			case 176: // getgid
				return 1000n;
			case 177: // getegid
				return 1000n;
			case 214: { // brk
				return 0x06000000n; // Return end of heap
			}
			case 215: // munmap
				return 0n;
			case 222: { // mmap
				const length = Number(args[1]);
				const prot = Number(args[2]);
				if (length > 0 && length < 0x10000000 && this.memoryManager) {
					let ucProt = 0;
					if (prot & 1) { ucProt |= 1; } // PROT_READ
					if (prot & 2) { ucProt |= 2; } // PROT_WRITE
					if (prot & 4) { ucProt |= 4; } // PROT_EXEC
					const addr = 0x20000000n + BigInt(this._arm64MmapOffset);
					const pageSize = BigInt(this.emulator!.getPageSize());
					const alignedSize = ((BigInt(length) + pageSize - 1n) / pageSize) * pageSize;
					try {
						this.emulator!.mapMemoryRaw(addr, Number(alignedSize), ucProt || 1);
						this.memoryManager.trackAllocation(addr, Number(alignedSize), ucProt || 1, 'mmap-arm64');
						this._arm64MmapOffset += Number(alignedSize);
						return addr;
					} catch {
						return BigInt(-12); // -ENOMEM
					}
				}
				return BigInt(-12);
			}
			case 226: // mprotect
				return 0n;
			default:
				console.log(`[arm64 syscall] Unhandled syscall ${syscallNum}`);
				return BigInt(-38); // -ENOSYS
		}
	}

	/**
	 * Pop the return address from the stack and set the instruction pointer
	 */
	private async popReturnAddress(): Promise<void> {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'arm64') {
			// ARM64: Return address is in LR (X30), not on the stack
			const regs = await this.emulator.getRegistersArm64();
			const retAddr = regs.lr; // X30 = Link Register
			await this.emulator.setRegister('pc', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		} else if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			const memBuf = await this.emulator.readMemory(regs.rsp, 8);
			const retAddr = memBuf.readBigUInt64LE();

			// Detect if reached via CALL or JMP (tail call)
			let isCall = false;
			try {
				// Check for CALL rel32 (E8 xx xx xx xx)
				const buf5 = await this.emulator.readMemory(retAddr - 5n, 5);
				if (buf5[0] === 0xE8) isCall = true;

				// Check for CALL r/m64 (FF 15 xx xx xx xx) (CALL [RIP+disp32])
				const buf6 = await this.emulator.readMemory(retAddr - 6n, 6);
				if (buf6[0] === 0xFF && buf6[1] === 0x15) isCall = true;

				// Check for CALL reg (FF D0-D7)
				const buf2 = await this.emulator.readMemory(retAddr - 2n, 2);
				if (buf2[0] === 0xFF && buf2[1] >= 0xD0 && buf2[1] <= 0xD7) isCall = true;
			} catch {
				// Memory unreadable, assume CALL to be safe?
				// Actually, tail calls are less common, so default to true if we can't read.
				isCall = true;
			}

			if (isCall) {
				await this.emulator.setRegister('rsp', regs.rsp + 8n);
				await this.emulator.setRegister('rip', retAddr);
				this.emulator.setCurrentAddress(retAddr);
			} else {
				// It's a tail call (JMP). The stack top is the return address of the *caller*.
				// But we are returning from the stub NOW, so we must go to that address.
				// Oh wait! If it's a JMP, the stub ITSELF should jump to retAddr and pop.
				// Wait, if it's a JMP to the stub, the stub *is* the function. The return address
				// is indeed at [rsp], and we MUST pop it and go there to return from the JMP caller!
				// Yes! Whether it was reached via CALL or JMP, we are completing the function
				// execution and we must return to whatever is on top of the stack.
				await this.emulator.setRegister('rsp', regs.rsp + 8n);
				await this.emulator.setRegister('rip', retAddr);
				this.emulator.setCurrentAddress(retAddr);
			}
		} else {
			const regs = this.emulator.getRegistersX86();
			const memBuf = await this.emulator.readMemory(BigInt(regs.esp), 4);
			const retAddr = BigInt(memBuf.readUInt32LE());
			await this.emulator.setRegister('esp', BigInt(regs.esp + 4));
			await this.emulator.setRegister('eip', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		}
	}

	/**
	 * Pop the return address from the stack synchronously.
	 * Required for ELF API interceptions because code hooks run synchronously.
	 */
	private popReturnAddressSync(): void {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'arm64') {
			console.warn('[popReturnAddressSync] ARM64 sync popping is unsupported in worker mode');
		} else if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			const memBuf = this.emulator.readMemorySync(regs.rsp, 8);
			const retAddr = memBuf.readBigUInt64LE();

			// Detect if reached via CALL or JMP
			let isCall = false;
			try {
				const buf5 = this.emulator.readMemorySync(retAddr - 5n, 5);
				if (buf5[0] === 0xE8) isCall = true; // CALL rel32

				const buf6 = this.emulator.readMemorySync(retAddr - 6n, 6);
				if (buf6[0] === 0xFF && buf6[1] === 0x15) isCall = true; // CALL r/m64

				const buf2 = this.emulator.readMemorySync(retAddr - 2n, 2);
				if (buf2[0] === 0xFF && buf2[1] >= 0xD0 && buf2[1] <= 0xD7) isCall = true; // CALL reg
			} catch {
				isCall = true;
			}

			if (isCall) {
				// Normal call: pop the return address
				this.emulator.setRegisterSync('rsp', regs.rsp + 8n);
				this.emulator.setRegisterSync('rip', retAddr);
				this.emulator.setCurrentAddress(retAddr);
			} else {
				// Tail call (JMP) or PLT trampoline.
				// In a tail call, the stack pointer already points to the caller's return address.
				// So we pop it and jump to it!
				// Wait! If `puts` is called via JMP, then `main` called `sub_x` (pushed retAddr_main),
				// and `sub_x` JMPs to `puts`. `puts` finishes and returns to `main`.
				// SO WE MUST POP IT!
				// The only exception is if the *trampoline* (PLT) itself pushed something.
				// In standard ELF, `call puts@plt` pushes retAddr_sub_x. Then PLT does `jmp [got]`.
				// So `retAddr_sub_x` is on top. We pop it.
				// In the user's scenario: `jmp puts@plt`.
				// PLT does `jmp [got]`.
				// Stack top is `retAddr_main`. We pop it and return to main.
				// So popping is ALWAYS correct!
				// What if the user meant that because the hook is called from `installELFApiInterceptor`,
				// maybe the hook modifies RAX and then DOES NOT POP?
				// Well, I added `popReturnAddressSync()` recently.
				// Oh, the user just saw `0x65726f63786568` on the stack.
				// Why is "hexcore" on the stack?
				// Let's implement popping always for x64, but keep the logging.
				this.emulator.setRegisterSync('rsp', regs.rsp + 8n);
				this.emulator.setRegisterSync('rip', retAddr);
				this.emulator.setCurrentAddress(retAddr);
			}
		} else {
			const regs = this.emulator.getRegistersX86();
			const memBuf = this.emulator.readMemorySync(BigInt(regs.esp), 4);
			const retAddr = BigInt(memBuf.readUInt32LE());
			this.emulator.setRegisterSync('esp', BigInt(regs.esp + 4));
			this.emulator.setRegisterSync('eip', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		}
	}

	/**
	 * Detect file type from magic bytes
	 */
	private detectFileType(): 'pe' | 'elf' | 'raw' {
		if (!this.fileBuffer || this.fileBuffer.length < 4) {
			return 'raw';
		}

		if (this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A) {
			return 'pe';
		}

		if (this.fileBuffer[0] === 0x7F && this.fileBuffer.toString('ascii', 1, 4) === 'ELF') {
			return 'elf';
		}

		return 'raw';
	}

	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureType {
		if (!this.fileBuffer) {
			return 'x64';
		}

		// PE file
		if (this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A) {
			const peOffset = this.fileBuffer.readUInt32LE(0x3C);
			if (peOffset + 6 < this.fileBuffer.length) {
				const machine = this.fileBuffer.readUInt16LE(peOffset + 4);
				switch (machine) {
					case 0x014c: return 'x86';
					case 0x8664: return 'x64';
					case 0x01c0: return 'arm';
					case 0xaa64: return 'arm64';
				}
			}
		}

		// ELF file
		if (this.fileBuffer[0] === 0x7F && this.fileBuffer.toString('ascii', 1, 4) === 'ELF') {
			const elfClass = this.fileBuffer[4];
			const machine = this.fileBuffer.readUInt16LE(18);
			switch (machine) {
				case 0x03: return elfClass === 2 ? 'x64' : 'x86';
				case 0x3E: return 'x64';
				case 0x28: return 'arm';
				case 0xB7: return 'arm64';
			}
		}

		return 'x64';
	}

	/**
	 * Step one instruction in emulation mode
	 */
	async emulationStep(): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		await this.emulator.step();
		await this.updateEmulationRegisters();
		this.emit('step');
	}

	/**
	 * Continue emulation until breakpoint or end
	 */
	async emulationContinue(): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		// Unicorn async continue can desync callback address vs register snapshot on
		// some ELF flows. For ELF targets we use deterministic stepped continue.
		if (this.fileType === 'elf') {
			await this.continueElfSafely();
		} else {
			await this.emulator.continue();
		}
		await this.updateEmulationRegisters();
		this.emit('continue');
	}

	/**
	 * Deterministic continue path for ELF binaries.
	 * Executes one instruction at a time so API hooks always observe a coherent
	 * register state, while still honoring breakpoint semantics.
	 */
	private async continueElfSafely(): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		const maxInstructions = 250000;
		const maxStagnantSteps = 5000;
		const breakpoints = new Set(this.emulator.getBreakpoints().map(bp => bp.toString()));

		let firstStep = true;
		let stagnantSteps = 0;
		let currentAddress = await this.getCurrentInstructionPointer();

		for (let step = 0; step < maxInstructions; step++) {
			if (this.isTerminalExecutionAddress(currentAddress)) {
				return;
			}

			// Match continue semantics: if we resumed from a breakpoint, execute one
			// instruction first and only stop on subsequent breakpoint hits.
			if (!firstStep && breakpoints.has(currentAddress.toString())) {
				return;
			}

			try {
				await this.emulator.step();
			} catch (error: unknown) {
				const faultAddress = await this.getCurrentInstructionPointer();
				if (this.isTerminalExecutionAddress(faultAddress) || this.hasTerminalLinuxApiCall()) {
					return;
				}
				throw error;
			}

			const nextAddress = await this.getCurrentInstructionPointer();
			if (this.hasTerminalLinuxApiCall()) {
				return;
			}
			if (this.isTerminalExecutionAddress(nextAddress)) {
				return;
			}

			if (nextAddress === currentAddress) {
				stagnantSteps += 1;
				if (stagnantSteps >= maxStagnantSteps) {
					throw new Error(`Safe ELF continue stalled at 0x${nextAddress.toString(16)}`);
				}
			} else {
				stagnantSteps = 0;
			}

			currentAddress = nextAddress;
			firstStep = false;
		}

		throw new Error(`Safe ELF continue hit instruction budget (${maxInstructions}) at 0x${currentAddress.toString(16)}`);
	}

	private isTerminalExecutionAddress(address: bigint): boolean {
		return address === 0n || address === 0xDEADDEADn || address === 0xDEADDEADDEADDEADn || address === 0xDEAD0000n;
	}

	private async getCurrentInstructionPointer(): Promise<bigint> {
		if (!this.emulator) {
			return 0n;
		}

		try {
			if (this.architecture === 'x64') {
				return this.emulator.getRegistersX64().rip;
			}
			if (this.architecture === 'x86') {
				return BigInt(this.emulator.getRegistersX86().eip);
			}
			if (this.architecture === 'arm64') {
				const regs = await this.emulator.getRegistersArm64();
				return regs.pc;
			}
		} catch {
			// Fallback to wrapper state below.
		}

		return this.emulator.getState().currentAddress;
	}

	private hasTerminalLinuxApiCall(): boolean {
		// ARM64 direct syscalls are tracked separately from linuxApiHooks
		if (this._arm64ExitRequested) {
			return true;
		}

		if (!this.linuxApiHooks) {
			return false;
		}

		const lastCall = this.linuxApiHooks.getLastCall();
		if (!lastCall) {
			return false;
		}

		if (lastCall.name === 'exit' || lastCall.name === '_exit' || lastCall.name === 'abort') {
			return true;
		}

		// x86/x64 exit syscalls: 60 (exit), 231 (exit_group)
		// ARM64 exit syscalls: 93 (exit), 94 (exit_group)
		if (lastCall.dll === 'syscall') {
			const terminalSyscalls = ['sys_60', 'sys_231', 'sys_93', 'sys_94'];
			return terminalSyscalls.includes(lastCall.name);
		}

		return false;
	}

	/**
	 * Set breakpoint
	 */
	emulationSetBreakpoint(address: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.addBreakpoint(address);
	}

	/**
	 * Remove breakpoint
	 */
	emulationRemoveBreakpoint(address: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.removeBreakpoint(address);
	}

	/**
	 * Read memory in emulation mode
	 */
	async emulationReadMemory(address: bigint, size: number): Promise<Buffer> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		return this.emulator.readMemory(address, size);
	}

	/**
	 * Write memory in emulation mode
	 */
	async emulationWriteMemory(address: bigint, data: Buffer): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		await this.emulator.writeMemory(address, data);
	}

	/**
	 * Set register value in emulation mode
	 */
	async emulationSetRegister(name: string, value: bigint): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		await this.emulator.setRegister(name, value);
	}

	/**
	 * Update registers from emulator
	 */
	private async updateEmulationRegisters(): Promise<void> {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			this.registers = regs;
		} else if (this.architecture === 'x86') {
			const regs = this.emulator.getRegistersX86();
			this.registers = {
				rax: BigInt(regs.eax),
				rbx: BigInt(regs.ebx),
				rcx: BigInt(regs.ecx),
				rdx: BigInt(regs.edx),
				rsi: BigInt(regs.esi),
				rdi: BigInt(regs.edi),
				rbp: BigInt(regs.ebp),
				rsp: BigInt(regs.esp),
				rip: BigInt(regs.eip),
				rflags: BigInt(regs.eflags)
			};
		} else if (this.architecture === 'arm64') {
			const regs = await this.emulator.getRegistersArm64();
			// Map ARM64 registers to the RegisterState interface.
			// ARM64 general-purpose registers X0-X30, SP, PC, LR (=X30), FP (=X29), NZCV.
			// We map them into the x86-style RegisterState for UI compatibility:
			// rax→x0, rbx→x1, rcx→x2, rdx→x3, rsi→x4, rdi→x5, rbp→fp(x29), rsp→sp,
			// r8→x8, r9→x9, r10→x10, r11→x11, r12→x12, r13→x13, r14→x14, r15→x15,
			// rip→pc, rflags→nzcv
			this.registers = {
				rax: regs.x0,
				rbx: regs.x1,
				rcx: regs.x2,
				rdx: regs.x3,
				rsi: regs.x4,
				rdi: regs.x5,
				rbp: regs.fp,       // X29 / Frame Pointer
				rsp: regs.sp,       // Stack Pointer
				r8: regs.x8,
				r9: regs.x9,
				r10: regs.x10,
				r11: regs.x11,
				r12: regs.x12,
				r13: regs.x13,
				r14: regs.x14,
				r15: regs.x15,
				rip: regs.pc,       // Program Counter
				rflags: regs.nzcv   // Condition flags (NZCV)
			};

			// Store full ARM64 register set as extended data for the UI
			this._arm64Registers = regs;
		}
	}

	/**
	 * Get emulation state
	 *
	 * After startEmulation(), isRunning reflects the debugEngine state (loaded & ready).
	 * isReady indicates the emulator is initialized and ready to step/continue.
	 * The wrapper's isRunning only becomes true during active emuStart calls.
	 */
	getEmulationState(): EmulationState | null {
		if (!this.emulator) {
			return null;
		}
		const state = this.emulator.getState();
		// If the debug engine has loaded a binary, report isRunning=true
		// even if we're not actively inside an emuStart call.
		// This tells the UI/tests "the debugger session is active and ready".
		if (this.isRunning && !state.isRunning) {
			state.isRunning = true;
			// If not actively executing, we're paused at the entry point
			if (!state.isPaused) {
				state.isPaused = true;
			}
		}
		return state;
	}

	/**
	 * Get memory regions from emulator or memory manager
	 */
	async getMemoryRegions(): Promise<MemoryRegion[]> {
		if (!this.emulator) {
			return [];
		}

		// Use memory manager allocations for named regions
		if (this.memoryManager) {
			return this.memoryManager.getAllocations().map(alloc => ({
				address: alloc.address,
				size: alloc.size,
				permissions: this.permsToString(alloc.permissions),
				name: alloc.name
			}));
		}

		const regions = await this.emulator.getMemoryRegions();
		return regions.map(r => ({
			address: r.address,
			size: Number(r.size),
			permissions: r.permissions,
			name: undefined
		}));
	}

	/**
	 * Get the emulation memory regions from Unicorn directly
	 */
	async getEmulationMemoryRegions(): Promise<MemoryRegion[]> {
		return this.getMemoryRegions();
	}

	/**
	 * Get registers
	 */
	getRegisters(): Partial<RegisterState> {
		return this.registers;
	}

	/**
	 * Get API call log (from Windows hooks, Linux hooks, or ARM64 direct syscalls)
	 */
	getApiCallLog(): ApiCallLog[] {
		if (this.apiHooks) {
			return this.apiHooks.getCallLog();
		}
		if (this.linuxApiHooks) {
			// Combine PLT-based calls with ARM64 direct syscalls (static binaries)
			const pltCalls = this.linuxApiHooks.getCallLog();
			if (this._arm64SyscallLog.length > 0) {
				return [...pltCalls, ...this._arm64SyscallLog];
			}
			return pltCalls;
		}
		// ARM64 static binaries with no PLT — return direct syscall log only
		return this._arm64SyscallLog;
	}

	/**
	 * Get the centralized TraceManager instance for API/libc call trace access.
	 */
	getTraceManager(): TraceManager {
		return this._traceManager;
	}

	/**
	 * Set stdin buffer for scanf/read emulation in ELF binaries.
	 * Multiple inputs separated by newlines.
	 * Example: setStdinBuffer("42\nhello\n") for two scanf calls.
	 */
	setStdinBuffer(input: string): void {
		if (this.linuxApiHooks) {
			this.linuxApiHooks.setStdinBuffer(input);
		}
		// Also feed the ARM64 direct-syscall stdin buffer
		this._arm64StdinBuffer = input;
		this._arm64StdinOffset = 0;
	}

	/**
	 * Save emulation snapshot
	 */
	saveSnapshot(): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.saveState();
		this.emit('snapshot-saved');
	}

	/**
	 * Restore emulation snapshot
	 */
	restoreSnapshot(): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.restoreState();
		this.updateEmulationRegisters();
		this.emit('snapshot-restored');
	}

	/**
	 * Stop emulation
	 */
	stop(): void {
		if (this.emulator) {
			this.emulator.stop();
		}
		this.isRunning = false;
	}

	/**
	 * Event listener registration
	 */
	onEvent(listener: (event: string, data?: any) => void): void {
		this.listeners.push(listener);
	}

	private emit(event: string, data?: any): void {
		this.listeners.forEach(l => l(event, data));
	}

	/**
	 * Convert numeric permissions to string
	 */
	private permsToString(perms: number): string {
		let result = '';
		if (perms & 1) { result += 'r'; }
		if (perms & 2) { result += 'w'; }
		if (perms & 4) { result += 'x'; }
		return result || '---';
	}

	/**
	 * Get loaded PE info
	 */
	getPEInfo(): PEInfo | undefined {
		return this.peLoader?.getPEInfo();
	}

	/**
	 * Get loaded ELF info
	 */
	getELFInfo(): ELFInfo | undefined {
		return this.elfLoader?.getELFInfo();
	}

	/**
	 * Run a fixed number of instructions.
	 * For ELF targets, delegates to emulationContinue which uses the proven
	 * continueElfSafely path (single-instruction stepping without the extra
	 * CODE hook that start() adds — avoids native heap corruption).
	 * For PE/raw targets, uses emuStartAsync with count=N for performance.
	 */
	async emulationRunCounted(count: number, timeout: number = 0): Promise<void> {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}

		const currentAddr = this.emulator.getState().currentAddress;
		await this.emulator.runSync(currentAddr, count, timeout);
		await this.updateEmulationRegisters();
		this.emit('continue');
	}

	/**
	 * Get captured stdout from emulation (both PLT hooks and direct ARM64 syscalls)
	 */
	getStdoutBuffer(): string {
		let buffer = this._arm64StdoutBuffer;
		if (this.linuxApiHooks) {
			buffer += this.linuxApiHooks.getStdoutBuffer();
		}
		return buffer;
	}

	/**
	 * Get the current architecture
	 */
	getArchitecture(): ArchitectureType {
		return this.architecture;
	}

	/**
	 * Get the current file type
	 */
	getFileType(): 'pe' | 'elf' | 'raw' {
		return this.fileType;
	}

	/**
	 * Get full ARM64 register set (not x86-mapped)
	 */
	getFullRegisters(): Record<string, string> {
		if (!this.emulator) {
			return {};
		}

		if (this.architecture === 'arm64') {
			const regs = this.emulator.getRegistersArm64();
			const result: Record<string, string> = {};
			for (const [key, value] of Object.entries(regs)) {
				result[key] = '0x' + (value as bigint).toString(16);
			}
			return result;
		}

		if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			const result: Record<string, string> = {};
			for (const [key, value] of Object.entries(regs)) {
				result[key] = '0x' + (value as bigint).toString(16);
			}
			return result;
		}

		if (this.architecture === 'x86') {
			const regs = this.emulator.getRegistersX86();
			const result: Record<string, string> = {};
			for (const [key, value] of Object.entries(regs)) {
				result[key] = '0x' + (value as number).toString(16);
			}
			return result;
		}

		return {};
	}

	/**
	 * Dispose emulator resources
	 */
	disposeEmulation(): void {
		this.isRunning = false;
		if (this.memoryManager) {
			this.memoryManager.dispose();
			this.memoryManager = undefined;
		}
		if (this.emulator) {
			this.emulator.dispose();
			this.emulator = undefined;
		}
		this.peLoader = undefined;
		this.elfLoader = undefined;
		this.apiHooks = undefined;
		this.linuxApiHooks = undefined;
	}
}
