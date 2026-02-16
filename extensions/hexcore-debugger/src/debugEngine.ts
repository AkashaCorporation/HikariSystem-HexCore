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

	// ARM64 mmap offset tracker for syscall-based memory allocation
	private _arm64MmapOffset: number = 0;
	// ARM64 full register set (extended data for UI beyond x86 mapping)
	private _arm64Registers: any = null;

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
			(address, size, perms) => this.emulator!.mapMemoryRaw(address, size, perms),
			this.emulator.getPageSize()
		);

		// Set up memory fault handler
		this.emulator.setMemoryFaultHandler((type, address, size, _value) => {
			return this.memoryManager!.handlePageFault(address, size, type);
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

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);
		this.setupArm64Stack();

		// Install API call interceptor via code hook
		this.installApiInterceptor();

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		this.emulator!.setRegister(ipReg, peInfo.entryPoint);
		this.emulator!.setCurrentAddress(peInfo.entryPoint);

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
		const exitImport = elfInfo.imports.find(imp => imp.name === 'exit' || imp.name === '_exit');
		this.linuxApiHooks.setMainReturnAddress(exitImport?.stubAddress ?? null);

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);
		this.setupArm64Stack();
		this.initializeElfProcessStack();

		// Setup TLS (Thread Local Storage) region for fs:[0x28] stack canary access.
		// Linux x64 uses FS segment for TLS. The kernel sets FS_BASE via arch_prctl.
		// We allocate a 4KB TLS block and set FS_BASE to point to it.
		// fs:[0x28] is the stack canary — we write a known value there.
		this.setupLinuxTLS();

		// Install ELF API interceptor (PLT stubs → libc hooks)
		this.installELFApiInterceptor();

		// Install syscall handler for direct syscalls
		this.installSyscallHandler();

		// Set instruction pointer to entry point
		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		this.emulator!.setRegister(ipReg, elfInfo.entryPoint);
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
		this.emulator!.loadCode(this.fileBuffer!, loadBase);
		this.baseAddress = loadBase;

		// Initialize heap
		this.memoryManager!.initializeHeap();

		// Setup stack
		const stackBase = 0x7FFF0000n;
		this.emulator!.setupStack(stackBase);
		this.setupArm64Stack();

		const ipReg = this.architecture === 'arm64' ? 'pc' : (this.architecture === 'x64' ? 'rip' : 'eip');
		this.emulator!.setRegister(ipReg, loadBase);
		this.emulator!.setCurrentAddress(loadBase);
	}

	/**
	 * Configure ARM64-specific stack semantics after the base stack is mapped.
	 * ARM64 doesn't push return addresses to the stack — it uses the Link Register (X30/LR).
	 * Set LR to a sentinel value so a RET at the end of main stops emulation.
	 * Also ensure SP is 16-byte aligned as required by the AAPCS64 ABI.
	 */
	private setupArm64Stack(): void {
		if (!this.emulator || this.architecture !== 'arm64') {
			return;
		}

		try {
			// Set LR (X30) to sentinel return address so RET stops emulation
			this.emulator.setRegister('lr', 0xDEAD0000n);

			// Read current SP and ensure 16-byte alignment (AAPCS64 requirement)
			const regs = this.emulator.getRegistersArm64();
			const alignedSp = (regs.sp / 16n) * 16n;
			if (alignedSp !== regs.sp) {
				this.emulator.setRegister('sp', alignedSp);
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
	private setupLinuxTLS(): void {
		if (!this.emulator || !this.memoryManager) {
			return;
		}

		// Keep TLS below the default stack mapping (0x7FFF0000..0x800F0000).
		const TLS_BASE = 0x7FFEF000n;
		const TLS_SIZE = 0x1000;         // 4KB

		try {
			// Map TLS region as RW if it is not already mapped.
			try {
				this.emulator.mapMemoryRaw(TLS_BASE, TLS_SIZE, 3); // PROT_READ | PROT_WRITE
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

			this.emulator.writeMemory(TLS_BASE, tls);

			// Set FS_BASE to point to TLS region
			if (this.architecture === 'x64') {
				this.emulator.setRegister('fs_base', TLS_BASE);
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
	private initializeElfProcessStack(): void {
		if (!this.emulator) {
			return;
		}

		try {
			if (this.architecture === 'arm64') {
				// ARM64 ELF ABI: argc in X0, argv pointer in X1, envp pointer in X2
				// argv array and strings are still on the stack, but argc is passed via register
				const regs = this.emulator.getRegistersArm64();
				let stackPtr = regs.sp - 0x80n;
				stackPtr = (stackPtr / 16n) * 16n; // 16-byte alignment (AAPCS64)

				// Write argv[0] string on the stack
				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x40n;
				this.emulator.writeMemory(argv0Addr, argv0);

				// Build argv array on stack: [argv0_ptr, NULL]
				const argvArray = Buffer.alloc(16);
				argvArray.writeBigUInt64LE(argv0Addr, 0);  // argv[0]
				argvArray.writeBigUInt64LE(0n, 8);          // argv[1] = NULL (terminator)
				const argvAddr = stackPtr;
				this.emulator.writeMemory(argvAddr, argvArray);

				// envp array on stack: [NULL]
				const envpArray = Buffer.alloc(8);
				envpArray.writeBigUInt64LE(0n, 0);          // envp[0] = NULL
				const envpAddr = stackPtr + 16n;
				this.emulator.writeMemory(envpAddr, envpArray);

				// Set registers: X0 = argc, X1 = argv, X2 = envp
				this.emulator.setRegister('x0', 1n);
				this.emulator.setRegister('x1', argvAddr);
				this.emulator.setRegister('x2', envpAddr);

				// Update SP
				this.emulator.setRegister('sp', stackPtr - 0x40n);
				return;
			}

			if (this.architecture === 'x64') {
				const regs = this.emulator.getRegistersX64();
				let stackPtr = regs.rsp - 0x80n;
				stackPtr = (stackPtr / 16n) * 16n;

				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x40n;
				this.emulator.writeMemory(argv0Addr, argv0);

				const layout = Buffer.alloc(32);
				layout.writeBigUInt64LE(1n, 0);      // argc
				layout.writeBigUInt64LE(argv0Addr, 8);  // argv[0]
				layout.writeBigUInt64LE(0n, 16);     // argv[1] = NULL
				layout.writeBigUInt64LE(0n, 24);     // envp = NULL
				this.emulator.writeMemory(stackPtr, layout);
				this.emulator.setRegister('rsp', stackPtr);
				return;
			}

			if (this.architecture === 'x86') {
				const regs = this.emulator.getRegistersX86();
				const stackPtr = BigInt(regs.esp - 0x60);
				const argv0 = Buffer.from('hexcore\0', 'ascii');
				const argv0Addr = stackPtr - 0x20n;
				this.emulator.writeMemory(argv0Addr, argv0);

				const layout = Buffer.alloc(16);
				layout.writeUInt32LE(1, 0); // argc
				layout.writeUInt32LE(Number(argv0Addr & 0xFFFFFFFFn), 4);
				layout.writeUInt32LE(0, 8); // argv[1] = NULL
				layout.writeUInt32LE(0, 12); // envp = NULL
				this.emulator.writeMemory(stackPtr, layout);
				this.emulator.setRegister('esp', Number(stackPtr & 0xFFFFFFFFn));
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
					this.emulator!.setRegister('rax', returnValue);
				} else {
					this.emulator!.setRegister('eax', returnValue);
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
						this.emulator!.setRegister('rax', returnValue);
					} else {
						this.emulator!.setRegister('eax', returnValue);
					}
				}

				const redirectAddr = this.linuxApiHooks!.getRedirectAddress();
				if (!isTerminatingCall && redirectAddr !== null) {
					// Redirect execution to the handler-provided target (e.g. main()).
					// Keep caller return address on stack so the redirected function can return.
					if (this.architecture === 'x64') {
						this.emulator!.setRegister('rip', redirectAddr);
						this.emulator!.setCurrentAddress(redirectAddr);
					} else {
						this.emulator!.setRegister('eip', redirectAddr);
						this.emulator!.setCurrentAddress(redirectAddr);
					}
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

		this.emulator.setInterruptHandler((intno: number) => {
			if (this.architecture === 'arm64') {
				// ARM64: SVC #0 generates interrupt 2 in Unicorn
				if (intno === 2) {
					const result = this.handleArm64Syscall();

					// Set return value in X0
					this.emulator!.setRegister('x0', result);

					// Emit syscall event for the UI
					const regs = this.emulator!.getRegistersArm64();
					const sysNum = Number(regs.x8); // ARM64 syscall number is in X8

					this.emit('api-call', {
						dll: 'syscall',
						name: `sys_${sysNum}`,
						returnValue: result
					});
				}
				return;
			}

			// int 0x80 on x86 or SYSCALL instruction generates interrupt 2 in Unicorn
			if (intno === 0x80 || intno === 2) {
				const result = this.linuxApiHooks!.handleSyscall();

				// Set return value in RAX
				if (this.architecture === 'x64') {
					this.emulator!.setRegister('rax', result);
				} else {
					this.emulator!.setRegister('eax', result);
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
	 * Handle ARM64 syscalls (SVC #0).
	 * ARM64 Linux syscall convention: X8 = syscall number, X0-X5 = arguments, X0 = return value.
	 * Syscall numbers are different from x86/x64 — ARM64 uses its own numbering.
	 */
	private handleArm64Syscall(): bigint {
		if (!this.emulator) {
			return BigInt(-38); // -ENOSYS
		}

		const regs = this.emulator.getRegistersArm64();
		const syscallNum = Number(regs.x8); // ARM64 syscall number is in X8
		const args = [regs.x0, regs.x1, regs.x2, regs.x3, regs.x4, regs.x5];

		return this.dispatchArm64Syscall(syscallNum, args);
	}

	/**
	 * Dispatch an ARM64 Linux syscall by number.
	 * ARM64 syscall numbers differ from x86/x64.
	 * Reference: https://arm64.syscall.sh/
	 */
	private dispatchArm64Syscall(syscallNum: number, args: bigint[]): bigint {
		switch (syscallNum) {
			case 56: // openat
				return 3n; // Return a dummy fd
			case 57: // close
				return 0n;
			case 63: { // read(fd, buf, count)
				return 0n; // EOF
			}
			case 64: { // write(fd, buf, count)
				const count = Number(args[2]);
				if (count > 0 && count < 0x10000) {
					try {
						const data = this.emulator!.readMemory(args[1], count);
						const fd = Number(args[0]);
						console.log(`[arm64 syscall write fd${fd}] ${data.toString('utf8')}`);
						return BigInt(count);
					} catch {
						return BigInt(-14); // -EFAULT
					}
				}
				return 0n;
			}
			case 93: // exit
				console.log(`[arm64 syscall exit] code=${Number(args[0])}`);
				this.emulator!.stop();
				return 0n;
			case 94: // exit_group
				console.log(`[arm64 syscall exit_group] code=${Number(args[0])}`);
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
	private popReturnAddress(): void {
		if (!this.emulator) {
			return;
		}

		if (this.architecture === 'arm64') {
			// ARM64: Return address is in LR (X30), not on the stack
			const regs = this.emulator.getRegistersArm64();
			const retAddr = regs.lr; // X30 = Link Register
			this.emulator.setRegister('pc', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		} else if (this.architecture === 'x64') {
			const regs = this.emulator.getRegistersX64();
			const retAddr = this.emulator.readMemory(regs.rsp, 8).readBigUInt64LE();
			this.emulator.setRegister('rsp', regs.rsp + 8n);
			this.emulator.setRegister('rip', retAddr);
			this.emulator.setCurrentAddress(retAddr);
		} else {
			const regs = this.emulator.getRegistersX86();
			const retAddr = BigInt(this.emulator.readMemory(BigInt(regs.esp), 4).readUInt32LE());
			this.emulator.setRegister('esp', BigInt(regs.esp + 4));
			this.emulator.setRegister('eip', retAddr);
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
		let currentAddress = this.getCurrentInstructionPointer();

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
				const faultAddress = this.getCurrentInstructionPointer();
				if (this.isTerminalExecutionAddress(faultAddress) || this.hasTerminalLinuxApiCall()) {
					return;
				}
				throw error;
			}

			const nextAddress = this.getCurrentInstructionPointer();
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

	private getCurrentInstructionPointer(): bigint {
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
		} catch {
			// Fallback to wrapper state below.
		}

		return this.emulator.getState().currentAddress;
	}

	private hasTerminalLinuxApiCall(): boolean {
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

		return lastCall.dll === 'syscall' && (lastCall.name === 'sys_60' || lastCall.name === 'sys_231');
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
	emulationReadMemory(address: bigint, size: number): Buffer {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		return this.emulator.readMemory(address, size);
	}

	/**
	 * Write memory in emulation mode
	 */
	emulationWriteMemory(address: bigint, data: Buffer): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.writeMemory(address, data);
	}

	/**
	 * Set register value in emulation mode
	 */
	emulationSetRegister(name: string, value: bigint): void {
		if (!this.emulator) {
			throw new Error('Emulator not initialized');
		}
		this.emulator.setRegister(name, value);
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
			const regs = this.emulator.getRegistersArm64();
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
	getMemoryRegions(): MemoryRegion[] {
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

		return this.emulator.getMemoryRegions().map(r => ({
			address: r.address,
			size: Number(r.size),
			permissions: r.permissions,
			name: undefined
		}));
	}

	/**
	 * Get the emulation memory regions from Unicorn directly
	 */
	getEmulationMemoryRegions(): MemoryRegion[] {
		return this.getMemoryRegions();
	}

	/**
	 * Get registers
	 */
	getRegisters(): Partial<RegisterState> {
		return this.registers;
	}

	/**
	 * Get API call log (from Windows hooks or Linux hooks)
	 */
	getApiCallLog(): ApiCallLog[] {
		if (this.apiHooks) {
			return this.apiHooks.getCallLog();
		}
		if (this.linuxApiHooks) {
			return this.linuxApiHooks.getCallLog();
		}
		return [];
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
