/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';

// Types from hexcore-unicorn
interface UnicornModule {
	Unicorn: new (arch: number, mode: number) => UnicornInstance;
	ARCH: ArchConstants;
	MODE: ModeConstants;
	PROT: ProtConstants;
	HOOK: HookConstants;
	X86_REG: X86RegConstants;
	ARM64_REG: Arm64RegConstants;
	version: () => { major: number; minor: number; string: string };
}

interface UnicornInstance {
	arch: number;
	mode: number;
	handle: bigint;
	pageSize: number;
	emuStart(begin: bigint | number, until: bigint | number, timeout?: number, count?: number): void;
	emuStartAsync(begin: bigint | number, until: bigint | number, timeout?: number, count?: number): Promise<void>;
	emuStop(): void;
	memMap(address: bigint | number, size: number, perms: number): void;
	memRead(address: bigint | number, size: number): Buffer;
	memWrite(address: bigint | number, data: Buffer): void;
	memProtect(address: bigint | number, size: number, perms: number): void;
	memRegions(): Array<{ begin: bigint; end: bigint; perms: number }>;
	regRead(regId: number): bigint | number;
	regWrite(regId: number, value: bigint | number): void;
	hookAdd(type: number, callback: Function, begin?: bigint | number, end?: bigint | number): number;
	hookDel(hookHandle: number): void;
	contextSave(): UnicornContext;
	contextRestore(context: UnicornContext): void;
	close(): void;
}

interface UnicornContext {
	free(): void;
	size: number;
}

interface ArchConstants {
	X86: number;
	ARM: number;
	ARM64: number;
	MIPS: number;
	RISCV: number;
}

interface ModeConstants {
	MODE_16: number;
	MODE_32: number;
	MODE_64: number;
	LITTLE_ENDIAN: number;
	BIG_ENDIAN: number;
}

interface ProtConstants {
	READ: number;
	WRITE: number;
	EXEC: number;
	ALL: number;
}

interface HookConstants {
	CODE: number;
	BLOCK: number;
	MEM_READ: number;
	MEM_WRITE: number;
	INTR: number;
	UC_HOOK_MEM_READ_UNMAPPED: number;
	UC_HOOK_MEM_WRITE_UNMAPPED: number;
	UC_HOOK_MEM_FETCH_UNMAPPED: number;
	UC_HOOK_MEM_UNMAPPED: number;
}

interface X86RegConstants {
	RAX: number; RBX: number; RCX: number; RDX: number;
	RSI: number; RDI: number; RBP: number; RSP: number;
	R8: number; R9: number; R10: number; R11: number;
	R12: number; R13: number; R14: number; R15: number;
	RIP: number; RFLAGS: number;
	EAX: number; EBX: number; ECX: number; EDX: number;
	ESI: number; EDI: number; EBP: number; ESP: number;
	EIP: number; EFLAGS: number;
	FS_BASE: number; GS_BASE: number;
}

interface Arm64RegConstants {
	X0: number; X1: number; X2: number; X3: number;
	X4: number; X5: number; X6: number; X7: number;
	X8: number; X9: number; X10: number; X11: number;
	X12: number; X13: number; X14: number; X15: number;
	X16: number; X17: number; X18: number; X19: number;
	X20: number; X21: number; X22: number; X23: number;
	X24: number; X25: number; X26: number; X27: number;
	X28: number; X29: number; X30: number;
	SP: number; PC: number; LR: number; FP: number;
	NZCV: number;
}

// Emulation state
export interface EmulationState {
	isRunning: boolean;
	isPaused: boolean;
	isReady: boolean;
	currentAddress: bigint;
	instructionsExecuted: number;
	lastError?: string;
}

// Register state for different architectures
export interface X86_64Registers {
	rax: bigint; rbx: bigint; rcx: bigint; rdx: bigint;
	rsi: bigint; rdi: bigint; rbp: bigint; rsp: bigint;
	r8: bigint; r9: bigint; r10: bigint; r11: bigint;
	r12: bigint; r13: bigint; r14: bigint; r15: bigint;
	rip: bigint; rflags: bigint;
}

export interface X86Registers {
	eax: number; ebx: number; ecx: number; edx: number;
	esi: number; edi: number; ebp: number; esp: number;
	eip: number; eflags: number;
}

export interface Arm64Registers {
	x0: bigint; x1: bigint; x2: bigint; x3: bigint;
	x4: bigint; x5: bigint; x6: bigint; x7: bigint;
	x8: bigint; x9: bigint; x10: bigint; x11: bigint;
	x12: bigint; x13: bigint; x14: bigint; x15: bigint;
	x16: bigint; x17: bigint; x18: bigint; x19: bigint;
	x20: bigint; x21: bigint; x22: bigint; x23: bigint;
	x24: bigint; x25: bigint; x26: bigint; x27: bigint;
	x28: bigint; x29: bigint; x30: bigint;
	sp: bigint; pc: bigint; lr: bigint; fp: bigint;
	nzcv: bigint;
}

// Memory region info
export interface MemoryRegion {
	address: bigint;
	size: bigint;
	permissions: string;
	name?: string;
}

// Hook callback types
export type CodeHookCallback = (address: bigint, size: number) => void;
export type MemoryHookCallback = (type: number, address: bigint, size: number, value: bigint) => void;
export type MemoryFaultCallback = (type: number, address: bigint, size: number, value: bigint) => boolean;
export type InterruptCallback = (intno: number) => void;

export type ArchitectureType = 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'riscv';

export class UnicornWrapper {
	private unicornModule?: UnicornModule;
	private uc?: UnicornInstance;
	private architecture: ArchitectureType = 'x64';
	private initialized: boolean = false;
	private lastError?: string;
	private state: EmulationState = {
		isRunning: false,
		isPaused: false,
		isReady: false,
		currentAddress: 0n,
		instructionsExecuted: 0
	};
	private codeHooks: Map<number, CodeHookCallback> = new Map();
	private memoryHooks: Map<number, MemoryHookCallback> = new Map();
	private breakpoints: Set<bigint> = new Set();
	private savedContext?: UnicornContext;
	private activeHookHandles: number[] = [];
	// Flag set by API interceptors when they redirect execution (popReturnAddress)
	private _apiHookRedirected: boolean = false;
	// Mutations requested while Unicorn is executing inside a hook callback.
	// Native bindings block direct memWrite/regWrite during emulation.
	private deferredMemoryWrites: Array<{ address: bigint; data: Buffer }> = [];
	private deferredRegisterWrites: Map<string, bigint | number> = new Map();

	// Configurable callbacks for memory faults and interrupts
	private memoryFaultHandler?: MemoryFaultCallback;
	private interruptHandler?: InterruptCallback;

	/**
	 * Initialize the Unicorn engine
	 */
	async initialize(arch: ArchitectureType): Promise<void> {
		if (this.initialized && this.uc && this.architecture === arch) {
			return;
		}

		if (this.uc) {
			this.dispose();
		}

		this.architecture = arch;

		// Try to load hexcore-unicorn from the extensions folder
		const possiblePaths = [
			path.join(__dirname, '..', '..', 'hexcore-unicorn'),
			path.join(__dirname, '..', '..', '..', 'hexcore-unicorn'),
			'hexcore-unicorn'
		];

		const result = loadNativeModule<UnicornModule>({
			moduleName: 'hexcore-unicorn',
			candidatePaths: possiblePaths
		});

		if (!result.module) {
			this.lastError = result.errorMessage;
			this.initialized = false;
			throw new Error('Failed to load hexcore-unicorn module');
		}

		this.lastError = undefined;
		const unicornModule = result.module;
		this.unicornModule = unicornModule;

		const { arch: ucArch, mode } = this.getArchMode(arch);
		this.uc = new unicornModule.Unicorn(ucArch, mode);
		this.initialized = true;
		this.state.isReady = true;

		// Install memory fault hooks
		this.installMemoryFaultHooks();

		console.log(`Unicorn initialized: ${arch} (version: ${unicornModule.version().string})`);
	}

	/**
	 * Install hooks for unmapped memory access (page faults)
	 */
	private installMemoryFaultHooks(): void {
		if (!this.uc || !this.unicornModule) {
			return;
		}

		const HOOK = this.unicornModule.HOOK;

		// Combined hook for all unmapped memory access
		const faultHook = this.uc.hookAdd(
			HOOK.UC_HOOK_MEM_READ_UNMAPPED | HOOK.UC_HOOK_MEM_WRITE_UNMAPPED | HOOK.UC_HOOK_MEM_FETCH_UNMAPPED,
			(type: number, address: bigint, size: number, value: bigint) => {
				if (this.memoryFaultHandler) {
					return this.memoryFaultHandler(type, address, size, value);
				}
				return false;
			}
		);
		this.activeHookHandles.push(faultHook);
	}

	/**
	 * Set handler for memory faults (unmapped access)
	 * Handler should return true if it handled the fault (mapped the memory),
	 * false to let the emulation crash.
	 */
	setMemoryFaultHandler(handler: MemoryFaultCallback): void {
		this.memoryFaultHandler = handler;
	}

	/**
	 * Set handler for interrupts (syscalls)
	 */
	setInterruptHandler(handler: InterruptCallback): void {
		this.interruptHandler = handler;

		if (!this.uc || !this.unicornModule) {
			return;
		}

		const HOOK = this.unicornModule.HOOK;
		const intrHook = this.uc.hookAdd(HOOK.INTR, (intno: number) => {
			if (this.interruptHandler) {
				this.interruptHandler(intno);
			}
		});
		this.activeHookHandles.push(intrHook);
	}

	/**
	 * Get Unicorn architecture and mode constants
	 */
	private getArchMode(arch: ArchitectureType): { arch: number; mode: number } {
		const ARCH = this.unicornModule!.ARCH;
		const MODE = this.unicornModule!.MODE;

		switch (arch) {
			case 'x86':
				return { arch: ARCH.X86, mode: MODE.MODE_32 };
			case 'x64':
				return { arch: ARCH.X86, mode: MODE.MODE_64 };
			case 'arm':
				return { arch: ARCH.ARM, mode: MODE.MODE_32 };
			case 'arm64':
				return { arch: ARCH.ARM64, mode: MODE.LITTLE_ENDIAN };
			case 'mips':
				return { arch: ARCH.MIPS, mode: MODE.MODE_32 | MODE.LITTLE_ENDIAN };
			case 'riscv':
				return { arch: ARCH.RISCV, mode: MODE.MODE_64 };
			default:
				return { arch: ARCH.X86, mode: MODE.MODE_64 };
		}
	}

	/**
	 * Load binary code into emulator memory
	 */
	loadCode(code: Buffer, baseAddress: bigint): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const PROT = this.unicornModule!.PROT;
		const pageSize = BigInt(this.uc.pageSize);
		const alignedBase = (baseAddress / pageSize) * pageSize;
		const alignedSize = Math.ceil(code.length / Number(pageSize)) * Number(pageSize);

		// Map memory with RWX permissions
		this.uc.memMap(alignedBase, alignedSize, PROT.ALL);

		// Write code to memory
		this.uc.memWrite(baseAddress, code);

		console.log(`Loaded ${code.length} bytes at 0x${baseAddress.toString(16)}`);
	}

	/**
	 * Map additional memory region
	 */
	mapMemory(address: bigint, size: number, permissions: 'r' | 'w' | 'x' | 'rw' | 'rx' | 'rwx'): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const perms = this.parsePermissions(permissions);
		const pageSize = BigInt(this.uc.pageSize);
		const alignedBase = (address / pageSize) * pageSize;
		const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);

		this.uc.memMap(alignedBase, alignedSize, perms);
	}

	/**
	 * Map memory with numeric permissions (Unicorn PROT_* values)
	 */
	mapMemoryRaw(address: bigint, size: number, perms: number): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const pageSize = BigInt(this.uc.pageSize);
		const alignedBase = (address / pageSize) * pageSize;
		const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);

		this.uc.memMap(alignedBase, alignedSize, perms);
	}

	/**
	 * Change memory permissions
	 */
	memProtect(address: bigint, size: number, perms: number): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}
		this.uc.memProtect(address, size, perms);
	}

	/**
	 * Parse permission string to Unicorn PROT_* values
	 */
	private parsePermissions(permissions: string): number {
		const PROT = this.unicornModule!.PROT;
		let perms = 0;
		if (permissions.includes('r')) {
			perms |= PROT.READ;
		}
		if (permissions.includes('w')) {
			perms |= PROT.WRITE;
		}
		if (permissions.includes('x')) {
			perms |= PROT.EXEC;
		}
		return perms;
	}

	/**
	 * Set up stack for emulation with proper alignment
	 */
	setupStack(stackBase: bigint, stackSize: number = 0x100000): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const PROT = this.unicornModule!.PROT;
		this.uc.memMap(stackBase, stackSize, PROT.READ | PROT.WRITE);

		// Set stack pointer to near top of stack, 16-byte aligned
		let sp = stackBase + BigInt(stackSize) - 0x1000n;
		sp = (sp / 16n) * 16n; // 16-byte alignment for x64 ABI

		// Push a fake return address (0xDEADDEAD) so RET at the end of main stops emulation
		if (this.architecture === 'x64') {
			sp -= 8n;
			const retBuf = Buffer.alloc(8);
			retBuf.writeBigUInt64LE(0xDEADDEADDEADDEADn);
			this.uc.memWrite(sp, retBuf);
		} else if (this.architecture === 'x86') {
			sp -= 4n;
			const retBuf = Buffer.alloc(4);
			retBuf.writeUInt32LE(0xDEADDEAD);
			this.uc.memWrite(sp, retBuf);
		}

		this.setStackPointer(sp);
	}

	/**
	 * Set stack pointer based on architecture
	 */
	private setStackPointer(sp: bigint): void {
		if (!this.uc) {
			return;
		}

		const X86_REG = this.unicornModule!.X86_REG;
		const ARM64_REG = this.unicornModule!.ARM64_REG;

		switch (this.architecture) {
			case 'x64':
				this.uc.regWrite(X86_REG.RSP, sp);
				break;
			case 'x86':
				this.uc.regWrite(X86_REG.ESP, Number(sp & 0xFFFFFFFFn));
				break;
			case 'arm64':
				this.uc.regWrite(ARM64_REG.SP, sp);
				break;
		}
	}

	/**
	 * Start emulation
	 *
	 * IMPORTANT: Unicorn's code hook fires BEFORE each instruction executes.
	 * For step mode, we must NOT emuStop() in the hook, or the instruction never runs.
	 * Instead, we pass count=1 to emuStart and let Unicorn handle it natively.
	 *
	 * For breakpoints, we skip the breakpoint if it's the start address (so continue
	 * from a breakpoint doesn't immediately re-trigger it).
	 *
	 * API hook handling: When a code hook callback (API interceptor) redirects execution
	 * by calling notifyApiRedirect(), we emuStop() to prevent the stub instruction from
	 * executing, then restart emulation from the redirected address. This loop is
	 * transparent to callers — continue() will seamlessly handle multiple API calls.
	 */
	async start(startAddress: bigint, endAddress: bigint = 0n, timeout: number = 0, count: number = 0): Promise<void> {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		this.state.isRunning = true;
		this.state.isPaused = false;
		this.state.isReady = true;
		this.state.currentAddress = startAddress;

		// Track whether this is the very first instruction (to skip breakpoint on start address)
		let isFirstInstruction = true;
		this.deferredMemoryWrites = [];
		this.deferredRegisterWrites.clear();

		// Add code hook for tracking
		const HOOK = this.unicornModule!.HOOK;
		const hookHandle = this.uc.hookAdd(HOOK.CODE, (addr: bigint, size: number) => {
			this.state.currentAddress = addr;
			this.state.instructionsExecuted++;

			// Check for breakpoints (skip if it's the start address to avoid re-triggering)
			if (this.breakpoints.has(addr) && !isFirstInstruction) {
				this.uc!.emuStop();
				this.state.isPaused = true;
				return; // Don't fire code hooks when hitting a breakpoint
			}

			isFirstInstruction = false;

			// Reset API redirect flag before calling hooks
			this._apiHookRedirected = false;

			// Notify registered code hooks (API interception, etc.)
			this.codeHooks.forEach(cb => cb(addr, size));

			// If an API interceptor redirected execution, stop emulation now
			// to prevent the stub instruction (RET) from executing and corrupting the stack.
			// The start() loop will restart emulation from the redirected address.
			if (this._apiHookRedirected) {
				this.uc!.emuStop();
			}
		});

		try {
			// Loop to handle API hook redirects transparently.
			// When an API interceptor stops emulation (via notifyApiRedirect),
			// we restart from the new address. For step mode (count=1), we don't loop.
			let currentStart = startAddress;
			const isStepping = count === 1;
			const MAX_API_REDIRECTS = 1000; // Safety limit to prevent infinite loops
			let redirectCount = 0;

			while (true) {
				this._apiHookRedirected = false;

				try {
					await this.uc.emuStartAsync(currentStart, endAddress, timeout, count);
				} catch (error: any) {
					// If the error is from an API redirect stop, that's expected
					if (!this._apiHookRedirected) {
						this.state.lastError = error.message;
						throw error;
					}
				} finally {
					// Apply writes requested by hook callbacks after Unicorn stops.
					this.applyDeferredMutations();
				}

				// Sync the actual address from Unicorn registers
				this.syncCurrentAddress();

				// If this was an API hook redirect and we're not stepping, restart from new address
				if (this._apiHookRedirected && !isStepping && !this.state.isPaused) {
					redirectCount++;
					if (redirectCount >= MAX_API_REDIRECTS) {
						console.warn(`[unicorn] API redirect limit reached (${MAX_API_REDIRECTS}), stopping emulation`);
						this.state.lastError = `API redirect limit reached (${MAX_API_REDIRECTS})`;
						break;
					}
					currentStart = this.state.currentAddress;
					isFirstInstruction = true; // Reset so breakpoint at new address is skipped
					this._apiHookRedirected = false;
					continue;
				}

				break;
			}
		} finally {
			// After emulation stops, read the actual RIP from Unicorn to sync state
			this.syncCurrentAddress();
			this.state.isRunning = false;
			this.state.isPaused = true;
			// Always delete the tracking hook to prevent leaks
			try { this.uc.hookDel(hookHandle); } catch {}
		}
	}

	private applyDeferredMutations(): void {
		if (!this.uc) {
			this.deferredMemoryWrites = [];
			this.deferredRegisterWrites.clear();
			return;
		}

		if (this.deferredMemoryWrites.length === 0 && this.deferredRegisterWrites.size === 0) {
			return;
		}

		const pendingMemWrites = this.deferredMemoryWrites;
		const pendingRegWrites = Array.from(this.deferredRegisterWrites.entries());
		this.deferredMemoryWrites = [];
		this.deferredRegisterWrites.clear();

		for (const write of pendingMemWrites) {
			try {
				this.uc.memWrite(write.address, write.data);
			} catch (error: unknown) {
				this.lastError = toErrorMessage(error);
				console.warn(`[unicorn] Deferred memWrite failed at 0x${write.address.toString(16)}: ${this.lastError}`);
			}
		}

		for (const [name, value] of pendingRegWrites) {
			try {
				this.setRegisterImmediate(name, value);
			} catch (error: unknown) {
				this.lastError = toErrorMessage(error);
				console.warn(`[unicorn] Deferred register write failed for ${name}: ${this.lastError}`);
			}
		}
	}

	/**
	 * Notify the emulation loop that an API interceptor has redirected execution.
	 * Call this from API hook handlers (after popReturnAddress) so the start() loop
	 * knows to stop the current emulation and restart from the new address.
	 */
	notifyApiRedirect(): void {
		this._apiHookRedirected = true;
	}

	/**
	 * Read the actual instruction pointer from Unicorn registers and sync state.
	 * This ensures currentAddress reflects reality after emuStop/step.
	 */
	private syncCurrentAddress(): void {
		if (!this.uc || !this.unicornModule) { return; }

		try {
			const X86_REG = this.unicornModule.X86_REG;
			const ARM64_REG = this.unicornModule.ARM64_REG;

			switch (this.architecture) {
				case 'x64':
					this.state.currentAddress = BigInt(this.uc.regRead(X86_REG.RIP));
					break;
				case 'x86':
					this.state.currentAddress = BigInt(this.uc.regRead(X86_REG.EIP));
					break;
				case 'arm64':
					this.state.currentAddress = BigInt(this.uc.regRead(ARM64_REG.PC));
					break;
			}
		} catch {
			// If register read fails, keep the last known address
		}
	}

	/**
	 * Step one instruction.
	 * Uses count=1 in emuStart to execute exactly one instruction natively.
	 * Does NOT use stepMode flag (which would prevent the instruction from running).
	 */
	async step(): Promise<void> {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const currentAddr = this.state.currentAddress;
		// count=1 tells Unicorn to execute exactly 1 instruction then stop
		await this.start(currentAddr, 0n, 0, 1);
	}

	/**
	 * Continue execution from current address until breakpoint, exit, or error.
	 */
	async continue(): Promise<void> {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		this.state.isPaused = false;
		await this.start(this.state.currentAddress);
	}

	/**
	 * Stop emulation
	 */
	stop(): void {
		if (!this.uc) {
			return;
		}
		this.uc.emuStop();
		this.state.isRunning = false;
	}

	/**
	 * Add breakpoint
	 */
	addBreakpoint(address: bigint): void {
		this.breakpoints.add(address);
	}

	/**
	 * Remove breakpoint
	 */
	removeBreakpoint(address: bigint): void {
		this.breakpoints.delete(address);
	}

	/**
	 * Get all breakpoints
	 */
	getBreakpoints(): bigint[] {
		return Array.from(this.breakpoints);
	}

	/**
	 * Read memory
	 */
	readMemory(address: bigint, size: number): Buffer {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}
		return this.uc.memRead(address, size);
	}

	/**
	 * Write memory
	 */
	writeMemory(address: bigint, data: Buffer): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		if (this.state.isRunning) {
			// Buffer may be reused by caller; clone to avoid mutation races.
			this.deferredMemoryWrites.push({ address, data: Buffer.from(data) });
			return;
		}

		this.uc.memWrite(address, data);
	}

	/**
	 * Get x86-64 registers
	 */
	getRegistersX64(): X86_64Registers {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const REG = this.unicornModule!.X86_REG;
		return {
			rax: BigInt(this.uc.regRead(REG.RAX)),
			rbx: BigInt(this.uc.regRead(REG.RBX)),
			rcx: BigInt(this.uc.regRead(REG.RCX)),
			rdx: BigInt(this.uc.regRead(REG.RDX)),
			rsi: BigInt(this.uc.regRead(REG.RSI)),
			rdi: BigInt(this.uc.regRead(REG.RDI)),
			rbp: BigInt(this.uc.regRead(REG.RBP)),
			rsp: BigInt(this.uc.regRead(REG.RSP)),
			r8: BigInt(this.uc.regRead(REG.R8)),
			r9: BigInt(this.uc.regRead(REG.R9)),
			r10: BigInt(this.uc.regRead(REG.R10)),
			r11: BigInt(this.uc.regRead(REG.R11)),
			r12: BigInt(this.uc.regRead(REG.R12)),
			r13: BigInt(this.uc.regRead(REG.R13)),
			r14: BigInt(this.uc.regRead(REG.R14)),
			r15: BigInt(this.uc.regRead(REG.R15)),
			rip: BigInt(this.uc.regRead(REG.RIP)),
			rflags: BigInt(this.uc.regRead(REG.RFLAGS))
		};
	}

	/**
	 * Get x86 (32-bit) registers
	 */
	getRegistersX86(): X86Registers {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const REG = this.unicornModule!.X86_REG;
		return {
			eax: Number(this.uc.regRead(REG.EAX)),
			ebx: Number(this.uc.regRead(REG.EBX)),
			ecx: Number(this.uc.regRead(REG.ECX)),
			edx: Number(this.uc.regRead(REG.EDX)),
			esi: Number(this.uc.regRead(REG.ESI)),
			edi: Number(this.uc.regRead(REG.EDI)),
			ebp: Number(this.uc.regRead(REG.EBP)),
			esp: Number(this.uc.regRead(REG.ESP)),
			eip: Number(this.uc.regRead(REG.EIP)),
			eflags: Number(this.uc.regRead(REG.EFLAGS))
		};
	}

	/**
	 * Get ARM64 registers
	 */
	getRegistersArm64(): Arm64Registers {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const REG = this.unicornModule!.ARM64_REG;
		return {
			x0: BigInt(this.uc.regRead(REG.X0)),
			x1: BigInt(this.uc.regRead(REG.X1)),
			x2: BigInt(this.uc.regRead(REG.X2)),
			x3: BigInt(this.uc.regRead(REG.X3)),
			x4: BigInt(this.uc.regRead(REG.X4)),
			x5: BigInt(this.uc.regRead(REG.X5)),
			x6: BigInt(this.uc.regRead(REG.X6)),
			x7: BigInt(this.uc.regRead(REG.X7)),
			x8: BigInt(this.uc.regRead(REG.X8)),
			x9: BigInt(this.uc.regRead(REG.X9)),
			x10: BigInt(this.uc.regRead(REG.X10)),
			x11: BigInt(this.uc.regRead(REG.X11)),
			x12: BigInt(this.uc.regRead(REG.X12)),
			x13: BigInt(this.uc.regRead(REG.X13)),
			x14: BigInt(this.uc.regRead(REG.X14)),
			x15: BigInt(this.uc.regRead(REG.X15)),
			x16: BigInt(this.uc.regRead(REG.X16)),
			x17: BigInt(this.uc.regRead(REG.X17)),
			x18: BigInt(this.uc.regRead(REG.X18)),
			x19: BigInt(this.uc.regRead(REG.X19)),
			x20: BigInt(this.uc.regRead(REG.X20)),
			x21: BigInt(this.uc.regRead(REG.X21)),
			x22: BigInt(this.uc.regRead(REG.X22)),
			x23: BigInt(this.uc.regRead(REG.X23)),
			x24: BigInt(this.uc.regRead(REG.X24)),
			x25: BigInt(this.uc.regRead(REG.X25)),
			x26: BigInt(this.uc.regRead(REG.X26)),
			x27: BigInt(this.uc.regRead(REG.X27)),
			x28: BigInt(this.uc.regRead(REG.X28)),
			x29: BigInt(this.uc.regRead(REG.X29)),
			x30: BigInt(this.uc.regRead(REG.X30)),
			sp: BigInt(this.uc.regRead(REG.SP)),
			pc: BigInt(this.uc.regRead(REG.PC)),
			lr: BigInt(this.uc.regRead(REG.LR)),
			fp: BigInt(this.uc.regRead(REG.FP)),
			nzcv: BigInt(this.uc.regRead(REG.NZCV))
		};
	}

	/**
	 * Set register value with correct type handling per architecture
	 */
	setRegister(name: string, value: bigint | number): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const regName = name.toLowerCase();
		if (this.state.isRunning) {
			this.deferredRegisterWrites.set(regName, value);
			return;
		}

		this.setRegisterImmediate(regName, value);
	}

	private setRegisterImmediate(name: string, value: bigint | number): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const X86_REG = this.unicornModule!.X86_REG;
		const ARM64_REG = this.unicornModule!.ARM64_REG;

		// x86-64 registers (including segment bases for TLS/TEB access)
		const x64Regs: Record<string, number> = {
			'rax': X86_REG.RAX, 'rbx': X86_REG.RBX, 'rcx': X86_REG.RCX, 'rdx': X86_REG.RDX,
			'rsi': X86_REG.RSI, 'rdi': X86_REG.RDI, 'rbp': X86_REG.RBP, 'rsp': X86_REG.RSP,
			'r8': X86_REG.R8, 'r9': X86_REG.R9, 'r10': X86_REG.R10, 'r11': X86_REG.R11,
			'r12': X86_REG.R12, 'r13': X86_REG.R13, 'r14': X86_REG.R14, 'r15': X86_REG.R15,
			'rip': X86_REG.RIP, 'rflags': X86_REG.RFLAGS,
			'fs_base': X86_REG.FS_BASE, 'gs_base': X86_REG.GS_BASE
		};

		// x86-32 registers
		const x86Regs: Record<string, number> = {
			'eax': X86_REG.EAX, 'ebx': X86_REG.EBX, 'ecx': X86_REG.ECX, 'edx': X86_REG.EDX,
			'esi': X86_REG.ESI, 'edi': X86_REG.EDI, 'ebp': X86_REG.EBP, 'esp': X86_REG.ESP,
			'eip': X86_REG.EIP, 'eflags': X86_REG.EFLAGS
		};

		// ARM64 registers
		const arm64Regs: Record<string, number> = {
			'x0': ARM64_REG.X0, 'x1': ARM64_REG.X1, 'x2': ARM64_REG.X2, 'x3': ARM64_REG.X3,
			'x4': ARM64_REG.X4, 'x5': ARM64_REG.X5, 'x6': ARM64_REG.X6, 'x7': ARM64_REG.X7,
			'x8': ARM64_REG.X8, 'x9': ARM64_REG.X9, 'x10': ARM64_REG.X10, 'x11': ARM64_REG.X11,
			'x12': ARM64_REG.X12, 'x13': ARM64_REG.X13, 'x14': ARM64_REG.X14, 'x15': ARM64_REG.X15,
			'x16': ARM64_REG.X16, 'x17': ARM64_REG.X17, 'x18': ARM64_REG.X18, 'x19': ARM64_REG.X19,
			'x20': ARM64_REG.X20, 'x21': ARM64_REG.X21, 'x22': ARM64_REG.X22, 'x23': ARM64_REG.X23,
			'x24': ARM64_REG.X24, 'x25': ARM64_REG.X25, 'x26': ARM64_REG.X26, 'x27': ARM64_REG.X27,
			'x28': ARM64_REG.X28, 'x29': ARM64_REG.X29, 'x30': ARM64_REG.X30,
			'sp': ARM64_REG.SP, 'pc': ARM64_REG.PC, 'lr': ARM64_REG.LR, 'fp': ARM64_REG.FP,
			'nzcv': ARM64_REG.NZCV
		};

		// Fix: use correct type per architecture to avoid type confusion
		if (x64Regs[name] !== undefined) {
			this.uc.regWrite(x64Regs[name], BigInt(value));
		} else if (x86Regs[name] !== undefined) {
			this.uc.regWrite(x86Regs[name], Number(value) & 0xFFFFFFFF);
		} else if (arm64Regs[name] !== undefined) {
			this.uc.regWrite(arm64Regs[name], BigInt(value));
		} else {
			throw new Error(`Unknown register: ${name.toLowerCase()}`);
		}
	}

	/**
	 * Get mapped memory regions
	 */
	getMemoryRegions(): MemoryRegion[] {
		if (!this.uc) {
			return [];
		}

		const PROT = this.unicornModule!.PROT;
		return this.uc.memRegions().map(region => {
			let perms = '';
			if (region.perms & PROT.READ) {
				perms += 'r';
			}
			if (region.perms & PROT.WRITE) {
				perms += 'w';
			}
			if (region.perms & PROT.EXEC) {
				perms += 'x';
			}

			return {
				address: region.begin,
				size: region.end - region.begin,
				permissions: perms || '---'
			};
		});
	}

	/**
	 * Get the page size
	 */
	getPageSize(): number {
		return this.uc?.pageSize ?? 0x1000;
	}

	/**
	 * Get the underlying Unicorn PROT constants
	 */
	getProtConstants(): ProtConstants | undefined {
		return this.unicornModule?.PROT;
	}

	/**
	 * Get the X86_REG constants
	 */
	getX86RegConstants(): X86RegConstants | undefined {
		return this.unicornModule?.X86_REG;
	}

	/**
	 * Save current state (snapshot)
	 */
	saveState(): void {
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		if (this.savedContext) {
			this.savedContext.free();
		}
		this.savedContext = this.uc.contextSave();
	}

	/**
	 * Restore saved state
	 */
	restoreState(): void {
		if (!this.uc || !this.savedContext) {
			throw new Error('No saved state');
		}
		this.uc.contextRestore(this.savedContext);
	}

	/**
	 * Get emulation state
	 */
	getState(): EmulationState {
		return { ...this.state };
	}

	/**
	 * Set the current address (used when patching RIP externally, e.g. after API hook return)
	 */
	setCurrentAddress(addr: bigint): void {
		this.state.currentAddress = addr;
	}

	/**
	 * Get current architecture
	 */
	getArchitecture(): ArchitectureType {
		return this.architecture;
	}

	/**
	 * Add code execution hook
	 */
	onCodeExecute(callback: CodeHookCallback): number {
		const id = Date.now();
		this.codeHooks.set(id, callback);
		return id;
	}

	/**
	 * Remove code hook
	 */
	removeCodeHook(id: number): void {
		this.codeHooks.delete(id);
	}

	/**
	 * Check if initialized
	 */
	isInitialized(): boolean {
		return this.initialized && this.uc !== undefined;
	}

	getLastError(): string | undefined {
		return this.lastError;
	}

	/**
	 * Close and cleanup
	 */
	dispose(): void {
		// Clean up all active hook handles
		if (this.uc) {
			for (const handle of this.activeHookHandles) {
				try {
					this.uc.hookDel(handle);
				} catch {
					// Ignore errors during cleanup
				}
			}
		}
		this.activeHookHandles = [];

		if (this.savedContext) {
			this.savedContext.free();
			this.savedContext = undefined;
		}
		if (this.uc) {
			this.uc.close();
			this.uc = undefined;
		}
		this.initialized = false;
		this.state.isReady = false;
		this.codeHooks.clear();
		this.memoryHooks.clear();
		this.breakpoints.clear();
		this.memoryFaultHandler = undefined;
		this.interruptHandler = undefined;
		this._apiHookRedirected = false;
	}
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}
