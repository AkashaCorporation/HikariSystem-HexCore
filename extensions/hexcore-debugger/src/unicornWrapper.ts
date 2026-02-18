/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';
import { Arm64WorkerClient } from './arm64WorkerClient';

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
export type AsyncInterruptCallback = (intno: number) => Promise<void>;

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
	// Async version of interrupt handler for ARM64 worker mode
	private _interruptHandlerAsync?: AsyncInterruptCallback;
	// Flag: true when executing inside a blocking hook callback (INTR/MEM_FAULT).
	// During blocking hooks the Unicorn thread is paused, so direct regWrite/memMap
	// via the native binding is safe — no need for deferred writes.
	private _insideBlockingHook: boolean = false;

	// Flag: set by stop() to signal ARM64 sync loops to terminate.
	// In sync mode, uc_emu_stop() is a no-op (no active emulation), so the
	// loop must check this flag after each step/syscall dispatch.
	private _stopRequested: boolean = false;

	// Track whether the INTR hook is currently installed (to avoid
	// redundant remove/reinstall when step() is called repeatedly).
	private _intrHookInstalled: boolean = false;

	// ARM64 worker client: runs Unicorn in a separate Node.js process to
	// avoid Chromium UtilityProcess security restrictions (ACG/CFG).
	private _arm64Worker?: Arm64WorkerClient;
	// When using the worker, we cache Unicorn constants fetched from it.
	private _workerConstants?: Record<string, unknown>;
	// Worker-side context ID for save/restore state
	private _workerContextId?: number;

	/**
	 * Initialize the Unicorn engine
	 */
	async initialize(arch: ArchitectureType): Promise<void> {
		if (this.initialized && this.architecture === arch) {
			// Already initialized for this arch
			if (arch === 'arm64' && this._arm64Worker) {
				return;
			}
			if (arch !== 'arm64' && this.uc) {
				return;
			}
		}

		if (this.uc) {
			this.dispose();
		}
		if (this._arm64Worker) {
			this._arm64Worker.dispose();
			this._arm64Worker = undefined;
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

		if (arch === 'arm64') {
			// ARM64: use worker process to avoid Chromium UtilityProcess
			// ACG/CFG restrictions that crash Unicorn's JIT backend.
			console.log('[arm64] Starting ARM64 worker process...');
			this._arm64Worker = new Arm64WorkerClient();
			await this._arm64Worker.start();

			const { arch: ucArch, mode } = this.getArchMode(arch);
			const initResult = await this._arm64Worker.initialize(ucArch, mode);
			console.log(`[arm64] Worker initialized: version=${initResult.version}, pageSize=${initResult.pageSize}`);

			this.initialized = true;
			this.state.isReady = true;
			console.log(`Unicorn initialized via worker: ${arch} (version: ${initResult.version})`);
			return;
		}

		const { arch: ucArch, mode } = this.getArchMode(arch);
		console.log(`[DIAG] About to create Unicorn instance: arch=${ucArch}, mode=${mode}`);
		this.uc = new unicornModule.Unicorn(ucArch, mode);
		console.log(`[DIAG] Unicorn instance created OK, handle=${this.uc.handle}`);
		this.initialized = true;
		this.state.isReady = true;

		// Install memory fault hooks.
		// Not needed for ARM64 (handled in worker).
		this.installMemoryFaultHooks();

		console.log(`Unicorn initialized: ${arch} (version: ${unicornModule.version().string})`);
	}

	/**
	 * Install hooks for unmapped memory access (page faults).
	 *
	 * NOT used for ARM64 — the TSFN (ThreadSafeFunction) used by the native
	 * InvalidMemHookCB crashes in Electron's UtilityProcess extension host.
	 * For ARM64, memory faults are handled in JS via handleArm64MemoryFault.
	 */
	private installMemoryFaultHooks(): void {
		if (!this.uc || !this.unicornModule) {
			return;
		}

		const HOOK = this.unicornModule.HOOK;

		// Combined hook for all unmapped memory access.
		// The native InvalidMemHookCB performs uc_mem_map directly on the Unicorn
		// thread (same thread as uc_emu_start) to avoid cross-thread issues.
		// This JS callback is called asynchronously via NonBlockingCall for
		// tracking/logging only — the memory is already mapped by the time this runs.
		const faultHook = this.uc.hookAdd(
			HOOK.UC_HOOK_MEM_READ_UNMAPPED | HOOK.UC_HOOK_MEM_WRITE_UNMAPPED | HOOK.UC_HOOK_MEM_FETCH_UNMAPPED,
			(type: number, address: bigint, size: number, _value: bigint) => {
				// Notify the memory fault handler for tracking (memory already mapped in C++)
				if (this.memoryFaultHandler) {
					this.memoryFaultHandler(type, address, size, _value);
				}
				// Return value is ignored — C++ already handled the fault
				return true;
			}
		);
		this.activeHookHandles.push(faultHook);
	}

	/**
	 * Handle a memory fault for ARM64 sync execution (no native hook).
	 *
	 * When Unicorn emuStart(count=1) throws UC_ERR_READ_UNMAPPED (code 6),
	 * UC_ERR_WRITE_UNMAPPED (code 7), or UC_ERR_FETCH_UNMAPPED (code 8),
	 * this method maps the faulting page with RWX from JS (same thread)
	 * and notifies the memoryFaultHandler for tracking.
	 *
	 * @returns `true` if the fault was handled (caller should retry);
	 *          `false` if it's an unrecoverable error.
	 */
	private handleArm64MemoryFault(error: unknown): boolean {
		if (!this.uc || !this.unicornModule) {
			return false;
		}

		const msg = toErrorMessage(error);
		// Match "(code: 6)", "(code: 7)", or "(code: 8)"
		const codeMatch = /\(code:\s*(?<errCode>[678])\)/.exec(msg);
		if (!codeMatch?.groups) {
			return false;
		}

		// Read the faulting address from the PC — for fetch faults the PC
		// is the unmapped address; for read/write faults the PC is the
		// instruction that triggered the access, but the actual faulting
		// address is in the error message implicitly.  Unicorn does not
		// advance PC on error, so the instruction can be retried.
		//
		// For fetch unmapped (code 8), the PC *is* the unmapped address.
		// For read/write unmapped (code 6/7), we need the data address
		// which Unicorn doesn't expose in the error message.  However,
		// the native InvalidMemHookCB auto-maps using the faulting address
		// from the callback parameters.  Since we don't have a native hook,
		// we map a generous region around the current PC for fetch faults.
		// For read/write faults, re-running the instruction will fault
		// again with the same address. We use the regRead-based approach:
		// read the instruction at PC, decode the memory operand, and map it.
		//
		// Simpler approach: for fetch faults map the PC page; for data
		// faults, map a broad region.  Since this is ARM64 with known
		// memory layout (ELF loaded at known base), most faults are fetch
		// faults on code pages or stack/heap accesses that should already
		// be mapped.  The most common case is fetch unmapped at startup.

		const errCode = Number(codeMatch.groups['errCode']);
		const PROT = this.unicornModule.PROT;
		const pageSize = this.uc.pageSize;

		let faultAddr = 0n;

		if (errCode === 8) {
			// UC_ERR_FETCH_UNMAPPED: PC points to unmapped code
			faultAddr = BigInt(this.uc.regRead(this.unicornModule.ARM64_REG.PC));
		} else {
			// UC_ERR_READ_UNMAPPED / UC_ERR_WRITE_UNMAPPED:
			// We don't know the exact data address from the error message.
			// Read the 4-byte instruction at PC and attempt to extract the
			// base register for the memory operand.  As a fallback, map a
			// region around SP (most common cause of data faults).
			const pc = BigInt(this.uc.regRead(this.unicornModule.ARM64_REG.PC));
			let decoded = false;

			try {
				const insnBuf = this.uc.memRead(pc, 4);
				const insn = insnBuf.readUInt32LE(0);
				// ARM64 LDR/STR (unsigned offset): bits [31:22] pattern
				// Base register is in bits [9:5]
				const rn = (insn >> 5) & 0x1F;
				if (rn <= 30) {
					const ARM64_REG = this.unicornModule.ARM64_REG;
					const regMap: Record<number, number> = {};
					for (let r = 0; r <= 28; r++) {
						regMap[r] = (ARM64_REG as unknown as Record<string, number>)[`X${r}`];
					}
					regMap[29] = ARM64_REG.X29; // FP
					regMap[30] = ARM64_REG.X30; // LR
					const baseVal = BigInt(this.uc.regRead(regMap[rn]));
					if (baseVal >= 0x1000n) {
						faultAddr = baseVal;
						decoded = true;
					}
				}
			} catch {
				// Fall through to SP-based fallback
			}

			if (!decoded) {
				// Fallback: use SP as a heuristic for data faults
				faultAddr = BigInt(this.uc.regRead(this.unicornModule.ARM64_REG.SP));
			}
		}

		// Reject NULL page and very high addresses (same as C++ handler)
		if (faultAddr < 0x1000n) {
			return false;
		}
		if (faultAddr > 0x00007FFFFFFFFFFFn) {
			return false;
		}

		const pageSizeBig = BigInt(pageSize);
		const alignedAddr = (faultAddr / pageSizeBig) * pageSizeBig;
		const alignedSize = pageSize; // Map at least one page

		try {
			this.uc.memMap(alignedAddr, alignedSize, PROT.ALL);
		} catch {
			// memMap failed (e.g., already mapped, OOM) — unrecoverable
			return false;
		}

		// Notify the JS memory fault handler for tracking
		if (this.memoryFaultHandler) {
			const type = errCode === 8 ? 16 : (errCode === 6 ? 19 : 20);
			this.memoryFaultHandler(type, faultAddr, 0, 0n);
		}

		return true; // Fault handled, caller should retry the instruction
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
	 * Set handler for interrupts (syscalls).
	 *
	 * For ARM64, only the JS callback is stored — no native INTR hook is
	 * installed.  ARM64 uses synchronous stepped execution where SVC
	 * instructions are detected by opcode inspection and the handler is
	 * called directly from the JS loop.  Installing the native INTR hook
	 * (which uses TSFN BlockingCall) triggers STATUS_STACK_BUFFER_OVERRUN
	 * (0xC0000409) inside Electron's UtilityProcess extension host because
	 * BlockingCall cannot safely marshal between the Unicorn thread and the
	 * main thread in that environment.
	 */
	setInterruptHandler(handler: InterruptCallback): void {
		this.interruptHandler = handler;

		if (!this.uc || !this.unicornModule) {
			return;
		}

		// ARM64: skip native INTR hook entirely — the sync execution path
		// in startArm64Sync / runSyncSteppedArm64 handles SVC inline.
		// For worker mode, startArm64Worker handles it.
		if (this.architecture === 'arm64') {
			return;
		}

		const HOOK = this.unicornModule.HOOK;
		// The native InterruptHookCB uses BlockingCall, so this callback runs
		// synchronously while the Unicorn thread is paused. Direct regWrite
		// calls are safe here (no need for deferred writes).
		const intrHook = this.uc.hookAdd(HOOK.INTR, (intno: number) => {
			this._insideBlockingHook = true;
			try {
				if (this.interruptHandler) {
					this.interruptHandler(intno);
				}
			} finally {
				this._insideBlockingHook = false;
			}
		});
		this.activeHookHandles.push(intrHook);
		this._intrHookInstalled = true;
	}

	/**
	 * Set async handler for interrupts (ARM64 worker mode).
	 * This handler is used by startArm64Worker where we can await async operations.
	 */
	setAsyncInterruptHandler(handler: AsyncInterruptCallback): void {
		this._interruptHandlerAsync = handler;
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
	async loadCode(code: Buffer, baseAddress: bigint): Promise<void> {
		if (this._arm64Worker) {
			const pageSize = BigInt(this._arm64Worker.getPageSize());
			const alignedBase = (baseAddress / pageSize) * pageSize;
			const alignedSize = Math.ceil(code.length / Number(pageSize)) * Number(pageSize);
			await this._arm64Worker.memMap(alignedBase, alignedSize, this.unicornModule!.PROT.ALL);
			await this._arm64Worker.memWrite(baseAddress, code);
			console.log(`Loaded ${code.length} bytes at 0x${baseAddress.toString(16)} (worker)`);
			return;
		}

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
	async mapMemory(address: bigint, size: number, permissions: 'r' | 'w' | 'x' | 'rw' | 'rx' | 'rwx'): Promise<void> {
		const perms = this.parsePermissions(permissions);
		if (this._arm64Worker) {
			const pageSize = BigInt(this._arm64Worker.getPageSize());
			const alignedBase = (address / pageSize) * pageSize;
			const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);
			await this._arm64Worker.memMap(alignedBase, alignedSize, perms);
			return;
		}

		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		const pageSize = BigInt(this.uc.pageSize);
		const alignedBase = (address / pageSize) * pageSize;
		const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);

		this.uc.memMap(alignedBase, alignedSize, perms);
	}

	/**
	 * Map memory with numeric permissions (Unicorn PROT_* values)
	 */
	async mapMemoryRaw(address: bigint, size: number, perms: number): Promise<void> {
		if (this._arm64Worker) {
			const pageSize = BigInt(this._arm64Worker.getPageSize());
			const alignedBase = (address / pageSize) * pageSize;
			const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);
			await this._arm64Worker.memMap(alignedBase, alignedSize, perms);
			return;
		}

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
	async memProtect(address: bigint, size: number, perms: number): Promise<void> {
		if (this._arm64Worker) {
			await this._arm64Worker.memProtect(address, size, perms);
			return;
		}
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
	async setupStack(stackBase: bigint, stackSize: number = 0x100000): Promise<void> {
		if (this._arm64Worker) {
			const PROT = this.unicornModule!.PROT;
			await this._arm64Worker.memMap(stackBase, stackSize, PROT.READ | PROT.WRITE);

			// ARM64 doesn't push return addresses (uses LR), so just set SP
			let sp = stackBase + BigInt(stackSize) - 0x1000n;
			sp = (sp / 16n) * 16n;
			await this._arm64Worker.regWrite(this.unicornModule!.ARM64_REG.SP, sp);
			return;
		}

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
		if (!this.uc && !this._arm64Worker) {
			throw new Error('Unicorn not initialized');
		}

		// ARM64 worker mode: use worker's executeBatch for emulation
		if (this._arm64Worker) {
			await this.startArm64Worker(startAddress, endAddress, count);
			return;
		}

		// ARM64 in-process sync mode (fallback, should not be reached with worker)
		if (this.architecture === 'arm64') {
			this.startArm64Sync(startAddress, endAddress, count);
			return;
		}

		this._stopRequested = false;
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
		const hookHandle = this.uc!.hookAdd(HOOK.CODE, (addr: bigint, size: number) => {
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
					await this.uc!.emuStartAsync(currentStart, endAddress, timeout, count);
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
			try { this.uc!.hookDel(hookHandle); } catch { }
		}
	}

	/**
	 * ARM64 worker-based execution for start/step/continue.
	 *
	 * Runs emulation in the worker process using executeBatch(), with
	 * breakpoints, code hooks (API interception), and SVC syscall dispatch
	 * handled on the host side between batches.
	 *
	 * The worker executes a batch of instructions, returning when it
	 * encounters an SVC, terminal address, or the batch limit. The host
	 * dispatches syscalls, checks breakpoints, and sends the next batch.
	 */
	private async startArm64Worker(startAddress: bigint, endAddress: bigint, count: number): Promise<void> {
		if (!this._arm64Worker || !this.unicornModule) {
			throw new Error('ARM64 worker not initialized');
		}

		this._stopRequested = false;
		this.state.isRunning = false; // Not using async Unicorn; no deferred writes
		this.state.isPaused = false;
		this.state.isReady = true;
		this.state.currentAddress = startAddress;

		const SVC_MASK = 0xFFE0001F;
		const SVC_VALUE = 0xD4000001;
		const maxInstructions = count > 0 ? count : 250000;
		const batchSize = count === 1 ? 1 : Math.min(1000, maxInstructions);
		const terminalAddresses = [0n, 0xDEAD0000n, 0xDEADDEADn, 0xDEADDEADDEADDEADn];
		if (endAddress !== 0n) {
			terminalAddresses.push(endAddress);
		}

		let totalExecuted = 0;
		let isFirstInstruction = true;
		let currentPc = startAddress;

		try {
			while (totalExecuted < maxInstructions) {
				if (this._stopRequested) {
					break;
				}

				// Read PC from worker
				const ARM64_REG = this.unicornModule.ARM64_REG;
				currentPc = await this._arm64Worker.regRead(ARM64_REG.PC) as bigint;
				this.state.currentAddress = currentPc;

				// Breakpoint check (skip on first instruction)
				if (this.breakpoints.has(currentPc) && !isFirstInstruction) {
					this.state.isPaused = true;
					return;
				}
				isFirstInstruction = false;

				// Fire code hooks (API interception) before executing
				this._apiHookRedirected = false;
				this.codeHooks.forEach(cb => cb(currentPc, 4));
				if (this._apiHookRedirected) {
					// API interceptor redirected — read new PC from worker
					isFirstInstruction = true;
					continue;
				}

				// Execute a batch in the worker
				const remaining = maxInstructions - totalExecuted;
				const thisBatch = Math.min(batchSize, remaining);

				const result = await this._arm64Worker.executeBatch(
					currentPc, thisBatch, SVC_MASK, SVC_VALUE, terminalAddresses
				);

				totalExecuted += result.instructionsExecuted;
				this.state.instructionsExecuted += result.instructionsExecuted;
				this.state.currentAddress = result.pc;

				if (result.error) {
					this.state.lastError = result.error;
					break;
				}

				if (result.stopped) {
					// Terminal address reached
					break;
				}

				if (result.svcEncountered) {
					// SVC detected — dispatch syscall handler on the host side.
					// For ARM64 worker mode, we use the async interrupt handler
					// (interruptHandlerAsync) if available, otherwise fall back
					// to the sync handler (which may not work with async register ops).
					if (this._interruptHandlerAsync) {
						await this._interruptHandlerAsync(2);
					} else if (this.interruptHandler) {
						this.interruptHandler(2);
					}
					// Advance PC past SVC (4 bytes)
					await this._arm64Worker.regWrite(ARM64_REG.PC, result.pc + 4n);

					if (this._stopRequested) {
						break;
					}
					// Continue with the next batch
					continue;
				}
			}
		} finally {
			// Sync the final PC
			if (this._arm64Worker) {
				try {
					const ARM64_REG = this.unicornModule!.ARM64_REG;
					const finalPc = await this._arm64Worker.regRead(ARM64_REG.PC) as bigint;
					this.state.currentAddress = finalPc;
				} catch {
					// Worker may have exited
				}
			}
			this.state.isPaused = true;
		}
	}

	/**
	 * ARM64 synchronous execution for start/step/continue (in-process fallback).
	 *
	 * Same approach as runSyncSteppedArm64 but also handles breakpoints and
	 * code hooks (API interception). Each instruction is executed with sync
	 * emuStart(count=1), followed by SVC detection and interrupt dispatch.
	 *
	 * No native hooks (INTR or MEM_UNMAPPED) are installed for ARM64 — both
	 * use TSFN which crashes in Electron's UtilityProcess.  SVC is handled
	 * inline; memory faults are caught as emuStart exceptions and handled
	 * via handleArm64MemoryFault.
	 */
	private startArm64Sync(startAddress: bigint, endAddress: bigint, count: number): void {
		if (!this.uc || !this.unicornModule) {
			throw new Error('Unicorn not initialized');
		}

		this._stopRequested = false;

		this.state.isRunning = false; // sync mode — no deferred writes needed
		this.state.isPaused = false;
		this.state.isReady = true;
		this.state.currentAddress = startAddress;

		const ARM64_REG = this.unicornModule.ARM64_REG;
		const SVC_MASK = 0xFFE0001F;
		const SVC_VALUE = 0xD4000001;
		const maxInstructions = count > 0 ? count : 250000;
		let isFirstInstruction = true;

		try {
			for (let i = 0; i < maxInstructions; i++) {
				// Check if stop was requested (e.g., exit/exit_group syscall)
				if (this._stopRequested) {
					break;
				}

				const pcBefore = BigInt(this.uc.regRead(ARM64_REG.PC));
				this.state.currentAddress = pcBefore;

				// Breakpoint check (skip on first instruction to allow continue-from-breakpoint)
				if (this.breakpoints.has(pcBefore) && !isFirstInstruction) {
					this.state.isPaused = true;
					return;
				}
				isFirstInstruction = false;

				// Fire code hooks (API interception)
				this._apiHookRedirected = false;
				this.codeHooks.forEach(cb => cb(pcBefore, 4));
				if (this._apiHookRedirected) {
					// API interceptor redirected execution — sync PC and restart
					this.syncCurrentAddress();
					isFirstInstruction = true;
					continue;
				}

				// Terminal address check
				if (pcBefore === 0n || pcBefore === 0xDEAD0000n ||
					pcBefore === 0xDEADDEADn || pcBefore === 0xDEADDEADDEADDEADn) {
					break;
				}

				// End address check
				if (endAddress !== 0n && pcBefore === endAddress) {
					break;
				}

				// Read instruction before executing
				let insn = 0;
				try {
					const insnBuf = this.uc.memRead(pcBefore, 4);
					insn = insnBuf.readUInt32LE(0);
				} catch { /* let emuStart handle unmapped memory */ }

				// Check if the instruction is SVC BEFORE executing it.
				// Without an INTR hook, Unicorn raises UC_ERR_EXCEPTION for SVC
				// and does NOT advance PC. We detect this, dispatch the syscall
				// handler directly, and advance PC manually (+4 bytes).
				const isSvc = (insn & SVC_MASK) === SVC_VALUE;

				if (isSvc) {
					// Do NOT call emuStart for SVC — it throws UC_ERR_EXCEPTION.
					// Dispatch the interrupt handler directly and advance PC.
					this.state.instructionsExecuted++;
					if (this.interruptHandler) {
						this.interruptHandler(2);
					}
					// Advance PC past the SVC instruction (4 bytes)
					this.uc.regWrite(ARM64_REG.PC, pcBefore + 4n);
					if (this._stopRequested) {
						break;
					}
				} else {
					// Execute 1 instruction synchronously
					try {
						this.uc.emuStart(pcBefore, 0n, 0, 1);
					} catch (error: unknown) {
						// Handle memory faults (no native hook for ARM64)
						if (this.handleArm64MemoryFault(error)) {
							// Page was mapped — retry the same instruction
							i--;
							continue;
						}
						this.state.lastError = toErrorMessage(error);
						break;
					}
					this.state.instructionsExecuted++;
				}

				// Handle SVC is already done above; just sync PC
				this.syncCurrentAddress();
			}
		} finally {
			this.syncCurrentAddress();
			this.state.isPaused = true;
			// ARM64 never installs the native INTR hook (see setInterruptHandler),
			// so no cleanup is needed here.
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
	 * For ARM64 worker mode, this is a no-op (PC is synced in startArm64Worker).
	 */
	private syncCurrentAddress(): void {
		if (!this.uc || !this.unicornModule) { return; }
		// ARM64 worker: PC is synced in startArm64Worker, skip
		if (this._arm64Worker) { return; }

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
	 * Run N instructions with minimal overhead.
	 * Used for headless/diagnostic runs.
	 *
	 * For ARM64, uses synchronous stepped execution to avoid a fatal crash:
	 * emuStartAsync runs Unicorn in a worker thread, and the INTR hook uses
	 * BlockingCall (TSFN) to dispatch syscalls to the JS main thread. On
	 * Windows, this combination triggers STATUS_STACK_BUFFER_OVERRUN (0xC0000409)
	 * inside the Unicorn DLL's ARM64 TCG backend.  The fix is to run ARM64
	 * instructions one-by-one via synchronous emuStart(count=1) on the main
	 * thread — with the INTR hook temporarily removed — and detect SVC
	 * instructions by inspecting the opcode after each step.
	 *
	 * For other architectures, uses emuStartAsync so the event loop stays
	 * free for TSFN-based hook callbacks.
	 */
	async runSync(startAddress: bigint, count: number, timeout: number = 0): Promise<void> {
		if (!this.uc && !this._arm64Worker) {
			throw new Error('Unicorn not initialized');
		}

		// ARM64 worker: delegate to startArm64Worker (same batch-based approach)
		if (this._arm64Worker) {
			await this.startArm64Worker(startAddress, 0n, count);
			return;
		}

		// ARM64: use synchronous stepped execution to avoid TSFN/threading crash
		if (this.architecture === 'arm64') {
			this.runSyncSteppedArm64(startAddress, count);
			return;
		}

		this.state.isRunning = true;
		this.state.isPaused = false;
		this.state.currentAddress = startAddress;
		this.deferredMemoryWrites = [];
		this.deferredRegisterWrites.clear();

		try {
			await this.uc!.emuStartAsync(startAddress, 0n, timeout, count);
		} catch (error: unknown) {
			this.state.lastError = toErrorMessage(error);
			throw error;
		} finally {
			this.applyDeferredMutations();
			this.syncCurrentAddress();
			this.state.isRunning = false;
			this.state.isPaused = true;
		}
	}

	/**
	 * ARM64 synchronous stepped execution.
	 *
	 * Runs exactly `count` instructions (or fewer if emulation terminates)
	 * using sync emuStart(count=1) in a loop.  SVC instructions are detected
	 * by reading the 4-byte opcode at the current PC and calling the
	 * interruptHandler directly (no native INTR hook is installed for ARM64).
	 *
	 * No native memory fault hook is installed for ARM64 either — both TSFN
	 * types (BlockingCall and NonBlockingCall) crash Electron's UtilityProcess.
	 * Memory faults are caught as emuStart exceptions and handled in JS via
	 * handleArm64MemoryFault.
	 */
	private runSyncSteppedArm64(startAddress: bigint, count: number): void {
		if (!this.uc || !this.unicornModule) {
			throw new Error('Unicorn not initialized');
		}

		this._stopRequested = false;

		this.state.isRunning = false; // Not using async, so no deferred writes needed
		this.state.isPaused = false;
		this.state.currentAddress = startAddress;

		const ARM64_REG = this.unicornModule.ARM64_REG;
		// ARM64 SVC #0 opcode: 0xD4000001
		// General SVC mask: (insn & 0xFFE0001F) === 0xD4000001
		const SVC_MASK = 0xFFE0001F;
		const SVC_VALUE = 0xD4000001;

		try {
			for (let i = 0; i < count; i++) {
				// Check if stop was requested (e.g., exit/exit_group syscall)
				if (this._stopRequested) {
					break;
				}

				const pcBefore = BigInt(this.uc.regRead(ARM64_REG.PC));

				// Check for terminal addresses before executing
				if (pcBefore === 0n || pcBefore === 0xDEAD0000n ||
					pcBefore === 0xDEADDEADn || pcBefore === 0xDEADDEADDEADDEADn) {
					break;
				}

				// Read the 4-byte instruction at current PC BEFORE executing it.
				// If the memory is unmapped, the C++ fault handler auto-maps it.
				let insn = 0;
				try {
					const insnBuf = this.uc.memRead(pcBefore, 4);
					insn = insnBuf.readUInt32LE(0);
				} catch {
					// Cannot read instruction — memory may be unmapped.
					// Let emuStart handle it (will trigger fault hook).
				}

				// Check if the instruction is SVC BEFORE executing it.
				// Without an INTR hook, Unicorn raises UC_ERR_EXCEPTION for SVC
				// and does NOT advance PC. We detect this case, dispatch the
				// syscall handler directly, and advance PC manually (+4 bytes).
				const isSvc = (insn & SVC_MASK) === SVC_VALUE;

				if (isSvc) {
					// Do NOT call emuStart for SVC — it would throw UC_ERR_EXCEPTION.
					// Dispatch the interrupt handler directly and advance PC.
					this.state.instructionsExecuted++;
					if (this.interruptHandler) {
						this.interruptHandler(2);
					}
					// Advance PC past the SVC instruction (4 bytes)
					this.uc.regWrite(ARM64_REG.PC, pcBefore + 4n);
					if (this._stopRequested) {
						break;
					}
				} else {
					// Execute exactly 1 instruction synchronously
					try {
						this.uc.emuStart(pcBefore, 0n, 0, 1);
					} catch (error: unknown) {
						// Handle memory faults (no native hook for ARM64)
						if (this.handleArm64MemoryFault(error)) {
							// Page was mapped — retry the same instruction
							i--;
							continue;
						}
						this.state.lastError = toErrorMessage(error);
						break;
					}
					this.state.instructionsExecuted++;
				}

				// Sync PC after execution + possible handler changes
				this.syncCurrentAddress();
			}
		} finally {
			this.syncCurrentAddress();
			this.state.isPaused = true;
			// ARM64 never installs the native INTR hook — SVC is handled inline.
		}
	}

	/**
	 * Find the index of the INTR hook handle in activeHookHandles.
	 * The INTR hook is added by setInterruptHandler and is always the last entry
	 * pushed to activeHookHandles after the memory fault hooks.
	 */
	private findIntrHookIndex(): number {
		// The INTR hook is the last one added (after the mem fault hook in initialize()).
		// Memory fault hook is always at index 0 (added first in installMemoryFaultHooks).
		// INTR hook is at index 1+ (added later by setInterruptHandler).
		// Return the last index since INTR is added last.
		if (this.activeHookHandles.length > 1) {
			return this.activeHookHandles.length - 1;
		}
		return -1;
	}

	/**
	 * Re-install the TSFN-based INTR hook for async execution.
	 * Called after ARM64 sync stepping completes.
	 */
	private reinstallIntrHook(): void {
		if (!this.uc || !this.unicornModule || !this.interruptHandler) {
			return;
		}

		// Avoid double-install
		if (this._intrHookInstalled) {
			return;
		}

		const HOOK = this.unicornModule.HOOK;
		const handler = this.interruptHandler;

		try {
			const intrHook = this.uc.hookAdd(HOOK.INTR, (intno: number) => {
				this._insideBlockingHook = true;
				try {
					handler(intno);
				} finally {
					this._insideBlockingHook = false;
				}
			});
			this.activeHookHandles.push(intrHook);
			this._intrHookInstalled = true;
		} catch (error: unknown) {
			console.warn(`[unicorn] Failed to reinstall INTR hook: ${toErrorMessage(error)}`);
		}
	}

	/**
	 * Step one instruction.
	 * Uses count=1 in emuStart to execute exactly one instruction natively.
	 * Does NOT use stepMode flag (which would prevent the instruction from running).
	 */
	async step(): Promise<void> {
		if (!this.uc && !this._arm64Worker) {
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
		if (!this.uc && !this._arm64Worker) {
			throw new Error('Unicorn not initialized');
		}

		this.state.isPaused = false;
		await this.start(this.state.currentAddress);
	}

	/**
	 * Stop emulation
	 */
	stop(): void {
		this._stopRequested = true;
		if (this._arm64Worker) {
			// Worker uses _stopRequested flag; also try emuStop in worker
			this._arm64Worker.emuStop().catch(() => { /* ignore */ });
		}
		if (this.uc) {
			this.uc.emuStop();
		}
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
	async readMemory(address: bigint, size: number): Promise<Buffer> {
		if (this._arm64Worker) {
			return await this._arm64Worker.memRead(address, size);
		}
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}
		return this.uc.memRead(address, size);
	}

	/**
	 * Read memory synchronously (for in-process x86/x64 hook callbacks only).
	 * Must NOT be called when using the ARM64 worker.
	 */
	readMemorySync(address: bigint, size: number): Buffer {
		if (this._arm64Worker) {
			throw new Error('readMemorySync cannot be used with ARM64 worker');
		}
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}
		return this.uc.memRead(address, size);
	}

	/**
	 * Write memory
	 */
	async writeMemory(address: bigint, data: Buffer): Promise<void> {
		if (this._arm64Worker) {
			await this._arm64Worker.memWrite(address, data);
			return;
		}

		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		if (this.state.isRunning && !this._insideBlockingHook) {
			// Buffer may be reused by caller; clone to avoid mutation races.
			this.deferredMemoryWrites.push({ address, data: Buffer.from(data) });
			return;
		}

		this.uc.memWrite(address, data);
	}

	/**
	 * Write memory synchronously (for in-process x86/x64 hook callbacks only).
	 * Must NOT be called when using the ARM64 worker.
	 */
	writeMemorySync(address: bigint, data: Buffer): void {
		if (this._arm64Worker) {
			throw new Error('writeMemorySync cannot be used with ARM64 worker');
		}
		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		if (this.state.isRunning && !this._insideBlockingHook) {
			this.deferredMemoryWrites.push({ address, data: Buffer.from(data) });
			return;
		}

		this.uc.memWrite(address, data);
	}

	/**
	 * Set register synchronously (for in-process x86/x64 hook callbacks only).
	 * Must NOT be called when using the ARM64 worker.
	 */
	setRegisterSync(name: string, value: bigint | number): void {
		if (this._arm64Worker) {
			throw new Error('setRegisterSync cannot be used with ARM64 worker');
		}

		const regName = name.toLowerCase();

		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		if (this.state.isRunning && !this._insideBlockingHook) {
			this.deferredRegisterWrites.set(regName, value);
			return;
		}

		this.setRegisterImmediate(regName, value);
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
	async getRegistersArm64(): Promise<Arm64Registers> {
		if (this._arm64Worker) {
			return await this._arm64Worker.readAllRegisters();
		}

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
	async setRegister(name: string, value: bigint | number): Promise<void> {
		const regName = name.toLowerCase();

		if (this._arm64Worker) {
			// Route to worker for ARM64
			const ARM64_REG = this.unicornModule!.ARM64_REG;
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
			const regId = arm64Regs[regName];
			if (regId === undefined) {
				throw new Error(`Unknown ARM64 register: ${regName}`);
			}
			await this._arm64Worker.regWrite(regId, BigInt(value));
			return;
		}

		if (!this.uc) {
			throw new Error('Unicorn not initialized');
		}

		// During blocking hook callbacks the Unicorn thread is paused, so
		// direct regWrite is safe even though isRunning is true.
		if (this.state.isRunning && !this._insideBlockingHook) {
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
	async getMemoryRegions(): Promise<MemoryRegion[]> {
		if (this._arm64Worker) {
			const PROT = this.unicornModule!.PROT;
			const regions = await this._arm64Worker.memRegions();
			return regions.map(region => {
				let perms = '';
				if (region.perms & PROT.READ) { perms += 'r'; }
				if (region.perms & PROT.WRITE) { perms += 'w'; }
				if (region.perms & PROT.EXEC) { perms += 'x'; }
				return {
					address: region.begin,
					size: region.end - region.begin,
					permissions: perms || '---'
				};
			});
		}

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
		if (this._arm64Worker) {
			return this._arm64Worker.getPageSize();
		}
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
	async saveState(): Promise<void> {
		if (this._arm64Worker) {
			if (this._workerContextId !== undefined) {
				await this._arm64Worker.contextFree(this._workerContextId);
			}
			this._workerContextId = await this._arm64Worker.contextSave();
			return;
		}
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
	async restoreState(): Promise<void> {
		if (this._arm64Worker) {
			if (this._workerContextId === undefined) {
				throw new Error('No saved state');
			}
			await this._arm64Worker.contextRestore(this._workerContextId);
			return;
		}
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
		return this.initialized && (this.uc !== undefined || this._arm64Worker !== undefined);
	}

	getLastError(): string | undefined {
		return this.lastError;
	}

	/**
	 * Close and cleanup
	 */
	dispose(): void {
		// Dispose ARM64 worker if active
		if (this._arm64Worker) {
			this._arm64Worker.dispose();
			this._arm64Worker = undefined;
			this._workerContextId = undefined;
		}

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
		this._stopRequested = false;
		this._intrHookInstalled = false;
	}
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}
