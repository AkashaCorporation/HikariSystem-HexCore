/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Unicorn Emulation Wrapper
 *  CPU emulation interface using Unicorn Engine
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';

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
}

interface Arm64RegConstants {
	X0: number; X1: number; X2: number; X3: number;
	X4: number; X5: number; X6: number; X7: number;
	SP: number; PC: number; LR: number; FP: number;
	NZCV: number;
}

// Emulation state
export interface EmulationState {
	isRunning: boolean;
	isPaused: boolean;
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
export type MemoryHookCallback = (type: string, address: bigint, size: number, value: bigint) => void;

export type ArchitectureType = 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'riscv';

export class UnicornWrapper {
	private unicornModule?: UnicornModule;
	private uc?: UnicornInstance;
	private architecture: ArchitectureType = 'x64';
	private state: EmulationState = {
		isRunning: false,
		isPaused: false,
		currentAddress: 0n,
		instructionsExecuted: 0
	};
	private codeHooks: Map<number, CodeHookCallback> = new Map();
	private memoryHooks: Map<number, MemoryHookCallback> = new Map();
	private breakpoints: Set<bigint> = new Set();
	private savedContext?: UnicornContext;
	private stepMode: boolean = false;

	/**
	 * Initialize the Unicorn engine
	 */
	async initialize(arch: ArchitectureType): Promise<void> {
		this.architecture = arch;

		// Try to load hexcore-unicorn from the extensions folder
		const possiblePaths = [
			path.join(__dirname, '..', '..', 'hexcore-unicorn'),
			path.join(__dirname, '..', '..', '..', 'hexcore-unicorn'),
			'hexcore-unicorn'
		];

		for (const modulePath of possiblePaths) {
			try {
				this.unicornModule = require(modulePath) as UnicornModule;
				break;
			} catch {
				continue;
			}
		}

		if (!this.unicornModule) {
			throw new Error('Failed to load hexcore-unicorn module');
		}

		const { arch: ucArch, mode } = this.getArchMode(arch);
		this.uc = new this.unicornModule.Unicorn(ucArch, mode);

		console.log(`Unicorn initialized: ${arch} (version: ${this.unicornModule.version().string})`);
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
		if (!this.uc) throw new Error('Unicorn not initialized');

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
		if (!this.uc) throw new Error('Unicorn not initialized');

		const PROT = this.unicornModule!.PROT;
		let perms = 0;
		if (permissions.includes('r')) perms |= PROT.READ;
		if (permissions.includes('w')) perms |= PROT.WRITE;
		if (permissions.includes('x')) perms |= PROT.EXEC;

		const pageSize = BigInt(this.uc.pageSize);
		const alignedBase = (address / pageSize) * pageSize;
		const alignedSize = Math.ceil(size / Number(pageSize)) * Number(pageSize);

		this.uc.memMap(alignedBase, alignedSize, perms);
	}

	/**
	 * Set up stack for emulation
	 */
	setupStack(stackBase: bigint, stackSize: number = 0x100000): void {
		if (!this.uc) throw new Error('Unicorn not initialized');

		const PROT = this.unicornModule!.PROT;
		this.uc.memMap(stackBase, stackSize, PROT.READ | PROT.WRITE);

		// Set stack pointer to middle of stack
		const sp = stackBase + BigInt(stackSize / 2);
		this.setStackPointer(sp);
	}

	/**
	 * Set stack pointer based on architecture
	 */
	private setStackPointer(sp: bigint): void {
		if (!this.uc) return;

		const X86_REG = this.unicornModule!.X86_REG;
		const ARM64_REG = this.unicornModule!.ARM64_REG;

		switch (this.architecture) {
			case 'x64':
				this.uc.regWrite(X86_REG.RSP, sp);
				break;
			case 'x86':
				this.uc.regWrite(X86_REG.ESP, Number(sp));
				break;
			case 'arm64':
				this.uc.regWrite(ARM64_REG.SP, sp);
				break;
		}
	}

	/**
	 * Start emulation
	 */
	async start(startAddress: bigint, endAddress: bigint = 0n, timeout: number = 0, count: number = 0): Promise<void> {
		if (!this.uc) throw new Error('Unicorn not initialized');

		this.state.isRunning = true;
		this.state.isPaused = false;
		this.state.currentAddress = startAddress;
		this.state.instructionsExecuted = 0;

		// Add code hook for tracking
		const HOOK = this.unicornModule!.HOOK;
		const hookHandle = this.uc.hookAdd(HOOK.CODE, (addr: bigint, size: number) => {
			this.state.currentAddress = addr;
			this.state.instructionsExecuted++;

			// Check for breakpoints
			if (this.breakpoints.has(addr)) {
				this.uc!.emuStop();
				this.state.isPaused = true;
			}

			// Step mode - stop after each instruction
			if (this.stepMode) {
				this.uc!.emuStop();
				this.state.isPaused = true;
			}

			// Notify hooks
			this.codeHooks.forEach(cb => cb(addr, size));
		});

		try {
			await this.uc.emuStartAsync(startAddress, endAddress, timeout, count);
		} catch (error: any) {
			this.state.lastError = error.message;
			throw error;
		} finally {
			this.state.isRunning = false;
			this.uc.hookDel(hookHandle);
		}
	}

	/**
	 * Step one instruction
	 */
	async step(): Promise<void> {
		if (!this.uc) throw new Error('Unicorn not initialized');

		const currentAddr = this.state.currentAddress;
		this.stepMode = true;
		try {
			await this.start(currentAddr, 0n, 0, 1);
		} finally {
			this.stepMode = false;
		}
	}

	/**
	 * Continue execution
	 */
	async continue(): Promise<void> {
		if (!this.uc) throw new Error('Unicorn not initialized');

		this.state.isPaused = false;
		this.stepMode = false;
		await this.start(this.state.currentAddress);
	}

	/**
	 * Stop emulation
	 */
	stop(): void {
		if (!this.uc) return;
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
		if (!this.uc) throw new Error('Unicorn not initialized');
		return this.uc.memRead(address, size);
	}

	/**
	 * Write memory
	 */
	writeMemory(address: bigint, data: Buffer): void {
		if (!this.uc) throw new Error('Unicorn not initialized');
		this.uc.memWrite(address, data);
	}

	/**
	 * Get x86-64 registers
	 */
	getRegistersX64(): X86_64Registers {
		if (!this.uc) throw new Error('Unicorn not initialized');

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
		if (!this.uc) throw new Error('Unicorn not initialized');

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
		if (!this.uc) throw new Error('Unicorn not initialized');

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
			sp: BigInt(this.uc.regRead(REG.SP)),
			pc: BigInt(this.uc.regRead(REG.PC)),
			lr: BigInt(this.uc.regRead(REG.LR)),
			fp: BigInt(this.uc.regRead(REG.FP)),
			nzcv: BigInt(this.uc.regRead(REG.NZCV))
		};
	}

	/**
	 * Set register value
	 */
	setRegister(name: string, value: bigint | number): void {
		if (!this.uc) throw new Error('Unicorn not initialized');

		const X86_REG = this.unicornModule!.X86_REG;
		const ARM64_REG = this.unicornModule!.ARM64_REG;

		// x86-64 registers
		const x86Regs: Record<string, number> = {
			'rax': X86_REG.RAX, 'rbx': X86_REG.RBX, 'rcx': X86_REG.RCX, 'rdx': X86_REG.RDX,
			'rsi': X86_REG.RSI, 'rdi': X86_REG.RDI, 'rbp': X86_REG.RBP, 'rsp': X86_REG.RSP,
			'r8': X86_REG.R8, 'r9': X86_REG.R9, 'r10': X86_REG.R10, 'r11': X86_REG.R11,
			'r12': X86_REG.R12, 'r13': X86_REG.R13, 'r14': X86_REG.R14, 'r15': X86_REG.R15,
			'rip': X86_REG.RIP, 'rflags': X86_REG.RFLAGS,
			'eax': X86_REG.EAX, 'ebx': X86_REG.EBX, 'ecx': X86_REG.ECX, 'edx': X86_REG.EDX,
			'esi': X86_REG.ESI, 'edi': X86_REG.EDI, 'ebp': X86_REG.EBP, 'esp': X86_REG.ESP,
			'eip': X86_REG.EIP, 'eflags': X86_REG.EFLAGS
		};

		// ARM64 registers
		const arm64Regs: Record<string, number> = {
			'x0': ARM64_REG.X0, 'x1': ARM64_REG.X1, 'x2': ARM64_REG.X2, 'x3': ARM64_REG.X3,
			'x4': ARM64_REG.X4, 'x5': ARM64_REG.X5, 'x6': ARM64_REG.X6, 'x7': ARM64_REG.X7,
			'sp': ARM64_REG.SP, 'pc': ARM64_REG.PC, 'lr': ARM64_REG.LR, 'fp': ARM64_REG.FP
		};

		const regName = name.toLowerCase();
		if (x86Regs[regName] !== undefined) {
			this.uc.regWrite(x86Regs[regName], value);
		} else if (arm64Regs[regName] !== undefined) {
			this.uc.regWrite(arm64Regs[regName], value);
		} else {
			throw new Error(`Unknown register: ${name}`);
		}
	}

	/**
	 * Get mapped memory regions
	 */
	getMemoryRegions(): MemoryRegion[] {
		if (!this.uc) return [];

		const PROT = this.unicornModule!.PROT;
		return this.uc.memRegions().map(region => {
			let perms = '';
			if (region.perms & PROT.READ) perms += 'r';
			if (region.perms & PROT.WRITE) perms += 'w';
			if (region.perms & PROT.EXEC) perms += 'x';

			return {
				address: region.begin,
				size: region.end - region.begin,
				permissions: perms || '---'
			};
		});
	}

	/**
	 * Save current state (snapshot)
	 */
	saveState(): void {
		if (!this.uc) throw new Error('Unicorn not initialized');

		if (this.savedContext) {
			this.savedContext.free();
		}
		this.savedContext = this.uc.contextSave();
	}

	/**
	 * Restore saved state
	 */
	restoreState(): void {
		if (!this.uc || !this.savedContext) throw new Error('No saved state');
		this.uc.contextRestore(this.savedContext);
	}

	/**
	 * Get emulation state
	 */
	getState(): EmulationState {
		return { ...this.state };
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
		return this.uc !== undefined;
	}

	/**
	 * Close and cleanup
	 */
	dispose(): void {
		if (this.savedContext) {
			this.savedContext.free();
			this.savedContext = undefined;
		}
		if (this.uc) {
			this.uc.close();
			this.uc = undefined;
		}
		this.codeHooks.clear();
		this.memoryHooks.clear();
		this.breakpoints.clear();
	}
}
