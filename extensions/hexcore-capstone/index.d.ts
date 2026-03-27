/**
 * HexCore Capstone - TypeScript Definitions
 * Modern N-API bindings for Capstone disassembler engine
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

/// <reference types="node" />

/**
 * Architecture constants
 */
export const ARCH: {
	readonly ARM: number;
	readonly ARM64: number;
	readonly MIPS: number;
	readonly X86: number;
	readonly PPC: number;
	readonly SPARC: number;
	readonly SYSZ: number;
	readonly XCORE: number;
	readonly M68K: number;
	readonly TMS320C64X: number;
	readonly M680X: number;
	readonly EVM: number;
	readonly WASM?: number;
	readonly BPF?: number;
	readonly RISCV?: number;
};

/**
 * Mode constants
 */
export const MODE: {
	readonly LITTLE_ENDIAN: number;
	readonly BIG_ENDIAN: number;
	readonly ARM: number;
	readonly THUMB: number;
	readonly MCLASS: number;
	readonly V8: number;
	readonly MODE_16: number;
	readonly MODE_32: number;
	readonly MODE_64: number;
	readonly MICRO: number;
	readonly MIPS3: number;
	readonly MIPS32R6: number;
	readonly MIPS2: number;
	readonly V9: number;
	readonly QPX: number;
	readonly M68K_000: number;
	readonly M68K_010: number;
	readonly M68K_020: number;
	readonly M68K_030: number;
	readonly M68K_040: number;
	readonly M68K_060: number;
	readonly RISCV32?: number;
	readonly RISCV64?: number;
	readonly RISCVC?: number;
};

/**
 * Option type constants
 */
export const OPT: {
	readonly SYNTAX: number;
	readonly DETAIL: number;
	readonly MODE: number;
	readonly MEM: number;
	readonly SKIPDATA: number;
	readonly SKIPDATA_SETUP: number;
	readonly MNEMONIC: number;
	readonly UNSIGNED: number;
};

/**
 * Option value constants
 */
export const OPT_VALUE: {
	readonly OFF: number;
	readonly ON: number;
	readonly SYNTAX_DEFAULT: number;
	readonly SYNTAX_INTEL: number;
	readonly SYNTAX_ATT: number;
	readonly SYNTAX_NOREGNAME: number;
	readonly SYNTAX_MASM: number;
};

/**
 * Error code constants
 */
export const ERR: {
	readonly OK: number;
	readonly MEM: number;
	readonly ARCH: number;
	readonly HANDLE: number;
	readonly CSH: number;
	readonly MODE: number;
	readonly OPTION: number;
	readonly DETAIL: number;
	readonly MEMSETUP: number;
	readonly VERSION: number;
	readonly DIET: number;
	readonly SKIPDATA: number;
	readonly X86_ATT: number;
	readonly X86_INTEL: number;
	readonly X86_MASM: number;
};

/**
 * Memory operand structure
 */
export interface MemoryOperand {
	segment?: number;
	base: number;
	index?: number;
	scale?: number;
	disp: number;
}

/**
 * x86 operand structure
 */
export interface X86Operand {
	type: number;
	size: number;
	access: number;
	avxBcast: number;
	avxZeroOpmask: boolean;
	reg?: number;
	imm?: number;
	mem?: MemoryOperand;
}

/**
 * x86 instruction detail
 */
export interface X86Detail {
	prefix: number[];
	opcode: number[];
	rexPrefix: number;
	addrSize: number;
	modRM: number;
	sib: number;
	disp: number;
	sibIndex: number;
	sibScale: number;
	sibBase: number;
	xopCC: number;
	sseCC: number;
	avxCC: number;
	avxSAE: boolean;
	avxRM: number;
	eflags: number;
	operands: X86Operand[];
}

/**
 * Shift operand structure
 */
export interface ShiftOperand {
	type: number;
	value: number;
}

/**
 * ARM operand structure
 */
export interface ArmOperand {
	type: number;
	access: number;
	reg?: number;
	imm?: number;
	fp?: number;
	mem?: {
		base: number;
		index: number;
		scale: number;
		disp: number;
		lshift: number;
	};
	shift?: ShiftOperand;
	vectorIndex: number;
	subtracted: boolean;
}

/**
 * ARM instruction detail
 */
export interface ArmDetail {
	usermode: boolean;
	vectorSize: number;
	vectorData: number;
	cpsMode: number;
	cpsFlag: number;
	cc: number;
	updateFlags: boolean;
	writeback: boolean;
	memBarrier: number;
	operands: ArmOperand[];
}

/**
 * ARM64 operand structure
 */
export interface Arm64Operand {
	type: number;
	access: number;
	reg?: number;
	imm?: number;
	fp?: number;
	mem?: {
		base: number;
		index: number;
		disp: number;
	};
	shift?: ShiftOperand;
	ext: number;
	vas: number;
	vectorIndex: number;
}

/**
 * ARM64 instruction detail
 */
export interface Arm64Detail {
	cc: number;
	updateFlags: boolean;
	writeback: boolean;
	operands: Arm64Operand[];
}

/**
 * MIPS operand structure
 */
export interface MipsOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		disp: number;
	};
}

/**
 * MIPS instruction detail
 */
export interface MipsDetail {
	operands: MipsOperand[];
}

/**
 * PPC operand structure
 */
export interface PpcOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		disp: number;
	};
	crx?: {
		scale: number;
		reg: number;
		cond: number;
	};
}

/**
 * PPC instruction detail
 */
export interface PpcDetail {
	bc: number;
	bh: number;
	updateCr0: boolean;
	operands: PpcOperand[];
}

/**
 * SPARC operand structure
 */
export interface SparcOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		index: number;
		disp: number;
	};
}

/**
 * SPARC instruction detail
 */
export interface SparcDetail {
	cc: number;
	hint: number;
	operands: SparcOperand[];
}

/**
 * SystemZ operand structure
 */
export interface SyszOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		index: number;
		length: number;
		disp: number;
	};
}

/**
 * SystemZ instruction detail
 */
export interface SyszDetail {
	cc: number;
	operands: SyszOperand[];
}

/**
 * XCore operand structure
 */
export interface XcoreOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		index: number;
		disp: number;
		direct: number;
	};
}

/**
 * XCore instruction detail
 */
export interface XcoreDetail {
	operands: XcoreOperand[];
}

/**
 * M68K operand structure
 */
export interface M68kOperand {
	type: number;
	addressMode: number;
	reg?: number;
	imm?: number;
	fpDouble?: number;
	fpSingle?: number;
	regBits?: number;
	regPair?: {
		reg0: number;
		reg1: number;
	};
	mem?: {
		baseReg: number;
		indexReg: number;
		inBaseReg: number;
		inDisp: number;
		outDisp: number;
		disp: number;
		scale: number;
		bitfield: number;
		width: number;
		offset: number;
		indexSize: number;
	};
}

/**
 * M68K instruction detail
 */
export interface M68kDetail {
	opSize: number;
	operands: M68kOperand[];
}

/**
 * RISC-V operand structure
 */
export interface RiscvOperand {
	type: number;
	reg?: number;
	imm?: number;
	mem?: {
		base: number;
		disp: number;
	};
}

/**
 * RISC-V instruction detail
 */
export interface RiscvDetail {
	operands: RiscvOperand[];
}

/**
 * Instruction detail (when detail mode is enabled)
 */
export interface InstructionDetail {
	regsRead: number[];
	regsWrite: number[];
	groups: number[];
	x86?: X86Detail;
	arm?: ArmDetail;
	arm64?: Arm64Detail;
	mips?: MipsDetail;
	ppc?: PpcDetail;
	sparc?: SparcDetail;
	sysz?: SyszDetail;
	xcore?: XcoreDetail;
	m68k?: M68kDetail;
	riscv?: RiscvDetail;
}

/**
 * Disassembled instruction
 */
export interface Instruction {
	/** Instruction ID */
	id: number;
	/** Address of this instruction */
	address: number;
	/** Size of this instruction in bytes */
	size: number;
	/** Raw bytes of this instruction */
	bytes: Buffer;
	/** Mnemonic (e.g., "mov", "push") */
	mnemonic: string;
	/** Operand string (e.g., "rax, rbx") */
	opStr: string;
	/** Detailed info (only when detail mode is enabled) */
	detail?: InstructionDetail;
}

/**
 * Version information
 */
export interface Version {
	major: number;
	minor: number;
	string: string;
}

/**
 * Capstone disassembler class
 *
 * @example
 * ```typescript
 * import { Capstone, ARCH, MODE, OPT, OPT_VALUE } from 'hexcore-capstone';
 *
 * // Create disassembler for x86-64
 * const cs = new Capstone(ARCH.X86, MODE.MODE_64);
 *
 * // Enable detail mode for operand info
 * cs.setOption(OPT.DETAIL, OPT_VALUE.ON);
 *
 * // Disassemble code
 * const code = Buffer.from([0x55, 0x48, 0x89, 0xe5]);
 * const instructions = cs.disasm(code, 0x1000);
 *
 * for (const insn of instructions) {
 *   console.log(`${insn.address.toString(16)}: ${insn.mnemonic} ${insn.opStr}`);
 * }
 *
 * // Clean up
 * cs.close();
 * ```
 */
/**
 * Function boundary detected by the prologue scanner and call target analysis.
 */
export interface FunctionBoundary {
	/** Start address of the function (BigInt for 64-bit safety) */
	start: bigint;
	/** End address (last instruction address) */
	end: bigint;
	/** Total size in bytes */
	size: number;
	/** Number of instructions (0 if not counted in fast scan) */
	instructionCount: number;
	/** How this function was detected */
	detectionMethod: 'prologue' | 'call_target' | 'symbol' | 'heuristic';
	/** Confidence score 0.0 - 1.0 */
	confidence: number;
	/** Whether the function contains a return instruction */
	hasReturn: boolean;
	/** Whether this is a thunk (tiny function with just a jump) */
	isThunk: boolean;
	/** Addresses of functions called by this function */
	callTargets: bigint[];
	/** Addresses of functions that call this function */
	calledBy: bigint[];
}

export class Capstone {
	/**
	 * Create a new Capstone disassembler instance
	 *
	 * @param arch - Architecture constant (use ARCH.X86, ARCH.ARM, etc.)
	 * @param mode - Mode flags (use MODE.MODE_64, MODE.LITTLE_ENDIAN, etc.)
	 * @throws Error if architecture or mode is invalid
	 *
	 * @example
	 * ```typescript
	 * // x86-64 disassembler
	 * const cs64 = new Capstone(ARCH.X86, MODE.MODE_64);
	 *
	 * // ARM Thumb mode
	 * const csArm = new Capstone(ARCH.ARM, MODE.THUMB);
	 *
	 * // MIPS big-endian 32-bit
	 * const csMips = new Capstone(ARCH.MIPS, MODE.MODE_32 | MODE.BIG_ENDIAN);
	 * ```
	 */
	constructor(arch: number, mode: number);

	/**
	 * Disassemble code buffer (synchronous)
	 *
	 * **Note:** For large buffers (>1MB), use `disasmAsync()` to avoid blocking.
	 *
	 * @param code - Buffer containing machine code to disassemble
	 * @param address - Base address of the code (for correct jump targets)
	 * @param count - Maximum number of instructions to disassemble (0 = all)
	 * @returns Array of disassembled instructions
	 *
	 * @example
	 * ```typescript
	 * const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3]);
	 * const insns = cs.disasm(code, 0x401000);
	 * // Returns: push rbp, mov rbp,rsp, ret
	 * ```
	 */
	disasm(code: Buffer | Uint8Array, address: number, count?: number): Instruction[];

	/**
	 * Disassemble code buffer (asynchronous, non-blocking)
	 *
	 * Use this method for large buffers to avoid blocking the event loop.
	 * The disassembly runs in a background thread and returns a Promise.
	 *
	 * @param code - Buffer containing machine code to disassemble
	 * @param address - Base address of the code (for correct jump targets)
	 * @param count - Maximum number of instructions to disassemble (0 = all)
	 * @returns Promise resolving to array of disassembled instructions
	 *
	 * @example
	 * ```typescript
	 * // Large file async disassembly
	 * const largeCode = fs.readFileSync('large_binary.bin');
	 * const insns = await cs.disasmAsync(largeCode, 0x401000);
	 * console.log(`Disassembled ${insns.length} instructions`);
	 * ```
	 */
	disasmAsync(code: Buffer | Uint8Array, address: number, count?: number): Promise<Instruction[]>;

	/**
	 * Detect function boundaries in a code buffer
	 *
	 * Scans the buffer for function prologue patterns (push rbp, stp x29/x30, etc.)
	 * and collects call targets to identify function boundaries. Runs asynchronously
	 * in a background thread.
	 *
	 * @param code - Buffer containing machine code to analyze
	 * @param baseAddress - Virtual address of the first byte in the buffer
	 * @param maxFunctions - Maximum number of functions to detect (default 5000)
	 * @returns Promise resolving to array of detected function boundaries
	 *
	 * @example
	 * ```typescript
	 * const cs = new Capstone(ARCH.X86, MODE.MODE_64);
	 * const functions = await cs.detectFunctions(codeBuffer, 0x140001000n);
	 * for (const fn of functions) {
	 *   console.log(`Function at ${fn.start.toString(16)}, ${fn.size} bytes, confidence: ${fn.confidence}`);
	 * }
	 * cs.close();
	 * ```
	 */
	detectFunctions(code: Buffer | Uint8Array, baseAddress: number | bigint, maxFunctions?: number): Promise<FunctionBoundary[]>;

	/**
	 * Set a disassembler option
	 *
	 * @param type - Option type (OPT.DETAIL, OPT.SYNTAX, etc.)
	 * @param value - Option value (OPT_VALUE.ON, OPT_VALUE.SYNTAX_INTEL, etc.)
	 * @returns true on success, throws on failure
	 *
	 * @example
	 * ```typescript
	 * // Enable detailed instruction info
	 * cs.setOption(OPT.DETAIL, OPT_VALUE.ON);
	 *
	 * // Use Intel syntax (default)
	 * cs.setOption(OPT.SYNTAX, OPT_VALUE.SYNTAX_INTEL);
	 *
	 * // Use AT&T syntax
	 * cs.setOption(OPT.SYNTAX, OPT_VALUE.SYNTAX_ATT);
	 * ```
	 */
	setOption(type: number, value: number): boolean;

	/**
	 * Close the disassembler and free resources
	 *
	 * Always call this when done to prevent memory leaks.
	 */
	close(): void;

	/**
	 * Get register name by ID
	 *
	 * @param regId - Register ID from instruction details
	 * @returns Register name (e.g., "rax", "eip") or null if not found
	 *
	 * @example
	 * ```typescript
	 * const insn = cs.disasm(code, 0x1000)[0];
	 * if (insn.detail?.x86?.operands[0]?.reg) {
	 *   console.log(cs.regName(insn.detail.x86.operands[0].reg)); // "rbp"
	 * }
	 * ```
	 */
	regName(regId: number): string | null;

	/**
	 * Get instruction name by ID
	 *
	 * @param insnId - Instruction ID from disassembled instruction
	 * @returns Instruction name or null if not found
	 */
	insnName(insnId: number): string | null;

	/**
	 * Get group name by ID
	 *
	 * @param groupId - Group ID from instruction details
	 * @returns Group name (e.g., "jump", "call", "ret") or null
	 */
	groupName(groupId: number): string | null;

	/**
	 * Check if the disassembler handle is still open
	 * @returns true if open
	 */
	isOpen(): boolean;

	/**
	 * Get the last error code
	 * @returns Error code (use ERR constants)
	 */
	getError(): number;

	/**
	 * Get error message string
	 * @param err - Error code (optional, defaults to last error)
	 * @returns Error message
	 */
	strError(err?: number): string;
}

/**
 * Get Capstone version
 * @returns Version information
 */
export function version(): Version;

/**
 * Check if an architecture is supported
 * @param arch Architecture constant
 * @returns true if supported
 */
export function support(arch: number): boolean;

export default Capstone;
