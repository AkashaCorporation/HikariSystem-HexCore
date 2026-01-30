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
 * ARM operand structure
 */
export interface ArmOperand {
	type: number;
	access: number;
	reg?: number;
	imm?: number;
	fp?: number;
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
 */
export class Capstone {
	/**
	 * Create a new Capstone disassembler instance
	 * @param arch Architecture (use ARCH constants)
	 * @param mode Mode (use MODE constants, can be combined with |)
	 */
	constructor(arch: number, mode: number);

	/**
	 * Disassemble code buffer
	 * @param code Buffer containing machine code
	 * @param address Base address of the code
	 * @param count Maximum number of instructions to disassemble (0 = all)
	 * @returns Array of disassembled instructions
	 */
	disasm(code: Buffer | Uint8Array, address: number, count?: number): Instruction[];

	/**
	 * Set a disassembler option
	 * @param type Option type (use OPT constants)
	 * @param value Option value (use OPT_VALUE constants)
	 * @returns true on success
	 */
	setOption(type: number, value: number): boolean;

	/**
	 * Close the disassembler and free resources
	 */
	close(): void;

	/**
	 * Get register name by ID
	 * @param regId Register ID
	 * @returns Register name or null if not found
	 */
	regName(regId: number): string | null;

	/**
	 * Get instruction name by ID
	 * @param insnId Instruction ID
	 * @returns Instruction name or null if not found
	 */
	insnName(insnId: number): string | null;

	/**
	 * Get group name by ID
	 * @param groupId Group ID
	 * @returns Group name or null if not found
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
	 * @param err Error code (optional, defaults to last error)
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
