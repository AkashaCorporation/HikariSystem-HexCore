/**
 * HexCore Keystone - Native Node.js Bindings
 * TypeScript Definitions
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

/**
 * Keystone architectures
 */
export const ARCH: {
	ARM: number;
	ARM64: number;
	MIPS: number;
	X86: number;
	PPC: number;
	SPARC: number;
	SYSTEMZ: number;
	HEXAGON: number;
	EVM: number;
};

/**
 * Keystone modes
 */
export const MODE: {
	// Endianness
	LITTLE_ENDIAN: number;
	BIG_ENDIAN: number;
	// ARM modes
	ARM: number;
	THUMB: number;
	V8: number;
	// x86 modes
	MODE_16: number;
	MODE_32: number;
	MODE_64: number;
	// MIPS modes
	MICRO: number;
	MIPS3: number;
	MIPS32R6: number;
	MIPS32: number;
	MIPS64: number;
	// PPC modes
	PPC32: number;
	PPC64: number;
	QPX: number;
	// SPARC modes
	SPARC32: number;
	SPARC64: number;
	V9: number;
};

/**
 * Keystone options
 */
export const OPT: {
	SYNTAX: number;
};

/**
 * Keystone option values
 */
export const OPT_VALUE: {
	SYNTAX_INTEL: number;
	SYNTAX_ATT: number;
	SYNTAX_NASM: number;
	SYNTAX_MASM: number;
	SYNTAX_GAS: number;
	SYNTAX_RADIX16: number;
};

/**
 * Keystone error codes
 */
export const ERR: {
	OK: number;
	NOMEM: number;
	ARCH: number;
	HANDLE: number;
	MODE: number;
	VERSION: number;
	OPT_INVALID: number;
	ASM_EXPR_TOKEN: number;
	ASM_DIRECTIVE_VALUE_RANGE: number;
	ASM_DIRECTIVE_ID: number;
	ASM_DIRECTIVE_TOKEN: number;
	ASM_DIRECTIVE_STR: number;
	ASM_DIRECTIVE_COMMA: number;
	ASM_INVALIDOPERAND: number;
	ASM_MISSINGFEATURE: number;
	ASM_MNEMONICFAIL: number;
};

/**
 * Result of assembly operation
 */
export interface AssembleResult {
	/** Assembled bytes (null if error) */
	bytes: Buffer | null;
	/** Size of assembled code in bytes */
	size: number;
	/** Number of statements assembled */
	statCount: number;
	/** Error message (only present if error occurred) */
	error?: string;
}

/**
 * Version information
 */
export interface VersionInfo {
	major: number;
	minor: number;
	string: string;
}

/**
 * Keystone assembler class
 */
export class Keystone {
	/**
	 * Create a new Keystone instance
	 * @param arch - Architecture (use ARCH constants)
	 * @param mode - Mode (use MODE constants)
	 */
	constructor(arch: number, mode: number);

	/**
	 * Assemble a string of assembly code (synchronous)
	 * @param asmCode - Assembly code string (e.g., "push rbp; mov rbp, rsp")
	 * @param address - Base address for assembly (default: 0)
	 * @returns Assembly result with bytes, size, and statCount
	 */
	asm(asmCode: string, address?: number): AssembleResult;

	/**
	 * Assemble a string of assembly code (asynchronous)
	 * @param asmCode - Assembly code string
	 * @param address - Base address for assembly (default: 0)
	 * @returns Promise resolving to assembly result
	 */
	asmAsync(asmCode: string, address?: number): Promise<AssembleResult>;

	/**
	 * Set an option
	 * @param type - Option type (use OPT constants)
	 * @param value - Option value (use OPT_VALUE constants)
	 * @returns True if successful
	 */
	setOption(type: number, value: number): boolean;

	/**
	 * Close the Keystone handle and free resources
	 */
	close(): void;

	/**
	 * Check if the handle is still open
	 * @returns True if handle is open
	 */
	isOpen(): boolean;

	/**
	 * Get the last error code
	 * @returns Error code (use ERR constants to interpret)
	 */
	getError(): number;

	/**
	 * Get error message string
	 * @param errCode - Optional error code (defaults to last error)
	 * @returns Human-readable error message
	 */
	strError(errCode?: number): string;
}

/**
 * Get Keystone version information
 * @returns Version object with major, minor, and string
 */
export function version(): VersionInfo;

/**
 * Check if an architecture is supported
 * @param arch - Architecture (use ARCH constants)
 * @returns True if architecture is supported
 */
export function archSupported(arch: number): boolean;
