/**
 * HexCore Remill - TypeScript Definitions
 * N-API bindings for Remill — lifts machine code to LLVM IR bitcode
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

/// <reference types="node" />

/**
 * Architecture name constants.
 *
 * These map to Remill's internal architecture identifiers.
 * Pass one of these to the RemillLifter constructor.
 */
export const ARCH: {
	/** 32-bit x86 (IA-32) */
	readonly X86: 'x86';
	/** 32-bit x86 with AVX extensions */
	readonly X86_AVX: 'x86_avx';
	/** 32-bit x86 with AVX-512 extensions */
	readonly X86_AVX512: 'x86_avx512';
	/** 64-bit x86 (AMD64 / x86-64) */
	readonly AMD64: 'amd64';
	/** 64-bit x86 with AVX extensions */
	readonly AMD64_AVX: 'amd64_avx';
	/** 64-bit x86 with AVX-512 extensions */
	readonly AMD64_AVX512: 'amd64_avx512';
	/** 64-bit ARM (AArch64 / ARMv8-A) */
	readonly AARCH64: 'aarch64';
	/** 32-bit SPARC (SPARCv8) */
	readonly SPARC32: 'sparc32';
	/** 64-bit SPARC (SPARCv9) */
	readonly SPARC64: 'sparc64';
};

/**
 * OS name constants for lifting context.
 *
 * The OS affects ABI conventions used during lifting (calling conventions,
 * TLS access patterns, etc.). Defaults to LINUX if not specified.
 */
export const OS: {
	readonly LINUX: 'linux';
	readonly MACOS: 'macos';
	readonly WINDOWS: 'windows';
	readonly SOLARIS: 'solaris';
};

/**
 * Result of a lift operation.
 */
export interface LiftResult {
	/** Whether the lift succeeded */
	success: boolean;
	/** LLVM IR text representation of the lifted code */
	ir: string;
	/** Error message if success is false */
	error: string;
	/** Start address of the lifted code */
	address: number;
	/** Number of input bytes that were successfully consumed */
	bytesConsumed: number;
}

/**
 * Remill lifter class.
 *
 * Creates a lifter instance bound to a specific architecture. The lifter
 * translates raw machine code bytes into LLVM IR text, which can then be
 * analyzed, optimized, or passed to a decompiler like Rellic.
 *
 * Each lifter owns an LLVM context and a loaded semantics module, so it
 * is relatively heavyweight. Reuse instances when lifting multiple blocks
 * of the same architecture.
 *
 * @example
 * ```typescript
 * import { RemillLifter, ARCH, OS } from 'hexcore-remill';
 *
 * // Lift x86-64 code
 * const lifter = new RemillLifter(ARCH.AMD64);
 * const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
 * const result = lifter.liftBytes(code, 0x401000);
 *
 * if (result.success) {
 *   console.log(result.ir);
 *   console.log(`Consumed ${result.bytesConsumed} bytes`);
 * } else {
 *   console.error(result.error);
 * }
 *
 * lifter.close();
 * ```
 *
 * @example
 * ```typescript
 * // Lift with Windows ABI context
 * const lifter = new RemillLifter(ARCH.AMD64, OS.WINDOWS);
 * ```
 *
 * @example
 * ```typescript
 * // Async lifting for large buffers
 * const lifter = new RemillLifter(ARCH.AMD64);
 * const largeCode = fs.readFileSync('section.bin');
 * const result = await lifter.liftBytesAsync(largeCode, 0x140001000);
 * lifter.close();
 * ```
 */
export class RemillLifter {
	/**
	 * Create a new Remill lifter for the given architecture.
	 *
	 * @param arch - Architecture name (use ARCH constants)
	 * @param os - OS name for ABI context (optional, defaults to 'linux')
	 * @throws Error if architecture is unsupported or semantics fail to load
	 */
	constructor(arch: string, os?: string);

	/**
	 * Lift raw machine code bytes to LLVM IR (synchronous).
	 *
	 * Decodes and lifts instructions starting at the given address.
	 * Stops at the first instruction that cannot be decoded or lifted.
	 *
	 * For large buffers (>64KB), prefer `liftBytesAsync()`.
	 *
	 * @param code - Buffer containing raw machine code
	 * @param address - Virtual address of the first byte
	 * @returns Lift result with LLVM IR text
	 */
	liftBytes(code: Buffer | Uint8Array, address: number | bigint): LiftResult;

	/**
	 * Lift raw machine code bytes to LLVM IR (asynchronous).
	 *
	 * Runs the lifting in a background thread to avoid blocking the
	 * event loop. Use this for large code sections.
	 *
	 * @param code - Buffer containing raw machine code
	 * @param address - Virtual address of the first byte
	 * @returns Promise resolving to lift result
	 */
	liftBytesAsync(code: Buffer | Uint8Array, address: number | bigint): Promise<LiftResult>;

	/**
	 * Get the architecture name this lifter was created with.
	 * @returns Architecture name string
	 */
	getArch(): string;

	/**
	 * Release native resources (LLVM context, semantics module).
	 *
	 * Always call this when done to prevent memory leaks.
	 * The lifter cannot be used after calling close().
	 */
	close(): void;

	/**
	 * Check if the lifter is still open and usable.
	 * @returns true if open
	 */
	isOpen(): boolean;

	/**
	 * Get list of supported architecture names.
	 * @returns Array of architecture name strings
	 */
	static getSupportedArchs(): string[];
}

/**
 * Module version string.
 */
export const version: string;

export default RemillLifter;
