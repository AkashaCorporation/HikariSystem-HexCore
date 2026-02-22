/**
 * HexCore Rellic - TypeScript Definitions
 * N-API bindings for Rellic — decompiles LLVM IR to pseudo-C
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

/**
 * Result of a decompilation operation.
 */
export interface DecompileResult {
	/** Whether the decompilation succeeded */
	success: boolean;
	/** Generated pseudo-C code (empty if failed) */
	code: string;
	/** Error message (empty if succeeded) */
	error: string;
	/** Number of functions decompiled */
	functionCount: number;
}

/**
 * Rellic decompiler class.
 *
 * Creates a decompiler instance that translates LLVM IR text into
 * pseudo-C code. The decompiler owns LLVM, Clang, and Z3 contexts,
 * so it is relatively heavyweight. Reuse instances when decompiling
 * multiple IR texts.
 *
 * @example
 * ```typescript
 * import { RellicDecompiler } from 'hexcore-rellic';
 *
 * const decompiler = new RellicDecompiler();
 * const irText = `
 *   define i32 @add(i32 %a, i32 %b) {
 *     %sum = add i32 %a, %b
 *     ret i32 %sum
 *   }
 * `;
 * const result = decompiler.decompile(irText);
 *
 * if (result.success) {
 *   console.log(result.code);
 *   console.log(`Decompiled ${result.functionCount} function(s)`);
 * } else {
 *   console.error(result.error);
 * }
 *
 * decompiler.close();
 * ```
 *
 * @example
 * ```typescript
 * // Async decompilation for large IR
 * const decompiler = new RellicDecompiler();
 * const result = await decompiler.decompileAsync(largeIrText);
 * decompiler.close();
 * ```
 */
export class RellicDecompiler {
	constructor();

	/**
	 * Decompile LLVM IR text to pseudo-C (synchronous).
	 *
	 * For large IR texts (>64KB), prefer `decompileAsync()`.
	 *
	 * @param irText - LLVM IR text to decompile
	 * @returns Decompile result with pseudo-C code
	 */
	decompile(irText: string): DecompileResult;

	/**
	 * Decompile LLVM IR text to pseudo-C (asynchronous).
	 *
	 * Runs the decompilation in a background thread to avoid blocking
	 * the event loop. Use this for large IR texts.
	 *
	 * @param irText - LLVM IR text to decompile
	 * @returns Promise resolving to decompile result
	 */
	decompileAsync(irText: string): Promise<DecompileResult>;

	/**
	 * Release native resources (LLVM context, Clang context, Z3).
	 *
	 * Always call this when done to prevent memory leaks.
	 * Calling close() multiple times is safe (idempotent).
	 */
	close(): void;

	/**
	 * Check if the decompiler is still open and usable.
	 * @returns true if open
	 */
	isOpen(): boolean;
}

/**
 * Module version string.
 */
export const version: string;

export default RellicDecompiler;
