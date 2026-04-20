/**
 * HexCore Souper — LLVM IR superoptimizer via Z3 SMT solving.
 *
 * Wraps Google Souper to provide LLVM IR superoptimization in the
 * HexCore reverse engineering pipeline.
 *
 * Pipeline: Remill (lift) → **Souper (optimize)** → Helix (decompile)
 *
 * @example
 * ```typescript
 * import { SouperOptimizer } from 'hexcore-souper';
 *
 * const optimizer = new SouperOptimizer();
 * const result = optimizer.optimize(llvmIrText, { timeoutMs: 10000 });
 * if (result.success) {
 *     console.log(`Optimized: ${result.candidatesReplaced}/${result.candidatesFound} candidates`);
 *     // result.ir contains the optimized LLVM IR
 * }
 * optimizer.close();
 * ```
 *
 * @module hexcore-souper
 */

/**
 * Options for the LLVM IR superoptimization pass.
 */
export interface OptimizeOptions {
    /**
     * Maximum number of optimization candidates to extract per function.
     * Set to 0 for unlimited. Higher values may increase optimization quality
     * at the cost of solve time.
     * @default 1000
     */
    readonly maxCandidates?: number;

    /**
     * Z3 SMT solver timeout in milliseconds per candidate.
     * Lower values are faster but may miss optimizations.
     * @default 30000
     */
    readonly timeoutMs?: number;

    /**
     * Enable aggressive synthesis strategies.
     * Tries harder to find optimizations but may significantly increase
     * solve time. Recommended for small, critical functions only.
     * @default false
     */
    readonly aggressiveMode?: boolean;
}

/**
 * Result of a superoptimization pass.
 */
export interface OptimizeResult {
    /** Whether the optimization completed without fatal errors. */
    readonly success: boolean;

    /**
     * Optimized LLVM IR text.
     * Empty string on failure.
     */
    readonly ir: string;

    /**
     * Error message describing the failure.
     * Empty string on success.
     */
    readonly error: string;

    /**
     * Number of optimization candidates found in the IR.
     * A candidate is an instruction sequence that Souper can analyze.
     */
    readonly candidatesFound: number;

    /**
     * Number of candidates successfully replaced with simpler equivalents.
     * `candidatesReplaced <= candidatesFound`.
     */
    readonly candidatesReplaced: number;

    /**
     * Wall-clock time for the optimization pass in milliseconds.
     * Includes parsing, extraction, solving, and replacement.
     */
    readonly optimizationTimeMs: number;
}

/**
 * Information about the SMT solver backing Souper.
 */
export interface SolverInfo {
    /** Solver name (e.g., "z3"). */
    readonly name: string;

    /** Solver version string. */
    readonly version: string;
}

/**
 * LLVM IR superoptimizer powered by Google Souper and Z3 SMT solving.
 *
 * Souper extracts optimization candidates from LLVM IR, queries Z3 to find
 * semantically equivalent but simpler instruction sequences, and applies
 * the replacements in-place.
 *
 * Lifecycle:
 * 1. Create with `new SouperOptimizer()`
 * 2. Call `optimize()` or `optimizeAsync()` for each IR module
 * 3. Call `close()` when done
 *
 * @example
 * ```typescript
 * const optimizer = new SouperOptimizer();
 *
 * // Synchronous (blocks Node.js event loop — use for small IR)
 * const result = optimizer.optimize(irText);
 *
 * // Asynchronous (non-blocking — use for large IR > 64KB)
 * const result = await optimizer.optimizeAsync(irText, {
 *     timeoutMs: 15000,
 *     maxCandidates: 500
 * });
 *
 * optimizer.close();
 * ```
 */
export class SouperOptimizer {
    /**
     * Create a new SouperOptimizer instance.
     * Initializes the LLVM context and Souper infrastructure.
     * @throws If LLVM context creation fails
     */
    constructor();

    /**
     * Optimize LLVM IR text synchronously.
     *
     * Parses the IR, extracts optimization candidates, queries Z3 for
     * simpler equivalents, applies replacements, and returns the
     * optimized IR.
     *
     * **Warning**: This blocks the Node.js event loop. For IR larger than
     * ~64KB, prefer `optimizeAsync()`.
     *
     * @param irText LLVM IR text to optimize (e.g., from Remill's liftBytes)
     * @param options Optimization options
     * @returns Optimization result with the optimized IR and statistics
     * @throws If the optimizer is closed
     */
    optimize(irText: string, options?: OptimizeOptions): OptimizeResult;

    /**
     * Optimize LLVM IR text asynchronously.
     *
     * Same pipeline as `optimize()` but runs on a worker thread to avoid
     * blocking the Node.js event loop.
     *
     * @param irText LLVM IR text to optimize
     * @param options Optimization options
     * @returns Promise resolving to the optimization result
     * @throws If the optimizer is closed
     */
    optimizeAsync(irText: string, options?: OptimizeOptions): Promise<OptimizeResult>;

    /**
     * Close the optimizer and release all resources.
     *
     * After calling close(), the optimizer cannot be used again.
     * Calling close() on an already-closed optimizer is a no-op.
     */
    close(): void;

    /**
     * Check if the optimizer is still open and usable.
     * @returns `true` if optimize/optimizeAsync can be called
     */
    isOpen(): boolean;

    /**
     * Get the Souper wrapper version string.
     * @returns Version string (e.g., "0.1.0")
     */
    static getVersion(): string;

    /**
     * Get information about the backing SMT solver.
     * @returns Solver name and version
     */
    static getSolverInfo(): SolverInfo;
}

/**
 * Module version string.
 */
export const version: string;
