/**
 * Copyright (c) HikariSystem. All rights reserved.
 *
 * hexcore-souper — SouperOptimizer N-API wrapper.
 *
 * Wraps Google Souper's LLVM IR superoptimization pipeline:
 *   1. Parse LLVM IR text → LLVM Module
 *   2. Extract optimization candidates via Souper's Extractor
 *   3. Query Z3 SMT solver for simpler replacements
 *   4. Apply replacements to the LLVM Module
 *   5. Serialize optimized Module back to IR text
 */

#pragma once

#include <napi.h>
#include <string>
#include <memory>
#include <vector>
#include <chrono>
#include <map>

// Forward declarations — LLVM
namespace llvm {
class LLVMContext;
class Module;
} // namespace llvm

// Forward declarations — Souper
namespace souper {
class InstContext;
} // namespace souper

/**
 * Options for the superoptimization pass.
 */
struct OptimizeOptions {
    /** Maximum candidates to extract per function (0 = unlimited). */
    size_t maxCandidates = 1000;

    /** Z3 solver timeout in milliseconds per candidate. */
    size_t timeoutMs = 30000;

    /**
     * Aggressive mode — tries harder synthesis strategies.
     * May significantly increase solve time.
     */
    bool aggressiveMode = false;
};

/**
 * Result of a superoptimization pass.
 */
struct OptimizeResult {
    /** Whether the optimization completed without fatal errors. */
    bool success = false;

    /** Optimized LLVM IR text (empty on failure). */
    std::string ir;

    /** Error message (empty on success). */
    std::string error;

    /** Number of optimization candidates found. */
    uint32_t candidatesFound = 0;

    /** Number of candidates successfully replaced. */
    uint32_t candidatesReplaced = 0;

    /** Wall-clock time for the optimization pass (ms). */
    double optimizationTimeMs = 0.0;
};

/**
 * N-API wrapper for the Souper LLVM IR superoptimizer.
 *
 * Usage from JavaScript:
 * @example
 *   const { SouperOptimizer } = require('hexcore-souper');
 *   const optimizer = new SouperOptimizer();
 *   const result = optimizer.optimize(irText, { timeoutMs: 10000 });
 *   if (result.success) {
 *       console.log(result.ir);
 *       console.log(`Replaced ${result.candidatesReplaced} of ${result.candidatesFound}`);
 *   }
 *   optimizer.close();
 */
class SouperOptimizer : public Napi::ObjectWrap<SouperOptimizer> {
public:
    /**
     * Register the class with N-API.
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * Constructor — initializes LLVM context and Souper infrastructure.
     */
    explicit SouperOptimizer(const Napi::CallbackInfo& info);

    /**
     * Destructor — cleans up Souper and LLVM resources.
     */
    ~SouperOptimizer();

    /**
     * Core optimization pipeline (called internally).
     *
     * @param irText  LLVM IR text to optimize
     * @param options Optimization options
     * @return OptimizeResult with optimized IR and stats
     */
    OptimizeResult DoOptimize(const std::string& irText,
                              const OptimizeOptions& options = OptimizeOptions{});

    /**
     * Convert a C++ OptimizeResult to a JavaScript object.
     */
    Napi::Object OptimizeResultToJS(Napi::Env env, const OptimizeResult& result);

private:
    // ── N-API methods ──────────────────────────────────────────────────

    /** Synchronous optimize: optimize(irText, options?) → OptimizeResult */
    Napi::Value Optimize(const Napi::CallbackInfo& info);

    /** Asynchronous optimize: optimizeAsync(irText, options?) → Promise<OptimizeResult> */
    Napi::Value OptimizeAsync(const Napi::CallbackInfo& info);

    /** Close the optimizer and release resources. */
    Napi::Value Close(const Napi::CallbackInfo& info);

    /** Check if the optimizer is still open. */
    Napi::Value IsOpen(const Napi::CallbackInfo& info);

    /** Static: get Souper version string. */
    static Napi::Value GetVersion(const Napi::CallbackInfo& info);

    /** Static: get solver information. */
    static Napi::Value GetSolverInfo(const Napi::CallbackInfo& info);

    // ── Helpers ────────────────────────────────────────────────────────

    /** Parse OptimizeOptions from a JS object. */
    OptimizeOptions ParseOptions(Napi::Env env, Napi::Value val);

    // ── State ──────────────────────────────────────────────────────────

    bool closed_ = false;
    std::unique_ptr<llvm::LLVMContext> context_;
};

/**
 * AsyncWorker for optimizeAsync().
 *
 * Runs the DoOptimize pipeline off the main thread to avoid blocking
 * the Node.js event loop on large IR inputs.
 */
class OptimizeWorker : public Napi::AsyncWorker {
public:
    OptimizeWorker(Napi::Env env,
                   SouperOptimizer* optimizer,
                   std::string irText,
                   OptimizeOptions options);

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

    Napi::Promise::Deferred& GetDeferred() { return deferred_; }

private:
    SouperOptimizer* optimizer_;
    std::string irText_;
    OptimizeOptions options_;
    OptimizeResult result_;
    Napi::Promise::Deferred deferred_;
};
