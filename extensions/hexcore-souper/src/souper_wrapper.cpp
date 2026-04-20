/**
 * Copyright (c) HikariSystem. All rights reserved.
 *
 * hexcore-souper — SouperOptimizer v0.2.0
 *
 * Real Souper optimization pipeline:
 *   1. Parse LLVM IR text → Module
 *   2. Extract optimization candidates (ExtractCandidates)
 *   3. Create solver (Z3 via SMTLIB2)
 *   4. For each candidate, infer replacement via SMT
 *   5. Replace instructions in Module
 *   6. Serialize optimized Module back to IR text
 */

#include "souper_wrapper.h"

#include <sstream>
#include <cstring>
#include <cstdlib>

#ifdef _WIN32
#include <stdlib.h>  // _putenv_s
#endif

// ── LLVM headers ───────────────────────────────────────────────────────
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/MemoryBuffer.h>

// ── Souper headers ─────────────────────────────────────────────────────
#include <souper/Extractor/Candidates.h>
#include <souper/Extractor/Solver.h>
#include <souper/Inst/Inst.h>
#include <souper/Tool/GetSolver.h>

using namespace Napi;

// ═══════════════════════════════════════════════════════════════════════
//  SouperOptimizer — Class Registration
// ═══════════════════════════════════════════════════════════════════════

Napi::Object SouperOptimizer::Init(Napi::Env env, Napi::Object exports) {
    Napi::Function func = DefineClass(env, "SouperOptimizer", {
        InstanceMethod("optimize", &SouperOptimizer::Optimize),
        InstanceMethod("optimizeAsync", &SouperOptimizer::OptimizeAsync),
        InstanceMethod("close", &SouperOptimizer::Close),
        InstanceMethod("isOpen", &SouperOptimizer::IsOpen),
        StaticMethod("getVersion", &SouperOptimizer::GetVersion),
        StaticMethod("getSolverInfo", &SouperOptimizer::GetSolverInfo),
    });

    Napi::FunctionReference* constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("SouperOptimizer", func);
    return exports;
}

// ═══════════════════════════════════════════════════════════════════════
//  Constructor / Destructor
// ═══════════════════════════════════════════════════════════════════════

SouperOptimizer::SouperOptimizer(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<SouperOptimizer>(info) {
    try {
        context_ = std::make_unique<llvm::LLVMContext>();
    } catch (const std::exception& e) {
        Napi::Error::New(info.Env(),
            std::string("Failed to initialize SouperOptimizer: ") + e.what()
        ).ThrowAsJavaScriptException();
    }
}

SouperOptimizer::~SouperOptimizer() {
    closed_ = true;
    context_.reset();
}

// ═══════════════════════════════════════════════════════════════════════
//  Core Optimization Pipeline v0.2.0
// ═══════════════════════════════════════════════════════════════════════

OptimizeResult SouperOptimizer::DoOptimize(
    const std::string& irText,
    const OptimizeOptions& options)
{
    OptimizeResult result;
    auto startTime = std::chrono::high_resolution_clock::now();

    // ── Phase 1: Parse LLVM IR ─────────────────────────────────────────
    llvm::SMDiagnostic diag;
    auto memBuf = llvm::MemoryBuffer::getMemBuffer(irText, "souper-input");

    auto module = llvm::parseIR(*memBuf, diag, *context_);
    if (!module) {
        std::string errMsg;
        llvm::raw_string_ostream errStream(errMsg);
        diag.print("souper", errStream);
        errStream.flush();

        result.success = false;
        result.error = "Failed to parse LLVM IR: " + errMsg;
        return result;
    }

    // ── Phase 2: Verify module ─────────────────────────────────────────
    {
        std::string verifyErr;
        llvm::raw_string_ostream verifyStream(verifyErr);
        if (llvm::verifyModule(*module, &verifyStream)) {
            verifyStream.flush();
            result.success = false;
            result.error = "LLVM IR verification failed: " + verifyErr;
            return result;
        }
    }

    // ── Phase 3: Initialize Souper ─────────────────────────────────────
    souper::InstContext IC;
    uint32_t totalCandidates = 0;
    uint32_t totalReplaced = 0;

    // Ensure Z3 DLLs are findable when LLVM spawns the z3.exe process
#ifdef _WIN32
    {
        // Extract directory from Z3Path and add to PATH
        std::string z3Dir(souper::Z3Path);
        auto lastSlash = z3Dir.find_last_of("/\\");
        if (lastSlash != std::string::npos) {
            z3Dir = z3Dir.substr(0, lastSlash);
            std::string currentPath = getenv("PATH") ? getenv("PATH") : "";
            std::string newPath = z3Dir + ";" + currentPath;
            _putenv_s("PATH", newPath.c_str());
        }
    }
#endif

    // Try to get the SMT solver (Z3 via SMTLIB2 external process)
    souper::KVStore *KV = nullptr;
    std::unique_ptr<souper::Solver> solver;
    std::string solverDebug;
    try {
        solver = souper::GetSolver(KV);
        if (solver) {
            solverDebug = "solver_created:" + solver->getName();
        } else {
            solverDebug = "solver_null";
        }
    } catch (const std::exception& e) {
        solverDebug = std::string("solver_exception:") + e.what();
        solver = nullptr;
    } catch (...) {
        solverDebug = "solver_unknown_exception";
        solver = nullptr;
    }

    std::string inferDebug;
    int inferAttempts = 0, inferErrors = 0, inferEmpty = 0;

    // ── Phase 4: Extract & optimize per function ───────────────────────
    for (auto& func : *module) {
        if (func.isDeclaration()) continue;

        try {
            souper::ExprBuilderContext EBC;
            souper::ExprBuilderOptions EBOpts;

            souper::FunctionCandidateSet FCS =
                souper::ExtractCandidates(func, IC, EBC, EBOpts);

            for (auto& BCS : FCS.Blocks) {
                totalCandidates += static_cast<uint32_t>(BCS->Replacements.size());

                if (!solver) continue;

                for (auto& CR : BCS->Replacements) {
                    if (options.maxCandidates > 0 &&
                        totalCandidates > options.maxCandidates)
                        break;

                    inferAttempts++;
                    try {
                        std::vector<souper::Inst*> RHSCandidates;
                        std::error_code EC = solver->infer(
                            CR.BPCs, CR.PCs,
                            CR.Mapping.LHS,
                            RHSCandidates,
                            /*AllowMultipleRHSs=*/false,
                            IC);

                        if (EC) {
                            inferErrors++;
                            if (inferDebug.empty()) {
                                inferDebug = "first_error:" + EC.message();
                            }
                        } else if (RHSCandidates.empty()) {
                            inferEmpty++;
                        } else {
                            // Found a replacement!
                            CR.Mapping.RHS = RHSCandidates[0];

                            // Apply: replace LLVM instruction with the inferred value
                            if (CR.Origin && CR.Mapping.RHS) {
                                // If RHS is a constant, replace directly
                                if (CR.Mapping.RHS->K == souper::Inst::Const) {
                                    auto *origInst = CR.Origin;
                                    auto constVal = CR.Mapping.RHS->Val;
                                    auto *llvmConst = llvm::ConstantInt::get(
                                        origInst->getType(), constVal);
                                    origInst->replaceAllUsesWith(llvmConst);
                                    origInst->eraseFromParent();
                                }
                            }
                            totalReplaced++;
                        }
                    } catch (const std::exception& e) {
                        inferErrors++;
                        if (inferDebug.empty()) {
                            inferDebug = std::string("infer_exception:") + e.what();
                        }
                        continue;
                    } catch (...) {
                        inferErrors++;
                        continue;
                    }
                }
            }
        } catch (...) {
            // Non-fatal: skip this function
            continue;
        }
    }

    // Clean up KVStore if allocated
    delete KV;

    // ── Phase 5: Serialize module ──────────────────────────────────────
    {
        std::string outIR;
        llvm::raw_string_ostream outStream(outIR);
        module->print(outStream, nullptr);
        outStream.flush();
        result.ir = std::move(outIR);
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    result.success = true;
    result.candidatesFound = totalCandidates;
    result.candidatesReplaced = totalReplaced;
    result.optimizationTimeMs =
        std::chrono::duration<double, std::milli>(endTime - startTime).count();

    // Debug: attach solver diagnostics to error field when no replacements made
    if (totalReplaced == 0 && totalCandidates > 0) {
        std::string diag = "[debug] " + solverDebug +
            " | attempts=" + std::to_string(inferAttempts) +
            " errors=" + std::to_string(inferErrors) +
            " empty=" + std::to_string(inferEmpty);
        if (!inferDebug.empty()) diag += " | " + inferDebug;
        result.error = diag;
    }

    return result;
}

// ═══════════════════════════════════════════════════════════════════════
//  Result Conversion
// ═══════════════════════════════════════════════════════════════════════

Napi::Object SouperOptimizer::OptimizeResultToJS(Napi::Env env,
                                                  const OptimizeResult& result)
{
    auto obj = Napi::Object::New(env);
    obj.Set("success", Napi::Boolean::New(env, result.success));
    obj.Set("ir", Napi::String::New(env, result.ir));
    obj.Set("error", Napi::String::New(env, result.error));
    obj.Set("candidatesFound", Napi::Number::New(env, result.candidatesFound));
    obj.Set("candidatesReplaced", Napi::Number::New(env, result.candidatesReplaced));
    obj.Set("optimizationTimeMs", Napi::Number::New(env, result.optimizationTimeMs));
    return obj;
}

// ═══════════════════════════════════════════════════════════════════════
//  N-API Instance Methods
// ═══════════════════════════════════════════════════════════════════════

Napi::Value SouperOptimizer::Optimize(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (closed_) {
        Napi::Error::New(env, "SouperOptimizer is closed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected string argument: irText")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string irText = info[0].As<Napi::String>().Utf8Value();

    OptimizeOptions options;
    if (info.Length() >= 2 && info[1].IsObject()) {
        options = ParseOptions(env, info[1]);
    }

    OptimizeResult result = DoOptimize(irText, options);
    return OptimizeResultToJS(env, result);
}

Napi::Value SouperOptimizer::OptimizeAsync(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (closed_) {
        Napi::Error::New(env, "SouperOptimizer is closed").ThrowAsJavaScriptException();
        return env.Undefined();
    }

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected string argument: irText")
            .ThrowAsJavaScriptException();
        return env.Undefined();
    }
    std::string irText = info[0].As<Napi::String>().Utf8Value();

    OptimizeOptions options;
    if (info.Length() >= 2 && info[1].IsObject()) {
        options = ParseOptions(env, info[1]);
    }

    auto* worker = new OptimizeWorker(env, this, std::move(irText), options);
    auto promise = worker->GetDeferred().Promise();
    worker->Queue();
    return promise;
}

Napi::Value SouperOptimizer::Close(const Napi::CallbackInfo& info) {
    if (!closed_) {
        closed_ = true;
        context_.reset();
    }
    return info.Env().Undefined();
}

Napi::Value SouperOptimizer::IsOpen(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), !closed_);
}

// ═══════════════════════════════════════════════════════════════════════
//  Static Methods
// ═══════════════════════════════════════════════════════════════════════

Napi::Value SouperOptimizer::GetVersion(const Napi::CallbackInfo& info) {
    return Napi::String::New(info.Env(), "0.2.0");
}

Napi::Value SouperOptimizer::GetSolverInfo(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    auto obj = Napi::Object::New(env);
    obj.Set("name", Napi::String::New(env, "z3"));
    obj.Set("version", Napi::String::New(env, "4.16.0"));
    return obj;
}

// ═══════════════════════════════════════════════════════════════════════
//  Helpers
// ═══════════════════════════════════════════════════════════════════════

OptimizeOptions SouperOptimizer::ParseOptions(Napi::Env env, Napi::Value val) {
    OptimizeOptions opts;
    if (!val.IsObject()) return opts;

    auto obj = val.As<Napi::Object>();

    if (obj.Has("maxCandidates") && obj.Get("maxCandidates").IsNumber()) {
        opts.maxCandidates = static_cast<size_t>(
            obj.Get("maxCandidates").As<Napi::Number>().Uint32Value());
    }
    if (obj.Has("timeoutMs") && obj.Get("timeoutMs").IsNumber()) {
        opts.timeoutMs = static_cast<size_t>(
            obj.Get("timeoutMs").As<Napi::Number>().Uint32Value());
    }
    if (obj.Has("aggressiveMode") && obj.Get("aggressiveMode").IsBoolean()) {
        opts.aggressiveMode = obj.Get("aggressiveMode").As<Napi::Boolean>().Value();
    }

    return opts;
}

// ═══════════════════════════════════════════════════════════════════════
//  AsyncWorker
// ═══════════════════════════════════════════════════════════════════════

OptimizeWorker::OptimizeWorker(
    Napi::Env env,
    SouperOptimizer* optimizer,
    std::string irText,
    OptimizeOptions options)
    : Napi::AsyncWorker(env)
    , optimizer_(optimizer)
    , irText_(std::move(irText))
    , options_(options)
    , deferred_(Napi::Promise::Deferred::New(env))
{
}

void OptimizeWorker::Execute() {
    try {
        result_ = optimizer_->DoOptimize(irText_, options_);
    } catch (const std::exception& e) {
        SetError(std::string("Optimization failed: ") + e.what());
    }
}

void OptimizeWorker::OnOK() {
    Napi::HandleScope scope(Env());
    deferred_.Resolve(optimizer_->OptimizeResultToJS(Env(), result_));
}

void OptimizeWorker::OnError(const Napi::Error& error) {
    deferred_.Reject(error.Value());
}
