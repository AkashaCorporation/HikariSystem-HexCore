/**
 * Copyright (c) HikariSystem. All rights reserved.
 *
 * hexcore-souper — SouperOptimizer v0.2.2
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
#include <algorithm>
#include <limits>
#include <map>
#include <unordered_set>

#ifdef _WIN32
#include <stdlib.h>  // _putenv_s
#endif

// ── LLVM headers ───────────────────────────────────────────────────────
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Verifier.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Transforms/Utils/Local.h>

// ── Souper headers ─────────────────────────────────────────────────────
#include <souper/Extractor/Candidates.h>
#include <souper/Extractor/Solver.h>
#include <souper/Codegen/Codegen.h>
#include <souper/Inst/Inst.h>
#include <souper/SMTLIB2/Solver.h>
#include <souper/Tool/GetSolver.h>

using namespace Napi;

namespace {

unsigned timeoutSeconds(size_t timeoutMs) {
    if (timeoutMs == 0) return 0;
    const size_t seconds = (timeoutMs + 999) / 1000;
    return static_cast<unsigned>(std::min<size_t>(
        seconds, std::numeric_limits<unsigned>::max()));
}

std::string resolveZ3Path() {
    const char* packagedPath = std::getenv("HEXCORE_Z3_PATH");
    if (packagedPath && packagedPath[0] != '\0') return packagedPath;
    return souper::Z3Path;
}

#ifdef _WIN32
std::unique_ptr<souper::SMTLIBSolver> createUnderlyingSolver() {
    const std::string z3Path(resolveZ3Path());

    souper::SolverProgram program = [z3Path](
        const std::vector<std::string>& args,
        llvm::StringRef redirectIn,
        llvm::StringRef redirectOut,
        llvm::StringRef,
        unsigned timeout) -> int {
        SECURITY_ATTRIBUTES security = {};
        security.nLength = sizeof(security);
        security.bInheritHandle = TRUE;

        HANDLE input = CreateFileA(
            redirectIn.str().c_str(), GENERIC_READ, FILE_SHARE_READ,
            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE output = CreateFileA(
            redirectOut.str().c_str(), GENERIC_WRITE, FILE_SHARE_READ,
            &security, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        HANDLE error = CreateFileA(
            "NUL", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
            &security, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

        if (input == INVALID_HANDLE_VALUE ||
            output == INVALID_HANDLE_VALUE ||
            error == INVALID_HANDLE_VALUE) {
            if (input != INVALID_HANDLE_VALUE) CloseHandle(input);
            if (output != INVALID_HANDLE_VALUE) CloseHandle(output);
            if (error != INVALID_HANDLE_VALUE) CloseHandle(error);
            return -1;
        }

        std::string command = '"' + z3Path + '"';
        for (const auto& arg : args) command += " " + arg;
        std::vector<char> mutableCommand(command.begin(), command.end());
        mutableCommand.push_back('\0');

        STARTUPINFOA startup = {};
        startup.cb = sizeof(startup);
        startup.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        startup.wShowWindow = SW_HIDE;
        startup.hStdInput = input;
        startup.hStdOutput = output;
        startup.hStdError = error;

        PROCESS_INFORMATION process = {};
        const BOOL created = CreateProcessA(
            z3Path.c_str(), mutableCommand.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process);

        CloseHandle(input);
        CloseHandle(output);
        CloseHandle(error);

        if (!created) return -1;

        const DWORD waitMs = timeout > 0 ? timeout * 1000 : INFINITE;
        const DWORD waitResult = WaitForSingleObject(process.hProcess, waitMs);
        if (waitResult == WAIT_TIMEOUT) {
            TerminateProcess(process.hProcess, ERROR_TIMEOUT);
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            return -2;
        }

        DWORD exitCode = 1;
        if (waitResult == WAIT_OBJECT_0) {
            GetExitCodeProcess(process.hProcess, &exitCode);
        }
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
        if (waitResult != WAIT_OBJECT_0) return -1;

        const std::string outputPath = redirectOut.str();
        FILE* outputFile = nullptr;
        if (fopen_s(&outputFile, outputPath.c_str(), "rb") == 0 && outputFile) {
            fseek(outputFile, 0, SEEK_END);
            const long outputSize = ftell(outputFile);
            fseek(outputFile, 0, SEEK_SET);
            std::string content(
                outputSize > 0 ? static_cast<size_t>(outputSize) : 0, '\0');
            if (!content.empty()) {
                fread(content.data(), 1, content.size(), outputFile);
            }
            fclose(outputFile);

            content.erase(
                std::remove(content.begin(), content.end(), '\r'),
                content.end());
            if (fopen_s(&outputFile, outputPath.c_str(), "wb") == 0 &&
                outputFile) {
                if (!content.empty()) {
                    fwrite(content.data(), 1, content.size(), outputFile);
                }
                fclose(outputFile);
            }
        }

        return static_cast<int>(exitCode);
    };

    return souper::createZ3Solver(std::move(program), souper::KeepSolverInputs);
}
#else
std::unique_ptr<souper::SMTLIBSolver> createUnderlyingSolver() {
    return souper::createZ3Solver(
        souper::makeExternalSolverProgram(resolveZ3Path()),
        souper::KeepSolverInputs);
}
#endif

std::unique_ptr<souper::Solver> createSolver(size_t timeoutMs,
                                             souper::KVStore*& kv) {
    auto solver = souper::createBaseSolver(
        createUnderlyingSolver(), timeoutSeconds(timeoutMs));
    if (souper::ExternalCache) {
        kv = new souper::KVStore;
        solver = souper::createExternalCachingSolver(std::move(solver), kv);
    }
    if (souper::MemCache) {
        solver = souper::createMemCachingSolver(std::move(solver));
    }
    return solver;
}

size_t expressionSize(souper::Inst* inst,
                      std::unordered_set<souper::Inst*>& visited) {
    if (!inst || !visited.insert(inst).second) return 0;
    size_t size = 1;
    for (auto* operand : inst->Ops) size += expressionSize(operand, visited);
    return size;
}

souper::Inst* selectRhs(const std::vector<souper::Inst*>& candidates,
                        bool aggressiveMode) {
    if (candidates.empty()) return nullptr;
    if (!aggressiveMode || candidates.size() == 1) return candidates.front();

    return *std::min_element(
        candidates.begin(), candidates.end(),
        [](souper::Inst* lhs, souper::Inst* rhs) {
            std::unordered_set<souper::Inst*> lhsVisited;
            std::unordered_set<souper::Inst*> rhsVisited;
            return expressionSize(lhs, lhsVisited) <
                   expressionSize(rhs, rhsVisited);
        });
}

bool applyReplacement(llvm::Module& module,
                      llvm::DominatorTree& dominatorTree,
                      std::map<souper::Inst*, llvm::Value*>& replacedValues,
                      souper::CandidateReplacement& candidate) {
    auto* origin = candidate.Origin;
    auto* rhs = candidate.Mapping.RHS;
    if (!origin || !origin->getParent() || !rhs) return false;

    bool hasApplicableUse = false;
    if (candidate.Mapping.LHS->HarvestKind ==
        souper::HarvestType::HarvestedFromDef) {
        hasApplicableUse = !origin->use_empty();
    } else {
        for (const llvm::Use& use : origin->uses()) {
            const auto* user = llvm::dyn_cast<llvm::Instruction>(use.getUser());
            if (user && user->getParent() == candidate.Mapping.LHS->HarvestFrom) {
                hasApplicableUse = true;
                break;
            }
        }
    }
    if (!hasApplicableUse) return false;

    llvm::IRBuilder<> builder(origin);
    llvm::Value* replacement = souper::Codegen(
        origin->getContext(), &module, builder, &dominatorTree, origin,
        replacedValues).getValue(rhs);
    if (!replacement || replacement == origin ||
        replacement->getType() != origin->getType()) {
        return false;
    }

    bool applied = false;
    if (candidate.Mapping.LHS->HarvestKind ==
        souper::HarvestType::HarvestedFromDef) {
        applied = !origin->use_empty();
        origin->replaceAllUsesWith(replacement);
        replacedValues[candidate.Mapping.LHS] = replacement;
    } else {
        for (auto use = origin->use_begin(); use != origin->use_end();) {
            llvm::Use& current = *use++;
            auto* user = llvm::dyn_cast<llvm::Instruction>(current.getUser());
            if (user && user->getParent() == candidate.Mapping.LHS->HarvestFrom) {
                current.set(replacement);
                applied = true;
            }
        }
    }

    return applied;
}

void eliminateDeadInstructions(llvm::Function& function) {
    bool changed = false;
    do {
        changed = false;
        for (auto& block : function) {
            for (auto instruction = block.begin(); instruction != block.end();) {
                llvm::Instruction* current = &*instruction++;
                if (llvm::isInstructionTriviallyDead(current)) {
                    current->eraseFromParent();
                    changed = true;
                }
            }
        }
    } while (changed);
}

} // namespace

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
//  Core Optimization Pipeline v0.2.2
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
    uint32_t totalAttempted = 0;
    uint32_t totalInferred = 0;
    uint32_t totalReplaced = 0;
    uint32_t totalTimeouts = 0;

    // Ensure Z3 DLLs are findable when LLVM spawns the z3.exe process
#ifdef _WIN32
    {
        // Extract directory from Z3Path and add to PATH
        std::string z3Dir(resolveZ3Path());
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
        solver = createSolver(options.timeoutMs, KV);
        if (solver) {
            solverDebug = "solver_created:" + solver->getName() +
                " timeout_ms=" + std::to_string(options.timeoutMs);
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
    uint32_t inferErrors = 0, inferEmpty = 0, inferNotApplied = 0;

    // ── Phase 4: Extract & optimize per function ───────────────────────
    for (auto& func : *module) {
        if (func.isDeclaration()) continue;

        try {
            souper::ExprBuilderContext EBC;
            souper::ExprBuilderOptions EBOpts;
            llvm::DominatorTree dominatorTree(func);
            std::map<souper::Inst*, llvm::Value*> replacedValues;
            size_t functionAttempts = 0;
            bool limitReached = false;
            const uint32_t replacementsBeforeFunction = totalReplaced;

            souper::FunctionCandidateSet FCS =
                souper::ExtractCandidates(func, IC, EBC, EBOpts);

            for (auto& BCS : FCS.Blocks) {
                totalCandidates += static_cast<uint32_t>(BCS->Replacements.size());
            }

            for (auto& BCS : FCS.Blocks) {

                if (!solver) continue;

                for (auto& CR : BCS->Replacements) {
                    if (options.maxCandidates > 0 &&
                        functionAttempts >= options.maxCandidates) {
                        limitReached = true;
                        break;
                    }

                    functionAttempts++;
                    totalAttempted++;
                    try {
                        std::vector<souper::Inst*> RHSCandidates;
                        std::error_code EC = solver->infer(
                            CR.BPCs, CR.PCs,
                            CR.Mapping.LHS,
                            RHSCandidates,
                            /*AllowMultipleRHSs=*/options.aggressiveMode,
                            IC);

                        if (EC) {
                            inferErrors++;
                            if (EC == std::errc::timed_out) totalTimeouts++;
                            if (inferDebug.empty()) {
                                inferDebug = "first_error:" + EC.message();
                            }
                        } else if (RHSCandidates.empty()) {
                            inferEmpty++;
                        } else {
                            totalInferred++;
                            CR.Mapping.RHS = selectRhs(
                                RHSCandidates, options.aggressiveMode);
                            if (applyReplacement(
                                    *module, dominatorTree, replacedValues, CR)) {
                                totalReplaced++;
                            } else {
                                inferNotApplied++;
                            }
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
                if (limitReached) break;
            }

            if (totalReplaced > replacementsBeforeFunction) {
                eliminateDeadInstructions(func);
            }
        } catch (...) {
            // Non-fatal: skip this function
            continue;
        }
    }

    // Clean up KVStore if allocated
    delete KV;

    // Codegen can synthesize general RHS expressions. Never return transformed
    // IR unless the final module still satisfies LLVM's verifier.
    {
        std::string verifyErr;
        llvm::raw_string_ostream verifyStream(verifyErr);
        if (llvm::verifyModule(*module, &verifyStream)) {
            verifyStream.flush();
            result.success = false;
            result.error = "Optimized LLVM IR verification failed: " + verifyErr;
            return result;
        }
    }

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
    result.candidatesAttempted = totalAttempted;
    result.candidatesInferred = totalInferred;
    result.candidatesReplaced = totalReplaced;
    result.solverTimeouts = totalTimeouts;
    result.optimizationTimeMs =
        std::chrono::duration<double, std::milli>(endTime - startTime).count();

    if (totalCandidates > 0) {
        std::string diag = solverDebug +
            " | attempts=" + std::to_string(totalAttempted) +
            " inferred=" + std::to_string(totalInferred) +
            " not_applied=" + std::to_string(inferNotApplied) +
            " timeouts=" + std::to_string(totalTimeouts) +
            " errors=" + std::to_string(inferErrors) +
            " empty=" + std::to_string(inferEmpty);
        if (!inferDebug.empty()) diag += " | " + inferDebug;
        result.diagnostics = std::move(diag);
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
    obj.Set("diagnostics", Napi::String::New(env, result.diagnostics));
    obj.Set("candidatesFound", Napi::Number::New(env, result.candidatesFound));
    obj.Set("candidatesAttempted", Napi::Number::New(env, result.candidatesAttempted));
    obj.Set("candidatesInferred", Napi::Number::New(env, result.candidatesInferred));
    obj.Set("candidatesReplaced", Napi::Number::New(env, result.candidatesReplaced));
    obj.Set("solverTimeouts", Napi::Number::New(env, result.solverTimeouts));
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
    return Napi::String::New(info.Env(), kSouperWrapperVersion);
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
