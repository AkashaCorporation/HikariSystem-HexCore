/**
 * HexCore Rellic - N-API Wrapper Header
 * Decompiles LLVM IR to pseudo-C via Rellic
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef HEXCORE_RELLIC_WRAPPER_H
#define HEXCORE_RELLIC_WRAPPER_H

#include <napi.h>
#include <string>
#include <vector>
#include <memory>

// LLVM headers needed for DoDecompile
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Type.h>
#include <llvm/AsmParser/Parser.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>

/**
 * Result of a decompilation operation.
 */
struct DecompileResult {
	bool success;
	std::string code;          // Pseudo-C output
	std::string error;         // Error message if !success
	int functionCount;         // Number of functions decompiled
};

/**
 * RellicDecompiler — N-API ObjectWrap that owns LLVM + Clang + Z3 contexts.
 *
 * Lifecycle:
 *   const decompiler = new RellicDecompiler();
 *   const result = decompiler.decompile(irText);
 *   decompiler.close();
 */
class RellicDecompiler : public Napi::ObjectWrap<RellicDecompiler> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);

	explicit RellicDecompiler(const Napi::CallbackInfo& info);
	~RellicDecompiler();

	// Public for AsyncWorker access
	DecompileResult DoDecompile(const std::string& irText);
	Napi::Object DecompileResultToJS(Napi::Env env, const DecompileResult& result);

private:
	// --- JS-visible methods ---
	Napi::Value Decompile(const Napi::CallbackInfo& info);
	Napi::Value DecompileAsync(const Napi::CallbackInfo& info);
	Napi::Value Close(const Napi::CallbackInfo& info);
	Napi::Value IsOpen(const Napi::CallbackInfo& info);

	// --- State ---
	bool closed_ = false;
	std::unique_ptr<llvm::LLVMContext> llvmContext_;
	// clang::ASTContext and Z3 context are created lazily during decompilation
};

/**
 * AsyncWorker for non-blocking decompilation.
 */
class DecompileAsyncWorker : public Napi::AsyncWorker {
public:
	DecompileAsyncWorker(
		Napi::Env env,
		RellicDecompiler* decompiler,
		std::string irText);

	void Execute() override;
	void OnOK() override;
	void OnError(const Napi::Error& error) override;

	Napi::Promise::Deferred& GetDeferred() { return deferred_; }

private:
	RellicDecompiler* decompiler_;
	std::string irText_;
	DecompileResult result_;
	Napi::Promise::Deferred deferred_;
};

#endif  // HEXCORE_RELLIC_WRAPPER_H
