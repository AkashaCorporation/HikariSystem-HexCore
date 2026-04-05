/**
 * HexCore Remill - N-API Wrapper Header
 * Lifts machine code to LLVM IR bitcode
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef HEXCORE_REMILL_WRAPPER_H
#define HEXCORE_REMILL_WRAPPER_H

#include <napi.h>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>

// Forward declarations
namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm

namespace remill {
class Arch;
class IntrinsicTable;
}  // namespace remill

/**
 * Options to control lifting boundaries and prevent oversized IR.
 */
struct LiftOptions {
	size_t maxInstructions = 2000;    // Max decoded instructions per lift
	size_t maxBasicBlocks  = 500;     // Max basic block leaders
	size_t maxBytes        = 32768;   // Max bytes to decode (32KB)
	bool   splitAtCalls    = true;    // Record external CALL targets
	bool   optimizeIR      = true;    // Run LLVM passes (mem2reg, instcombine, simplifycfg, dce)
	bool   inlineSemantics = false;   // Preserve named semantic calls by default for downstream decompilers
};

/**
 * Result of lifting a single instruction or block of bytes.
 */
struct LiftResult {
	bool success;
	std::string ir;          // LLVM IR as text
	std::string error;       // Error message if !success
	uint64_t address;        // Start address
	uint64_t bytesConsumed;  // How many input bytes were consumed

	// Boundary detection metadata
	bool truncated = false;            // True if limits were hit before all bytes consumed
	uint64_t nextAddress = 0;          // Where to continue lifting (valid if truncated)
	std::vector<uint64_t> callTargets; // Discovered external CALL targets
	std::string truncationReason;      // "max_instructions" | "max_blocks" | "max_bytes"

	// Register analysis metadata
	std::vector<std::string> implicitParams; // Registers read before written (function params)
};

/**
 * RemillLifter — N-API ObjectWrap that owns an Arch + LLVMContext.
 *
 * Lifecycle:
 *   const lifter = new RemillLifter('amd64');
 *   const result = lifter.liftBytes(buffer, 0x401000);
 *   lifter.close();
 */
class RemillLifter : public Napi::ObjectWrap<RemillLifter> {
public:
	static Napi::Object Init(Napi::Env env, Napi::Object exports);

	explicit RemillLifter(const Napi::CallbackInfo& info);
	~RemillLifter();

	// Public for AsyncWorker access
	LiftResult DoLift(const uint8_t* bytes, size_t length, uint64_t address,
	                   const LiftOptions& options = LiftOptions{});
	Napi::Object LiftResultToJS(Napi::Env env, const LiftResult& result);

private:
	// --- JS-visible methods ---
	Napi::Value LiftBytes(const Napi::CallbackInfo& info);
	Napi::Value LiftBytesAsync(const Napi::CallbackInfo& info);
	Napi::Value GetArch(const Napi::CallbackInfo& info);
	static Napi::Value GetSupportedArchs(const Napi::CallbackInfo& info);
	Napi::Value Close(const Napi::CallbackInfo& info);
	Napi::Value IsOpen(const Napi::CallbackInfo& info);
	Napi::Value SetExternalSymbols(const Napi::CallbackInfo& info);
	Napi::Value ClearExternalSymbols(const Napi::CallbackInfo& info);

	// --- State ---
	std::string archName_;
	bool closed_ = false;

	// FIX-011: External symbol map (fakeAddr → symbol name) for ET_REL relocations.
	// Set from JS before liftBytes(); used after lifting to resolve CALLI targets.
	std::map<uint64_t, std::string> externalSymbols_;

	std::unique_ptr<llvm::LLVMContext> context_;
	std::unique_ptr<llvm::Module> semanticsModule_;
	std::unique_ptr<const remill::Arch> arch_;  // Arch::Get returns unique_ptr
	std::unique_ptr<remill::IntrinsicTable> intrinsics_;
};

/**
 * AsyncWorker for non-blocking lift operations.
 */
class LiftBytesWorker : public Napi::AsyncWorker {
public:
	LiftBytesWorker(
		Napi::Env env,
		RemillLifter* lifter,
		std::vector<uint8_t> bytes,
		uint64_t address,
		LiftOptions options);

	void Execute() override;
	void OnOK() override;
	void OnError(const Napi::Error& error) override;

	Napi::Promise::Deferred& GetDeferred() { return deferred_; }

private:
	RemillLifter* lifter_;
	std::vector<uint8_t> bytes_;
	uint64_t address_;
	LiftOptions options_;
	LiftResult result_;
	Napi::Promise::Deferred deferred_;
};

#endif  // HEXCORE_REMILL_WRAPPER_H
