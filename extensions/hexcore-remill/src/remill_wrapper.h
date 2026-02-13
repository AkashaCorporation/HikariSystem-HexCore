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
#include <memory>
#include <cstdint>

// Forward declarations — real Remill/LLVM types resolved at link time
namespace llvm {
class LLVMContext;
class Module;
}  // namespace llvm

namespace remill {
class Arch;
class IntrinsicTable;
}  // namespace remill

/**
 * Result of lifting a single instruction or block of bytes.
 */
struct LiftResult {
	bool success;
	std::string ir;          // LLVM IR as text
	std::string error;       // Error message if !success
	uint64_t address;        // Start address
	uint64_t bytesConsumed;  // How many input bytes were consumed
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

private:
	// --- JS-visible methods ---------------------------------------------------

	/** Lift raw bytes synchronously → { success, ir, error, address, bytesConsumed } */
	Napi::Value LiftBytes(const Napi::CallbackInfo& info);

	/** Lift raw bytes asynchronously (runs in worker thread) */
	Napi::Value LiftBytesAsync(const Napi::CallbackInfo& info);

	/** Get the architecture name this lifter was created with */
	Napi::Value GetArch(const Napi::CallbackInfo& info);

	/** Get supported architectures list */
	static Napi::Value GetSupportedArchs(const Napi::CallbackInfo& info);

	/** Release native resources */
	Napi::Value Close(const Napi::CallbackInfo& info);

	/** Check if the lifter is still open */
	Napi::Value IsOpen(const Napi::CallbackInfo& info);

	// --- Internal helpers -----------------------------------------------------

	LiftResult DoLift(const uint8_t* bytes, size_t length, uint64_t address);
	Napi::Object LiftResultToJS(Napi::Env env, const LiftResult& result);

	// --- State ----------------------------------------------------------------

	std::string archName_;
	bool closed_ = false;

	// Opaque pointers — allocated in constructor, freed in destructor / Close()
	std::unique_ptr<llvm::LLVMContext> context_;
	std::unique_ptr<llvm::Module> semanticsModule_;
	const remill::Arch* arch_ = nullptr;  // non-owning, managed by Remill
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
		uint64_t address);

	void Execute() override;
	void OnOK() override;
	void OnError(const Napi::Error& error) override;

private:
	RemillLifter* lifter_;
	std::vector<uint8_t> bytes_;
	uint64_t address_;
	LiftResult result_;
	Napi::Promise::Deferred deferred_;
};

#endif  // HEXCORE_REMILL_WRAPPER_H
