/**
 * HexCore Remill - N-API Wrapper Implementation
 * Lifts machine code to LLVM IR bitcode
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "remill_wrapper.h"

#include <remill/Arch/Arch.h>
#include <remill/Arch/Name.h>
#include <remill/BC/IntrinsicTable.h>
#include <remill/BC/Lifter.h>
#include <remill/BC/Util.h>
#include <remill/OS/OS.h>

#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/raw_ostream.h>

#include <sstream>

// ---------------------------------------------------------------------------
// RemillLifter
// ---------------------------------------------------------------------------

Napi::Object RemillLifter::Init(Napi::Env env, Napi::Object exports) {
	Napi::Function func = DefineClass(env, "RemillLifter", {
		InstanceMethod("liftBytes", &RemillLifter::LiftBytes),
		InstanceMethod("liftBytesAsync", &RemillLifter::LiftBytesAsync),
		InstanceMethod("getArch", &RemillLifter::GetArch),
		InstanceMethod("close", &RemillLifter::Close),
		InstanceMethod("isOpen", &RemillLifter::IsOpen),
		StaticMethod("getSupportedArchs", &RemillLifter::GetSupportedArchs),
	});

	Napi::FunctionReference* constructor = new Napi::FunctionReference();
	*constructor = Napi::Persistent(func);
	env.SetInstanceData(constructor);

	exports.Set("RemillLifter", func);
	return exports;
}

RemillLifter::RemillLifter(const Napi::CallbackInfo& info)
	: Napi::ObjectWrap<RemillLifter>(info) {

	Napi::Env env = info.Env();

	if (info.Length() < 1 || !info[0].IsString()) {
		Napi::TypeError::New(env,
			"Expected architecture name string (e.g. 'amd64', 'x86', 'aarch64')")
			.ThrowAsJavaScriptException();
		return;
	}

	archName_ = info[0].As<Napi::String>().Utf8Value();

	// Determine OS name — default to linux semantics for lifting
	std::string osName = "linux";
	if (info.Length() >= 2 && info[1].IsString()) {
		osName = info[1].As<Napi::String>().Utf8Value();
	}

	// Create LLVM context
	context_ = std::make_unique<llvm::LLVMContext>();

	// Get the architecture
	auto archName = remill::GetArchName(archName_);
	if (archName == remill::kArchInvalid) {
		Napi::Error::New(env,
			"Unsupported architecture: " + archName_ +
			". Use RemillLifter.getSupportedArchs() for valid names.")
			.ThrowAsJavaScriptException();
		return;
	}

	auto osName_e = remill::GetOSName(osName);

	arch_ = remill::Arch::Get(*context_, osName_e, archName);
	if (!arch_) {
		Napi::Error::New(env, "Failed to initialize Remill arch: " + archName_)
			.ThrowAsJavaScriptException();
		return;
	}

	// Load semantics module (contains instruction implementations as LLVM IR)
	semanticsModule_ = remill::LoadArchSemantics(arch_);
	if (!semanticsModule_) {
		Napi::Error::New(env,
			"Failed to load semantics module for arch: " + archName_)
			.ThrowAsJavaScriptException();
		return;
	}

	// Create intrinsic table from the semantics module
	intrinsics_ = std::make_unique<remill::IntrinsicTable>(semanticsModule_.get());
}

RemillLifter::~RemillLifter() {
	closed_ = true;
	intrinsics_.reset();
	semanticsModule_.reset();
	context_.reset();
	arch_ = nullptr;
}

Napi::Value RemillLifter::LiftBytes(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Lifter is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected (buffer, address)")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Get the byte buffer
	const uint8_t* bytes = nullptr;
	size_t length = 0;

	if (info[0].IsBuffer()) {
		auto buf = info[0].As<Napi::Buffer<uint8_t>>();
		bytes = buf.Data();
		length = buf.Length();
	} else if (info[0].IsTypedArray()) {
		auto arr = info[0].As<Napi::Uint8Array>();
		bytes = arr.Data();
		length = arr.ByteLength();
	} else {
		Napi::TypeError::New(env, "First argument must be Buffer or Uint8Array")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Get the base address
	uint64_t address = 0;
	if (info[1].IsNumber()) {
		address = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	} else if (info[1].IsBigInt()) {
		bool lossless = false;
		address = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	} else {
		Napi::TypeError::New(env, "Second argument must be number or BigInt (address)")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	LiftResult result = DoLift(bytes, length, address);
	return LiftResultToJS(env, result);
}

Napi::Value RemillLifter::LiftBytesAsync(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();

	if (closed_) {
		Napi::Error::New(env, "Lifter is closed").ThrowAsJavaScriptException();
		return env.Undefined();
	}

	if (info.Length() < 2) {
		Napi::TypeError::New(env, "Expected (buffer, address)")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	// Copy bytes into a vector for the worker thread
	std::vector<uint8_t> bytesCopy;
	if (info[0].IsBuffer()) {
		auto buf = info[0].As<Napi::Buffer<uint8_t>>();
		bytesCopy.assign(buf.Data(), buf.Data() + buf.Length());
	} else if (info[0].IsTypedArray()) {
		auto arr = info[0].As<Napi::Uint8Array>();
		bytesCopy.assign(arr.Data(), arr.Data() + arr.ByteLength());
	} else {
		Napi::TypeError::New(env, "First argument must be Buffer or Uint8Array")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	uint64_t address = 0;
	if (info[1].IsNumber()) {
		address = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());
	} else if (info[1].IsBigInt()) {
		bool lossless = false;
		address = info[1].As<Napi::BigInt>().Uint64Value(&lossless);
	}

	auto* worker = new LiftBytesWorker(env, this, std::move(bytesCopy), address);
	worker->Queue();

	// The worker creates and returns the promise deferred
	// We return the promise from the deferred stored in the worker
	// Note: actual promise return is handled by the worker pattern
	return env.Undefined();  // TODO: return deferred.Promise() from worker
}

Napi::Value RemillLifter::GetArch(const Napi::CallbackInfo& info) {
	return Napi::String::New(info.Env(), archName_);
}

Napi::Value RemillLifter::GetSupportedArchs(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	Napi::Array result = Napi::Array::New(env);

	const char* archs[] = {
		"x86", "x86_avx", "x86_avx512",
		"amd64", "amd64_avx", "amd64_avx512",
		"aarch64",
		"sparc32", "sparc64",
		nullptr
	};

	uint32_t idx = 0;
	for (const char** p = archs; *p; ++p) {
		result.Set(idx++, Napi::String::New(env, *p));
	}

	return result;
}

Napi::Value RemillLifter::Close(const Napi::CallbackInfo& info) {
	if (!closed_) {
		closed_ = true;
		intrinsics_.reset();
		semanticsModule_.reset();
		context_.reset();
		arch_ = nullptr;
	}
	return info.Env().Undefined();
}

Napi::Value RemillLifter::IsOpen(const Napi::CallbackInfo& info) {
	return Napi::Boolean::New(info.Env(), !closed_);
}

// ---------------------------------------------------------------------------
// Internal: DoLift
// ---------------------------------------------------------------------------

LiftResult RemillLifter::DoLift(
	const uint8_t* bytes, size_t length, uint64_t address) {

	LiftResult result;
	result.address = address;
	result.bytesConsumed = 0;
	result.success = false;

	if (!arch_ || !semanticsModule_ || !intrinsics_) {
		result.error = "Lifter not properly initialized";
		return result;
	}

	// Create a fresh module for this lift operation
	auto liftModule = remill::LoadArchSemantics(arch_);
	if (!liftModule) {
		result.error = "Failed to create lift module";
		return result;
	}

	auto intrinsics = std::make_unique<remill::IntrinsicTable>(liftModule.get());

	// Create the instruction lifter
	auto lifter = arch_->DefaultLifter(*intrinsics);

	// Decode and lift each instruction
	remill::Instruction inst;
	uint64_t pc = address;
	size_t offset = 0;

	// Create a lifted function to hold the instructions
	auto func = arch_->DeclareLiftedFunction(
		"lifted_" + std::to_string(address), liftModule.get());
	arch_->InitializeEmptyLiftedFunction(func);

	auto block = &func->getEntryBlock();

	while (offset < length) {
		// Decode the instruction
		if (!arch_->DecodeInstruction(pc, {bytes + offset, length - offset}, inst)) {
			if (offset == 0) {
				result.error = "Failed to decode instruction at 0x" +
					std::to_string(address);
				return result;
			}
			break;  // Stop at first undecoded instruction
		}

		// Lift the instruction into the block
		auto status = lifter->LiftIntoBlock(inst, block, false);
		if (status != remill::LiftStatus::kLiftedInstruction) {
			if (offset == 0) {
				result.error = "Failed to lift instruction at 0x" +
					std::to_string(pc);
				return result;
			}
			break;
		}

		offset += inst.bytes.size();
		pc += inst.bytes.size();
	}

	result.bytesConsumed = offset;

	// Print the module IR to string
	std::string irStr;
	llvm::raw_string_ostream os(irStr);
	func->print(os);
	os.flush();

	result.ir = irStr;
	result.success = true;
	return result;
}

Napi::Object RemillLifter::LiftResultToJS(
	Napi::Env env, const LiftResult& result) {

	Napi::Object obj = Napi::Object::New(env);
	obj.Set("success", Napi::Boolean::New(env, result.success));
	obj.Set("ir", Napi::String::New(env, result.ir));
	obj.Set("error", Napi::String::New(env, result.error));
	obj.Set("address", Napi::Number::New(env,
		static_cast<double>(result.address)));
	obj.Set("bytesConsumed", Napi::Number::New(env,
		static_cast<double>(result.bytesConsumed)));
	return obj;
}

// ---------------------------------------------------------------------------
// LiftBytesWorker
// ---------------------------------------------------------------------------

LiftBytesWorker::LiftBytesWorker(
	Napi::Env env,
	RemillLifter* lifter,
	std::vector<uint8_t> bytes,
	uint64_t address)
	: Napi::AsyncWorker(env),
	  lifter_(lifter),
	  bytes_(std::move(bytes)),
	  address_(address),
	  deferred_(Napi::Promise::Deferred::New(env)) {}

void LiftBytesWorker::Execute() {
	result_ = lifter_->DoLift(bytes_.data(), bytes_.size(), address_);
	if (!result_.success) {
		SetError(result_.error);
	}
}

void LiftBytesWorker::OnOK() {
	Napi::Env env = Env();
	deferred_.Resolve(lifter_->LiftResultToJS(env, result_));
}

void LiftBytesWorker::OnError(const Napi::Error& error) {
	deferred_.Reject(error.Value());
}
