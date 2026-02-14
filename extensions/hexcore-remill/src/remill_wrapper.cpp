/**
 * HexCore Remill - N-API Wrapper Implementation
 * Lifts machine code to LLVM IR bitcode
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "remill_wrapper.h"

// MSVC doesn't define __x86_64__, so Remill's Name.h #error fires.
// Define REMILL_ARCH before including any Remill headers.
#if defined(_M_X64) && !defined(REMILL_ARCH)
#define REMILL_ARCH "amd64_avx"
#define REMILL_ON_AMD64 1
#define REMILL_ON_X86 0
#define REMILL_ON_AARCH64 0
#define REMILL_ON_AARCH32 0
#define REMILL_ON_SPARC64 0
#define REMILL_ON_SPARC32 0
#define REMILL_ON_PPC 0
#elif defined(_M_IX86) && !defined(REMILL_ARCH)
#define REMILL_ARCH "x86"
#define REMILL_ON_AMD64 0
#define REMILL_ON_X86 1
#define REMILL_ON_AARCH64 0
#define REMILL_ON_AARCH32 0
#define REMILL_ON_SPARC64 0
#define REMILL_ON_SPARC32 0
#define REMILL_ON_PPC 0
#endif

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
#include <llvm/Transforms/Utils/Cloning.h>

#include <sstream>
#include <filesystem>

// Forward-declare Win32 functions to avoid #include <windows.h> which
// conflicts with Sleigh's CHAR token (ghidra::sleightokentype::CHAR
// vs winnt.h typedef char CHAR).
#ifdef _WIN32
extern "C" {
__declspec(dllimport) void* __stdcall GetModuleHandleA(const char*);
__declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void*, char*, unsigned long);
}
#endif

// Helper: resolve the semantics directory at runtime.
//
// Priority:
//   1. REMILL_SEMANTICS_DIR env var (explicit override)
//   2. Relative to the .node binary — works for both layouts:
//        build/Release/hexcore_remill.node   (dev build)
//        prebuilds/win32-x64/hexcore_remill.node (packaged)
//      Both are 2 directories below the extension root, so we need
//      3 parent_path() calls: file → containing dir → intermediate → root.
//   3. Relative to CWD as last resort (dev convenience)
//   4. Compile-time __FILE__ path (dev only)
//
// On Windows we use GetModuleHandleA("hexcore_remill.node") +
// GetModuleFileNameA to find the DLL path at runtime.
static std::filesystem::path GetSemanticsDir() {
	const std::filesystem::path relSem =
		std::filesystem::path("deps") / "remill" / "share" / "semantics";

	// 1. Environment variable override
	const char* envDir = std::getenv("REMILL_SEMANTICS_DIR");
	if (envDir && envDir[0] != '\0') {
		std::filesystem::path envPath(envDir);
		if (std::filesystem::is_directory(envPath)) {
			return envPath;
		}
	}

	// 2. Resolve from the .node binary location
#ifdef _WIN32
	// Try both naming conventions: underscore (prebuildify) and hyphen (prebuild-install)
	void* hMod = GetModuleHandleA("hexcore_remill.node");
	if (!hMod) {
		hMod = GetModuleHandleA("hexcore-remill.node");
	}
	if (hMod) {
		char dllPath[260] = {0};  // MAX_PATH = 260
		unsigned long len = GetModuleFileNameA(hMod, dllPath, 260);
		if (len > 0 && len < 260) {
			// dllPath example:
			//   .../extensions/hexcore-remill/build/Release/hexcore_remill.node
			//   .../extensions/hexcore-remill/prebuilds/win32-x64/hexcore_remill.node
			//
			// parent_path(1): removes filename  → .../build/Release
			// parent_path(2): removes Release   → .../build
			// parent_path(3): removes build     → .../hexcore-remill  (extension root)
			auto extensionRoot = std::filesystem::path(dllPath)
				.parent_path()
				.parent_path()
				.parent_path();
			auto semDir = extensionRoot / relSem;
			if (std::filesystem::is_directory(semDir)) {
				return semDir;
			}
		}
	}
#endif

	// 3. Fallback: relative to CWD (works when running from module root)
	auto cwdSem = std::filesystem::current_path() / relSem;
	if (std::filesystem::is_directory(cwdSem)) {
		return cwdSem;
	}

	// 4. Last resort: compile-time path (dev only — won't work on other machines)
	std::filesystem::path srcFile(__FILE__);
	return srcFile.parent_path().parent_path() / relSem;
}

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

	// Validate architecture name
	auto archEnum = remill::GetArchName(archName_);
	if (archEnum == remill::kArchInvalid) {
		Napi::Error::New(env,
			"Unsupported architecture: " + archName_ +
			". Use RemillLifter.getSupportedArchs() for valid names.")
			.ThrowAsJavaScriptException();
		return;
	}

	auto osEnum = remill::GetOSName(osName);

	// Arch::Get returns unique_ptr<const Arch>
	arch_ = remill::Arch::Get(*context_, osEnum, archEnum);
	if (!arch_) {
		Napi::Error::New(env, "Failed to initialize Remill arch: " + archName_)
			.ThrowAsJavaScriptException();
		return;
	}

	// Load semantics module (contains instruction implementations as LLVM IR)
	std::vector<std::filesystem::path> semDirs = { GetSemanticsDir() };
	semanticsModule_ = remill::LoadArchSemantics(arch_.get(), semDirs);
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
	arch_.reset();
	context_.reset();
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

	try {
		LiftResult result = DoLift(bytes, length, address);
		return LiftResultToJS(env, result);
	} catch (const std::exception& e) {
		LiftResult result;
		result.address = address;
		result.bytesConsumed = 0;
		result.success = false;
		result.error = std::string("Native exception during lift: ") + e.what();
		return LiftResultToJS(env, result);
	} catch (...) {
		LiftResult result;
		result.address = address;
		result.bytesConsumed = 0;
		result.success = false;
		result.error = "Unknown native exception during lift";
		return LiftResultToJS(env, result);
	}
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
	auto promise = worker->GetDeferred().Promise();
	worker->Queue();
	return promise;
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
		arch_.reset();
		context_.reset();
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

	if (length == 0) {
		result.error = "Empty buffer";
		return result;
	}

	// Clone the cached semantics module instead of reloading from disk.
	// LoadArchSemantics reads ~50MB of .bc per call; CloneModule copies the
	// in-memory IR in microseconds with zero disk I/O.
	auto liftModule = llvm::CloneModule(*semanticsModule_);
	if (!liftModule) {
		result.error = "Failed to clone semantics module";
		return result;
	}

	auto intrinsics = std::make_unique<remill::IntrinsicTable>(liftModule.get());

	// DefaultLifter returns shared_ptr<OperandLifter>
	auto lifter = arch_->DefaultLifter(*intrinsics);

	// DefaultLifter always returns an InstructionLifterIntf-derived object.
	// Use static_pointer_cast (dynamic_pointer_cast requires RTTI which is
	// disabled by NAPI_DISABLE_CPP_EXCEPTIONS).
	auto instLifter = std::static_pointer_cast<remill::InstructionLifterIntf>(lifter);

	// Decode and lift each instruction
	remill::Instruction inst;
	uint64_t pc = address;
	size_t offset = 0;

	// Create a lifted function to hold the instructions
	auto func = arch_->DeclareLiftedFunction(
		"lifted_" + std::to_string(address), liftModule.get());
	arch_->InitializeEmptyLiftedFunction(func);

	auto block = &func->getEntryBlock();

	// Create initial decoding context for this architecture
	auto context = arch_->CreateInitialContext();

	while (offset < length) {
		std::string_view instrBytes(
			reinterpret_cast<const char*>(bytes + offset), length - offset);

		// DecodeInstruction requires DecodingContext as 4th parameter
		if (!arch_->DecodeInstruction(pc, instrBytes, inst, context)) {
			if (offset == 0) {
				result.error = "Failed to decode instruction at 0x" +
					std::to_string(address);
				return result;
			}
			break;  // Stop at first undecoded instruction
		}

		// LiftIntoBlock with 2-arg overload (inst, block)
		auto status = instLifter->LiftIntoBlock(inst, block, false);
		if (status != remill::kLiftedInstruction) {
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

	// Print the function IR to string
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
	try {
		result_ = lifter_->DoLift(bytes_.data(), bytes_.size(), address_);
		if (!result_.success) {
			SetError(result_.error);
		}
	} catch (const std::exception& e) {
		result_.address = address_;
		result_.bytesConsumed = 0;
		result_.success = false;
		result_.error = std::string("Native exception during async lift: ") + e.what();
		SetError(result_.error);
	} catch (...) {
		result_.address = address_;
		result_.bytesConsumed = 0;
		result_.success = false;
		result_.error = "Unknown native exception during async lift";
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
