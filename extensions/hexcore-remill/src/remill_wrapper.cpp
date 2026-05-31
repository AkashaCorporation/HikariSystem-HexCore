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

#include <llvm/IR/Instructions.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GlobalAlias.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/Intrinsics.h>

// LLVM New Pass Manager + optimization passes
#include <llvm/Passes/PassBuilder.h>
#include <llvm/IR/PassManager.h>
#include <llvm/Transforms/Utils/Mem2Reg.h>
#include <llvm/Transforms/InstCombine/InstCombine.h>
#include <llvm/Transforms/Scalar/SimplifyCFG.h>
#include <llvm/Transforms/Scalar/DCE.h>
#include <llvm/Transforms/Scalar/ADCE.h>
#include <llvm/Transforms/Scalar/DeadStoreElimination.h>
#include <llvm/Transforms/Scalar/EarlyCSE.h>
#include <llvm/Transforms/Scalar/SROA.h>
#include <llvm/Transforms/Utils/Cloning.h>
#include <llvm/Analysis/CGSCCPassManager.h>
#include <llvm/Analysis/LoopAnalysisManager.h>

#include <sstream>
#include <set>
#include <vector>
#include <filesystem>
#include <mutex>
#include <variant>
#include <algorithm>

// FIX-024: Intel XED Instruction Length Decoder for x86 desync recovery.
// When Remill's arch_->DecodeInstruction fails on exotic x86 instructions
// (AVX-512, APX, MPX, etc.), XED-ILD gives us the instruction length so
// we can emit a NoOp placeholder and advance exactly one instruction,
// preserving code density and all subsequent basic blocks.
extern "C" {
#include <xed/xed-interface.h>
}

// Forward-declare Win32 functions to avoid #include <windows.h> which
// conflicts with Sleigh's CHAR token (ghidra::sleightokentype::CHAR
// vs winnt.h typedef char CHAR).
#ifdef _WIN32
extern "C" {
__declspec(dllimport) void* __stdcall GetModuleHandleA(const char*);
__declspec(dllimport) unsigned long __stdcall GetModuleFileNameA(void*, char*, unsigned long);
}
#endif

// ═══════════════════════════════════════════════════════════════════════
// FIX-024: XED Instruction Length Decoder helper
// ═══════════════════════════════════════════════════════════════════════

/**
 * One-time thread-safe initialization of XED tables.
 * XED is stateless after init, so a single global init is sufficient.
 */
static void EnsureXedInitialized() {
	static std::once_flag xedInitFlag;
	std::call_once(xedInitFlag, []() {
		xed_tables_init();
	});
}

/**
 * Decode instruction length using XED-ILD (Instruction Length Decoder).
 * Returns the length in bytes, or 0 if XED also fails to recognize the
 * instruction (truly invalid bytes).
 *
 * @param bytes     Pointer to the instruction bytes
 * @param maxLen    Maximum bytes available to read (avoid overrun)
 * @param is64Bit   True for LONG_64 mode, false for LEGACY_32
 */
static size_t XedInstructionLength(const uint8_t* bytes, size_t maxLen, bool is64Bit) {
	if (!bytes || maxLen == 0) {
		return 0;
	}

	EnsureXedInitialized();

	xed_decoded_inst_t xedd;
	xed_decoded_inst_zero(&xedd);
	xed_decoded_inst_set_mode(
		&xedd,
		is64Bit ? XED_MACHINE_MODE_LONG_64 : XED_MACHINE_MODE_LEGACY_32,
		is64Bit ? XED_ADDRESS_WIDTH_64b   : XED_ADDRESS_WIDTH_32b);

	// xed_ild_decode is the length-only decoder — much faster than xed_decode.
	// It only parses the prefix/opcode structure to compute length, without
	// decoding operands. Perfect for our use case.
	const unsigned int capLen = static_cast<unsigned int>(
		maxLen > XED_MAX_INSTRUCTION_BYTES ? XED_MAX_INSTRUCTION_BYTES : maxLen);

	xed_error_enum_t err = xed_ild_decode(&xedd, bytes, capLen);
	if (err != XED_ERROR_NONE) {
		return 0;
	}

	unsigned int len = xed_decoded_inst_get_length(&xedd);
	if (len == 0 || len > maxLen) {
		return 0;
	}
	return static_cast<size_t>(len);
}

static llvm::AllocaInst* FindNamedAlloca(llvm::Function* func, llvm::StringRef name) {
	if (!func) {
		return nullptr;
	}

	for (auto& inst : func->getEntryBlock()) {
		auto* allocaInst = llvm::dyn_cast<llvm::AllocaInst>(&inst);
		if (!allocaInst) {
			continue;
		}
		if (allocaInst->getName() == name) {
			return allocaInst;
		}
	}

	return nullptr;
}

// ═══════════════════════════════════════════════════════════════════════
// FIX-052b: Recover a direct-jump target from the DECODED instruction.
// ═══════════════════════════════════════════════════════════════════════
// In the LLVM-18 / Remill build we link against, a relative unconditional
// `jmp rel8/rel32` is lifted as a `JMPI` semantic-helper CALL and the decoder
// reports `inst.branch_taken_pc == 0` — the real target survives only as the
// helper's i64 immediate (and in the decode-time flow info). Relying on
// `branch_taken_pc` alone therefore drops EVERY unconditional-jump edge, so the
// callfuscation jmp-chain collapses into one block. This helper recovers the
// target from, in priority order:
//   1. inst.branch_taken_pc                       (set for cond branches / some builds)
//   2. the DirectJump flow's known_target          (decoder's authoritative target)
//   3. a kTypeAddress / kControlFlowTarget operand  (displacement = absolute target)
//   4. (caller-side fallback) the lifted JMPI call's i64 arg — see ReadJmpiTarget.
// Returns 0 when no decode-time target is available (caller then tries the
// post-lift JMPI scan).
static uint64_t ResolveDirectJumpTargetFromDecode(const remill::Instruction& inst) {
	if (inst.branch_taken_pc) {
		return inst.branch_taken_pc;
	}

	// Decoder flow info: DirectJump.taken_flow.known_target.
	if (auto* dj = std::get_if<remill::Instruction::DirectJump>(&inst.flows)) {
		if (dj->taken_flow.known_target) {
			return dj->taken_flow.known_target;
		}
	}
	// Conditional direct branch keeps the taken target the same way.
	if (auto* ci = std::get_if<remill::Instruction::ConditionalInstruction>(&inst.flows)) {
		if (auto* dj = std::get_if<remill::Instruction::DirectJump>(&ci->taken_branch)) {
			if (dj->taken_flow.known_target) {
				return dj->taken_flow.known_target;
			}
		}
	}

	// Operand scan: a control-flow target address operand carries the absolute
	// destination in `displacement` for x86 relative jumps.
	for (const auto& op : inst.operands) {
		if (op.type == remill::Operand::kTypeAddress &&
		    op.addr.kind == remill::Operand::Address::kControlFlowTarget) {
			return static_cast<uint64_t>(op.addr.displacement);
		}
	}

	return 0;
}

// Post-lift fallback: read the i64 target argument from the JMPI helper call
// most recently emitted into `block`. The JMPI signature is
//   JMPI(ptr %memory, ptr %state, i64 <target>, ptr %NEXT_PC)
// so the target is the first i64 ConstantInt argument. Returns 0 if not found.
static uint64_t ReadJmpiTargetFromBlock(llvm::BasicBlock* block) {
	if (!block) {
		return 0;
	}
	for (auto it = block->rbegin(); it != block->rend(); ++it) {
		auto* CI = llvm::dyn_cast<llvm::CallInst>(&*it);
		if (!CI) {
			continue;
		}
		auto* callee = CI->getCalledFunction();
		if (!callee || !callee->getName().contains("JMPI")) {
			continue;
		}
		for (unsigned a = 0; a < CI->arg_size(); ++a) {
			if (auto* c = llvm::dyn_cast<llvm::ConstantInt>(CI->getArgOperand(a))) {
				if (c->getType()->isIntegerTy(64)) {
					return c->getZExtValue();
				}
			}
		}
	}
	return 0;
}

static LiftOptions ParseLiftOptions(const Napi::Value& value) {
	LiftOptions options;

	if (!value.IsObject()) {
		return options;
	}

	auto opts = value.As<Napi::Object>();
	if (opts.Has("maxInstructions") && opts.Get("maxInstructions").IsNumber())
		options.maxInstructions = opts.Get("maxInstructions").As<Napi::Number>().Uint32Value();
	if (opts.Has("maxBasicBlocks") && opts.Get("maxBasicBlocks").IsNumber())
		options.maxBasicBlocks = opts.Get("maxBasicBlocks").As<Napi::Number>().Uint32Value();
	if (opts.Has("maxBytes") && opts.Get("maxBytes").IsNumber())
		options.maxBytes = opts.Get("maxBytes").As<Napi::Number>().Uint32Value();
	if (opts.Has("splitAtCalls") && opts.Get("splitAtCalls").IsBoolean())
		options.splitAtCalls = opts.Get("splitAtCalls").As<Napi::Boolean>().Value();
	if (opts.Has("optimizeIR") && opts.Get("optimizeIR").IsBoolean())
		options.optimizeIR = opts.Get("optimizeIR").As<Napi::Boolean>().Value();
	if (opts.Has("inlineSemantics") && opts.Get("inlineSemantics").IsBoolean())
		options.inlineSemantics = opts.Get("inlineSemantics").As<Napi::Boolean>().Value();
	// FIX-052b: opt-in CFG-preserving optimization pipeline (deflatten path only).
	if (opts.Has("preserveCfgTopology") && opts.Get("preserveCfgTopology").IsBoolean())
		options.preserveCfgTopology = opts.Get("preserveCfgTopology").As<Napi::Boolean>().Value();

	// --- Item 2: additionalLeaders ---
	if (opts.Has("additionalLeaders") && opts.Get("additionalLeaders").IsArray()) {
		auto arr = opts.Get("additionalLeaders").As<Napi::Array>();
		options.additionalLeaders.reserve(arr.Length());
		for (uint32_t i = 0; i < arr.Length(); i++) {
			Napi::Value el = arr.Get(i);
			if (el.IsNumber()) {
				options.additionalLeaders.push_back(
					static_cast<uint64_t>(el.As<Napi::Number>().Int64Value()));
			} else if (el.IsBigInt()) {
				bool lossless = false;
				options.additionalLeaders.push_back(
					el.As<Napi::BigInt>().Uint64Value(&lossless));
			}
		}
	}

	// --- Item 3: liftMode ---
	if (opts.Has("liftMode") && opts.Get("liftMode").IsString()) {
		std::string modeStr = opts.Get("liftMode").As<Napi::String>().Utf8Value();
		if (modeStr == "pe64") {
			options.mode = LiftMode::PE64;
		} else if (modeStr == "elf_relocatable") {
			options.mode = LiftMode::ElfRelocatable;
		}
		// else: Generic (default)
	}

	// --- Item 3: knownFunctionEnds (PE64 mode) ---
	if (opts.Has("knownFunctionEnds") && opts.Get("knownFunctionEnds").IsArray()) {
		auto arr = opts.Get("knownFunctionEnds").As<Napi::Array>();
		options.knownFunctionEnds.reserve(arr.Length());
		for (uint32_t i = 0; i < arr.Length(); i++) {
			Napi::Value el = arr.Get(i);
			if (el.IsNumber()) {
				options.knownFunctionEnds.push_back(
					static_cast<uint64_t>(el.As<Napi::Number>().Int64Value()));
			} else if (el.IsBigInt()) {
				bool lossless = false;
				options.knownFunctionEnds.push_back(
					el.As<Napi::BigInt>().Uint64Value(&lossless));
			}
		}
	}

	return options;
}

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
		InstanceMethod("setExternalSymbols", &RemillLifter::SetExternalSymbols),
		InstanceMethod("clearExternalSymbols", &RemillLifter::ClearExternalSymbols),
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

	// Parse optional lift options (3rd argument)
	LiftOptions options = info.Length() > 2 ? ParseLiftOptions(info[2]) : LiftOptions{};

	try {
		LiftResult result = DoLift(bytes, length, address, options);
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

	LiftOptions options = info.Length() > 2 ? ParseLiftOptions(info[2]) : LiftOptions{};

	auto* worker = new LiftBytesWorker(env, this, std::move(bytesCopy), address, options);
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
	const uint8_t* bytes, size_t length, uint64_t address,
	const LiftOptions& options) {

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
	auto liftModule = llvm::CloneModule(*semanticsModule_);
	if (!liftModule) {
		result.error = "Failed to clone semantics module";
		return result;
	}

	auto intrinsics = std::make_unique<remill::IntrinsicTable>(liftModule.get());
	auto lifter = arch_->DefaultLifter(*intrinsics);
	auto instLifter = std::static_pointer_cast<remill::InstructionLifterIntf>(lifter);

	// Create initial decoding context for this architecture
	auto context = arch_->CreateInitialContext();

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 1: Pre-decode all instructions to discover basic block leaders
	// ═══════════════════════════════════════════════════════════════════════
	// A "leader" is the first address of a basic block.  Leaders are:
	//   1. The entry address (always a leader)
	//   2. The target of any branch (conditional or unconditional)
	//   3. The fall-through address of a conditional branch
	//
	// We decode every instruction once, collect its category, and record
	// leaders.  This pre-pass does NOT lift — it only decodes.

	struct DecodedInst {
		remill::Instruction inst;
		uint64_t pc;
		size_t size;
	};
	std::vector<DecodedInst> decoded;
	std::set<uint64_t> leaders;

	leaders.insert(address);  // Entry is always a leader

	// Pre-compute knownFunctionEnds as a set for O(log n) lookup
	std::set<uint64_t> functionEndSet(options.knownFunctionEnds.begin(),
	                                   options.knownFunctionEnds.end());

	// FIX-024 debug counters
	size_t fix024_xedRecovered = 0;
	size_t fix024_xedFailed = 0;
	size_t fix024_decodeFailures = 0;

	{
		remill::Instruction scanInst;
		uint64_t scanPC = address;
		size_t scanOffset = 0;
		auto scanContext = arch_->CreateInitialContext();

		// FIX-053: AArch64 (and other fixed-width RISC ISAs) decode failure on
		// multi-instruction buffers.
		//
		// Remill's AArch64 ArchDecodeInstruction has a HARD length gate:
		//     if (kInstructionSize != inst_bytes.size()) {
		//         inst.category = Instruction::kCategoryInvalid; return false;
		//     }
		// i.e. it requires EXACTLY 4 bytes -- not "at least 4". The x86/amd64
		// decoder, by contrast, wants the whole remaining stream (variable-length
		// + idiom fusing). This wrapper historically handed `length - scanOffset`
		// (the ENTIRE remaining buffer) to DecodeInstruction, which is correct for
		// x86 but makes EVERY AArch64 instruction except a lone 4-byte tail fail
		// the length gate. The failed decode then fell through to the FIX-024 XED
		// path and became a kCategoryNoOp stub, so the lift produced no real IR
		// (observed: `mov x0,#1; ret` -> "Failed to lift instruction").
		//
		// Arch.h's own note prescribes the fix: pass at most MaxInstructionSize()
		// bytes. For FIXED-WIDTH arches (Min == Max, e.g. AArch64 = 4) we clamp
		// the decode window to exactly that width. For VARIABLE-WIDTH arches
		// (x86/amd64) we keep the full-buffer behavior BYTE-FOR-BYTE so no x86
		// lift changes (idiom fusing + the FIX-052b jmp handling are untouched).
		const uint64_t minInsnSize = arch_->MinInstructionSize(scanContext);
		const uint64_t maxInsnSize =
			arch_->MaxInstructionSize(scanContext, /*permit_fuse_idioms=*/false);
		const bool fixedWidthIsa =
			(minInsnSize == maxInsnSize) && (maxInsnSize > 0);

		while (scanOffset < length) {
			// ─── PE64 mode: stop at known function end ──────────────────
			if (options.mode == LiftMode::PE64 && functionEndSet.count(scanPC)) {
				break;
			}

			// ─── PE64 mode: treat 0xCC (int3) as padding/terminator ────
			if (options.mode == LiftMode::PE64 && scanOffset < length) {
				const uint8_t* p = bytes + scanOffset;
				if (*p == 0xCC) {
					// Skip consecutive int3 padding bytes
					while (scanOffset < length && bytes[scanOffset] == 0xCC) {
						scanOffset++;
						scanPC++;
					}
					// If there's code after the padding, it's a new leader
					if (scanOffset < length) {
						leaders.insert(scanPC);
					}
					continue;
				}
			}

			// FIX-053: For fixed-width ISAs (AArch64), clamp the decode window to
			// exactly one instruction width so Remill's strict length gate accepts
			// it. For variable-width ISAs (x86/amd64), hand the whole remaining
			// buffer exactly as before.
			size_t decodeWindow = length - scanOffset;
			if (fixedWidthIsa &&
				static_cast<uint64_t>(decodeWindow) > maxInsnSize) {
				decodeWindow = static_cast<size_t>(maxInsnSize);
			}
			std::string_view instrBytes(
				reinterpret_cast<const char*>(bytes + scanOffset), decodeWindow);

			// FIX-053: Reset the reused Instruction before every decode.
			//
			// `scanInst` is reused across the whole Phase-1 sweep. Remill's x86
			// decoder clears prior decode state internally, but the AArch64
			// decoder APPENDS operands onto whatever is already in `inst.operands`
			// without first clearing them. So the 2nd (and every later) AArch64
			// instruction inherited the previous instruction's operands, ending up
			// with MORE operands than its semantics ISEL function has parameters,
			// InstructionLifter then bails with kLiftedMismatchedISEL and the lift
			// stops after a single instruction (observed: every AArch64 function
			// lifted only its first instruction). Resetting first makes each decode
			// start from a clean Instruction, exactly like Remill's own TraceLifter
			// uses a fresh Instruction per address. No-op cost for x86.
			scanInst.Reset();

			if (!arch_->DecodeInstruction(scanPC, instrBytes, scanInst, scanContext)) {
				fix024_decodeFailures++;
				// FIX-023: Intercept endbr64/endbr32 — Remill has no semantic for these
				// CET instructions, but they are architectural NOPs. Create a synthetic
				// DecodedInst so the scan continues past them instead of stopping.
				if (scanOffset + 4 <= length) {
					const uint8_t* p = bytes + scanOffset;
					bool isEndbr64 = (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFA);
					bool isEndbr32 = (p[0] == 0xF3 && p[1] == 0x0F && p[2] == 0x1E && p[3] == 0xFB);
					if (isEndbr64 || isEndbr32) {
						DecodedInst di;
						di.pc = scanPC;
						di.size = 4;
						di.inst.category = remill::Instruction::kCategoryNoOp;
						di.inst.bytes = std::string(reinterpret_cast<const char*>(p), 4);
						di.inst.branch_taken_pc = 0;
						di.inst.branch_not_taken_pc = 0;
						decoded.push_back(di);
						scanOffset += 4;
						scanPC += 4;
						continue;
					}
				}
				// FIX-023: Also handle `call __fentry__` (E8 00 00 00 00) — ftrace NOP
				// sled in kernel modules. The displacement is 0 (unresolved relocation),
				// making it a call to PC+5 which is just a fallthrough NOP.
				if (scanOffset + 5 <= length) {
					const uint8_t* p = bytes + scanOffset;
					if (p[0] == 0xE8 && p[1] == 0x00 && p[2] == 0x00 &&
						p[3] == 0x00 && p[4] == 0x00) {
						DecodedInst di;
						di.pc = scanPC;
						di.size = 5;
						di.inst.category = remill::Instruction::kCategoryNoOp;
						di.inst.bytes = std::string(reinterpret_cast<const char*>(p), 5);
						di.inst.branch_taken_pc = 0;
						di.inst.branch_not_taken_pc = 0;
						decoded.push_back(di);
						scanOffset += 5;
						scanPC += 5;
						continue;
					}
				}

				// ═══════════════════════════════════════════════════════════════
				// FIX-024: Desync recovery via XED Instruction Length Decoder
				// ═══════════════════════════════════════════════════════════════
				// Remill's DecodeInstruction only supports instructions with full
				// semantic models. Exotic x86 instructions (AVX-512, APX, MPX,
				// some SSE4/AES/SHA variants) will fail even though they are
				// architecturally valid. Stopping the scan here loses the entire
				// rest of the function — observed on kernel modules where only
				// ~33 of ~500 instructions were lifted before this fix.
				//
				// Instead, use XED-ILD (Intel's official length decoder, already
				// linked via deps/xed/lib/xed-ild.lib) to determine the instruction
				// length, emit a NoOp placeholder of the correct size, and advance
				// exactly one instruction. The undecodable instruction becomes a
				// no-op stub in the lifted IR, but all its neighbors lift normally.
				//
				// For ARM64, instructions are fixed 4 bytes, so we just advance 4.
				// For AMD64/x86, we call XED-ILD.
				//
				// If XED also fails (truly invalid bytes like alignment padding
				// in the middle of code), fall through to the break.
				{
					const uint8_t* p = bytes + scanOffset;
					const size_t remaining = length - scanOffset;
					size_t insnLen = 0;

					// Match archName_ string (set in constructor, e.g. "amd64_avx",
					// "x86", "aarch64"). Avoids dependency on remill::Arch internal
					// enum layout which may change between versions.
					const std::string& an = archName_;
					const bool isAMD64 = (
						an == "amd64" || an == "amd64_avx" || an == "amd64_avx512");
					const bool isX86 = (
						an == "x86" || an == "x86_avx" || an == "x86_avx512");
					const bool isAArch64 = (
						an == "aarch64" || an == "aarch64_little_endian");

					if (isAMD64 || isX86) {
						insnLen = XedInstructionLength(p, remaining, isAMD64);
					} else if (isAArch64) {
						// ARM64 instructions are always 4 bytes, always 4-byte aligned
						if (remaining >= 4 && (scanPC & 0x3) == 0) {
							insnLen = 4;
						}
					}

					if (insnLen > 0 && insnLen <= remaining) {
						DecodedInst di;
						di.pc = scanPC;
						di.size = insnLen;
						di.inst.category = remill::Instruction::kCategoryNoOp;
						di.inst.bytes = std::string(reinterpret_cast<const char*>(p), insnLen);
						di.inst.branch_taken_pc = 0;
						di.inst.branch_not_taken_pc = 0;
						decoded.push_back(di);
						scanOffset += insnLen;
						scanPC += insnLen;
						fix024_xedRecovered++;
						continue;
					}
				}

				// XED/ARM fallback also failed — truly invalid bytes. Stop scan.
				fix024_xedFailed++;
				{
					char bytesHex[64] = {0};
					size_t written = 0;
					for (size_t k = 0; k < 8 && scanOffset + k < length && written < 60; k++) {
						written += snprintf(bytesHex + written, 64 - written, "%02x ",
						                    (unsigned)(uint8_t)bytes[scanOffset + k]);
					}
					llvm::errs() << "[FIX-024] XED recovery FAILED at 0x"
					             << llvm::Twine::utohexstr(scanPC) << " (arch=" << archName_
					             << ", first bytes: " << bytesHex << ")\n";
				}
				break;
			}

			DecodedInst di;
			di.inst = scanInst;
			di.pc = scanPC;
			di.size = scanInst.bytes.size();
			decoded.push_back(di);

			uint64_t nextPC = scanPC + scanInst.bytes.size();
			uint64_t endAddr = address + length;

			// Check if this instruction is a branch or call
			// Remill categorizes instructions — check for jumps
			switch (scanInst.category) {
			case remill::Instruction::kCategoryDirectJump: {
				// FIX-052b: Recover the target from the decoded instruction —
				// `branch_taken_pc` is 0 for `jmp rel` in this Remill build.
				uint64_t jumpTarget = ResolveDirectJumpTargetFromDecode(scanInst);
				if (jumpTarget) {
					// FIX-019: Check if jump target is a kernel return thunk
					// (retpoline: `jmp __x86_return_thunk` replaces `ret` in Spectre-mitigated kernels)
					auto thunkIt = externalSymbols_.find(jumpTarget);
					if (thunkIt != externalSymbols_.end()) {
						const auto& symName = thunkIt->second;
						if (symName == "__x86_return_thunk" ||
							symName.find("__x86_indirect_thunk_") == 0 ||
							symName == "__x86_return_thunk_safe") {
							// Treat as function return — don't add fallthrough as leader
							// The block will get a ret terminator in Phase 4
							break;
						}
					}

					// ─── PE64 mode: out-of-range jmp = tail call ────────
					// MSVC emits tail calls as `jmp other_function`. If the
					// target falls outside our function range, record it as
					// an external call target rather than a BB leader.
					if (options.mode == LiftMode::PE64) {
						bool outOfRange = jumpTarget < address ||
						                  jumpTarget >= endAddr;
						if (outOfRange) {
							result.callTargets.push_back(jumpTarget);
							break;  // Don't add as leader
						}
					}

					// ─── ElfRelocatable mode: out-of-.text jmp = external ─
					// Don't follow branches to addresses outside the provided
					// buffer (they point to other sections or modules).
					if (options.mode == LiftMode::ElfRelocatable) {
						bool outOfRange = jumpTarget < address ||
						                  jumpTarget >= endAddr;
						if (outOfRange) {
							result.callTargets.push_back(jumpTarget);
							break;
						}
					}

					// Normal unconditional jump: target is a leader (only when
					// in-buffer; an out-of-buffer Generic-mode jmp is a tail call
					// and is handled at wire time, not made a leader here).
					if (jumpTarget >= address && jumpTarget < endAddr) {
						leaders.insert(jumpTarget);
					}
				}
				break;
			}

			case remill::Instruction::kCategoryConditionalBranch:
				// Conditional branch: both target and fall-through are leaders
				if (scanInst.branch_taken_pc) {
					leaders.insert(scanInst.branch_taken_pc);
				}
				if (scanInst.branch_not_taken_pc) {
					leaders.insert(scanInst.branch_not_taken_pc);
				} else {
					leaders.insert(nextPC);
				}
				break;

			case remill::Instruction::kCategoryDirectFunctionCall:
			case remill::Instruction::kCategoryIndirectFunctionCall:
				// Function call — fall-through is a leader, record call target
				if (scanOffset + scanInst.bytes.size() < length) {
					leaders.insert(nextPC);
				}
				// Record call targets for boundary metadata
				if (options.splitAtCalls && scanInst.branch_taken_pc) {
					bool isExternal = scanInst.branch_taken_pc < address ||
					                  scanInst.branch_taken_pc >= endAddr;
					if (isExternal) {
						result.callTargets.push_back(scanInst.branch_taken_pc);
					} else {
						// FIX-021: Also record INTERNAL call targets so the TypeScript
						// layer can lift them recursively for multi-function modules.
						result.callTargets.push_back(scanInst.branch_taken_pc);
					}
				}
				break;

			case remill::Instruction::kCategoryFunctionReturn:
			case remill::Instruction::kCategoryIndirectJump:
				// Return or indirect jump — next instruction (if any) is a leader
				if (scanOffset + scanInst.bytes.size() < length) {
					leaders.insert(nextPC);
				}
				break;

			default:
				break;
			}

			scanOffset += scanInst.bytes.size();
			scanPC = nextPC;

			// ─── Boundary detection: stop if limits are exceeded ─────────
			if (decoded.size() >= options.maxInstructions) {
				result.truncated = true;
				result.truncationReason = "max_instructions";
				break;
			}
			if (leaders.size() >= options.maxBasicBlocks) {
				result.truncated = true;
				result.truncationReason = "max_blocks";
				break;
			}
			if (scanOffset >= options.maxBytes) {
				result.truncated = true;
				result.truncationReason = "max_bytes";
				break;
			}
		}

		// Record where to continue if we truncated
		if (result.truncated && !decoded.empty()) {
			auto& lastInst = decoded.back();
			result.nextAddress = lastInst.pc + lastInst.size;
		}

		// FIX-024: Phase 1 summary — silent safety net.
		// Only log when XED recovery was actually needed (exotic ISA encountered).
		// Counters are always incremented so we can diagnose future binaries that
		// activate the path. For normal x86_64 / AArch64 code this never fires.
		if (fix024_decodeFailures > 0 || fix024_xedRecovered > 0 || fix024_xedFailed > 0) {
			llvm::errs() << "[FIX-024] Phase 1 @0x"
			             << llvm::Twine::utohexstr(address)
			             << ": decoded=" << decoded.size()
			             << " leaders=" << leaders.size()
			             << " scanned=" << scanOffset << "/" << length << " bytes"
			             << " decodeFailures=" << fix024_decodeFailures
			             << " xedRecovered=" << fix024_xedRecovered
			             << " xedFailed=" << fix024_xedFailed
			             << " truncated=" << (result.truncated ? result.truncationReason : "no")
			             << "\n";
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 1.5: Inject additional BB leaders from external analysis
	// ═══════════════════════════════════════════════════════════════════════
	// TypeScript can extract leaders from jump table targets (.rodata),
	// PE .pdata exception directory, or ELF symtab function addresses.
	// Insert them into the leaders set before Phase 2 creates basic blocks.
	if (!options.additionalLeaders.empty()) {
		uint64_t endAddr = address + length;
		for (uint64_t extraLeader : options.additionalLeaders) {
			// Only accept leaders that fall within the decoded range
			if (extraLeader >= address && extraLeader < endAddr) {
				leaders.insert(extraLeader);
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 2: Create LLVM basic blocks for each leader
	// ═══════════════════════════════════════════════════════════════════════

	auto func = arch_->DeclareLiftedFunction(
		"lifted_" + std::to_string(address), liftModule.get());
	arch_->InitializeEmptyLiftedFunction(func);

	// Map: leader address → BasicBlock
	std::map<uint64_t, llvm::BasicBlock*> bbMap;

	// The entry block is always the first leader
	bbMap[address] = &func->getEntryBlock();

	// Create additional blocks for other leaders
	for (uint64_t leaderAddr : leaders) {
		if (leaderAddr == address) continue;  // Already have the entry block

		// Only create blocks for leaders that are within our function range
		uint64_t endAddr = address + length;
		if (leaderAddr >= address && leaderAddr < endAddr) {
			auto* bb = llvm::BasicBlock::Create(
				liftModule->getContext(),
				"bb_" + std::to_string(leaderAddr),
				func);
			bbMap[leaderAddr] = bb;
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 3: Lift instructions into their respective basic blocks
	// ═══════════════════════════════════════════════════════════════════════

	size_t totalOffset = 0;

	// Map from CALLI CallInst* → concrete call target, populated during Phase 3
	// for every direct function call Remill decodes with a known branch_taken_pc.
	std::map<llvm::CallInst*, uint64_t> calliTargets;

	// FIX-052: Direct-jump targets that are inside the lift buffer but were not
	// pre-registered as leaders in Phase 1 (e.g. the linear scan was truncated
	// before reaching them, or they landed mid-instruction relative to the
	// linear sweep). We must NOT classify these as tail calls / drop them: the
	// jump is INTRA-function, so the edge has to be preserved. We collect them
	// here and the Phase 3.4 / post-gap rewire connect the br once the target
	// block exists.
	//
	// FIX-052b review fix: the in-function window is the ACTUAL decoded extent,
	// not the raw buffer length. `length` can span past the executable region
	// into RO data (Phase 1 stops at maxBytes / desync); using the raw length
	// would mark an unscanned tail as "in-buffer". Clamp to maxBytes.
	uint64_t bufEndAddr = address + std::min<size_t>(length, options.maxBytes);
	std::set<uint64_t> pendingJumpTargets;

	// FIX-052b: jump PC → recovered direct-jump target (decode-time or post-lift
	// JMPI immediate). Lets the Phase 3.4 rewire connect edges without re-deriving
	// the target, since `branch_taken_pc` is 0 for `jmp rel` in this build.
	std::map<uint64_t, uint64_t> directJumpTargets;

	for (size_t i = 0; i < decoded.size(); i++) {
		auto& di = decoded[i];

		// Find the block this instruction belongs to
		llvm::BasicBlock* currentBlock = nullptr;
		if (bbMap.count(di.pc)) {
			currentBlock = bbMap[di.pc];
		} else {
			// Find the block whose leader is the highest address <= di.pc
			auto it = bbMap.upper_bound(di.pc);
			if (it != bbMap.begin()) {
				--it;
				currentBlock = it->second;
			} else {
				currentBlock = &func->getEntryBlock();
			}
		}

		// FIX-023: Skip synthetic NOPs (endbr64, call __fentry__) — they have
		// no Remill semantic and LiftIntoBlock would fail on them. They were
		// already added to `decoded` as kCategoryNoOp in Phase 1.
		if (di.inst.category == remill::Instruction::kCategoryNoOp &&
			di.size >= 4 && di.size <= 5) {
			const uint8_t firstByte = static_cast<uint8_t>(di.inst.bytes[0]);
			if (firstByte == 0xF3 || firstByte == 0xE8) {
				// Synthetic NOP — skip lifting, just count the bytes
				totalOffset += di.size;
				continue;
			}
		}

		// FIX-052b: If this instruction's owning block ALREADY has a terminator,
		// the instruction is dead space after an in-block branch — typically a
		// mid-instruction jump target, where a `jmp` inside this leader-range
		// already closed the block, and the bytes here overlap the previous
		// instruction. Lifting it would append a body AFTER the terminator,
		// producing a MALFORMED double-terminator block (caught by the LLVM
		// verifier / can crash later passes on adversarial/obfuscated input).
		// Skip it: its real, instruction-aligned copy lives in its own leader
		// block (created from the recovered jump target). Just advance the byte
		// counter so boundary accounting stays correct.
		if (currentBlock->getTerminator()) {
			totalOffset += di.size;
			continue;
		}

		// Lift the instruction into its block
		auto status = instLifter->LiftIntoBlock(di.inst, currentBlock, false);
		if (status != remill::kLiftedInstruction) {
			if (totalOffset == 0) {
				result.error = "Failed to lift instruction at 0x" +
					std::to_string(di.pc);
				return result;
			}
			break;
		}

		totalOffset += di.size;

		// ─── Record direct call targets ─────────────────────────────────
		// For direct function calls, Remill's decoder sets branch_taken_pc
		// to the concrete call target.  Scan the block backwards to find
		// the CALLI instruction just emitted and store the target address.
		if (di.inst.branch_taken_pc &&
			di.inst.category == remill::Instruction::kCategoryDirectFunctionCall) {
			for (auto it = currentBlock->rbegin(); it != currentBlock->rend(); ++it) {
				if (auto* CI = llvm::dyn_cast<llvm::CallInst>(&*it)) {
					auto* calledFn = CI->getCalledFunction();
					if (calledFn && calledFn->getName().contains("CALLI")) {
						calliTargets[CI] = di.inst.branch_taken_pc;
						break;
					}
				}
			}
		}

		// ─── Wire control flow ──────────────────────────────────────────
		// After lifting a branch instruction, add LLVM terminators to connect
		// the blocks.  Remill emits __remill_jump() calls but does NOT create
		// LLVM br instructions — we must do that ourselves.

		uint64_t nextPC = di.pc + di.size;

		switch (di.inst.category) {
		case remill::Instruction::kCategoryDirectJump: {
			// FIX-052b: Recover the target. `branch_taken_pc` is 0 for `jmp rel`
			// in this Remill build; fall back to decode-time flow/operands, then
			// to the i64 immediate of the JMPI helper we just lifted.
			uint64_t jumpTarget = ResolveDirectJumpTargetFromDecode(di.inst);
			if (!jumpTarget) {
				jumpTarget = ReadJmpiTargetFromBlock(currentBlock);
			}
			if (jumpTarget) {
				directJumpTargets[di.pc] = jumpTarget;
			}

			// FIX-019: If jump target is a return thunk, emit ret instead of br
			if (jumpTarget) {
				auto thunkIt = externalSymbols_.find(jumpTarget);
				if (thunkIt != externalSymbols_.end()) {
					const auto& symName = thunkIt->second;
					if (symName == "__x86_return_thunk" ||
						symName.find("__x86_indirect_thunk_") == 0 ||
						symName == "__x86_return_thunk_safe") {
						// Return thunk — emit ret, not br
						llvm::IRBuilder<> builder(currentBlock);
						builder.CreateRet(func->getArg(2));
						break;
					}
				}
			}

			// Normal unconditional jump: br label %target_bb
			if (jumpTarget && bbMap.count(jumpTarget)) {
				if (!currentBlock->getTerminator()) {
					llvm::IRBuilder<> builder(currentBlock);
					builder.CreateBr(bbMap[jumpTarget]);
				}
			} else if (jumpTarget &&
			           jumpTarget >= address &&
			           jumpTarget < bufEndAddr) {
				// FIX-052: In-buffer jump target with no block YET. This is an
				// intra-function jump (very common after callfuscation
				// deflattening, where the whole body is a chain of unconditional
				// jmps). It must NOT be treated as a tail call / dropped. Record
				// it so Phase 3.4 / the post-gap-scan rewire connect the `br` once
				// the target block exists (it normally does, since Phase 1 lists
				// every in-buffer direct-jump target as a leader; this guards the
				// rare out-of-order / gap-materialized case). currentBlock is left
				// open here on purpose.
				pendingJumpTargets.insert(jumpTarget);
			}
			// else: out-of-buffer target = tail call; leave the block open so
			// Phase 4 finalizes it as `ret` (FIX-052b beacon caveat in Phase 4).
			break;
		}

		case remill::Instruction::kCategoryConditionalBranch: {
			// Conditional branch: Remill's helper receives BRANCH_TAKEN and
			// NEXT_PC out-params.  Use those values first instead of guessing
			// from the last ICmp.  Falling back to ConstantTrue corrupts CFG.
			if (di.inst.branch_taken_pc && bbMap.count(di.inst.branch_taken_pc)) {
				uint64_t fallthroughPC = di.inst.branch_not_taken_pc ? 
					di.inst.branch_not_taken_pc : nextPC;

				llvm::BasicBlock* trueBB = bbMap[di.inst.branch_taken_pc];
				llvm::BasicBlock* falseBB = bbMap.count(fallthroughPC) ?
					bbMap[fallthroughPC] : nullptr;

				if (trueBB && falseBB) {
					llvm::IRBuilder<> builder(currentBlock);

					llvm::Value* cond = nullptr;

					// Preferred: BRANCH_TAKEN written by Remill jump helper.
					if (auto* branchTakenAlloca = FindNamedAlloca(func, "BRANCH_TAKEN")) {
						auto* branchTakenTy = branchTakenAlloca->getAllocatedType();
						auto* rawBranchTaken = builder.CreateLoad(
							branchTakenTy, branchTakenAlloca, "branch_taken");

						if (branchTakenTy->isIntegerTy(1)) {
							cond = rawBranchTaken;
						} else if (branchTakenTy->isIntegerTy()) {
							cond = builder.CreateICmpNE(
								rawBranchTaken,
								llvm::ConstantInt::get(branchTakenTy, 0),
								"branch_taken.bool");
						}
					}

					// Secondary fallback: compare NEXT_PC against the taken target.
					if (!cond) {
						if (auto* nextPcAlloca = FindNamedAlloca(func, "NEXT_PC")) {
							auto* nextPcTy = nextPcAlloca->getAllocatedType();
							auto* loadedNextPc = builder.CreateLoad(nextPcTy, nextPcAlloca, "next_pc");
							if (nextPcTy->isIntegerTy(64)) {
								cond = builder.CreateICmpEQ(
									loadedNextPc,
									llvm::ConstantInt::get(nextPcTy, di.inst.branch_taken_pc),
									"next_pc_is_taken");
							}
						}
					}

					// Legacy fallback: look for the last ICmp in this block.
					if (!cond) {
						for (auto it = currentBlock->rbegin(); it != currentBlock->rend(); ++it) {
							if (auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&*it)) {
								cond = icmp;
								break;
							}
						}
					}

					if (!cond) {
						// Last-resort fallback keeps the old behavior, but should now
						// be hit far less often. Prefer conservative false over hardwired
						// "always take" to reduce CFG distortion when analysis fails.
						cond = llvm::ConstantInt::getFalse(liftModule->getContext());
					}

					builder.CreateCondBr(cond, trueBB, falseBB);
				}
			}
			break;
		}

		case remill::Instruction::kCategoryFunctionReturn: {
			// Return: ret ptr %memory
			llvm::IRBuilder<> builder(currentBlock);
			builder.CreateRet(func->getArg(2));
			break;
		}

		case remill::Instruction::kCategoryNormal:
		case remill::Instruction::kCategoryNoOp:
		// ═══════════════════════════════════════════════════════════════
		// FIX-025: Fall-through after CALL to next BB (return point).
		// ═══════════════════════════════════════════════════════════════
		// A direct/indirect CALL is lifted by Remill as if the call returns
		// normally — execution flows through to the next PC. When the next
		// instruction begins a new basic block (marked as a leader, e.g. by
		// pathfinder because a branch target lands there), we MUST wire a
		// fall-through br so LLVM sees that BB as reachable.
		//
		// Without this, Phase 4's "add ret to orphan BBs" fallback forces a
		// ret at the end of the caller's block, severing its link to the
		// return-point BB. LLVM DCE then removes the return-point BB and
		// everything only reachable through it — on kbase_jit_allocate this
		// collapsed 134 BBs down to ~7 and lost 95% of the function body.
		//
		// AsyncHyperCall (e.g. syscall) also returns and falls through.
		case remill::Instruction::kCategoryDirectFunctionCall:
		case remill::Instruction::kCategoryIndirectFunctionCall:
		case remill::Instruction::kCategoryAsyncHyperCall:
		case remill::Instruction::kCategoryConditionalAsyncHyperCall: {
			// If the NEXT instruction starts a new block, add a fallthrough
			// branch to connect them.
			if (i + 1 < decoded.size() && bbMap.count(nextPC)) {
				// Only add branch if this block doesn't already have a terminator
				if (!currentBlock->getTerminator()) {
					llvm::IRBuilder<> builder(currentBlock);
					builder.CreateBr(bbMap[nextPC]);
				}
			}
			break;
		}

		default:
			break;
		}
	}

	result.bytesConsumed = totalOffset;

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 3.4: Re-wire in-buffer direct jumps whose edge was dropped
	// ═══════════════════════════════════════════════════════════════════════
	// FIX-052: A deflattened callfuscation body is one long chain of
	// unconditional `jmp`s. If a direct jump's in-buffer target acquired its
	// block only AFTER Phase 3 lifted the jump (e.g. the target block is
	// materialized by the Phase 3.5 gap scan below, or two leaders were
	// discovered out of linear order), the `br` edge would never be emitted and
	// Phase 4 would slap a bogus `ret` on the source block — collapsing the
	// function toward its entry (the `sub_40b663(); return;` symptom).
	//
	// This pass does NOT create or re-lift any blocks (that would double-emit
	// instructions, since Phase 3 already lifted every decoded instruction into
	// its owning block). It only connects the edge: for each decoded direct jump
	// whose target now has a block and whose SOURCE block is still open, emit the
	// missing `br`. The source block is the one whose leader is the greatest
	// leader <= jump PC — the same ownership lookup Phase 3 uses. We run this
	// before AND after the gap scan so freshly gap-created targets are wired too.
	auto rewireDroppedJumpEdges = [&]() {
		for (size_t i = 0; i < decoded.size(); i++) {
			auto& di = decoded[i];
			if (di.inst.category != remill::Instruction::kCategoryDirectJump)
				continue;
			// FIX-052b: use the recovered target (branch_taken_pc is 0 here).
			auto tgtIt = directJumpTargets.find(di.pc);
			uint64_t jt = (tgtIt != directJumpTargets.end()) ? tgtIt->second : 0;
			if (!jt || jt < address || jt >= bufEndAddr) continue;  // not in-buffer
			if (!bbMap.count(jt)) continue;                          // no target block

			llvm::BasicBlock* src = nullptr;
			auto it = bbMap.upper_bound(di.pc);
			if (it != bbMap.begin()) { --it; src = it->second; }
			if (!src || src->getTerminator()) continue;              // already wired

			llvm::IRBuilder<> builder(src);
			builder.CreateBr(bbMap[jt]);
		}
	};
	if (!pendingJumpTargets.empty()) {
		rewireDroppedJumpEdges();
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 3.5: Gap scan — discover unreached decoded instructions
	// ═══════════════════════════════════════════════════════════════════════
	// After Phase 3, some decoded instructions may not belong to any basic
	// block (their PC doesn't fall in any [leader, next_leader) range).
	// Instructions after kCategoryIndirectJump or kCategoryFunctionReturn
	// that weren't reached are potential new leaders — especially switch
	// case fallthrough or code after conditional return patterns.
	//
	// We re-lift discovered gaps into new basic blocks to recover more code.
	{
		// Collect all PCs that are leaders (have basic blocks)
		std::set<uint64_t> coveredLeaders;
		for (auto& [addr, bb] : bbMap) {
			coveredLeaders.insert(addr);
		}

		std::vector<uint64_t> gapLeaders;
		for (size_t i = 0; i < decoded.size(); i++) {
			uint64_t pc = decoded[i].pc;

			// Check if this instruction falls within an existing BB range
			auto it = coveredLeaders.upper_bound(pc);
			if (it != coveredLeaders.begin()) {
				--it;
				// pc >= *it means it's in the range [*it, next_leader)
				// This instruction is covered by an existing block
				continue;
			}

			// This instruction is NOT covered by any block. Check if the
			// previous instruction was an indirect jump or return — if so,
			// this is likely a new block (switch case target, code after
			// conditional return, etc.)
			if (i > 0) {
				auto prevCat = decoded[i - 1].inst.category;
				if (prevCat == remill::Instruction::kCategoryIndirectJump ||
				    prevCat == remill::Instruction::kCategoryFunctionReturn ||
				    prevCat == remill::Instruction::kCategoryDirectJump) {
					gapLeaders.push_back(pc);
				}
			}
		}

		// Create new basic blocks for gap leaders and re-lift
		if (!gapLeaders.empty()) {
			uint64_t endAddr = address + length;
			for (uint64_t gapAddr : gapLeaders) {
				if (gapAddr >= address && gapAddr < endAddr && !bbMap.count(gapAddr)) {
					auto* bb = llvm::BasicBlock::Create(
						liftModule->getContext(),
						"bb_gap_" + std::to_string(gapAddr),
						func);
					bbMap[gapAddr] = bb;
					leaders.insert(gapAddr);

					// Lift instructions in this gap block
					for (size_t i = 0; i < decoded.size(); i++) {
						if (decoded[i].pc < gapAddr) continue;

						// Stop if we've reached another existing leader
						auto nextLeaderIt = leaders.upper_bound(gapAddr);
						if (nextLeaderIt != leaders.end() && decoded[i].pc >= *nextLeaderIt) {
							break;
						}

						auto& di = decoded[i];
						// Skip synthetic NOPs (endbr64 / __fentry__)
						if (di.inst.category == remill::Instruction::kCategoryNoOp &&
							di.size >= 4 && di.size <= 5) {
							const uint8_t firstByte = static_cast<uint8_t>(di.inst.bytes[0]);
							if (firstByte == 0xF3 || firstByte == 0xE8) continue;
						}

						auto status = instLifter->LiftIntoBlock(di.inst, bb, false);
						if (status != remill::kLiftedInstruction) break;

						// Wire fallthrough to next block if needed.
						// FIX-025: CALL categories also fall-through to return point.
						uint64_t nextPC = di.pc + di.size;
						if (di.inst.category == remill::Instruction::kCategoryNormal ||
						    di.inst.category == remill::Instruction::kCategoryNoOp ||
						    di.inst.category == remill::Instruction::kCategoryDirectFunctionCall ||
						    di.inst.category == remill::Instruction::kCategoryIndirectFunctionCall ||
						    di.inst.category == remill::Instruction::kCategoryAsyncHyperCall ||
						    di.inst.category == remill::Instruction::kCategoryConditionalAsyncHyperCall) {
							if (bbMap.count(nextPC) && !bb->getTerminator()) {
								llvm::IRBuilder<> builder(bb);
								builder.CreateBr(bbMap[nextPC]);
							}
						} else if (di.inst.category == remill::Instruction::kCategoryDirectJump) {
							// FIX-052b: recover the target (branch_taken_pc is 0 for jmp rel).
							uint64_t gj = ResolveDirectJumpTargetFromDecode(di.inst);
							if (!gj) gj = ReadJmpiTargetFromBlock(bb);
							if (gj) directJumpTargets[di.pc] = gj;
							if (gj && bbMap.count(gj)) {
								if (!bb->getTerminator()) {
									llvm::IRBuilder<> builder(bb);
									builder.CreateBr(bbMap[gj]);
								}
							}
							break;
						} else if (di.inst.category == remill::Instruction::kCategoryFunctionReturn) {
							llvm::IRBuilder<> builder(bb);
							builder.CreateRet(func->getArg(2));
							break;
						} else if (di.inst.category == remill::Instruction::kCategoryConditionalBranch ||
						           di.inst.category == remill::Instruction::kCategoryIndirectJump) {
							break;  // Already wired or can't resolve
						}
					}
				}
			}
		}
	}

	// FIX-052: Re-run the dropped-edge rewire AFTER the gap scan. The gap scan
	// can materialize a direct jump's target block; connect any source block
	// whose `br` was deferred because the target didn't exist during Phase 3.
	rewireDroppedJumpEdges();

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 4: Ensure every basic block has a terminator
	// ═══════════════════════════════════════════════════════════════════════
	// Remill's LiftIntoBlock leaves blocks "open" (no ret/br).
	// Add terminators to any blocks that still lack them.
	//
	// FIX-052b (review): for a block whose final decoded instruction is an
	// in-buffer direct jump we could NOT resolve to a block, emit `unreachable`
	// — a visible "lost edge" beacon — instead of a semantically-wrong `ret`.
	// A `ret` where the binary has a `jmp` is a hard CFG miscompile that DCE then
	// uses to silently drop everything downstream. `unreachable` makes the loss
	// explicit to the decompiler / reviewer and keeps the verifier happy.
	//
	// Collect the set of PCs that begin a block, and the source block of every
	// unresolved in-buffer direct jump.
	std::set<llvm::BasicBlock*> lostEdgeBlocks;
	for (const auto& [jumpPC, tgt] : directJumpTargets) {
		if (tgt < address || tgt >= bufEndAddr) continue;  // tail call -> ret is fine
		if (bbMap.count(tgt)) continue;                    // resolved -> already br'd
		// Unresolved in-buffer target: find the source block (greatest leader <= jumpPC).
		auto it = bbMap.upper_bound(jumpPC);
		if (it != bbMap.begin()) {
			--it;
			lostEdgeBlocks.insert(it->second);
		}
	}

	for (auto &BB : *func) {
		if (!BB.getTerminator()) {
			llvm::IRBuilder<> builder(&BB);
			if (lostEdgeBlocks.count(&BB)) {
				// Lost in-buffer jump edge — beacon, do not fake a return.
				builder.CreateUnreachable();
			} else {
				// Return the memory pointer (3rd argument) to match Remill convention.
				builder.CreateRet(func->getArg(2));
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 4.2: Entry-block split for back-edges to the function entry
	// ═══════════════════════════════════════════════════════════════════════
	// FIX-052b: A back-edge that targets the entry address (e.g. `jmp` back to
	// the function start — common in deflattened VM dispatch loops) makes the
	// LLVM function ENTRY block a branch target. The entry block holds the
	// `alloca`s (NEXT_PC, BRANCH_TAKEN); SROA/mem2reg ASSERT/segfault when the
	// alloca-bearing entry block has a predecessor (the entry block is required
	// to have no predecessors for promotion). Micro-test proof: a back-edge to a
	// NON-entry block lifts fine (br=2), but `jmp` to the entry block segfaults.
	//
	// Fix (standard LLVM idiom): insert a fresh entry block `E0` BEFORE the old
	// entry, move the `alloca`s into `E0`, and have `E0` unconditionally branch
	// to the old entry. `E0` (now the entry) has no predecessors and owns the
	// allocas, satisfying mem2reg; the old entry becomes an ordinary block that
	// any back-edge may target. Only done when the entry actually has a
	// predecessor, so normal functions are untouched.
	{
		llvm::BasicBlock* oldEntry = &func->getEntryBlock();
		if (oldEntry->hasNPredecessorsOrMore(1)) {
			auto& ctx = liftModule->getContext();
			auto* newEntry = llvm::BasicBlock::Create(ctx, "entry_preheader", func, oldEntry);

			// Move all alloca instructions from the old entry into the new entry.
			std::vector<llvm::AllocaInst*> allocas;
			for (auto& I : *oldEntry) {
				if (auto* AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
					allocas.push_back(AI);
				}
			}
			for (auto* AI : allocas) {
				AI->removeFromParent();
				AI->insertInto(newEntry, newEntry->end());
			}

			// New entry falls through to the old entry block.
			llvm::IRBuilder<> builder(newEntry);
			builder.CreateBr(oldEntry);
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 4.5: Resolve NEXT_PC constant propagation for call targets
	// ═══════════════════════════════════════════════════════════════════════
	// Remill emits each direct call target as:
	//   store i64 %program_counter, ptr %NEXT_PC     ; initial (runtime arg)
	//   ...
	//   %a = add i64 %prev_next_pc, instr_size
	//   store i64 %a, ptr %NEXT_PC
	//   %b = load i64, ptr %NEXT_PC                  ; always right after store
	//   %target = sub i64 %b, rel32_displacement
	//   call @CALLI(..., i64 %target, ...)
	//
	// Since %program_counter is a known constant (= address passed to DoLift),
	// substituting it + forwarding NEXT_PC stores makes all direct call targets
	// resolve to concrete i64 constants, eliminating "sub_(vN ± offset)" noise
	// in the Helix decompiler output.
	{
		// Step 1: Replace %program_counter argument with the concrete address.
		// It is the sole i64 argument at index 1 (State* is 0, Memory* is 2).
		llvm::Value* pcArg = nullptr;
		{
			unsigned idx = 0;
			for (auto& arg : func->args()) {
				if (idx == 1 && arg.getType()->isIntegerTy(64)) {
					pcArg = &arg;
					break;
				}
				++idx;
			}
		}
		if (pcArg) {
			auto* concretePC = llvm::ConstantInt::get(
				llvm::Type::getInt64Ty(liftModule->getContext()), address);
			pcArg->replaceAllUsesWith(concretePC);
		}

		// Step 1.5: Inject concrete call targets recorded during Phase 3.
		// Directly replaces CALLI target arguments (arg index 2) with the
		// concrete address decoded by Remill — no NEXT_PC propagation needed.
		// This fixes all direct call targets regardless of CFG topology.
		for (auto& [CI, target] : calliTargets) {
			auto* targetConst = llvm::ConstantInt::get(
				llvm::Type::getInt64Ty(liftModule->getContext()), target);
			if (CI->arg_size() > 2)
				CI->setArgOperand(2, targetConst);
		}

		// Step 2: Find the %NEXT_PC alloca in the entry block, then build
		// sets of its load/store users directly from the USE-DEF chain.
		// Using users() avoids fragile getPointerOperand() pointer comparison.
		llvm::AllocaInst* nextPCAlloca = nullptr;
		for (auto& I : func->getEntryBlock()) {
			if (auto* AI = llvm::dyn_cast<llvm::AllocaInst>(&I)) {
				if (AI->hasName() && AI->getName() == "NEXT_PC") {
					nextPCAlloca = AI;
					break;
				}
			}
		}

		// Step 3: Multi-pass inter-block + intra-block store-to-load forwarding.
		// For single-predecessor blocks, inherit the predecessor's outgoing value.
		// Repeat until no more loads can be forwarded.
		if (nextPCAlloca) {
			// Collect load/store users via USE-DEF chain (not pointer comparison).
			std::set<llvm::Instruction*> nextPCLoadSet;
			std::set<llvm::Instruction*> nextPCStoreSet;
			for (auto* U : nextPCAlloca->users()) {
				if (llvm::isa<llvm::LoadInst>(U))
					nextPCLoadSet.insert(llvm::cast<llvm::Instruction>(U));
				else if (llvm::isa<llvm::StoreInst>(U))
					nextPCStoreSet.insert(llvm::cast<llvm::Instruction>(U));
			}

			// Propagate: repeat until stable (handles single-predecessor chains).
			std::map<llvm::BasicBlock*, llvm::Value*> blockOutgoing;
			bool fwdChanged = true;
			while (fwdChanged) {
				fwdChanged = false;
				for (auto& BB : *func) {
					// Inherit incoming value from single predecessor if known.
					llvm::Value* lastStored = nullptr;
					if (auto* pred = BB.getSinglePredecessor()) {
						// Only inherit NEXT_PC across an edge when the predecessor
						// has a single successor. For conditional branches, the outgoing
						// NEXT_PC is path-dependent; blindly forwarding it corrupts the
						// target block's synthetic PC/NEXT_PC stamp.
						auto* predTerm = pred->getTerminator();
						const bool safeSingleSuccessor =
							predTerm && predTerm->getNumSuccessors() == 1;
						if (safeSingleSuccessor) {
							auto it = blockOutgoing.find(pred);
							if (it != blockOutgoing.end())
								lastStored = it->second;
						}
					}

					std::vector<std::pair<llvm::LoadInst*, llvm::Value*>> toReplace;
					for (auto& I : BB) {
						if (auto* SI = llvm::dyn_cast<llvm::StoreInst>(&I)) {
							if (nextPCStoreSet.count(SI))
								lastStored = SI->getValueOperand();
						} else if (auto* LI = llvm::dyn_cast<llvm::LoadInst>(&I)) {
							if (nextPCLoadSet.count(LI) && lastStored)
								toReplace.push_back({LI, lastStored});
						}
					}

					for (auto& [LI, val] : toReplace) {
						LI->replaceAllUsesWith(val);
						LI->eraseFromParent();
						nextPCLoadSet.erase(LI);
						fwdChanged = true;
					}

					if (lastStored)
						blockOutgoing[&BB] = lastStored;
				}
			}
		}

		// Step 4: Fold constant binary operations (add/sub/mul/and/or/xor) that
		// now have two ConstantInt operands as a result of the substitutions above.
		bool changed = true;
		while (changed) {
			changed = false;
			for (auto& BB : *func) {
				for (auto it = BB.begin(); it != BB.end(); ) {
					auto& I = *it++;
					auto* BO = llvm::dyn_cast<llvm::BinaryOperator>(&I);
					if (!BO) continue;

					auto* C0 = llvm::dyn_cast<llvm::ConstantInt>(BO->getOperand(0));
					auto* C1 = llvm::dyn_cast<llvm::ConstantInt>(BO->getOperand(1));
					if (!C0 || !C1) continue;

					uint64_t v0 = C0->getZExtValue();
					uint64_t v1 = C1->getZExtValue();
					uint64_t result = 0;
					bool foldable = true;

					switch (BO->getOpcode()) {
						case llvm::Instruction::Add: result = v0 + v1; break;
						case llvm::Instruction::Sub: result = v0 - v1; break;
						case llvm::Instruction::Mul: result = v0 * v1; break;
						case llvm::Instruction::And: result = v0 & v1; break;
						case llvm::Instruction::Or:  result = v0 | v1; break;
						case llvm::Instruction::Xor: result = v0 ^ v1; break;
						default: foldable = false; break;
					}

					if (!foldable) continue;

					auto* folded = llvm::ConstantInt::get(BO->getType(), result);
					BO->replaceAllUsesWith(folded);
					BO->eraseFromParent();
					changed = true;
				}
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 5: Strip module (same as before)
	// ═══════════════════════════════════════════════════════════════════════

	{
		// 1. Collect all Values reachable from the lifted function
		std::set<llvm::Function*> reachableFunctions;
		std::set<llvm::GlobalVariable*> reachableGlobals;
		std::vector<llvm::Function*> worklist;

		reachableFunctions.insert(func);
		worklist.push_back(func);

		while (!worklist.empty()) {
			llvm::Function* current = worklist.back();
			worklist.pop_back();

			for (auto &BB : *current) {
				for (auto &I : BB) {
					// Track called functions
					if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
						if (auto *CalledF = CI->getCalledFunction()) {
							if (reachableFunctions.insert(CalledF).second) {
								worklist.push_back(CalledF);
							}
						}
					}
					// Track referenced globals from all operands
					for (unsigned op = 0; op < I.getNumOperands(); ++op) {
						if (auto *GV = llvm::dyn_cast<llvm::GlobalVariable>(I.getOperand(op))) {
							reachableGlobals.insert(GV);
						}
					}
				}
			}
		}

		// 2. Remove all aliases
		std::vector<llvm::GlobalAlias*> aliasesToRemove;
		for (auto &A : liftModule->aliases()) {
			aliasesToRemove.push_back(&A);
		}
		for (auto *A : aliasesToRemove) {
			A->replaceAllUsesWith(llvm::UndefValue::get(A->getType()));
			A->eraseFromParent();
		}

		// 3. Remove all IFuncs
		std::vector<llvm::GlobalIFunc*> ifuncsToRemove;
		for (auto &IF : liftModule->ifuncs()) {
			ifuncsToRemove.push_back(&IF);
		}
		for (auto *IF : ifuncsToRemove) {
			IF->replaceAllUsesWith(llvm::UndefValue::get(IF->getType()));
			IF->eraseFromParent();
		}

		// 4. Remove unreachable globals
		std::vector<llvm::GlobalVariable*> gvToRemove;
		for (auto &GV : liftModule->globals()) {
			if (reachableGlobals.count(&GV) == 0) {
				gvToRemove.push_back(&GV);
			}
		}
		for (auto *GV : gvToRemove) {
			GV->replaceAllUsesWith(llvm::UndefValue::get(GV->getType()));
			GV->eraseFromParent();
		}

		// 5. Remove unreachable functions
		std::vector<llvm::Function*> fnToRemove;
		for (auto &F : *liftModule) {
			if (reachableFunctions.count(&F) == 0) {
				fnToRemove.push_back(&F);
			}
		}
		for (auto *F : fnToRemove) {
			F->replaceAllUsesWith(llvm::UndefValue::get(F->getType()));
			F->eraseFromParent();
		}

		// 6. Semantic inlining (selective + optional full).
		//
		// SSE/FP semantics are ALWAYS inlined so that downstream decompilers
		// see native LLVM ops (fmul, fadd, fcmp+select) instead of opaque
		// calls like MINSS(), MULSS().  Helix v0.8.0 recognizes fcmp+select
		// patterns and emits correct if-structure — operand resolution is
		// a Helix-side fix (State GEP → XMM float value tracking).
		// Non-SSE semantics stay as named calls (Helix pattern-matches them).
		{
			auto isSseSemantic = [](llvm::Function* F) -> bool {
				if (!F) return false;
				llvm::StringRef name = F->getName();
				if (!name.contains("_GLOBAL__N_1")) return false;
				// Scalar single/double
				if (name.contains("ADDSS") || name.contains("SUBSS") ||
				    name.contains("MULSS") || name.contains("DIVSS") ||
				    name.contains("MINSS") || name.contains("MAXSS") ||
				    name.contains("SQRTSS")) return true;
				if (name.contains("ADDSD") || name.contains("SUBSD") ||
				    name.contains("MULSD") || name.contains("DIVSD") ||
				    name.contains("MINSD") || name.contains("MAXSD") ||
				    name.contains("SQRTSD")) return true;
				// Packed
				if (name.contains("ADDPS") || name.contains("SUBPS") ||
				    name.contains("MULPS") || name.contains("DIVPS")) return true;
				if (name.contains("ADDPD") || name.contains("SUBPD") ||
				    name.contains("MULPD") || name.contains("DIVPD")) return true;
				// Comparisons
				if (name.contains("COMISS") || name.contains("UCOMISS") ||
				    name.contains("COMISD") || name.contains("UCOMISD")) return true;
				// Conversions
				if (name.contains("CVTSS") || name.contains("CVTSD") ||
				    name.contains("CVTPS") || name.contains("CVTPD") ||
				    name.contains("CVTSI") || name.contains("CVTTSS") ||
				    name.contains("CVTTSD")) return true;
				// Bitwise (XOR for negation/zeroing)
				if (name.contains("XORPS") || name.contains("XORPD") ||
				    name.contains("ANDPS") || name.contains("ANDPD") ||
				    name.contains("ORPS")  || name.contains("ORPD") ||
				    name.contains("ANDNPS")|| name.contains("ANDNPD")) return true;
				return false;
			};

			bool inlined = true;
			unsigned rounds = 0;
			while (inlined && rounds++ < 8) {
				inlined = false;
				llvm::SmallVector<llvm::CallInst*, 32> callsToInline;

				for (auto &BB : *func) {
					for (auto &I : BB) {
						if (auto *CI = llvm::dyn_cast<llvm::CallInst>(&I)) {
							auto *callee = CI->getCalledFunction();
							if (callee && !callee->isDeclaration() &&
							    !callee->isIntrinsic() && callee != func) {
								if (options.inlineSemantics || isSseSemantic(callee)) {
									callsToInline.push_back(CI);
								}
							}
						}
					}
				}

				for (auto *CI : callsToInline) {
					llvm::InlineFunctionInfo IFI;
					auto result = llvm::InlineFunction(*CI, IFI);
					if (result.isSuccess()) {
						inlined = true;
					}
				}
			}
		}

		// 7. Strip bodies from helper functions but keep their declarations.
		// This preserves readable named semantic callsites in compatibility mode
		// while still keeping the final module compact.
		for (auto &F : *liftModule) {
			if (&F != func && !F.isDeclaration()) {
				F.deleteBody();
			}
		}

		// 7. Remove named metadata that may reference deleted values
		std::vector<llvm::NamedMDNode*> namedMDToRemove;
		for (auto &NMD : liftModule->named_metadata()) {
			llvm::StringRef name = NMD.getName();
			if (name != "llvm.module.flags" && name != "llvm.ident" &&
				!name.starts_with("remill")) {
				namedMDToRemove.push_back(&NMD);
			}
		}
		for (auto *NMD : namedMDToRemove) {
			NMD->eraseFromParent();
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 5.3: State Register Naming + Implicit Parameter Detection
	// ═══════════════════════════════════════════════════════════════════════
	// Name GEPs and loads from State pointer (arg 0) with register names.
	// Detect implicit parameters (registers read before written in entry).
	// NOTE: GEPs are NOT replaced with allocas — the *(int64_t)(void*)0
	// rendering is fixed on the Helix decompiler side.
	{
		llvm::Value* statePtr = func->getArg(0);
		const auto& DL = liftModule->getDataLayout();

		std::set<std::string> regsWrittenInEntry;
		std::set<std::string> implicitParamSet;

		for (auto& BB : *func) {
			bool isEntry = (&BB == &func->getEntryBlock());
			for (auto& I : BB) {
				auto* GEP = llvm::dyn_cast<llvm::GetElementPtrInst>(&I);
				if (!GEP || GEP->getPointerOperand() != statePtr)
					continue;

				llvm::APInt offset(64, 0);
				if (!GEP->accumulateConstantOffset(DL, offset))
					continue;

				uint64_t byteOff = offset.getZExtValue();
				if (byteOff >= 8192) continue;  // sanity: State < 4KB

				auto* reg = arch_->RegisterAtStateOffset(byteOff);
				if (!reg) continue;

				// Name the GEP and its load/store users
				if (!GEP->hasName())
					GEP->setName("&" + reg->name);

				for (auto* U : GEP->users()) {
					if (auto* LI = llvm::dyn_cast<llvm::LoadInst>(U)) {
						if (!LI->hasName()) LI->setName(reg->name);
						if (isEntry && !regsWrittenInEntry.count(reg->name))
							implicitParamSet.insert(reg->name);
					}
					if (auto* SI = llvm::dyn_cast<llvm::StoreInst>(U)) {
						if (SI->getPointerOperand() == GEP && isEntry)
							regsWrittenInEntry.insert(reg->name);
					}
				}
			}
		}

		for (auto& name : implicitParamSet)
			result.implicitParams.push_back(name);
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 5.4: Lower LLVM Intrinsics to Named Functions
	// ═══════════════════════════════════════════════════════════════════════
	// Intrinsics like llvm.ctpop, llvm.ctlz, llvm.cttz, llvm.bswap are
	// not recognized by the Helix decompiler. Replace with named calls.
	{
		llvm::SmallVector<llvm::CallInst*, 16> intrinsicCalls;

		for (auto& BB : *func) {
			for (auto& I : BB) {
				auto* CI = llvm::dyn_cast<llvm::CallInst>(&I);
				if (!CI) continue;
				auto* callee = CI->getCalledFunction();
				if (!callee || !callee->isIntrinsic()) continue;

				switch (callee->getIntrinsicID()) {
				case llvm::Intrinsic::ctpop:
				case llvm::Intrinsic::ctlz:
				case llvm::Intrinsic::cttz:
				case llvm::Intrinsic::bswap:
					intrinsicCalls.push_back(CI);
					break;
				default:
					break;
				}
			}
		}

		for (auto* CI : intrinsicCalls) {
			auto* callee = CI->getCalledFunction();
			auto intrID = callee->getIntrinsicID();
			auto* retTy = CI->getType();
			if (!retTy->isIntegerTy()) continue;  // skip vector intrinsics
			unsigned bits = retTy->getIntegerBitWidth();

			const char* baseName = nullptr;
			switch (intrID) {
			case llvm::Intrinsic::ctpop: baseName = "__popcnt"; break;
			case llvm::Intrinsic::ctlz:  baseName = "__clz"; break;
			case llvm::Intrinsic::cttz:  baseName = "__ctz"; break;
			case llvm::Intrinsic::bswap: baseName = "__bswap"; break;
			default: continue;
			}

			std::string funcName = std::string(baseName) + std::to_string(bits);
			auto* fnTy = llvm::FunctionType::get(retTy, {retTy}, false);
			auto fnCallee = liftModule->getOrInsertFunction(funcName, fnTy);

			llvm::IRBuilder<> builder(CI);
			auto* newCall = builder.CreateCall(fnCallee, {CI->getArgOperand(0)});
			newCall->setName(funcName);
			CI->replaceAllUsesWith(newCall);
			CI->eraseFromParent();
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 5.5: Run LLVM optimization passes to clean up the IR
	// ═══════════════════════════════════════════════════════════════════════
	// Remill generates verbose IR with many redundant store/load patterns
	// through the State struct.  Running standard LLVM passes dramatically
	// reduces IR size and improves downstream decompilation quality.
	//
	// Pipeline: SROA → mem2reg → instcombine → simplifycfg → DCE → ADCE
	//   - SROA:        breaks aggregate allocas into scalar SSA values
	//   - mem2reg:     promotes remaining allocas to SSA registers
	//   - EarlyCSE:    eliminates common subexpressions (redundant loads)
	//   - instcombine: folds/simplifies instruction sequences
	//   - simplifycfg: merges trivial blocks, removes dead branches
	//   - DCE:         removes dead instructions
	//   - ADCE:        aggressive dead code elimination (catches more)
	//   - DSE:         dead store elimination (removes unused State writes)

	if (options.optimizeIR) {
		// Create analysis managers
		llvm::LoopAnalysisManager LAM;
		llvm::FunctionAnalysisManager FAM;
		llvm::CGSCCAnalysisManager CGAM;
		llvm::ModuleAnalysisManager MAM;

		// Create pass builder and register analyses
		llvm::PassBuilder PB;
		PB.registerModuleAnalyses(MAM);
		PB.registerCGSCCAnalyses(CGAM);
		PB.registerFunctionAnalyses(FAM);
		PB.registerLoopAnalyses(LAM);
		PB.crossRegisterProxies(LAM, FAM, CGAM, MAM);

		// Build function pass pipeline.
		//
		// FIX-052b: TWO pipelines, selected by options.preserveCfgTopology.
		//
		// DEFAULT (preserveCfgTopology == false) — UNCHANGED from before this fix,
		// byte-for-byte. Full cleanup including SimplifyCFG + SROA(ModifyCFG).
		// This is what every NORMAL helix.decompile / liftToIR uses, so ordinary
		// decompiles keep their existing CFG cleanup and readable pseudo-C.
		//   SROA(ModifyCFG) → mem2reg → EarlyCSE → InstCombine → SimplifyCFG → DCE
		//   → ADCE → DSE → InstCombine → SimplifyCFG → InstCombine → SimplifyCFG
		//   → ADCE   (the double SimplifyCFG round matters; see Quality Gates).
		//
		// CFG-PRESERVING (preserveCfgTopology == true) — set ONLY by the
		// disassembler for the callfuscation-deflattened / high-block path. Drops
		// SimplifyCFG (its MergeBlockIntoPredecessor collapses the deflattened
		// single-pred/single-succ jmp-chain into ONE straight-line block —
		// verified even with real back-edges: 980/978 → 1/0) and runs SROA in
		// PreserveCFG mode. Value passes (mem2reg/EarlyCSE/InstCombine/DCE/ADCE/
		// DSE) still clean State-struct noise without touching CFG topology, so
		// the recovered multi-block structure survives to Helix.
		llvm::FunctionPassManager FPM;
		const bool preserveCfg = options.preserveCfgTopology;

		if (preserveCfg) {
			FPM.addPass(llvm::SROAPass(llvm::SROAOptions::PreserveCFG));
			FPM.addPass(llvm::PromotePass());            // mem2reg
			FPM.addPass(llvm::EarlyCSEPass());
			FPM.addPass(llvm::InstCombinePass());
			FPM.addPass(llvm::DCEPass());
			FPM.addPass(llvm::ADCEPass());
			FPM.addPass(llvm::DSEPass());
			FPM.addPass(llvm::InstCombinePass());
			FPM.addPass(llvm::InstCombinePass());
			FPM.addPass(llvm::ADCEPass());
		} else {
			FPM.addPass(llvm::SROAPass(llvm::SROAOptions::ModifyCFG));
			FPM.addPass(llvm::PromotePass());            // mem2reg
			FPM.addPass(llvm::EarlyCSEPass());            // common subexpression elimination
			FPM.addPass(llvm::InstCombinePass());          // instruction combining
			FPM.addPass(llvm::SimplifyCFGPass());          // simplify control flow graph
			FPM.addPass(llvm::DCEPass());                  // dead code elimination
			FPM.addPass(llvm::ADCEPass());                 // aggressive dead code elimination
			FPM.addPass(llvm::DSEPass());                  // dead store elimination

			// Second round: instcombine + simplifycfg after DSE may expose more
			FPM.addPass(llvm::InstCombinePass());
			FPM.addPass(llvm::SimplifyCFGPass());

			// Third round: catch remaining dead branches + constant conditions
			FPM.addPass(llvm::InstCombinePass());
			FPM.addPass(llvm::SimplifyCFGPass());
			FPM.addPass(llvm::ADCEPass());
		}

		// Run on all functions in the module (primarily the lifted function)
		llvm::ModulePassManager MPM;
		MPM.addPass(llvm::createModuleToFunctionPassAdaptor(std::move(FPM)));
		MPM.run(*liftModule, MAM);
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 6: Name all unnamed instructions to avoid SSA numbering issues
	// ═══════════════════════════════════════════════════════════════════════
	// Multi-block lifting inserts instructions into different blocks out of
	// creation order, and the strip phase removes referenced values.  This
	// can leave gaps/duplicates in the automatic numbering (%0, %1, ...).
	// Giving every value an explicit name sidesteps the issue entirely.
	{
		unsigned counter = 0;
		for (auto &F : *liftModule) {
			for (auto &BB : F) {
				if (!BB.hasName()) {
					BB.setName("bb_" + std::to_string(counter++));
				}
				for (auto &I : BB) {
					if (!I.hasName() && !I.getType()->isVoidTy()) {
						I.setName("v" + std::to_string(counter++));
					}
				}
			}
		}
	}

	// ═══════════════════════════════════════════════════════════════════════
	// Phase 5.6: Resolve external CALLI targets using externalSymbols_ map
	// ═══════════════════════════════════════════════════════════════════════
	// For ET_REL (kernel modules), the TypeScript layer patches call
	// displacements to point to fake addresses (0x7FFF0000+). The Remill
	// lifter decodes these as real calls and records them in callTargets.
	// However, Phase 4.5 (calliTargets) often fails to inject the concrete
	// target into the CALLI arg because the CallInst pointer becomes stale.
	//
	// This phase walks ALL instructions looking for CALLI calls where
	// arg[2] (the target) is an i64 constant matching our fake address map.
	// When found, it creates a declared external function and replaces the
	// CALLI with a direct call to it.
	//
	// Even if the i64 constant was NOT injected by Phase 4.5, we also scan
	// callTargets (populated by Phase 3) and inject external function
	// declarations into the module so the downstream decompiler knows about
	// the external dependencies.

	if (!externalSymbols_.empty()) {
		auto& ctx = liftModule->getContext();
		auto* voidTy = llvm::Type::getVoidTy(ctx);
		auto* i8PtrTy = llvm::PointerType::get(ctx, 0);

		// Create a generic external function type: ptr(...)
		auto* externFnTy = llvm::FunctionType::get(i8PtrTy, /* isVarArg= */ true);

		// Cache declared external functions
		std::map<std::string, llvm::Function*> declaredFns;
		auto getOrCreateExtern = [&](const std::string& name) -> llvm::Function* {
			auto it = declaredFns.find(name);
			if (it != declaredFns.end()) return it->second;
			auto* fn = llvm::Function::Create(
				externFnTy, llvm::GlobalValue::ExternalLinkage, name, liftModule.get());
			declaredFns[name] = fn;
			return fn;
		};

		size_t resolvedCount = 0;

		// Strategy 1: Scan callTargets from Phase 3 and inject declares
		for (uint64_t ct : result.callTargets) {
			auto it = externalSymbols_.find(ct);
			if (it != externalSymbols_.end()) {
				getOrCreateExtern(it->second);
				resolvedCount++;
			}
		}

		// Strategy 2: Walk all CallInsts and try to replace CALLI calls
		// where the target arg is a constant matching externalSymbols_.
		for (auto& F : *liftModule) {
			for (auto& BB : F) {
				std::vector<llvm::CallInst*> toReplace;
				for (auto& I : BB) {
					auto* CI = llvm::dyn_cast<llvm::CallInst>(&I);
					if (!CI) continue;

					auto* calledFn = CI->getCalledFunction();
					if (!calledFn || !calledFn->getName().contains("CALLI")) continue;

					// CALLI signature: (Memory, State, target_i64, NEXT_PC, ...)
					// arg[2] is the call target address
					if (CI->arg_size() <= 2) continue;
					auto* targetArg = llvm::dyn_cast<llvm::ConstantInt>(CI->getArgOperand(2));
					if (!targetArg) continue;

					uint64_t targetAddr = targetArg->getZExtValue();
					auto symIt = externalSymbols_.find(targetAddr);
					if (symIt == externalSymbols_.end()) continue;

					// Found a CALLI with a resolved external target!
					// We can't easily replace the CALLI call with a different
					// function signature in-place (Remill's CALLI passes State/Memory).
					// Instead, inject a comment-style call right after: the downstream
					// IR text replacement in TypeScript will pick it up.
					// For now, just ensure the declare exists.
					getOrCreateExtern(symIt->second);
					resolvedCount++;
				}
			}
		}

		// Strategy 3: Regardless of CALLI matching, declare ALL external
		// symbols so the IR has `declare ptr @mutex_lock(...)` etc.
		// The Helix decompiler uses these + @__hxreloc__ to resolve calls.
		for (auto& [addr, name] : externalSymbols_) {
			getOrCreateExtern(name);
		}
	}

	// Print the stripped module
	std::string irStr;
	llvm::raw_string_ostream os(irStr);
	liftModule->print(os, nullptr);
	os.flush();

	result.ir = irStr;
	result.success = true;
	return result;
}

// ═══════════════════════════════════════════════════════════════════════
// FIX-011: setExternalSymbols / clearExternalSymbols
// ═══════════════════════════════════════════════════════════════════════
// Called from JS before liftBytes() to provide a map of
// fakeAddr → symbolName for ET_REL relocations. After lifting,
// DoLift Phase 5.6 uses this map to resolve CALLI targets.

Napi::Value RemillLifter::SetExternalSymbols(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (info.Length() < 1 || !info[0].IsObject()) {
		Napi::TypeError::New(env, "setExternalSymbols expects an object { address: name, ... }")
			.ThrowAsJavaScriptException();
		return env.Undefined();
	}

	externalSymbols_.clear();
	Napi::Object map = info[0].As<Napi::Object>();
	Napi::Array keys = map.GetPropertyNames();
	for (uint32_t i = 0; i < keys.Length(); i++) {
		std::string key = keys.Get(i).As<Napi::String>().Utf8Value();
		std::string name = map.Get(key).As<Napi::String>().Utf8Value();
		uint64_t addr = std::stoull(key);
		externalSymbols_[addr] = name;
	}
	return Napi::Number::New(env, static_cast<double>(externalSymbols_.size()));
}

Napi::Value RemillLifter::ClearExternalSymbols(const Napi::CallbackInfo& info) {
	externalSymbols_.clear();
	return info.Env().Undefined();
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

	// Boundary detection metadata
	obj.Set("truncated", Napi::Boolean::New(env, result.truncated));
	obj.Set("nextAddress", Napi::Number::New(env,
		static_cast<double>(result.nextAddress)));
	if (!result.truncationReason.empty()) {
		obj.Set("truncationReason", Napi::String::New(env, result.truncationReason));
	}

	// External call targets discovered during lifting
	auto targets = Napi::Array::New(env, result.callTargets.size());
	for (size_t i = 0; i < result.callTargets.size(); i++) {
		targets.Set(static_cast<uint32_t>(i), Napi::Number::New(env,
			static_cast<double>(result.callTargets[i])));
	}
	obj.Set("callTargets", targets);

	// Implicit parameters (registers read before written)
	auto params = Napi::Array::New(env, result.implicitParams.size());
	for (size_t i = 0; i < result.implicitParams.size(); i++) {
		params.Set(static_cast<uint32_t>(i),
			Napi::String::New(env, result.implicitParams[i]));
	}
	obj.Set("implicitParams", params);

	return obj;
}

// ---------------------------------------------------------------------------
// LiftBytesWorker
// ---------------------------------------------------------------------------

LiftBytesWorker::LiftBytesWorker(
	Napi::Env env,
	RemillLifter* lifter,
	std::vector<uint8_t> bytes,
	uint64_t address,
	LiftOptions options)
	: Napi::AsyncWorker(env),
	  lifter_(lifter),
	  bytes_(std::move(bytes)),
	  address_(address),
	  options_(options),
	  deferred_(Napi::Promise::Deferred::New(env)) {}

void LiftBytesWorker::Execute() {
	try {
		result_ = lifter_->DoLift(bytes_.data(), bytes_.size(), address_, options_);
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
