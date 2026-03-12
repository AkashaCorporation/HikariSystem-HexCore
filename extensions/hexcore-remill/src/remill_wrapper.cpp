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

#include <sstream>
#include <set>
#include <vector>
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

	{
		remill::Instruction scanInst;
		uint64_t scanPC = address;
		size_t scanOffset = 0;
		auto scanContext = arch_->CreateInitialContext();

		while (scanOffset < length) {
			std::string_view instrBytes(
				reinterpret_cast<const char*>(bytes + scanOffset), length - scanOffset);

			if (!arch_->DecodeInstruction(scanPC, instrBytes, scanInst, scanContext)) {
				break;
			}

			DecodedInst di;
			di.inst = scanInst;
			di.pc = scanPC;
			di.size = scanInst.bytes.size();
			decoded.push_back(di);

			uint64_t nextPC = scanPC + scanInst.bytes.size();

			// Check if this instruction is a branch
			// Remill categorizes instructions — check for jumps
			switch (scanInst.category) {
			case remill::Instruction::kCategoryDirectJump:
				// Unconditional jump: target_pc is a leader
				if (!scanInst.branch_taken_pc) {
					// Fallback: check operands for the target
				} else {
					leaders.insert(scanInst.branch_taken_pc);
				}
				break;

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
			// Unconditional jump: br label %target_bb
			if (di.inst.branch_taken_pc && bbMap.count(di.inst.branch_taken_pc)) {
				llvm::IRBuilder<> builder(currentBlock);
				builder.CreateBr(bbMap[di.inst.branch_taken_pc]);
			}
			break;
		}

		case remill::Instruction::kCategoryConditionalBranch: {
			// Conditional branch: need to find the condition value
			// Remill emitted a __remill_jump call — the condition is the
			// comparison result stored in flags.  We'll look for the last
			// ICmp or the condition operand of the __remill_jump call.
			//
			// For now, emit a conditional branch with an i1 placeholder
			// that we'll populate from the last flag computation.
			if (di.inst.branch_taken_pc && bbMap.count(di.inst.branch_taken_pc)) {
				uint64_t fallthroughPC = di.inst.branch_not_taken_pc ? 
					di.inst.branch_not_taken_pc : nextPC;

				llvm::BasicBlock* trueBB = bbMap[di.inst.branch_taken_pc];
				llvm::BasicBlock* falseBB = bbMap.count(fallthroughPC) ?
					bbMap[fallthroughPC] : nullptr;

				if (trueBB && falseBB) {
					llvm::IRBuilder<> builder(currentBlock);

					// Try to find the condition from the last ICmp in this block
					llvm::Value* cond = nullptr;
					for (auto it = currentBlock->rbegin(); it != currentBlock->rend(); ++it) {
						if (auto* icmp = llvm::dyn_cast<llvm::ICmpInst>(&*it)) {
							cond = icmp;
							break;
						}
					}

					if (!cond) {
						// Fallback: create a true constant (always take branch)
						// This is suboptimal but safe — Helix will still see the structure
						cond = llvm::ConstantInt::getTrue(liftModule->getContext());
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
		case remill::Instruction::kCategoryNoOp: {
			// Normal instruction: if the NEXT instruction starts a new block,
			// add a fallthrough branch to connect them
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
	// Phase 4: Ensure every basic block has a terminator
	// ═══════════════════════════════════════════════════════════════════════
	// Remill's LiftIntoBlock leaves blocks "open" (no ret/br).
	// Add terminators to any blocks that still lack them.

	for (auto &BB : *func) {
		if (!BB.getTerminator()) {
			llvm::IRBuilder<> builder(&BB);
			// Return the memory pointer (3rd argument) to match Remill convention.
			builder.CreateRet(func->getArg(2));
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
						auto it = blockOutgoing.find(pred);
						if (it != blockOutgoing.end())
							lastStored = it->second;
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

		// 6. Strip bodies from callee functions (keep as declarations)
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

	// Print the stripped module
	std::string irStr;
	llvm::raw_string_ostream os(irStr);
	liftModule->print(os, nullptr);
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
