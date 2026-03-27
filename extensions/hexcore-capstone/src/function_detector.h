// Copyright (c) HikariSystem. All rights reserved.
// Licensed under the MIT License. See LICENSE in the project root.

#ifndef FUNCTION_DETECTOR_H
#define FUNCTION_DETECTOR_H

#include <napi.h>
#include <capstone/capstone.h>
#include <vector>
#include <set>
#include <string>
#include <cstring>
#include <algorithm>

// ============================================================================
// FunctionBoundary — result structure for detected functions
// ============================================================================
struct FunctionBoundary {
	uint64_t start;
	uint64_t end;             // address of last instruction
	uint32_t size;            // bytes from start to end of last instruction
	uint32_t instructionCount;
	std::string detectionMethod; // "prologue", "call_target", "symbol", "heuristic"
	float confidence;            // 0.0 - 1.0
	std::vector<uint64_t> callTargets;   // functions this one calls
	std::vector<uint64_t> calledBy;      // functions that call this one
	bool hasReturn;
	bool isThunk;               // single jump to another function
};

// ============================================================================
// Prologue pattern matchers
// ============================================================================

// x86/x64 prologue patterns (checked on first 1-4 instructions)
static inline bool isX86Prologue(const uint8_t* code, size_t codeLen) {
	if (codeLen < 1) return false;

	// push rbp / push ebp
	if (code[0] == 0x55) return true;

	// endbr64 (F3 0F 1E FA) + push rbp
	if (codeLen >= 5 && code[0] == 0xF3 && code[1] == 0x0F &&
	    code[2] == 0x1E && code[3] == 0xFA && code[4] == 0x55) return true;

	// endbr32 (F3 0F 1E FB) + push ebp
	if (codeLen >= 5 && code[0] == 0xF3 && code[1] == 0x0F &&
	    code[2] == 0x1E && code[3] == 0xFB && code[4] == 0x55) return true;

	// mov edi, edi / push ebp / mov ebp, esp (Windows hotpatch)
	if (codeLen >= 5 && code[0] == 0x8B && code[1] == 0xFF &&
	    code[2] == 0x55 && code[3] == 0x8B && code[4] == 0xEC) return true;

	// sub rsp, imm8 (48 83 EC xx) — leaf function without frame pointer
	if (codeLen >= 4 && code[0] == 0x48 && code[1] == 0x83 &&
	    code[2] == 0xEC) return true;

	// sub rsp, imm32 (48 81 EC xx xx xx xx)
	if (codeLen >= 7 && code[0] == 0x48 && code[1] == 0x81 &&
	    code[2] == 0xEC) return true;

	// push r14/r15/rbx etc (common non-volatile register saves)
	// 41 56 = push r14, 41 57 = push r15, 53 = push rbx
	if (codeLen >= 2 && code[0] == 0x41 && (code[1] == 0x56 || code[1] == 0x57)) return true;

	return false;
}

static inline bool isARM64Prologue(uint32_t word) {
	// STP x29, x30, [sp, #offset]! (pre-indexed)
	// Encoding: 101 0100 1 1 0 imm7 11110 11101  → mask FC407FFF, expect A8007BFD
	// But the immediate varies, so: (word & 0xFC407FFF) == 0xA8007BFD
	// Actually more common: STP x29, x30, [sp, #-N]!
	// 1010 1001 10 imm7 11110 11101 → A9807BFD family
	if ((word & 0xFFC07FFF) == 0xA9807BFD) return true;  // STP x29, x30, [sp, #-N]!
	if ((word & 0xFC407FFF) == 0xA8007BFD) return true;   // STP x29, x30, pre-index variants

	// PACIASP (D503233F)
	if (word == 0xD503233F) return true;

	// SUB SP, SP, #imm (stack allocation as first instruction)
	// 1101 0001 00 imm12 11111 11111 → D10003FF with SP
	if ((word & 0xFF0003FF) == 0xD10003FF && ((word >> 5) & 0x1F) == 31) return true;

	return false;
}

static inline bool isARM32Prologue(uint32_t word) {
	// PUSH {regs, lr} — STMDB SP!, {regs, lr}
	// E92D XXXX where bit 14 (LR) is set
	if ((word & 0xFFFF0000) == 0xE92D0000 && (word & (1 << 14)) != 0) return true;

	// PUSH {r4-r11, lr} variants
	// Thumb2: E92D 4xxx
	if ((word & 0xFFFF0000) == 0xE92D0000 && (word & 0x4000) != 0) return true;

	return false;
}

static inline bool isMIPSPrologue(const uint8_t* code, size_t codeLen, bool bigEndian) {
	if (codeLen < 8) return false;
	// addiu $sp, $sp, -N  (little endian: XX XX BD 27)
	// followed by sw $ra, offset($sp)
	uint32_t word;
	if (bigEndian) {
		word = (code[0] << 24) | (code[1] << 16) | (code[2] << 8) | code[3];
	} else {
		word = code[0] | (code[1] << 8) | (code[2] << 16) | (code[3] << 24);
	}
	// addiu sp, sp, -N → opcode 001001 rs=11101 rt=11101 → 27BDXXXX
	if ((word & 0xFFFF0000) == 0x27BD0000) return true;

	return false;
}

// ============================================================================
// FunctionDetectorWorker — AsyncWorker for background function detection
// ============================================================================
class FunctionDetectorWorker : public Napi::AsyncWorker {
public:
	FunctionDetectorWorker(
		Napi::Env env,
		Napi::Promise::Deferred deferred,
		cs_arch arch,
		cs_mode mode,
		std::vector<uint8_t> code,
		uint64_t baseAddress,
		uint32_t maxFunctions
	) : Napi::AsyncWorker(env),
	    deferred_(deferred),
	    arch_(arch),
	    mode_(mode),
	    code_(std::move(code)),
	    baseAddress_(baseAddress),
	    maxFunctions_(maxFunctions) {}

	void Execute() override {
		csh handle;
		cs_err err = cs_open(arch_, mode_, &handle);
		if (err != CS_ERR_OK) {
			SetError(std::string("Capstone error: ") + cs_strerror(err));
			return;
		}

		// Enable DETAIL for group analysis (isCall, isRet, isJump)
		cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

		// Phase 1: Linear scan — disassemble entire buffer, collect prologues and call targets
		std::set<uint64_t> prologueAddrs;
		std::set<uint64_t> callTargets;
		std::set<uint64_t> retAddrs;

		// For the iter API
		cs_insn* insn = cs_malloc(handle);
		if (!insn) {
			cs_close(&handle);
			SetError("Failed to allocate Capstone instruction");
			return;
		}

		const uint8_t* codePtr = code_.data();
		size_t codeSize = code_.size();
		uint64_t addr = baseAddress_;

		// Check bytes at offset 0 for prologue before iterating
		if (checkPrologue(code_.data(), code_.size())) {
			prologueAddrs.insert(baseAddress_);
		}

		while (cs_disasm_iter(handle, &codePtr, &codeSize, &addr, insn)) {
			// Check if this instruction starts a prologue sequence
			size_t offset = static_cast<size_t>(insn->address - baseAddress_);
			if (offset < code_.size()) {
				size_t remaining = code_.size() - offset;
				if (checkPrologue(code_.data() + offset, remaining)) {
					prologueAddrs.insert(insn->address);
				}
			}

			// Check instruction groups
			if (insn->detail) {
				bool isCall = false;
				bool isRet = false;
				bool isJump = false;

				for (uint8_t g = 0; g < insn->detail->groups_count; g++) {
					uint8_t grp = insn->detail->groups[g];
					if (grp == CS_GRP_CALL) isCall = true;
					if (grp == CS_GRP_RET || grp == CS_GRP_IRET) isRet = true;
					if (grp == CS_GRP_JUMP) isJump = true;
				}

				if (isCall) {
					uint64_t target = extractTarget(insn);
					if (target != 0 && target >= baseAddress_ &&
					    target < baseAddress_ + code_.size()) {
						callTargets.insert(target);
					}
				}

				if (isRet) {
					retAddrs.insert(insn->address);
				}

				// Unconditional jump to a far address after a ret could indicate
				// a thunk or tail call — the target is a potential function
				if (isJump && !isCall) {
					uint64_t target = extractTarget(insn);
					if (target != 0 && target >= baseAddress_ &&
					    target < baseAddress_ + code_.size()) {
						// Only if the previous instruction was a ret or
						// this jump is at a prologue-detected boundary
						if (prologueAddrs.count(insn->address)) {
							callTargets.insert(target);
						}
					}
				}
			}
		}

		cs_free(insn, 1);

		// Phase 2: Merge candidates (prologues + call targets)
		std::set<uint64_t> allCandidates;
		allCandidates.insert(prologueAddrs.begin(), prologueAddrs.end());
		allCandidates.insert(callTargets.begin(), callTargets.end());

		// Phase 3: Build function boundaries
		// Sort candidates and assign each one the range until the next candidate
		std::vector<uint64_t> sorted(allCandidates.begin(), allCandidates.end());
		std::sort(sorted.begin(), sorted.end());

		// Limit to maxFunctions
		if (maxFunctions_ > 0 && sorted.size() > maxFunctions_) {
			sorted.resize(maxFunctions_);
		}

		for (size_t i = 0; i < sorted.size(); i++) {
			FunctionBoundary fb;
			fb.start = sorted[i];

			// End is either next function start - 1 or end of buffer
			uint64_t nextStart = (i + 1 < sorted.size()) ?
				sorted[i + 1] : baseAddress_ + code_.size();
			fb.end = nextStart - 1;
			fb.size = static_cast<uint32_t>(nextStart - sorted[i]);

			// Detection method
			bool isPrologue = prologueAddrs.count(sorted[i]) > 0;
			bool isCallTgt = callTargets.count(sorted[i]) > 0;
			if (isPrologue && isCallTgt) {
				fb.detectionMethod = "prologue";
				fb.confidence = 0.95f;
			} else if (isPrologue) {
				fb.detectionMethod = "prologue";
				fb.confidence = 0.85f;
			} else if (isCallTgt) {
				fb.detectionMethod = "call_target";
				fb.confidence = 0.75f;
			} else {
				fb.detectionMethod = "heuristic";
				fb.confidence = 0.5f;
			}

			// Check if any ret exists within this function's range
			auto retIt = retAddrs.lower_bound(sorted[i]);
			fb.hasReturn = (retIt != retAddrs.end() && *retIt < nextStart);

			// Check if it's a thunk (very small function with just a jump)
			fb.isThunk = (fb.size <= 16 && !fb.hasReturn);

			fb.instructionCount = 0; // Would need a second pass to count accurately

			// Call relationships
			// callTargets that fall within our range are our callees
			// (simplified — full analysis would re-disassemble each function)

			results_.push_back(std::move(fb));
		}

		cs_close(&handle);
	}

	void OnOK() override {
		Napi::Env env = Env();
		Napi::Array result = Napi::Array::New(env, results_.size());

		for (size_t i = 0; i < results_.size(); i++) {
			const auto& fb = results_[i];
			Napi::Object obj = Napi::Object::New(env);

			obj.Set("start", Napi::BigInt::New(env, fb.start));
			obj.Set("end", Napi::BigInt::New(env, fb.end));
			obj.Set("size", Napi::Number::New(env, fb.size));
			obj.Set("instructionCount", Napi::Number::New(env, fb.instructionCount));
			obj.Set("detectionMethod", Napi::String::New(env, fb.detectionMethod));
			obj.Set("confidence", Napi::Number::New(env, fb.confidence));
			obj.Set("hasReturn", Napi::Boolean::New(env, fb.hasReturn));
			obj.Set("isThunk", Napi::Boolean::New(env, fb.isThunk));

			Napi::Array callTargets = Napi::Array::New(env, fb.callTargets.size());
			for (size_t j = 0; j < fb.callTargets.size(); j++) {
				callTargets.Set(j, Napi::BigInt::New(env, fb.callTargets[j]));
			}
			obj.Set("callTargets", callTargets);

			Napi::Array calledBy = Napi::Array::New(env, fb.calledBy.size());
			for (size_t j = 0; j < fb.calledBy.size(); j++) {
				calledBy.Set(j, Napi::BigInt::New(env, fb.calledBy[j]));
			}
			obj.Set("calledBy", calledBy);

			result.Set(i, obj);
		}

		deferred_.Resolve(result);
	}

	void OnError(const Napi::Error& error) override {
		deferred_.Reject(error.Value());
	}

private:
	Napi::Promise::Deferred deferred_;
	cs_arch arch_;
	cs_mode mode_;
	std::vector<uint8_t> code_;
	uint64_t baseAddress_;
	uint32_t maxFunctions_;
	std::vector<FunctionBoundary> results_;

	// Check if bytes at current position match a prologue pattern
	bool checkPrologue(const uint8_t* data, size_t len) {
		switch (arch_) {
		case CS_ARCH_X86:
			return isX86Prologue(data, len);

		case CS_ARCH_ARM64:
			if (len >= 4) {
				uint32_t word = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
				return isARM64Prologue(word);
			}
			return false;

		case CS_ARCH_ARM:
			if (len >= 4) {
				uint32_t word;
				if (mode_ & CS_MODE_BIG_ENDIAN) {
					word = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
				} else {
					word = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
				}
				return isARM32Prologue(word);
			}
			return false;

		case CS_ARCH_MIPS:
			return isMIPSPrologue(data, len, (mode_ & CS_MODE_BIG_ENDIAN) != 0);

		default:
			return false;
		}
	}

	// Extract jump/call target address from instruction
	uint64_t extractTarget(cs_insn* insn) {
		switch (arch_) {
		case CS_ARCH_X86:
			if (insn->detail && insn->detail->x86.op_count > 0) {
				cs_x86_op& op = insn->detail->x86.operands[0];
				if (op.type == X86_OP_IMM) {
					return static_cast<uint64_t>(op.imm);
				}
			}
			break;

		case CS_ARCH_ARM64:
			if (insn->detail && insn->detail->arm64.op_count > 0) {
				cs_arm64_op& op = insn->detail->arm64.operands[0];
				if (op.type == ARM64_OP_IMM) {
					return static_cast<uint64_t>(op.imm);
				}
			}
			break;

		case CS_ARCH_ARM:
			if (insn->detail && insn->detail->arm.op_count > 0) {
				cs_arm_op& op = insn->detail->arm.operands[0];
				if (op.type == ARM_OP_IMM) {
					return static_cast<uint64_t>(op.imm);
				}
			}
			break;

		case CS_ARCH_MIPS:
			if (insn->detail && insn->detail->mips.op_count > 0) {
				cs_mips_op& op = insn->detail->mips.operands[0];
				if (op.type == MIPS_OP_IMM) {
					return static_cast<uint64_t>(op.imm);
				}
			}
			break;

		default:
			break;
		}
		return 0;
	}
};

#endif // FUNCTION_DETECTOR_H
