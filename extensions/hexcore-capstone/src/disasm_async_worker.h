/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

#ifndef DISASM_ASYNC_WORKER_H
#define DISASM_ASYNC_WORKER_H

#include <napi.h>
#include <capstone/capstone.h>
#include <vector>
#include <cstring>
#include <variant>
#include <optional>
#include <utility>

// ============================================================================
// Intermediate structures for transferring data from worker thread to main
// These hold copies of Capstone data that can be safely passed between threads
// ============================================================================

// x86 operand
struct X86OpResult {
	uint8_t type;
	uint8_t size;
	uint8_t access;
	uint8_t avx_bcast;
	bool avx_zero_opmask;
	// Value based on type
	uint32_t reg;
	int64_t imm;
	struct {
		uint32_t segment;
		uint32_t base;
		uint32_t index;
		int scale;
		int64_t disp;
	} mem;
};

// x86 detail
struct X86DetailResult {
	uint8_t prefix[4];
	uint8_t opcode[4];
	uint8_t rex;
	uint8_t addr_size;
	uint8_t modrm;
	uint8_t sib;
	int64_t disp;
	uint32_t sib_index;
	int8_t sib_scale;
	uint32_t sib_base;
	uint8_t xop_cc;
	uint8_t sse_cc;
	uint8_t avx_cc;
	bool avx_sae;
	uint8_t avx_rm;
	uint64_t eflags;
	std::vector<X86OpResult> operands;
};

// ARM operand
struct ArmOpResult {
	uint8_t type;
	uint8_t access;
	uint32_t reg;
	int32_t imm;
	double fp;
	struct {
		uint32_t base;
		uint32_t index;
		int scale;
		int32_t disp;
		int lshift;
	} mem;
	int8_t shift_type;
	uint32_t shift_value;
	int8_t vector_index;
	bool subtracted;
};

// ARM detail
struct ArmDetailResult {
	bool usermode;
	int vector_size;
	int vector_data;
	int cps_mode;
	int cps_flag;
	int cc;
	bool update_flags;
	bool writeback;
	int mem_barrier;
	std::vector<ArmOpResult> operands;
};

// ARM64 operand
struct Arm64OpResult {
	uint8_t type;
	uint8_t access;
	uint32_t reg;
	int64_t imm;
	double fp;
	struct {
		uint32_t base;
		uint32_t index;
		int32_t disp;
	} mem;
	uint8_t shift_type;
	uint32_t shift_value;
	uint8_t ext;
	int8_t vas;
	int8_t vector_index;
};

// ARM64 detail
struct Arm64DetailResult {
	int cc;
	bool update_flags;
	bool writeback;
	std::vector<Arm64OpResult> operands;
};

// MIPS operand
struct MipsOpResult {
	uint8_t type;
	uint32_t reg;
	int64_t imm;
	struct {
		uint32_t base;
		int64_t disp;
	} mem;
};

// MIPS detail
struct MipsDetailResult {
	std::vector<MipsOpResult> operands;
};

// PPC operand
struct PpcOpResult {
	uint8_t type;
	uint32_t reg;
	int64_t imm;
	struct {
		uint32_t base;
		int32_t disp;
	} mem;
	struct {
		uint32_t scale;
		uint32_t reg;
		int cond;
	} crx;
};

// PPC detail
struct PpcDetailResult {
	int bc;
	int bh;
	bool update_cr0;
	std::vector<PpcOpResult> operands;
};

// SPARC operand
struct SparcOpResult {
	uint8_t type;
	uint32_t reg;
	int64_t imm;
	struct {
		uint8_t base;
		uint8_t index;
		int32_t disp;
	} mem;
};

// SPARC detail
struct SparcDetailResult {
	int cc;
	int hint;
	std::vector<SparcOpResult> operands;
};

// SystemZ operand
struct SyszOpResult {
	uint8_t type;
	uint32_t reg;
	int64_t imm;
	struct {
		uint8_t base;
		uint8_t index;
		uint64_t length;
		int64_t disp;
	} mem;
};

// SystemZ detail
struct SyszDetailResult {
	int cc;
	std::vector<SyszOpResult> operands;
};

// XCore operand
struct XcoreOpResult {
	uint8_t type;
	uint32_t reg;
	int32_t imm;
	struct {
		uint8_t base;
		uint8_t index;
		int32_t disp;
		int direct;
	} mem;
};

// XCore detail
struct XcoreDetailResult {
	std::vector<XcoreOpResult> operands;
};

// M68K operand
struct M68kOpResult {
	uint8_t type;
	uint8_t address_mode;
	uint32_t reg;
	uint64_t imm;
	double dimm;
	float simm;
	uint32_t register_bits;
	struct {
		uint32_t reg_0;
		uint32_t reg_1;
	} reg_pair;
	struct {
		uint32_t base_reg;
		uint32_t index_reg;
		uint32_t in_base_reg;
		uint32_t in_disp;
		uint32_t out_disp;
		int16_t disp;
		uint8_t scale;
		uint8_t bitfield;
		uint8_t width;
		uint8_t offset;
		uint8_t index_size;
	} mem;
};

// M68K detail
struct M68kDetailResult {
	uint8_t op_size_type;
	std::vector<M68kOpResult> operands;
};

// RISC-V operand
struct RiscvOpResult {
	uint8_t type;
	uint32_t reg;
	int64_t imm;
	struct {
		uint32_t base;
		int64_t disp;
	} mem;
};

// RISC-V detail
struct RiscvDetailResult {
	std::vector<RiscvOpResult> operands;
};

// Union of all architecture details
using ArchDetailResult = std::variant<
	std::monostate,
	X86DetailResult,
	ArmDetailResult,
	Arm64DetailResult,
	MipsDetailResult,
	PpcDetailResult,
	SparcDetailResult,
	SyszDetailResult,
	XcoreDetailResult,
	M68kDetailResult,
	RiscvDetailResult
>;

/**
 * Intermediate structure to hold disassembled instruction data
 * This is used to transfer data from worker thread to main thread
 */
struct DisasmResult {
	uint32_t id;
	uint64_t address;
	uint16_t size;
	std::vector<uint8_t> bytes;
	std::string mnemonic;
	std::string op_str;

	// Detail data (optional)
	bool hasDetail;
	std::vector<uint16_t> regsRead;
	std::vector<uint16_t> regsWrite;
	std::vector<uint8_t> groups;

	// Architecture-specific detail
	ArchDetailResult archDetail;
};

/**
 * AsyncWorker for non-blocking disassembly
 * Runs cs_disasm in a background thread and returns results via Promise
 */
class DisasmAsyncWorker : public Napi::AsyncWorker {
public:
	DisasmAsyncWorker(
		Napi::Env env,
		cs_arch arch,
		cs_mode mode,
		std::vector<uint8_t> code,
		uint64_t address,
		size_t count,
		std::vector<std::pair<cs_opt_type, size_t>> optionState
	) : Napi::AsyncWorker(env),
		deferred_(Napi::Promise::Deferred::New(env)),
		arch_(arch),
		mode_(mode),
		code_(std::move(code)),
		address_(address),
		count_(count),
		includeDetail_(false),
		optionState_(std::move(optionState)),
		numInsns_(0),
		error_(CS_ERR_OK) {

		for (const auto& option : optionState_) {
			if (option.first == CS_OPT_DETAIL) {
				includeDetail_ = (option.second == CS_OPT_ON);
			}
		}
	}

	~DisasmAsyncWorker() {}

	/**
	 * Get the Promise that will be resolved when work completes
	 */
	Napi::Promise GetPromise() { return deferred_.Promise(); }

	/**
	 * Execute in background thread - no V8/N-API calls allowed here!
	 */
	void Execute() override {
		csh handle;
		cs_err err = cs_open(arch_, mode_, &handle);

		if (err != CS_ERR_OK) {
			error_ = err;
			return;
		}

		for (const auto& option : optionState_) {
			err = cs_option(handle, option.first, option.second);
			if (err != CS_ERR_OK) {
				error_ = err;
				cs_close(&handle);
				return;
			}
		}

		cs_insn* insn = nullptr;

		// Perform disassembly in background thread
		numInsns_ = cs_disasm(
			handle,
			code_.data(),
			code_.size(),
			address_,
			count_,
			&insn
		);

		if (numInsns_ == 0) {
			error_ = cs_errno(handle);
			// Only treat as error if Capstone reported an actual error
			// numInsns_ == 0 with CS_ERR_OK means no valid instructions found (not an error)
			if (error_ != CS_ERR_OK) {
				cs_close(&handle);
				return;
			}
		}

		// Copy data to our intermediate structures (no V8 objects here!)
		results_.reserve(numInsns_);

		for (size_t i = 0; i < numInsns_; i++) {
			DisasmResult result;
			result.id = insn[i].id;
			result.address = insn[i].address;
			result.size = insn[i].size;
			result.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
			result.mnemonic = insn[i].mnemonic;
			result.op_str = insn[i].op_str;
			result.hasDetail = false;

			// Copy detail if available and requested
			if (includeDetail_ && insn[i].detail != nullptr) {
				result.hasDetail = true;
				cs_detail* detail = insn[i].detail;

				result.regsRead.assign(
					detail->regs_read,
					detail->regs_read + detail->regs_read_count
				);
				result.regsWrite.assign(
					detail->regs_write,
					detail->regs_write + detail->regs_write_count
				);
				result.groups.assign(
					detail->groups,
					detail->groups + detail->groups_count
				);

				// Copy architecture-specific detail
				CopyArchDetail(result, &insn[i]);
			}

			results_.push_back(std::move(result));
		}

		// Free Capstone memory
		if (numInsns_ > 0) {
			cs_free(insn, numInsns_);
		}
		cs_close(&handle);
	}

	/**
	 * Called in main thread after Execute completes successfully
	 */
	void OnOK() override {
		Napi::Env env = Env();
		Napi::HandleScope scope(env);

		// Convert results to JavaScript array
		Napi::Array jsArray = Napi::Array::New(env, results_.size());

		for (size_t i = 0; i < results_.size(); i++) {
			jsArray.Set(static_cast<uint32_t>(i), ResultToObject(env, results_[i]));
		}

		deferred_.Resolve(jsArray);
	}

	/**
	 * Called in main thread if Execute throws
	 */
	void OnError(const Napi::Error& error) override {
		deferred_.Reject(error.Value());
	}

private:
	Napi::Promise::Deferred deferred_;
	cs_arch arch_;
	cs_mode mode_;
	std::vector<uint8_t> code_;
	uint64_t address_;
	size_t count_;
	bool includeDetail_;
	std::vector<std::pair<cs_opt_type, size_t>> optionState_;

	// Results from Execute()
	size_t numInsns_;
	cs_err error_;
	std::vector<DisasmResult> results_;

	/**
	 * Copy architecture-specific detail in worker thread
	 */
	void CopyArchDetail(DisasmResult& result, cs_insn* insn) {
		cs_detail* detail = insn->detail;

		switch (arch_) {
			case CS_ARCH_X86:
				result.archDetail = CopyX86Detail(&detail->x86);
				break;
			case CS_ARCH_ARM:
				result.archDetail = CopyArmDetail(&detail->arm);
				break;
			case CS_ARCH_ARM64:
				result.archDetail = CopyArm64Detail(&detail->arm64);
				break;
			case CS_ARCH_MIPS:
				result.archDetail = CopyMipsDetail(&detail->mips);
				break;
			case CS_ARCH_PPC:
				result.archDetail = CopyPpcDetail(&detail->ppc);
				break;
			case CS_ARCH_SPARC:
				result.archDetail = CopySparcDetail(&detail->sparc);
				break;
			case CS_ARCH_SYSZ:
				result.archDetail = CopySyszDetail(&detail->sysz);
				break;
			case CS_ARCH_XCORE:
				result.archDetail = CopyXcoreDetail(&detail->xcore);
				break;
			case CS_ARCH_M68K:
				result.archDetail = CopyM68kDetail(&detail->m68k);
				break;
#ifdef CS_ARCH_RISCV
			case CS_ARCH_RISCV:
				result.archDetail = CopyRiscvDetail(&detail->riscv);
				break;
#endif
			default:
				result.archDetail = std::monostate{};
				break;
		}
	}

	// ========================================================================
	// Copy functions for each architecture (worker thread safe)
	// ========================================================================

	X86DetailResult CopyX86Detail(cs_x86* x86) {
		X86DetailResult result;

		memcpy(result.prefix, x86->prefix, 4);
		memcpy(result.opcode, x86->opcode, 4);
		result.rex = x86->rex;
		result.addr_size = x86->addr_size;
		result.modrm = x86->modrm;
		result.sib = x86->sib;
		result.disp = x86->disp;
		result.sib_index = x86->sib_index;
		result.sib_scale = x86->sib_scale;
		result.sib_base = x86->sib_base;
		result.xop_cc = x86->xop_cc;
		result.sse_cc = x86->sse_cc;
		result.avx_cc = x86->avx_cc;
		result.avx_sae = x86->avx_sae;
		result.avx_rm = x86->avx_rm;
		result.eflags = x86->eflags;

		result.operands.reserve(x86->op_count);
		for (uint8_t i = 0; i < x86->op_count; i++) {
			cs_x86_op* op = &x86->operands[i];
			X86OpResult opRes;
			opRes.type = op->type;
			opRes.size = op->size;
			opRes.access = op->access;
			opRes.avx_bcast = op->avx_bcast;
			opRes.avx_zero_opmask = op->avx_zero_opmask;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.segment = op->mem.segment;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.scale = op->mem.scale;
			opRes.mem.disp = op->mem.disp;
			result.operands.push_back(opRes);
		}

		return result;
	}

	ArmDetailResult CopyArmDetail(cs_arm* arm) {
		ArmDetailResult result;

		result.usermode = arm->usermode;
		result.vector_size = arm->vector_size;
		result.vector_data = arm->vector_data;
		result.cps_mode = arm->cps_mode;
		result.cps_flag = arm->cps_flag;
		result.cc = arm->cc;
		result.update_flags = arm->update_flags;
		result.writeback = arm->writeback;
		result.mem_barrier = arm->mem_barrier;

		result.operands.reserve(arm->op_count);
		for (uint8_t i = 0; i < arm->op_count; i++) {
			cs_arm_op* op = &arm->operands[i];
			ArmOpResult opRes;
			opRes.type = op->type;
			opRes.access = op->access;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.fp = op->fp;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.scale = op->mem.scale;
			opRes.mem.disp = op->mem.disp;
			opRes.mem.lshift = op->mem.lshift;
			opRes.shift_type = op->shift.type;
			opRes.shift_value = op->shift.value;
			opRes.vector_index = op->vector_index;
			opRes.subtracted = op->subtracted;
			result.operands.push_back(opRes);
		}

		return result;
	}

	Arm64DetailResult CopyArm64Detail(cs_arm64* arm64) {
		Arm64DetailResult result;

		result.cc = arm64->cc;
		result.update_flags = arm64->update_flags;
		result.writeback = arm64->writeback;

		result.operands.reserve(arm64->op_count);
		for (uint8_t i = 0; i < arm64->op_count; i++) {
			cs_arm64_op* op = &arm64->operands[i];
			Arm64OpResult opRes;
			opRes.type = op->type;
			opRes.access = op->access;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.fp = op->fp;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.disp = op->mem.disp;
			opRes.shift_type = op->shift.type;
			opRes.shift_value = op->shift.value;
			opRes.ext = op->ext;
			opRes.vas = op->vas;
			opRes.vector_index = op->vector_index;
			result.operands.push_back(opRes);
		}

		return result;
	}

	MipsDetailResult CopyMipsDetail(cs_mips* mips) {
		MipsDetailResult result;

		result.operands.reserve(mips->op_count);
		for (uint8_t i = 0; i < mips->op_count; i++) {
			cs_mips_op* op = &mips->operands[i];
			MipsOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.disp = op->mem.disp;
			result.operands.push_back(opRes);
		}

		return result;
	}

	PpcDetailResult CopyPpcDetail(cs_ppc* ppc) {
		PpcDetailResult result;

		result.bc = ppc->bc;
		result.bh = ppc->bh;
		result.update_cr0 = ppc->update_cr0;

		result.operands.reserve(ppc->op_count);
		for (uint8_t i = 0; i < ppc->op_count; i++) {
			cs_ppc_op* op = &ppc->operands[i];
			PpcOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.disp = op->mem.disp;
			opRes.crx.scale = op->crx.scale;
			opRes.crx.reg = op->crx.reg;
			opRes.crx.cond = op->crx.cond;
			result.operands.push_back(opRes);
		}

		return result;
	}

	SparcDetailResult CopySparcDetail(cs_sparc* sparc) {
		SparcDetailResult result;

		result.cc = sparc->cc;
		result.hint = sparc->hint;

		result.operands.reserve(sparc->op_count);
		for (uint8_t i = 0; i < sparc->op_count; i++) {
			cs_sparc_op* op = &sparc->operands[i];
			SparcOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.disp = op->mem.disp;
			result.operands.push_back(opRes);
		}

		return result;
	}

	SyszDetailResult CopySyszDetail(cs_sysz* sysz) {
		SyszDetailResult result;

		result.cc = sysz->cc;

		result.operands.reserve(sysz->op_count);
		for (uint8_t i = 0; i < sysz->op_count; i++) {
			cs_sysz_op* op = &sysz->operands[i];
			SyszOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.length = op->mem.length;
			opRes.mem.disp = op->mem.disp;
			result.operands.push_back(opRes);
		}

		return result;
	}

	XcoreDetailResult CopyXcoreDetail(cs_xcore* xcore) {
		XcoreDetailResult result;

		result.operands.reserve(xcore->op_count);
		for (uint8_t i = 0; i < xcore->op_count; i++) {
			cs_xcore_op* op = &xcore->operands[i];
			XcoreOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.index = op->mem.index;
			opRes.mem.disp = op->mem.disp;
			opRes.mem.direct = op->mem.direct;
			result.operands.push_back(opRes);
		}

		return result;
	}

	M68kDetailResult CopyM68kDetail(cs_m68k* m68k) {
		M68kDetailResult result;

		result.op_size_type = m68k->op_size.type;

		result.operands.reserve(m68k->op_count);
		for (uint8_t i = 0; i < m68k->op_count; i++) {
			cs_m68k_op* op = &m68k->operands[i];
			M68kOpResult opRes;
			opRes.type = op->type;
			opRes.address_mode = op->address_mode;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.dimm = op->dimm;
			opRes.simm = op->simm;
			opRes.register_bits = op->register_bits;
			opRes.reg_pair.reg_0 = op->reg_pair.reg_0;
			opRes.reg_pair.reg_1 = op->reg_pair.reg_1;
			opRes.mem.base_reg = op->mem.base_reg;
			opRes.mem.index_reg = op->mem.index_reg;
			opRes.mem.in_base_reg = op->mem.in_base_reg;
			opRes.mem.in_disp = op->mem.in_disp;
			opRes.mem.out_disp = op->mem.out_disp;
			opRes.mem.disp = op->mem.disp;
			opRes.mem.scale = op->mem.scale;
			opRes.mem.bitfield = op->mem.bitfield;
			opRes.mem.width = op->mem.width;
			opRes.mem.offset = op->mem.offset;
			opRes.mem.index_size = op->mem.index_size;
			result.operands.push_back(opRes);
		}

		return result;
	}

#ifdef CS_ARCH_RISCV
	RiscvDetailResult CopyRiscvDetail(cs_riscv* riscv) {
		RiscvDetailResult result;

		result.operands.reserve(riscv->op_count);
		for (uint8_t i = 0; i < riscv->op_count; i++) {
			cs_riscv_op* op = &riscv->operands[i];
			RiscvOpResult opRes;
			opRes.type = op->type;
			opRes.reg = op->reg;
			opRes.imm = op->imm;
			opRes.mem.base = op->mem.base;
			opRes.mem.disp = op->mem.disp;
			result.operands.push_back(opRes);
		}

		return result;
	}
#endif

	// ========================================================================
	// Convert functions - main thread (can use N-API)
	// ========================================================================

	/**
	 * Convert our intermediate structure to a JavaScript object
	 */
	Napi::Object ResultToObject(Napi::Env env, const DisasmResult& result) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("id", Napi::Number::New(env, result.id));
		obj.Set("address", Napi::Number::New(env, static_cast<double>(result.address)));
		obj.Set("size", Napi::Number::New(env, result.size));
		obj.Set("mnemonic", Napi::String::New(env, result.mnemonic));
		obj.Set("opStr", Napi::String::New(env, result.op_str));

		// Copy bytes
		Napi::Buffer<uint8_t> bytes = Napi::Buffer<uint8_t>::Copy(
			env, result.bytes.data(), result.bytes.size()
		);
		obj.Set("bytes", bytes);

		// Add detail if available
		if (result.hasDetail) {
			Napi::Object detail = Napi::Object::New(env);

			// Registers read
			Napi::Array regsRead = Napi::Array::New(env, result.regsRead.size());
			for (size_t j = 0; j < result.regsRead.size(); j++) {
				regsRead.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.regsRead[j]));
			}
			detail.Set("regsRead", regsRead);

			// Registers written
			Napi::Array regsWrite = Napi::Array::New(env, result.regsWrite.size());
			for (size_t j = 0; j < result.regsWrite.size(); j++) {
				regsWrite.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.regsWrite[j]));
			}
			detail.Set("regsWrite", regsWrite);

			// Groups
			Napi::Array groups = Napi::Array::New(env, result.groups.size());
			for (size_t j = 0; j < result.groups.size(); j++) {
				groups.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.groups[j]));
			}
			detail.Set("groups", groups);

			// Architecture-specific detail
			std::visit([&](auto&& arg) {
				using T = std::decay_t<decltype(arg)>;
				if constexpr (std::is_same_v<T, X86DetailResult>) {
					detail.Set("x86", X86DetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, ArmDetailResult>) {
					detail.Set("arm", ArmDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, Arm64DetailResult>) {
					detail.Set("arm64", Arm64DetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, MipsDetailResult>) {
					detail.Set("mips", MipsDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, PpcDetailResult>) {
					detail.Set("ppc", PpcDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, SparcDetailResult>) {
					detail.Set("sparc", SparcDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, SyszDetailResult>) {
					detail.Set("sysz", SyszDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, XcoreDetailResult>) {
					detail.Set("xcore", XcoreDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, M68kDetailResult>) {
					detail.Set("m68k", M68kDetailToObject(env, arg));
				} else if constexpr (std::is_same_v<T, RiscvDetailResult>) {
					detail.Set("riscv", RiscvDetailToObject(env, arg));
				}
				// std::monostate - no arch detail
			}, result.archDetail);

			obj.Set("detail", detail);
		}

		return obj;
	}

	// x86 detail to JS object
	Napi::Object X86DetailToObject(Napi::Env env, const X86DetailResult& x86) {
		Napi::Object obj = Napi::Object::New(env);

		Napi::Array prefix = Napi::Array::New(env, 4);
		for (int i = 0; i < 4; i++) {
			prefix.Set(i, Napi::Number::New(env, x86.prefix[i]));
		}
		obj.Set("prefix", prefix);

		Napi::Array opcode = Napi::Array::New(env, 4);
		for (int i = 0; i < 4; i++) {
			opcode.Set(i, Napi::Number::New(env, x86.opcode[i]));
		}
		obj.Set("opcode", opcode);

		obj.Set("rexPrefix", Napi::Number::New(env, x86.rex));
		obj.Set("addrSize", Napi::Number::New(env, x86.addr_size));
		obj.Set("modRM", Napi::Number::New(env, x86.modrm));
		obj.Set("sib", Napi::Number::New(env, x86.sib));
		obj.Set("disp", Napi::Number::New(env, static_cast<double>(x86.disp)));
		obj.Set("sibIndex", Napi::Number::New(env, x86.sib_index));
		obj.Set("sibScale", Napi::Number::New(env, x86.sib_scale));
		obj.Set("sibBase", Napi::Number::New(env, x86.sib_base));
		obj.Set("xopCC", Napi::Number::New(env, x86.xop_cc));
		obj.Set("sseCC", Napi::Number::New(env, x86.sse_cc));
		obj.Set("avxCC", Napi::Number::New(env, x86.avx_cc));
		obj.Set("avxSAE", Napi::Boolean::New(env, x86.avx_sae));
		obj.Set("avxRM", Napi::Number::New(env, x86.avx_rm));
		obj.Set("eflags", Napi::Number::New(env, static_cast<double>(x86.eflags)));

		Napi::Array operands = Napi::Array::New(env, x86.operands.size());
		for (size_t i = 0; i < x86.operands.size(); i++) {
			const X86OpResult& op = x86.operands[i];
			Napi::Object opObj = Napi::Object::New(env);

			opObj.Set("type", Napi::Number::New(env, op.type));
			opObj.Set("size", Napi::Number::New(env, op.size));
			opObj.Set("access", Napi::Number::New(env, op.access));
			opObj.Set("avxBcast", Napi::Number::New(env, op.avx_bcast));
			opObj.Set("avxZeroOpmask", Napi::Boolean::New(env, op.avx_zero_opmask));

			switch (op.type) {
				case X86_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case X86_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case X86_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("segment", Napi::Number::New(env, op.mem.segment));
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("scale", Napi::Number::New(env, op.mem.scale));
						mem.Set("disp", Napi::Number::New(env, static_cast<double>(op.mem.disp)));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}

			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// ARM detail to JS object
	Napi::Object ArmDetailToObject(Napi::Env env, const ArmDetailResult& arm) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("usermode", Napi::Boolean::New(env, arm.usermode));
		obj.Set("vectorSize", Napi::Number::New(env, arm.vector_size));
		obj.Set("vectorData", Napi::Number::New(env, arm.vector_data));
		obj.Set("cpsMode", Napi::Number::New(env, arm.cps_mode));
		obj.Set("cpsFlag", Napi::Number::New(env, arm.cps_flag));
		obj.Set("cc", Napi::Number::New(env, arm.cc));
		obj.Set("updateFlags", Napi::Boolean::New(env, arm.update_flags));
		obj.Set("writeback", Napi::Boolean::New(env, arm.writeback));
		obj.Set("memBarrier", Napi::Number::New(env, arm.mem_barrier));

		Napi::Array operands = Napi::Array::New(env, arm.operands.size());
		for (size_t i = 0; i < arm.operands.size(); i++) {
			const ArmOpResult& op = arm.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));
			opObj.Set("access", Napi::Number::New(env, op.access));

			switch (op.type) {
				case ARM_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case ARM_OP_IMM:
				case ARM_OP_PIMM:
				case ARM_OP_CIMM:
					opObj.Set("imm", Napi::Number::New(env, op.imm));
					break;
				case ARM_OP_FP:
					opObj.Set("fp", Napi::Number::New(env, op.fp));
					break;
				case ARM_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("scale", Napi::Number::New(env, op.mem.scale));
						mem.Set("disp", Napi::Number::New(env, op.mem.disp));
						mem.Set("lshift", Napi::Number::New(env, op.mem.lshift));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}

			if (op.shift_type != 0) {
				Napi::Object shift = Napi::Object::New(env);
				shift.Set("type", Napi::Number::New(env, op.shift_type));
				shift.Set("value", Napi::Number::New(env, op.shift_value));
				opObj.Set("shift", shift);
			}

			opObj.Set("vectorIndex", Napi::Number::New(env, op.vector_index));
			opObj.Set("subtracted", Napi::Boolean::New(env, op.subtracted));

			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// ARM64 detail to JS object
	Napi::Object Arm64DetailToObject(Napi::Env env, const Arm64DetailResult& arm64) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("cc", Napi::Number::New(env, arm64.cc));
		obj.Set("updateFlags", Napi::Boolean::New(env, arm64.update_flags));
		obj.Set("writeback", Napi::Boolean::New(env, arm64.writeback));

		Napi::Array operands = Napi::Array::New(env, arm64.operands.size());
		for (size_t i = 0; i < arm64.operands.size(); i++) {
			const Arm64OpResult& op = arm64.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));
			opObj.Set("access", Napi::Number::New(env, op.access));

			switch (op.type) {
				case ARM64_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case ARM64_OP_IMM:
				case ARM64_OP_CIMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case ARM64_OP_FP:
					opObj.Set("fp", Napi::Number::New(env, op.fp));
					break;
				case ARM64_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("disp", Napi::Number::New(env, op.mem.disp));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}

			if (op.shift_type != 0) {
				Napi::Object shift = Napi::Object::New(env);
				shift.Set("type", Napi::Number::New(env, op.shift_type));
				shift.Set("value", Napi::Number::New(env, op.shift_value));
				opObj.Set("shift", shift);
			}

			opObj.Set("ext", Napi::Number::New(env, op.ext));
			opObj.Set("vas", Napi::Number::New(env, op.vas));
			opObj.Set("vectorIndex", Napi::Number::New(env, op.vector_index));

			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// MIPS detail to JS object
	Napi::Object MipsDetailToObject(Napi::Env env, const MipsDetailResult& mips) {
		Napi::Object obj = Napi::Object::New(env);

		Napi::Array operands = Napi::Array::New(env, mips.operands.size());
		for (size_t i = 0; i < mips.operands.size(); i++) {
			const MipsOpResult& op = mips.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

			switch (op.type) {
				case MIPS_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case MIPS_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case MIPS_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("disp", Napi::Number::New(env, static_cast<double>(op.mem.disp)));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// PPC detail to JS object
	Napi::Object PpcDetailToObject(Napi::Env env, const PpcDetailResult& ppc) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("bc", Napi::Number::New(env, ppc.bc));
		obj.Set("bh", Napi::Number::New(env, ppc.bh));
		obj.Set("updateCr0", Napi::Boolean::New(env, ppc.update_cr0));

		Napi::Array operands = Napi::Array::New(env, ppc.operands.size());
		for (size_t i = 0; i < ppc.operands.size(); i++) {
			const PpcOpResult& op = ppc.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

			switch (op.type) {
				case PPC_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case PPC_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case PPC_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("disp", Napi::Number::New(env, static_cast<double>(op.mem.disp)));
						opObj.Set("mem", mem);
					}
					break;
				case PPC_OP_CRX:
					{
						Napi::Object crx = Napi::Object::New(env);
						crx.Set("scale", Napi::Number::New(env, op.crx.scale));
						crx.Set("reg", Napi::Number::New(env, op.crx.reg));
						crx.Set("cond", Napi::Number::New(env, op.crx.cond));
						opObj.Set("crx", crx);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// SPARC detail to JS object
	Napi::Object SparcDetailToObject(Napi::Env env, const SparcDetailResult& sparc) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("cc", Napi::Number::New(env, sparc.cc));
		obj.Set("hint", Napi::Number::New(env, sparc.hint));

		Napi::Array operands = Napi::Array::New(env, sparc.operands.size());
		for (size_t i = 0; i < sparc.operands.size(); i++) {
			const SparcOpResult& op = sparc.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

			switch (op.type) {
				case SPARC_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case SPARC_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case SPARC_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("disp", Napi::Number::New(env, op.mem.disp));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// SystemZ detail to JS object
	Napi::Object SyszDetailToObject(Napi::Env env, const SyszDetailResult& sysz) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("cc", Napi::Number::New(env, sysz.cc));

		Napi::Array operands = Napi::Array::New(env, sysz.operands.size());
		for (size_t i = 0; i < sysz.operands.size(); i++) {
			const SyszOpResult& op = sysz.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

			switch (op.type) {
				case SYSZ_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case SYSZ_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case SYSZ_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("length", Napi::Number::New(env, static_cast<double>(op.mem.length)));
						mem.Set("disp", Napi::Number::New(env, static_cast<double>(op.mem.disp)));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// XCore detail to JS object
	Napi::Object XcoreDetailToObject(Napi::Env env, const XcoreDetailResult& xcore) {
		Napi::Object obj = Napi::Object::New(env);

		Napi::Array operands = Napi::Array::New(env, xcore.operands.size());
		for (size_t i = 0; i < xcore.operands.size(); i++) {
			const XcoreOpResult& op = xcore.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

			switch (op.type) {
				case XCORE_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case XCORE_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, op.imm));
					break;
				case XCORE_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("index", Napi::Number::New(env, op.mem.index));
						mem.Set("disp", Napi::Number::New(env, op.mem.disp));
						mem.Set("direct", Napi::Number::New(env, op.mem.direct));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// M68K detail to JS object
	Napi::Object M68kDetailToObject(Napi::Env env, const M68kDetailResult& m68k) {
		Napi::Object obj = Napi::Object::New(env);

		obj.Set("opSize", Napi::Number::New(env, m68k.op_size_type));

		Napi::Array operands = Napi::Array::New(env, m68k.operands.size());
		for (size_t i = 0; i < m68k.operands.size(); i++) {
			const M68kOpResult& op = m68k.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));
			opObj.Set("addressMode", Napi::Number::New(env, op.address_mode));

			switch (op.type) {
				case M68K_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case M68K_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case M68K_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("baseReg", Napi::Number::New(env, op.mem.base_reg));
						mem.Set("indexReg", Napi::Number::New(env, op.mem.index_reg));
						mem.Set("inBaseReg", Napi::Number::New(env, op.mem.in_base_reg));
						mem.Set("inDisp", Napi::Number::New(env, op.mem.in_disp));
						mem.Set("outDisp", Napi::Number::New(env, op.mem.out_disp));
						mem.Set("disp", Napi::Number::New(env, op.mem.disp));
						mem.Set("scale", Napi::Number::New(env, op.mem.scale));
						mem.Set("bitfield", Napi::Number::New(env, op.mem.bitfield));
						mem.Set("width", Napi::Number::New(env, op.mem.width));
						mem.Set("offset", Napi::Number::New(env, op.mem.offset));
						mem.Set("indexSize", Napi::Number::New(env, op.mem.index_size));
						opObj.Set("mem", mem);
					}
					break;
				case M68K_OP_FP_DOUBLE:
					opObj.Set("fpDouble", Napi::Number::New(env, op.dimm));
					break;
				case M68K_OP_FP_SINGLE:
					opObj.Set("fpSingle", Napi::Number::New(env, op.simm));
					break;
				case M68K_OP_REG_BITS:
					opObj.Set("regBits", Napi::Number::New(env, op.register_bits));
					break;
				case M68K_OP_REG_PAIR:
					{
						Napi::Object regPair = Napi::Object::New(env);
						regPair.Set("reg0", Napi::Number::New(env, op.reg_pair.reg_0));
						regPair.Set("reg1", Napi::Number::New(env, op.reg_pair.reg_1));
						opObj.Set("regPair", regPair);
					}
					break;
				default:
					break;
			}
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}

	// RISC-V detail to JS object
	Napi::Object RiscvDetailToObject(Napi::Env env, const RiscvDetailResult& riscv) {
		Napi::Object obj = Napi::Object::New(env);

		Napi::Array operands = Napi::Array::New(env, riscv.operands.size());
		for (size_t i = 0; i < riscv.operands.size(); i++) {
			const RiscvOpResult& op = riscv.operands[i];
			Napi::Object opObj = Napi::Object::New(env);
			opObj.Set("type", Napi::Number::New(env, op.type));

#ifdef CS_ARCH_RISCV
			switch (op.type) {
				case RISCV_OP_REG:
					opObj.Set("reg", Napi::Number::New(env, op.reg));
					break;
				case RISCV_OP_IMM:
					opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op.imm)));
					break;
				case RISCV_OP_MEM:
					{
						Napi::Object mem = Napi::Object::New(env);
						mem.Set("base", Napi::Number::New(env, op.mem.base));
						mem.Set("disp", Napi::Number::New(env, static_cast<double>(op.mem.disp)));
						opObj.Set("mem", mem);
					}
					break;
				default:
					break;
			}
#endif
			operands.Set(static_cast<uint32_t>(i), opObj);
		}
		obj.Set("operands", operands);

		return obj;
	}
};

#endif // DISASM_ASYNC_WORKER_H
