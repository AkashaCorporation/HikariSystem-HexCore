/*
 * HexCore Capstone - Native Node.js Bindings
 * Capstone Wrapper Implementation
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "capstone_wrapper.h"
#include <cstring>

// Static constructor reference
Napi::FunctionReference CapstoneWrapper::constructor;

/**
 * Initialize the class and export it
 */
Napi::Object CapstoneWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "Capstone", {
        InstanceMethod("disasm", &CapstoneWrapper::Disasm),
        InstanceMethod("setOption", &CapstoneWrapper::SetOption),
        InstanceMethod("close", &CapstoneWrapper::Close),
        InstanceMethod("regName", &CapstoneWrapper::RegName),
        InstanceMethod("insnName", &CapstoneWrapper::InsnName),
        InstanceMethod("groupName", &CapstoneWrapper::GroupName),
        InstanceMethod("isOpen", &CapstoneWrapper::IsOpen),
        InstanceMethod("getError", &CapstoneWrapper::GetError),
        InstanceMethod("strError", &CapstoneWrapper::StrError),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    exports.Set("Capstone", func);
    return exports;
}

/**
 * Constructor - opens Capstone handle
 */
CapstoneWrapper::CapstoneWrapper(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<CapstoneWrapper>(info), handle_(0), opened_(false) {

    Napi::Env env = info.Env();

    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected 2 arguments: arch and mode")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsNumber() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Arguments must be numbers")
            .ThrowAsJavaScriptException();
        return;
    }

    arch_ = static_cast<cs_arch>(info[0].As<Napi::Number>().Int32Value());
    mode_ = static_cast<cs_mode>(info[1].As<Napi::Number>().Int32Value());

    cs_err err = cs_open(arch_, mode_, &handle_);
    if (err != CS_ERR_OK) {
        Napi::Error::New(env, std::string("Failed to open Capstone: ") + cs_strerror(err))
            .ThrowAsJavaScriptException();
        return;
    }

    opened_ = true;
}

/**
 * Destructor
 */
CapstoneWrapper::~CapstoneWrapper() {
    if (opened_ && handle_ != 0) {
        cs_close(&handle_);
        opened_ = false;
    }
}

/**
 * Disassemble a buffer
 */
Napi::Value CapstoneWrapper::Disasm(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Capstone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected at least 2 arguments: buffer and address")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    // Get the code buffer
    Napi::Buffer<uint8_t> codeBuffer;
    const uint8_t* code;
    size_t codeSize;

    if (info[0].IsBuffer()) {
        codeBuffer = info[0].As<Napi::Buffer<uint8_t>>();
        code = codeBuffer.Data();
        codeSize = codeBuffer.Length();
    } else if (info[0].IsTypedArray()) {
        Napi::TypedArray typedArray = info[0].As<Napi::TypedArray>();
        code = static_cast<const uint8_t*>(typedArray.ArrayBuffer().Data()) + typedArray.ByteOffset();
        codeSize = typedArray.ByteLength();
    } else {
        Napi::TypeError::New(env, "First argument must be a Buffer or Uint8Array")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    // Get base address
    if (!info[1].IsNumber()) {
        Napi::TypeError::New(env, "Second argument (address) must be a number")
            .ThrowAsJavaScriptException();
        return env.Null();
    }
    uint64_t address = static_cast<uint64_t>(info[1].As<Napi::Number>().Int64Value());

    // Get max instructions (optional)
    size_t count = 0; // 0 means disassemble all
    if (info.Length() > 2 && info[2].IsNumber()) {
        count = static_cast<size_t>(info[2].As<Napi::Number>().Uint32Value());
    }

    // Disassemble
    cs_insn* insn;
    size_t numInsns = cs_disasm(handle_, code, codeSize, address, count, &insn);

    // Convert to JavaScript array
    Napi::Array result = Napi::Array::New(env, numInsns);

    for (size_t i = 0; i < numInsns; i++) {
        result.Set(static_cast<uint32_t>(i), InstructionToObject(env, &insn[i]));
    }

    // Free Capstone-allocated memory
    if (numInsns > 0) {
        cs_free(insn, numInsns);
    }

    return result;
}

/**
 * Convert a single instruction to a JavaScript object
 */
Napi::Object CapstoneWrapper::InstructionToObject(Napi::Env env, cs_insn* insn) {
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("id", Napi::Number::New(env, insn->id));
    obj.Set("address", Napi::Number::New(env, static_cast<double>(insn->address)));
    obj.Set("size", Napi::Number::New(env, insn->size));
    obj.Set("mnemonic", Napi::String::New(env, insn->mnemonic));
    obj.Set("opStr", Napi::String::New(env, insn->op_str));

    // Copy bytes
    Napi::Buffer<uint8_t> bytes = Napi::Buffer<uint8_t>::Copy(env, insn->bytes, insn->size);
    obj.Set("bytes", bytes);

    // Add detail if available
    if (insn->detail != nullptr) {
        obj.Set("detail", DetailToObject(env, insn));
    }

    return obj;
}

/**
 * Convert instruction detail to JavaScript object
 */
Napi::Object CapstoneWrapper::DetailToObject(Napi::Env env, cs_insn* insn) {
    Napi::Object obj = Napi::Object::New(env);
    cs_detail* detail = insn->detail;

    // Registers read
    Napi::Array regsRead = Napi::Array::New(env, detail->regs_read_count);
    for (uint8_t i = 0; i < detail->regs_read_count; i++) {
        regsRead.Set(i, Napi::Number::New(env, detail->regs_read[i]));
    }
    obj.Set("regsRead", regsRead);

    // Registers written
    Napi::Array regsWrite = Napi::Array::New(env, detail->regs_write_count);
    for (uint8_t i = 0; i < detail->regs_write_count; i++) {
        regsWrite.Set(i, Napi::Number::New(env, detail->regs_write[i]));
    }
    obj.Set("regsWrite", regsWrite);

    // Groups
    Napi::Array groups = Napi::Array::New(env, detail->groups_count);
    for (uint8_t i = 0; i < detail->groups_count; i++) {
        groups.Set(i, Napi::Number::New(env, detail->groups[i]));
    }
    obj.Set("groups", groups);

    // Architecture-specific detail
    switch (arch_) {
        case CS_ARCH_X86:
            obj.Set("x86", X86DetailToObject(env, &detail->x86));
            break;
        case CS_ARCH_ARM:
            obj.Set("arm", ArmDetailToObject(env, &detail->arm));
            break;
        case CS_ARCH_ARM64:
            obj.Set("arm64", Arm64DetailToObject(env, &detail->arm64));
            break;
        case CS_ARCH_MIPS:
            obj.Set("mips", MipsDetailToObject(env, &detail->mips));
            break;
        default:
            break;
    }

    return obj;
}

/**
 * Convert x86 detail to JavaScript object
 */
Napi::Object CapstoneWrapper::X86DetailToObject(Napi::Env env, cs_x86* x86) {
    Napi::Object obj = Napi::Object::New(env);

    // Prefix bytes
    Napi::Array prefix = Napi::Array::New(env, 4);
    for (int i = 0; i < 4; i++) {
        prefix.Set(i, Napi::Number::New(env, x86->prefix[i]));
    }
    obj.Set("prefix", prefix);

    // Opcode
    Napi::Array opcode = Napi::Array::New(env, 4);
    for (int i = 0; i < 4; i++) {
        opcode.Set(i, Napi::Number::New(env, x86->opcode[i]));
    }
    obj.Set("opcode", opcode);

    obj.Set("rexPrefix", Napi::Number::New(env, x86->rex));
    obj.Set("addrSize", Napi::Number::New(env, x86->addr_size));
    obj.Set("modRM", Napi::Number::New(env, x86->modrm));
    obj.Set("sib", Napi::Number::New(env, x86->sib));
    obj.Set("disp", Napi::Number::New(env, static_cast<double>(x86->disp)));
    obj.Set("sibIndex", Napi::Number::New(env, x86->sib_index));
    obj.Set("sibScale", Napi::Number::New(env, x86->sib_scale));
    obj.Set("sibBase", Napi::Number::New(env, x86->sib_base));
    obj.Set("xopCC", Napi::Number::New(env, x86->xop_cc));
    obj.Set("sseCC", Napi::Number::New(env, x86->sse_cc));
    obj.Set("avxCC", Napi::Number::New(env, x86->avx_cc));
    obj.Set("avxSAE", Napi::Boolean::New(env, x86->avx_sae));
    obj.Set("avxRM", Napi::Number::New(env, x86->avx_rm));
    obj.Set("eflags", Napi::Number::New(env, static_cast<double>(x86->eflags)));

    // Operands
    Napi::Array operands = Napi::Array::New(env, x86->op_count);
    for (uint8_t i = 0; i < x86->op_count; i++) {
        cs_x86_op* op = &x86->operands[i];
        Napi::Object opObj = Napi::Object::New(env);

        opObj.Set("type", Napi::Number::New(env, op->type));
        opObj.Set("size", Napi::Number::New(env, op->size));
        opObj.Set("access", Napi::Number::New(env, op->access));
        opObj.Set("avxBcast", Napi::Number::New(env, op->avx_bcast));
        opObj.Set("avxZeroOpmask", Napi::Boolean::New(env, op->avx_zero_opmask));

        switch (op->type) {
            case X86_OP_REG:
                opObj.Set("reg", Napi::Number::New(env, op->reg));
                break;
            case X86_OP_IMM:
                opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op->imm)));
                break;
            case X86_OP_MEM:
                {
                    Napi::Object mem = Napi::Object::New(env);
                    mem.Set("segment", Napi::Number::New(env, op->mem.segment));
                    mem.Set("base", Napi::Number::New(env, op->mem.base));
                    mem.Set("index", Napi::Number::New(env, op->mem.index));
                    mem.Set("scale", Napi::Number::New(env, op->mem.scale));
                    mem.Set("disp", Napi::Number::New(env, static_cast<double>(op->mem.disp)));
                    opObj.Set("mem", mem);
                }
                break;
            default:
                break;
        }

        operands.Set(i, opObj);
    }
    obj.Set("operands", operands);

    return obj;
}

/**
 * Convert ARM detail to JavaScript object
 */
Napi::Object CapstoneWrapper::ArmDetailToObject(Napi::Env env, cs_arm* arm) {
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("usermode", Napi::Boolean::New(env, arm->usermode));
    obj.Set("vectorSize", Napi::Number::New(env, arm->vector_size));
    obj.Set("vectorData", Napi::Number::New(env, arm->vector_data));
    obj.Set("cpsMode", Napi::Number::New(env, arm->cps_mode));
    obj.Set("cpsFlag", Napi::Number::New(env, arm->cps_flag));
    obj.Set("cc", Napi::Number::New(env, arm->cc));
    obj.Set("updateFlags", Napi::Boolean::New(env, arm->update_flags));
    obj.Set("writeback", Napi::Boolean::New(env, arm->writeback));
    obj.Set("memBarrier", Napi::Number::New(env, arm->mem_barrier));

    // Operands (simplified)
    Napi::Array operands = Napi::Array::New(env, arm->op_count);
    for (uint8_t i = 0; i < arm->op_count; i++) {
        cs_arm_op* op = &arm->operands[i];
        Napi::Object opObj = Napi::Object::New(env);
        opObj.Set("type", Napi::Number::New(env, op->type));
        opObj.Set("access", Napi::Number::New(env, op->access));

        switch (op->type) {
            case ARM_OP_REG:
                opObj.Set("reg", Napi::Number::New(env, op->reg));
                break;
            case ARM_OP_IMM:
            case ARM_OP_PIMM:
            case ARM_OP_CIMM:
                opObj.Set("imm", Napi::Number::New(env, op->imm));
                break;
            case ARM_OP_FP:
                opObj.Set("fp", Napi::Number::New(env, op->fp));
                break;
            default:
                break;
        }

        operands.Set(i, opObj);
    }
    obj.Set("operands", operands);

    return obj;
}

/**
 * Convert ARM64 detail to JavaScript object
 */
Napi::Object CapstoneWrapper::Arm64DetailToObject(Napi::Env env, cs_arm64* arm64) {
    Napi::Object obj = Napi::Object::New(env);

    obj.Set("cc", Napi::Number::New(env, arm64->cc));
    obj.Set("updateFlags", Napi::Boolean::New(env, arm64->update_flags));
    obj.Set("writeback", Napi::Boolean::New(env, arm64->writeback));

    // Operands (simplified)
    Napi::Array operands = Napi::Array::New(env, arm64->op_count);
    for (uint8_t i = 0; i < arm64->op_count; i++) {
        cs_arm64_op* op = &arm64->operands[i];
        Napi::Object opObj = Napi::Object::New(env);
        opObj.Set("type", Napi::Number::New(env, op->type));
        opObj.Set("access", Napi::Number::New(env, op->access));

        switch (op->type) {
            case ARM64_OP_REG:
                opObj.Set("reg", Napi::Number::New(env, op->reg));
                break;
            case ARM64_OP_IMM:
            case ARM64_OP_CIMM:
                opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op->imm)));
                break;
            case ARM64_OP_FP:
                opObj.Set("fp", Napi::Number::New(env, op->fp));
                break;
            default:
                break;
        }

        operands.Set(i, opObj);
    }
    obj.Set("operands", operands);

    return obj;
}

/**
 * Convert MIPS detail to JavaScript object
 */
Napi::Object CapstoneWrapper::MipsDetailToObject(Napi::Env env, cs_mips* mips) {
    Napi::Object obj = Napi::Object::New(env);

    // Operands
    Napi::Array operands = Napi::Array::New(env, mips->op_count);
    for (uint8_t i = 0; i < mips->op_count; i++) {
        cs_mips_op* op = &mips->operands[i];
        Napi::Object opObj = Napi::Object::New(env);
        opObj.Set("type", Napi::Number::New(env, op->type));

        switch (op->type) {
            case MIPS_OP_REG:
                opObj.Set("reg", Napi::Number::New(env, op->reg));
                break;
            case MIPS_OP_IMM:
                opObj.Set("imm", Napi::Number::New(env, static_cast<double>(op->imm)));
                break;
            case MIPS_OP_MEM:
                {
                    Napi::Object mem = Napi::Object::New(env);
                    mem.Set("base", Napi::Number::New(env, op->mem.base));
                    mem.Set("disp", Napi::Number::New(env, static_cast<double>(op->mem.disp)));
                    opObj.Set("mem", mem);
                }
                break;
            default:
                break;
        }

        operands.Set(i, opObj);
    }
    obj.Set("operands", operands);

    return obj;
}

/**
 * Set Capstone option
 */
Napi::Value CapstoneWrapper::SetOption(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Capstone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected 2 number arguments: type and value")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    cs_opt_type type = static_cast<cs_opt_type>(info[0].As<Napi::Number>().Int32Value());
    size_t value = static_cast<size_t>(info[1].As<Napi::Number>().Int64Value());

    cs_err err = cs_option(handle_, type, value);
    if (err != CS_ERR_OK) {
        Napi::Error::New(env, std::string("Failed to set option: ") + cs_strerror(err))
            .ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    return Napi::Boolean::New(env, true);
}

/**
 * Close the Capstone handle
 */
Napi::Value CapstoneWrapper::Close(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (opened_ && handle_ != 0) {
        cs_close(&handle_);
        opened_ = false;
    }

    return env.Undefined();
}

/**
 * Get register name
 */
Napi::Value CapstoneWrapper::RegName(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Capstone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected register ID as number")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned int regId = info[0].As<Napi::Number>().Uint32Value();
    const char* name = cs_reg_name(handle_, regId);

    if (name == nullptr) {
        return env.Null();
    }

    return Napi::String::New(env, name);
}

/**
 * Get instruction name
 */
Napi::Value CapstoneWrapper::InsnName(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Capstone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected instruction ID as number")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned int insnId = info[0].As<Napi::Number>().Uint32Value();
    const char* name = cs_insn_name(handle_, insnId);

    if (name == nullptr) {
        return env.Null();
    }

    return Napi::String::New(env, name);
}

/**
 * Get group name
 */
Napi::Value CapstoneWrapper::GroupName(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Capstone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected group ID as number")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    unsigned int groupId = info[0].As<Napi::Number>().Uint32Value();
    const char* name = cs_group_name(handle_, groupId);

    if (name == nullptr) {
        return env.Null();
    }

    return Napi::String::New(env, name);
}

/**
 * Check if handle is open
 */
Napi::Value CapstoneWrapper::IsOpen(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), opened_);
}

/**
 * Get last error code
 */
Napi::Value CapstoneWrapper::GetError(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        return Napi::Number::New(env, CS_ERR_HANDLE);
    }

    return Napi::Number::New(env, cs_errno(handle_));
}

/**
 * Get error message string
 */
Napi::Value CapstoneWrapper::StrError(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    cs_err err;
    if (info.Length() > 0 && info[0].IsNumber()) {
        err = static_cast<cs_err>(info[0].As<Napi::Number>().Int32Value());
    } else if (opened_) {
        err = cs_errno(handle_);
    } else {
        err = CS_ERR_HANDLE;
    }

    return Napi::String::New(env, cs_strerror(err));
}
