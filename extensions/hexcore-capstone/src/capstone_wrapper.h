/*
 * HexCore Capstone - Native Node.js Bindings
 * Capstone Wrapper Header
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef CAPSTONE_WRAPPER_H
#define CAPSTONE_WRAPPER_H

#include <napi.h>
#include <capstone/capstone.h>
#include <vector>
#include <string>
#include <utility>

// Forward declaration
class DisasmAsyncWorker;

/**
 * CapstoneWrapper - N-API class wrapping Capstone disassembler
 *
 * JavaScript usage:
 *   const cs = new Capstone(ARCH.X86, MODE.MODE_64);
 *   const instructions = cs.disasm(buffer, 0x1000);
 *   const instructionsAsync = await cs.disasmAsync(buffer, 0x1000);
 *   cs.close();
 */
class CapstoneWrapper : public Napi::ObjectWrap<CapstoneWrapper> {
public:
    /**
     * Initialize the class in the module exports
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * Constructor called from JavaScript
     * @param info Contains arch and mode arguments
     */
    CapstoneWrapper(const Napi::CallbackInfo& info);

    /**
     * Destructor - ensures handle is closed
     */
    ~CapstoneWrapper();

    // Accessors for async worker
    csh GetHandle() const { return handle_; }
    cs_arch GetArch() const { return arch_; }
    bool IsOpened() const { return opened_; }

private:
    // Capstone handle
    csh handle_;
    bool opened_;
    cs_arch arch_;
    cs_mode mode_;
    bool detailEnabled_;
    std::vector<std::pair<cs_opt_type, size_t>> asyncOptionState_;

    // Class reference for preventing garbage collection during async ops
    static Napi::FunctionReference constructor;

    /**
     * Disassemble a buffer (synchronous)
     * @param info[0] Buffer - code to disassemble
     * @param info[1] Number - base address
     * @param info[2] Number - (optional) max instructions, 0 = all
     * @returns Array of instruction objects
     */
    Napi::Value Disasm(const Napi::CallbackInfo& info);

    /**
     * Disassemble a buffer (asynchronous - non-blocking)
     * @param info[0] Buffer - code to disassemble
     * @param info[1] Number - base address
     * @param info[2] Number - (optional) max instructions, 0 = all
     * @returns Promise<Array> of instruction objects
     */
    Napi::Value DisasmAsync(const Napi::CallbackInfo& info);

    /**
     * Set option
     * @param info[0] Number - option type (CS_OPT_*)
     * @param info[1] Number - option value
     */
    Napi::Value SetOption(const Napi::CallbackInfo& info);

    /**
     * Close the handle and free resources
     */
    Napi::Value Close(const Napi::CallbackInfo& info);

    /**
     * Get register name by ID
     * @param info[0] Number - register ID
     * @returns String - register name
     */
    Napi::Value RegName(const Napi::CallbackInfo& info);

    /**
     * Get instruction name by ID
     * @param info[0] Number - instruction ID
     * @returns String - instruction name
     */
    Napi::Value InsnName(const Napi::CallbackInfo& info);

    /**
     * Get group name by ID
     * @param info[0] Number - group ID
     * @returns String - group name
     */
    Napi::Value GroupName(const Napi::CallbackInfo& info);

    /**
     * Check if handle is opened
     * @returns Boolean
     */
    Napi::Value IsOpen(const Napi::CallbackInfo& info);

    /**
     * Get last error code
     * @returns Number - error code
     */
    Napi::Value GetError(const Napi::CallbackInfo& info);

    /**
     * Get error message string
     * @param info[0] Number - (optional) error code, defaults to last error
     * @returns String - error message
     */
    Napi::Value StrError(const Napi::CallbackInfo& info);

    void RememberAsyncOption(cs_opt_type type, size_t value);

    // Helper methods
    Napi::Object InstructionToObject(Napi::Env env, cs_insn* insn);
    Napi::Object DetailToObject(Napi::Env env, cs_insn* insn);
    Napi::Object X86DetailToObject(Napi::Env env, cs_x86* x86);
    Napi::Object ArmDetailToObject(Napi::Env env, cs_arm* arm);
    Napi::Object Arm64DetailToObject(Napi::Env env, cs_arm64* arm64);
    Napi::Object MipsDetailToObject(Napi::Env env, cs_mips* mips);
    Napi::Object PpcDetailToObject(Napi::Env env, cs_ppc* ppc);
    Napi::Object SparcDetailToObject(Napi::Env env, cs_sparc* sparc);
    Napi::Object SyszDetailToObject(Napi::Env env, cs_sysz* sysz);
    Napi::Object XcoreDetailToObject(Napi::Env env, cs_xcore* xcore);
    Napi::Object M68kDetailToObject(Napi::Env env, cs_m68k* m68k);
#ifdef CS_ARCH_RISCV
    Napi::Object RiscvDetailToObject(Napi::Env env, cs_riscv* riscv);
#endif
};

#endif // CAPSTONE_WRAPPER_H

