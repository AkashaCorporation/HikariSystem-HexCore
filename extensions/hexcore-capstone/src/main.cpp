/*
 * HexCore Capstone - Native Node.js Bindings
 * Main entry point for N-API addon
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include <napi.h>
#include "capstone_wrapper.h"

/**
 * Initialize the addon module
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize Capstone wrapper class
    CapstoneWrapper::Init(env, exports);

    // Export architecture constants
    Napi::Object arch = Napi::Object::New(env);
    arch.Set("ARM", Napi::Number::New(env, CS_ARCH_ARM));
    arch.Set("ARM64", Napi::Number::New(env, CS_ARCH_ARM64));
    arch.Set("MIPS", Napi::Number::New(env, CS_ARCH_MIPS));
    arch.Set("X86", Napi::Number::New(env, CS_ARCH_X86));
    arch.Set("PPC", Napi::Number::New(env, CS_ARCH_PPC));
    arch.Set("SPARC", Napi::Number::New(env, CS_ARCH_SPARC));
    arch.Set("SYSZ", Napi::Number::New(env, CS_ARCH_SYSZ));
    arch.Set("XCORE", Napi::Number::New(env, CS_ARCH_XCORE));
    arch.Set("M68K", Napi::Number::New(env, CS_ARCH_M68K));
    arch.Set("TMS320C64X", Napi::Number::New(env, CS_ARCH_TMS320C64X));
    arch.Set("M680X", Napi::Number::New(env, CS_ARCH_M680X));
    arch.Set("EVM", Napi::Number::New(env, CS_ARCH_EVM));
    #ifdef CS_ARCH_WASM
    arch.Set("WASM", Napi::Number::New(env, CS_ARCH_WASM));
    #endif
    #ifdef CS_ARCH_BPF
    arch.Set("BPF", Napi::Number::New(env, CS_ARCH_BPF));
    #endif
    #ifdef CS_ARCH_RISCV
    arch.Set("RISCV", Napi::Number::New(env, CS_ARCH_RISCV));
    #endif
    exports.Set("ARCH", arch);

    // Export mode constants
    Napi::Object mode = Napi::Object::New(env);
    mode.Set("LITTLE_ENDIAN", Napi::Number::New(env, CS_MODE_LITTLE_ENDIAN));
    mode.Set("BIG_ENDIAN", Napi::Number::New(env, CS_MODE_BIG_ENDIAN));
    mode.Set("ARM", Napi::Number::New(env, CS_MODE_ARM));
    mode.Set("THUMB", Napi::Number::New(env, CS_MODE_THUMB));
    mode.Set("MCLASS", Napi::Number::New(env, CS_MODE_MCLASS));
    mode.Set("V8", Napi::Number::New(env, CS_MODE_V8));
    mode.Set("MODE_16", Napi::Number::New(env, CS_MODE_16));
    mode.Set("MODE_32", Napi::Number::New(env, CS_MODE_32));
    mode.Set("MODE_64", Napi::Number::New(env, CS_MODE_64));
    mode.Set("MICRO", Napi::Number::New(env, CS_MODE_MICRO));
    mode.Set("MIPS3", Napi::Number::New(env, CS_MODE_MIPS3));
    mode.Set("MIPS32R6", Napi::Number::New(env, CS_MODE_MIPS32R6));
    mode.Set("MIPS2", Napi::Number::New(env, CS_MODE_MIPS2));
    mode.Set("V9", Napi::Number::New(env, CS_MODE_V9));
    mode.Set("QPX", Napi::Number::New(env, CS_MODE_QPX));
    mode.Set("M68K_000", Napi::Number::New(env, CS_MODE_M68K_000));
    mode.Set("M68K_010", Napi::Number::New(env, CS_MODE_M68K_010));
    mode.Set("M68K_020", Napi::Number::New(env, CS_MODE_M68K_020));
    mode.Set("M68K_030", Napi::Number::New(env, CS_MODE_M68K_030));
    mode.Set("M68K_040", Napi::Number::New(env, CS_MODE_M68K_040));
    mode.Set("M68K_060", Napi::Number::New(env, CS_MODE_M68K_060));
    #ifdef CS_MODE_RISCV32
    mode.Set("RISCV32", Napi::Number::New(env, CS_MODE_RISCV32));
    mode.Set("RISCV64", Napi::Number::New(env, CS_MODE_RISCV64));
    mode.Set("RISCVC", Napi::Number::New(env, CS_MODE_RISCVC));
    #endif
    exports.Set("MODE", mode);

    // Export option constants
    Napi::Object opt = Napi::Object::New(env);
    opt.Set("SYNTAX", Napi::Number::New(env, CS_OPT_SYNTAX));
    opt.Set("DETAIL", Napi::Number::New(env, CS_OPT_DETAIL));
    opt.Set("MODE", Napi::Number::New(env, CS_OPT_MODE));
    opt.Set("MEM", Napi::Number::New(env, CS_OPT_MEM));
    opt.Set("SKIPDATA", Napi::Number::New(env, CS_OPT_SKIPDATA));
    opt.Set("SKIPDATA_SETUP", Napi::Number::New(env, CS_OPT_SKIPDATA_SETUP));
    opt.Set("MNEMONIC", Napi::Number::New(env, CS_OPT_MNEMONIC));
    opt.Set("UNSIGNED", Napi::Number::New(env, CS_OPT_UNSIGNED));
    exports.Set("OPT", opt);

    // Export option value constants
    Napi::Object optValue = Napi::Object::New(env);
    optValue.Set("OFF", Napi::Number::New(env, CS_OPT_OFF));
    optValue.Set("ON", Napi::Number::New(env, CS_OPT_ON));
    optValue.Set("SYNTAX_DEFAULT", Napi::Number::New(env, CS_OPT_SYNTAX_DEFAULT));
    optValue.Set("SYNTAX_INTEL", Napi::Number::New(env, CS_OPT_SYNTAX_INTEL));
    optValue.Set("SYNTAX_ATT", Napi::Number::New(env, CS_OPT_SYNTAX_ATT));
    optValue.Set("SYNTAX_NOREGNAME", Napi::Number::New(env, CS_OPT_SYNTAX_NOREGNAME));
    optValue.Set("SYNTAX_MASM", Napi::Number::New(env, CS_OPT_SYNTAX_MASM));
    exports.Set("OPT_VALUE", optValue);

    // Export error constants
    Napi::Object err = Napi::Object::New(env);
    err.Set("OK", Napi::Number::New(env, CS_ERR_OK));
    err.Set("MEM", Napi::Number::New(env, CS_ERR_MEM));
    err.Set("ARCH", Napi::Number::New(env, CS_ERR_ARCH));
    err.Set("HANDLE", Napi::Number::New(env, CS_ERR_HANDLE));
    err.Set("CSH", Napi::Number::New(env, CS_ERR_CSH));
    err.Set("MODE", Napi::Number::New(env, CS_ERR_MODE));
    err.Set("OPTION", Napi::Number::New(env, CS_ERR_OPTION));
    err.Set("DETAIL", Napi::Number::New(env, CS_ERR_DETAIL));
    err.Set("MEMSETUP", Napi::Number::New(env, CS_ERR_MEMSETUP));
    err.Set("VERSION", Napi::Number::New(env, CS_ERR_VERSION));
    err.Set("DIET", Napi::Number::New(env, CS_ERR_DIET));
    err.Set("SKIPDATA", Napi::Number::New(env, CS_ERR_SKIPDATA));
    err.Set("X86_ATT", Napi::Number::New(env, CS_ERR_X86_ATT));
    err.Set("X86_INTEL", Napi::Number::New(env, CS_ERR_X86_INTEL));
    err.Set("X86_MASM", Napi::Number::New(env, CS_ERR_X86_MASM));
    exports.Set("ERR", err);

    // Export version function
    exports.Set("version", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        int major, minor;
        cs_version(&major, &minor);

        Napi::Object version = Napi::Object::New(env);
        version.Set("major", Napi::Number::New(env, major));
        version.Set("minor", Napi::Number::New(env, minor));
        version.Set("string", Napi::String::New(env,
            std::to_string(major) + "." + std::to_string(minor)));
        return version;
    }));

    // Export support check function
    exports.Set("support", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1 || !info[0].IsNumber()) {
            Napi::TypeError::New(env, "Architecture constant required").ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }

        int arch = info[0].As<Napi::Number>().Int32Value();
        bool supported = cs_support(arch);
        return Napi::Boolean::New(env, supported);
    }));

    return exports;
}

NODE_API_MODULE(hexcore_capstone, Init)
