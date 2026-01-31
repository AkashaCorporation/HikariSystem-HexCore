/*
 * HexCore Keystone - Native Node.js Bindings
 * Main Entry Point
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include <napi.h>
#include <keystone/keystone.h>
#include "keystone_wrapper.h"

/**
 * Get Keystone version
 */
Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    unsigned int major, minor;
    ks_version(&major, &minor);

    Napi::Object result = Napi::Object::New(env);
    result.Set("major", Napi::Number::New(env, major));
    result.Set("minor", Napi::Number::New(env, minor));
    result.Set("string", Napi::String::New(env,
        std::to_string(major) + "." + std::to_string(minor)));

    return result;
}

/**
 * Check if architecture is supported
 */
Napi::Value ArchSupported(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (info.Length() < 1 || !info[0].IsNumber()) {
        Napi::TypeError::New(env, "Expected architecture number")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    ks_arch arch = static_cast<ks_arch>(info[0].As<Napi::Number>().Int32Value());
    bool supported = ks_arch_supported(arch);

    return Napi::Boolean::New(env, supported);
}

/**
 * Module initialization
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize the Keystone class
    KeystoneWrapper::Init(env, exports);

    // Export utility functions
    exports.Set("version", Napi::Function::New(env, GetVersion));
    exports.Set("archSupported", Napi::Function::New(env, ArchSupported));

    // Export architecture constants
    Napi::Object ARCH = Napi::Object::New(env);
    ARCH.Set("ARM", Napi::Number::New(env, KS_ARCH_ARM));
    ARCH.Set("ARM64", Napi::Number::New(env, KS_ARCH_ARM64));
    ARCH.Set("MIPS", Napi::Number::New(env, KS_ARCH_MIPS));
    ARCH.Set("X86", Napi::Number::New(env, KS_ARCH_X86));
    ARCH.Set("PPC", Napi::Number::New(env, KS_ARCH_PPC));
    ARCH.Set("SPARC", Napi::Number::New(env, KS_ARCH_SPARC));
    ARCH.Set("SYSTEMZ", Napi::Number::New(env, KS_ARCH_SYSTEMZ));
    ARCH.Set("HEXAGON", Napi::Number::New(env, KS_ARCH_HEXAGON));
    ARCH.Set("EVM", Napi::Number::New(env, KS_ARCH_EVM));
    exports.Set("ARCH", ARCH);

    // Export mode constants
    Napi::Object MODE = Napi::Object::New(env);
    MODE.Set("LITTLE_ENDIAN", Napi::Number::New(env, KS_MODE_LITTLE_ENDIAN));
    MODE.Set("BIG_ENDIAN", Napi::Number::New(env, KS_MODE_BIG_ENDIAN));
    // ARM modes
    MODE.Set("ARM", Napi::Number::New(env, KS_MODE_ARM));
    MODE.Set("THUMB", Napi::Number::New(env, KS_MODE_THUMB));
    MODE.Set("V8", Napi::Number::New(env, KS_MODE_V8));
    // x86 modes
    MODE.Set("MODE_16", Napi::Number::New(env, KS_MODE_16));
    MODE.Set("MODE_32", Napi::Number::New(env, KS_MODE_32));
    MODE.Set("MODE_64", Napi::Number::New(env, KS_MODE_64));
    // MIPS modes
    MODE.Set("MICRO", Napi::Number::New(env, KS_MODE_MICRO));
    MODE.Set("MIPS3", Napi::Number::New(env, KS_MODE_MIPS3));
    MODE.Set("MIPS32R6", Napi::Number::New(env, KS_MODE_MIPS32R6));
    MODE.Set("MIPS32", Napi::Number::New(env, KS_MODE_MIPS32));
    MODE.Set("MIPS64", Napi::Number::New(env, KS_MODE_MIPS64));
    // PPC modes
    MODE.Set("PPC32", Napi::Number::New(env, KS_MODE_PPC32));
    MODE.Set("PPC64", Napi::Number::New(env, KS_MODE_PPC64));
    MODE.Set("QPX", Napi::Number::New(env, KS_MODE_QPX));
    // SPARC modes
    MODE.Set("SPARC32", Napi::Number::New(env, KS_MODE_SPARC32));
    MODE.Set("SPARC64", Napi::Number::New(env, KS_MODE_SPARC64));
    MODE.Set("V9", Napi::Number::New(env, KS_MODE_V9));
    exports.Set("MODE", MODE);

    // Export option constants
    Napi::Object OPT = Napi::Object::New(env);
    OPT.Set("SYNTAX", Napi::Number::New(env, KS_OPT_SYNTAX));
    exports.Set("OPT", OPT);

    // Export option value constants
    Napi::Object OPT_VALUE = Napi::Object::New(env);
    OPT_VALUE.Set("SYNTAX_INTEL", Napi::Number::New(env, KS_OPT_SYNTAX_INTEL));
    OPT_VALUE.Set("SYNTAX_ATT", Napi::Number::New(env, KS_OPT_SYNTAX_ATT));
    OPT_VALUE.Set("SYNTAX_NASM", Napi::Number::New(env, KS_OPT_SYNTAX_NASM));
    OPT_VALUE.Set("SYNTAX_MASM", Napi::Number::New(env, KS_OPT_SYNTAX_MASM));
    OPT_VALUE.Set("SYNTAX_GAS", Napi::Number::New(env, KS_OPT_SYNTAX_GAS));
    OPT_VALUE.Set("SYNTAX_RADIX16", Napi::Number::New(env, KS_OPT_SYNTAX_RADIX16));
    exports.Set("OPT_VALUE", OPT_VALUE);

    // Export error constants
    Napi::Object ERR = Napi::Object::New(env);
    ERR.Set("OK", Napi::Number::New(env, KS_ERR_OK));
    ERR.Set("NOMEM", Napi::Number::New(env, KS_ERR_NOMEM));
    ERR.Set("ARCH", Napi::Number::New(env, KS_ERR_ARCH));
    ERR.Set("HANDLE", Napi::Number::New(env, KS_ERR_HANDLE));
    ERR.Set("MODE", Napi::Number::New(env, KS_ERR_MODE));
    ERR.Set("VERSION", Napi::Number::New(env, KS_ERR_VERSION));
    ERR.Set("OPT_INVALID", Napi::Number::New(env, KS_ERR_OPT_INVALID));
    ERR.Set("ASM_EXPR_TOKEN", Napi::Number::New(env, KS_ERR_ASM_EXPR_TOKEN));
    ERR.Set("ASM_DIRECTIVE_VALUE_RANGE", Napi::Number::New(env, KS_ERR_ASM_DIRECTIVE_VALUE_RANGE));
    ERR.Set("ASM_DIRECTIVE_ID", Napi::Number::New(env, KS_ERR_ASM_DIRECTIVE_ID));
    ERR.Set("ASM_DIRECTIVE_TOKEN", Napi::Number::New(env, KS_ERR_ASM_DIRECTIVE_TOKEN));
    ERR.Set("ASM_DIRECTIVE_STR", Napi::Number::New(env, KS_ERR_ASM_DIRECTIVE_STR));
    ERR.Set("ASM_DIRECTIVE_COMMA", Napi::Number::New(env, KS_ERR_ASM_DIRECTIVE_COMMA));
    ERR.Set("ASM_INVALIDOPERAND", Napi::Number::New(env, KS_ERR_ASM_INVALIDOPERAND));
    ERR.Set("ASM_MISSINGFEATURE", Napi::Number::New(env, KS_ERR_ASM_MISSINGFEATURE));
    ERR.Set("ASM_MNEMONICFAIL", Napi::Number::New(env, KS_ERR_ASM_MNEMONICFAIL));
    exports.Set("ERR", ERR);

    return exports;
}

NODE_API_MODULE(hexcore_keystone, Init)
