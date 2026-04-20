/**
 * Copyright (c) HikariSystem. All rights reserved.
 *
 * hexcore-souper — LLVM IR superoptimizer via Z3 SMT solving.
 * N-API entry point.
 */

#include <napi.h>
#include "souper_wrapper.h"

// Souper global — DebugLevel used across multiple Souper libs
// (normally set by command-line option in souper CLI tools)
unsigned int DebugLevel = 0;

static Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize the SouperOptimizer class
    SouperOptimizer::Init(env, exports);

    // Export version string
    exports.Set("version", Napi::String::New(env, "0.1.0"));

    return exports;
}

NODE_API_MODULE(hexcore_souper, Init)
