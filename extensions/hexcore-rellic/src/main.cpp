/**
 * HexCore Rellic - N-API Entry Point
 * Decompiles LLVM IR to pseudo-C via Rellic
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include <napi.h>
#include "rellic_wrapper.h"

/**
 * N-API module initialization.
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
	RellicDecompiler::Init(env, exports);

	exports.Set("version", Napi::String::New(env, "0.1.0"));

	return exports;
}

NODE_API_MODULE(hexcore_rellic, Init)
