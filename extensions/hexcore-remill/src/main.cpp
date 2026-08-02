/**
 * HexCore Remill - N-API Entry Point
 * Lifts machine code to LLVM IR bitcode
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include <napi.h>
#include <remill/Version/Version.h>
#include "remill_wrapper.h"

/**
 * Module constants — architecture name aliases for convenience.
 */
static Napi::Object CreateArchConstants(Napi::Env env) {
	Napi::Object arch = Napi::Object::New(env);
	arch.Set("X86", Napi::String::New(env, "x86"));
	arch.Set("X86_AVX", Napi::String::New(env, "x86_avx"));
	arch.Set("X86_AVX512", Napi::String::New(env, "x86_avx512"));
	arch.Set("AMD64", Napi::String::New(env, "amd64"));
	arch.Set("AMD64_AVX", Napi::String::New(env, "amd64_avx"));
	arch.Set("AMD64_AVX512", Napi::String::New(env, "amd64_avx512"));
	arch.Set("AARCH64", Napi::String::New(env, "aarch64"));
	arch.Set("SPARC32", Napi::String::New(env, "sparc32"));
	arch.Set("SPARC64", Napi::String::New(env, "sparc64"));
	return arch;
}

/**
 * Module constants — OS name aliases.
 */
static Napi::Object CreateOSConstants(Napi::Env env) {
	Napi::Object os = Napi::Object::New(env);
	os.Set("LINUX", Napi::String::New(env, "linux"));
	os.Set("MACOS", Napi::String::New(env, "macos"));
	os.Set("WINDOWS", Napi::String::New(env, "windows"));
	os.Set("SOLARIS", Napi::String::New(env, "solaris"));
	return os;
}

/**
 * N-API module initialization.
 */
Napi::Object Init(Napi::Env env, Napi::Object exports) {
	RemillLifter::Init(env, exports);

	exports.Set("ARCH", CreateArchConstants(env));
	exports.Set("OS", CreateOSConstants(env));
	exports.Set("version", Napi::String::New(env, "0.5.1"));
	exports.Set("upstreamVersion", Napi::String::New(env, "6.0.1"));

	const auto upstreamCommit = remill::version::GetCommitHash();
	exports.Set("upstreamCommit", Napi::String::New(
		env, upstreamCommit.data(), upstreamCommit.size()));

	return exports;
}

NODE_API_MODULE(hexcore_remill, Init)
