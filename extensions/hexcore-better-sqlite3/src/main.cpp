/*
 * HexCore SQLite3 - Native Node.js Bindings
 * Main entry point for N-API addon
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include <napi.h>
#include <sqlite3.h>
#include "sqlite3_wrapper.h"

static Napi::FunctionReference errorConstructor;
static bool isInitialized = false;

/**
 * setErrorConstructor - called from JS to register the SqliteError class
 */
static Napi::Value SetErrorConstructor(const Napi::CallbackInfo& info) {
	Napi::Env env = info.Env();
	if (info.Length() < 1 || !info[0].IsFunction()) {
		Napi::TypeError::New(env, "Expected a constructor function").ThrowAsJavaScriptException();
		return env.Undefined();
	}
	errorConstructor = Napi::Persistent(info[0].As<Napi::Function>());
	return env.Undefined();
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
	DatabaseWrapper::Init(env, exports);
	StatementWrapper::Init(env, exports);

	exports.Set("setErrorConstructor", Napi::Function::New(env, SetErrorConstructor));

	// Export isInitialized as a property (mutable from JS side)
	exports.Set("isInitialized", Napi::Boolean::New(env, false));

	return exports;
}

NODE_API_MODULE(hexcore_sqlite3, Init)
