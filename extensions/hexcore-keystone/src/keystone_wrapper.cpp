/*
 * HexCore Keystone - Native Node.js Bindings
 * Keystone Wrapper Implementation
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#include "keystone_wrapper.h"
#include "assemble_async_worker.h"
#include <cstring>

// Static member initialization
Napi::FunctionReference KeystoneWrapper::constructor;

/**
 * Initialize the class in module exports
 */
Napi::Object KeystoneWrapper::Init(Napi::Env env, Napi::Object exports) {
    Napi::HandleScope scope(env);

    Napi::Function func = DefineClass(env, "Keystone", {
        InstanceMethod("asm", &KeystoneWrapper::Asm),
        InstanceMethod("asmAsync", &KeystoneWrapper::AsmAsync),
        InstanceMethod("setOption", &KeystoneWrapper::SetOption),
        InstanceMethod("close", &KeystoneWrapper::Close),
        InstanceMethod("isOpen", &KeystoneWrapper::IsOpen),
        InstanceMethod("getError", &KeystoneWrapper::GetError),
        InstanceMethod("strError", &KeystoneWrapper::StrError),
    });

    constructor = Napi::Persistent(func);
    constructor.SuppressDestruct();

    exports.Set("Keystone", func);
    return exports;
}

/**
 * Constructor
 */
KeystoneWrapper::KeystoneWrapper(const Napi::CallbackInfo& info)
    : Napi::ObjectWrap<KeystoneWrapper>(info),
      handle_(nullptr),
      opened_(false),
      arch_(KS_ARCH_X86),
      mode_(KS_MODE_64) {

    Napi::Env env = info.Env();

    if (info.Length() < 2) {
        Napi::TypeError::New(env, "Expected arch and mode arguments")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!info[0].IsNumber() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Arch and mode must be numbers")
            .ThrowAsJavaScriptException();
        return;
    }

    arch_ = static_cast<ks_arch>(info[0].As<Napi::Number>().Int32Value());
    mode_ = static_cast<ks_mode>(info[1].As<Napi::Number>().Int32Value());

    ks_err err = ks_open(arch_, mode_, &handle_);
    if (err != KS_ERR_OK) {
        std::string errMsg = "Failed to initialize Keystone: ";
        errMsg += ks_strerror(err);
        Napi::Error::New(env, errMsg).ThrowAsJavaScriptException();
        return;
    }

    opened_ = true;
}

/**
 * Destructor
 */
KeystoneWrapper::~KeystoneWrapper() {
    if (opened_ && handle_ != nullptr) {
        ks_close(handle_);
        handle_ = nullptr;
        opened_ = false;
    }
}

/**
 * Assemble (synchronous)
 */
Napi::Value KeystoneWrapper::Asm(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Keystone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected assembly string as first argument")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string asmCode = info[0].As<Napi::String>().Utf8Value();
    uint64_t address = 0;

    if (info.Length() >= 2 && info[1].IsNumber()) {
        address = static_cast<uint64_t>(info[1].As<Napi::Number>().DoubleValue());
    }

    unsigned char* encoding = nullptr;
    size_t size = 0;
    size_t statCount = 0;

    int result = ks_asm(handle_, asmCode.c_str(), address, &encoding, &size, &statCount);

    Napi::Object resultObj = Napi::Object::New(env);

    if (result != 0) {
        ks_err err = ks_errno(handle_);
        resultObj.Set("error", Napi::String::New(env, ks_strerror(err)));
        resultObj.Set("bytes", env.Null());
        resultObj.Set("size", Napi::Number::New(env, 0));
        resultObj.Set("statCount", Napi::Number::New(env, 0));
    } else {
        // Copy bytes to Node buffer
        Napi::Buffer<uint8_t> buffer = Napi::Buffer<uint8_t>::Copy(env, encoding, size);
        resultObj.Set("bytes", buffer);
        resultObj.Set("size", Napi::Number::New(env, static_cast<double>(size)));
        resultObj.Set("statCount", Napi::Number::New(env, static_cast<double>(statCount)));

        // Free Keystone allocated memory
        ks_free(encoding);
    }

    return resultObj;
}

/**
 * Assemble (asynchronous)
 */
Napi::Value KeystoneWrapper::AsmAsync(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Keystone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 1 || !info[0].IsString()) {
        Napi::TypeError::New(env, "Expected assembly string as first argument")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    std::string asmCode = info[0].As<Napi::String>().Utf8Value();
    uint64_t address = 0;

    if (info.Length() >= 2 && info[1].IsNumber()) {
        address = static_cast<uint64_t>(info[1].As<Napi::Number>().DoubleValue());
    }

    // Create async worker
    AssembleAsyncWorker* worker = new AssembleAsyncWorker(
        env,
        handle_,
        std::move(asmCode),
        address
    );

    worker->Queue();
    return worker->GetPromise();
}

/**
 * Set option
 */
Napi::Value KeystoneWrapper::SetOption(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        Napi::Error::New(env, "Keystone handle is closed")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    if (info.Length() < 2 || !info[0].IsNumber() || !info[1].IsNumber()) {
        Napi::TypeError::New(env, "Expected option type and value as numbers")
            .ThrowAsJavaScriptException();
        return env.Null();
    }

    ks_opt_type type = static_cast<ks_opt_type>(info[0].As<Napi::Number>().Int32Value());
    size_t value = static_cast<size_t>(info[1].As<Napi::Number>().Int64Value());

    ks_err err = ks_option(handle_, type, value);

    if (err != KS_ERR_OK) {
        Napi::Error::New(env, ks_strerror(err)).ThrowAsJavaScriptException();
        return Napi::Boolean::New(env, false);
    }

    return Napi::Boolean::New(env, true);
}

/**
 * Close handle
 */
Napi::Value KeystoneWrapper::Close(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (opened_ && handle_ != nullptr) {
        ks_close(handle_);
        handle_ = nullptr;
        opened_ = false;
    }

    return env.Undefined();
}

/**
 * Check if handle is open
 */
Napi::Value KeystoneWrapper::IsOpen(const Napi::CallbackInfo& info) {
    return Napi::Boolean::New(info.Env(), opened_);
}

/**
 * Get last error code
 */
Napi::Value KeystoneWrapper::GetError(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    if (!opened_) {
        return Napi::Number::New(env, KS_ERR_HANDLE);
    }

    return Napi::Number::New(env, ks_errno(handle_));
}

/**
 * Get error message string
 */
Napi::Value KeystoneWrapper::StrError(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();

    ks_err err;
    if (info.Length() > 0 && info[0].IsNumber()) {
        err = static_cast<ks_err>(info[0].As<Napi::Number>().Int32Value());
    } else if (opened_) {
        err = ks_errno(handle_);
    } else {
        err = KS_ERR_HANDLE;
    }

    return Napi::String::New(env, ks_strerror(err));
}
