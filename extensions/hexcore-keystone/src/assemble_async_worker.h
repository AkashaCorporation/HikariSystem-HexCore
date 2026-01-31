/*
 * HexCore Keystone - Native Node.js Bindings
 * Async Assembly Worker
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef ASSEMBLE_ASYNC_WORKER_H
#define ASSEMBLE_ASYNC_WORKER_H

#include <napi.h>
#include <keystone/keystone.h>
#include <vector>
#include <string>

/**
 * Intermediate structure to hold assembled data
 * This is used to transfer data from worker thread to main thread
 */
struct AssembleResult {
    std::vector<uint8_t> bytes;
    size_t statCount;
    bool success;
    ks_err error;
    std::string errorMsg;
};

/**
 * AsyncWorker for non-blocking assembly
 * Runs ks_asm in a background thread and returns results via Promise
 */
class AssembleAsyncWorker : public Napi::AsyncWorker {
public:
    AssembleAsyncWorker(
        Napi::Env env,
        ks_engine* handle,
        std::string asmCode,
        uint64_t address
    ) : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        handle_(handle),
        asmCode_(std::move(asmCode)),
        address_(address) {
        result_.success = false;
        result_.statCount = 0;
        result_.error = KS_ERR_OK;
    }

    ~AssembleAsyncWorker() {}

    /**
     * Get the Promise that will be resolved when work completes
     */
    Napi::Promise GetPromise() { return deferred_.Promise(); }

    /**
     * Execute in background thread - no V8/N-API calls allowed here!
     */
    void Execute() override {
        unsigned char* encoding = nullptr;
        size_t size = 0;
        size_t statCount = 0;

        int ret = ks_asm(handle_, asmCode_.c_str(), address_, &encoding, &size, &statCount);

        if (ret != 0) {
            result_.success = false;
            result_.error = ks_errno(handle_);
            result_.errorMsg = ks_strerror(result_.error);
        } else {
            result_.success = true;
            result_.bytes.assign(encoding, encoding + size);
            result_.statCount = statCount;

            // Free Keystone allocated memory
            ks_free(encoding);
        }
    }

    /**
     * Called in main thread after Execute completes successfully
     */
    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);

        Napi::Object resultObj = Napi::Object::New(env);

        if (!result_.success) {
            resultObj.Set("error", Napi::String::New(env, result_.errorMsg));
            resultObj.Set("bytes", env.Null());
            resultObj.Set("size", Napi::Number::New(env, 0));
            resultObj.Set("statCount", Napi::Number::New(env, 0));
        } else {
            Napi::Buffer<uint8_t> buffer = Napi::Buffer<uint8_t>::Copy(
                env, result_.bytes.data(), result_.bytes.size()
            );
            resultObj.Set("bytes", buffer);
            resultObj.Set("size", Napi::Number::New(env, static_cast<double>(result_.bytes.size())));
            resultObj.Set("statCount", Napi::Number::New(env, static_cast<double>(result_.statCount)));
        }

        deferred_.Resolve(resultObj);
    }

    /**
     * Called in main thread if Execute throws
     */
    void OnError(const Napi::Error& error) override {
        deferred_.Reject(error.Value());
    }

private:
    Napi::Promise::Deferred deferred_;
    ks_engine* handle_;
    std::string asmCode_;
    uint64_t address_;
    AssembleResult result_;
};

#endif // ASSEMBLE_ASYNC_WORKER_H
