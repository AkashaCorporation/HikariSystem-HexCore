/*
 * HexCore Keystone - Native Node.js Bindings
 * Keystone Wrapper Header
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef KEYSTONE_WRAPPER_H
#define KEYSTONE_WRAPPER_H

#include <napi.h>
#include <keystone/keystone.h>
#include <vector>
#include <string>

// Forward declaration
class AssembleAsyncWorker;

/**
 * KeystoneWrapper - N-API class wrapping Keystone assembler
 *
 * JavaScript usage:
 *   const ks = new Keystone(ARCH.X86, MODE.MODE_64);
 *   const result = ks.asm("push rbp; mov rbp, rsp", 0x1000);
 *   const resultAsync = await ks.asmAsync("nop; nop; ret", 0x1000);
 *   ks.close();
 */
class KeystoneWrapper : public Napi::ObjectWrap<KeystoneWrapper> {
public:
    /**
     * Initialize the class in the module exports
     */
    static Napi::Object Init(Napi::Env env, Napi::Object exports);

    /**
     * Constructor called from JavaScript
     * @param info Contains arch and mode arguments
     */
    KeystoneWrapper(const Napi::CallbackInfo& info);

    /**
     * Destructor - ensures handle is closed
     */
    ~KeystoneWrapper();

    // Accessors for async worker
    ks_engine* GetHandle() const { return handle_; }
    ks_arch GetArch() const { return arch_; }
    bool IsOpened() const { return opened_; }

private:
    // Keystone handle
    ks_engine* handle_;
    bool opened_;
    ks_arch arch_;
    ks_mode mode_;

    // Class reference for preventing garbage collection during async ops
    static Napi::FunctionReference constructor;

    /**
     * Assemble a string (synchronous)
     * @param info[0] String - assembly code
     * @param info[1] Number - base address
     * @returns Object { bytes: Buffer, statCount: number, error?: string }
     */
    Napi::Value Asm(const Napi::CallbackInfo& info);

    /**
     * Assemble a string (asynchronous - non-blocking)
     * @param info[0] String - assembly code
     * @param info[1] Number - base address
     * @returns Promise<Object> { bytes: Buffer, statCount: number }
     */
    Napi::Value AsmAsync(const Napi::CallbackInfo& info);

    /**
     * Set option
     * @param info[0] Number - option type (KS_OPT_*)
     * @param info[1] Number - option value
     */
    Napi::Value SetOption(const Napi::CallbackInfo& info);

    /**
     * Close the handle and free resources
     */
    Napi::Value Close(const Napi::CallbackInfo& info);

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
     * @param info[0] Number - (optional) error code
     * @returns String - error message
     */
    Napi::Value StrError(const Napi::CallbackInfo& info);
};

#endif // KEYSTONE_WRAPPER_H
