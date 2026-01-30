/*
 * HexCore Capstone - Native Node.js Bindings
 * Async Disassembly Worker
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

#ifndef DISASM_ASYNC_WORKER_H
#define DISASM_ASYNC_WORKER_H

#include <napi.h>
#include <capstone/capstone.h>
#include <vector>
#include <cstring>

/**
 * Intermediate structure to hold disassembled instruction data
 * This is used to transfer data from worker thread to main thread
 */
struct DisasmResult {
    uint32_t id;
    uint64_t address;
    uint16_t size;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string op_str;

    // Detail data (optional)
    bool hasDetail;
    std::vector<uint16_t> regsRead;
    std::vector<uint16_t> regsWrite;
    std::vector<uint8_t> groups;
};

/**
 * AsyncWorker for non-blocking disassembly
 * Runs cs_disasm in a background thread and returns results via Promise
 */
class DisasmAsyncWorker : public Napi::AsyncWorker {
public:
    DisasmAsyncWorker(
        Napi::Env env,
        csh handle,
        cs_arch arch,
        std::vector<uint8_t> code,
        uint64_t address,
        size_t count,
        bool includeDetail
    ) : Napi::AsyncWorker(env),
        deferred_(Napi::Promise::Deferred::New(env)),
        handle_(handle),
        arch_(arch),
        code_(std::move(code)),
        address_(address),
        count_(count),
        includeDetail_(includeDetail),
        numInsns_(0),
        error_(CS_ERR_OK) {}

    ~DisasmAsyncWorker() {}

    /**
     * Get the Promise that will be resolved when work completes
     */
    Napi::Promise GetPromise() { return deferred_.Promise(); }

    /**
     * Execute in background thread - no V8/N-API calls allowed here!
     */
    void Execute() override {
        cs_insn* insn = nullptr;

        // Perform disassembly in background thread
        numInsns_ = cs_disasm(
            handle_,
            code_.data(),
            code_.size(),
            address_,
            count_,
            &insn
        );

        if (numInsns_ == 0) {
            error_ = cs_errno(handle_);
            return;
        }

        // Copy data to our intermediate structures (no V8 objects here!)
        results_.reserve(numInsns_);

        for (size_t i = 0; i < numInsns_; i++) {
            DisasmResult result;
            result.id = insn[i].id;
            result.address = insn[i].address;
            result.size = insn[i].size;
            result.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);
            result.mnemonic = insn[i].mnemonic;
            result.op_str = insn[i].op_str;
            result.hasDetail = false;

            // Copy detail if available and requested
            if (includeDetail_ && insn[i].detail != nullptr) {
                result.hasDetail = true;
                cs_detail* detail = insn[i].detail;

                result.regsRead.assign(
                    detail->regs_read,
                    detail->regs_read + detail->regs_read_count
                );
                result.regsWrite.assign(
                    detail->regs_write,
                    detail->regs_write + detail->regs_write_count
                );
                result.groups.assign(
                    detail->groups,
                    detail->groups + detail->groups_count
                );
            }

            results_.push_back(std::move(result));
        }

        // Free Capstone memory
        cs_free(insn, numInsns_);
    }

    /**
     * Called in main thread after Execute completes successfully
     */
    void OnOK() override {
        Napi::Env env = Env();
        Napi::HandleScope scope(env);

        // Convert results to JavaScript array
        Napi::Array jsArray = Napi::Array::New(env, results_.size());

        for (size_t i = 0; i < results_.size(); i++) {
            jsArray.Set(static_cast<uint32_t>(i), ResultToObject(env, results_[i]));
        }

        deferred_.Resolve(jsArray);
    }

    /**
     * Called in main thread if Execute throws
     */
    void OnError(const Napi::Error& error) override {
        deferred_.Reject(error.Value());
    }

private:
    Napi::Promise::Deferred deferred_;
    csh handle_;
    cs_arch arch_;
    std::vector<uint8_t> code_;
    uint64_t address_;
    size_t count_;
    bool includeDetail_;

    // Results from Execute()
    size_t numInsns_;
    cs_err error_;
    std::vector<DisasmResult> results_;

    /**
     * Convert our intermediate structure to a JavaScript object
     */
    Napi::Object ResultToObject(Napi::Env env, const DisasmResult& result) {
        Napi::Object obj = Napi::Object::New(env);

        obj.Set("id", Napi::Number::New(env, result.id));
        obj.Set("address", Napi::Number::New(env, static_cast<double>(result.address)));
        obj.Set("size", Napi::Number::New(env, result.size));
        obj.Set("mnemonic", Napi::String::New(env, result.mnemonic));
        obj.Set("opStr", Napi::String::New(env, result.op_str));

        // Copy bytes
        Napi::Buffer<uint8_t> bytes = Napi::Buffer<uint8_t>::Copy(
            env, result.bytes.data(), result.bytes.size()
        );
        obj.Set("bytes", bytes);

        // Add detail if available
        if (result.hasDetail) {
            Napi::Object detail = Napi::Object::New(env);

            // Registers read
            Napi::Array regsRead = Napi::Array::New(env, result.regsRead.size());
            for (size_t j = 0; j < result.regsRead.size(); j++) {
                regsRead.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.regsRead[j]));
            }
            detail.Set("regsRead", regsRead);

            // Registers written
            Napi::Array regsWrite = Napi::Array::New(env, result.regsWrite.size());
            for (size_t j = 0; j < result.regsWrite.size(); j++) {
                regsWrite.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.regsWrite[j]));
            }
            detail.Set("regsWrite", regsWrite);

            // Groups
            Napi::Array groups = Napi::Array::New(env, result.groups.size());
            for (size_t j = 0; j < result.groups.size(); j++) {
                groups.Set(static_cast<uint32_t>(j), Napi::Number::New(env, result.groups[j]));
            }
            detail.Set("groups", groups);

            obj.Set("detail", detail);
        }

        return obj;
    }
};

#endif // DISASM_ASYNC_WORKER_H
