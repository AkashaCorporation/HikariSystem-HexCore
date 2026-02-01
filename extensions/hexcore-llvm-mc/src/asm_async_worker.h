#ifndef ASM_ASYNC_WORKER_H
#define ASM_ASYNC_WORKER_H

#include <napi.h>
#include <string>
#include <vector>
#include <cstdint>

// Forward declaration
class LlvmMcWrapper;

class AsmAsyncWorker : public Napi::AsyncWorker {
public:
    AsmAsyncWorker(Napi::Env env, Napi::Promise::Deferred deferred,
                   LlvmMcWrapper* wrapper, const std::string& code,
                   uint64_t address)
        : Napi::AsyncWorker(env),
          deferred_(deferred),
          wrapper_(wrapper),
          code_(code),
          address_(address),
          success_(false) {}

    void Execute() override;
    void OnOK() override;
    void OnError(const Napi::Error& error) override;

private:
    Napi::Promise::Deferred deferred_;
    LlvmMcWrapper* wrapper_;
    std::string code_;
    uint64_t address_;
    std::vector<uint8_t> result_;
    std::string errorMsg_;
    bool success_;
};

// Implementation inline to avoid linking issues
#include "llvm_mc_wrapper.h"

inline void AsmAsyncWorker::Execute() {
    success_ = wrapper_->AssembleCode(code_, address_, result_, errorMsg_);
}

inline void AsmAsyncWorker::OnOK() {
    Napi::Env env = Env();

    if (success_) {
        Napi::Object result = Napi::Object::New(env);
        result.Set("bytes", Napi::Buffer<uint8_t>::Copy(env, result_.data(), result_.size()));
        result.Set("size", Napi::Number::New(env, static_cast<double>(result_.size())));
        result.Set("address", Napi::BigInt::New(env, address_));
        result.Set("statement", Napi::String::New(env, code_));
        deferred_.Resolve(result);
    } else {
        deferred_.Reject(Napi::Error::New(env, errorMsg_).Value());
    }
}

inline void AsmAsyncWorker::OnError(const Napi::Error& error) {
    deferred_.Reject(error.Value());
}

#endif // ASM_ASYNC_WORKER_H
