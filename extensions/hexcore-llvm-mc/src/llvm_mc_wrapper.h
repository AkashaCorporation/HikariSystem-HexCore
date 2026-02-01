#ifndef LLVM_MC_WRAPPER_H
#define LLVM_MC_WRAPPER_H

#include <napi.h>
#include <memory>
#include <string>
#include <vector>

// Forward declarations for LLVM types
namespace llvm {
    class Target;
    class MCRegisterInfo;
    class MCAsmInfo;
    class MCInstrInfo;
    class MCSubtargetInfo;
    class MCContext;
    class MCObjectFileInfo;
}

class LlvmMcWrapper : public Napi::ObjectWrap<LlvmMcWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    static Napi::FunctionReference constructor;

    LlvmMcWrapper(const Napi::CallbackInfo& info);
    ~LlvmMcWrapper();

    // Public method for async worker access
    bool AssembleCode(const std::string& code, uint64_t address,
                      std::vector<uint8_t>& bytes, std::string& error);

private:
    std::string triple_;
    std::string cpu_;
    std::string features_;
    bool closed_;
    bool intelSyntax_;

    // LLVM objects (raw pointers - owned by wrapper)
    const llvm::Target* target_;
    std::unique_ptr<llvm::MCRegisterInfo> regInfo_;
    std::unique_ptr<llvm::MCAsmInfo> asmInfo_;
    std::unique_ptr<llvm::MCInstrInfo> instrInfo_;
    std::unique_ptr<llvm::MCSubtargetInfo> subtargetInfo_;

    // JavaScript method bindings
    Napi::Value Assemble(const Napi::CallbackInfo& info);
    Napi::Value AssembleAsync(const Napi::CallbackInfo& info);
    Napi::Value AssembleMultiple(const Napi::CallbackInfo& info);
    Napi::Value SetOption(const Napi::CallbackInfo& info);
    Napi::Value GetTriple(const Napi::CallbackInfo& info);
    Napi::Value GetCpu(const Napi::CallbackInfo& info);
    Napi::Value GetFeatures(const Napi::CallbackInfo& info);
    Napi::Value Close(const Napi::CallbackInfo& info);
    Napi::Value GetIsOpen(const Napi::CallbackInfo& info);
    Napi::Value GetHandle(const Napi::CallbackInfo& info);

    // Helper to throw if closed
    void ThrowIfClosed(Napi::Env env);
};

#endif // LLVM_MC_WRAPPER_H
