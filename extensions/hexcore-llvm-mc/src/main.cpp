#include <napi.h>
#include "llvm_mc_wrapper.h"

#include <llvm/Support/TargetSelect.h>
#include <llvm/MC/TargetRegistry.h>

#include <string>
#include <sstream>

// Target initialization declarations - ALL TARGETS
// X86
extern "C" void LLVMInitializeX86TargetInfo();
extern "C" void LLVMInitializeX86Target();
extern "C" void LLVMInitializeX86TargetMC();
extern "C" void LLVMInitializeX86AsmParser();
extern "C" void LLVMInitializeX86AsmPrinter();

// ARM
extern "C" void LLVMInitializeARMTargetInfo();
extern "C" void LLVMInitializeARMTarget();
extern "C" void LLVMInitializeARMTargetMC();
extern "C" void LLVMInitializeARMAsmParser();
extern "C" void LLVMInitializeARMAsmPrinter();

// AArch64
extern "C" void LLVMInitializeAArch64TargetInfo();
extern "C" void LLVMInitializeAArch64Target();
extern "C" void LLVMInitializeAArch64TargetMC();
extern "C" void LLVMInitializeAArch64AsmParser();
extern "C" void LLVMInitializeAArch64AsmPrinter();

// Mips
extern "C" void LLVMInitializeMipsTargetInfo();
extern "C" void LLVMInitializeMipsTarget();
extern "C" void LLVMInitializeMipsTargetMC();
extern "C" void LLVMInitializeMipsAsmParser();
extern "C" void LLVMInitializeMipsAsmPrinter();

// RISCV
extern "C" void LLVMInitializeRISCVTargetInfo();
extern "C" void LLVMInitializeRISCVTarget();
extern "C" void LLVMInitializeRISCVTargetMC();
extern "C" void LLVMInitializeRISCVAsmParser();
extern "C" void LLVMInitializeRISCVAsmPrinter();

// PowerPC
extern "C" void LLVMInitializePowerPCTargetInfo();
extern "C" void LLVMInitializePowerPCTarget();
extern "C" void LLVMInitializePowerPCTargetMC();
extern "C" void LLVMInitializePowerPCAsmParser();
extern "C" void LLVMInitializePowerPCAsmPrinter();

// Sparc
extern "C" void LLVMInitializeSparcTargetInfo();
extern "C" void LLVMInitializeSparcTarget();
extern "C" void LLVMInitializeSparcTargetMC();
extern "C" void LLVMInitializeSparcAsmParser();
extern "C" void LLVMInitializeSparcAsmPrinter();

// SystemZ
extern "C" void LLVMInitializeSystemZTargetInfo();
extern "C" void LLVMInitializeSystemZTarget();
extern "C" void LLVMInitializeSystemZTargetMC();
extern "C" void LLVMInitializeSystemZAsmParser();
extern "C" void LLVMInitializeSystemZAsmPrinter();

// Hexagon
extern "C" void LLVMInitializeHexagonTargetInfo();
extern "C" void LLVMInitializeHexagonTarget();
extern "C" void LLVMInitializeHexagonTargetMC();
extern "C" void LLVMInitializeHexagonAsmParser();
extern "C" void LLVMInitializeHexagonAsmPrinter();

// WebAssembly
extern "C" void LLVMInitializeWebAssemblyTargetInfo();
extern "C" void LLVMInitializeWebAssemblyTarget();
extern "C" void LLVMInitializeWebAssemblyTargetMC();
extern "C" void LLVMInitializeWebAssemblyAsmParser();
extern "C" void LLVMInitializeWebAssemblyAsmPrinter();

// BPF
extern "C" void LLVMInitializeBPFTargetInfo();
extern "C" void LLVMInitializeBPFTarget();
extern "C" void LLVMInitializeBPFTargetMC();
extern "C" void LLVMInitializeBPFAsmParser();
extern "C" void LLVMInitializeBPFAsmPrinter();

// LoongArch
extern "C" void LLVMInitializeLoongArchTargetInfo();
extern "C" void LLVMInitializeLoongArchTarget();
extern "C" void LLVMInitializeLoongArchTargetMC();
extern "C" void LLVMInitializeLoongArchAsmParser();
extern "C" void LLVMInitializeLoongArchAsmPrinter();

// Initialize ALL targets
static bool InitializeLLVMTargets() {
    static bool initialized = false;
    if (!initialized) {
        // X86
        LLVMInitializeX86TargetInfo();
        LLVMInitializeX86Target();
        LLVMInitializeX86TargetMC();
        LLVMInitializeX86AsmParser();
        LLVMInitializeX86AsmPrinter();

        // ARM
        LLVMInitializeARMTargetInfo();
        LLVMInitializeARMTarget();
        LLVMInitializeARMTargetMC();
        LLVMInitializeARMAsmParser();
        LLVMInitializeARMAsmPrinter();

        // AArch64
        LLVMInitializeAArch64TargetInfo();
        LLVMInitializeAArch64Target();
        LLVMInitializeAArch64TargetMC();
        LLVMInitializeAArch64AsmParser();
        LLVMInitializeAArch64AsmPrinter();

        // Mips
        LLVMInitializeMipsTargetInfo();
        LLVMInitializeMipsTarget();
        LLVMInitializeMipsTargetMC();
        LLVMInitializeMipsAsmParser();
        LLVMInitializeMipsAsmPrinter();

        // RISCV
        LLVMInitializeRISCVTargetInfo();
        LLVMInitializeRISCVTarget();
        LLVMInitializeRISCVTargetMC();
        LLVMInitializeRISCVAsmParser();
        LLVMInitializeRISCVAsmPrinter();

        // PowerPC
        LLVMInitializePowerPCTargetInfo();
        LLVMInitializePowerPCTarget();
        LLVMInitializePowerPCTargetMC();
        LLVMInitializePowerPCAsmParser();
        LLVMInitializePowerPCAsmPrinter();

        // Sparc
        LLVMInitializeSparcTargetInfo();
        LLVMInitializeSparcTarget();
        LLVMInitializeSparcTargetMC();
        LLVMInitializeSparcAsmParser();
        LLVMInitializeSparcAsmPrinter();

        // SystemZ
        LLVMInitializeSystemZTargetInfo();
        LLVMInitializeSystemZTarget();
        LLVMInitializeSystemZTargetMC();
        LLVMInitializeSystemZAsmParser();
        LLVMInitializeSystemZAsmPrinter();

        // Hexagon
        LLVMInitializeHexagonTargetInfo();
        LLVMInitializeHexagonTarget();
        LLVMInitializeHexagonTargetMC();
        LLVMInitializeHexagonAsmParser();
        LLVMInitializeHexagonAsmPrinter();

        // WebAssembly
        LLVMInitializeWebAssemblyTargetInfo();
        LLVMInitializeWebAssemblyTarget();
        LLVMInitializeWebAssemblyTargetMC();
        LLVMInitializeWebAssemblyAsmParser();
        LLVMInitializeWebAssemblyAsmPrinter();

        // BPF
        LLVMInitializeBPFTargetInfo();
        LLVMInitializeBPFTarget();
        LLVMInitializeBPFTargetMC();
        LLVMInitializeBPFAsmParser();
        LLVMInitializeBPFAsmPrinter();

        // LoongArch
        LLVMInitializeLoongArchTargetInfo();
        LLVMInitializeLoongArchTarget();
        LLVMInitializeLoongArchTargetMC();
        LLVMInitializeLoongArchAsmParser();
        LLVMInitializeLoongArchAsmPrinter();

        initialized = true;
    }
    return true;
}

// Get LLVM version string
static Napi::Value GetVersion(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    std::ostringstream oss;
    oss << LLVM_VERSION_MAJOR << "." << LLVM_VERSION_MINOR << "." << LLVM_VERSION_PATCH;
    return Napi::String::New(env, oss.str());
}

// Get list of available targets
static Napi::Value GetTargets(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    Napi::Array targets = Napi::Array::New(env);

    uint32_t i = 0;
    for (auto it = llvm::TargetRegistry::targets().begin();
         it != llvm::TargetRegistry::targets().end(); ++it) {
        Napi::Object target = Napi::Object::New(env);
        target.Set("name", Napi::String::New(env, it->getName()));
        target.Set("description", Napi::String::New(env, it->getShortDescription()));
        targets.Set(i++, target);
    }

    return targets;
}

// Create TRIPLE constants object
static Napi::Object CreateTripleObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // x86
    obj.Set("X86", Napi::String::New(env, "i386-unknown-unknown"));
    obj.Set("X86_64", Napi::String::New(env, "x86_64-unknown-unknown"));
    obj.Set("I386", Napi::String::New(env, "i386-unknown-unknown"));
    obj.Set("I686", Napi::String::New(env, "i686-unknown-unknown"));

    // ARM
    obj.Set("ARM", Napi::String::New(env, "arm-unknown-unknown"));
    obj.Set("ARMV7", Napi::String::New(env, "armv7-unknown-unknown"));
    obj.Set("ARMV8", Napi::String::New(env, "armv8-unknown-unknown"));
    obj.Set("THUMB", Napi::String::New(env, "thumb-unknown-unknown"));
    obj.Set("THUMBV7", Napi::String::New(env, "thumbv7-unknown-unknown"));

    // ARM64
    obj.Set("ARM64", Napi::String::New(env, "aarch64-unknown-unknown"));
    obj.Set("AARCH64", Napi::String::New(env, "aarch64-unknown-unknown"));

    // MIPS
    obj.Set("MIPS", Napi::String::New(env, "mips-unknown-unknown"));
    obj.Set("MIPSEL", Napi::String::New(env, "mipsel-unknown-unknown"));
    obj.Set("MIPS64", Napi::String::New(env, "mips64-unknown-unknown"));
    obj.Set("MIPS64EL", Napi::String::New(env, "mips64el-unknown-unknown"));

    // PowerPC
    obj.Set("PPC", Napi::String::New(env, "powerpc-unknown-unknown"));
    obj.Set("PPC64", Napi::String::New(env, "powerpc64-unknown-unknown"));
    obj.Set("PPC64LE", Napi::String::New(env, "powerpc64le-unknown-unknown"));

    // SPARC
    obj.Set("SPARC", Napi::String::New(env, "sparc-unknown-unknown"));
    obj.Set("SPARCV9", Napi::String::New(env, "sparcv9-unknown-unknown"));
    obj.Set("SPARC64", Napi::String::New(env, "sparc64-unknown-unknown"));

    // RISC-V
    obj.Set("RISCV32", Napi::String::New(env, "riscv32-unknown-unknown"));
    obj.Set("RISCV64", Napi::String::New(env, "riscv64-unknown-unknown"));

    // System Z
    obj.Set("SYSTEMZ", Napi::String::New(env, "systemz-unknown-unknown"));
    obj.Set("S390X", Napi::String::New(env, "s390x-unknown-unknown"));

    // Hexagon
    obj.Set("HEXAGON", Napi::String::New(env, "hexagon-unknown-unknown"));

    // WebAssembly
    obj.Set("WASM32", Napi::String::New(env, "wasm32-unknown-unknown"));
    obj.Set("WASM64", Napi::String::New(env, "wasm64-unknown-unknown"));

    // BPF
    obj.Set("BPF", Napi::String::New(env, "bpf-unknown-unknown"));
    obj.Set("BPFEL", Napi::String::New(env, "bpfel-unknown-unknown"));
    obj.Set("BPFEB", Napi::String::New(env, "bpfeb-unknown-unknown"));

    // LoongArch
    obj.Set("LOONGARCH32", Napi::String::New(env, "loongarch32-unknown-unknown"));
    obj.Set("LOONGARCH64", Napi::String::New(env, "loongarch64-unknown-unknown"));

    return obj;
}

// Create SYNTAX constants object
static Napi::Object CreateSyntaxObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("INTEL", Napi::Number::New(env, 0));
    obj.Set("ATT", Napi::Number::New(env, 1));
    return obj;
}

// Create OPTION constants object
static Napi::Object CreateOptionObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("SYNTAX", Napi::Number::New(env, 0));
    return obj;
}

// Create ERR constants object
static Napi::Object CreateErrObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);
    obj.Set("OK", Napi::Number::New(env, 0));
    obj.Set("INVALID_TRIPLE", Napi::Number::New(env, 1));
    obj.Set("ASM_FAILED", Napi::Number::New(env, 2));
    obj.Set("NOMEM", Napi::Number::New(env, 3));
    obj.Set("CLOSED", Napi::Number::New(env, 4));
    obj.Set("INVALID_PARAM", Napi::Number::New(env, 5));
    return obj;
}

// Create CPU presets for common architectures
static Napi::Object CreateCpuObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // x86 CPUs
    Napi::Object x86 = Napi::Object::New(env);
    x86.Set("GENERIC", Napi::String::New(env, "generic"));
    x86.Set("I386", Napi::String::New(env, "i386"));
    x86.Set("I486", Napi::String::New(env, "i486"));
    x86.Set("I586", Napi::String::New(env, "i586"));
    x86.Set("PENTIUM", Napi::String::New(env, "pentium"));
    x86.Set("PENTIUM_PRO", Napi::String::New(env, "pentiumpro"));
    x86.Set("PENTIUM2", Napi::String::New(env, "pentium2"));
    x86.Set("PENTIUM3", Napi::String::New(env, "pentium3"));
    x86.Set("PENTIUM4", Napi::String::New(env, "pentium4"));
    x86.Set("CORE2", Napi::String::New(env, "core2"));
    x86.Set("COREI7", Napi::String::New(env, "corei7"));
    x86.Set("SKYLAKE", Napi::String::New(env, "skylake"));
    x86.Set("ALDERLAKE", Napi::String::New(env, "alderlake"));
    obj.Set("X86", x86);

    // ARM CPUs
    Napi::Object arm = Napi::Object::New(env);
    arm.Set("GENERIC", Napi::String::New(env, "generic"));
    arm.Set("CORTEX_A7", Napi::String::New(env, "cortex-a7"));
    arm.Set("CORTEX_A8", Napi::String::New(env, "cortex-a8"));
    arm.Set("CORTEX_A9", Napi::String::New(env, "cortex-a9"));
    arm.Set("CORTEX_A15", Napi::String::New(env, "cortex-a15"));
    arm.Set("CORTEX_A53", Napi::String::New(env, "cortex-a53"));
    arm.Set("CORTEX_A72", Napi::String::New(env, "cortex-a72"));
    arm.Set("CORTEX_M0", Napi::String::New(env, "cortex-m0"));
    arm.Set("CORTEX_M3", Napi::String::New(env, "cortex-m3"));
    arm.Set("CORTEX_M4", Napi::String::New(env, "cortex-m4"));
    obj.Set("ARM", arm);

    // ARM64 CPUs
    Napi::Object arm64 = Napi::Object::New(env);
    arm64.Set("GENERIC", Napi::String::New(env, "generic"));
    arm64.Set("CORTEX_A53", Napi::String::New(env, "cortex-a53"));
    arm64.Set("CORTEX_A72", Napi::String::New(env, "cortex-a72"));
    arm64.Set("CORTEX_A76", Napi::String::New(env, "cortex-a76"));
    arm64.Set("APPLE_A12", Napi::String::New(env, "apple-a12"));
    arm64.Set("APPLE_A14", Napi::String::New(env, "apple-a14"));
    arm64.Set("APPLE_M1", Napi::String::New(env, "apple-m1"));
    obj.Set("ARM64", arm64);

    return obj;
}

// Create FEATURES presets
static Napi::Object CreateFeaturesObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // x86 features
    Napi::Object x86 = Napi::Object::New(env);
    x86.Set("SSE", Napi::String::New(env, "+sse"));
    x86.Set("SSE2", Napi::String::New(env, "+sse2"));
    x86.Set("SSE3", Napi::String::New(env, "+sse3"));
    x86.Set("SSSE3", Napi::String::New(env, "+ssse3"));
    x86.Set("SSE4_1", Napi::String::New(env, "+sse4.1"));
    x86.Set("SSE4_2", Napi::String::New(env, "+sse4.2"));
    x86.Set("AVX", Napi::String::New(env, "+avx"));
    x86.Set("AVX2", Napi::String::New(env, "+avx2"));
    x86.Set("AVX512F", Napi::String::New(env, "+avx512f"));
    obj.Set("X86", x86);

    // ARM features
    Napi::Object arm = Napi::Object::New(env);
    arm.Set("NEON", Napi::String::New(env, "+neon"));
    arm.Set("VFP3", Napi::String::New(env, "+vfp3"));
    arm.Set("VFP4", Napi::String::New(env, "+vfp4"));
    obj.Set("ARM", arm);

    return obj;
}

// Module initialization
Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize LLVM targets
    InitializeLLVMTargets();

    // Initialize wrapper class
    LlvmMcWrapper::Init(env, exports);

    // Export version function
    exports.Set("version", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        return GetVersion(info);
    }));

    // Export getTargets function
    exports.Set("getTargets", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        return GetTargets(info);
    }));

    // Export constants
    exports.Set("TRIPLE", CreateTripleObject(env));
    exports.Set("SYNTAX", CreateSyntaxObject(env));
    exports.Set("OPTION", CreateOptionObject(env));
    exports.Set("ERR", CreateErrObject(env));
    exports.Set("CPU", CreateCpuObject(env));
    exports.Set("FEATURES", CreateFeaturesObject(env));

    return exports;
}

NODE_API_MODULE(hexcore_llvm_mc, Init)
