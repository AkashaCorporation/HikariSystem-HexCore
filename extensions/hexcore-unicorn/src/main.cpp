#include <napi.h>
#include "unicorn_wrapper.h"
#include <unicorn/unicorn.h>
#include <sstream>
#include <string>

// X86 register definitions
#include <unicorn/x86.h>

// ARM register definitions
#ifdef UC_ARCH_ARM
#include <unicorn/arm.h>
#endif

// ARM64 register definitions
#ifdef UC_ARCH_ARM64
#include <unicorn/arm64.h>
#endif

// MIPS register definitions
#ifdef UC_ARCH_MIPS
#include <unicorn/mips.h>
#endif

// SPARC register definitions
#ifdef UC_ARCH_SPARC
#include <unicorn/sparc.h>
#endif

// PPC register definitions
#ifdef UC_ARCH_PPC
#include <unicorn/ppc.h>
#endif

// M68K register definitions
#ifdef UC_ARCH_M68K
#include <unicorn/m68k.h>
#endif

// RISCV register definitions
#ifdef UC_ARCH_RISCV
#include <unicorn/riscv.h>
#endif

// S390X register definitions
#ifdef UC_ARCH_S390X
#include <unicorn/s390x.h>
#endif

// ============== Helper Macros ==============

#define SET_CONST(obj, name, val) obj.Set(#name, Napi::Number::New(env, val))
#define SET_CONST_NAME(obj, name) obj.Set(#name, Napi::Number::New(env, name))

// ============== Architecture Constants ==============

Napi::Object CreateArchObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    SET_CONST_NAME(obj, UC_ARCH_ARM);
    SET_CONST_NAME(obj, UC_ARCH_ARM64);
    SET_CONST_NAME(obj, UC_ARCH_MIPS);
    SET_CONST_NAME(obj, UC_ARCH_X86);
    SET_CONST_NAME(obj, UC_ARCH_PPC);
    SET_CONST_NAME(obj, UC_ARCH_SPARC);
    SET_CONST_NAME(obj, UC_ARCH_M68K);
#ifdef UC_ARCH_RISCV
    SET_CONST_NAME(obj, UC_ARCH_RISCV);
#endif
#ifdef UC_ARCH_S390X
    SET_CONST_NAME(obj, UC_ARCH_S390X);
#endif
#ifdef UC_ARCH_TRICORE
    SET_CONST_NAME(obj, UC_ARCH_TRICORE);
#endif

    // Friendly names
    obj.Set("ARM", Napi::Number::New(env, UC_ARCH_ARM));
    obj.Set("ARM64", Napi::Number::New(env, UC_ARCH_ARM64));
    obj.Set("MIPS", Napi::Number::New(env, UC_ARCH_MIPS));
    obj.Set("X86", Napi::Number::New(env, UC_ARCH_X86));
    obj.Set("PPC", Napi::Number::New(env, UC_ARCH_PPC));
    obj.Set("SPARC", Napi::Number::New(env, UC_ARCH_SPARC));
    obj.Set("M68K", Napi::Number::New(env, UC_ARCH_M68K));
#ifdef UC_ARCH_RISCV
    obj.Set("RISCV", Napi::Number::New(env, UC_ARCH_RISCV));
#endif
#ifdef UC_ARCH_S390X
    obj.Set("S390X", Napi::Number::New(env, UC_ARCH_S390X));
#endif
#ifdef UC_ARCH_TRICORE
    obj.Set("TRICORE", Napi::Number::New(env, UC_ARCH_TRICORE));
#endif

    return obj;
}

// ============== Mode Constants ==============

Napi::Object CreateModeObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // Generic modes
    SET_CONST_NAME(obj, UC_MODE_LITTLE_ENDIAN);
    SET_CONST_NAME(obj, UC_MODE_BIG_ENDIAN);

    // ARM modes
    SET_CONST_NAME(obj, UC_MODE_ARM);
    SET_CONST_NAME(obj, UC_MODE_THUMB);
#ifdef UC_MODE_MCLASS
    SET_CONST_NAME(obj, UC_MODE_MCLASS);
#endif
#ifdef UC_MODE_V8
    SET_CONST_NAME(obj, UC_MODE_V8);
#endif
#ifdef UC_MODE_ARMBE8
    SET_CONST_NAME(obj, UC_MODE_ARMBE8);
#endif

    // X86 modes
    SET_CONST_NAME(obj, UC_MODE_16);
    SET_CONST_NAME(obj, UC_MODE_32);
    SET_CONST_NAME(obj, UC_MODE_64);

    // MIPS modes
    SET_CONST_NAME(obj, UC_MODE_MIPS3);
    SET_CONST_NAME(obj, UC_MODE_MIPS32R6);
    SET_CONST_NAME(obj, UC_MODE_MIPS32);
    SET_CONST_NAME(obj, UC_MODE_MIPS64);

    // SPARC modes
    SET_CONST_NAME(obj, UC_MODE_SPARC32);
    SET_CONST_NAME(obj, UC_MODE_SPARC64);
#ifdef UC_MODE_V9
    SET_CONST_NAME(obj, UC_MODE_V9);
#endif

    // PPC modes
#ifdef UC_MODE_PPC32
    SET_CONST_NAME(obj, UC_MODE_PPC32);
#endif
#ifdef UC_MODE_PPC64
    SET_CONST_NAME(obj, UC_MODE_PPC64);
#endif
#ifdef UC_MODE_QPX
    SET_CONST_NAME(obj, UC_MODE_QPX);
#endif

    // RISCV modes
#ifdef UC_MODE_RISCV32
    SET_CONST_NAME(obj, UC_MODE_RISCV32);
#endif
#ifdef UC_MODE_RISCV64
    SET_CONST_NAME(obj, UC_MODE_RISCV64);
#endif

    // Friendly names
    obj.Set("LITTLE_ENDIAN", Napi::Number::New(env, UC_MODE_LITTLE_ENDIAN));
    obj.Set("BIG_ENDIAN", Napi::Number::New(env, UC_MODE_BIG_ENDIAN));
    obj.Set("MODE_16", Napi::Number::New(env, UC_MODE_16));
    obj.Set("MODE_32", Napi::Number::New(env, UC_MODE_32));
    obj.Set("MODE_64", Napi::Number::New(env, UC_MODE_64));

    return obj;
}

// ============== Memory Protection Constants ==============

Napi::Object CreateProtObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    SET_CONST_NAME(obj, UC_PROT_NONE);
    SET_CONST_NAME(obj, UC_PROT_READ);
    SET_CONST_NAME(obj, UC_PROT_WRITE);
    SET_CONST_NAME(obj, UC_PROT_EXEC);
    SET_CONST_NAME(obj, UC_PROT_ALL);

    // Friendly names
    obj.Set("NONE", Napi::Number::New(env, UC_PROT_NONE));
    obj.Set("READ", Napi::Number::New(env, UC_PROT_READ));
    obj.Set("WRITE", Napi::Number::New(env, UC_PROT_WRITE));
    obj.Set("EXEC", Napi::Number::New(env, UC_PROT_EXEC));
    obj.Set("ALL", Napi::Number::New(env, UC_PROT_ALL));
    obj.Set("RW", Napi::Number::New(env, UC_PROT_READ | UC_PROT_WRITE));
    obj.Set("RX", Napi::Number::New(env, UC_PROT_READ | UC_PROT_EXEC));
    obj.Set("RWX", Napi::Number::New(env, UC_PROT_ALL));

    return obj;
}

// ============== Hook Type Constants ==============

Napi::Object CreateHookObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // Interrupt hooks
    SET_CONST_NAME(obj, UC_HOOK_INTR);

    // Instruction hooks
    SET_CONST_NAME(obj, UC_HOOK_INSN);

    // Code hooks
    SET_CONST_NAME(obj, UC_HOOK_CODE);

    // Block hooks
    SET_CONST_NAME(obj, UC_HOOK_BLOCK);

    // Memory hooks - unmapped
    SET_CONST_NAME(obj, UC_HOOK_MEM_READ_UNMAPPED);
    SET_CONST_NAME(obj, UC_HOOK_MEM_WRITE_UNMAPPED);
    SET_CONST_NAME(obj, UC_HOOK_MEM_FETCH_UNMAPPED);

    // Memory hooks - protected
    SET_CONST_NAME(obj, UC_HOOK_MEM_READ_PROT);
    SET_CONST_NAME(obj, UC_HOOK_MEM_WRITE_PROT);
    SET_CONST_NAME(obj, UC_HOOK_MEM_FETCH_PROT);

    // Memory hooks - valid access
    SET_CONST_NAME(obj, UC_HOOK_MEM_READ);
    SET_CONST_NAME(obj, UC_HOOK_MEM_WRITE);
    SET_CONST_NAME(obj, UC_HOOK_MEM_FETCH);

    // Combined memory hooks
    SET_CONST_NAME(obj, UC_HOOK_MEM_READ_AFTER);
    SET_CONST_NAME(obj, UC_HOOK_MEM_UNMAPPED);
    SET_CONST_NAME(obj, UC_HOOK_MEM_PROT);
    SET_CONST_NAME(obj, UC_HOOK_MEM_READ_INVALID);
    SET_CONST_NAME(obj, UC_HOOK_MEM_WRITE_INVALID);
    SET_CONST_NAME(obj, UC_HOOK_MEM_FETCH_INVALID);
    SET_CONST_NAME(obj, UC_HOOK_MEM_INVALID);
    SET_CONST_NAME(obj, UC_HOOK_MEM_VALID);

#ifdef UC_HOOK_INSN_INVALID
    SET_CONST_NAME(obj, UC_HOOK_INSN_INVALID);
#endif

#ifdef UC_HOOK_EDGE_GENERATED
    SET_CONST_NAME(obj, UC_HOOK_EDGE_GENERATED);
#endif

#ifdef UC_HOOK_TCG_OPCODE
    SET_CONST_NAME(obj, UC_HOOK_TCG_OPCODE);
#endif

    // Friendly names
    obj.Set("INTR", Napi::Number::New(env, UC_HOOK_INTR));
    obj.Set("INSN", Napi::Number::New(env, UC_HOOK_INSN));
    obj.Set("CODE", Napi::Number::New(env, UC_HOOK_CODE));
    obj.Set("BLOCK", Napi::Number::New(env, UC_HOOK_BLOCK));
    obj.Set("MEM_READ", Napi::Number::New(env, UC_HOOK_MEM_READ));
    obj.Set("MEM_WRITE", Napi::Number::New(env, UC_HOOK_MEM_WRITE));
    obj.Set("MEM_FETCH", Napi::Number::New(env, UC_HOOK_MEM_FETCH));
    obj.Set("MEM_ALL", Napi::Number::New(env, UC_HOOK_MEM_VALID));

    return obj;
}

// ============== Memory Type Constants ==============

Napi::Object CreateMemTypeObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    SET_CONST_NAME(obj, UC_MEM_READ);
    SET_CONST_NAME(obj, UC_MEM_WRITE);
    SET_CONST_NAME(obj, UC_MEM_FETCH);
    SET_CONST_NAME(obj, UC_MEM_READ_UNMAPPED);
    SET_CONST_NAME(obj, UC_MEM_WRITE_UNMAPPED);
    SET_CONST_NAME(obj, UC_MEM_FETCH_UNMAPPED);
    SET_CONST_NAME(obj, UC_MEM_WRITE_PROT);
    SET_CONST_NAME(obj, UC_MEM_READ_PROT);
    SET_CONST_NAME(obj, UC_MEM_FETCH_PROT);
    SET_CONST_NAME(obj, UC_MEM_READ_AFTER);

    return obj;
}

// ============== Query Type Constants ==============

Napi::Object CreateQueryObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    SET_CONST_NAME(obj, UC_QUERY_MODE);
    SET_CONST_NAME(obj, UC_QUERY_PAGE_SIZE);
    SET_CONST_NAME(obj, UC_QUERY_ARCH);
#ifdef UC_QUERY_TIMEOUT
    SET_CONST_NAME(obj, UC_QUERY_TIMEOUT);
#endif

    // Friendly names
    obj.Set("MODE", Napi::Number::New(env, UC_QUERY_MODE));
    obj.Set("PAGE_SIZE", Napi::Number::New(env, UC_QUERY_PAGE_SIZE));
    obj.Set("ARCH", Napi::Number::New(env, UC_QUERY_ARCH));

    return obj;
}

// ============== Error Constants ==============

Napi::Object CreateErrObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    SET_CONST_NAME(obj, UC_ERR_OK);
    SET_CONST_NAME(obj, UC_ERR_NOMEM);
    SET_CONST_NAME(obj, UC_ERR_ARCH);
    SET_CONST_NAME(obj, UC_ERR_HANDLE);
    SET_CONST_NAME(obj, UC_ERR_MODE);
    SET_CONST_NAME(obj, UC_ERR_VERSION);
    SET_CONST_NAME(obj, UC_ERR_READ_UNMAPPED);
    SET_CONST_NAME(obj, UC_ERR_WRITE_UNMAPPED);
    SET_CONST_NAME(obj, UC_ERR_FETCH_UNMAPPED);
    SET_CONST_NAME(obj, UC_ERR_HOOK);
    SET_CONST_NAME(obj, UC_ERR_INSN_INVALID);
    SET_CONST_NAME(obj, UC_ERR_MAP);
    SET_CONST_NAME(obj, UC_ERR_WRITE_PROT);
    SET_CONST_NAME(obj, UC_ERR_READ_PROT);
    SET_CONST_NAME(obj, UC_ERR_FETCH_PROT);
    SET_CONST_NAME(obj, UC_ERR_ARG);
    SET_CONST_NAME(obj, UC_ERR_READ_UNALIGNED);
    SET_CONST_NAME(obj, UC_ERR_WRITE_UNALIGNED);
    SET_CONST_NAME(obj, UC_ERR_FETCH_UNALIGNED);
    SET_CONST_NAME(obj, UC_ERR_HOOK_EXIST);
    SET_CONST_NAME(obj, UC_ERR_RESOURCE);
    SET_CONST_NAME(obj, UC_ERR_EXCEPTION);

    // Friendly names
    obj.Set("OK", Napi::Number::New(env, UC_ERR_OK));
    obj.Set("NOMEM", Napi::Number::New(env, UC_ERR_NOMEM));
    obj.Set("ARCH", Napi::Number::New(env, UC_ERR_ARCH));
    obj.Set("HANDLE", Napi::Number::New(env, UC_ERR_HANDLE));
    obj.Set("MODE", Napi::Number::New(env, UC_ERR_MODE));

    return obj;
}

// ============== X86 Register Constants ==============

Napi::Object CreateX86RegObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // 64-bit general purpose registers
    obj.Set("RAX", Napi::Number::New(env, UC_X86_REG_RAX));
    obj.Set("RBX", Napi::Number::New(env, UC_X86_REG_RBX));
    obj.Set("RCX", Napi::Number::New(env, UC_X86_REG_RCX));
    obj.Set("RDX", Napi::Number::New(env, UC_X86_REG_RDX));
    obj.Set("RSI", Napi::Number::New(env, UC_X86_REG_RSI));
    obj.Set("RDI", Napi::Number::New(env, UC_X86_REG_RDI));
    obj.Set("RBP", Napi::Number::New(env, UC_X86_REG_RBP));
    obj.Set("RSP", Napi::Number::New(env, UC_X86_REG_RSP));
    obj.Set("R8", Napi::Number::New(env, UC_X86_REG_R8));
    obj.Set("R9", Napi::Number::New(env, UC_X86_REG_R9));
    obj.Set("R10", Napi::Number::New(env, UC_X86_REG_R10));
    obj.Set("R11", Napi::Number::New(env, UC_X86_REG_R11));
    obj.Set("R12", Napi::Number::New(env, UC_X86_REG_R12));
    obj.Set("R13", Napi::Number::New(env, UC_X86_REG_R13));
    obj.Set("R14", Napi::Number::New(env, UC_X86_REG_R14));
    obj.Set("R15", Napi::Number::New(env, UC_X86_REG_R15));
    obj.Set("RIP", Napi::Number::New(env, UC_X86_REG_RIP));
    obj.Set("RFLAGS", Napi::Number::New(env, UC_X86_REG_RFLAGS));

    // 32-bit general purpose registers
    obj.Set("EAX", Napi::Number::New(env, UC_X86_REG_EAX));
    obj.Set("EBX", Napi::Number::New(env, UC_X86_REG_EBX));
    obj.Set("ECX", Napi::Number::New(env, UC_X86_REG_ECX));
    obj.Set("EDX", Napi::Number::New(env, UC_X86_REG_EDX));
    obj.Set("ESI", Napi::Number::New(env, UC_X86_REG_ESI));
    obj.Set("EDI", Napi::Number::New(env, UC_X86_REG_EDI));
    obj.Set("EBP", Napi::Number::New(env, UC_X86_REG_EBP));
    obj.Set("ESP", Napi::Number::New(env, UC_X86_REG_ESP));
    obj.Set("EIP", Napi::Number::New(env, UC_X86_REG_EIP));
    obj.Set("EFLAGS", Napi::Number::New(env, UC_X86_REG_EFLAGS));

    // 16-bit registers
    obj.Set("AX", Napi::Number::New(env, UC_X86_REG_AX));
    obj.Set("BX", Napi::Number::New(env, UC_X86_REG_BX));
    obj.Set("CX", Napi::Number::New(env, UC_X86_REG_CX));
    obj.Set("DX", Napi::Number::New(env, UC_X86_REG_DX));
    obj.Set("SI", Napi::Number::New(env, UC_X86_REG_SI));
    obj.Set("DI", Napi::Number::New(env, UC_X86_REG_DI));
    obj.Set("BP", Napi::Number::New(env, UC_X86_REG_BP));
    obj.Set("SP", Napi::Number::New(env, UC_X86_REG_SP));
    obj.Set("IP", Napi::Number::New(env, UC_X86_REG_IP));

    // 8-bit registers
    obj.Set("AL", Napi::Number::New(env, UC_X86_REG_AL));
    obj.Set("AH", Napi::Number::New(env, UC_X86_REG_AH));
    obj.Set("BL", Napi::Number::New(env, UC_X86_REG_BL));
    obj.Set("BH", Napi::Number::New(env, UC_X86_REG_BH));
    obj.Set("CL", Napi::Number::New(env, UC_X86_REG_CL));
    obj.Set("CH", Napi::Number::New(env, UC_X86_REG_CH));
    obj.Set("DL", Napi::Number::New(env, UC_X86_REG_DL));
    obj.Set("DH", Napi::Number::New(env, UC_X86_REG_DH));

    // Segment registers
    obj.Set("CS", Napi::Number::New(env, UC_X86_REG_CS));
    obj.Set("DS", Napi::Number::New(env, UC_X86_REG_DS));
    obj.Set("ES", Napi::Number::New(env, UC_X86_REG_ES));
    obj.Set("FS", Napi::Number::New(env, UC_X86_REG_FS));
    obj.Set("GS", Napi::Number::New(env, UC_X86_REG_GS));
    obj.Set("SS", Napi::Number::New(env, UC_X86_REG_SS));

    // Control registers
    obj.Set("CR0", Napi::Number::New(env, UC_X86_REG_CR0));
    obj.Set("CR2", Napi::Number::New(env, UC_X86_REG_CR2));
    obj.Set("CR3", Napi::Number::New(env, UC_X86_REG_CR3));
    obj.Set("CR4", Napi::Number::New(env, UC_X86_REG_CR4));
#ifdef UC_X86_REG_CR8
    obj.Set("CR8", Napi::Number::New(env, UC_X86_REG_CR8));
#endif

    // Debug registers
    obj.Set("DR0", Napi::Number::New(env, UC_X86_REG_DR0));
    obj.Set("DR1", Napi::Number::New(env, UC_X86_REG_DR1));
    obj.Set("DR2", Napi::Number::New(env, UC_X86_REG_DR2));
    obj.Set("DR3", Napi::Number::New(env, UC_X86_REG_DR3));
    obj.Set("DR6", Napi::Number::New(env, UC_X86_REG_DR6));
    obj.Set("DR7", Napi::Number::New(env, UC_X86_REG_DR7));

    // FPU registers
    obj.Set("FP0", Napi::Number::New(env, UC_X86_REG_FP0));
    obj.Set("FP1", Napi::Number::New(env, UC_X86_REG_FP1));
    obj.Set("FP2", Napi::Number::New(env, UC_X86_REG_FP2));
    obj.Set("FP3", Napi::Number::New(env, UC_X86_REG_FP3));
    obj.Set("FP4", Napi::Number::New(env, UC_X86_REG_FP4));
    obj.Set("FP5", Napi::Number::New(env, UC_X86_REG_FP5));
    obj.Set("FP6", Napi::Number::New(env, UC_X86_REG_FP6));
    obj.Set("FP7", Napi::Number::New(env, UC_X86_REG_FP7));

    // XMM registers
    obj.Set("XMM0", Napi::Number::New(env, UC_X86_REG_XMM0));
    obj.Set("XMM1", Napi::Number::New(env, UC_X86_REG_XMM1));
    obj.Set("XMM2", Napi::Number::New(env, UC_X86_REG_XMM2));
    obj.Set("XMM3", Napi::Number::New(env, UC_X86_REG_XMM3));
    obj.Set("XMM4", Napi::Number::New(env, UC_X86_REG_XMM4));
    obj.Set("XMM5", Napi::Number::New(env, UC_X86_REG_XMM5));
    obj.Set("XMM6", Napi::Number::New(env, UC_X86_REG_XMM6));
    obj.Set("XMM7", Napi::Number::New(env, UC_X86_REG_XMM7));
    obj.Set("XMM8", Napi::Number::New(env, UC_X86_REG_XMM8));
    obj.Set("XMM9", Napi::Number::New(env, UC_X86_REG_XMM9));
    obj.Set("XMM10", Napi::Number::New(env, UC_X86_REG_XMM10));
    obj.Set("XMM11", Napi::Number::New(env, UC_X86_REG_XMM11));
    obj.Set("XMM12", Napi::Number::New(env, UC_X86_REG_XMM12));
    obj.Set("XMM13", Napi::Number::New(env, UC_X86_REG_XMM13));
    obj.Set("XMM14", Napi::Number::New(env, UC_X86_REG_XMM14));
    obj.Set("XMM15", Napi::Number::New(env, UC_X86_REG_XMM15));

    // YMM registers (AVX)
    obj.Set("YMM0", Napi::Number::New(env, UC_X86_REG_YMM0));
    obj.Set("YMM1", Napi::Number::New(env, UC_X86_REG_YMM1));
    obj.Set("YMM2", Napi::Number::New(env, UC_X86_REG_YMM2));
    obj.Set("YMM3", Napi::Number::New(env, UC_X86_REG_YMM3));
    obj.Set("YMM4", Napi::Number::New(env, UC_X86_REG_YMM4));
    obj.Set("YMM5", Napi::Number::New(env, UC_X86_REG_YMM5));
    obj.Set("YMM6", Napi::Number::New(env, UC_X86_REG_YMM6));
    obj.Set("YMM7", Napi::Number::New(env, UC_X86_REG_YMM7));
    obj.Set("YMM8", Napi::Number::New(env, UC_X86_REG_YMM8));
    obj.Set("YMM9", Napi::Number::New(env, UC_X86_REG_YMM9));
    obj.Set("YMM10", Napi::Number::New(env, UC_X86_REG_YMM10));
    obj.Set("YMM11", Napi::Number::New(env, UC_X86_REG_YMM11));
    obj.Set("YMM12", Napi::Number::New(env, UC_X86_REG_YMM12));
    obj.Set("YMM13", Napi::Number::New(env, UC_X86_REG_YMM13));
    obj.Set("YMM14", Napi::Number::New(env, UC_X86_REG_YMM14));
    obj.Set("YMM15", Napi::Number::New(env, UC_X86_REG_YMM15));

    // MSR
    obj.Set("MSR", Napi::Number::New(env, UC_X86_REG_MSR));

    // MXCSR
    obj.Set("MXCSR", Napi::Number::New(env, UC_X86_REG_MXCSR));

    // GDT/LDT/IDT
    obj.Set("GDTR", Napi::Number::New(env, UC_X86_REG_GDTR));
    obj.Set("IDTR", Napi::Number::New(env, UC_X86_REG_IDTR));
    obj.Set("LDTR", Napi::Number::New(env, UC_X86_REG_LDTR));
    obj.Set("TR", Napi::Number::New(env, UC_X86_REG_TR));

    // FS/GS base (x86-64)
    obj.Set("FS_BASE", Napi::Number::New(env, UC_X86_REG_FS_BASE));
    obj.Set("GS_BASE", Napi::Number::New(env, UC_X86_REG_GS_BASE));

    return obj;
}

// ============== ARM Register Constants ==============

Napi::Object CreateArmRegObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // General purpose registers
    obj.Set("R0", Napi::Number::New(env, UC_ARM_REG_R0));
    obj.Set("R1", Napi::Number::New(env, UC_ARM_REG_R1));
    obj.Set("R2", Napi::Number::New(env, UC_ARM_REG_R2));
    obj.Set("R3", Napi::Number::New(env, UC_ARM_REG_R3));
    obj.Set("R4", Napi::Number::New(env, UC_ARM_REG_R4));
    obj.Set("R5", Napi::Number::New(env, UC_ARM_REG_R5));
    obj.Set("R6", Napi::Number::New(env, UC_ARM_REG_R6));
    obj.Set("R7", Napi::Number::New(env, UC_ARM_REG_R7));
    obj.Set("R8", Napi::Number::New(env, UC_ARM_REG_R8));
    obj.Set("R9", Napi::Number::New(env, UC_ARM_REG_R9));
    obj.Set("R10", Napi::Number::New(env, UC_ARM_REG_R10));
    obj.Set("R11", Napi::Number::New(env, UC_ARM_REG_R11));
    obj.Set("R12", Napi::Number::New(env, UC_ARM_REG_R12));

    // Special registers
    obj.Set("SP", Napi::Number::New(env, UC_ARM_REG_SP));
    obj.Set("LR", Napi::Number::New(env, UC_ARM_REG_LR));
    obj.Set("PC", Napi::Number::New(env, UC_ARM_REG_PC));
    obj.Set("CPSR", Napi::Number::New(env, UC_ARM_REG_CPSR));
    obj.Set("SPSR", Napi::Number::New(env, UC_ARM_REG_SPSR));

    // Aliases
    obj.Set("FP", Napi::Number::New(env, UC_ARM_REG_R11)); // Frame pointer
    obj.Set("IP", Napi::Number::New(env, UC_ARM_REG_R12)); // Intra-procedure scratch

    return obj;
}

// ============== ARM64 Register Constants ==============

Napi::Object CreateArm64RegObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // 64-bit general purpose registers
    obj.Set("X0", Napi::Number::New(env, UC_ARM64_REG_X0));
    obj.Set("X1", Napi::Number::New(env, UC_ARM64_REG_X1));
    obj.Set("X2", Napi::Number::New(env, UC_ARM64_REG_X2));
    obj.Set("X3", Napi::Number::New(env, UC_ARM64_REG_X3));
    obj.Set("X4", Napi::Number::New(env, UC_ARM64_REG_X4));
    obj.Set("X5", Napi::Number::New(env, UC_ARM64_REG_X5));
    obj.Set("X6", Napi::Number::New(env, UC_ARM64_REG_X6));
    obj.Set("X7", Napi::Number::New(env, UC_ARM64_REG_X7));
    obj.Set("X8", Napi::Number::New(env, UC_ARM64_REG_X8));
    obj.Set("X9", Napi::Number::New(env, UC_ARM64_REG_X9));
    obj.Set("X10", Napi::Number::New(env, UC_ARM64_REG_X10));
    obj.Set("X11", Napi::Number::New(env, UC_ARM64_REG_X11));
    obj.Set("X12", Napi::Number::New(env, UC_ARM64_REG_X12));
    obj.Set("X13", Napi::Number::New(env, UC_ARM64_REG_X13));
    obj.Set("X14", Napi::Number::New(env, UC_ARM64_REG_X14));
    obj.Set("X15", Napi::Number::New(env, UC_ARM64_REG_X15));
    obj.Set("X16", Napi::Number::New(env, UC_ARM64_REG_X16));
    obj.Set("X17", Napi::Number::New(env, UC_ARM64_REG_X17));
    obj.Set("X18", Napi::Number::New(env, UC_ARM64_REG_X18));
    obj.Set("X19", Napi::Number::New(env, UC_ARM64_REG_X19));
    obj.Set("X20", Napi::Number::New(env, UC_ARM64_REG_X20));
    obj.Set("X21", Napi::Number::New(env, UC_ARM64_REG_X21));
    obj.Set("X22", Napi::Number::New(env, UC_ARM64_REG_X22));
    obj.Set("X23", Napi::Number::New(env, UC_ARM64_REG_X23));
    obj.Set("X24", Napi::Number::New(env, UC_ARM64_REG_X24));
    obj.Set("X25", Napi::Number::New(env, UC_ARM64_REG_X25));
    obj.Set("X26", Napi::Number::New(env, UC_ARM64_REG_X26));
    obj.Set("X27", Napi::Number::New(env, UC_ARM64_REG_X27));
    obj.Set("X28", Napi::Number::New(env, UC_ARM64_REG_X28));
    obj.Set("X29", Napi::Number::New(env, UC_ARM64_REG_X29));
    obj.Set("X30", Napi::Number::New(env, UC_ARM64_REG_X30));

    // 32-bit general purpose registers
    obj.Set("W0", Napi::Number::New(env, UC_ARM64_REG_W0));
    obj.Set("W1", Napi::Number::New(env, UC_ARM64_REG_W1));
    obj.Set("W2", Napi::Number::New(env, UC_ARM64_REG_W2));
    obj.Set("W3", Napi::Number::New(env, UC_ARM64_REG_W3));
    obj.Set("W4", Napi::Number::New(env, UC_ARM64_REG_W4));
    obj.Set("W5", Napi::Number::New(env, UC_ARM64_REG_W5));
    obj.Set("W6", Napi::Number::New(env, UC_ARM64_REG_W6));
    obj.Set("W7", Napi::Number::New(env, UC_ARM64_REG_W7));
    obj.Set("W8", Napi::Number::New(env, UC_ARM64_REG_W8));
    obj.Set("W9", Napi::Number::New(env, UC_ARM64_REG_W9));
    obj.Set("W10", Napi::Number::New(env, UC_ARM64_REG_W10));
    obj.Set("W11", Napi::Number::New(env, UC_ARM64_REG_W11));
    obj.Set("W12", Napi::Number::New(env, UC_ARM64_REG_W12));
    obj.Set("W13", Napi::Number::New(env, UC_ARM64_REG_W13));
    obj.Set("W14", Napi::Number::New(env, UC_ARM64_REG_W14));
    obj.Set("W15", Napi::Number::New(env, UC_ARM64_REG_W15));
    obj.Set("W16", Napi::Number::New(env, UC_ARM64_REG_W16));
    obj.Set("W17", Napi::Number::New(env, UC_ARM64_REG_W17));
    obj.Set("W18", Napi::Number::New(env, UC_ARM64_REG_W18));
    obj.Set("W19", Napi::Number::New(env, UC_ARM64_REG_W19));
    obj.Set("W20", Napi::Number::New(env, UC_ARM64_REG_W20));
    obj.Set("W21", Napi::Number::New(env, UC_ARM64_REG_W21));
    obj.Set("W22", Napi::Number::New(env, UC_ARM64_REG_W22));
    obj.Set("W23", Napi::Number::New(env, UC_ARM64_REG_W23));
    obj.Set("W24", Napi::Number::New(env, UC_ARM64_REG_W24));
    obj.Set("W25", Napi::Number::New(env, UC_ARM64_REG_W25));
    obj.Set("W26", Napi::Number::New(env, UC_ARM64_REG_W26));
    obj.Set("W27", Napi::Number::New(env, UC_ARM64_REG_W27));
    obj.Set("W28", Napi::Number::New(env, UC_ARM64_REG_W28));
    obj.Set("W29", Napi::Number::New(env, UC_ARM64_REG_W29));
    obj.Set("W30", Napi::Number::New(env, UC_ARM64_REG_W30));

    // Special registers
    obj.Set("SP", Napi::Number::New(env, UC_ARM64_REG_SP));
    obj.Set("PC", Napi::Number::New(env, UC_ARM64_REG_PC));
    obj.Set("NZCV", Napi::Number::New(env, UC_ARM64_REG_NZCV));

    // Aliases
    obj.Set("FP", Napi::Number::New(env, UC_ARM64_REG_X29)); // Frame pointer
    obj.Set("LR", Napi::Number::New(env, UC_ARM64_REG_X30)); // Link register

    // SIMD/FP registers (partial)
    obj.Set("Q0", Napi::Number::New(env, UC_ARM64_REG_Q0));
    obj.Set("Q1", Napi::Number::New(env, UC_ARM64_REG_Q1));
    obj.Set("Q2", Napi::Number::New(env, UC_ARM64_REG_Q2));
    obj.Set("Q3", Napi::Number::New(env, UC_ARM64_REG_Q3));

    return obj;
}

// ============== MIPS Register Constants ==============

Napi::Object CreateMipsRegObject(Napi::Env env) {
    Napi::Object obj = Napi::Object::New(env);

    // General purpose registers
    obj.Set("ZERO", Napi::Number::New(env, UC_MIPS_REG_0));
    obj.Set("AT", Napi::Number::New(env, UC_MIPS_REG_1));
    obj.Set("V0", Napi::Number::New(env, UC_MIPS_REG_2));
    obj.Set("V1", Napi::Number::New(env, UC_MIPS_REG_3));
    obj.Set("A0", Napi::Number::New(env, UC_MIPS_REG_4));
    obj.Set("A1", Napi::Number::New(env, UC_MIPS_REG_5));
    obj.Set("A2", Napi::Number::New(env, UC_MIPS_REG_6));
    obj.Set("A3", Napi::Number::New(env, UC_MIPS_REG_7));
    obj.Set("T0", Napi::Number::New(env, UC_MIPS_REG_8));
    obj.Set("T1", Napi::Number::New(env, UC_MIPS_REG_9));
    obj.Set("T2", Napi::Number::New(env, UC_MIPS_REG_10));
    obj.Set("T3", Napi::Number::New(env, UC_MIPS_REG_11));
    obj.Set("T4", Napi::Number::New(env, UC_MIPS_REG_12));
    obj.Set("T5", Napi::Number::New(env, UC_MIPS_REG_13));
    obj.Set("T6", Napi::Number::New(env, UC_MIPS_REG_14));
    obj.Set("T7", Napi::Number::New(env, UC_MIPS_REG_15));
    obj.Set("S0", Napi::Number::New(env, UC_MIPS_REG_16));
    obj.Set("S1", Napi::Number::New(env, UC_MIPS_REG_17));
    obj.Set("S2", Napi::Number::New(env, UC_MIPS_REG_18));
    obj.Set("S3", Napi::Number::New(env, UC_MIPS_REG_19));
    obj.Set("S4", Napi::Number::New(env, UC_MIPS_REG_20));
    obj.Set("S5", Napi::Number::New(env, UC_MIPS_REG_21));
    obj.Set("S6", Napi::Number::New(env, UC_MIPS_REG_22));
    obj.Set("S7", Napi::Number::New(env, UC_MIPS_REG_23));
    obj.Set("T8", Napi::Number::New(env, UC_MIPS_REG_24));
    obj.Set("T9", Napi::Number::New(env, UC_MIPS_REG_25));
    obj.Set("K0", Napi::Number::New(env, UC_MIPS_REG_26));
    obj.Set("K1", Napi::Number::New(env, UC_MIPS_REG_27));
    obj.Set("GP", Napi::Number::New(env, UC_MIPS_REG_28));
    obj.Set("SP", Napi::Number::New(env, UC_MIPS_REG_29));
    obj.Set("FP", Napi::Number::New(env, UC_MIPS_REG_30));
    obj.Set("RA", Napi::Number::New(env, UC_MIPS_REG_31));

    // Special registers
    obj.Set("PC", Napi::Number::New(env, UC_MIPS_REG_PC));
    obj.Set("HI", Napi::Number::New(env, UC_MIPS_REG_HI));
    obj.Set("LO", Napi::Number::New(env, UC_MIPS_REG_LO));

    return obj;
}

// ============== Module Initialization ==============

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Initialize classes
    UnicornWrapper::Init(env, exports);
    UnicornContext::Init(env, exports);

    // Export constants
    exports.Set("ARCH", CreateArchObject(env));
    exports.Set("MODE", CreateModeObject(env));
    exports.Set("PROT", CreateProtObject(env));
    exports.Set("HOOK", CreateHookObject(env));
    exports.Set("MEM", CreateMemTypeObject(env));
    exports.Set("QUERY", CreateQueryObject(env));
    exports.Set("ERR", CreateErrObject(env));

    // Architecture-specific register constants
    exports.Set("X86_REG", CreateX86RegObject(env));
    exports.Set("ARM_REG", CreateArmRegObject(env));
    exports.Set("ARM64_REG", CreateArm64RegObject(env));
    exports.Set("MIPS_REG", CreateMipsRegObject(env));

    // Export version function
    exports.Set("version", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        unsigned int major, minor;
        unsigned int combined = uc_version(&major, &minor);

        Napi::Object result = Napi::Object::New(env);
        result.Set("major", Napi::Number::New(env, major));
        result.Set("minor", Napi::Number::New(env, minor));
        result.Set("combined", Napi::Number::New(env, combined));
        result.Set("string", Napi::String::New(env,
            std::to_string(major) + "." + std::to_string(minor)));
        return result;
    }));

    // Export archSupported function
    exports.Set("archSupported", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1) {
            Napi::TypeError::New(env, "Expected 1 argument: arch").ThrowAsJavaScriptException();
            return Napi::Boolean::New(env, false);
        }
        int arch = info[0].As<Napi::Number>().Int32Value();
        bool supported = uc_arch_supported(static_cast<uc_arch>(arch));
        return Napi::Boolean::New(env, supported);
    }));

    // Export strerror function
    exports.Set("strerror", Napi::Function::New(env, [](const Napi::CallbackInfo& info) {
        Napi::Env env = info.Env();
        if (info.Length() < 1) {
            Napi::TypeError::New(env, "Expected 1 argument: errorCode").ThrowAsJavaScriptException();
            return Napi::String::New(env, "");
        }
        int errCode = info[0].As<Napi::Number>().Int32Value();
        const char* message = uc_strerror(static_cast<uc_err>(errCode));
        return Napi::String::New(env, message);
    }));

    return exports;
}

NODE_API_MODULE(hexcore_unicorn, Init)
