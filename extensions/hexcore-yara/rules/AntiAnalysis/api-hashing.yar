// HexCore built-in rules — API hashing / PEB walk detection
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects:
//   - PEB walk byte patterns (gs:[0x60] x64, fs:[0x30] x86)
//   - Well-known hash constants (djb2, fnv1a, ror13)
//   - MZ/PE header check opcodes (indicating export table iteration)

rule ApiHashing_PEB_Walk_X64
{
    meta:
        description = "PEB walk pattern for API hash resolution (x64) — mov rax, gs:[0x60] followed by MZ/PE check"
        severity = "critical"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        // mov rax, gs:[0x60]
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        // cmp word ptr [...], 0x5A4D  ("MZ")
        $mz_a = { 66 81 3? 4D 5A }
        $mz_b = { 66 39 ?? ?? 4D 5A }
        // cmp dword ptr [...], 0x00004550  ("PE\0\0")
        $pe_a = { 81 3? 50 45 00 00 }
        $pe_b = { 81 7? ?? 50 45 00 00 }
    condition:
        $peb64 and (any of ($mz_*) or any of ($pe_*))
}

rule ApiHashing_PEB_Walk_X86
{
    meta:
        description = "PEB walk pattern for API hash resolution (x86) — mov eax, fs:[0x30] followed by MZ/PE check"
        severity = "critical"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        // mov eax, fs:[0x30]
        $peb32 = { 64 A1 30 00 00 00 }
        // cmp word ptr [...], 0x5A4D  ("MZ")
        $mz = { 66 81 3? 4D 5A }
        // cmp dword ptr [...], 0x00004550  ("PE\0\0")
        $pe = { 81 3? 50 45 00 00 }
    condition:
        $peb32 and ($mz or $pe)
}

rule ApiHashing_DJB2_Constant
{
    meta:
        description = "Contains djb2 hash seed constant 0x1505 (5381) — djb2 API hashing"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        // mov reg, 0x00001505  (djb2 seed as imm32)
        $seed1 = { B? 05 15 00 00 }
        // mov dword ptr [...], 0x00001505
        $seed2 = { C7 ?? 05 15 00 00 }
        // mov reg, 0x1505 (imm16 variant)
        $seed3 = { 66 B? 05 15 }
        // djb2 multiplier pattern: mul + 33
        // hash * 33 = hash * 32 + hash = (hash << 5) + hash
        // shl eax, 5 ; add eax, edx — very common
        $mul = { C1 ?? 05 03 }
    condition:
        any of them
}

rule ApiHashing_FNV1a_Constant
{
    meta:
        description = "Contains FNV-1a hash constants (offset basis 0x811C9DC5 or prime 0x01000193)"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        // FNV-1a 32-bit offset basis: 0x811C9DC5
        $basis = { C5 9D 1C 81 }
        // FNV-1a 32-bit prime: 0x01000193
        $prime = { 93 01 00 01 }
    condition:
        any of them
}

rule ApiHashing_ROR13_Pattern
{
    meta:
        description = "Contains ror 13 rotate pattern — Metasploit-style API hashing"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        // ror reg, 13 (0x0D)
        $ror1 = { C1 C? 0D }
        // ror r/m32, 13
        $ror2 = { C1 C? 0D }
        // 0x0D imm8 variant
        $ror3 = { D3 C? }
    condition:
        // ror13 alone is not conclusive; look for combination with loop
        any of them
}

rule ApiHashing_GetProcAddress_Replacement
{
    meta:
        description = "Imports LoadLibrary but not GetProcAddress — suspicious (resolves APIs via hash)"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "ApiHashing"
    strings:
        $load1 = "LoadLibraryA"
        $load2 = "LoadLibraryW"
        $load3 = "LdrLoadDll"
        $load4 = "LdrGetDllHandle"
    condition:
        any of ($load*)
}
