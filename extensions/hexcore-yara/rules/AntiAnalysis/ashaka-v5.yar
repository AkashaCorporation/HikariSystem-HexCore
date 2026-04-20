// HexCore built-in rules — Ashaka Mirage v5 / polymorphic evasion
// Companions to ashaka-v3.yar. Target v5 techniques that neither
// v3 nor v4 exercised:
//   - FNV-1a with non-standard primes
//   - KUSER_SHARED_DATA direct memory reads (bypasses rdtsc/cpuid hooks)
//   - Environmental keying via MachineGuid + UserName + VolumeSerial
//   - Fragmented PEB walk (3+ helper functions)
//   - Ordinal imports

rule Ashaka_v5_FNV1a_Custom_Prime
{
    meta:
        description = "FNV-1a hashing with non-standard prime/offset constants — polymorphic API hashing (v5 Ashaka Mirage)"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        // FNV-1a STANDARD 64-bit prime (0x100000001B3) in little-endian
        $fnv_std_prime = { B3 01 00 00 01 00 00 00 }
        // Standard FNV-1a 64-bit offset basis (0xCBF29CE484222325)
        $fnv_std_offset = { 25 23 22 84 E4 9C F2 CB }
        // Golden-ratio-derived 64-bit prime (often used as custom)
        $fnv_gr_prime = { 15 7C 4A 7F B9 79 37 9E }
        // Non-standard offset derived from golden ratio
        $fnv_gr_offset = { 6B 2A ED 8A 62 15 E1 B7 }
        // 64-bit rol/ror + xor hash loop pattern (imul reg64, reg64, imm32 is rare)
        $hash_loop = { 48 0F AF ?? }
    condition:
        (any of ($fnv_gr_*) or ($fnv_std_prime and $fnv_std_offset))
        and #hash_loop > 0
}

rule Ashaka_v5_KUSER_SHARED_DATA_Access
{
    meta:
        description = "Direct reads from KUSER_SHARED_DATA (0x7FFE0000..0x7FFE1000) — timing/version checks that bypass rdtsc/cpuid opcode hooks"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "Ashaka"
    strings:
        // mov ?ax, qword ptr ds:[0x7FFE0008]   — InterruptTime low  (x64)
        // Encoded as 4x-byte disp32 with segment prefix variations
        $ku_int_lo = { 48 A1 08 00 FE 7F 00 00 00 00 }
        $ku_int_hi = { 48 A1 0C 00 FE 7F 00 00 00 00 }
        // mov reg32, [0x7FFE0008] / [0x7FFE0014] / [0x7FFE0320] absolute loads
        // RIP-relative form doesn't reach 0x7FFE0000, so these are absolute 32-bit
        $ku_any_abs = { 67 8B ?? 08 00 FE 7F }
        // Literal 0x7FFE0000 / 0x7FFE0008 / 0x7FFE0014 imm32 (common as mov reg, imm32)
        $ku_lit_00 = { B? 00 00 FE 7F }
        $ku_lit_08 = { B? 08 00 FE 7F }
        $ku_lit_14 = { B? 14 00 FE 7F }
        $ku_lit_20 = { B? 20 00 FE 7F }
        $ku_lit_320 = { B? 20 03 FE 7F }  // TickCountMultiplier
    condition:
        any of ($ku_int_*) or any of ($ku_any_*) or 2 of ($ku_lit_*)
}

rule Ashaka_v5_Environmental_Keying
{
    meta:
        description = "Environmental keying — payload XOR key derived from machine-specific identifiers (MachineGuid / UserName / VolumeSerial). Defeats sandbox emulation that doesn't replicate the target host."
        severity = "critical"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $mg1 = "MachineGuid" ascii
        $mg2 = "MachineGuid" wide
        $cr  = "SOFTWARE\\Microsoft\\Cryptography" ascii
        $crw = "SOFTWARE\\Microsoft\\Cryptography" wide
        $gvi = "GetVolumeInformation"
        $gui = "GetUserName"
        $rqv = "RegQueryValueEx"
        $roa = "RegOpenKeyEx"
    condition:
        (any of ($mg*) or any of ($cr*))
        and $gvi
        and ($gui or $rqv or $roa)
}

rule Ashaka_v5_Fragmented_PEB_Walk
{
    meta:
        description = "PEB walk split across 3+ helper functions — individual pieces (gs:60, MZ check, PE check, hash loop) present but no single yara-window captures them. Heuristic catches the combination via rdata-embedded export directory offsets."
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        $fs30  = { 64 A1 30 00 00 00 }
        // DllBase -> DOS -> NT -> export directory — common offsets
        $dos_magic = { 66 81 3? 4D 5A }
        $nt_magic = { 81 3? 50 45 00 00 }
        // IMAGE_DIRECTORY_ENTRY_EXPORT offset in OptionalHeader (0x70 for PE32, 0x80 for PE32+)
        $export_off64 = { 8B 8? 88 00 00 00 }  // mov reg, [reg + 0x88] — RVA of export dir
        // InMemoryOrderLinks access (offset 0x20 in LDR_DATA_TABLE_ENTRY)
        $imol = { 48 8B ?? 20 }
    condition:
        (any of ($peb64, $fs30))
        and (any of ($dos_magic, $nt_magic))
        and ($export_off64 or $imol)
}

rule Ashaka_v5_Ordinal_Import_Hint
{
    meta:
        description = "GetProcAddress called with small integer cast to LPCSTR — ordinal-based import resolution to avoid plaintext API names"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $gpa = "GetProcAddress"
        // mov rdx/edx, 0x000000?? immediately before a call reg — typical ordinal pass
        // (pattern kept loose — true positives need ordinal < 0x10000)
        $ord_mov64 = { BA ?? ?? 00 00 48 8B ?? E8 }
        $ord_mov32 = { BA ?? ?? 00 00 FF 15 }
    condition:
        $gpa and (any of ($ord_*))
}

rule Ashaka_v5_Opaque_Predicate_Pattern
{
    meta:
        description = "Opaque-always-true predicates like ((x*x + x) & 1) — used to confuse symbolic execution and control-flow analyzers"
        severity = "low"
        author = "HexCore"
        category = "obfuscation"
        family = "Ashaka"
    strings:
        // imul reg, reg (x*x), then add reg, reg (x*x + x), then and reg, 1
        $pred_x2_add_and = {
            0F AF ?? ?? 01 ?? 83 E? 01
        }
    condition:
        #pred_x2_add_and >= 2
}

rule Ashaka_v5_Self_Modifying_Stub
{
    meta:
        description = "VirtualProtect flipping code pages to PAGE_EXECUTE_READWRITE followed by writes — self-decrypting entry stub indicator"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $vp = "VirtualProtect"
        // PAGE_EXECUTE_READWRITE = 0x40 pushed as imm8
        $pageflag = { 6A 40 }
        // XOR loop with register-indirect write — classic decrypt stub
        $xor_write = { 30 ?? 48 FF C? 48 39 ?? 75 }
    condition:
        $vp and $pageflag and $xor_write
}

rule Ashaka_v5_Banner_String
{
    meta:
        description = "Ashaka Mirage v5 self-identification banner — HexCore training dummy"
        severity = "info"
        author = "HexCore"
        category = "attribution"
        family = "Ashaka"
    strings:
        $m1 = "Ashaka Mirage" ascii
        $m2 = "HexCore Training Dummy" ascii
        $m3 = "AkashaCorporation" ascii
    condition:
        any of them
}
