// HexCore built-in rules — Ashaka Shadow v3.0 signature family
// Shipped with hexcore-yara extension, loaded from rules/ on activation.
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects the anti-analysis pattern family first seen in
// "Malware HexCore Defeat v3.0 — Ashaka Shadow" (dummy malware used for
// HexCore self-test). Real-world families using the same tradecraft
// (multi-byte XOR with printable key + djb2 PEB walk + dynamic
// ShellExecuteW) trigger the same combo.

rule Ashaka_XOR_Key_Literal
{
    meta:
        description = "Multi-byte XOR key 'Ashaka' (0x41 0x53 0x68 0x61 0x73 0x6B 0x61) in .rdata"
        severity = "high"
        author = "HexCore"
        category = "obfuscation"
        family = "Ashaka"
    strings:
        // Contiguous ASCII "Ashaka" with leading A-S-h pattern
        $key = { 41 53 68 61 73 6B 61 }
    condition:
        $key
}

rule Ashaka_DJB2_IsDebuggerPresent_Hash
{
    meta:
        description = "Pre-computed djb2 hash of 'IsDebuggerPresent' (0xE4524B4E) — indicates hash-based API resolution"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        // Little-endian: 0xE4524B4E
        $hash_le = { 4E 4B 52 E4 }
        // As imm32 in mov: B? 4E 4B 52 E4
        $hash_mov = { B? 4E 4B 52 E4 }
        // As imm32 in cmp: 81 F? 4E 4B 52 E4
        $hash_cmp = { 81 F? 4E 4B 52 E4 }
    condition:
        any of them
}

rule Ashaka_DJB2_Common_API_Hashes
{
    meta:
        description = "Known pre-computed djb2 hashes for common anti-analysis / loader APIs"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        // djb2("IsDebuggerPresent")      = 0xE4524B4E
        $h1 = { 4E 4B 52 E4 }
        // djb2("NtQueryInformationProcess") = 0xCCBE3820
        $h2 = { 20 38 BE CC }
        // djb2("GetProcAddress") = 0xCF31BB1F
        $h3 = { 1F BB 31 CF }
        // djb2("LoadLibraryA") = 0xC8AC8026
        $h4 = { 26 80 AC C8 }
        // djb2("VirtualAlloc") = 0x382D4DE5
        $h5 = { E5 4D 2D 38 }
        // djb2("VirtualProtect") = 0x844FE914
        $h6 = { 14 E9 4F 84 }
        // djb2("CreateRemoteThread") = 0x38E98F7A
        $h7 = { 7A 8F E9 38 }
    condition:
        2 of them
}

rule Ashaka_Dynamic_ShellExecute
{
    meta:
        description = "Dynamic resolution of ShellExecuteW via LoadLibrary + GetProcAddress — beacon or launcher pattern"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $shell32 = "shell32.dll" nocase
        $shellexec_w = "ShellExecuteW"
        $shellexec_a = "ShellExecuteA"
        $shellexec_ex_w = "ShellExecuteExW"
        $shellexec_ex_a = "ShellExecuteExA"
        $load = "LoadLibraryA"
        $gpa = "GetProcAddress"
    condition:
        ($shell32 or any of ($shellexec_*)) and $load and $gpa
}

rule Ashaka_Full_Combo
{
    meta:
        description = "Ashaka Shadow v3 full combo — PEB walk + djb2 + rdtsc timing + VM string checks + dynamic ShellExecute"
        severity = "critical"
        author = "HexCore"
        category = "anti-analysis"
        family = "Ashaka"
    strings:
        // x64 PEB walk
        $peb64 = { 65 48 8B 04 25 60 00 00 00 }
        // djb2 multiplier (hash << 5) + hash
        $djb2_mul = { C1 ?? 05 03 }
        // rdtsc
        $rdtsc = { 0F 31 }
        // cpuid
        $cpuid = { 0F A2 }
        // VM product strings
        $vm1 = "VBoxGuest"
        $vm2 = "VMware"
        $vm3 = "VirtualBox"
        $vm4 = "Sandbox"
        // Registry anti-VM
        $reg = "SOFTWARE\\VirtualBox Guest Additions"
        // Dynamic loader
        $load = "LoadLibraryA"
    condition:
        $peb64
        and $djb2_mul
        and $rdtsc
        and $cpuid
        and 2 of ($vm*)
        and $reg
        and $load
}

rule Ashaka_MultiByte_XOR_Init_Sequence
{
    meta:
        description = "Stack-resident multi-byte XOR blob initialization — 8+ consecutive mov imm8 into [rbp+offset] that form XOR-obfuscated payload"
        severity = "medium"
        author = "HexCore"
        category = "obfuscation"
        family = "Ashaka"
    strings:
        // 6+ mov byte [rbp+N], imm8 in a row (C6 45 NN II)
        // Typical MSVC codegen for `std::vector<unsigned char>` with imm8 initializers
        $burst = {
            C6 45 ?? ??
            C6 45 ?? ??
            C6 45 ?? ??
            C6 45 ?? ??
            C6 45 ?? ??
            C6 45 ?? ??
        }
    condition:
        $burst
}

rule Ashaka_Evasion_Gate_String
{
    meta:
        description = "Contains 'Ashaka' / 'Shadow' banner or debug strings typical of this malware family"
        severity = "medium"
        author = "HexCore"
        category = "attribution"
        family = "Ashaka"
    strings:
        $banner1 = "Ashaka" nocase
        $banner2 = "Shadow" nocase
        // stderr messages from the evasion gate (v3 and v4)
        $err1 = "[!] IsDebuggerPresent" ascii
        $err2 = "[!] PEB.BeingDebugged" ascii
        $err3 = "[!] ProcessDebugPort" ascii
        $err4 = "[!] ProcessWow64Information" ascii     // v4
        $err5 = "[!] rdtsc timing" ascii
        $err6 = "[!] VM Name Detected" ascii            // v4
        $err7 = "[!] VM Registry Detected" ascii        // v4
        $err8 = "[!] CPUID Hypervisor Bit Detected" ascii  // v4
        $err9 = "Hostile. Sleeping" ascii
        $err10 = "[!] Beacon failed" ascii              // v3+v4
    condition:
        ($banner1 and $banner2) or 3 of ($err*)
}

// ===============================================================
// v4.0 "Ashaka Shadow PRO" — polymorphic additions
// ===============================================================

rule Ashaka_v4_Runtime_Key_Generation
{
    meta:
        description = "Runtime XOR key generation via GetTickCount64 ^ GetCurrentProcessId — Ashaka v4 polymorphic pattern"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $api1 = "GetTickCount64"
        $api2 = "GetTickCount"
        $api3 = "GetCurrentProcessId"
        // Dynamic-API combo v4 uses
        $api4 = "LoadLibraryA"
        $api5 = "GetProcAddress"
        // djb2 base seed still present (salt applied at runtime, BUT the
        // base constant 0xE4524B4E is still a compile-time imm32).
        $djb2_isdbg = { 4E 4B 52 E4 }
    condition:
        (any of ($api1, $api2)) and $api3 and $api4 and $api5 and $djb2_isdbg
}

rule Ashaka_v4_Fragmented_Payload_Vector
{
    meta:
        description = "Fragmented payload storage pattern — 3 std::vector<unsigned char> chunks + VirtualAlloc"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        $va = "VirtualAlloc"
        $vf = "VirtualFree"
        // v4 keeps the plaintext URL literal despite runtime XOR re-encode
        $url = "https://github.com/AkashaCorporation" ascii
        $url_w = "https://github.com/AkashaCorporation" wide
    condition:
        $va and $vf and (any of ($url*))
}

rule Ashaka_v4_Salted_DJB2
{
    meta:
        description = "Salted djb2 hashing — base seed 0x1505 AND dynamic salt source (GetTickCount + PID). v4 polymorphic API resolver."
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "Ashaka"
    strings:
        // djb2 seed 0x1505 (as imm32 or imm16)
        $seed_32 = { B? 05 15 00 00 }
        $seed_16 = { 66 B? 05 15 }
        // (hash << 5) + hash  ≡  shl + add pattern
        $mul = { C1 ?? 05 03 }
        // salt sources
        $tick = "GetTickCount"
        $pid  = "GetCurrentProcessId"
    condition:
        (any of ($seed_*)) and $mul and $tick and $pid
}
