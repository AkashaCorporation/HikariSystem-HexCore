// HexCore built-in rules — anti-debug detection
// Shipped with hexcore-yara extension, loaded from rules/ on activation.
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects:
//   - Import-based anti-debug APIs (IsDebuggerPresent, CheckRemoteDebuggerPresent, etc.)
//   - Direct PEB access byte patterns (gs:[0x60] x64, fs:[0x30] x86)
//   - Privileged opcodes used for anti-analysis (rdtsc, rdtscp, int 2d)

rule AntiDebug_API_IsDebuggerPresent
{
    meta:
        description = "Imports kernel32!IsDebuggerPresent — classic anti-debug check"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $api = "IsDebuggerPresent"
    condition:
        any of them
}

rule AntiDebug_API_CheckRemoteDebuggerPresent
{
    meta:
        description = "Imports kernel32!CheckRemoteDebuggerPresent — anti-debug"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $api = "CheckRemoteDebuggerPresent"
    condition:
        any of them
}

rule AntiDebug_API_NtQueryInformationProcess
{
    meta:
        description = "Imports ntdll!NtQueryInformationProcess — anti-debug via ProcessDebugPort/ProcessDebugFlags"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $api = "NtQueryInformationProcess"
    condition:
        any of them
}

rule AntiDebug_API_DebugActiveProcess
{
    meta:
        description = "Imports kernel32!DebugActiveProcess — self-debug trick to prevent debuggers"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $api = "DebugActiveProcess"
    condition:
        any of them
}

rule AntiDebug_API_OutputDebugString
{
    meta:
        description = "Imports kernel32!OutputDebugStringA/W — can be used as timing check anti-debug"
        severity = "medium"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $api1 = "OutputDebugStringA"
        $api2 = "OutputDebugStringW"
    condition:
        any of them
}

rule AntiDebug_PEB_Access_X64
{
    meta:
        description = "Direct x64 PEB access via gs:[0x60] — common anti-debug / API hash resolution"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        // mov rax, gs:[0x60] — full encoding
        $peb64_a = { 65 48 8B 04 25 60 00 00 00 }
        // mov rax, qword ptr gs:[0x60] — alternative encoding
        $peb64_b = { 65 48 A1 60 00 00 00 00 00 00 00 }
    condition:
        any of them
}

rule AntiDebug_PEB_Access_X86
{
    meta:
        description = "Direct x86 PEB access via fs:[0x30] — classic anti-debug technique"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        // mov eax, fs:[0x30]
        $peb32 = { 64 A1 30 00 00 00 }
    condition:
        any of them
}

rule AntiDebug_Timing_RDTSC
{
    meta:
        description = "Uses rdtsc instruction — often paired with timing checks for anti-emulation"
        severity = "medium"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiAnalysis"
    strings:
        // rdtsc: 0F 31
        $rdtsc = { 0F 31 }
        // rdtscp: 0F 01 F9
        $rdtscp = { 0F 01 F9 }
    condition:
        any of them
}

rule AntiDebug_INT_2D
{
    meta:
        description = "Uses int 2d — legacy kernel debugger detection"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        $int2d = { CD 2D }
    condition:
        $int2d
}

rule AntiDebug_Hardware_Breakpoint_Check
{
    meta:
        description = "Reads DR0-DR7 debug registers — detects hardware breakpoints"
        severity = "high"
        author = "HexCore"
        category = "anti-analysis"
        family = "AntiDebug"
    strings:
        // GetThreadContext / SetThreadContext are typical companions
        $api1 = "GetThreadContext"
        $api2 = "SetThreadContext"
        // Also check for ZwGetContextThread (syscall variant)
        $api3 = "ZwGetContextThread"
        $api4 = "NtGetContextThread"
    condition:
        2 of them
}
