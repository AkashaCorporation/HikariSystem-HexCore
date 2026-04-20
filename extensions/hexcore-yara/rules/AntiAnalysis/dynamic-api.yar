// HexCore built-in rules — dynamic API resolution / evasion imports
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects:
//   - GetProcAddress + LoadLibrary combo (classic runtime resolution)
//   - Reflective DLL loading indicators
//   - NT syscall stubs

rule DynamicAPI_GetProcAddress_LoadLibrary
{
    meta:
        description = "Classic dynamic API resolution — GetProcAddress + LoadLibraryA combo"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "DynamicAPI"
    strings:
        $gpa = "GetProcAddress"
        $ll1 = "LoadLibraryA"
        $ll2 = "LoadLibraryW"
        $ll3 = "LoadLibraryExA"
        $ll4 = "LoadLibraryExW"
    condition:
        $gpa and any of ($ll*)
}

rule DynamicAPI_GetModuleHandle_GetProcAddress
{
    meta:
        description = "Uses GetModuleHandle + GetProcAddress — dynamic resolution from already-loaded DLL"
        severity = "medium"
        author = "HexCore"
        category = "evasion"
        family = "DynamicAPI"
    strings:
        $gmh1 = "GetModuleHandleA"
        $gmh2 = "GetModuleHandleW"
        $gpa = "GetProcAddress"
    condition:
        any of ($gmh*) and $gpa
}

rule DynamicAPI_LdrLoadDll
{
    meta:
        description = "Uses ntdll!LdrLoadDll directly — bypasses kernel32 loader, evades hooks"
        severity = "high"
        author = "HexCore"
        category = "evasion"
        family = "DynamicAPI"
    strings:
        $ldr1 = "LdrLoadDll"
        $ldr2 = "LdrGetProcedureAddress"
        $ldr3 = "LdrGetDllHandle"
    condition:
        any of them
}

rule DynamicAPI_Reflective_Loading
{
    meta:
        description = "Reflective DLL loading indicators — ReflectiveLoader export or ManualMap"
        severity = "critical"
        author = "HexCore"
        category = "evasion"
        family = "ReflectiveDLL"
    strings:
        $s1 = "ReflectiveLoader"
        $s2 = "ReflectivePESize"
        $s3 = "ManualMap"
    condition:
        any of them
}

rule DynamicAPI_Direct_Syscalls
{
    meta:
        description = "Direct syscall invocation — evades userland API hooks"
        severity = "critical"
        author = "HexCore"
        category = "evasion"
        family = "DirectSyscall"
    strings:
        // mov eax, SSN ; syscall ; ret
        // Typical pattern: 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3
        $ss1 = { 4C 8B D1 B8 ?? ?? 00 00 0F 05 C3 }
        // mov r10, rcx ; mov eax, SSN ; syscall ; ret (x64 convention)
        $ss2 = { 49 89 CA B8 ?? ?? 00 00 0F 05 C3 }
    condition:
        any of them
}

rule DynamicAPI_Process_Injection_APIs
{
    meta:
        description = "Process injection API combo — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread"
        severity = "critical"
        author = "HexCore"
        category = "injection"
        family = "ProcessInjection"
    strings:
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $create = "CreateRemoteThread"
        $createEx = "CreateRemoteThreadEx"
        $nt_alloc = "NtAllocateVirtualMemory"
        $nt_write = "NtWriteVirtualMemory"
    condition:
        ($alloc and $write and ($create or $createEx)) or
        ($nt_alloc and $nt_write)
}
