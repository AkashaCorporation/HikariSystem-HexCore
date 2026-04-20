// HexCore built-in rules — obfuscation / packing / encoding detection
// Toggle: hexcore.yara.builtinRulesEnabled (default true)
//
// Detects:
//   - Single-byte XOR loop instruction patterns
//   - Multi-byte XOR with fixed key patterns
//   - Stack string construction sequences
//   - Base64 / hex encoding tables

rule Obfuscation_XOR_Loop_Pattern
{
    meta:
        description = "Single-byte XOR decoder loop instruction pattern"
        severity = "medium"
        author = "HexCore"
        category = "obfuscation"
        family = "XorLoop"
    strings:
        // xor byte [rcx+rax], dl ; inc rax ; cmp rax, rdx ; jb/jl
        // pattern: 30 14 01 48 FF C0 48 39 ?? 72/7C
        $p1 = { 30 ?? ?? 48 FF C? 48 39 ?? 72 }
        // xor dl, [reg+reg] ; ... ; jne
        $p2 = { 30 ?? ?? ?? 4? FF C? ?? 3? ?? 75 }
    condition:
        any of them
}

rule Obfuscation_Stack_String_Construction
{
    meta:
        description = "Stack string construction via repeated mov byte [rbp+N], imm8"
        severity = "medium"
        author = "HexCore"
        category = "obfuscation"
        family = "StackString"
    strings:
        // 4+ consecutive mov byte [rbp+N], imm8 sequences
        // C6 45 ?? ??  (4 bytes each, at least 4 in a row = 16 bytes)
        $p1 = { C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? C6 45 ?? ?? }
        // Same for [rsp+N]
        $p2 = { C6 44 24 ?? ?? C6 44 24 ?? ?? C6 44 24 ?? ?? }
    condition:
        any of them
}

rule Obfuscation_Base64_Alphabet
{
    meta:
        description = "Contains embedded base64 alphabet"
        severity = "low"
        author = "HexCore"
        category = "obfuscation"
        family = "Base64"
    strings:
        // Standard base64 alphabet (first 32 chars)
        $b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    condition:
        $b64
}

rule Obfuscation_Custom_Base64_Alphabet
{
    meta:
        description = "Contains 64-character alphabet-like string (possible custom base64)"
        severity = "medium"
        author = "HexCore"
        category = "obfuscation"
        family = "CustomBase64"
    strings:
        // Hex digits + some extras — typical custom encoder alphabets
        $alpha1 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        $alpha2 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    condition:
        any of them
}

rule Obfuscation_Large_XOR_Immediate
{
    meta:
        description = "Uses multi-byte XOR immediate (indicates obfuscation/encryption)"
        severity = "low"
        author = "HexCore"
        category = "obfuscation"
        family = "XorImm"
    strings:
        // xor reg, imm32 is common enough to NOT flag alone;
        // require presence of multiple XOR instructions nearby
        $p1 = { 48 33 ?? ?? ?? ?? ?? ?? ?? ?? ?? 48 33 }
    condition:
        $p1
}
