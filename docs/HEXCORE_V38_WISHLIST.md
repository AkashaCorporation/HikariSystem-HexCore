# HexCore v3.7/v3.8 Wishlist — Real-World CTF Analysis

> **Data**: 2026-03-12  
> **Origem**: Análise prática de crackme/CTF com HexCore v3.7.0-beta.1  
> **Contexto**: Features que fariam diferença em análise autônoma de binários obfuscados
>
> **⚠️ Status Update (2026-04-19, pré-release v3.8.0)**:
> Nenhum dos 5 itens W1–W5 shipou como comando headless dedicado nas versões v3.7.1 / v3.7.2 / v3.8.0. Eles permanecem como backlog sob a seção **Milestone 7** em `docs/HexCore.3.8.0.md` (itens 7.1 "Cross-references headless", 7.2 "PE IAT Resolution", 7.3 "TLS Callback exposure", 7.4 "XOR brute-force headless"). Dois têm cobertura parcial pré-existente:
> - **W3 TLS Callbacks**: o campo `tlsCallbacks` já aparece no output de `analyzePEHeadless` (`hexcore-peanalyzer/src/peParser.ts`). Um comando dedicado `hexcore.peanalyzer.tlsCallbacks` ainda não existe.
> - **W5 XOR Brute Force**: a lógica já vive dentro de `hexcore-strings extractAdvanced`. Um comando headless isolado não foi extraído.
>
> Os 5 items continuam válidos como pedido de feature — só não bateram o corte da v3.8.0. Próxima minor provável.

---

## Performance Atual (v3.7.0-beta.1)

### ✅ O que funcionou bem

- **Pipeline runner**: 15/15 steps executados sem erro
- **Capstone disasm**: Impecável, rápido (2.2s para analyzeAll de 81KB), preciso
- **Remill lift**: IR de 247KB gerado em ~200ms, sem crash
- **Helix decompile**: Funcionou nos 3 targets (main, sub_4015D5, sub_402560), output legível
- **Hex viewer dumps**: Instantâneos
- **PE Analyzer**: Detectou 14 seções, 65 imports corretamente
- **Report Composer**: Gerou relatório final completo

### ⚠️ O que ficou fraco

1. **Emulação Unicorn crashou no entry point**
   - CRT init do MinGW faz jmp para fora do range esperado
   - Falta suporte a CRT stubs para PE32
   - **Roadmap**: v3.7 item 1.1 (Permissive Memory Mapping) resolve parcialmente

2. **Helix decompile usa tipos x64 em binário x86 32-bit**
   - Output usa `int64_t`, `rbp`, `rsp` para binário PE32
   - Deveria usar `int32_t`, `ebp`, `esp`
   - Output funcional mas confuso

3. **Chamadas indiretas não resolvidas**
   - `call eax`, `call [0x40C16C]` aparecem como `sub_rax()` ou `[WARNING] Indirect call`
   - Nenhuma engine conseguiu resolver
   - **Wishlist**: Item W4 (IAT Resolution) resolveria parcialmente

4. **Sem análise de IAT automática**
   - PE Analyzer detecta imports mas disassembler não cruza com `call [IAT_entry]`
   - Não dá nomes às chamadas indiretas via IAT
   - **Wishlist**: Item W4

---

## Onde Precisei Sair da HexCore

Scripts Python com Capstone/Unicorn direto foram necessários para:

### 1. Disassembly Interativo
- **Problema**: Precisei disassemblar funções específicas seguindo o fluxo iterativamente
  - "O que tem em 0x40141D?"
  - "E o 0x402CD9?"
- **HexCore atual**: `disassembleAtHeadless` funciona mas é um job por vez, lento para investigação
- **Solução**: Item W1 (Cross-References Headless)

### 2. Emulação Controlada
- **Problema**: Testei stack com Unicorn puro para confirmar se bug era nosso vs do binário
- **HexCore atual**: Não tem modo "emula a partir de endereço X com registradores Y"
- **Solução**: Item W2 (Emulate From Address)

### 3. PE Parsing Manual
- **Problema**: Precisei ler TLS callbacks, Debug Directory, data directories individuais
- **HexCore atual**: PE Analyzer dá overview mas não expõe TLS callbacks nem data directories
- **Solução**: Item W3 (TLS Callbacks Exposure)

### 4. XOR Brute Force
- **Problema**: Procurei flag XOR-encoded
- **HexCore atual**: `hexcore-strings` tem XOR detection mas não foi usado no pipeline
- **Solução**: Item W5 (XOR Brute Force Headless)

### 5. Cross-References
- **Problema**: Procurei quem referencia 0x40B020, 0x40BDB4
- **HexCore atual**: Não tem xref headless
- **Solução**: Item W1

---

## Wishlist Items — v3.7.1 / v3.7.2 / v3.8

### W1. Cross-References Headless
**Comando**: `hexcore.disasm.xrefHeadless`

**O quê**: Dado um endereço, retorna todas as referências a ele no binário

**Por quê**: Essencial para seguir fluxo de dados em análise de crackmes/CTFs

**Interface**:
```json
{
  "file": "path/to/binary",
  "address": "0x40B020",
  "output": "path/to/xrefs.json",
  "quiet": true
}
```

**Output**:
```json
{
  "target": "0x40B020",
  "references": [
    { "address": "0x401234", "type": "call", "instruction": "call 0x40B020" },
    { "address": "0x402567", "type": "data", "instruction": "mov eax, [0x40B020]" },
    { "address": "0x403890", "type": "jump", "instruction": "jmp 0x40B020" }
  ],
  "count": 3
}
```

**Esforço**: 3-5 dias  
**Prioridade**: Alta (análise interativa)  
**Versão sugerida**: v3.7.1

---

### W2. Emulate From Address
**Comando**: `hexcore.debug.emulateFromAddress`

**O quê**: Emula a partir de endereço arbitrário com registradores/memória customizados

**Por quê**: Testar paths específicos sem executar do entry point

**Interface**:
```json
{
  "file": "path/to/binary",
  "startAddress": "0x401234",
  "registers": {
    "eax": "0x12345678",
    "ebx": "0xDEADBEEF",
    "esp": "0x7FFE0000"
  },
  "memory": [
    { "address": "0x40B000", "data": "48656C6C6F" }
  ],
  "maxInstructions": 10000,
  "breakpoints": ["0x401500"],
  "output": "path/to/trace.json",
  "quiet": true
}
```

**Esforço**: 5-7 dias  
**Prioridade**: Alta (emulação controlada)  
**Versão sugerida**: v3.7.2

---

### W3. TLS Callbacks Exposure
**Comando**: `hexcore.peanalyzer.tlsCallbacks`

**O quê**: Expor TLS callbacks do PE

**Por quê**: TLS callbacks são primeiro código executado, onde anti-debug/flag construction geralmente vive

**Interface**:
```json
{
  "file": "path/to/binary.exe",
  "output": "path/to/tls.json",
  "quiet": true
}
```

**Output**:
```json
{
  "tlsDirectory": {
    "startAddressOfRawData": "0x40B000",
    "endAddressOfRawData": "0x40B100",
    "addressOfIndex": "0x40B104",
    "addressOfCallbacks": "0x40B108"
  },
  "callbacks": [
    { "address": "0x401234", "rva": "0x1234" },
    { "address": "0x405678", "rva": "0x5678" }
  ],
  "count": 2
}
```

**Esforço**: 2-3 dias  
**Prioridade**: Média (análise PE avançada)  
**Versão sugerida**: v3.7.1

---

### W4. IAT Resolution
**Comando**: `hexcore.peanalyzer.resolveIAT`

**O quê**: Mapear endereços IAT → nomes de função

**Por quê**: Transforma `call [0x40C16C]` em `call GetProcAddress`

**Interface**:
```json
{
  "file": "path/to/binary.exe",
  "output": "path/to/iat.json",
  "quiet": true
}
```

**Output**:
```json
{
  "iat": [
    { "address": "0x40C16C", "dll": "kernel32.dll", "function": "GetProcAddress" },
    { "address": "0x40C170", "dll": "kernel32.dll", "function": "LoadLibraryA" },
    { "address": "0x40C174", "dll": "user32.dll", "function": "MessageBoxA" }
  ],
  "count": 3
}
```

**Integração com disassembler**:
- `analyzeAll` e `disassembleAtHeadless` devem cruzar IAT automaticamente
- `call [0x40C16C]` vira `call GetProcAddress ; IAT[0x40C16C]`

**Esforço**: 3-5 dias  
**Prioridade**: Alta (qualidade de disassembly)  
**Versão sugerida**: v3.7.1

---

### W5. XOR Brute Force Headless
**Comando**: `hexcore.strings.xorBruteForceHeadless`

**O quê**: Expor XOR brute force como comando headless no pipeline

**Por quê**: Já existe no módulo strings mas não está acessível via pipeline

**Interface**:
```json
{
  "file": "path/to/binary",
  "minLength": 8,
  "output": "path/to/xor_strings.json",
  "quiet": true
}
```

**Output**:
```json
{
  "xorStrings": [
    {
      "offset": "0x1234",
      "key": "0x42",
      "decoded": "HTB{flag_here}",
      "length": 14,
      "confidence": 0.95
    }
  ],
  "count": 1
}
```

**Esforço**: 1-2 dias (já existe, só expor)  
**Prioridade**: Baixa (já funciona via UI)  
**Versão sugerida**: v3.7.1

---

## Integração com Roadmap v3.7/v3.8

### v3.7 (Já Planejado)
- ✅ **1.1 Permissive Memory Mapping** — Resolve crash de emulação parcialmente
- ✅ **1.2/1.3 PRNG Implementation** — Resolve validação de crackmes com rand()
- ✅ **2.1 Rellic IR Optimization** — Melhora qualidade de decompilação
- ✅ **2.2 Junk Instruction Filtering** — Reduz poluição em binários obfuscados
- ✅ **2.3 Memory Dump During Emulation** — Facilita análise de VMs
- ✅ **2.4 Runtime Memory Disassembly** — Análise de código decriptado em runtime
- ✅ **3.1 VM Detection Heuristics** — Detecta dispatchers automaticamente

### v3.7.1 (Wishlist — Análise Interativa)
- **W1** Cross-References Headless
- **W3** TLS Callbacks Exposure
- **W4** IAT Resolution
- **W5** XOR Brute Force Headless

### v3.7.2 (Wishlist — Emulação Avançada)
- **W2** Emulate From Address

### v3.8 (Já Planejado)
- ✅ **4.1-4.4 Souper Integration** — Superoptimização de LLVM IR via SMT solvers

---

## Priorização

### Crítico (v3.7.1)
1. **W4 IAT Resolution** — Melhora qualidade de disassembly imediatamente
2. **W1 Cross-References** — Essencial para análise interativa

### Alto (v3.7.1)
3. **W3 TLS Callbacks** — Análise PE completa
4. **W5 XOR Brute Force** — Baixo esforço, alto valor

### Médio (v3.7.2)
5. **W2 Emulate From Address** — Emulação controlada (maior esforço)

---

## Estimativa de Esforço Total

| Versão | Items | Esforço Total | Prazo |
|--------|-------|---------------|-------|
| v3.7.1 | W1, W3, W4, W5 | 9-15 dias | 2-3 semanas |
| v3.7.2 | W2 | 5-7 dias | 1 semana |

**Total wishlist**: 14-22 dias (~3-4 semanas)

---

## Notas Finais

- Nenhum item é urgente para beta.2 — são melhorias para roadmap
- Pipeline core (disasm → lift → decompile → emulate → report) está funcionando
- O que falta é a **camada de análise interativa** que hoje requer scripts Python externos
- Com W1-W5 implementados, HexCore seria autossuficiente para 90%+ dos CTFs/crackmes

---

**Próximo passo**: Criar specs individuais para W1, W3, W4, W5 (v3.7.1) após conclusão da v3.7.0 stable.
