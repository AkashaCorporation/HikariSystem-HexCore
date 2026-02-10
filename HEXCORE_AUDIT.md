# Relatorio de Auditoria dos Motores HexCore
**Data:** 03/02/2026  
**Auditores:** Agente (Skills: `cpp-pro`, `reverse-engineer`)

---

## Atualizacao de Status - 10/02/2026 (v3.2.2 Hotfix)

### Melhorias Confirmadas
- Pipeline runner com mapa de capacidades atualizado para `hexcore.yara.scan` e `hexcore.pipeline.listCapabilities`.
- Comandos headless padronizados para automacao (`file`, `quiet`, `output`) com validacao de saida por passo.
- Cobertura de `activationEvents` expandida em extensoes criticas, reduzindo erro de `Command '...' not found` em build empacotada.
- Entropy Analyzer refatorado para arquitetura modular e streaming com bloco adaptativo (mais estavel em arquivos grandes).

### Riscos Ainda Acompanhar
- Debugger em cenarios de execucao profunda (step/continue prolongado) ainda exige hardening adicional.
- Parte de hooks de I/O de libc continua em modo stub em cenarios Linux mais complexos.

### Veredito Atual
**MELHOROU PARA USO PRATICO / AINDA EM EVOLUCAO**

O projeto saiu de falhas estruturais de automacao e entrou em um estado mais confiavel para analise real. Ainda nao e "final", mas ja e apresentavel para uso tecnico com transparencia sobre limites.

## Resumo Executivo (Snapshot 03/02/2026)
**Veredito:** **INSTAVEL / NAO PRONTO PARA PRODUCAO**

Os motores HexCore (`hexcore-capstone`, `hexcore-unicorn`, `hexcore-llvm-mc`) tem base funcional, mas o build e a distribuicao de binarios nativos ainda quebram facilmente em clones limpos. Isso explica o "funciona na minha maquina".

## Achados Corrigidos (confirmados no codigo)
- Capstone async nao compartilha o mesmo handle: `DisasmAsyncWorker` abre o proprio `csh` por worker.
- Unicorn ja bloqueia mutacoes durante emulacao via `emulating_` em C++.
- LLVM MC ja faz reuse de pipeline em `AssembleMultiple` (nao recria todo o pipeline por instrucao).

## Riscos Atuais (causas de erro no clone)
- Carregamento nativo inconsistente entre motores (paths e mensagens diferentes).
- Prebuilds nem sempre presentes no clone, causando falha de `require`.
- Dependencias de runtime (ex: `unicorn.dll`) nao garantidas junto ao `.node`.
- Arquitetura detectada nao era aplicada no disassembler (corrigido na base).
- Patching com padding invalido em arquiteturas nao x86 (corrigido).

## Inventario de APIs (publico)
### hexcore-capstone
- Classe `Capstone`
- `constructor(arch, mode)`
- `disasm(code, address, count?)`
- `disasmAsync(code, address, count?)`
- `setOption(type, value)`
- `close()`
- `regName(regId)`
- `insnName(insnId)`
- `groupName(groupId)`
- `isOpen()`
- `getError()`
- `strError(err?)`
- Funcoes: `version()`, `support(arch)`
- Constantes: `ARCH`, `MODE`, `OPT`, `OPT_VALUE`, `ERR`

### hexcore-unicorn
- Classe `Unicorn`
- `constructor(arch, mode)`
- `emuStart(begin, until, timeout?, count?)`
- `emuStartAsync(begin, until, timeout?, count?)`
- `emuStop()`
- `memMap(address, size, perms)`
- `memMapPtr(address, data, perms)`
- `memUnmap(address, size)`
- `memProtect(address, size, perms)`
- `memRead(address, size)`
- `memWrite(address, data)`
- `memRegions()`
- `regRead(regId)`
- `regWrite(regId, value)`
- `regReadBatch(regIds)`
- `regWriteBatch(regIds, values)`
- `hookAdd(type, callback, begin?, end?, extra?)`
- `hookDel(handle)`
- `contextSave()`
- `contextRestore(context)`
- `query(queryType)`
- `ctlWrite(optType, value)`
- `ctlRead(optType)`
- `close()`
- Classe `UnicornContext`
- `free()`
- `size`
- Funcoes: `version()`, `archSupported(arch)`, `strerror(errorCode)`
- Constantes: `ARCH`, `MODE`, `PROT`, `HOOK`, `MEM`, `QUERY`, `ERR`
- Registradores: `X86_REG`, `ARM_REG`, `ARM64_REG`, `MIPS_REG`

### hexcore-llvm-mc
- Classe `LlvmMc`
- `constructor(triple, cpu?, features?)`
- `assemble(code, address?)`
- `assembleAsync(code, address?)`
- `assembleMultiple(instructions, startAddress?)`
- `setOption(option, value)`
- `getTriple()`
- `getCpu()`
- `getFeatures()`
- `close()`
- `isOpen`
- `handle`
- Funcoes: `version()`, `getTargets()`
- Constantes: `TRIPLE`, `SYNTAX`, `OPTION`, `ERR`, `CPU`, `FEATURES`

## Mapa de Uso nas Extensoes
### hexcore-disassembler
- Usa `CapstoneWrapper` para `disasmAsync` e deteccao de instrucoes.
- Usa `LlvmMcWrapper` para `assemble`, `assembleMultiple` e patching.
- Expande parsing PE via `hexcore-peanalyzer` e faz fallback manual em ELF/RAW.

### hexcore-debugger
- Usa `UnicornWrapper` para emulacao (start, step, continue, breakpoints).
- Prove leitura de memoria e registradores via Unicorn.

## Acoes em Curso
- Padronizar loader nativo com diagnostico consistente.
- Padronizar `postinstall` para baixar prebuilds e fazer fallback no build local.
- Garantir runtime deps (ex: `unicorn.dll`) junto do `.node`.
- CI dedicado para prebuilds Windows, com expansao futura para Linux/macOS.
