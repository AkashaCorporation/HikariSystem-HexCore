# Especificação Técnica: Driver de Melhorias no Sistema de Extensões HexCore

**Versão**: 1.0.0
**Data**: 2026-03-12
**Status**: Draft
**Autor**: HikariSystem Engineering

---

## 1. Visão Geral

Esta especificação define os requisitos técnicos para o driver de melhorias no sistema de extensões do projeto HexCore, focando nos módulos de **Disassembler**, **Debugger**, **Strings** e **Report Composer**. O objetivo é padronizar, otimizar e expandir as capacidades desses módulos mantendo compatibilidade com a arquitetura VS Code.

---

## 2. Análise dos Componentes Críticos

### 2.1 Capstone Engine (v1.3.2)

**Função**: Engine de desmontagem multi-arquitetura
**Arquiteturas Suportadas**: x86, x64, ARM, ARM64, MIPS, MIPS64, PPC, SPARC, M68K, RISC-V

#### Protocolos de Segurança para Modificações

| Aspecto | Protocolo | Risco |
|---------|-----------|-------|
| Wrapper C++ | Nunca modificar `capstone_wrapper.cpp` sem review de 2 pares | Alto |
| Prebuilds | Sempre regenerar via `prebuildify --napi --strip` após mudanças | Médio |
| API Surface | Manter backward compatibility com `index.d.ts` | Alto |
| Async Workers | Validar thread-safety em `disasm_async_worker.h` | Crítico |

#### Dependências do Sistema
- N-API v8 (obrigatório)
- C++17 mínimo
- node-gyp 10.x
- Visual Studio Build Tools 2022 (Windows)

### 2.2 Remill Engine (v0.1.2)

**Função**: Lifter de machine code para LLVM IR bitcode
**Arquiteturas**: x86, x64, AArch64, SPARC32, SPARC64

#### Protocolos de Segurança para Modificações

| Aspecto | Protocolo | Risco |
|---------|-----------|-------|
| Deps Pesadas | Nunca modificar `_rebuild_mt.py` sem documentar | Crítico |
| LLVM 18 | Manter compatibilidade com bitcode format 18.x | Alto |
| Sleigh/Ghidra | Validar conflito `windows.h` vs `CHAR` typedef | Alto |
| Prebuilds | Usar deps pré-compiladas de `remill-deps-win32-x64.zip` | Médio |

#### Dependências Críticas
- LLVM 18 (168 libs estáticas, ~131 MB)
- XED (Intel X86 Encoder Decoder)
- glog + gflags
- Sleigh (Ghidra decompiler)

### 2.3 Helix Engine (Experimental)

**Função**: Decompilador de binários e LLVM IR para pseudo-C
**Status**: Experimental — Engine standalone via NAPI-RS
**Arquiteturas**: x86, x86_64, ARM, AArch64, MIPS, MIPS64, PowerPC, SPARC, RISC-V
**Binding**: NAPI-RS (Rust → Node.js), `.node` pré-compilado (não usa prebuildify)

> **IMPORTANTE**: Helix é um engine independente. NÃO depende de Rellic nem de nenhum outro decompilador.
> Ele aceita tanto binários diretos quanto LLVM IR (gerado pelo Remill) como entrada.

#### Protocolos de Segurança para Modificações

| Aspecto | Protocolo | Risco |
|---------|-----------|-------|
| `.node` caching | Remover `.node` antigo antes de substituir — VS Code pode cachear | Alto |
| `loadNativeModule` | Carregar via `candidatePaths`, NUNCA declarar em `dependencies` | Crítico |
| Arch mapping | Validar mapeamento Capstone → Helix via `helixArchMapper.ts` | Médio |
| IR decompilation | x86 (32-bit) é promovido para x86_64 (IR do Remill já é arch-agnostic) | Médio |
| Async threshold | IR > 64KB deve ser offloaded para worker thread (engine `.node` é síncrono) | Alto |
| API Surface | Manter backward compatibility com `index.d.ts` (auto-gerado por NAPI-RS) | Alto |

#### Dependências do Sistema
- NAPI-RS runtime (embutido no `.node`)
- Sem dependências externas em runtime (zero deps)
- Build requer Rust toolchain + NAPI-RS CLI

### 2.4 LLVM-MC Engine (v1.0.0)

**Função**: Assembler baseado em LLVM MC
**Arquiteturas**: x86, x86-64, ARM, AArch64, MIPS, RISC-V, PowerPC, SPARC

#### Protocolos de Segurança

| Aspecto | Protocolo | Risco |
|---------|-----------|-------|
| Assembly | Validar output antes de patch em binários | Crítico |
| Syntax | Suportar Intel e AT&T syntax | Médio |
| Prebuilds | Regenerar para cada plataforma suportada | Baixo |

---

## 3. Diretrizes de Implementação

### 3.1 Módulos de Baixo Risco

**Definição**: Mudanças que não afetam API surface, não modificam código nativo, e não alteram comportamento de parsing.

#### Módulos Classificados como Baixo Risco

| Módulo | Tipo de Mudança | Requisitos |
|--------|-----------------|------------|
| `hexcore-strings` | Novos patterns de regex | Testes unitários obrigatórios |
| `hexcore-strings` | Categorias adicionais | Documentação de categorias |
| `hexcore-common` | Utilitários TypeScript | Sem dependências novas |
| Report Generator | Templates de relatório | Validação de output |

#### Processo de Implementação
1. Criar branch de feature
2. Implementar com testes unitários
3. Executar `npm run compile` sem erros
4. Submeter PR com descrição detalhada
5. Review de 1 par
6. Merge para main

### 3.2 Módulos de Alto Risco

**Definição**: Mudanças que afetam código nativo, modificam API surface, ou alteram comportamento de engines.

#### Módulos Classificados como Alto Risco

| Módulo | Tipo de Mudança | Requisitos |
|--------|-----------------|------------|
| `hexcore-capstone` | Wrapper C++ | Review de 2 pares + testes de regressão |
| `hexcore-remill` | Build system | Validação em ambiente isolado |
| `hexcore-unicorn` | Emulation hooks | Testes de estabilidade |
| `hexcore-llvm-mc` | Assembly output | Validação de binários gerados |
| `hexcore-helix` | Engine NAPI-RS / arch mapping | Validação de `.node` + testes de decompilação |
| `hexcore-disassembler` | Pipeline de análise | Testes de integração completos |
| `hexcore-debugger` | Session management | Testes de snapshot/restore |

#### Processo de Implementação
1. Criar RFC (Request for Comments) detalhado
2. Review de arquitetura com time
3. Criar branch de feature
4. Implementar com testes unitários E de integração
5. Executar bateria completa de testes
6. Validação manual em ambiente de staging
7. Submeter PR com documentação completa
8. Review de 2 pares obrigatório
9. Aprovação de tech lead
10. Merge com flag de feature (se aplicável)

---

## 4. Requisitos de Compatibilidade com VS Code

### 4.1 Arquitetura de Extensões

```
VS Code Extension Host
├── hexcore-disassembler (non-native)
│   ├── hexcore-common (TypeScript puro)
│   ├── hexcore-capstone (nativo, carregado dinamicamente)
│   ├── hexcore-llvm-mc (nativo, carregado dinamicamente)
│   ├── hexcore-remill (nativo, nativeExtensions list)
│   ├── hexcore-rellic (nativo, DEPRECATED — substituído pelo Helix)
│   └── hexcore-helix (nativo NAPI-RS, carregado dinamicamente)
├── hexcore-debugger (non-native)
│   ├── hexcore-common
│   └── hexcore-unicorn (nativo, carregado dinamicamente)
├── hexcore-strings (non-native)
│   └── hexcore-common
└── hexcore-common (non-native, TypeScript puro)
```

### 4.2 Regras de Dependências

**CRÍTICO**: Extensões consumidoras NUNCA devem declarar engines nativas como dependencies.

```json
// CORRETO - hexcore-disassembler/package.json
{
  "dependencies": {
    "hexcore-common": "file:../hexcore-common"
  }
}

// INCORRETO - NÃO FAZER ISSO
{
  "dependencies": {
    "hexcore-common": "file:../hexcore-common",
    "hexcore-capstone": "file:../hexcore-capstone",  // ❌
    "hexcore-remill": "file:../hexcore-remill"        // ❌
  }
}
```

### 4.3 Carregamento Dinâmico de Engines Nativas

```typescript
// Padrão obrigatório para carregar engines nativas
import { loadNativeModule } from 'hexcore-common';

const candidatePaths = [
    path.join(__dirname, '..', '..', 'hexcore-capstone'),
    path.join(__dirname, '..', '..', '..', 'hexcore-capstone')
];

const result = loadNativeModule<CapstoneModule>({
    moduleName: 'hexcore-capstone',
    candidatePaths
});
```

### 4.4 Lista nativeExtensions

Arquivo: `build/lib/extensions.ts`

```typescript
const nativeExtensions = [
    'microsoft-authentication',
    'hexcore-remill',
    'hexcore-rellic',
];
```

**Regra**: Adicionar nova engine nativa aqui APENAS se ela tiver deps pesadas que precisam de tratamento especial no CI.

> **Nota**: `hexcore-helix` NÃO está nesta lista porque usa NAPI-RS com `.node` pré-compilado auto-contido (zero deps externas). Já `hexcore-rellic` está listado por razões históricas mas está DEPRECATED.

---

## 5. Estratégias de Teste

### 5.1 Testes Unitários

#### Módulo: hexcore-disassembler

| Teste | Cobertura | Frequência |
|-------|-----------|------------|
| Capstone wrapper | 90%+ | Todo commit |
| Instruction parsing | 95%+ | Todo commit |
| CFG generation | 85%+ | Todo commit |
| Xref resolution | 90%+ | Todo commit |

#### Módulo: hexcore-debugger

| Teste | Cobertura | Frequência |
|-------|-----------|------------|
| Unicorn wrapper | 90%+ | Todo commit |
| Snapshot/Restore | 95%+ | Todo commit |
| Breakpoint management | 90%+ | Todo commit |
| Memory operations | 85%+ | Todo commit |

#### Módulo: hexcore-strings

| Teste | Cobertura | Frequência |
|-------|-----------|------------|
| XOR brute-force | 95%+ | Todo commit |
| Stack string detection | 90%+ | Todo commit |
| String categorization | 85%+ | Todo commit |
| Report generation | 90%+ | Todo commit |

### 5.2 Testes de Integração

```bash
# Testes de integração por módulo
npm run test:integration:disassembler
npm run test:integration:debugger
npm run test:integration:strings

# Testes de integração completos
npm run test:integration:all
```

### 5.3 Testes de Performance

| Métrica | Threshold | Medição |
|---------|-----------|---------|
| Disassembly de 1MB | < 2s | Benchmark |
| Emulation de 10k instruções | < 500ms | Benchmark |
| String extraction de 10MB | < 3s | Benchmark |
| Memory usage (pico) | < 512MB | Profiling |

### 5.4 Testes de Regressão

```bash
# Antes de qualquer merge em módulos de alto risco
npm run test:regression:native
npm run test:regression:api
npm run test:regression:performance
```

---

## 6. Cronograma de Implementação Faseada

### Fase 1: Fundação (Semanas 1-2)

| Tarefa | Responsável | Checkpoint |
|--------|-------------|------------|
| Auditoria de código existente | Time de engenharia | Relatório de gaps |
| Definição de métricas baseline | DevOps | Dashboard configurado |
| Setup de ambiente de staging | Infraestrutura | Ambiente validado |

### Fase 2: Módulos de Baixo Risco (Semanas 3-4)

| Tarefa | Responsável | Checkpoint |
|--------|-------------|------------|
| Novas categorias em hexcore-strings | Dev A | Testes passando |
| Templates de relatório | Dev B | Documentação completa |
| Utilitários em hexcore-common | Dev A | API documentada |

### Fase 3: Módulos de Alto Risco - Parte 1 (Semanas 5-8)

| Tarefa | Responsável | Checkpoint |
|--------|-------------|------------|
| Melhorias no Capstone wrapper | Dev C | RFC aprovado |
| Otimização de prebuilds | DevOps | CI atualizado |
| Testes de regressão nativos | QA | Suite completa |

### Fase 4: Módulos de Alto Risco - Parte 2 (Semanas 9-12)

| Tarefa | Responsável | Checkpoint |
|--------|-------------|------------|
| Pipeline de análise melhorado | Dev D | Benchmarks OK |
| Session management debugger | Dev E | Snapshots validados |
| Integração Remill otimizada | Dev C | Build time reduzido |

### Fase 5: Validação e Release (Semanas 13-14)

| Tarefa | Responsável | Checkpoint |
|--------|-------------|------------|
| Testes de aceitação | QA | Todos passando |
| Documentação final | Tech Writer | Docs publicadas |
| Release candidate | Release Manager | RC aprovado |

---

## 7. Métricas de Performance e Critérios de Aceitação

### 7.1 hexcore-disassembler

| Métrica | Atual | Target | Critério de Aceitação |
|---------|-------|--------|----------------------|
| Disassembly speed (1MB) | 3.2s | < 2.0s | 37% melhoria |
| Memory usage (pico) | 680MB | < 512MB | 25% redução |
| Function discovery | 85% | > 95% | 10% melhoria |
| Xref accuracy | 92% | > 98% | 6% melhoria |

### 7.2 hexcore-debugger

| Métrica | Atual | Target | Critério de Aceitação |
|---------|-------|--------|----------------------|
| Emulation speed | 8k inst/s | > 15k inst/s | 87% melhoria |
| Snapshot time | 450ms | < 200ms | 55% redução |
| Restore time | 380ms | < 150ms | 60% redução |
| Memory overhead | 120MB | < 80MB | 33% redução |

### 7.3 hexcore-strings

| Métrica | Atual | Target | Critério de Aceitação |
|---------|-------|--------|----------------------|
| Extraction speed (10MB) | 4.5s | < 3.0s | 33% melhoria |
| XOR detection accuracy | 78% | > 90% | 12% melhoria |
| False positive rate | 15% | < 5% | 66% redução |
| Memory usage | 250MB | < 180MB | 28% redução |

### 7.4 Report Composer (Novo)

| Métrica | Target | Critério de Aceitação |
|---------|--------|----------------------|
| Report generation time | < 2s | Para análise de 100MB |
| Template rendering | < 500ms | Para 50+ seções |
| Export formats | 3+ | Markdown, HTML, JSON |
| Customization | 100% | Templates editáveis |

---

## 8. Plano de Rollback

### 8.1 Estratégia Geral

```
┌─────────────────────────────────────────────────────────────┐
│                    PLANO DE ROLLBACK                         │
├─────────────────────────────────────────────────────────────┤
│ 1. Feature Flags para todas as mudanças de alto risco       │
│ 2. Versionamento semântico rigoroso                         │
│ 3. Snapshots de prebuilds antes de atualizações             │
│ 4. Rollback automático em caso de falha nos testes          │
└─────────────────────────────────────────────────────────────┘
```

### 8.2 Rollback por Módulo

#### Módulos de Baixo Risco

| Cenário | Ação | Tempo Estimado |
|---------|------|----------------|
| Bug em regex pattern | Reverter commit específico | < 5 min |
| Template com erro | Rollback de template | < 5 min |
| Utilitário quebrado | Reverter módulo | < 10 min |

#### Módulos de Alto Risco

| Cenário | Ação | Tempo Estimado |
|---------|------|----------------|
| Capstone wrapper com bug | Desabilitar feature flag | < 2 min |
| Prebuild corrompido | Restaurar snapshot | < 15 min |
| Remill build falha | Rollback para versão anterior | < 30 min |
| API breaking change | Reverter + comunicar | < 1 hora |

### 8.3 Procedimento de Rollback Detalhado

```bash
# 1. Identificar versão estável
git log --oneline -10

# 2. Criar branch de rollback
git checkout -b rollback/emergency-$(date +%Y%m%d)

# 3. Reverter para versão estável
git revert <commit-hash> --no-commit

# 4. Regenerar prebuilds se necessário
cd extensions/hexcore-capstone
npm run make-prebuild

# 5. Executar testes de validação
npm run test:regression:all

# 6. Deploy de emergência
npm run deploy:emergency
```

### 8.4 Comunicação de Rollback

| Canal | Timing | Responsável |
|-------|--------|-------------|
| Slack #hexcore-alerts | Imediato | Dev que identificou |
| Email stakeholders | < 30 min | Tech Lead |
| Status page | < 1 hora | DevOps |
| Post-mortem | < 48 horas | Time responsável |

---

## 9. Diagramas de Arquitetura

### 9.1 Arquitetura Atual

```
┌─────────────────────────────────────────────────────────────────┐
│                    HikariSystem HexCore                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │ Disassembler │  │   Debugger   │  │   Strings    │          │
│  │   v1.3.0     │  │   v2.1.0     │  │   v1.2.0     │          │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘          │
│         │                  │                  │                  │
│         └──────────────────┼──────────────────┘                  │
│                            │                                     │
│                    ┌───────▼───────┐                             │
│                    │ hexcore-common│                             │
│                    │   (TypeScript)│                             │
│                    └───────┬───────┘                             │
│                            │                                     │
│         ┌──────────────────┼──────────────────┐                  │
│         │                  │                  │                  │
│  ┌──────▼───────┐  ┌──────▼───────┐  ┌──────▼───────┐          │
│  │   Capstone   │  │   Unicorn    │  │   LLVM-MC    │          │
│  │   v1.3.2     │  │   v1.2.1     │  │   v1.0.0     │          │
│  │   (Nativo)   │  │   (Nativo)   │  │   (Nativo)   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │    Remill    │  │    Rellic    │  │    Helix     │          │
│  │   v0.1.2     │  │ (DEPRECATED) │  │ (Experim.)   │          │
│  │   (Nativo)   │  │   (Nativo)   │  │ (NAPI-RS)    │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.2 Arquitetura Proposta (Pós-Melhorias)

```
┌─────────────────────────────────────────────────────────────────────┐
│                    HikariSystem HexCore v2.0                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐        │
│  │  Disassembler  │  │    Debugger    │  │    Strings     │        │
│  │    v2.0.0      │  │    v3.0.0      │  │    v2.0.0      │        │
│  │  ┌──────────┐  │  │  ┌──────────┐  │  │  ┌──────────┐  │        │
│  │  │ Pipeline │  │  │  │ Session  │  │  │  │  XOR     │  │        │
│  │  │ Engine   │  │  │  │ Manager  │  │  │  │  Engine  │  │        │
│  │  └──────────┘  │  │  └──────────┘  │  │  └──────────┘  │        │
│  │  ┌──────────┐  │  │  ┌──────────┐  │  │  ┌──────────┐  │        │
│  │  │   CFG    │  │  │  │ Snapshot │  │  │  │  Stack   │  │        │
│  │  │ Builder  │  │  │  │ Manager  │  │  │  │ Detector │  │        │
│  │  └──────────┘  │  │  └──────────┘  │  │  └──────────┘  │        │
│  └───────┬────────┘  └───────┬────────┘  └───────┬────────┘        │
│          │                   │                   │                   │
│          └───────────────────┼───────────────────┘                   │
│                              │                                       │
│                      ┌───────▼───────┐                               │
│                      │ hexcore-common│                               │
│                      │    v2.0.0     │                               │
│                      │  ┌─────────┐  │                               │
│                      │  │ Native  │  │                               │
│                      │  │ Loader  │  │                               │
│                      │  └─────────┘  │                               │
│                      │  ┌─────────┐  │                               │
│                      │  │ Report  │  │                               │
│                      │  │Composer │  │                               │
│                      │  └─────────┘  │                               │
│                      └───────┬───────┘                               │
│                              │                                       │
│          ┌───────────────────┼───────────────────┐                   │
│          │                   │                   │                   │
│  ┌───────▼───────┐  ┌───────▼───────┐  ┌───────▼───────┐           │
│  │   Capstone    │  │    Unicorn    │  │   LLVM-MC     │           │
│  │    v2.0.0     │  │    v2.0.0     │  │    v2.0.0     │           │
│  │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │           │
│  │  │ Async   │  │  │  │ Hook    │  │  │  │ Syntax  │  │           │
│  │  │ Worker  │  │  │  │ Manager │  │  │  │ Manager │  │           │
│  │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │           │
│  └───────────────┘  └───────────────┘  └───────────────┘           │
│                                                                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐           │
│  │    Remill     │  │   Rellic      │  │     Helix     │           │
│  │    v1.0.0     │  │  DEPRECATED   │  │    v1.0.0     │           │
│  │  ┌─────────┐  │  │  ┌─────────┐  │  │  ┌─────────┐  │           │
│  │  │  IR     │  │  │  │  C      │  │  │  │  C      │  │           │
│  │  │ Lifter  │  │  │  │Decompil.│  │  │  │Decompil.│  │           │
│  │  └─────────┘  │  │  └─────────┘  │  │  └─────────┘  │           │
│  └───────────────┘  └───────────────┘  └───────────────┘           │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### 9.3 Fluxo de Dados - Análise de Binário

```
┌─────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────┐
│  Input  │───▶│   Parser    │───▶│   Engine    │───▶│ Output  │
│ Binary  │    │   (PE/ELF)  │    │ Selection   │    │ Report  │
└─────────┘    └─────────────┘    └─────────────┘    └─────────┘
                      │                   │
                      ▼                   ▼
               ┌─────────────┐    ┌─────────────┐
               │   Header    │    │   Capstone  │
               │   Analysis  │    │   Disasm    │
               └─────────────┘    └─────────────┘
                      │                   │
                      ▼                   ▼
               ┌─────────────┐    ┌─────────────┐
               │   Section   │    │   Unicorn   │
               │   Mapping   │    │   Emulate   │
               └─────────────┘    └─────────────┘
                      │                   │
                      ▼                   ▼
               ┌─────────────┐    ┌─────────────┐
               │   Strings   │    │   Remill    │
               │  Extraction │    │   Lift IR   │
               └─────────────┘    └─────────────┘
                      │                   │
                      │                   ▼
                      │           ┌─────────────┐
                      │           │    Helix    │
                      │           │ Decompile C │
                      │           └─────────────┘
                      │                   │
                      └─────────┬─────────┘
                                ▼
                        ┌─────────────┐
                        │   Report    │
                        │  Composer   │
                        └─────────────┘
```

---

## 10. Análise de Impacto

### 10.1 Impacto no Build System

| Componente | Impacto | Mitigação |
|------------|---------|-----------|
| CI/CD Pipeline | +15 min build time | Parallelização de jobs |
| Prebuilds | +500MB storage | Limpeza automática de versões antigas |
| Dependencies | +2 novas deps | Validação de segurança |

### 10.2 Impacto na Performance

| Operação | Impacto Esperado | Validação |
|----------|------------------|-----------|
| Startup time | +200ms | Benchmark automatizado |
| Memory baseline | +50MB | Profiling contínuo |
| Disassembly speed | -30% (melhoria) | Testes de performance |

### 10.3 Impacto na Manutenibilidade

| Aspecto | Antes | Depois | Melhoria |
|---------|-------|--------|----------|
| Código duplicado | 15% | < 5% | 66% redução |
| Test coverage | 72% | > 90% | 25% melhoria |
| Documentação | Parcial | Completa | 100% cobertura |

### 10.4 Riscos e Mitigações

| Risco | Probabilidade | Impacto | Mitigação |
|-------|---------------|---------|-----------|
| Breaking changes em API | Média | Alto | Versionamento semântico + deprecation warnings |
| Performance degradation | Baixa | Alto | Benchmarks automatizados em CI |
| Incompatibilidade de prebuilds | Média | Médio | Matrix de teste multi-plataforma |
| Memory leaks em código nativo | Baixa | Crítico | Valgrind/ASAN em CI |

---

## 11. Checklist de Validação

### 11.1 Pré-Implementação

- [ ] RFC aprovado para mudanças de alto risco
- [ ] Ambiente de staging configurado
- [ ] Baseline de métricas estabelecido
- [ ] Testes de regressão existentes passando

### 11.2 Durante Implementação

- [ ] Testes unitários escritos para novo código
- [ ] Testes de integração atualizados
- [ ] Documentação atualizada
- [ ] Code review realizado

### 11.3 Pré-Release

- [ ] Todos os testes passando
- [ ] Benchmarks dentro dos thresholds
- [ ] Documentação completa
- [ ] Plano de rollback testado

### 11.4 Pós-Release

- [ ] Monitoramento ativo por 48h
- [ ] Feedback coletado de usuários
- [ ] Post-mortem se houve rollback
- [ ] Atualização de métricas baseline

---

## 12. Referências

- [POWER.md - Native Engines](file:///c:/Users/Mazum/Desktop/vscode-main/powers/hexcore-native-engines/POWER.md)
- [AGENTS.md - VS Code Instructions](file:///c:/Users/Mazum/Desktop/vscode-main/AGENTS.md)
- [HexCore v2.0 Roadmap](docs/HEXCORE_V2_ROADMAP.md)
- [New Extensions Documentation](docs/NEW_EXTENSIONS.md)

---

**Aprovações**:

| Role | Nome | Data | Assinatura |
|------|------|------|------------|
| Tech Lead | | | |
| Security Lead | | | |
| QA Lead | | | |
| Release Manager | | | |
