---
name: HexCore Binary Analysis
description: Skill para análise de binários com ferramentas HexCore integradas ao editor
---

# HexCore Binary Analysis Skill

## Overview

HexCore é um conjunto de extensões para análise de binários e engenharia reversa integrado ao VS Code. Esta skill documenta como você (agente) pode usar as ferramentas disponíveis para auxiliar o usuário em tarefas de análise.

> **IMPORTANTE**: As ferramentas HexCore são extensões do VS Code. Elas geram outputs visuais (webviews, documentos markdown). Como agente, você pode sugerir que o usuário execute comandos específicos e ajudar a interpretar os resultados descritos.

---

## Available Extensions

### 1. HexCore Disassembler (`hexcore-disassembler`)
**Status**: ✅ Funcional (Capstone Engine via WebAssembly)

Disassembler profissional com suporte a x86, x64, ARM, ARM64 e MIPS.

**Commands**:
- `hexcore.disasm.analyzeFile` - Disassemblar um binário
- `hexcore.disasm.goToAddress` - Navegar para endereço específico
- `hexcore.disasm.findXrefs` - Encontrar referências cruzadas
- `hexcore.disasm.addComment` - Adicionar comentário em um endereço
- `hexcore.disasm.renameFunction` - Renomear função
- `hexcore.disasm.showCFG` - Mostrar grafo de fluxo de controle
- `hexcore.disasm.searchString` - Buscar referências de string
- `hexcore.disasm.exportASM` - Exportar assembly para arquivo

**Arquiteturas suportadas**:
- `x86` - Intel 32-bit
- `x64` - Intel 64-bit (AMD64)
- `arm` - ARM 32-bit
- `arm64` - ARM 64-bit (AArch64)
- `mips` - MIPS 32-bit

---

### 2. HexCore Hex Viewer (`hexcore-hexviewer`)
**Status**: ✅ Funcional

Editor hexadecimal para visualizar e editar binários.

**Commands**:
- `hexcore.openHexView` - Abrir arquivo em visualização hex
- `hexcore.goToOffset` - Navegar para offset específico
- `hexcore.searchHex` - Buscar padrão hexadecimal
- `hexcore.copyAsHex` - Copiar seleção como hex
- `hexcore.copyAsC` - Copiar seleção como array C
- `hexcore.copyAsPython` - Copiar seleção como bytes Python
- `hexcore.addBookmark` - Adicionar bookmark
- `hexcore.applyTemplate` - Aplicar template de estrutura
- `hexcore.toggleEdit` - Alternar modo de edição

**Formatos suportados**: `.bin`, `.exe`, `.dll`, `.so`, `.dylib`, `.dat`, `.raw`

---

### 3. HexCore Strings (`hexcore-strings`)
**Status**: ✅ Funcional

Extração de strings ASCII e Unicode de binários.

**Command**:
- `hexcore.strings.extract` - Extrair strings de um arquivo

**Output**: Relatório markdown com:
- Strings categorizadas (URLs, IPs, paths, DLLs, APIs sensíveis)
- Offset de cada string
- Encoding (ASCII ou UTF-16LE)

---

### 4. HexCore Entropy (`hexcore-entropy`)
**Status**: ✅ Funcional

Análise visual de entropia para detectar regiões compactadas ou criptografadas.

**Command**:
- `hexcore.entropy.analyze` - Gerar gráfico de entropia

**Interpretação**:
- Entropia alta (>7.5) = provavelmente criptografado ou compactado
- Entropia média (4-7) = código ou dados normais
- Entropia baixa (<4) = dados repetitivos ou texto

---

### 5. HexCore PE Analyzer (`hexcore-peanalyzer`)
**Status**: ✅ Funcional

Analisador de arquivos PE (Windows executables).

**Commands**:
- `hexcore.peanalyzer.analyze` - Analisar arquivo PE
- `hexcore.peanalyzer.analyzeActive` - Analisar arquivo ativo

**Output**: Informações sobre headers, imports, exports, sections, resources.

---

### 6. HexCore File Type (`hexcore-filetype`)
**Status**: ✅ Funcional

Detecta o tipo real de arquivo usando magic bytes.

**Command**:
- `hexcore.filetype.detect` - Detectar tipo de arquivo

**Uso**: Identificar arquivos com extensão errada ou mascarados.

---

### 7. HexCore Hash Calculator (`hexcore-hashcalc`)
**Status**: ✅ Funcional

Calcula hashes de arquivos ou seleções.

**Commands** (prováveis, verificar package.json):
- `hexcore.hash.file` - Calcular hash de arquivo
- `hexcore.hash.selection` - Calcular hash de seleção

**Algoritmos**: MD5, SHA1, SHA256, SHA512

---

### 8. HexCore Base64 (`hexcore-base64`)
**Status**: ✅ Funcional

Codificação e decodificação Base64.

**Commands** (prováveis):
- `hexcore.base64.encode` - Codificar em Base64
- `hexcore.base64.decode` - Decodificar de Base64

---

### 9. HexCore YARA (`hexcore-yara`)
**Status**: ✅ Funcional

Integração com regras YARA para detecção de malware.

**Features**:
- Criação e edição de regras YARA
- Scanning de arquivos com regras
- Syntax highlighting para `.yar`/`.yara`

---

### 10. HexCore Debugger (`hexcore-debugger`)
**Status**: ✅ Funcional

Debugger integrado para análise dinâmica.

**Features**:
- Breakpoints
- Step through code
- Register view
- Memory view

---

## Workflow Típico de Análise

Quando o usuário pedir para analisar um binário, sugira este workflow:

1. **Identificação Inicial**
   ```
   Comando: hexcore.filetype.detect
   ```
   - Verificar o tipo real do arquivo
   - Detectar possíveis extensões incorretas

2. **Análise de Entropia**
   ```
   Comando: hexcore.entropy.analyze
   ```
   - Identificar regiões criptografadas/compactadas
   - Determinar se o binário está packed

3. **Extração de Strings**
   ```
   Comando: hexcore.strings.extract
   ```
   - Identificar URLs, IPs, paths, APIs
   - Procurar indicadores de comportamento

4. **Análise de Headers** (para PE/ELF)
   ```
   Comando: hexcore.peanalyzer.analyze
   ```
   - Verificar imports e exports
   - Analisar sections
   - Identificar anomalias

5. **Disassembly**
   ```
   Comando: hexcore.disasm.analyzeFile
   ```
   - Analisar funções importantes
   - Identificar chamadas de API suspeitas
   - Analisar fluxo de controle

---

## Como Usar Esta Skill

### O que você (agente) PODE fazer:

1. **Sugerir comandos**: "Execute o comando `hexcore.strings.extract` no arquivo suspeito"

2. **Interpretar resultados**: Quando o usuário compartilhar output das ferramentas, analisar e explicar

3. **Guiar análise**: Sugerir próximos passos baseado nos resultados

4. **Explicar conceitos**: Ensinar sobre entropia, PE headers, calling conventions, etc.

### O que você (agente) NÃO pode fazer diretamente:

1. Executar os comandos HexCore (são extensões visuais do VS Code)
2. Ver o conteúdo das webviews diretamente
3. Modificar binários através das ferramentas

### Exemplo de Interação

**Usuário**: "Analise este arquivo malware.bin"

**Agente**:
```
Para começar a análise, execute estes comandos no VS Code:

1. Primeiro, verifique o tipo real: Ctrl+Shift+P > "HexCore: Detect File Type"
2. Analise a entropia: Ctrl+Shift+P > "HexCore: Entropy Graph"
3. Extraia strings: Ctrl+Shift+P > "HexCore: Extract Strings"

Após executar cada comando, me descreva os resultados e posso ajudar
a interpretar o que encontrar.
```

---

## Referência Técnica

### Capstone Engine (Disassembler)
O disassembler usa Capstone Engine via WebAssembly para disassembly real.
Suporta Intel syntax por padrão.

### Formatos de Arquivo Suportados

| Formato | Extensões | Análise PE | Disassembly |
|---------|-----------|------------|-------------|
| PE32 | .exe, .dll | ✅ | ✅ x86 |
| PE64 | .exe, .dll | ✅ | ✅ x64 |
| ELF32 | .elf, .so | Parcial | ✅ x86 |
| ELF64 | .elf, .so | Parcial | ✅ x64 |
| Mach-O | .dylib | Parcial | ✅ arm64 |
| RAW | .bin | ❌ | ✅ (auto) |

---

## Troubleshooting

### Webview não aparece
- Verifique se a extensão está habilitada
- Recarregue a janela: Ctrl+Shift+P > "Developer: Reload Window"

### Disassembly incorreto
- Verifique a arquitetura selecionada
- Para binários PE/ELF, a arquitetura é detectada automaticamente
- Para arquivos .bin, especifique a arquitetura manualmente

### Arquivo muito grande
- Arquivos >100MB podem ser lentos
- Use a ferramenta de strings com streaming (já implementado)
- Considere analisar apenas sections específicas

---

*HexCore v1.0 - Powered by Capstone Engine*
