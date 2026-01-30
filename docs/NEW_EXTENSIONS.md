# HexCore v2.0 - Novas Extensões

## Extensões Criadas

### 1. hexcore-disassembler
Disassembly profissional com integração ao motor Capstone.

**Features:**
- Disassembly x86/x64/ARM/ARM64
- Navegação por endereços
- Cross-references (XREFs)
- Funções detectadas automaticamente
- Visualização de strings
- Exportação de assembly
- Suporte a comentários
- Renomeação de funções

**Comandos:**
- `HexCore: Disassemble Binary` - Abre arquivo para disassembly
- `HexCore: Go to Address` - Navega para endereço específico
- `HexCore: Find Cross-References` - Encontra referências cruzadas
- `HexCore: Add Comment` - Adiciona comentário
- `HexCore: Rename Function` - Renomeia função
- `HexCore: Show Control Flow Graph` - Mostra CFG
- `HexCore: Export Assembly` - Exporta para arquivo

### 2. hexcore-ai
Assistente de IA integrado (Kimi) para análise de malware.

**Features:**
- Chat interativo com IA
- Análise automática de funções
- Detecção de vulnerabilidades
- Geração de templates de exploit
- Ajuda para CTFs
- Análise completa de binários

**Comandos:**
- `AI: Ask Kimi Assistant` - Pergunta livre
- `AI: Analyze Current Function` - Analisa função atual
- `AI: Explain This Code` - Explica código em linguagem natural
- `AI: Find Vulnerabilities` - Busca vulnerabilidades
- `AI: Generate Exploit Template` - Gera template de exploit
- `AI: CTF Hint` - Dicas para CTFs
- `AI: Full Binary Analysis` - Análise completa

### 3. hexcore-debugger
Integração com debuggers para análise dinâmica.

**Features:**
- Integração WinDbg (Windows)
- Integração GDB (Linux/Mac)
- Controle de execução (step, continue)
- Breakpoints
- Visualização de registers
- Visualização de memória
- API tracing

**Comandos:**
- `Debug: Start Analysis` - Inicia debugging
- `Debug: Attach to Process` - Anexa a processo
- `Debug: Toggle Breakpoint` - Alterna breakpoint
- `Debug: Step Into` - Entra na função
- `Debug: Step Over` - Pula função
- `Debug: Continue` - Continua execução
- `Debug: Enable API Tracing` - Habilita trace de APIs

### 4. hexcore-yara
Scanner de regras YARA para detecção de malware.

**Features:**
- Regras YARA built-in (packers, malware)
- Scan de arquivos individuais
- Scan de diretórios
- Criação de regras customizadas
- Atualização automática de regras

**Regras Built-in:**
- UPX, VMProtect, Themida (packers)
- Suspicious API calls
- Base64 encoded executables
- Shellcode patterns
- Reverse shell indicators

**Comandos:**
- `YARA: Scan File` - Escaneia arquivo
- `YARA: Scan Workspace` - Escaneia workspace
- `YARA: Update Rules` - Atualiza regras
- `YARA: Create Rule from Selection` - Cria regra do texto selecionado

## Extensões Melhoradas

### hexcore-hexviewer v2
- Edição hex avançada
- Templates de estruturas
- Bookmarks
- Diff view

### hexcore-peanalyzer v2
- Análise de recursos
- Detecção anti-debugging
- Rich Header analysis
- Verificação de assinatura digital

## Instalação

```bash
# Disassembler
cd extensions/hexcore-disassembler
npm install
npm run compile

# AI Assistant
cd extensions/hexcore-ai
npm install
npm run compile

# Debugger
cd extensions/hexcore-debugger
npm install
npm run compile

# YARA
cd extensions/hexcore-yara
npm install
npm run compile
```

## Roadmap Futuro

### v2.1
- [ ] CFG visualization
- [ ] Decompiler integration
- [ ] Plugin system

### v2.2
- [ ] Collaborative analysis
- [ ] Cloud-based AI
- [ ] Mobile binary support

### v2.3
- [ ] Network protocol analyzer
- [ ] Memory forensics
- [ ] Timeline analysis
