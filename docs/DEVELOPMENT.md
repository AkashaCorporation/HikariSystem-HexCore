# HexCore — Guia de Desenvolvimento

Guia para configurar o ambiente de desenvolvimento do HikariSystem HexCore sem gambiarras.

---

## ⚠️ Notas Importantes

1. **`VSCODE_SKIP_NODE_VERSION_CHECK=1`** é obrigatório antes de qualquer `npm install` ou `npm run compile`. Sem isso, o preinstall pode rejeitar sua versão do Node.js.
2. **Prebuilds nativos** (Capstone, Unicorn, LLVM MC, Remill, better-sqlite3) são baixados automaticamente pelo `scripts/hexcore-native-install.js`. Não é necessário compilar localmente.
3. **Se `npm install` travar**: delete `build/npm/gyp/node_modules` e tente novamente. O preinstall tem timeout de 60 segundos para evitar hangs indefinidos.

---

## Pré-requisitos

| Ferramenta | Versão | Motivo |
|-----------|--------|--------|
| Node.js | 22.x (dev) / 18+ (produção) | Runtime + build |
| Python | 3.11+ | node-gyp (compilação nativa) |
| Visual Studio Build Tools 2022 | C++ workload | Compilação de addons nativos |
| Git | 2.40+ | Controle de versão |
| npm | 10+ | Gerenciador de pacotes |

### Windows — Instalar Build Tools
```powershell
# Via winget
winget install Microsoft.VisualStudio.2022.BuildTools

# Depois abrir o VS Installer e marcar:
# - "Desktop development with C++"
# - Windows SDK
```

---

## Setup Inicial

```powershell
# 1. Clonar o repositório
git clone https://github.com/LXrdKnowkill/HikariSystem-HexCore.git
cd HikariSystem-HexCore

# 2. Configurar variável de ambiente (obrigatório no HexCore)
$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"

# 3. Instalar dependências do monorepo
npm install

# 4. Instalar prebuilds nativos (Capstone, Unicorn, LLVM MC, SQLite)
node scripts/hexcore-native-install.js
```

---

## Build

### Build Completa (Desenvolvimento)
```powershell
# Compilar tudo (client + extensions)
npm run compile

# Ou rodar em modo watch (recompila automaticamente)
npm run watch
```

### Build de Extensões HexCore Individuais
```powershell
# Cada extensão pode ser compilada separadamente
cd extensions/hexcore-disassembler
npm run compile

cd extensions/hexcore-ioc
npm run compile

# Para extensões nativas (se precisar recompilar o .node)
cd extensions/hexcore-better-sqlite3
npm run build        # node-gyp rebuild
npm run build:debug  # node-gyp rebuild --debug
```

### Rodar o HexCore (Electron)
```powershell
$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"
.\scripts\code.bat
```

---

## Extensões Nativas

As extensões nativas usam prebuilds pré-compilados. O fluxo normal é:

1. `npm install` → roda `hexcore-native-install.js` → baixa prebuilds da GitHub Release
2. Se não encontrar prebuild, faz fallback para `node-gyp rebuild` (compila localmente)

### Compilar Nativo Localmente (quando necessário)
```powershell
cd extensions/hexcore-better-sqlite3
npm run build

# Verificar se compilou
node -e "const db = require('.'); const d = new db(':memory:'); console.log(d.pragma('compile_options')); d.close()"
```

### Gerar Prebuilds Localmente
```powershell
cd extensions/hexcore-better-sqlite3
npm run prebuild  # prebuildify --napi --strip
# Gera: prebuilds/win32-x64/node.napi.node
```

---

## Testes

```powershell
# Testes unitários (Electron)
.\scripts\test.bat

# Testes de extensão nativa
cd extensions/hexcore-better-sqlite3 && npm test
cd extensions/hexcore-unicorn && npm test
cd extensions/hexcore-capstone && npm test

# Testes de extensão TypeScript
cd extensions/hexcore-ioc && npm run compile && npm test
```

---

## Estrutura de Branches

| Branch | Propósito |
|--------|-----------|
| `stable` | Branch principal, código estável |
| `akasha-main-sync` | Sync com Project Akasha (R&D) |
| `feature/*` | Features em desenvolvimento |
| `fix/*` | Bugfixes |

---

## Variáveis de Ambiente

| Variável | Valor | Obrigatória |
|----------|-------|-------------|
| `VSCODE_SKIP_NODE_VERSION_CHECK` | `1` | Sim (dev) |
| `HEXCORE_RELEASE_TOKEN` | PAT do GitHub | Só no CI |

---

## Troubleshooting

### "Cannot find module 'node-addon-api'"
```powershell
cd extensions/hexcore-{name}
npm install node-addon-api --save-dev
```

### "node-gyp rebuild" falha no Windows
- Verificar Visual Studio Build Tools 2022 com C++ workload
- Verificar Python 3.11+ no PATH
- Rodar: `npm config set msvs_version 2022`

### "prebuild-install" não encontra release
- Verificar se existe release no repo standalone com o asset correto
- Formato: `{name}-v{version}-napi-v8-win32-x64.tar.gz`
- Rodar workflow `hexcore-native-prebuilds.yml` para gerar

### Build do Electron falha
- Sempre rodar com `$env:VSCODE_SKIP_NODE_VERSION_CHECK = "1"`
- Verificar se `npm install` completou sem erros
- Verificar se prebuilds nativos foram instalados
