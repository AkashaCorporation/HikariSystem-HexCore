---
name: "hexcore-native-engines"
displayName: "HexCore Native Engines"
description: "Best practices para desenvolvimento de wrappers nativos N-API no projeto HexCore. Cobre padrão de estrutura, build system, prebuilds, e migração de módulos legados."
keywords: ["hexcore", "native", "napi", "capstone", "unicorn", "prebuild", "node-gyp", "wrapper"]
author: "HikariSystem"
---

# HexCore Native Engines

## Overview

Este Power documenta o padrão oficial para wrappers nativos N-API no projeto HikariSystem HexCore. O HexCore é uma IDE de análise de malware e engenharia reversa baseada no VS Code, que integra engines nativas como Capstone (disassembler), Unicorn (emulador), LLVM MC (assembler) e better-sqlite3 (banco de dados).

Todos os wrappers nativos devem seguir um padrão consistente para garantir builds reproduzíveis, prebuilds automatizados e integração limpa com o monorepo do HexCore.

Este guia serve como referência para agentes (Kiro, Claude Code) e desenvolvedores ao criar, manter ou migrar extensões nativas.

## Onboarding

### Pré-requisitos

- Node.js 18+ (produção) / 22.x (prebuilds CI)
- Python 3.11+ (para node-gyp)
- Visual Studio Build Tools 2022 com C++ workload (Windows)
- GCC/Clang com suporte a C++17 (Linux/macOS)
- `node-gyp`, `prebuildify`, `prebuild-install` instalados globalmente ou como devDependencies

### Estrutura do Monorepo

```
HikariSystem-HexCore/
├── extensions/
│   ├── hexcore-capstone/       # Wrapper Capstone (referência)
│   ├── hexcore-unicorn/        # Wrapper Unicorn (referência)
│   ├── hexcore-llvm-mc/        # Wrapper LLVM MC (referência)
│   ├── hexcore-better-sqlite3/ # SQLite (precisa migração)
│   └── hexcore-ioc/            # Usa better-sqlite3 como dependência
├── scripts/
│   └── hexcore-native-install.js  # Script compartilhado de install
└── .github/workflows/
    ├── hexcore-native-prebuilds.yml  # CI de prebuilds
    └── hexcore-build.yml             # CI de build geral
```

### Repos Standalone (GitHub)

Cada engine nativa tem um repo standalone onde o código-fonte e as releases de prebuilds vivem:

- `LXrdKnowkill/hexcore-capstone`
- `LXrdKnowkill/hexcore-unicorn`
- `LXrdKnowkill/hexcore-llvm-mc`
- `LXrdKnowkill/hexcore-better-sqlite3`

O monorepo contém uma cópia sincronizada de cada engine em `extensions/hexcore-{name}/`.

## Padrão de Estrutura de um Wrapper Nativo

### Arquivos Obrigatórios

```
extensions/hexcore-{name}/
├── src/
│   ├── main.cpp              # Entry point N-API (napi_register_module_v1)
│   ├── {name}_wrapper.cpp    # Implementação do wrapper
│   ├── {name}_wrapper.h      # Header do wrapper
│   └── {op}_async_worker.h   # AsyncWorker para operações pesadas
├── deps/
│   └── {lib}/                # Headers e libs da engine nativa
│       ├── include/          # Headers públicos
│       └── (libs estáticas ou dinâmicas por plataforma)
├── prebuilds/
│   └── {platform}-{arch}/    # Binários pré-compilados
│       └── {target_name}.node
├── test/
│   └── test.js               # Smoke tests
├── binding.gyp               # Configuração de build node-gyp
├── index.js                  # Entry point CJS com fallback loading
├── index.mjs                 # ESM wrapper via createRequire
├── index.d.ts                # TypeScript definitions (tipos próprios)
├── package.json              # Metadados e scripts
├── .gitignore
├── .vscodeignore
├── README.md
└── LICENSE
```

### Arquivos Proibidos no Padrão

- `node-gyp-build` como dependência runtime
- `bindings` como dependência runtime
- Importação de tipos de pacotes npm externos no `index.d.ts`
- `lib/` como diretório de JavaScript intermediário (exceto se necessário pela lib original)

## package.json - Padrão

```json
{
  "name": "hexcore-{name}",
  "version": "X.Y.Z",
  "description": "Descrição clara do wrapper",
  "main": "./index.js",
  "module": "./index.mjs",
  "types": "./index.d.ts",
  "exports": {
    ".": {
      "import": "./index.mjs",
      "require": "./index.js",
      "types": "./index.d.ts"
    }
  },
  "scripts": {
    "install": "node ../../scripts/hexcore-native-install.js",
    "build": "node-gyp rebuild",
    "build:debug": "node-gyp rebuild --debug",
    "prebuild": "prebuildify --napi --strip",
    "test": "node test/test.js",
    "clean": "node-gyp clean"
  },
  "engines": {
    "vscode": "^1.0.0",
    "node": ">=18.0.0"
  },
  "activationEvents": [],
  "binary": {
    "napi_versions": [8]
  },
  "author": "HikariSystem",
  "license": "MIT"
}
```

### Pontos Críticos

- `"install"` DEVE usar `node ../../scripts/hexcore-native-install.js` (script compartilhado)
- `"exports"` DEVE ter dual CJS/ESM com types
- `"binary.napi_versions"` DEVE ser `[8]`
- Zero dependências runtime (sem `bindings`, sem `node-gyp-build`)
- `devDependencies`: `prebuildify`, `prebuild-install`, `node-addon-api`, `node-gyp`

## binding.gyp - Padrão

```python
{
  "targets": [{
    "target_name": "hexcore_{name}",
    "sources": [
      "src/main.cpp",
      "src/{name}_wrapper.cpp"
    ],
    "include_dirs": [
      "<!@(node -p \"require('node-addon-api').include\")",
      "deps/{lib}/include"
    ],
    "defines": [
      "NAPI_VERSION=8",
      "NAPI_DISABLE_CPP_EXCEPTIONS"
    ],
    "conditions": [
      ["OS=='win'", {
        "libraries": ["<(module_root_dir)/deps/{lib}/{lib}.lib"],
        "msvs_settings": {
          "VCCLCompilerTool": {
            "ExceptionHandling": 1,
            "AdditionalOptions": ["/std:c++17"]
          }
        }
      }],
      ["OS=='linux'", {
        "libraries": ["<(module_root_dir)/deps/{lib}/lib{lib}.a"],
        "cflags": ["-fPIC"],
        "cflags_cc": ["-fPIC", "-std=c++17"]
      }],
      ["OS=='mac'", {
        "libraries": ["<(module_root_dir)/deps/{lib}/lib{lib}.a"],
        "xcode_settings": {
          "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
          "CLANG_CXX_LIBRARY": "libc++",
          "MACOSX_DEPLOYMENT_TARGET": "10.15"
        }
      }]
    ]
  }]
}
```

### Regras do binding.gyp

- `target_name` segue o padrão `hexcore_{name}` (underscore, não hyphen)
- N-API versão 8 obrigatório
- C++17 mínimo em todas as plataformas
- Libs estáticas preferidas (exceto Unicorn que usa DLL dinâmica)
- Se a engine usa DLL dinâmica, usar `"copies"` para copiar para `build/Release/`

## index.js - Padrão de Loading

```javascript
'use strict';

let binding;
try {
    binding = require('./prebuilds/' + process.platform + '-' + process.arch + '/hexcore_{name}.node');
} catch (e1) {
    try {
        binding = require('./build/Release/hexcore_{name}.node');
    } catch (e2) {
        try {
            binding = require('./build/Debug/hexcore_{name}.node');
        } catch (e3) {
            throw new Error(
                'Failed to load hexcore-{name} native module. ' +
                'Errors:\n' +
                `  Prebuild: ${e1.message}\n` +
                `  Release: ${e2.message}\n` +
                `  Debug: ${e3.message}`
            );
        }
    }
}

module.exports = binding;
module.exports.default = binding.{MainClass};
module.exports.{MainClass} = binding.{MainClass};
// ... demais exports nomeados
```

### Ordem de Fallback (obrigatória)

1. `prebuilds/{platform}-{arch}/{target}.node` (prebuildify)
2. `build/Release/{target}.node` (node-gyp release)
3. `build/Debug/{target}.node` (node-gyp debug)

### Caso Especial: DLLs Dinâmicas (Unicorn)

Se a engine depende de DLLs dinâmicas, adicionar no topo do `index.js`:

```javascript
if (process.platform === 'win32') {
    const depsDir = path.join(__dirname, 'deps', '{lib}');
    if (fs.existsSync(path.join(depsDir, '{lib}.dll'))) {
        process.env.PATH = `${depsDir};${process.env.PATH || ''}`;
    }
}
```

## index.mjs - ESM Wrapper

```javascript
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const binding = require('./index.js');

export const { MainClass, CONST1, CONST2, version } = binding;
export default binding;
```

## index.d.ts - TypeScript Definitions

- DEVE definir todos os tipos inline (não importar de pacotes npm externos)
- DEVE documentar com JSDoc todas as classes, métodos e constantes
- DEVE incluir exemplos de uso nos JSDoc das classes principais
- Interfaces para constantes devem usar `readonly`

## Workflow de Prebuilds

### Como Funciona

1. O workflow `hexcore-native-prebuilds.yml` é disparado manualmente via `workflow_dispatch`
2. Para cada engine na matrix, ele:
   - Faz checkout do repo standalone (ex: `LXrdKnowkill/hexcore-capstone`)
   - Instala deps com `npm ci --ignore-scripts`
   - Roda `npm run prebuild` → `prebuildify --napi --strip`
   - Empacota `prebuilds/` em `{name}-v{version}-napi-v8-win32-x64.tar.gz`
   - Faz upload como artifact do GitHub Actions
   - Se `HEXCORE_RELEASE_TOKEN` existe, cria/atualiza uma GitHub Release no repo da engine

### Como Atualizar uma Engine

Quando você atualiza uma engine (ex: nova versão do Unicorn):

1. Atualize o código no repo standalone (`LXrdKnowkill/hexcore-{name}`)
2. Bumpe a versão no `package.json` do repo standalone
3. Dispare o workflow `hexcore-native-prebuilds.yml` no monorepo
4. O workflow vai:
   - Buildar os prebuilds com a nova versão
   - Criar uma release `v{nova_versão}` no repo standalone
   - Upload do `.tar.gz` na release
5. Sincronize o código atualizado para `extensions/hexcore-{name}/` no monorepo
6. Rode `node ../../scripts/hexcore-native-install.js` na extensão para baixar os novos prebuilds

### hexcore-native-install.js (Script Compartilhado)

O script de install compartilhado (`scripts/hexcore-native-install.js`) faz:

1. Tenta `prebuild-install` (baixa prebuilds da GitHub Release)
2. Se falhar, faz fallback para `node-gyp rebuild` (compila localmente)
3. Para Unicorn especificamente, copia DLLs runtime para o diretório do binário

### Formato do Asset de Release

```
{package-name}-v{version}-napi-v{napi}-{platform}-{arch}.tar.gz
```

Exemplo: `hexcore-capstone-v1.3.1-napi-v8-win32-x64.tar.gz`

## Migração do better-sqlite3

### Estado Atual (Não-Conforme)

O `hexcore-better-sqlite3` atualmente diverge do padrão em vários pontos:

| Aspecto | Padrão | better-sqlite3 (atual) |
|---------|--------|----------------------|
| Install script | `hexcore-native-install.js` | `node-gyp-build` |
| Loading | Fallback manual 3 níveis | `bindings` + `node-gyp-build` |
| Source | `main.cpp` + wrapper separado | Monolítico (`better_sqlite3.cpp`) |
| TypeScript defs | Tipos próprios inline | Importa de `better-sqlite3` npm |
| Runtime deps | Zero | `bindings`, `node-gyp-build` |
| Exports field | Dual CJS/ESM | Parcial |
| Entry point | `./index.js` | `lib/index.js` → `lib/database.js` |

### Dependentes

- `hexcore-ioc` usa `hexcore-better-sqlite3` via `file:../hexcore-better-sqlite3`
- A interface usada pelo IOC é mínima: `openDatabase(filename, options)` retornando um objeto com `exec()`, `prepare()`, `close()`

### Estratégia de Migração Recomendada

Dado que o better-sqlite3 tem uma estrutura interna complexa (`lib/database.js`, `lib/methods/`, etc.), a recomendação é:

1. Manter o C++ existente (`better_sqlite3.cpp` + `.hpp`) - funciona e é estável
2. Criar um `src/main.cpp` que re-exporta o módulo nativo existente (ou manter o binding atual se o refactor C++ for muito arriscado)
3. Reescrever `index.js` com o padrão de fallback loading
4. Reescrever `index.d.ts` com tipos próprios inline (sem importar de `better-sqlite3` npm)
5. Adicionar `"exports"` field no `package.json`
6. Trocar `"install"` para `node ../../scripts/hexcore-native-install.js`
7. Remover `bindings` e `node-gyp-build` das dependencies
8. Testar que `hexcore-ioc` continua funcionando

### Risco: Reverter vs Refazer

- Reverter o fork inteiro e recomeçar do zero é arriscado porque o C++ nativo já funciona
- Melhor abordagem: manter o core C++ e refatorar apenas a camada JavaScript/TypeScript de interface

## Troubleshooting

### Prebuild não encontrado no install

- Verifique se existe uma release no repo standalone com o asset correto
- O formato deve ser: `{name}-v{version}-napi-v8-{platform}-{arch}.tar.gz`
- Se não existir, dispare o workflow de prebuilds

### node-gyp rebuild falha

- Windows: Verifique Visual Studio Build Tools 2022 com C++ workload
- Verifique Python 3.11+ no PATH
- Verifique que `deps/{lib}/` contém os headers e libs necessários

### DLL não encontrada (Unicorn)

- Verifique que `deps/unicorn/unicorn.dll` existe
- O `index.js` deve adicionar o diretório ao PATH antes de carregar o addon

### TypeScript errors no index.d.ts

- Nunca importar tipos de pacotes npm externos
- Definir todas as interfaces e tipos inline

## Best Practices

- Sempre use N-API 8 para máxima compatibilidade
- Prefira libs estáticas sobre dinâmicas (menos problemas de runtime)
- Use AsyncWorker para operações que podem bloquear (disassembly de buffers grandes, emulação)
- Mantenha zero dependências runtime nos wrappers nativos
- Teste com `node test/test.js` antes de gerar prebuilds
- Sincronize o repo standalone com o monorepo após cada atualização
- Documente todas as constantes e classes no `index.d.ts` com JSDoc

## Referência Rápida de Comandos

```bash
# Build local (desenvolvimento)
cd extensions/hexcore-{name}
npm run build

# Build debug
npm run build:debug

# Gerar prebuilds localmente
npm run prebuild

# Testar
npm test

# Limpar build
npm run clean

# Install com prebuilds (no monorepo)
node ../../scripts/hexcore-native-install.js
```

---

**Engines**: Capstone, Unicorn, LLVM MC, better-sqlite3
**N-API**: v8 | **C++**: 17+ | **Node**: 18+
