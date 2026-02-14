# Runbook — Native Prebuilds

Passo a passo para gerar, publicar e consumir prebuilds nativos (.node) no HexCore.

---

## Visão Geral do Fluxo

```
Repo Standalone          Workflow (Akasha/HexCore)       Repo Standalone
(código fonte)    →      (build + prebuildify)      →    (GitHub Release)
                                                              ↓
                         Monorepo (npm install)     ←    (prebuild-install)
```

---

## 1. Atualizar uma Engine

### 1.1 Atualizar código no repo standalone

```powershell
cd C:\Users\Mazum\Desktop\StandalonePackagesHexCore\hexcore-{name}

# Fazer alterações no código C++/JS
# ...

# Bumpar versão no package.json
# Ex: 1.0.0 → 1.1.0
```

### 1.2 Commitar e pushar

```powershell
git add -A
git commit -m "feat: descricao da mudanca"
git push origin main
```

### 1.3 Bumpar versão no monorepo também

```powershell
cd C:\Users\Mazum\Desktop\vscode-main\extensions\hexcore-{name}
# Atualizar package.json com a mesma versão
```

---

## 2. Gerar Prebuilds via CI

### 2.1 Disparar o workflow

1. Ir em GitHub → Project-Akasha (ou HikariSystem-HexCore) → Actions
2. Selecionar "HexCore Native Prebuilds"
3. Clicar "Run workflow"
4. Selecionar branch (geralmente `main` ou `stable`)
5. Opcionalmente marcar "Include experimental engines"

### 2.2 O que o workflow faz

Para cada engine na matrix:
1. `actions/checkout` do repo standalone
2. `npm ci --ignore-scripts` (instala devDependencies)
3. `npm run prebuild` → `prebuildify --napi --strip`
4. Empacota `prebuilds/` em `.tar.gz`
5. Upload como artifact do GitHub Actions
6. Se `HEXCORE_RELEASE_TOKEN` existe → cria/atualiza GitHub Release no repo standalone

### 2.3 Engines na matrix

| Engine | Repo | Versão Atual |
|--------|------|-------------|
| hexcore-capstone | LXrdKnowkill/hexcore-capstone | 1.3.1 |
| hexcore-unicorn | LXrdKnowkill/hexcore-unicorn | 1.2.0 |
| hexcore-llvm-mc | LXrdKnowkill/hexcore-llvm-mc | 1.0.0 |
| hexcore-better-sqlite3 | LXrdKnowkill/hexcore-better-sqlite3 | 2.0.0 |
| hexcore-remill | LXrdKnowkill/hexcore-remill | 0.1.1 | Requer deps zip da release (131 MB) + semantics tarball |

### 2.4 Engines experimentais

Só rodam quando "Include experimental engines" está marcado no dispatch.

| Engine | Repo | Versão Atual | Nota |
|--------|------|-------------|------|
| hexcore-rellic | LXrdKnowkill/hexcore-rellic | — | Planejado |

---

## 3. Configurar HEXCORE_RELEASE_TOKEN

Sem esse token, os prebuilds ficam apenas como artifacts temporários do Actions.
Com o token, eles são publicados como releases permanentes nos repos standalone.

### 3.1 Gerar o token

1. GitHub → Settings (perfil) → Developer settings → Personal access tokens → Fine-grained tokens
2. Nome: `HEXCORE_RELEASE_TOKEN`
3. Repository access: selecionar os 4 repos standalone
4. Permissions: `Contents: Read and write`
5. Gerar e copiar

### 3.2 Adicionar como secret

1. Ir no repo onde o workflow roda (Project-Akasha ou HikariSystem-HexCore)
2. Settings → Secrets and variables → Actions
3. New repository secret
4. Nome: `HEXCORE_RELEASE_TOKEN`
5. Valor: colar o token

---

## 4. Formato dos Assets

```
{package-name}-v{version}-napi-v{napi}-{platform}-{arch}.tar.gz
```

Exemplos:
- `hexcore-capstone-v1.3.1-napi-v8-win32-x64.tar.gz`
- `hexcore-unicorn-v1.2.0-napi-v8-win32-x64.tar.gz`
- `hexcore-better-sqlite3-v2.0.0-napi-v8-win32-x64.tar.gz`

Conteúdo do .tar.gz:
```
prebuilds/
  win32-x64/
    hexcore-{name}.node    ← o binário nativo
```

---

## 5. Consumir Prebuilds no Monorepo

O script `scripts/hexcore-native-install.js` é chamado automaticamente no `npm install`.

Ordem de tentativa:
1. Prebuild local (`prebuilds/{platform}-{arch}/`)
2. Download da GitHub Release via `prebuild-install`
3. Fallback: `node-gyp rebuild` (compila localmente)

### Forçar re-download
```powershell
cd extensions/hexcore-{name}
rm -rf prebuilds
node ../../scripts/hexcore-native-install.js
```

---

## 6. Verificar Prebuild Instalado

```powershell
# Capstone
node -e "const cs = require('./extensions/hexcore-capstone'); console.log('Capstone OK:', cs.version())"

# Unicorn
node -e "const uc = require('./extensions/hexcore-unicorn'); console.log('Unicorn OK')"

# SQLite
node -e "const db = require('./extensions/hexcore-better-sqlite3')(':memory:'); console.log('SQLite OK:', db.pragma('compile_options').length, 'options'); db.close()"
```

---

## 7. Troubleshooting

### Release não foi criada
- Verificar se `HEXCORE_RELEASE_TOKEN` existe como secret no repo do workflow
- Verificar se o token tem permissão `Contents: Read and write` nos repos standalone
- Verificar logs do step "Upload Prebuilds to Release"

### prebuild-install retorna 404
- A release com a versão correta não existe no repo standalone
- Rodar o workflow de prebuilds para gerar

### Versão antiga do prebuild
- O workflow usa `--clobber` para sobrescrever assets existentes
- Se a versão não mudou, o asset é sobrescrito (mesmo binário, mesmo nome)
- Para forçar novo build: bumpar versão no package.json do standalone

### Repo privado consome minutos
- Windows runners: 2x multiplicador (1 min real = 2 min do plano)
- Workflow de ~6 min = ~12 min do plano
- Solução: mover workflow para repo público (minutos ilimitados)
