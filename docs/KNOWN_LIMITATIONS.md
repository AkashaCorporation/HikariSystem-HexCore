# Known Limitations — HexCore v3.3.0

Limitações conhecidas e workarounds para a versão atual.

---

## Build & CI

### 1. Prebuilds apenas para Windows (win32-x64)
- **Status:** Limitação ativa
- **Impacto:** Linux e macOS não têm prebuilds pré-compilados
- **Workaround:** Nessas plataformas, `hexcore-native-install.js` faz fallback para `node-gyp rebuild`
- **Solução futura:** Adicionar runners Linux/macOS ao workflow `hexcore-native-prebuilds.yml`

### 2. GitHub Actions — Minutos pagos em repo privado
- **Status:** Limitação ativa
- **Impacto:** Project-Akasha (privado) consome minutos do plano Free (2.000/mês)
- **Detalhes:** Windows runners têm multiplicador 2x. Workflow de prebuilds (~6 min) = ~12 min do plano
- **Workaround:** Rodar workflows no HikariSystem-HexCore (público, minutos ilimitados)
- **Solução futura:** Mover workflow de prebuilds para o repo público

### 3. Check "Prevent package-lock.json changes" falha em PRs
- **Status:** Limitação herdada do VS Code upstream
- **Impacto:** PRs que alteram package-lock.json mostram check falhando
- **Detalhes:** O workflow tenta verificar permissões no repo `microsoft/vscode` (403)
- **Workaround:** O check não é blocking — pode mergear mesmo com falha
- **Solução futura:** Desabilitar ou adaptar o workflow para o fork HexCore

### 4. Check de collaborator tenta acessar microsoft/vscode
- **Status:** Limitação herdada
- **Impacto:** Erro 403 nos logs do CI (cosmético, não bloqueia)
- **Detalhes:** `octokit/request-action` faz GET em `/repos/microsoft/vscode/collaborators/`
- **Workaround:** Ignorar
- **Solução futura:** Remover ou adaptar o workflow

---

## Extensões Nativas

### 5. better-sqlite3 — lib/ layer mantida por compatibilidade
- **Status:** Decisão de design
- **Impacto:** A pasta `lib/` com `database.js`, `methods/` etc. é mantida para compatibilidade
- **Detalhes:** O padrão HexCore proíbe `lib/` como diretório JS intermediário, mas o better-sqlite3
  precisa dele para manter a API `new Database()` com transactions, aggregates, etc.
- **Workaround:** Aceito como exceção documentada
- **Solução futura:** Migrar funcionalidades de `lib/` para o wrapper C++ gradualmente

### 6. Unicorn — DLL dinâmica necessária no Windows
- **Status:** Limitação da engine
- **Impacto:** `unicorn.dll` precisa estar no PATH ou no diretório do binário
- **Detalhes:** Diferente das outras engines que usam libs estáticas
- **Workaround:** `index.js` adiciona `deps/unicorn/` ao PATH automaticamente
- **Solução futura:** Nenhuma — é característica da engine Unicorn

### 7. LLVM MC — Asset de deps precisa ser baixado separadamente
- **Status:** Limitação ativa
- **Impacto:** O workflow de prebuilds tem step especial para baixar `llvm-win32-x64.zip`
- **Detalhes:** As libs LLVM são grandes demais para incluir no repo
- **Workaround:** Step condicional no workflow faz download automático
- **Solução futura:** Nenhuma necessária — funciona bem

---

## Plataforma

### 8. HexCore congelado na base VS Code 3.2.2
- **Status:** Limitação temporária
- **Impacto:** Não é possível atualizar para VS Code 3.3.0+ upstream
- **Detalhes:** Erro de build ao tentar atualizar a base do VS Code
- **Workaround:** Manter na base 3.2.2 e aplicar patches HexCore por cima
- **Solução futura:** Investigar e resolver o erro de build do upstream 3.3.0

### 9. Electron 39.2.7 — Versão fixa
- **Status:** Limitação de compatibilidade
- **Impacto:** Não atualizar Electron sem testar todas as extensões nativas
- **Detalhes:** Mudança de Electron pode quebrar N-API bindings
- **Workaround:** Manter versão fixa, testar antes de atualizar
- **Solução futura:** Testar com Electron mais recente quando estabilizar

---

## Segurança

### 10. HEXCORE_RELEASE_TOKEN — Permissões mínimas
- **Status:** Configuração necessária
- **Impacto:** Sem o token, prebuilds não são publicados como releases
- **Detalhes:** Token precisa de `Contents: Read and write` nos 4 repos standalone
- **Nota:** NÃO usar `Codespaces` — usar `Contents`

---

## Documentação

### 11. POWER.md — Seção de migração do better-sqlite3 desatualizada
- **Status:** Cosmético
- **Impacto:** O POWER.md ainda descreve o better-sqlite3 como "precisa migração"
- **Detalhes:** A migração já foi concluída na v3.3.0
- **Solução:** Atualizar POWER.md para refletir o estado atual
