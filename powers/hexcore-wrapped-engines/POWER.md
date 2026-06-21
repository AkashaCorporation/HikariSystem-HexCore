<!--
  HexCore Wrapped Engines -- the POWER.md for the "embrulha ferramenta de terceiro"
  class of engine. Sibling of powers/hexcore-native-engines/POWER.md (the N-API /
  node-gyp class). If an engine compiles our OWN C/C++/Rust into a `.node` loaded
  in-process, it belongs in native-engines. If it WRAPS a pre-built third-party
  tool invoked as a SUBPROCESS, it belongs here.
-->

# HexCore Wrapped Engines

## Overview

Esta classe cobre engines que **embrulham uma ferramenta de terceiro pré-construída**
em vez de compilar um addon nativo nosso. O traço comum:

- **Não geram `.node`** e **não usam node-gyp / N-API**.
- O "motor" é um **binário externo** (nosso wrapper self-contained, ou o binário do
  terceiro) **invocado por subprocesso**, nunca carregado in-process.
- A integração na IDE é uma extension TS fininha (`extensions/hexcore-<nome>`) que
  **localiza e executa** o binário e parseia a saída.

Por que separar do `hexcore-native-engines`: quase **nada** daquele padrão se aplica
aqui -- sem `binding.gyp`, sem `prebuildify`, sem `prebuild-install`, sem loading
in-process, sem `--napi`. Misturar só confundiria. Esta doc é a fonte de verdade da
classe; o native POWER.md continua sendo a das engines `.node`.

## Membros da classe

| Engine | Ferramenta embrulhada | Licença | Estado | Issue |
|--------|----------------------|---------|--------|-------|
| **hexcore-revenant** | ILSpy / `ICSharpCode.Decompiler` (decompile .NET CIL -> C# / IL) | MIT | pre-alpha (MVP shell-out) | #32 (Better tier) |
| **hexcore-bindiff** (planejado) | Google BinDiff (diff binario) | proprietaria (redistribuicao restrita -- checar) | planejado | #21 |

> Lição: bindiff vai cair exatamente neste padrão. A diferença entre membros é só
> COMO o binario chega (a gente builda o nosso com `dotnet publish`, ou redistribui /
> localiza o do terceiro conforme a licença dele) -- o resto (subprocesso, locate,
> fallback, contrato TS) é compartilhado.

## Sourcing: WRAP, não FORK (o jeito Remill)

Regra da casa, idêntica ao Remill (que linka `libremill` pinado, não forka):

- **Pinar** uma versão exata da lib/ferramenta upstream e **embrulhar** a API pública dela.
  - Revenant: `<PackageReference Include="ICSharpCode.Decompiler" Version="8.2.0.7535" />`.
- **Nunca forkar** a menos que precise patchar as tripas do upstream (não é o caso). Fork =
  rebase eterno + arrasta a GUI/repo inteiro. Upgrade = bumpar a versão pinada, só.
- **Licença:** carregar o aviso (MIT do ILSpy / ICSharpCode.Decompiler) no THIRD-PARTY-LICENSES
  do pacote. Para um terceiro proprietário (BinDiff), confirmar se podemos redistribuir;
  se não, o install **localiza** a instalação do usuário em vez de baixar o binário.

## Padrão de estrutura

Dois pedaços, como nas nativas (extension + engine), mas o "engine" é um binário externo:

```
extensions/hexcore-<nome>/            <- a extension TS (cola da IDE)
  package.json                        <- comandos + config (path override, timeout)
  tsconfig.json
  src/
    extension.ts                      <- registra comandos (UI + headless {quiet,output})
    <tool>Runner.ts                   <- localiza + executa o binario, parseia saida, NUNCA lança
  bin/<plat>/<binario>                <- (fase 2) o binario prebuilt baixado p/ ca; gitignored
  test/                               <- contrato + casos de borda

StandalonePackagesHexCore/hexcore-<nome>-engine/   <- (managed) o projeto que VIRA o binario
  <Nome>.csproj                       <- PackageReference da lib pinada
  Program.cs                          <- o wrapper fino (args -> JSON/texto)
  .github/workflows/<nome>-prebuilds.yml
```

### Runner (o coração, e o que troca entre fases)

- **Localizar** o binario em ordem: config override -> `bin/<plat>/` baixado -> tool do
  sistema (ex: `ilspycmd` global) -> erro estruturado. Resolver um caminho CONCRETO
  (sem shell, sem superficie de injeção).
- **Gate** na deteção do alvo (Revenant: CLR header / PE dir 14, igual as outras 4 peças).
- **Nunca lançar:** todo erro (alvo errado, tool ausente, timeout, saida vazia) retorna
  `{ ok:false, error }` legivel.
- **Fase 1 (MVP):** o runner chama a tool do sistema (ilspycmd instalado).
  **Fase 2:** o MESMO runner aponta pro binario prebuilt baixado -- a superficie de
  comandos da extension não muda, só o backend.

## Build / Prebuild (a esteira, toolchain diferente)

Fluxo conceitual **idêntico** ao native (migrate -> CI -> zip na Release -> download no
assembly), trocando só a toolchain e o artefato:

| Etapa | Native (`.node`) | Wrapped / managed (Revenant) |
|-------|------------------|------------------------------|
| Build em CI | `prebuildify --napi --strip` | `dotnet publish -c Release -r <rid> --self-contained -p:PublishSingleFile=true` |
| Matriz | win/linux/macos x arch | mesmos RIDs (win-x64, linux-x64, osx-x64, osx-arm64) |
| Artefato | `...-napi-v8-<plat>-<arch>.tar.gz` | `hexcore-<nome>-v<ver>-<plat>-<arch>.tar.gz` (o binario unico) |
| Custo de build | pesado (compila C++/LLVM -> pode OOM) | **leve** (sem compile pesado; só linka lib gerenciada + copia runtime -- NÃO dá OOM) |
| Install | `prebuild-install` baixa da Release | install-script proprio baixa o binario p/ `bin/<plat>/` |
| Loading | `index.js` carrega o `.node` | runner aponta pro binario (subprocesso) |

> **Ponto-chave sobre OOM:** o que estoura memoria é o *compile* de C++/LLVM (Remill,
> Helix). `dotnet publish` é leve -- o binario é grande (~30-70MB self-contained), mas
> isso é tamanho de artefato, não custo de build. O prebuild desta classe é mais BARATO
> que o das nativas, não mais caro. O motivo de ir pro modelo standalone+download é
> **não inchar o repo principal** com o binario grande, não OOM.

> **Otimização futura:** `PublishAot=true` (Native AOT) gera binario nativo menor sem
> runtime embutido -- mas a ICSharpCode.Decompiler usa muita reflection, então AOT é
> arriscado. Default = self-contained single-file; testar AOT depois.

## Repo standalone

Cada membro ganha um repo standalone (paralelo aos das nativas) que hospeda o projeto do
binario + o workflow de prebuild. As modificações do motor são migradas pra la, o CI
builda por plataforma, sobe os zips na Release, e o assembly da HexCore baixa o binario
certo. Mesma esteira; toolchain (dotnet publish) e artefato (binario, não `.node`)
diferentes.

## Checklist de um novo wrapped engine

1. [ ] Decidir sourcing: pinar+wrap (default) vs localizar instalação do usuario (se a
   licença proibir redistribuição).
2. [ ] Extension TS: `extension.ts` (UI + headless) + `<tool>Runner.ts` (locate + run +
   parse, nunca lança) + gate de deteção do alvo.
3. [ ] Validar o mecanismo em binarios reais + casos de borda (alvo errado, corrompido,
   timeout, tool ausente) ANTES de congelar o contrato.
4. [ ] (managed) Projeto `.csproj` no repo standalone + `dotnet publish` self-contained +
   workflow de prebuild por RID.
5. [ ] install-script que baixa o binario pro `bin/<plat>/`; runner com fallback p/ tool
   do sistema em dev.
6. [ ] THIRD-PARTY-LICENSES com o aviso do upstream (MIT etc.).
7. [ ] Entrada na tabela "Membros da classe" desta doc.
