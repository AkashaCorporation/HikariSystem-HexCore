# Helix + HQL: Nota de Integracao

## Contexto

Este documento se baseia na snapshot de codigo atualmente disponivel em `AllInOne` em `2026-04-01`.

Importante: esta analise nao esta baseada na release publica mais recente da Helix, e sim nesta arvore local, que esta mais proxima da versao que estamos produzindo internamente. O objetivo aqui e alinhar implementacao, contrato de dados e responsabilidades entre Helix e HQL.

## O que e a HQL

HQL (Helix Query Language) e a camada de analise semantica que roda em cima da AST decompilada pela Helix.

Em vez de procurar bytes, opcodes ou assinaturas frageis, a HQL procura estruturas semanticas na AST, por exemplo:

- loops com padroes de XOR
- chamadas de API em certa ordem
- operacoes aritmeticas com constantes especificas
- padroes de obfuscacao, crypto, unpacking ou VM

Em resumo:

- A Helix produz a representacao estruturada do codigo decompilado.
- A HQL consome essa estrutura e executa queries/signatures semanticas.

## Fluxo ideal de integracao

O fluxo esperado entre Helix e HQL e este:

1. A Helix recebe LLVM IR ou binario levantado.
2. A Helix roda o pipeline MLIR e chega na representacao de alto nivel.
3. A Helix emite:
   - pseudo-C para visualizacao humana
   - AST em FlatBuffers como contrato estruturado
4. O bridge Node/Rust expoe esse buffer para o IDE.
5. A HQL le esse buffer, hidrata ou adapta para sua AST interna e executa o matcher.
6. Os resultados da HQL podem acionar automacoes, triagem, classificacao ou proximos estagios de analise.

## O que existe hoje nesta snapshot

### 1. A Helix ja tem schema FlatBuffers

Existem schemas definidos em:

- `schemas/ast.fbs`
- `schemas/cfg.fbs`
- `schemas/common.fbs`

Ou seja: o contrato de transporte por FlatBuffers ja esta previsto na arquitetura.

### 2. O pipeline da Helix ja chama emissao FlatBuffer

No pipeline C++ a etapa de emissao faz duas coisas:

- gera pseudo-C
- gera FlatBuffer

Isso aparece no fluxo de `Pipeline::decompile()`, onde a etapa `emitFlatBuffer()` chama `FlatBufSerializer`.

### 3. A FFI Rust ja suporta receber FlatBuffer da engine

A camada Rust tem funcao para chamar `helix_engine_decompile_ir()` e receber `Vec<u8>` com o resultado binario da engine.

Ou seja: a passagem de bytes do lado nativo para o lado Rust/Node ja esta desenhada.

### 4. A HQL atual trabalha sobre AST hidratada em TypeScript

A HQL atual nao le FlatBuffers diretamente.

Ela trabalha sobre objetos TypeScript no formato `CNode`, como:

- `CBinaryExpr`
- `CForStmt`
- `CFunctionDecl`
- `CVarDecl`

O matcher atual percorre essa AST tipada em memoria.

## Problemas atuais identificados nesta snapshot

### 1. O serializer C++ de AST ainda esta em estado stub

O arquivo `engine/src/emit/FlatBufSerializer.cpp` declara explicitamente que a implementacao atual e minima/stub.

Hoje ele:

- escreve um `HAST` valido do ponto de vista superficial
- escreve nome de modulo
- coleta nomes de funcoes
- ainda nao serializa a AST completa
- ainda nao popula o vetor de funcoes de forma completa no formato final esperado

Em outras palavras: a infraestrutura existe, mas a serializacao completa ainda nao esta pronta.

### 2. O contrato `ast.fbs` nao bate 1:1 com a AST da HQL

O schema da Helix hoje e um AST generico baseado em:

- `Expression`
- `Statement`
- `DecompiledFunction`
- `AstModule`

Ja a HQL espera uma AST tipada por tipo de no, com nomes como:

- `CBinaryExpr`
- `CUnaryExpr`
- `CCallExpr`
- `CBlockStmt`
- `CIfStmt`
- `CForStmt`
- `CFunctionDecl`

Isso significa que, mesmo quando a Helix emitir o `HAST` completo, a HQL ainda vai precisar de uma camada de adaptacao.

### 3. O runtime Rust de AST parece temporario e nao reflete o schema final

O modulo Rust em `crates/helix-core/src/flatbuf/ast.rs` usa uma estrutura simplificada com campos como:

- `source`
- `param_count`
- `local_count`
- `stmt_count`

Mas o `ast.fbs` real define `DecompiledFunction` com campos como:

- `return_type`
- `params`
- `locals`
- `body`
- `calling_convention`

Ou seja: nesta snapshot, a camada Rust de AST ainda parece provisoria e nao representa o schema completo final.

### 4. O `HelixEngine.decompileIr()` publico ainda retorna texto, nao AST FlatBuffer

Apesar de a FFI Rust conseguir receber FlatBuffer, a API publica do lado Node/TypeScript ainda usa o caminho `decompile_ir_text()` e retorna:

- `source`
- `ast_buffer: None`

Entao, para o consumidor TypeScript, o caminho oficial atual ainda nao entrega o AST binario completo.

### 5. A HQL ainda nao possui leitor/hidratador de FlatBuffers

No projeto da HQL atual nao existe:

- parser de `HAST`
- reader de FlatBuffers
- adaptador `HAST -> CNode`

Hoje os testes constroem a AST manualmente em TypeScript.

## Conclusao tecnica

Nesta snapshot, a integracao Helix + HQL esta arquiteturalmente prevista, mas ainda nao esta fechada de ponta a ponta.

Hoje existem 3 gaps principais:

1. A Helix ainda nao emite o `HAST` completo de forma confiavel para consumo externo.
2. A API publica do bridge ainda nao entrega esse AST para o lado TypeScript.
3. A HQL ainda nao tem a camada de leitura/adaptacao do `HAST` para a AST que o matcher usa.

## Recomendacao de arquitetura

A recomendacao mais segura e esta:

- A Helix continua sendo a fonte canonica da AST serializada em FlatBuffers.
- O contrato canonico deve ser o `ast.fbs` final e congelado antes de expandir o uso da HQL.
- A HQL deve possuir um adaptador proprio `HAST -> CNode`.
- O matcher da HQL nao precisa conhecer MLIR nem internals da engine.

Isso desacopla responsabilidades:

- Helix: produz AST canonica
- Bridge: entrega buffer
- HQL: adapta e consulta

## O que precisa ser implementado

### Etapa 1. Fechar o contrato canonico

Definir oficialmente se o contrato final sera:

- o `ast.fbs` atual
- ou uma versao nova mais proxima da AST `CNode` usada pela HQL

Sem essa definicao, a HQL nao consegue implementar a camada de entrada de forma estavel.

### Etapa 2. Implementar a serializacao completa no C++

O `FlatBufSerializer.cpp` precisa serializar de forma completa:

- modulo
- funcoes
- tipos
- variaveis
- statements
- expressions

Com isso, a Helix passa a ser de fato a produtora do `HAST`.

### Etapa 3. Expor `astBuffer` no bridge publico

O bridge `hexcore-helix` precisa expor um caminho publico que devolva o AST FlatBuffer ao consumidor TS.

Exemplos possiveis:

- completar `decompileIr()` para preencher `astBuffer`
- criar `decompileIrAst()`
- criar `decompileIrFull()` com `source + astBuffer`

### Etapa 4. Criar o adaptador na HQL

A HQL precisa de um modulo que:

- leia o buffer `HAST`
- converta `Expression/Statement/DecompiledFunction` para `CNode`
- entregue um `CFunctionDecl` ou `CBlockStmt` raiz para o matcher

### Etapa 5. Travar compatibilidade com testes

Precisamos de testes de contrato entre Helix e HQL:

- fixture de IR
- AST FlatBuffer emitida pela Helix
- hidracao na HQL
- queries rodando com match esperado

## Perguntas que precisam de resposta do lado Helix

1. O contrato canonico final da AST e realmente o `schemas/ast.fbs` atual?
2. A Helix pretende emitir uma AST generica ou uma AST ja mais proxima da `CNode` que a HQL usa?
3. O `FlatBufSerializer.cpp` desta snapshot ainda e placeholder oficial?
4. O `crates/helix-core/src/flatbuf/ast.rs` e temporario ou deve representar o schema final?
5. A API publica de Node deve retornar `astBuffer` no fluxo principal de `decompileIr()`?

## Sugestao pratica de divisao de trabalho

### Responsabilidade Helix

- finalizar schema canonico
- implementar emissao FlatBuffer completa
- expor `astBuffer` no bridge

### Responsabilidade HQL

- implementar leitor/adaptador `HAST -> CNode`
- manter o matcher semantico
- definir signatures/queries e resultados

## Resumo executivo

O problema atual nao e "a HQL nao funciona".

O problema atual e que o caminho de integracao ainda esta incompleto:

- a Helix ja preve FlatBuffers
- a HQL ja preve AST semantica
- mas ainda falta fechar o contrato, emitir a AST completa e adaptar esse contrato para o matcher da HQL

## Texto curto para encaminhamento

Segue um texto curto que pode ser enviado junto com este documento:

"Estamos alinhando a integracao entre a Helix e a HQL. A HQL e a camada de query semantica que roda sobre a AST decompilada pela Helix para detectar comportamentos, algoritmos e padroes estruturais sem depender de bytes/opcodes. Nesta snapshot, a arquitetura ja preve uso de FlatBuffers, mas a integracao ainda nao esta fechada de ponta a ponta: o serializer C++ de AST ainda esta parcial, o bridge publico ainda nao expoe `astBuffer` no fluxo principal, e a HQL ainda nao tem o adaptador de `HAST` para a AST tipada que o matcher usa. O objetivo agora e fechar esse contrato e implementar esse caminho completo."

