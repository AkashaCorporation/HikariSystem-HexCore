import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import Database = require('hexcore-better-sqlite3');

import {
  buildFunctionAtlasRecord,
  buildFunctionAtlasBenchmarkArtifact,
  InMemoryFunctionAtlasIndex,
  rankFunctionAtlasRecords,
  SqliteFunctionAtlasIndex,
  validateFunctionAtlasRecord,
  validateFunctionAtlasProvenance,
  type FunctionAtlasProvenance,
} from '../src/atlas/functionAtlas';
import type { CFunctionDecl, CNode } from '../src/types/ast';
import { evaluateSimilarityBenchmark, evaluateSimilarityQueries } from '../benchmarks/bsim/evaluate';

const digest = (character: string): string => character.repeat(64);

function provenance(sampleId: string, compiler = 'msvc', binary = digest('a')): FunctionAtlasProvenance {
  return {
    corpusId: 'function-atlas-fixture',
    corpusVersion: '1',
    sampleId,
    sourceSha256: digest('b'),
    groundTruthSha256: digest('c'),
    binarySha256: binary,
    architecture: 'x86_64',
    format: 'pe64',
    compiler: {
      name: compiler,
      version: compiler === 'msvc' ? '19.44.35217' : '18.1.8',
      targetTriple: 'x86_64-pc-windows-msvc',
      optimization: 'O2',
      flags: ['/O2', '/Brepro'],
    },
    producer: { name: 'helix', version: '0.9.3-rc', hastSchema: 1 },
  };
}

function ref(name: string): CNode {
  return { kind: 'CVarRefExpr', name, type: 'uint32_t', storage: 'parameter' };
}

function semanticFunction(name: string, address: string, variable: string, constant = 16777619): CFunctionDecl {
  return {
    kind: 'CFunctionDecl',
    name,
    address,
    returnType: 'uint32_t',
    params: [{ kind: 'CVarDecl', name: variable, type: 'uint32_t', storage: 'parameter', parameterIndex: 0 }],
    body: {
      kind: 'CBlockStmt',
      body: [{
        kind: 'CWhileStmt',
        condition: {
          kind: 'CBinaryExpr',
          operator: '!=',
          left: ref(variable),
          right: { kind: 'CIntLitExpr', value: 0, width: 32, signed: false },
        },
        body: {
          kind: 'CBlockStmt',
          body: [{
            kind: 'CAssignStmt',
            target: ref(variable),
            value: {
              kind: 'CBinaryExpr',
              operator: '*',
              left: {
                kind: 'CBinaryExpr',
                operator: '^',
                left: ref(variable),
                right: { kind: 'CIntLitExpr', value: 2166136261, width: 32, signed: false },
              },
              right: { kind: 'CIntLitExpr', value: constant, width: 32, signed: false },
            },
          }],
        },
      }, {
        kind: 'CReturnStmt',
        value: ref(variable),
      }],
    },
  };
}

function unrelatedFunction(): CFunctionDecl {
  return {
    kind: 'CFunctionDecl',
    name: 'decode_packet',
    returnType: 'int32_t',
    params: [],
    body: {
      kind: 'CBlockStmt',
      body: [{
        kind: 'CIfStmt',
        condition: { kind: 'CCallExpr', callee: 'ReadFile', arguments: [] },
        then: { kind: 'CReturnStmt', value: { kind: 'CIntLitExpr', value: 1, width: 32, signed: true } },
        else: { kind: 'CReturnStmt', value: { kind: 'CIntLitExpr', value: -1, width: 32, signed: true } },
      }],
    },
  };
}

function trivialFunction(): CFunctionDecl {
  return {
    kind: 'CFunctionDecl',
    name: 'return_zero',
    returnType: 'int32_t',
    params: [],
    body: {
      kind: 'CBlockStmt',
      body: [{ kind: 'CReturnStmt', value: { kind: 'CIntLitExpr', value: 0, width: 32, signed: true } }],
    },
  };
}

const renamedA = buildFunctionAtlasRecord({
  function: semanticFunction('sub_140001000', '0x140001000', 'v1'),
  provenance: provenance('msvc-x64-O2', 'msvc', digest('a')),
});
const renamedB = buildFunctionAtlasRecord({
  function: semanticFunction('bench_fnv1_32', '0x180002000', 'hash'),
  provenance: provenance('clang-x64-O2', 'clang-cl', digest('d')),
});

assert.equal(renamedA.contentId, renamedB.contentId, 'normalized content ignores generated names and addresses');
assert.equal(renamedA.featureVectorSha256, renamedB.featureVectorSha256, 'normalized vectors are byte-stable');
assert.equal(renamedA.simHash64, renamedB.simHash64, 'simhash is deterministic');
assert.notEqual(renamedA.instanceId, renamedB.instanceId, 'exact compiler/corpus instances remain distinct');

const withComment = semanticFunction('commented', '0x140003000', 'renamed');
withComment.body!.body.unshift({ kind: 'CCommentStmt', text: 'volatile decompiler annotation' });
assert.equal(
  buildFunctionAtlasRecord({ function: withComment, provenance: provenance('commented', 'clang-cl', digest('f')) }).contentId,
  renamedA.contentId,
  'non-semantic comments do not perturb semantic content identity',
);

const changedConstant = buildFunctionAtlasRecord({
  function: semanticFunction('bench_fnv1_32', '0x180002000', 'hash', 31),
  provenance: provenance('clang-x64-O2-changed', 'clang-cl', digest('e')),
});
assert.notEqual(renamedA.contentId, changedConstant.contentId, 'semantic constants affect content identity');
assert.throws(
  () => validateFunctionAtlasRecord({ ...renamedA, simHash64: '0000000000000000' }),
  /simhash drift/,
  'content-addressed records reject feature/simhash tampering',
);

assert.throws(() => validateFunctionAtlasProvenance({
  ...provenance('invalid'),
  binarySha256: 'not-a-digest',
}), /binarySha256/, 'invalid provenance cannot enter the Atlas');

const unrelated = buildFunctionAtlasRecord({
  function: unrelatedFunction(),
  provenance: provenance('unrelated', 'clang-cl', digest('e')),
});
const index = new InMemoryFunctionAtlasIndex();
assert.equal(index.add(renamedB).indexed, true);
assert.equal(index.add(unrelated).indexed, true);
const ranked = index.query(renamedA, { topK: 5 });
assert.equal(ranked.suppressed, false);
assert.equal(ranked.matches[0]?.instanceId, renamedB.instanceId, 'same semantic function ranks first across compilers');
assert.equal(ranked.matches[0]?.similarity, 1);
assert.notEqual(ranked.matches[0]?.similarity, ranked.matches[0]?.significance, 'significance is not a renamed similarity score');
assert.ok((ranked.matches[0]?.significance ?? 0) > 0);
const benchmarkArtifact = buildFunctionAtlasBenchmarkArtifact([{ record: renamedA, result: ranked }]);
assert.equal(benchmarkArtifact.program, 'msvc-x64-O2');
assert.equal(
  benchmarkArtifact.artifactSha256,
  buildFunctionAtlasBenchmarkArtifact([{ record: renamedA, result: ranked }]).artifactSha256,
  'Function Atlas benchmark interchange is content addressed and deterministic',
);

const tiedA = buildFunctionAtlasRecord({
  function: semanticFunction('fn_a', '0x1000', 'x'),
  provenance: provenance('tie-a', 'clang-cl', digest('1')),
});
const tiedB = buildFunctionAtlasRecord({
  function: semanticFunction('fn_b', '0x2000', 'y'),
  provenance: provenance('tie-b', 'clang-cl', digest('2')),
});
const ties = rankFunctionAtlasRecords(renamedA, [tiedB, tiedA], { topK: 2 });
assert.deepEqual(
  ties.matches.map(match => match.instanceId),
  [tiedA.instanceId, tiedB.instanceId].sort(),
  'equal scores use deterministic content/instance identity tie-breaks',
);

const trivial = buildFunctionAtlasRecord({ function: trivialFunction(), provenance: provenance('trivial', 'msvc', digest('3')) });
assert.equal(trivial.triviality.trivial, true);
assert.equal(index.add(trivial).indexed, false, 'trivial functions are suppressed at ingestion');
assert.equal(index.query(trivial).suppressed, true, 'trivial queries are explicitly suppressed');
assert.equal(index.add(trivial, { includeTrivial: true }).indexed, true, 'explicit research override remains possible');

const sqlite = new Database(':memory:');
try {
  const sqliteIndex = new SqliteFunctionAtlasIndex(sqlite);
  assert.equal(sqliteIndex.add(renamedB).indexed, true);
  assert.equal(sqliteIndex.add(unrelated).indexed, true);
  assert.equal(sqliteIndex.query(renamedA, { topK: 1 }).matches[0]?.instanceId, renamedB.instanceId);
  assert.equal(sqliteIndex.list().length, 2, 'SQLite and memory indices expose the same canonical record contract');
  assert.equal(sqliteIndex.remove(unrelated.instanceId), true);
} finally {
  sqlite.close();
}

const metrics = evaluateSimilarityQueries([
  {
    program: 'compiler-a.dll',
    function: 'bench_fnv1_32',
    matches: [
      { executable: 'compiler-b.dll', function: 'bench_plain_add', similarity: 0.99 },
      { executable: 'compiler-b.dll', function: 'bench_fnv1_32', similarity: 0.98 },
    ],
  },
  {
    program: 'compiler-b.dll',
    function: 'bench_fnv1_32',
    matches: [{ executable: 'compiler-a.dll', function: 'bench_fnv1_32', similarity: 1 }],
  },
], { functions: { bench_fnv1_32: [], bench_plain_add: [] } });
assert.equal(metrics.eligibleQueryCount, 2);
assert.equal(metrics.top1Accuracy, 0.5);
assert.equal(metrics.top5Accuracy, 1);
assert.equal(metrics.meanReciprocalRank, 0.75);
assert.equal(metrics.recall, 1);
assert.equal(metrics.falseMatches, 1);

const evaluationRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-function-atlas-'));
try {
  const bsimRoot = path.join(evaluationRoot, 'bsim');
  const atlasRoot = path.join(evaluationRoot, 'atlas');
  fs.mkdirSync(bsimRoot);
  fs.mkdirSync(atlasRoot);
  const docs = [
    { program: 'compiler-a.dll', other: 'compiler-b.dll' },
    { program: 'compiler-b.dll', other: 'compiler-a.dll' },
  ];
  for (const [index, doc] of docs.entries()) {
    fs.writeFileSync(path.join(bsimRoot, `${index}.json`), JSON.stringify({
      schemaVersion: 1,
      program: doc.program,
      executableSha256: digest(index === 0 ? '4' : '5'),
      queries: [{
        function: 'bench_fnv1_32',
        matches: [{ executable: doc.other, function: 'bench_fnv1_32', similarity: 1, significance: 12 }],
      }],
    }));
    fs.writeFileSync(path.join(atlasRoot, `${index}.json`), JSON.stringify({
      program: doc.program,
      binarySha256: digest(index === 0 ? '4' : '5'),
      queries: [{
        sourceFunctionName: 'bench_fnv1_32',
        matches: [{ executable: doc.other, sourceFunctionName: 'bench_fnv1_32', similarity: 1, significance: 0.9 }],
      }],
    }));
  }
  const groundTruthPath = path.join(evaluationRoot, 'ground-truth.json');
  fs.writeFileSync(groundTruthPath, JSON.stringify({ functions: { bench_fnv1_32: [] } }));
  const comparison = evaluateSimilarityBenchmark({
    bsimPath: bsimRoot,
    functionAtlasPath: atlasRoot,
    groundTruthPath,
  });
  assert.equal(comparison.bsim.metrics.top1Accuracy, 1);
  assert.equal(comparison.functionAtlas?.metrics.top1Accuracy, 1);
  assert.equal(comparison.comparison?.recallDelta, 0);
  assert.equal(comparison.comparison?.falseMatchesDelta, 0, 'both engines are adjudicated by one ground-truth contract');
  const tamperedRoot = path.join(evaluationRoot, 'tampered');
  fs.mkdirSync(tamperedRoot);
  fs.writeFileSync(path.join(tamperedRoot, 'tampered.json'), JSON.stringify({ ...benchmarkArtifact, artifactSha256: digest('0') }));
  assert.throws(() => evaluateSimilarityBenchmark({
    bsimPath: bsimRoot,
    functionAtlasPath: tamperedRoot,
    groundTruthPath,
  }), /artifact hash drift/, 'benchmark comparison rejects tampered Function Atlas evidence');
} finally {
  fs.rmSync(evaluationRoot, { recursive: true, force: true });
}

console.log('function-atlas: 38 assertions passed');
