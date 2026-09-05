import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { CFunctionDecl } from '../src/types/ast.js';
import type { HQLSemanticFact, HQLSignature } from '../src/types/hql.js';
import { HQLMatcher } from '../src/engine/matcher.js';
import { validateSignature } from '../src/signatures/schema.js';
import { SessionDbReader } from '../src/adapter/sessionDb.js';

const fn: CFunctionDecl = { kind: 'CFunctionDecl', name: 'target', address: '0x140001000', returnType: 'void', params: [], body: { kind: 'CBlockStmt', body: [] } };
const provenance = [{ producer: 'pdb:fixture', source: 'debug-info', strength: 'debug', generation: 3 }];
const facts: HQLSemanticFact[] = [
  { kind: 'function-prototype', attributes: { functionIdentity: 'function:0x140001000', callingConventionId: 'win64', returnTypeId: 'type:void', variadic: false, noreturn: false, method: false, provider: 'pdb:fixture', evidenceStrength: 'debug', generation: 3 }, proofStatus: 'proven', provenance },
  { kind: 'xref', attributes: { relation: 'data-write', family: 'data', sourceAddress: '0x140001010', targetKind: 'global', targetIdentity: 'global:counter', accessWidthBits: 32, provider: 'r33', evidenceStrength: 'derived', generation: 3 }, proofStatus: 'proven', provenance },
];
const signature: HQLSignature = {
  id: 'semantic.typed-write', name: 'typed write', description: 'typed HXDB condition', severity: 'info', evidenceLevel: 'proven',
  semanticCondition: { all: [
    { fact: { fact: 'function-prototype', attributes: [{ field: 'callingConventionId', value: 'win64' }] } },
    { fact: { fact: 'xref', attributes: [{ field: 'relation', value: 'data-write' }, { field: 'accessWidthBits', value: 32 }] } },
    { not: { fact: { fact: 'summary-barrier', attributes: [{ field: 'lossy', value: true }] } } },
  ] },
};

assert.deepStrictEqual(validateSignature(signature), []);
const match = new HQLMatcher().evaluate(fn, signature, facts);
assert.ok(match);
assert.strictEqual(match?.matches.length, 0);
assert.strictEqual(match?.semanticMatches?.length, 2);
assert.strictEqual(match?.structuralCompleteness, 1);
assert.strictEqual(match?.evidenceLevel, 'proven');
const candidate = new HQLMatcher().evaluate(fn, signature, facts.map((fact, index) => index === 1 ? { ...fact, proofStatus: 'candidate' as const } : fact));
assert.strictEqual(candidate?.evidenceLevel, 'candidate');

const bad = { ...signature, semanticCondition: { fact: { fact: 'xref', attributes: [{ field: 'callingConventionId', value: 'win64' }] } } };
assert.ok(validateSignature(bad).some(error => error.includes('invalid for xref')));

const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-semantic-facts-'));
const dbPath = path.join(directory, 'fixture.db');
const sqlite = require('hexcore-better-sqlite3');
const db = sqlite.openDatabase(dbPath);
db.exec(`
  CREATE TABLE functions(address TEXT PRIMARY KEY, name TEXT, return_type TEXT);
  CREATE TABLE variables(func_address TEXT, original_name TEXT, new_name TEXT, new_type TEXT);
  CREATE TABLE hxdb_meta(key TEXT PRIMARY KEY, value TEXT);
  CREATE TABLE function_prototypes(target_identity TEXT, function_identity TEXT, function_address TEXT, record_json TEXT);
  CREATE TABLE type_bindings(target_identity TEXT, function_identity TEXT, record_json TEXT);
  CREATE TABLE reference_edges(analysis_target_identity TEXT, active INTEGER, owner_function_identity TEXT, target_identity_value TEXT, record_json TEXT);
  CREATE TABLE propagation_summaries(analysis_target_identity TEXT, function_identity TEXT, record_json TEXT);
  CREATE TABLE fact_conflicts(target_identity TEXT, fact_kind TEXT, fact_key TEXT, reason TEXT, winner_hash TEXT, loser_hash TEXT);
`);
db.prepare(`INSERT INTO hxdb_meta VALUES ('target_identity', ?)`).run('target:fixture');
db.prepare(`INSERT INTO function_prototypes VALUES (?, ?, ?, ?)`).run('target:fixture', 'function:0x140001000', '0x140001000', JSON.stringify({
  functionIdentity: 'function:0x140001000', callingConventionId: 'win64', returnTypeId: 'type:void', variadic: false, noreturn: false, method: false,
  evidence: { producer: 'pdb:fixture', source: 'debug-info', strength: 'debug', generation: 3 }, evidenceSet: [{ producer: 'pdb:fixture', source: 'debug-info', strength: 'debug', generation: 3 }],
}));
db.prepare(`INSERT INTO reference_edges VALUES (?, 1, ?, ?, ?)`).run('target:fixture', 'function:0x140001000', 'global:counter', JSON.stringify({
  relation: 'data-write', family: 'data', source: { address: '0x140001010' }, target: { kind: 'global', identity: 'global:counter' }, accessWidthBits: 32, generation: 3,
  evidence: { producer: 'r33', source: 'dataflow', strength: 'derived', generation: 3 }, evidenceSet: [{ producer: 'r33', source: 'dataflow', strength: 'derived', generation: 3 }], indirectResolutionSet: [],
}));
db.close();
const reader = new SessionDbReader(dbPath, sqlite);
try {
  const loaded = reader.getSemanticFacts('0x140001000');
  assert.ok(loaded.some(fact => fact.kind === 'function-prototype' && fact.proofStatus === 'proven'));
  assert.ok(loaded.some(fact => fact.kind === 'xref' && fact.attributes.relation === 'data-write'));
} finally {
  reader.dispose();
  fs.rmSync(directory, { recursive: true, force: true });
}

console.log('HQL typed HXDB semantic conditions: passed');
