import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { inspectHASTContract } from '../src/index.js';

const fixtureDir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures');
const declarationEvidence = fs.readFileSync(path.join(fixtureDir, 'declaration-type-evidence-v1_2.fb'));
const summary = inspectHASTContract(declarationEvidence);

assert.equal(summary.fileIdentifier, 'HAST');
assert.deepEqual([summary.schemaMajor, summary.schemaMinor], [1, 2]);
assert.equal(summary.functionCount, 1);
assert.equal(summary.functions[0].name, 'declaration_evidence');
assert.equal(summary.functions[0].address, '0x401000');
assert.equal(summary.functions[0].returnType, 'int32_t');
assert.deepEqual(summary.functions[0].params.map(item => [item.name, item.type]), [
  ['input', 'struct Input*'],
]);
assert.equal(summary.functions[0].locals.length, 2);
assert.equal(summary.functions[0].nativeQuality.status, 'unreported');

const mixed = fs.readFileSync(path.join(fixtureDir, 'native-quality-mixed-v1_1.fb'));
assert.throws(() => inspectHASTContract(mixed, {
  maxFunctions: 2,
  maxDeclarationsPerFunction: 8,
  maxTables: 64,
}), /function budget exceeded/);

const corrupt = Buffer.from(declarationEvidence);
corrupt[4] = 0;
assert.throws(() => inspectHASTContract(corrupt), /Invalid HAST file identifier/);

console.log('hastContractInspection: ok');
