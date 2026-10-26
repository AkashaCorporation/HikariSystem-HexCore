import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { hydrateHAST } from '../src/adapter/flatbuf.js';
import { scanHAST } from '../src/scan.js';
import type { HQLSignature } from '../src/types/hql.js';

const bytes = fs.readFileSync(path.join(__dirname, 'fixtures/native-quality-mixed-v1_1.fb'));
assert.strictEqual(createHash('sha256').update(bytes).digest('hex'), '5683f91b2b4104b39b3ebfd69f46188881c3ad05ca1219c724463af58f92e1f7');
const functions = hydrateHAST(bytes);
assert.deepStrictEqual(functions.map(fn => fn.hast?.nativeQuality?.status), ['no-known-loss', 'known-loss', 'unreported']);
assert.deepStrictEqual(functions.map(fn => fn.hast?.semanticEligible), [true, false, false]);
assert.deepStrictEqual(functions[1].hast?.nativeQuality?.issues, ['opaque-post-call-register']);
assert.notStrictEqual(functions[0].hast, functions[1].hast);
const signatures: HQLSignature[] = [{ id: 'test.native-quality', name: 'Native quality', description: 'Native quality transport fixture',
  severity: 'info', condition: { query: { target: 'CFunctionDecl' } } }];
const scans = scanHAST(bytes, signatures);
assert.deepStrictEqual(scans.map(fn => fn.status), ['ok', 'partial', 'partial']);
assert.deepStrictEqual(scans.map(fn => fn.evaluatedSignatureCount), [1, 0, 0]);
assert.deepStrictEqual(scanHAST(bytes, signatures), scans);

const field = (buffer: Buffer, table: number, slot: number): number => {
  const vtable = table - buffer.readInt32LE(table);
  const offset = buffer.readUInt16LE(vtable + slot);
  assert.ok(offset);
  return table + offset;
};
const indirect = (buffer: Buffer, offset: number): number => offset + buffer.readUInt32LE(offset);
const root = bytes.readUInt32LE(0);
const vector = indirect(bytes, field(bytes, root, 6));
const affected = indirect(bytes, vector + 8);
const issues = indirect(bytes, field(bytes, affected, 22));
const unknown = Buffer.from(bytes); unknown[issues + 4] = 253;
assert.strictEqual(hydrateHAST(unknown)[1].hast?.semanticEligible, false);
assert.deepStrictEqual(hydrateHAST(unknown)[1].hast?.nativeQuality?.issues, ['unknown-native-quality-253']);
const invalid = Buffer.from(bytes); invalid[field(bytes, affected, 20)] = 2;
const malformed = hydrateHAST(invalid);
assert.strictEqual(malformed[1].hast?.semanticEligible, false);
assert.strictEqual(malformed[0].hast?.semanticEligible, true);
assert.ok(malformed[1].adapterCoverage?.errors?.some(error => error.includes('quality marker')));
const missing = Buffer.from(bytes);
missing.writeUInt16LE(0, affected - missing.readInt32LE(affected) + 22);
assert.ok(hydrateHAST(missing)[1].adapterCoverage?.errors?.some(error => error.includes('issue vector')));
const missingCapability = Buffer.from(bytes);
const caps = indirect(bytes, field(bytes, root, 16));
for (let i = 0; i < bytes.readUInt32LE(caps); ++i) if (missingCapability[caps + 4 + i] === 7) missingCapability[caps + 4 + i] = 127;
assert.ok(hydrateHAST(missingCapability).every(fn => !fn.hast?.semanticEligible && fn.hast?.nativeQuality?.status === 'unreported'));
for (const length of [0, 4, 8, 16]) assert.throws(() => hydrateHAST(bytes.subarray(0, length)));

const legacy = fs.readFileSync(path.join(__dirname, 'fixtures/canonical-hast-v1.fb'));
const legacyScan = scanHAST(legacy, signatures);
assert.ok(legacyScan.every(fn => fn.status === 'partial' && fn.evaluatedSignatureCount === 0));
// Frozen v4 cache key for this unchanged legacy buffer and signature.
assert.notStrictEqual(legacyScan[0].cacheKey, 'ea61d448a06b27126a5923e907e54fb5161319cd3ca1291ada27a3eddf1dbf5e');
const semantic = fs.readFileSync(path.join(__dirname, 'fixtures/semantic-quality-v1_1.fb'));
assert.strictEqual(createHash('sha256').update(semantic).digest('hex'), 'a9a98a6c8a22f275060ab82fbf0ab091f3eeda74d7971f246131b1ee740d9259');
assert.ok(hydrateHAST(semantic).every(fn => fn.hast?.semanticEligible && fn.hast?.nativeQuality?.status === 'no-known-loss'));
console.log('nativeQuality: mixed functions, legacy gating, malformed input and native fixtures - OK');
