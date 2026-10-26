import * as assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { ByteBuffer } from 'flatbuffers';
import { hydrateHAST } from '../src/adapter/flatbuf.js';
import { HQLMatcher } from '../src/engine/matcher.js';
import type { HQLSignature } from '../src/types/hql.js';
import { hydrateHAST as hydrateLegacyHAST } from './fixtures/legacy-hql-v1_1/src/adapter/flatbuf.js';

const fixture = path.join(__dirname, 'fixtures', 'declaration-type-evidence-v1_2.fb');
const bytes = fs.readFileSync(fixture);
assert.strictEqual(bytes.length, 1096);
assert.strictEqual(createHash('sha256').update(bytes).digest('hex'),
  'f06df6367c1dd5839d60464560054c51352eab294818fe6212ec2739001bc2fd');

const legacyRoot = path.join(__dirname, 'fixtures', 'legacy-hql-v1_1');
const legacyManifest = JSON.parse(fs.readFileSync(
  path.join(legacyRoot, 'manifest.json'), 'utf8')) as {
    fileCount: number; treeSha256: string;
  };
const walk = (directory: string): string[] => fs.readdirSync(directory, { withFileTypes: true })
  .flatMap(entry => entry.isDirectory()
    ? walk(path.join(directory, entry.name))
    : [path.join(directory, entry.name)]);
const legacySourceRoot = path.join(legacyRoot, 'src');
const legacyFiles = walk(legacySourceRoot)
  .map(file => path.relative(legacySourceRoot, file).split(path.sep).join('/'))
  .sort();
const legacyTreeHash = createHash('sha256');
for (const relative of legacyFiles) {
  const fileHash = createHash('sha256')
    .update(fs.readFileSync(path.join(legacySourceRoot, relative)))
    .digest('hex');
  legacyTreeHash.update(relative).update('\0').update(fileHash).update('\n');
}
assert.strictEqual(legacyFiles.length, legacyManifest.fileCount);
assert.strictEqual(legacyTreeHash.digest('hex'), legacyManifest.treeSha256);

const functions = hydrateHAST(bytes);
assert.strictEqual(functions.length, 1);
const fn = functions[0];
assert.strictEqual(fn.hast?.schemaMinor, 2);
assert.ok(fn.hast?.capabilities.includes('declaration-type-evidence'));
assert.deepStrictEqual(fn.hast?.evidenceOrigins, [
  { producer: 'a-provider', generation: '2', targetIdentity: 'target:a', snapshotHash: '1'.repeat(64) },
  { producer: 'z-provider', generation: '9', targetIdentity: 'target:z', snapshotHash: 'f'.repeat(64) },
]);
assert.deepStrictEqual(fn.returnTypeEvidence, {
  source: 'debug-info', state: 'selected', authority: 'authoritative', strength: 100,
  originId: 1, origin: fn.hast?.evidenceOrigins?.[1],
});
assert.deepStrictEqual(fn.params[0].typeEvidence, {
  source: 'debug-info', state: 'selected', authority: 'authoritative', strength: 100,
  originId: 0, origin: fn.hast?.evidenceOrigins?.[0],
});
assert.deepStrictEqual(fn.locals?.[0].typeEvidence, {
  source: 'structural', state: 'selected-with-conflict', authority: 'derived', strength: 60,
  rejectedSpelling: 'uint64_t',
});
assert.deepStrictEqual(fn.locals?.[1].typeEvidence, {
  source: 'unknown', state: 'unreported', authority: 'unknown', strength: 0,
});

const typeRule = (id: string, name: string, type: string): HQLSignature => ({
  id,
  name: id,
  description: 'HAST 1.2 declaration evidence fixture',
  severity: 'info',
  evidenceLevel: 'proven',
  condition: { query: { target: 'CVarDecl', attributes: [
    { field: 'name', value: name }, { field: 'type', value: type },
  ] } },
});
const parameterRule = typeRule('fixture.parameter-type', fn.params[0].name, fn.params[0].type);
assert.strictEqual(new HQLMatcher(undefined, {
  targetIdentity: 'target:a', snapshotSha256: '1'.repeat(64),
}).evaluate(fn, parameterRule)?.evidenceLevel, 'proven');
assert.strictEqual(new HQLMatcher(undefined, {
  targetIdentity: 'target:wrong', snapshotSha256: '1'.repeat(64),
}).evaluate(fn, parameterRule)?.evidenceLevel, 'candidate');

const originalParameterEvidence = fn.params[0].typeEvidence;
fn.params[0].typeEvidence = {
  source: 'legacy', state: 'selected', authority: 'heuristic', strength: 30,
};
assert.strictEqual(new HQLMatcher(undefined, {
  targetIdentity: 'target:a', snapshotSha256: '1'.repeat(64),
}).evaluate(fn, parameterRule)?.evidenceLevel, 'signal');
fn.params[0].typeEvidence = {
  source: 'unknown', state: 'unreported', authority: 'unknown', strength: 0,
};
assert.strictEqual(new HQLMatcher(undefined, {
  targetIdentity: 'target:a', snapshotSha256: '1'.repeat(64),
}).evaluate(fn, parameterRule)?.evidenceLevel, 'signal');
fn.params[0].typeEvidence = originalParameterEvidence;

const local = fn.locals?.[0];
assert.ok(local);
const localRule = typeRule('fixture.conflicted-local-type', local.name, local.type);
assert.strictEqual(new HQLMatcher().evaluate(fn, localRule)?.evidenceLevel, 'signal');
const unreportedLocal = fn.locals?.[1];
assert.ok(unreportedLocal);
const unreportedRule = typeRule(
  'fixture.unreported-local-type', unreportedLocal.name, unreportedLocal.type);
assert.strictEqual(
  new HQLMatcher(undefined, {
    targetIdentity: 'target:z', snapshotSha256: 'f'.repeat(64),
  }).evaluate(fn, unreportedRule)?.evidenceLevel,
  'signal',
);

// A frozen phase-1 adapter is the forward-compatibility oracle: it must ignore
// the new final slots while preserving every HAST 1.1 field it understands.
const legacyFunctions = hydrateLegacyHAST(bytes);
assert.strictEqual(legacyFunctions.length, 1);
assert.strictEqual(legacyFunctions[0].name, 'declaration_evidence');
assert.strictEqual(legacyFunctions[0].params[0].name, 'input');
assert.strictEqual(legacyFunctions[0].returnType, 'int32_t');

// A real HAST 1.0/1.1 vtable is physically shorter. __offset must return absent
// rather than reading adjacent bytes, and the new adapter maps that to explicit
// unreported declaration evidence.
const legacyBytes = fs.readFileSync(path.join(__dirname, 'fixtures', 'canonical-hast-v1.fb'));
const old = hydrateHAST(legacyBytes)[0];
assert.strictEqual(old.returnTypeEvidence?.state, 'unreported');
assert.strictEqual(old.params[0].typeEvidence?.authority, 'unknown');

const locate = (buffer: Buffer) => {
  const bb = new ByteBuffer(buffer);
  const root = bb.readInt32(0);
  const field = (table: number, slot: number): number => {
    const offset = bb.__offset(table, slot);
    assert.ok(offset, `missing slot ${slot}`);
    return table + offset;
  };
  const indirect = (offset: number): number => offset + bb.readUint32(offset);
  const functionsVector = indirect(field(root, 6));
  const functionTable = indirect(functionsVector + 4);
  const paramsVector = indirect(field(functionTable, 10));
  const parameterTable = indirect(paramsVector + 4);
  const returnEvidence = indirect(field(functionTable, 24));
  return { bb, root, functionTable, parameterTable, returnEvidence, field, indirect };
};

const wrongMinor = Buffer.from(bytes);
{
  const { bb, root, field } = locate(wrongMinor);
  bb.writeUint16(field(root, 14), 1);
}
assert.throws(() => hydrateHAST(wrongMinor), /requires schema minor >= 2/);

const missingReturnEvidence = Buffer.from(bytes);
{
  const { bb, functionTable } = locate(missingReturnEvidence);
  const vtable = functionTable - bb.readInt32(functionTable);
  bb.writeUint16(vtable + 24, 0);
}
assert.throws(() => hydrateHAST(missingReturnEvidence), /return_type has a type without explicit declaration evidence/);

const missingCapability = Buffer.from(bytes);
{
  const { bb, root, field, indirect } = locate(missingCapability);
  const capabilities = indirect(field(root, 16));
  const count = bb.readUint32(capabilities);
  for (let index = 0; index < count; index++) {
    if (bb.readUint8(capabilities + 4 + index) === 8) bb.writeUint8(capabilities + 4 + index, 127);
  }
}
assert.throws(() => hydrateHAST(missingCapability), /origins are present without declaration-type-evidence capability/);

const invalidOrigin = Buffer.from(bytes);
{
  const { bb, returnEvidence, field } = locate(invalidOrigin);
  bb.writeUint32(field(returnEvidence, 14), 99);
}
assert.throws(() => hydrateHAST(invalidOrigin), /outside the origin registry/);

console.log('hastV12TypeEvidence: declarations, origins, 1.1 compatibility and malformed capability/payload gates - OK');
