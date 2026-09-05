import * as assert from 'assert';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { ByteBuffer } from 'flatbuffers';
import { hydrateHAST } from '../src/adapter/flatbuf.js';
import type { CNode } from '../src/types/ast.js';

const fixturePath = path.resolve(__dirname, 'fixtures', 'canonical-hast-v1.fb');
const bytes = fs.readFileSync(fixturePath);
assert.strictEqual(bytes.length, 1008);
assert.strictEqual(createHash('sha256').update(bytes).digest('hex'), 'fba30b0a37d330bac7eb7794f8624dda64f12163f853e23449574ca3d67c57ea');

const first = hydrateHAST(bytes);
const second = hydrateHAST(bytes);
assert.deepStrictEqual(second, first, 'C++ HAST hydration must be deterministic');
assert.strictEqual(first.length, 1);
const fn = first[0];
assert.strictEqual(fn.name, 'canonical_hast');
assert.strictEqual(fn.address, '0xfedcba9876543210');
assert.deepStrictEqual(fn.hast, {
  schemaMajor: 1,
  schemaMinor: 0,
  capabilities: [
    'node-ids', 'source-addresses', 'symbol-identities', 'typed-child-roles',
    'call-targets', 'field-offsets', 'expression-result-types',
  ],
  producer: 'hexcore-helix',
  producerVersion: '0.1.9',
  architecture: 'aarch64',
  pointerBits: 64,
  semanticEligible: true,
});
assert.strictEqual(fn.params[0].identityId, '0', 'present-zero variable identity must survive');
assert.strictEqual(fn.params[0].parameterIndex, 0, 'present-zero parameter index must survive');
assert.strictEqual(fn.body?.body[0].kind, 'CIfStmt');
const ifStmt = fn.body!.body[0];
assert.strictEqual(ifStmt.kind, 'CIfStmt');
if (ifStmt.kind !== 'CIfStmt') throw new Error('fixture shape changed');
assert.strictEqual(ifStmt.then.kind, 'CBlockStmt');
assert.strictEqual(ifStmt.else?.kind, 'CBlockStmt');
const thenExprStmt = ifStmt.then.kind === 'CBlockStmt' ? ifStmt.then.body[0] : undefined;
assert.strictEqual(thenExprStmt?.kind, 'CExprStmt');
if (!thenExprStmt || thenExprStmt.kind !== 'CExprStmt') throw new Error('then fixture shape changed');
assert.strictEqual(thenExprStmt.expression.kind, 'CFieldAccessExpr');
if (thenExprStmt.expression.kind !== 'CFieldAccessExpr') throw new Error('field fixture shape changed');
assert.strictEqual(thenExprStmt.expression.fieldOffset, '0x0', 'present-zero field offset must survive');
assert.strictEqual(thenExprStmt.expression.object.kind, 'CVarRefExpr');
if (thenExprStmt.expression.object.kind === 'CVarRefExpr') {
  assert.strictEqual(thenExprStmt.expression.object.identityId, '0');
  assert.strictEqual(thenExprStmt.expression.object.storage, 'parameter');
  assert.strictEqual(thenExprStmt.expression.object.parameterIndex, 0);
}
const elseExprStmt = ifStmt.else?.kind === 'CBlockStmt' ? ifStmt.else.body[0] : undefined;
assert.strictEqual(elseExprStmt?.kind, 'CExprStmt');
if (!elseExprStmt || elseExprStmt.kind !== 'CExprStmt' || elseExprStmt.expression.kind !== 'CCallExpr') throw new Error('call fixture shape changed');
assert.strictEqual(elseExprStmt.expression.callTarget, '0xd123456789abcde0');

const nodes = collect(fn);
assert.deepStrictEqual(nodes.map(node => node.nodeId).filter(Boolean), ['1', '2', '3', '4', '5', '6', '7']);
assert.strictEqual(fn.adapterCoverage?.coverage, 1);
assert.strictEqual(fn.adapterCoverage?.lossyNodes, 0);

const legacyRust = Uint8Array.from(bytes);
legacyRust.set(Buffer.from('HRST'), 4);
assert.throws(() => hydrateHAST(legacyRust), /Invalid HAST file identifier/);

const future = Uint8Array.from(bytes);
const futureBb = new ByteBuffer(future);
const root = futureBb.readInt32(futureBb.position()) + futureBb.position();
const majorOffset = futureBb.__offset(root, 12);
assert.ok(majorOffset > 0);
futureBb.writeUint16(root + majorOffset, 2);
assert.throws(() => hydrateHAST(future), /Unsupported HAST schema major 2/);

console.log('hastV1Contract: canonical C++ bytes, metadata, identities, roles, int64 and version gates - OK');

function collect(root: CNode): CNode[] {
  const result: CNode[] = [];
  const visit = (node: CNode): void => {
    result.push(node);
    for (const value of Object.values(node)) {
      if (Array.isArray(value)) {
        for (const child of value) if (isNode(child)) visit(child);
      } else if (isNode(value)) {
        visit(value);
      }
    }
  };
  visit(root);
  return result;
}

function isNode(value: unknown): value is CNode {
  return Boolean(value && typeof value === 'object' && typeof (value as { kind?: unknown }).kind === 'string');
}
