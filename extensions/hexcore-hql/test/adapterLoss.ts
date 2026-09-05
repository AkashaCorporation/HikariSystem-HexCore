import * as assert from 'assert';
import { Builder, ByteBuffer } from 'flatbuffers';
import { hydrateHAST } from '../src/adapter/flatbuf.js';
import { HQLMatcher } from '../src/engine/matcher.js';
import { scanHAST, signatureSetSha256 } from '../src/scan.js';
import type { HQLSignature } from '../src/types/hql.js';

type Offset = number;

function offsetVector(builder: Builder, offsets: Offset[]): Offset {
  builder.startVector(4, offsets.length, 4);
  for (let index = offsets.length - 1; index >= 0; index--) builder.addOffset(offsets[index]);
  return builder.endVector();
}

function expression(builder: Builder, kind: number, intValue = 0n, text?: string): Offset {
  const textOffset = text === undefined ? 0 : builder.createString(text);
  builder.startObject(9);
  builder.addFieldInt8(0, kind, 0);
  builder.addFieldInt64(1, intValue, 0n);
  if (textOffset) builder.addFieldOffset(3, textOffset, 0);
  return builder.endObject();
}

function statement(builder: Builder, kind: number, expressions: Offset[] = [], text?: string): Offset {
  const expressionsOffset = expressions.length === 0 ? 0 : offsetVector(builder, expressions);
  const textOffset = text === undefined ? 0 : builder.createString(text);
  builder.startObject(6);
  builder.addFieldInt8(0, kind, 0);
  if (expressionsOffset) builder.addFieldOffset(2, expressionsOffset, 0);
  if (textOffset) builder.addFieldOffset(5, textOffset, 0);
  return builder.endObject();
}

function fixtureHast(): Uint8Array {
  const builder = new Builder(512);
  const huge = expression(builder, 0, 9007199254740993n);
  const unknown = expression(builder, 255, 0n, 'future expression');
  const hugeStmt = statement(builder, 2, [huge]);
  const unknownStmt = statement(builder, 2, [unknown]);
  const asmStmt = statement(builder, 13, [], 'rdtsc');
  const incrementTarget = expression(builder, 3, 0n, 'counter');
  const incrementStmt = statement(builder, 1, [incrementTarget], '++');
  const body = offsetVector(builder, [hugeStmt, unknownStmt, asmStmt, incrementStmt]);
  const name = builder.createString('loss_fixture');

  builder.startObject(8);
  builder.addFieldOffset(0, name, 0);
  builder.addFieldInt64(1, 9007199254740995n, 0n);
  builder.addFieldOffset(5, body, 0);
  const fn = builder.endObject();
  const functions = offsetVector(builder, [fn]);

  builder.startObject(4);
  builder.addFieldOffset(1, functions, 0);
  const module = builder.endObject();
  builder.finish(module, 'HAST');
  return builder.asUint8Array();
}

const buffer = fixtureHast();
const functions = hydrateHAST(buffer);
assert.strictEqual(functions.length, 1);
const fn = functions[0];
assert.strictEqual(fn.name, 'loss_fixture');
assert.strictEqual(fn.address, '0x20000000000003');
assert.strictEqual(fn.body?.body[0].kind, 'CExprStmt');
if (fn.body?.body[0].kind === 'CExprStmt' && fn.body.body[0].expression.kind === 'CIntLitExpr') {
  assert.strictEqual(fn.body.body[0].expression.value, '9007199254740993');
  assert.strictEqual(fn.body.body[0].expression.exactValue, '9007199254740993');
}
assert.strictEqual(fn.body?.body[1].kind, 'CExprStmt');
if (fn.body?.body[1].kind === 'CExprStmt') assert.strictEqual(fn.body.body[1].expression.kind, 'CUnknownExpr');
assert.strictEqual(fn.body?.body[2].kind, 'CAsmStmt');
assert.strictEqual(fn.body?.body[3].kind, 'CAssignStmt');
if (fn.body?.body[3].kind === 'CAssignStmt') {
  assert.strictEqual(fn.body.body[3].compoundOperator, '++');
  assert.strictEqual(fn.body.body[3].value, undefined);
}
assert.deepStrictEqual(fn.adapterCoverage, {
  totalNodes: 9,
  lossyNodes: 2,
  coverage: 7 / 9,
  unsupportedNodeCounts: { 'CUnknownExpr:255': 1, CAsmStmt: 1 },
});

const exactSignature: HQLSignature = {
  id: 'fixture.exact-int64',
  name: 'Exact int64',
  description: 'Matches an exact integer beyond Number.MAX_SAFE_INTEGER',
  severity: 'info',
  evidenceLevel: 'candidate',
  condition: { query: { target: 'CIntLitExpr', attributes: [{ field: 'value', value: '9007199254740993' }] } },
};
const matcher = new HQLMatcher();
const exact = matcher.evaluate(fn, exactSignature);
assert.ok(exact);
assert.strictEqual(exact?.evidenceLevel, 'candidate');
assert.strictEqual(exact?.adapterCoverage, 7 / 9);
assert.strictEqual(exact?.adapterLossAffected, undefined);
const exactHexSignature: HQLSignature = {
  ...exactSignature,
  id: 'fixture.exact-int64-hex',
  condition: { query: { target: 'CIntLitExpr', attributes: [{ field: 'value', value: '0x20000000000001' }] } },
};
assert.ok(matcher.evaluate(fn, exactHexSignature), 'canonical hexadecimal query retains exact 64-bit identity');

const rootSignature: HQLSignature = {
  ...exactSignature,
  id: 'fixture.loss-affected-root',
  condition: { query: { target: 'CFunctionDecl', contains: [{ target: 'CIntLitExpr' }] } },
};
const rootMatch = matcher.evaluate(fn, rootSignature);
assert.ok(rootMatch);
assert.strictEqual(rootMatch?.evidenceLevel, 'signal');
assert.strictEqual(rootMatch?.adapterLossAffected, true);

const cleanSignature: HQLSignature = {
  ...exactSignature,
  id: 'fixture.no-match',
  condition: { query: { target: 'CCallExpr', attributes: [{ field: 'callee', value: 'never_called' }] } },
};
const scan = scanHAST(buffer, [cleanSignature]);
assert.strictEqual(scan.length, 1);
assert.strictEqual(scan[0].function, 'loss_fixture');
assert.strictEqual(scan[0].address, '0x20000000000003');
assert.strictEqual(scan[0].nodeCount, 9);
assert.strictEqual(scan[0].findings.length, 0);
assert.strictEqual(scan[0].status, 'partial');
assert.strictEqual(scan[0].truncated, false);
assert.match(scan[0].partialReasons[0], /Adapter coverage incomplete/);
assert.strictEqual(scan[0].evaluatedSignatureCount, 1);
assert.match(scan[0].cacheKey, /^[a-f0-9]{64}$/);
assert.strictEqual(scan[0].signatureSetSha256, signatureSetSha256([cleanSignature]));

const repeatedScan = scanHAST(buffer, [cleanSignature]);
assert.strictEqual(repeatedScan[0].cacheKey, scan[0].cacheKey);
const budgeted = scanHAST(buffer, [cleanSignature], undefined, { maxNodesPerFunction: 4 });
assert.strictEqual(budgeted[0].status, 'partial');
assert.strictEqual(budgeted[0].truncated, true);
assert.strictEqual(budgeted[0].evaluatedSignatureCount, 0);
assert.match(budgeted[0].truncationReasons[0], /AST node budget exceeded/);
assert.notStrictEqual(budgeted[0].cacheKey, scan[0].cacheKey);
assert.throws(() => scanHAST(buffer, [cleanSignature], undefined, { maxFunctions: 0 }), /positive safe integer/);
const controller = new AbortController();
controller.abort();
assert.throws(() => scanHAST(buffer, [cleanSignature], undefined, { signal: controller.signal }), /cancelled before hydration/);

const corrupted = Uint8Array.from(buffer);
const corruptedBb = new ByteBuffer(corrupted);
const rootPos = corruptedBb.readInt32(corruptedBb.position()) + corruptedBb.position();
const functionsOffset = corruptedBb.__offset(rootPos, 6);
const functionsStart = corruptedBb.__vector(rootPos + functionsOffset);
corruptedBb.writeInt32(functionsStart, 0x7fffffff);
const malformedFunctions = hydrateHAST(corrupted);
assert.strictEqual(malformedFunctions.length, 1, 'malformed function identity is retained');
assert.strictEqual(malformedFunctions[0].name, '<unhydrated_0>');
assert.strictEqual(malformedFunctions[0].adapterCoverage?.errors?.length, 1);
const malformedScan = scanHAST(corrupted, [cleanSignature]);
assert.strictEqual(malformedScan[0].status, 'partial');
assert.match(malformedScan[0].partialReasons[0], /hydration failed/);

console.log('adapterLoss: exact int64, explicit loss, coverage, clean identity - OK');
