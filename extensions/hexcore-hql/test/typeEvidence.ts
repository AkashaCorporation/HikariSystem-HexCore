import * as assert from 'assert';
import { Builder } from 'flatbuffers';
import { hydrateHAST, HASTTypeEvidenceContractError } from '../src/adapter/flatbuf.js';

type Offset = number;

function offsetVector(builder: Builder, values: Offset[]): Offset {
  builder.startVector(4, values.length, 4);
  for (let index = values.length - 1; index >= 0; index--) builder.addOffset(values[index]);
  return builder.endVector();
}

function byteVector(builder: Builder, values: number[]): Offset {
  builder.startVector(1, values.length, 1);
  for (let index = values.length - 1; index >= 0; index--) builder.addInt8(values[index]);
  return builder.endVector();
}

function integerType(builder: Builder): Offset {
  builder.startObject(9);
  builder.addFieldInt8(0, 2, 0);
  builder.addFieldInt16(2, 64, 0);
  return builder.endObject();
}

function evidenceOrigin(builder: Builder): Offset {
  const producer = builder.createString('dwarf:fixture-cu');
  const target = builder.createString(`target:sha256:${'a'.repeat(64)}`);
  const snapshot = builder.createString('b'.repeat(64));
  builder.startObject(4);
  builder.addFieldOffset(0, producer, 0);
  builder.addFieldInt64(1, 7n, -1n);
  builder.addFieldOffset(2, target, 0);
  builder.addFieldOffset(3, snapshot, 0);
  return builder.endObject();
}

function typeEvidence(
  builder: Builder,
  options: { state?: number; authority?: number; includeOrigin?: boolean } = {},
): Offset {
  builder.startObject(6);
  builder.addFieldInt8(0, 6, 0);
  builder.addFieldInt8(1, options.state ?? 1, 0);
  builder.addFieldInt8(2, options.authority ?? 3, 0);
  builder.addFieldInt16(3, 100, 0);
  if (options.includeOrigin !== false) builder.addFieldInt32(5, 0, 0xffffffff);
  return builder.endObject();
}

function fixture(options: {
  schemaMinor?: number;
  evidenceCapability?: boolean;
  includeReturnEvidence?: boolean;
  includeVariableEvidence?: boolean;
  includeOrigin?: boolean;
  state?: number;
  authority?: number;
} = {}): Uint8Array {
  const builder = new Builder(1024);
  const evidenceEnabled = options.evidenceCapability !== false;
  const origin = evidenceOrigin(builder);
  const origins = offsetVector(builder, [origin]);
  const type = integerType(builder);
  const variableEvidence = typeEvidence(builder, options);
  const variableName = builder.createString('value');
  builder.startObject(7);
  builder.addFieldOffset(0, variableName, 0);
  builder.addFieldOffset(1, type, 0);
  builder.addFieldInt8(2, 3, 0);
  builder.addFieldInt64(4, 0n, -1n);
  builder.addFieldInt32(5, 0, 0xffffffff);
  if (options.includeVariableEvidence !== false) builder.addFieldOffset(6, variableEvidence, 0);
  const variable = builder.endObject();
  const params = offsetVector(builder, [variable]);
  const returnEvidence = typeEvidence(builder, options);
  const qualityIssues = byteVector(builder, []);
  const functionName = builder.createString('typed_fixture');
  const callingConvention = builder.createString('sysv64');
  builder.startObject(11);
  builder.addFieldOffset(0, functionName, 0);
  builder.addFieldInt64(1, 0x1000n, 0n);
  builder.addFieldOffset(2, type, 0);
  builder.addFieldOffset(3, params, 0);
  builder.addFieldOffset(6, callingConvention, 0);
  builder.addFieldInt8(8, 1, 0);
  builder.addFieldOffset(9, qualityIssues, 0);
  if (options.includeReturnEvidence !== false) builder.addFieldOffset(10, returnEvidence, 0);
  const fn = builder.endObject();
  const functions = offsetVector(builder, [fn]);
  const capabilities = byteVector(builder, evidenceEnabled
    ? [0, 1, 2, 3, 4, 5, 6, 7, 8]
    : [0, 1, 2, 3, 4, 5, 6, 7]);
  const moduleName = builder.createString('typed-module');
  const producer = builder.createString('hexcore-helix');
  const version = builder.createString('0.9.4-rc.dev');
  builder.startObject(12);
  builder.addFieldOffset(0, moduleName, 0);
  builder.addFieldOffset(1, functions, 0);
  builder.addFieldInt16(4, 1, 0xffff);
  builder.addFieldInt16(5, options.schemaMinor ?? (evidenceEnabled ? 2 : 1), 0xffff);
  builder.addFieldOffset(6, capabilities, 0);
  builder.addFieldOffset(7, producer, 0);
  builder.addFieldOffset(8, version, 0);
  builder.addFieldInt8(9, 1, 255);
  builder.addFieldInt16(10, 64, 0);
  if (options.includeOrigin !== false) builder.addFieldOffset(11, origins, 0);
  const module = builder.endObject();
  builder.finish(module, 'HAST');
  return builder.asUint8Array();
}

const hydrated = hydrateHAST(fixture());
assert.strictEqual(hydrated.length, 1);
assert.deepStrictEqual(hydrated[0].hast?.capabilities, [
  'variable-identity', 'typed-expressions', 'stable-node-ids', 'source-addresses',
  'direct-call-targets', 'struct-field-offsets', 'statement-child-roles',
  'native-function-quality', 'declaration-type-evidence',
]);
assert.strictEqual(hydrated[0].hast?.semanticEligible, true);
assert.strictEqual(hydrated[0].returnTypeEvidence?.authority, 'authoritative');
assert.strictEqual(hydrated[0].params[0].typeEvidence?.source, 'debug-info');
assert.strictEqual(hydrated[0].params[0].typeEvidence?.origin?.generation, '7');
assert.match(hydrated[0].params[0].typeEvidence?.origin?.targetIdentity ?? '', /^target:sha256:/);

const conflicted = hydrateHAST(fixture({ state: 2 }));
assert.strictEqual(conflicted[0].returnTypeEvidence?.state, 'selected-with-conflict');
assert.strictEqual(conflicted[0].hast?.semanticEligible, false);

const legacy = hydrateHAST(fixture({ schemaMinor: 1, evidenceCapability: false,
  includeReturnEvidence: false, includeVariableEvidence: false, includeOrigin: false }));
assert.strictEqual(legacy[0].returnTypeEvidence, undefined);
assert.ok(!legacy[0].hast?.capabilities.includes('declaration-type-evidence'));

for (const invalid of [
  fixture({ schemaMinor: 1 }),
  fixture({ schemaMinor: 2, evidenceCapability: false }),
  fixture({ includeReturnEvidence: false }),
  fixture({ includeVariableEvidence: false }),
  fixture({ includeOrigin: false }),
  fixture({ authority: 3, includeOrigin: false }),
]) {
  assert.throws(() => hydrateHAST(invalid), HASTTypeEvidenceContractError);
}

console.log('typeEvidence: HAST 1.2 provenance, conflict downgrade and mismatch rejection - OK');
