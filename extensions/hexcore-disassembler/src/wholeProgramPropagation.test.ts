/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	canonicalizeSemanticType,
	type CanonicalSemanticType,
	type EvidenceStrength,
	type SemanticEvidence,
} from './semanticModel';
import { SemanticStore, type SemanticSqliteFactory } from './semanticStore';
import { SessionStore } from './sessionStore';
import {
	WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION,
	WholeProgramPropagationEngine,
	type FunctionPropagationSummary,
	type FunctionSummaryInput,
	type PropagatedValueFact,
	type PropagationConstraint,
	type PropagationValueRef,
} from './wholeProgramPropagation';

function loadNativeSqlite(): SemanticSqliteFactory {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	return require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')) as SemanticSqliteFactory;
}

const targetIdentity = `target:sha256:${'8'.repeat(64)}`;

function evidence(
	strength: EvidenceStrength = 'derived',
	generation = 1,
	producer = 'whole-program-test',
): SemanticEvidence {
	if (strength === 'definitive') {
		return { strength, source: 'analyst', producer, generation, userDefined: true };
	}
	return {
		strength,
		source: strength === 'debug' ? 'debug-info' : strength === 'signature' ? 'signature' : 'dataflow',
		producer,
		generation,
	};
}

function hashBody(label: string): string {
	return crypto.createHash('sha256').update(label, 'utf8').digest('hex');
}

function value(
	kind: PropagationValueRef['kind'],
	identity: string,
	functionIdentity?: string,
): PropagationValueRef {
	return { kind, identity, ...(functionIdentity ? { functionIdentity } : {}) };
}

function constraint<T extends Omit<PropagationConstraint, 'id' | 'evidence'>>(
	id: string,
	spec: T,
	ev: SemanticEvidence = evidence(),
): PropagationConstraint {
	return { id, evidence: ev, ...spec } as unknown as PropagationConstraint;
}

function summary(
	functionIdentity: string,
	constraints: readonly PropagationConstraint[],
	overrides: Partial<FunctionSummaryInput> = {},
): FunctionSummaryInput {
	return {
		analysisTargetIdentity: targetIdentity,
		functionIdentity,
		functionBodySha256: hashBody(functionIdentity),
		generation: 1,
		materialized: true,
		constraints,
		...overrides,
	};
}

function findFact(summaryValue: FunctionPropagationSummary, identity: string): PropagatedValueFact {
	const fact = summaryValue.valueFacts.find(item => item.value.identity === identity);
	assert.ok(fact, `Expected propagated fact ${identity} in ${summaryValue.functionIdentity}`);
	return fact;
}

function putFixtureTypes(store: SemanticStore): { integer: CanonicalSemanticType; pointer: CanonicalSemanticType; callback: CanonicalSemanticType } {
	const debug = evidence('debug', 1, 'pdb:fixture');
	const integer = canonicalizeSemanticType({ kind: 'integer', name: 'uint32_t', sizeBits: 32, alignBits: 32, signed: false }, debug);
	const pointer = canonicalizeSemanticType({ kind: 'pointer', name: 'void_ptr', targetTypeId: integer.typeId, sizeBits: 64, alignBits: 64 }, debug);
	const callback = canonicalizeSemanticType({
		kind: 'function',
		name: 'callback_t',
		functionType: { returnTypeId: integer.typeId, parameterTypeIds: [pointer.typeId], callingConventionId: 'win64' },
	}, debug);
	store.writeBatch({ types: [integer, pointer, callback] });
	return { integer, pointer, callback };
}

suite('Whole-program propagation R34', function () {
	this.timeout(30_000);

	test('reaches a bounded fixed point across values, memory, calls, globals, fields, ownership and function pointers', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const types = putFixtureTypes(store);
		const allocator = 'function:0x140001000';
		const fill = 'function:0x140002000';
		const main = 'function:0x140003000';

		const allocated = value('ssa', 'allocated', allocator);
		const allocatorInput = summary(allocator, [
			constraint('allocate', { kind: 'allocator-result', allocatorIdentity: 'import:malloc', result: allocated, allocationIdentity: 'heap-object:fixture', resultTypeId: types.pointer.typeId }),
			constraint('return', { kind: 'return', from: allocated }),
			constraint('free-observed', { kind: 'free', deallocatorIdentity: 'import:free', value: allocated }),
		], {
			returnRelationships: [{ value: allocated, relation: 'allocated-object' }],
			ownershipEffects: [
				{ kind: 'allocate', value: allocated, objectIdentity: 'heap-object:fixture' },
				{ kind: 'free', value: allocated, objectIdentity: 'heap-object:fixture' },
			],
		});

		const fillLocal = value('ssa', 'fill-value', fill);
		const fillInput = summary(fill, [
			constraint('fill-out', { kind: 'out-parameter', ordinal: 0, from: fillLocal }),
		], {
			parameters: [{ ordinal: 0, value: value('parameter', 'destination', fill), reads: false, writes: true, escapes: false }],
			seedFacts: [{ value: fillLocal, typeId: types.integer.typeId, evidence: evidence('signature', 1, 'import:fill') }],
		});

		const pointer = value('ssa', 'pointer', main);
		const copied = value('ssa', 'copied', main);
		const selected = value('ssa', 'selected', main);
		const casted = value('ssa', 'casted', main);
		const stackSlot = value('stack-slot', 'slot:-0x20', main);
		const reloaded = value('ssa', 'reloaded', main);
		const fieldPointer = value('ssa', 'field-pointer', main);
		const integerSource = value('ssa', 'integer-source', main);
		const loaded = value('ssa', 'loaded', main);
		const globalLoaded = value('ssa', 'global-loaded', main);
		const fieldLoaded = value('ssa', 'field-loaded', main);
		const outValue = value('ssa', 'out-value', main);
		const callbackValue = value('function-pointer', 'callback', main);
		const relocated = value('ssa', 'relocated', main);
		const mainInput = summary(main, [
			constraint('call-allocator', {
				kind: 'call', call: { callsiteIdentity: 'callsite:0x140003010', calleeIdentity: allocator, arguments: [], result: pointer },
			}),
			constraint('copy', { kind: 'copy', from: pointer, to: copied }),
			constraint('phi', { kind: 'phi', inputs: [pointer, copied], to: selected }),
			constraint('select', { kind: 'select', inputs: [selected, copied], to: casted }),
			constraint('cast', { kind: 'cast', from: casted, to: stackSlot, fromWidthBits: 64, toWidthBits: 64 }),
			constraint('spill', { kind: 'stack-spill', from: stackSlot, slot: stackSlot }),
			constraint('reload', { kind: 'stack-reload', slot: stackSlot, to: reloaded }),
			constraint('base-offset', { kind: 'base-offset', base: reloaded, to: fieldPointer, offsetBytes: 16, fieldIdentity: 'Context.value' }),
			constraint('store', { kind: 'store', from: integerSource, pointer }),
			constraint('load', { kind: 'load', pointer, to: loaded }),
			constraint('global-write', { kind: 'global-write', globalIdentity: 'global:counter', from: integerSource }),
			constraint('global-read', { kind: 'global-read', globalIdentity: 'global:counter', to: globalLoaded }),
			constraint('field-write', {
				kind: 'field-write',
				field: { fieldIdentity: 'Context.value', base: pointer, offsetBytes: 16, access: 'write', typeId: types.integer.typeId },
				from: integerSource,
			}),
			constraint('field-read', {
				kind: 'field-read',
				field: { fieldIdentity: 'Context.value', base: pointer, offsetBytes: 16, access: 'read', typeId: types.integer.typeId },
				to: fieldLoaded,
			}),
			constraint('call-fill', {
				kind: 'call',
				call: {
					callsiteIdentity: 'callsite:0x140003080', calleeIdentity: fill,
					arguments: [{ ordinal: 0, argument: outValue }], outParameters: [{ ordinal: 0, value: outValue }],
				},
			}),
			constraint('relocation', { kind: 'relocation', relocationIdentity: 'reloc:.rdata+8', to: relocated, targets: ['global:vtable'], typeId: types.pointer.typeId }),
			constraint('function-pointer', { kind: 'function-pointer', value: callbackValue, targets: [fill], resolved: true }),
			constraint('points-to', { kind: 'points-to', value: callbackValue, targets: ['callback-table:slot:1'] }),
		], {
			seedFacts: [
				{ value: integerSource, typeId: types.integer.typeId, evidence: evidence('signature', 1, 'import:fixture') },
				{ value: callbackValue, typeId: types.callback.typeId, evidence: evidence('debug', 1, 'pdb:callback') },
			],
			calls: [
				{ callsiteIdentity: 'callsite:0x140003010', calleeIdentity: allocator, arguments: [], result: pointer },
				{ callsiteIdentity: 'callsite:0x140003080', calleeIdentity: fill, arguments: [{ ordinal: 0, argument: outValue }], outParameters: [{ ordinal: 0, value: outValue }] },
			],
			globalEffects: [{ globalIdentity: 'global:counter', access: 'read-write', value: integerSource, relocationIdentity: 'reloc:.data' }],
			fieldAccesses: [
				{ fieldIdentity: 'Context.value', base: pointer, offsetBytes: 16, access: 'write', value: integerSource, typeId: types.integer.typeId },
				{ fieldIdentity: 'Context.value', base: pointer, offsetBytes: 16, access: 'read', value: fieldLoaded, typeId: types.integer.typeId },
			],
			functionPointerTargets: [{ value: callbackValue, targets: [fill], resolved: true }],
		});

		const run = new WholeProgramPropagationEngine(store).solve([mainInput, fillInput, allocatorInput], { generation: 1 });
		assert.strictEqual(run.status, 'committed');
		assert.strictEqual(run.committed, true);
		assert.ok(run.iterations >= 2 && run.iterations < 64);
		assert.deepStrictEqual(run.recomputedFunctions, [allocator, fill, main]);
		const mainSummary = run.summaries.find(item => item.functionIdentity === main)!;
		assert.strictEqual(mainSummary.schemaVersion, WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION);
		assert.deepStrictEqual(mainSummary.dependencies, [allocator, fill]);
		assert.strictEqual(findFact(mainSummary, 'pointer').acceptedTypeId, types.pointer.typeId);
		assert.ok(findFact(mainSummary, 'pointer').pointsTo.includes('heap-object:fixture'));
		assert.strictEqual(findFact(mainSummary, 'reloaded').acceptedTypeId, types.pointer.typeId);
		assert.ok(findFact(mainSummary, 'field-pointer').pointsTo.includes('field:Context.value'));
		assert.strictEqual(findFact(mainSummary, 'loaded').acceptedTypeId, types.integer.typeId);
		assert.strictEqual(findFact(mainSummary, 'global-loaded').acceptedTypeId, types.integer.typeId);
		assert.strictEqual(findFact(mainSummary, 'field-loaded').acceptedTypeId, types.integer.typeId);
		assert.strictEqual(findFact(mainSummary, 'out-value').acceptedTypeId, types.integer.typeId);
		assert.strictEqual(findFact(mainSummary, 'relocated').acceptedTypeId, types.pointer.typeId);
		assert.deepStrictEqual(findFact(mainSummary, 'callback').pointsTo, [
			'callback-table:slot:1',
			fill,
		].sort());
		assert.strictEqual(mainSummary.globalEffects.length, 1);
		assert.strictEqual(mainSummary.fieldAccesses.length, 2);
		assert.strictEqual(mainSummary.functionPointerTargets.length, 1);
		assert.ok(store.getWholeProgramPropagationStore().getSummary(main));
		assert.ok(store.listHistory('type-binding').some(item => item.recordJson.includes('whole-program') || item.recordJson.includes('integer-source')));
		store.dispose();
	});

	test('retains competing evidence as a union blocker and never publishes the conflicted binding', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const types = putFixtureTypes(store);
		const functionIdentity = 'function:0x140010000';
		const conflicted = value('ssa', 'conflicted', functionIdentity);
		const input = summary(functionIdentity, [], {
			seedFacts: [
				{ value: conflicted, typeId: types.pointer.typeId, evidence: evidence('debug', 1, 'pdb:strong') },
				{ value: conflicted, typeId: types.integer.typeId, evidence: evidence('derived', 1, 'heuristic:weak') },
			],
		});
		const run = new WholeProgramPropagationEngine(store).solve([input], { generation: 1 });
		const fact = findFact(run.summaries[0], 'conflicted');
		assert.strictEqual(fact.acceptedTypeId, types.pointer.typeId);
		assert.deepStrictEqual(fact.conflict?.typeIds, [types.integer.typeId, types.pointer.typeId].sort());
		assert.deepStrictEqual(fact.conflict?.strongestTypeIds, [types.pointer.typeId]);
		assert.strictEqual(fact.conflict?.blocker, true);
		assert.strictEqual(store.findTypeBindings(functionIdentity).some(item => item.valueIdentity === 'conflicted'), false);
		assert.strictEqual(run.summaries[0].conflicts.length, 1);
		store.dispose();
	});

	test('recomputes only the changed SCC and its consumers while preserving independent accepted summaries', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const types = putFixtureTypes(store);
		const a = 'function:0x140020000';
		const b = 'function:0x140021000';
		const c = 'function:0x140022000';
		const d = 'function:0x140023000';
		const mkCall = (owner: string, callee: string): FunctionSummaryInput => summary(owner, [
			constraint(`call-${callee}`, { kind: 'call', call: { callsiteIdentity: `callsite:${owner}:${callee}`, calleeIdentity: callee, arguments: [], result: value('ssa', 'result', owner) } }),
		], {
			calls: [{ callsiteIdentity: `callsite:${owner}:${callee}`, calleeIdentity: callee, arguments: [], result: value('ssa', 'result', owner) }],
			seedFacts: [{ value: value('return', 'return', owner), typeId: types.integer.typeId, evidence: evidence('signature') }],
		});
		const firstInputs = [mkCall(a, b), mkCall(b, a), mkCall(c, a), summary(d, [], {
			seedFacts: [{ value: value('return', 'return', d), typeId: types.pointer.typeId, evidence: evidence('signature') }],
		})];
		const engine = new WholeProgramPropagationEngine(store);
		const first = engine.solve(firstInputs, { generation: 1 });
		assert.strictEqual(first.status, 'committed');
		assert.strictEqual(store.getWholeProgramPropagationStore().listSummaries().length, 4);

		const changedInputs = firstInputs.map(item => item.functionIdentity === a
			? { ...item, functionBodySha256: hashBody('changed-a'), generation: 2 }
			: { ...item, generation: 2 });
		const second = engine.solve(changedInputs, { generation: 2, changedFunctions: [a] });
		assert.deepStrictEqual(second.affectedFunctions, [a, b, c]);
		assert.deepStrictEqual(second.recomputedFunctions, [a, b, c]);
		assert.strictEqual(store.getWholeProgramPropagationStore().getSummary(d)?.generation, 1);
		assert.strictEqual(store.getWholeProgramPropagationStore().getSummary(a)?.generation, 2);
		store.dispose();
	});

	test('builds a complete initial baseline even when only one function arrived dirty', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const first = summary('function:0x140010000', []);
		const second = summary('function:0x140020000', []);
		store.getWholeProgramPropagationStore().markDirty([first.functionIdentity], 1, 'fixture-before-baseline');
		const result = new WholeProgramPropagationEngine(store).solve([first, second], { generation: 1 });
		assert.strictEqual(result.status, 'committed');
		assert.deepStrictEqual(result.recomputedFunctions, [first.functionIdentity, second.functionIdentity]);
		assert.strictEqual(store.getWholeProgramPropagationStore().listSummaries().length, 2);
		store.dispose();
	});

	test('preserves the previous generation atomically on cancellation, timeout and points-to budget exhaustion', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		putFixtureTypes(store);
		const functionIdentity = 'function:0x140030000';
		const pointer = value('ssa', 'pointer', functionIdentity);
		const original = summary(functionIdentity, [
			constraint('points', { kind: 'points-to', value: pointer, targets: ['object:a'] }),
		]);
		const engine = new WholeProgramPropagationEngine(store);
		assert.strictEqual(engine.solve([original], { generation: 1 }).status, 'committed');
		const before = store.getWholeProgramPropagationStore().exportHash();
		const beforeHistory = store.listHistory().length;

		const changed = { ...original, generation: 2, functionBodySha256: hashBody('changed') };
		const cancelled = engine.solve([changed], {
			generation: 2,
			changedFunctions: [functionIdentity],
			cancellationToken: { isCancellationRequested: true },
		});
		assert.strictEqual(cancelled.status, 'cancelled');
		assert.strictEqual(cancelled.committed, false);
		assert.strictEqual(cancelled.priorAcceptedGeneration, 1);
		assert.strictEqual(store.getWholeProgramPropagationStore().exportHash(), before);

		let time = 0;
		const timedOut = engine.solve([changed], {
			generation: 2,
			changedFunctions: [functionIdentity],
			maxMilliseconds: 5,
			now: () => time += 10,
		});
		assert.strictEqual(timedOut.status, 'timeout');
		assert.strictEqual(store.getWholeProgramPropagationStore().exportHash(), before);

		const exhausted = engine.solve([{
			...changed,
			constraints: [constraint('too-many-targets', { kind: 'points-to', value: pointer, targets: ['object:a', 'object:b'] })],
		}], { generation: 2, changedFunctions: [functionIdentity], maxPointsToPerValue: 1 });
		assert.strictEqual(exhausted.status, 'budget-exhausted');
		assert.strictEqual(exhausted.committed, false);
		assert.strictEqual(store.getWholeProgramPropagationStore().exportHash(), before);
		assert.strictEqual(store.listHistory().length, beforeHistory);
		store.dispose();
	});

	test('invalidates an unsafe current summary without retaining it as an accepted baseline', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const functionIdentity = 'function:0x14003f000';
		const engine = new WholeProgramPropagationEngine(store);
		assert.strictEqual(engine.solve([summary(functionIdentity, [])], { generation: 1 }).status, 'committed');
		const persistence = store.getWholeProgramPropagationStore();
		assert.ok(persistence.getSummary(functionIdentity));
		assert.strictEqual(persistence.invalidateCurrentSummaries(
			[functionIdentity], 2, 'incomplete function body',
		), 1);
		assert.strictEqual(persistence.getSummary(functionIdentity), undefined);
		assert.ok(!persistence.listDirty().some(item => item.functionIdentity === functionIdentity));
		store.dispose();
	});

	test('produces byte-stable hashes across reordered reruns and persists dirty closure through SessionStore', () => {
		const db = loadNativeSqlite().openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const types = putFixtureTypes(store);
		const left = 'function:0x140040000';
		const right = 'function:0x140041000';
		const inputs = [
			summary(left, [constraint('left-copy', { kind: 'copy', from: value('ssa', 'a', left), to: value('ssa', 'b', left) })], {
				seedFacts: [{ value: value('ssa', 'a', left), typeId: types.integer.typeId, evidence: evidence('signature') }],
			}),
			summary(right, [constraint('right-copy', { kind: 'copy', from: value('ssa', 'x', right), to: value('ssa', 'y', right) })], {
				seedFacts: [{ value: value('ssa', 'x', right), typeId: types.pointer.typeId, evidence: evidence('debug') }],
			}),
		];
		const engine = new WholeProgramPropagationEngine(store);
		const first = engine.solve(inputs, { generation: 1 });
		const second = engine.solve([...inputs].reverse(), { generation: 1 });
		assert.strictEqual(second.inputHash, first.inputHash);
		assert.strictEqual(second.outputHash, first.outputHash);
		assert.strictEqual(second.runHash, first.runHash);
		assert.deepStrictEqual(second.summaries, first.summaries);
		store.dispose();

		const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-propagation-session-'));
		try {
			const binaryPath = path.join(tempDir, 'fixture.bin');
			fs.writeFileSync(binaryPath, Buffer.from([0x90, 0xc3]));
			const session = new SessionStore(binaryPath);
			const sessionStore = session.getSemanticStore();
			const sessionTarget = sessionStore.targetIdentity;
			const sessionFunction = 'function:0x401000';
			const sessionInput: FunctionSummaryInput = {
				...summary(sessionFunction, []),
				analysisTargetIdentity: sessionTarget,
			};
			const run = new WholeProgramPropagationEngine(sessionStore).solve([sessionInput], { generation: 0 });
			assert.strictEqual(run.status, 'committed');
			assert.strictEqual(session.getWholeProgramPropagationStore(), sessionStore.getWholeProgramPropagationStore());
			session.invalidateFunction('0x401000');
			assert.deepStrictEqual(
				session.getWholeProgramPropagationStore().listDirty().map(item => item.functionIdentity),
				[sessionFunction],
			);
			session.dispose();
		} finally {
			fs.rmSync(tempDir, { recursive: true, force: true });
		}
	});
});
