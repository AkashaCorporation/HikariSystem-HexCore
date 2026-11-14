/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { planQueryMaterialization, type QueryMaterializationPolicy } from './queryMaterialization';

const targetIdentity = `target:sha256:${'a'.repeat(64)}`;
const universeSha256 = 'b'.repeat(64);
const functions = [
	{ address: 0x1000, name: 'root', endAddress: 0x1010, callees: [0x2000] },
	{ address: 0x2000, name: 'direct', endAddress: 0x2020, callees: [0x3000] },
	{ address: 0x3000, name: 'recursive', endAddress: 0x3030, callees: [] },
];

function engine(options: {
	targetIdentity?: string;
	complete?: number[];
	reverseEdges?: boolean;
} = {}) {
	const edges = [
		{ edge: { relation: 'code-call-near', source: { ownerFunctionIdentity: 'function:0x1000' }, target: { kind: 'function', identity: 'function:0x2000', address: '0x2000' } }, active: true },
		{ edge: { relation: 'code-call-near', source: { ownerFunctionIdentity: 'function:0x2000' }, target: { kind: 'function', identity: 'function:0x3000', address: '0x3000' } }, active: true },
		{ edge: { relation: 'code-indirect-candidate', source: { ownerFunctionIdentity: 'function:0x1000' }, target: { kind: 'function', identity: 'function:0x9999' }, indirectResolution: { reason: 'points-to set remains open' } }, active: true },
	];
	if (options.reverseEdges) edges.reverse();
	const complete = new Set(options.complete ?? []);
	const store = {
		targetIdentity: options.targetIdentity ?? targetIdentity,
		getReferenceGraph: () => ({ listStoredEdges: () => edges }),
		getWholeProgramPropagationStore: () => ({ listDependencies: () => [
			{ consumerFunctionIdentity: 'function:0x2000', dependencyFunctionIdentity: 'function:0x3000' },
		] }),
	};
	return {
		getFunctions: () => functions,
		getFunctionAt: (address: number) => functions.find(fn => fn.address === address),
		peekFunctionBodyCompleteness: (address: number) => complete.has(address)
			? { state: 'complete', boundaryReached: true }
			: { state: 'lazy', boundaryReached: false },
		getAnalysisGeneration: () => 7,
		getSessionStore: () => ({
			getAnalysisTarget: () => ({ id: targetIdentity }),
			getAnalysisSession: () => ({ generation: 7 }),
			getAnalysisUniverseManifest: () => ({ universeSha256 }),
			getSemanticStore: () => store,
		}),
	};
}

const semantic = { fact: { fact: 'summary-call' } };
const structural = { query: { target: 'CCallExpr' } };
const needed: QueryMaterializationPolicy = { mode: 'needed', maxFunctions: 32, maxBytes: 4096, maxMilliseconds: 1000, maxDepth: 1 };
const bounded: QueryMaterializationPolicy = { mode: 'bounded', maxFunctions: 32, maxBytes: 4096, maxMilliseconds: 1000, maxDepth: 2 };

suite('G06 query-scoped materialization planner', () => {
	test('needed selects explicit and direct proven dependencies only', () => {
		const plan = planQueryMaterialization(engine(), { condition: semantic, addresses: ['0x1000'] }, needed);
		assert.deepStrictEqual(plan.requested.map(entry => entry.addressHex), ['0x1000', '0x2000']);
		assert.strictEqual(plan.budgetReason, 'maxDepth');
		assert.ok(plan.unknownReasons.some(reason => reason.function === 'function:0x3000' && reason.reason === 'maxDepth'));
		assert.ok(plan.unknownReasons.some(reason => reason.function === 'function:0x1000' && reason.reason === 'unresolved-indirect-target'));
	});

	test('bounded recursively follows exact references and propagation dependencies', () => {
		const first = planQueryMaterialization(engine(), { condition: semantic, functions: ['root'] }, bounded);
		const second = planQueryMaterialization(engine({ reverseEdges: true }), { condition: semantic, functions: ['root'] }, bounded);
		assert.deepStrictEqual(first.requested.map(entry => entry.addressHex), ['0x1000', '0x2000', '0x3000']);
		assert.strictEqual(first.estimatedBytes, 0x10 + 0x20 + 0x30);
		assert.strictEqual(first.planSha256, second.planSha256);
	});

	test('structural queries materialize only their explicit function body', () => {
		const plan = planQueryMaterialization(engine(), { condition: structural, addresses: ['0x1000'] }, bounded);
		assert.deepStrictEqual(plan.requested.map(entry => entry.addressHex), ['0x1000']);
		assert.strictEqual(plan.semanticDependenciesRequired, false);
	});

	test('prototype-only facts do not decode an unrelated body', () => {
		const plan = planQueryMaterialization(engine(), { condition: { fact: { fact: 'function-prototype' } }, addresses: ['0x1000'] }, bounded);
		assert.strictEqual(plan.bodyRequired, false);
		assert.strictEqual(plan.requested.length, 0);
		assert.strictEqual(plan.budgetExhausted, false);
	});

	test('complete bodies are not repeated but remain traversal roots', () => {
		const plan = planQueryMaterialization(engine({ complete: [0x1000, 0x2000] }), { condition: semantic, addresses: ['0x1000'] }, bounded);
		assert.deepStrictEqual(plan.requested.map(entry => entry.addressHex), ['0x3000']);
	});

	test('function and byte budgets retain explicit unknown reasons', () => {
		const one = planQueryMaterialization(engine(), { condition: semantic, addresses: ['0x1000'] }, { ...bounded, maxFunctions: 1 });
		assert.deepStrictEqual(one.requested.map(entry => entry.addressHex), ['0x1000']);
		assert.strictEqual(one.budgetReason, 'maxFunctions');
		assert.ok(one.unknownReasons.some(reason => reason.reason === 'maxFunctions'));
		const bytes = planQueryMaterialization(engine(), { condition: semantic, addresses: ['0x1000'] }, { ...bounded, maxBytes: 0x2f });
		assert.deepStrictEqual(bytes.requested.map(entry => entry.addressHex), ['0x1000']);
		assert.strictEqual(bytes.budgetReason, 'maxBytes');
	});

	test('unscoped and wrong-target requests fail closed', () => {
		const unscoped = planQueryMaterialization(engine(), { condition: semantic }, bounded);
		assert.strictEqual(unscoped.requested.length, 0);
		assert.strictEqual(unscoped.unknownReasons[0].reason, 'explicit-scope-required');
		assert.throws(() => planQueryMaterialization(engine({ targetIdentity: 'target:wrong' }),
			{ condition: semantic, addresses: ['0x1000'] }, bounded), /target differs/);
	});
});
