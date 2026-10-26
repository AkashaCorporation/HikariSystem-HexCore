import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { createHash } from 'crypto';
import { runAdHocQuery, normalizeAdHocQuery } from '../dist/index.js';
import { HQLMatcher } from '../dist/engine/matcher.js';
import { queryDigest } from '../dist/query/contract.js';
import type { QueryInput, QueryFunctionInput, AdHocCondition } from '../src/query/contract.js';

const identity = { targetIdentity: 'target:fixture', sessionId: 'session:fixture', generation: 7, universeSha256: 'a'.repeat(64), snapshotSha256: 'b'.repeat(64) };
const fact = { kind: 'summary-ownership' as const, attributes: { ownershipKind: 'free', generation: 7 }, proofStatus: 'candidate' as const, provenance: [{ producer: 'test', source: 'fixture', strength: 'derived', generation: 7 }] };
function unit(address = '0x1000'): QueryFunctionInput {
	return { function: 'fixture', address, snapshotSha256: identity.snapshotSha256, semanticFacts: [fact], semanticAvailable: true, semanticComplete: true, semanticReadErrors: [], partialReasons: [], astAvailable: true, astComplete: true,
		ast: { kind: 'CFunctionDecl', name: 'fixture', address, returnType: 'void', params: [], body: { kind: 'CBlockStmt', body: [{ kind: 'CExprStmt', expression: { kind: 'CCallExpr', callee: 'free', arguments: [], nodeId: 'node:1', sourceAddress: address } }] },
			adapterCoverage: { coverage: 1, totalNodes: 4, lossyNodes: 0, unsupportedNodeCounts: {} }, hast: { schemaMajor: 1, schemaMinor: 0, capabilities: [], architecture: 'x86_64', semanticEligible: true } } };
}
const own: AdHocCondition = { fact: { fact: 'summary-ownership', attributes: [{ field: 'ownershipKind', value: 'free' }] } };
const call: AdHocCondition = { query: { target: 'CCallExpr', attributes: [{ field: 'callee', value: 'free' }] } };
const absent: AdHocCondition = { fact: { fact: 'summary-barrier' } };
const input = (...functions: QueryFunctionInput[]): QueryInput => ({ identity, functions });
let checks = 0;
async function check(name: string, action: () => unknown | Promise<unknown>) { await action(); console.log(`PASS ${name}`); checks++; }

async function main() {
	await check('canonical JSON IR, aliases and projection order', () => {
		const a = normalizeAdHocQuery({ condition: own, addresses: ['0X00001000', '0x1000'], select: ['address', 'function'] });
		const b = normalizeAdHocQuery({ schemaVersion: 1, select: ['function', 'address'], addresses: ['0x1000'], materialization: 'never', condition: own });
		assert.strictEqual(queryDigest(a), queryDigest(b));
		assert.throws(() => normalizeAdHocQuery({ condition: own, materialization: 'needed' }));
		assert.throws(() => normalizeAdHocQuery({ condition: { fact: { fact: 'xref', attributes: [{ field: 'typo', value: 1 }] } } }));
		assert.throws(() => normalizeAdHocQuery({ condition: { count: { fact: { fact: 'xref' }, min: 4, max: 1 } } }));
		assert.throws(() => normalizeAdHocQuery({ condition: { query: { target: 'CStringLiteral' } } }));
		const cyclic: any = { all: [] }; cyclic.all.push(cyclic);
		assert.throws(() => normalizeAdHocQuery({ condition: cyclic }), /cyclic/);
		assert.throws(() => normalizeAdHocQuery({ condition: { fact: { fact: 'constructor' } } }), /invalid semantic fact/);
	});
	await check('typed rows reuse matcher semantics without signatures', async () => {
		const fn = unit(); const before = JSON.stringify(fn);
		const result = await runAdHocQuery(input(fn), { condition: { all: [own, call] } });
		assert.strictEqual(result.status, 'ok'); assert.strictEqual(result.resultCount, 1);
		assert.strictEqual(result.rows[0].proofStatus, 'signal');
		assert.strictEqual(result.rows[0].evidence?.nodes[0].nodeId, 'node:1');
		assert.deepStrictEqual(result.rows[0].evidence?.facts, new HQLMatcher().evaluateSemanticCondition(fn.semanticFacts, own as any).matches);
		assert.strictEqual(JSON.stringify(fn), before);
		assert.strictEqual(result.resultSha256, queryDigest({ ...result, resultSha256: undefined }));
	});
	await check('complete positive and negative equivalent to existing matcher', async () => {
		for (const condition of [own, absent, { not: absent }, { all: [own, absent] }, { any: [own, absent] }, { count: { fact: { fact: 'summary-ownership' }, exactly: 1 } }] as AdHocCondition[]) {
			const result = await runAdHocQuery(input(unit()), { condition });
			const expected = new HQLMatcher().evaluateSemanticCondition(unit().semanticFacts, condition as any).matched;
			assert.strictEqual(result.evaluations[0].state, expected ? 'matched' : 'negative');
		}
	});
	await check('open-world not/count cannot prove absence', async () => {
		const fn = { ...unit(), semanticComplete: false };
		for (const condition of [absent, { not: absent }, { count: { fact: { fact: 'summary-ownership' }, exactly: 1 } }, { count: { fact: { fact: 'summary-barrier' }, exactly: 0 } }] as AdHocCondition[]) {
			const result = await runAdHocQuery(input(fn), { condition });
			assert.strictEqual(result.evaluations[0].state, 'unknown'); assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.rows.length, 0);
		}
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: own })).evaluations[0].state, 'matched');
	});
	await check('mixed all/any retain decisive known branches', async () => {
		const fn = { ...unit(), semanticAvailable: false };
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: { any: [call, own] } })).evaluations[0].state, 'matched');
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: { all: [call, own] } })).evaluations[0].state, 'unknown');
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: { all: [{ not: call }, own] } })).evaluations[0].state, 'negative');
	});
	await check('unused evidence domains do not lower a structural result', async () => {
		const fn = unit(); fn.semanticComplete = false; fn.semanticReadErrors = ['unused semantic failure']; fn.semanticFacts[0] = { ...fact, proofStatus: 'candidate', provenance: [] };
		const result = await runAdHocQuery(input(fn), { condition: call });
		assert.strictEqual(result.status, 'ok'); assert.strictEqual(result.rows.length, 1);
		assert.deepStrictEqual(result.evaluations[0].semanticReadErrors, fn.semanticReadErrors);
	});
	await check('read failure and adapter loss do not become negative findings', async () => {
		const fn = unit(); fn.semanticReadErrors = ['summary unavailable']; fn.ast!.adapterCoverage!.coverage = 0.5;
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: { not: absent } })).evaluations[0].state, 'unknown');
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: { not: { query: { target: 'CForStmt' } } } })).evaluations[0].state, 'unknown');
	});
	await check('wrong producer and duplicated identities are errors', async () => {
		assert.strictEqual((await runAdHocQuery(input({ ...unit(), snapshotSha256: 'c'.repeat(64) }), { condition: own })).status, 'error');
		assert.strictEqual((await runAdHocQuery(input(unit(), unit()), { condition: own })).status, 'error');
		const fn = unit(); fn.ast!.address = '0x2000';
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: call })).status, 'error');
	});
	await check('invalid proof status cannot default to proven', async () => {
		const fn = unit(); fn.semanticFacts[0] = { ...fact, proofStatus: 'typo' as any };
		const result = await runAdHocQuery(input(fn), { condition: own });
		assert.strictEqual(result.status, 'error'); assert.strictEqual(result.rows.length, 0);
		fn.semanticFacts[0] = { ...fact, proofStatus: 'proven', provenance: [] };
		const missing = await runAdHocQuery(input(fn), { condition: own });
		assert.strictEqual(missing.status, 'partial'); assert.strictEqual(missing.rows[0].proofStatus, 'signal');
		assert.strictEqual(missing.rows[0].evidence?.facts[0].proofStatus, 'signal');
		assert.ok(missing.evaluations[0].partialReasons.includes('semantic-fact-without-provenance'));
	});
	await check('semantic explanation identities are bound to exact record origins', async () => {
		const fn = unit(); fn.semanticFacts[0] = { ...fact, origin: { targetIdentity: identity.targetIdentity, snapshotSha256: identity.snapshotSha256, collection: 'summaries', recordIdentity: 'record', recordSha256: 'c'.repeat(64) }, explainIdentity: `hql-semantic:${identity.snapshotSha256}:summaries:${'c'.repeat(64)}` };
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: own })).rows.length, 1);
		fn.semanticFacts[0] = { ...fn.semanticFacts[0], explainIdentity: 'forged' };
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: own })).status, 'error');
	});
	await check('exact summary effect identities survive query and reject wrong envelopes', async () => {
		const fn = unit();
		const base = `hql-semantic:${identity.snapshotSha256}:summaries:${'c'.repeat(64)}`;
		const exact = `${base}:effect:ownership:sha256:${'d'.repeat(64)}`;
		fn.semanticFacts[0] = { ...fact, origin: { targetIdentity: identity.targetIdentity, snapshotSha256: identity.snapshotSha256, collection: 'summaries', recordIdentity: 'record', recordSha256: 'c'.repeat(64) }, explainIdentity: exact };
		const result = await runAdHocQuery(input(fn), { condition: own });
		assert.strictEqual(result.rows[0].evidence.facts[0].explainIdentity, exact);
		for (const invalid of [exact.replace(':ownership:', ':global:'), exact.slice(0, -1), exact.replace('d'.repeat(64), 'g'.repeat(64)), exact.replace('c'.repeat(64), 'e'.repeat(64))]) {
			fn.semanticFacts[0] = { ...fn.semanticFacts[0], explainIdentity: invalid };
			assert.strictEqual((await runAdHocQuery(input(fn), { condition: own })).status, 'error');
		}
	});
	await check('exact filtering, mandatory evidence, missing address and deterministic repeat', async () => {
		const query = { condition: own, addresses: ['0x2000'], select: ['address'] };
		const a = await runAdHocQuery(input(unit(), unit('0x2000')), query);
		const b = await runAdHocQuery(input(unit('0x2000'), unit()), query);
		assert.deepStrictEqual(a, b); assert.strictEqual(a.coverage.requestedFunctions, 1);
		assert.strictEqual(a.rows[0].function, undefined); assert.ok(a.rows[0].evidence?.facts.length);
		const missing = await runAdHocQuery(input(unit()), query);
		assert.strictEqual(missing.status, 'partial'); assert.strictEqual(missing.coverage.unevaluatedFunctions, 1);
	});
	await check('function and row limits preserve unevaluated counts', async () => {
		for (const limits of [{ maxFunctions: 1 }, { maxRows: 1 }]) {
			const result = await runAdHocQuery(input(unit(), unit('0x2000')), { condition: own }, { limits });
			assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.coverage.unevaluatedFunctions, 1); assert.strictEqual(result.truncated, true);
		}
	});
	await check('producer-level truncation does not invalidate selected positive witnesses', async () => {
		const value: QueryInput = { ...input(unit()), requestedFunctions: 4, partialReasons: ['selection-limit'] };
		const result = await runAdHocQuery(value, { condition: own });
		assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.rows.length, 1);
		assert.strictEqual(result.coverage.evaluatedFunctions, 1); assert.strictEqual(result.coverage.unevaluatedFunctions, 3);
		assert.ok(result.partialReasons.includes('selection-limit'));
	});
	await check('actual AST count ignores falsely small adapter node count', async () => {
		const fn = unit(); fn.ast!.adapterCoverage!.totalNodes = 1;
		const result = await runAdHocQuery(input(fn), { condition: call }, { limits: { maxNodes: 2 } });
		assert.strictEqual(result.evaluations[0].state, 'unknown'); assert.ok(result.partialReasons.includes('query-node-limit'));
	});
	await check('operation, evidence and serialization budgets are explicit', async () => {
		const result = await runAdHocQuery(input(unit()), { condition: call }, { limits: { maxOperations: 1 } });
		assert.ok(result.partialReasons.includes('query-operation-limit'));
		const evidence = await runAdHocQuery(input(unit()), { condition: { all: [own, call] } }, { limits: { maxEvidencePerRow: 1 } });
		assert.strictEqual(evidence.status, 'partial'); assert.strictEqual(evidence.truncated, true);
		await assert.rejects(runAdHocQuery(input(unit()), { condition: own }, { limits: { maxInputBytes: 10 } }), /byte-limit/);
		const output = await runAdHocQuery(input(...Array.from({ length: 10 }, (_, i) => unit(`0x${(4096 + i).toString(16)}`))), { condition: own }, { limits: { maxOutputBytes: 4096 } });
		assert.strictEqual(output.status, 'partial'); assert.ok(output.partialReasons.includes('query-output-byte-limit'));
		assert.ok(Buffer.byteLength(JSON.stringify(output)) <= 4096);
	});
	await check('actual loss markers override complete adapter metadata', async () => {
		const fn = unit(); fn.ast!.body!.body.push({ kind: 'CUnknownStmt', sourceKind: 999, reason: 'fixture', lossy: true });
		const result = await runAdHocQuery(input(fn), { condition: { not: { query: { target: 'CForStmt' } } } });
		assert.strictEqual(result.evaluations[0].state, 'unknown'); assert.strictEqual(result.status, 'partial');
	});
	await check('already cancelled query is not an empty success', async () => {
		const controller = new AbortController(); controller.abort();
		const result = await runAdHocQuery(input(unit()), { condition: own }, { signal: controller.signal });
		assert.strictEqual(result.status, 'partial'); assert.ok(result.partialReasons.includes('query-cancelled')); assert.strictEqual(result.coverage.evaluatedFunctions, 0);
	});
	await check('external cancellation terminates busy matcher and leaves host responsive', async () => {
		const fn = unit(); fn.semanticFacts[0] = { ...fact, attributes: { ownershipKind: 'a'.repeat(40) + '!' } };
		const condition = { fact: { fact: 'summary-ownership', attributes: [{ field: 'ownershipKind', value: 're:^(a+)+$' }] } };
		const controller = new AbortController(); let heartbeat = 0;
		const interval = setInterval(() => heartbeat++, 10); const timer = setTimeout(() => controller.abort(), 300);
		try {
			const start = performance.now(); const result = await runAdHocQuery(input(fn), { condition }, { signal: controller.signal });
			assert.ok(result.partialReasons.includes('query-cancelled')); assert.ok(performance.now() - start < 3000); assert.ok(heartbeat > 5);
		} finally { clearInterval(interval); clearTimeout(timer); }
	});
	await check('external timeout terminates blocked regex, subsequent job works', async () => {
		const fn = unit(); fn.semanticFacts[0] = { ...fact, attributes: { ownershipKind: 'a'.repeat(40) + '!' } };
		const condition = { fact: { fact: 'summary-ownership', attributes: [{ field: 'ownershipKind', value: 're:^(a+)+$' }] } };
		const result = await runAdHocQuery(input(fn), { condition }, { limits: { timeoutMs: 300 } });
		assert.ok(result.partialReasons.includes('query-timeout')); assert.strictEqual(result.coverage.evaluatedFunctions, 0);
		assert.strictEqual((await runAdHocQuery(input(unit()), { condition: own })).status, 'ok');
	});
	function hastUnit(): QueryFunctionInput {
		const bytes = fs.readFileSync(path.join(__dirname, 'fixtures/semantic-quality-v1_1.fb'));
		const fn = unit('0xfedcba9876543210'); delete fn.ast;
		fn.astAvailable = false; fn.astComplete = false;
		fn.hastSource = { base64: bytes.toString('base64'), sha256: createHash('sha256').update(bytes).digest('hex'), identity: { ...identity }, targetArchitecture: 'aarch64', producerArchitecture: 'arm64', producerStatus: 'ok', semanticEligible: true, qualityIssues: [] };
		return fn;
	}
	const field = { query: { target: 'CFieldAccessExpr', attributes: [{ field: 'fieldOffset', value: '0x0' }] } };
	await check('canonical C++ HAST hydrates inside the query worker', async () => {
		const fn = hastUnit(); const before = JSON.stringify(fn);
		const first = await runAdHocQuery(input(fn), { condition: field });
		assert.strictEqual(first.status, 'ok', JSON.stringify(first)); assert.strictEqual(first.resultCount, 1);
		assert.strictEqual(first.evaluations[0].astSha256, fn.hastSource!.sha256);
		assert.strictEqual(first.evaluations[0].adapterCoverage?.coverage, 1);
		assert.deepStrictEqual(first, await runAdHocQuery(input(fn), { condition: field }));
		assert.strictEqual(JSON.stringify(fn), before);
	});
	await check('HAST digest and producer identities cannot be relabeled', async () => {
		const fn = hastUnit(); fn.hastSource!.sha256 = '0'.repeat(64);
		assert.strictEqual((await runAdHocQuery(input(fn), { condition: field })).status, 'error');
		const other = hastUnit(); other.hastSource!.identity.generation++;
		assert.strictEqual((await runAdHocQuery(input(other), { condition: field })).status, 'error');
		const wrongArch = hastUnit(); wrongArch.hastSource!.producerArchitecture = 'x64';
		assert.strictEqual((await runAdHocQuery(input(wrongArch), { condition: field })).status, 'error');
	});
	await check('partial producer and wrong metadata cannot yield structural rows', async () => {
		const partial = hastUnit(); partial.hastSource!.producerStatus = 'partial';
		const result = await runAdHocQuery(input(partial), { condition: field });
		assert.strictEqual(result.evaluations[0].state, 'unknown'); assert.strictEqual(result.status, 'partial');
		const wrong = hastUnit(); wrong.hastSource!.producerArchitecture = 'x64'; wrong.hastSource!.targetArchitecture = 'x64';
		assert.strictEqual((await runAdHocQuery(input(wrong), { condition: field })).evaluations[0].state, 'unknown');
	});
	await check('hydration limits are explicit and an excluded source is not hydrated', async () => {
		const fn = hastUnit();
		const limited = await runAdHocQuery(input(fn), { condition: field }, { limits: { maxNodes: 1 } });
		assert.strictEqual(limited.status, 'partial'); assert.strictEqual(limited.rows.length, 0);
		assert.strictEqual(limited.truncated, true);
		const bad = hastUnit(); bad.hastSource!.base64 = 'bad';
		const selected = await runAdHocQuery(input(unit(), bad), { condition: own, addresses: ['0x1000'] });
		assert.strictEqual(selected.status, 'ok'); assert.strictEqual(selected.coverage.requestedFunctions, 1);
	});
	console.log(`${checks} ad-hoc query checks passed`);
}
main().catch(error => { console.error(error); process.exitCode = 1; });
