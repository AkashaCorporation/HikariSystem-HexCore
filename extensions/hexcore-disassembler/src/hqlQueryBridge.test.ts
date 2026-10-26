/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { SessionStore } from './sessionStore';
import { canonicalSerialize, canonicalizeSemanticType } from './semanticModel';
import { openSemanticQueryView } from './semanticQueryView';
import { createHqlSnapshotReader } from './hqlScanner';
import { createHqlQueryInput, runHqlSnapshotQuery, type HqlQueryHastSource } from './hqlQueryBridge';

suite('HQL pinned query bridge', () => {
	let directory: string;
	let session: SessionStore;
	setup(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hql-query-'));
		const file = path.join(directory, 'fixture.bin'); fs.writeFileSync(file, Buffer.from([0xc3]));
		session = new SessionStore(file);
		session.bindAnalysisTarget({ filePath: file, fileSize: 1, format: 'raw', architecture: 'x64', imageBase: '0x1000' });
		const evidence = { strength: 'debug' as const, source: 'debug-info' as const, producer: 'fixture', generation: 0 };
		const store = session.getSemanticStore();
		const type = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, signed: true }, evidence); store.putType(type);
		store.putPrototype({ targetIdentity: store.targetIdentity, functionIdentity: 'function:0x1000', functionAddress: '0x1000', callingConventionId: 'win64', returnTypeId: type.typeId, parameters: [], evidence });
		session.renameFunction('0x1000', 'first');
	});
	teardown(() => { session.dispose(); fs.rmSync(directory, { recursive: true, force: true }); });
	const condition = { fact: { fact: 'function-prototype' } };
	test('constructs facts from the pinned view, with source record hashes and no writes', async () => {
		const revision = session.getSemanticReadRevision();
		const view = openSemanticQueryView(session);
		const input = createHqlQueryInput(view, [{ address: '0X00001000', name: 'ignored' }]);
		assert.strictEqual(input.functions[0].function, 'first');
		assert.strictEqual(input.functions[0].semanticComplete, false);
		const fact = input.functions[0].semanticFacts[0];
		assert.strictEqual(fact.origin?.targetIdentity, view.identity.targetIdentity);
		assert.strictEqual(fact.origin?.snapshotSha256, view.identity.snapshotSha256);
		assert.strictEqual(fact.origin?.recordSha256, crypto.createHash('sha256').update(canonicalSerialize(view.listPrototypes()[0])).digest('hex'));
		const result: any = await runHqlSnapshotQuery(view, [{ address: '0x1000' }], { condition });
		assert.strictEqual(result.rows.length, 1); assert.strictEqual(result.status, 'partial');
		assert.deepStrictEqual(result.rows[0].evidence.facts[0].origin, fact.origin);
		assert.strictEqual(session.getSemanticReadRevision(), revision);
	});
	test('a later edit does not rebind queries on an old view', async () => {
		const view = openSemanticQueryView(session);
		session.renameFunction('0x1000', 'second');
		const first: any = await runHqlSnapshotQuery(view, [{ address: '0x1000' }], { condition });
		const second: any = await runHqlSnapshotQuery(openSemanticQueryView(session), [{ address: '0x1000' }], { condition });
		assert.strictEqual(first.rows[0].function, 'first'); assert.strictEqual(second.rows[0].function, 'second');
		assert.notStrictEqual(first.identity.snapshotSha256, second.identity.snapshotSha256);
	});
	test('missing functions and upstream partial do not become clean negatives', async () => {
		const view = openSemanticQueryView(session);
		const missing: any = await runHqlSnapshotQuery(view, [{ address: '0x2000' }], { condition: { not: condition } });
		assert.strictEqual(missing.evaluations[0].state, 'unknown');
		const partial: any = await runHqlSnapshotQuery(view, [{ address: '0x1000' }], { condition }, { inputPartialReasons: ['partial ancestor'] });
		assert.strictEqual(partial.evaluations[0].state, 'unknown'); assert.strictEqual(partial.status, 'partial');
	});
	test('unavailable snapshot collections propagate through the same adapter', async () => {
		const view = openSemanticQueryView(session, { maxRows: 1 });
		const result: any = await runHqlSnapshotQuery(view, [{ address: '0x1000' }], { condition: { not: condition } });
		assert.strictEqual(result.evaluations[0].state, 'unknown');
		assert.ok(result.evaluations[0].semanticReadErrors.length > 0);
	});
	test('summary locations are explicit without fabricated producer provenance', () => {
		const targetIdentity = session.getSemanticStore().targetIdentity;
		const summary = { schemaVersion: 1, analysisTargetIdentity: targetIdentity, functionIdentity: 'function:0x1000', functionBodySha256: 'a'.repeat(64), generation: 0,
			parameterEffects: [], returnRelationships: [], calls: [], globalEffects: [], ownershipEffects: [{ kind: 'free', value: { identity: 'value:1', kind: 'register' } }], fieldAccesses: [], functionPointerTargets: [],
			barriers: [], dependencies: [], referenceEdgeHashes: [], valueFacts: [], conflicts: [], inputHash: 'b'.repeat(64), outputHash: 'c'.repeat(64) };
		(session as any).db.prepare('INSERT INTO propagation_summaries (analysis_target_identity,function_identity,generation,input_hash,output_hash,record_json) VALUES (?,?,?,?,?,?)').run(targetIdentity, summary.functionIdentity, 0, summary.inputHash, summary.outputHash, JSON.stringify(summary));
		const view = openSemanticQueryView(session);
		const fact = (createHqlSnapshotReader(view).getSemanticFacts('0x1000') as any[]).find(item => item.kind === 'summary-ownership');
		assert.strictEqual(fact.proofStatus, 'signal'); assert.deepStrictEqual(fact.provenance, []);
		assert.strictEqual(fact.origin.collection, 'summaries'); assert.strictEqual(fact.origin.recordIdentity, summary.functionIdentity);
		assert.strictEqual(fact.origin.recordSha256, crypto.createHash('sha256').update(canonicalSerialize(summary)).digest('hex'));
	});
	test('rejects duplicate selections and stale or unrelated HAST envelopes', () => {
		const view = openSemanticQueryView(session);
		assert.throws(() => createHqlQueryInput(view, [{ address: '0x1000' }, { address: '0x01000' }]), /Duplicate/);
		const source: HqlQueryHastSource = { base64: '', sha256: 'a'.repeat(64), identity: { ...view.identity, generation: 99 }, targetArchitecture: 'x64', producerArchitecture: 'x64', producerStatus: 'ok', semanticEligible: true, qualityIssues: [] };
		assert.throws(() => createHqlQueryInput(view, [{ address: '0x1000' }], new Map([['0x1000', source]])), /identity-mismatch/);
		assert.throws(() => createHqlQueryInput(view, [], new Map([['0x1000', source]])), /no matching selection/);
	});
});
