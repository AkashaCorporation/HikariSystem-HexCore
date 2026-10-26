/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SessionStore } from './sessionStore';
import { canonicalizeSemanticType } from './semanticModel';
import { openSemanticQueryView } from './semanticQueryView';
import { createLiveHqlSessionReader, scanTargetFunctions } from './hqlScanner';

suite('generation-pinned semantic query view', () => {
	let directory: string;
	let file: string;
	let session: SessionStore;
	function bind(): void { session.bindAnalysisTarget({ filePath: file, fileSize: 4, format: 'raw', architecture: 'x64', imageBase: '0x400000' }); }
	setup(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-query-view-'));
		file = path.join(directory, 'sample.bin'); fs.writeFileSync(file, Buffer.from([1, 2, 3, 4]));
		session = new SessionStore(file); bind();
	});
	teardown(() => { session.dispose(); fs.rmSync(directory, { recursive: true, force: true }); });
	function populate(): void {
		const evidence = { strength: 'debug' as const, source: 'debug-info' as const, producer: 'fixture', generation: 0 };
		const type = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, signed: true }, evidence);
		const store = session.getSemanticStore(); store.putType(type);
		store.putPrototype({ targetIdentity: store.targetIdentity, functionIdentity: 'function:0x1000', functionAddress: '0x1000', callingConventionId: 'win64', returnTypeId: type.typeId, parameters: [], evidence });
		session.renameFunction('0x1000', 'first');
	}
	test('captures typed data without SQL writes and remains immutable after annotation changes', () => {
		populate();
		const revision = session.getSemanticReadRevision();
		const view = openSemanticQueryView(session);
		assert.strictEqual(view.getCoverage().status, 'ok', JSON.stringify(view.getCoverage()));
		assert.strictEqual(session.getSemanticReadRevision(), revision);
		assert.ok(view.getPrototype('function:0x1000'));
		assert.strictEqual(view.getFunction('0x1000')?.name, 'first');
		assert.throws(() => { (view.getFunction('0x1000') as any).name = 'changed'; }, TypeError);
		assert.throws(() => { (view.exportSnapshot().data.types as any).push({}); }, TypeError);
		session.renameFunction('0x1000', 'second');
		const next = openSemanticQueryView(session);
		assert.strictEqual(view.getFunction('0x1000')?.name, 'first');
		assert.strictEqual(next.getFunction('0x1000')?.name, 'second');
		assert.notStrictEqual(next.identity.snapshotSha256, view.identity.snapshotSha256);
	});
	test('reopens the same accepted state with the same logical hash', () => {
		populate();
		const before = openSemanticQueryView(session);
		session.dispose(); session = new SessionStore(file); bind();
		const after = openSemanticQueryView(session);
		assert.strictEqual(after.identity.snapshotSha256, before.identity.snapshotSha256);
	});
	test('wrong target, generation, universe and pagination identity fail explicitly', () => {
		const view = openSemanticQueryView(session);
		assert.throws(() => openSemanticQueryView(session, { expectedTargetIdentity: 'other' }), /identity-mismatch/);
		assert.throws(() => openSemanticQueryView(session, { expectedGeneration: view.identity.generation + 1 }), /identity-mismatch/);
		assert.throws(() => openSemanticQueryView(session, { expectedUniverseSha256: '0'.repeat(64) }), /identity-mismatch/);
		assert.throws(() => view.page('types', { snapshotSha256: '0'.repeat(64) }), /identity-mismatch/);
		assert.throws(() => view.queryReferences({ atGeneration: 999 }), /identity-mismatch/);
	});
	test('an empty but bound universe is readable and not a negative-evidence proof', () => {
		const view = openSemanticQueryView(session);
		assert.strictEqual(view.getCoverage().universeMaterializations, 0);
		assert.strictEqual(view.getCoverage().negativeEvidenceUsable, false);
		assert.strictEqual(view.page('types').total, 0);
	});
	test('write attempts inside a read snapshot are blocked and normal writes resume afterwards', () => {
		assert.throws(() => session.withSemanticReadSnapshot(() => session.renameFunction('0x1000', 'forbidden')), /readonly|read-only/i);
		assert.strictEqual(session.getFunction('0x1000'), undefined);
		session.renameFunction('0x1000', 'allowed');
		assert.strictEqual(session.getFunction('0x1000')?.name, 'allowed');
		assert.throws(() => session.withSemanticReadSnapshot(() => Promise.resolve(1)), /synchronous/);
	});
	test('budgets mark unavailable collections instead of returning a clean empty query', () => {
		populate();
		const view = openSemanticQueryView(session, { maxRows: 1 });
		assert.strictEqual(view.getCoverage().status, 'partial');
		assert.ok(view.getCoverage().unavailableCollections.length);
		assert.throws(() => view.listTypes(), /collection-unavailable/);
	});
	test('dirty summaries and barriers remain explicit', () => {
		const targetIdentity = session.getSemanticStore().targetIdentity;
		const summary = { schemaVersion: 1, analysisTargetIdentity: targetIdentity, functionIdentity: 'function:0x1000', functionBodySha256: 'a'.repeat(64), generation: 0,
			parameterEffects: [], returnRelationships: [], calls: [], globalEffects: [], ownershipEffects: [], fieldAccesses: [], functionPointerTargets: [],
			barriers: [{ identity: 'barrier', reason: 'unresolved', lossy: true }], dependencies: [], referenceEdgeHashes: [], valueFacts: [], conflicts: [], inputHash: 'b'.repeat(64), outputHash: 'c'.repeat(64) };
		(session as any).db.prepare('INSERT INTO propagation_summaries (analysis_target_identity,function_identity,generation,input_hash,output_hash,record_json) VALUES (?,?,?,?,?,?)').run(targetIdentity, summary.functionIdentity, 0, summary.inputHash, summary.outputHash, JSON.stringify(summary));
		const clean = openSemanticQueryView(session);
		assert.strictEqual(clean.listBarriers()[0].barrier.lossy, true);
		session.getWholeProgramPropagationStore().markDirty([summary.functionIdentity], 0, 'changed');
		const dirty = openSemanticQueryView(session);
		assert.strictEqual(dirty.getCoverage().status, 'partial');
		assert.throws(() => dirty.getPropagationSummary(summary.functionIdentity), /stale-summary/);
		assert.ok(clean.getPropagationSummary(summary.functionIdentity));
	});
	test('live HQL consumes the same snapshot identity and pinned annotations', () => {
		populate();
		const view = openSemanticQueryView(session);
		const reader = createLiveHqlSessionReader(session);
		assert.strictEqual(reader.getSnapshotIdentity?.().snapshotSha256, view.identity.snapshotSha256);
		assert.strictEqual(reader.getSemanticFacts('0x1000').length, 1);
		session.renameFunction('0x1000', 'later');
		assert.strictEqual(reader.getFunctionName('0x1000'), 'first');
		reader.dispose();
	});
	test('a concurrent WAL writer cannot split one read snapshot across revisions', () => {
		populate();
		const sqlite = require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3'));
		const other = sqlite.openDatabase(path.join(directory, '.hexcore_session.db'));
		try {
			const before = openSemanticQueryView(session);
			session.withSemanticReadSnapshot(() => {
				assert.strictEqual(session.getFunction('0x1000')?.name, 'first');
				other.prepare('UPDATE functions SET name = ? WHERE address = ?').run('external', '0x1000');
				const pinned = openSemanticQueryView(session, { engineGeneration: 7 });
				assert.strictEqual(pinned.getFunction('0x1000')?.name, 'first');
				assert.strictEqual(pinned.identity.snapshotSha256, before.identity.snapshotSha256);
			});
			const after = openSemanticQueryView(session);
			assert.strictEqual(after.getFunction('0x1000')?.name, 'external');
			assert.notStrictEqual(after.identity.snapshotSha256, before.identity.snapshotSha256);
			assert.throws(() => openSemanticQueryView(session, { expectedSnapshotSha256: before.identity.snapshotSha256 }), /identity-mismatch/);
		} finally { other.close(); }
	});
	test('stale live session metadata is not silently rebound by a read', () => {
		const stored = JSON.parse(session.getMeta('analysis_session_json')!); stored.generation++;
		session.setMeta('analysis_session_json', JSON.stringify(stored));
		assert.throws(() => openSemanticQueryView(session), /stale live session/);
	});
	test('Semantic Explorer and HQL read the same logical view', () => {
		populate();
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__query_view_ui__' : resolve.call(this, request, ...args); };
		require.cache.__query_view_ui__ = { id: '__query_view_ui__', filename: '__query_view_ui__', loaded: true, exports: {} } as NodeModule;
		const { buildSemanticExplorerSnapshot } = require('./semanticExplorer');
		const reader = createLiveHqlSessionReader(session);
		const ui = buildSemanticExplorerSnapshot({ getSessionStore: () => session, getAnalysisGeneration: () => 42 });
		assert.strictEqual(ui.snapshotSha256, reader.getSnapshotIdentity?.().snapshotSha256);
		assert.strictEqual(ui.engineGeneration, 42);
		assert.strictEqual(ui.analysisGeneration, session.getAnalysisSession()!.generation);
	});
	test('retains conflicting typed evidence without modifying arbitration', () => {
		populate();
		const store = session.getSemanticStore();
		const prototype = store.getPrototype('function:0x1000')!;
		store.putPrototype({ ...prototype, callingConventionId: 'sysv64', evidence: { ...prototype.evidence, producer: 'other-debug' } });
		const view = openSemanticQueryView(session);
		assert.strictEqual(view.getPrototype('function:0x1000')?.canonicalHash, store.getPrototype('function:0x1000')?.canonicalHash);
		assert.ok(view.listConflicts('function:0x1000').length > 0);
	});
	test('HQL rejects missing/wrong producer identity before attaching a live snapshot', async () => {
		session.bindAnalysisTarget({ filePath: file, fileSize: 4, format: 'raw', architecture: 'arm64', imageBase: '0x400000' });
		const reader = createLiveHqlSessionReader(session);
		const astBuffer = fs.readFileSync(path.join(__dirname, '..', '..', 'hexcore-hql', 'test', 'fixtures', 'semantic-quality-v1_1.fb'));
		const decompile = { success: true, status: 'ok' as const, architecture: 'arm64', code: '', address: '0xfedcba9876543210', error: '', astBuffer };
		const missing = await scanTargetFunctions({ address: decompile.address }, async () => decompile, { session: () => reader });
		assert.strictEqual(missing[0].status, 'error');
		const wrong = await scanTargetFunctions({ address: decompile.address }, async () => ({ ...decompile, semanticContext: { target: { id: 'other' } } }), { session: () => reader });
		assert.strictEqual(wrong[0].status, 'error');
		const good = await scanTargetFunctions({ address: decompile.address }, async () => ({ ...decompile, semanticContext: { target: { id: reader.getTargetIdentity() } } }), { session: () => reader });
		assert.strictEqual(good[0].status, 'ok');
		assert.strictEqual(good[0].semanticQueryIdentity?.snapshotSha256, reader.getSnapshotIdentity?.().snapshotSha256);
		const legacyBuffer = fs.readFileSync(path.join(__dirname, '..', '..', 'hexcore-hql', 'test', 'fixtures', 'canonical-hast-v1.fb'));
		const legacy = await scanTargetFunctions({ address: decompile.address }, async () => ({ ...decompile, astBuffer: legacyBuffer, semanticContext: { target: { id: reader.getTargetIdentity() } } }), { session: () => reader });
		assert.strictEqual(legacy[0].status, 'partial');
		assert.strictEqual(legacy[0].hast?.semanticEligible, false);
		assert.strictEqual(legacy[0].evaluatedSignatureCount, 0);
		assert.ok(legacy[0].partialReasons?.some(reason => reason.includes('Native function quality was not reported')));
	});
});
