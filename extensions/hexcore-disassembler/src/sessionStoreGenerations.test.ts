/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SessionStore, peekAnalysisContractState } from './sessionStore';

suite('SessionStore generations and engine manifest (3.8.4 C2/C3)', () => {
	let tempDir = '';
	let binaryPath = '';

	const bind = (store: SessionStore) => store.bindAnalysisTarget({
		filePath: binaryPath,
		fileSize: 4,
		format: 'raw',
		architecture: 'x64',
		imageBase: '0x400000',
	});

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-session-generations-'));
		binaryPath = path.join(tempDir, 'sample.bin');
		fs.writeFileSync(binaryPath, Buffer.from([1, 2, 3, 4]));
	});

	teardown(() => {
		const resolved = path.resolve(tempDir);
		const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempRoot)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('fresh sessions bind an empty replay universe before semantic edits and retain it on reopen', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const initial = store.getAnalysisUniverseManifest();
		if (!initial) {
			store.dispose();
			assert.fail('a newly bound session must have a replay universe');
		}
		assert.strictEqual(initial.materializedFunctions.length, 0);
		const next = store.advanceAnalysisGeneration('semantic-applyPrototype', '0x1000');
		const expected = { generation: next.generation, universeSha256: initial.universeSha256 };
		assert.deepStrictEqual(JSON.parse(store.getMeta('analysis_generation_universe_json')!), expected);
		store.dispose();
		const reopened = new SessionStore(binaryPath);
		try {
			bind(reopened);
			assert.strictEqual(reopened.getAnalysisSession()?.generation, next.generation);
			assert.deepStrictEqual(JSON.parse(reopened.getMeta('analysis_generation_universe_json')!), expected);
			assert.strictEqual(reopened.getAnalysisUniverseManifest()?.universeSha256, initial.universeSha256);
			const reanalysis = reopened.startReanalysis();
			assert.deepStrictEqual(JSON.parse(reopened.getMeta('analysis_generation_universe_json')!), {
				...expected, generation: reanalysis.generation,
			});
		} finally { reopened.dispose(); }
	});

	test('rebinding a legacy session does not invent a missing replay universe', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		store.advanceAnalysisGeneration('legacy-fixture');
		const legacyDb = (store as unknown as { db: { exec(sql: string): void } }).db;
		legacyDb.exec(`DELETE FROM session_meta WHERE key IN ('analysis_universe_manifest_json', 'analysis_generation_universe_json')`);
		store.dispose();
		const reopened = new SessionStore(binaryPath);
		try {
			bind(reopened);
			assert.strictEqual(reopened.getAnalysisUniverseManifest(), undefined);
			assert.strictEqual(reopened.getMeta('analysis_generation_universe_json'), undefined);
		} finally { reopened.dispose(); }
	});

	test('a supplied universe hash must match persisted bodies before advancing generation', () => {
		const store = new SessionStore(binaryPath);
		try {
			bind(store);
			const before = store.getAnalysisSession()!.generation;
			const binding = store.getMeta('analysis_generation_universe_json');
			assert.throws(() => store.advanceAnalysisGeneration('mismatch', undefined, 'f'.repeat(64)), /universe manifest/);
			assert.strictEqual(store.getAnalysisSession()!.generation, before);
			assert.strictEqual(store.getMeta('analysis_generation_universe_json'), binding);
		} finally { store.dispose(); }
	});

	test('startReanalysis advances generation, persists it, wipes derived facts, keeps annotations', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const session0 = store.getAnalysisSession();
		assert.ok(session0);
		store.cacheFunction('0x1000', 'func_a', 0x40, 0x1040);
		store.recordInvestigation({
			id: 'inv-1', title: 't', kind: 'string-reference', query: 'q', status: 'complete',
		}, []);
		store.setComment('0x1000', 'analyst note');
		store.setBookmark('0x1000', 'entry');

		const session1 = store.startReanalysis();
		assert.strictEqual(session1.generation, session0.generation + 1);
		assert.strictEqual(session1.parentGeneration, session0.generation);
		assert.strictEqual(session1.id, session0.id);
		assert.strictEqual(store.getMeta('analysis_generation_counter'), String(session1.generation));
		assert.strictEqual(store.getCachedFunctions().length, 0);
		assert.strictEqual(store.getRecentInvestigations().length, 0);
		assert.strictEqual(store.getComment('0x1000'), 'analyst note');
		assert.strictEqual(store.getAllBookmarks().length, 1);
		store.dispose();

		// Generation survives close/reopen.
		const reopened = new SessionStore(binaryPath);
		bind(reopened);
		assert.strictEqual(reopened.getAnalysisSession()?.generation, session1.generation);
		assert.strictEqual(reopened.getMeta('analysis_generation_counter'), String(session1.generation));
		reopened.dispose();
	});

	test('legacy semantic aliases advance generation only when the prototype changes', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const initialGeneration = store.getAnalysisSession()!.generation;
		store.cacheFunction('0x1000', 'func_a', 0x40, 0x1040);

		store.retypeFunction('0x1000', 'int32_t');
		const changedGeneration = store.getAnalysisSession()!.generation;
		assert.strictEqual(changedGeneration, initialGeneration + 1);
		assert.strictEqual(store.getCachedFunctions().length, 0);

		store.cacheFunction('0x1000', 'func_a', 0x40, 0x1040);
		store.retypeFunction('0x1000', 'int32_t');
		assert.strictEqual(store.getAnalysisSession()!.generation, changedGeneration);
		assert.strictEqual(store.getCachedFunctions().length, 1);

		store.setFunctionCallingConvention('0x1000', 'cdecl');
		assert.strictEqual(store.getAnalysisSession()!.generation, changedGeneration + 1);
		store.dispose();
	});

	test('invalidateFunction removes only facts that depend on the function', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		store.cacheFunction('0x1000', 'func_a', 0x40, 0x1040);
		store.cacheFunction('0x2000', 'func_b', 0x40, 0x2040);
		store.recordInvestigation({
			id: 'inv-1', title: 't', kind: 'string-reference', query: 'q', status: 'complete',
		}, [
			{
				id: 'f-unsaved-a', investigationId: 'inv-1', kind: 'string-reference', query: 'q',
				label: 'a', stringAddress: '0x5000', referenceAddress: '0x1010',
				functionAddress: '0x1000', functionName: 'func_a', encoding: 'ascii',
				evidenceJson: '{}', saved: false,
			},
			{
				id: 'f-saved-a', investigationId: 'inv-1', kind: 'string-reference', query: 'q',
				label: 'b', stringAddress: '0x5004', referenceAddress: '0x1020',
				functionAddress: '0x1000', functionName: 'func_a', encoding: 'ascii',
				evidenceJson: '{}', saved: true,
			},
			{
				id: 'f-unsaved-b', investigationId: 'inv-1', kind: 'string-reference', query: 'q',
				label: 'c', stringAddress: '0x5008', referenceAddress: '0x2010',
				functionAddress: '0x2000', functionName: 'func_b', encoding: 'ascii',
				evidenceJson: '{}', saved: false,
			},
		]);

		const result = store.invalidateFunction('0x1000');
		assert.strictEqual(result.removedCachedFunctions, 1);
		assert.strictEqual(result.removedFindings, 1);
		assert.strictEqual(store.getCachedFunctions().length, 1);
		assert.strictEqual(store.getCachedFunctions()[0].address, '0x2000');
		const remaining = store.getInvestigationFindings('inv-1');
		assert.deepStrictEqual(remaining.map(finding => finding.id).sort(), ['f-saved-a', 'f-unsaved-b']);
		assert.strictEqual(store.getRecentInvestigations()[0].result_count, 2);
		store.dispose();
	});

	test('incremental refinement advances generation without deleting derived state', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		store.cacheFunction('0x1000', 'func_a', 0x40, 0x1040);
		store.recordInvestigation({
			id: 'inv-1', title: 't', kind: 'string-reference', query: 'q', status: 'complete',
		}, []);
		store.setComment('0x1000', 'analyst note');
		const before = store.getAnalysisSession()!;

		const universe = store.recordMaterializedFunction({
			address: '0x1000', endExclusive: '0x1040', bodySha256: 'a'.repeat(64),
		});
		const after = store.advanceAnalysisGeneration('function-materialization', '0x1000', universe.universeSha256);
		assert.strictEqual(after.id, before.id);
		assert.strictEqual(after.generation, before.generation + 1);
		assert.strictEqual(after.parentGeneration, before.generation);
		assert.strictEqual(store.getCachedFunctions().length, 1);
		assert.strictEqual(store.getRecentInvestigations().length, 1);
		assert.strictEqual(store.getComment('0x1000'), 'analyst note');
		assert.match(store.getMeta('analysis_last_incremental_update_json') ?? '', /function-materialization/);
		assert.strictEqual(store.getAnalysisUniverseManifest()?.materializedFunctions.length, 1);
		assert.strictEqual(store.getAnalysisUniverseManifest()?.universeSha256, universe.universeSha256);
		store.dispose();

		const reopened = new SessionStore(binaryPath);
		bind(reopened);
		assert.strictEqual(reopened.getAnalysisSession()?.generation, after.generation);
		assert.deepStrictEqual(reopened.getAnalysisUniverseManifest()?.materializedFunctions, [{
			address: '0x1000', endExclusive: '0x1040', bodySha256: 'a'.repeat(64),
		}]);
		reopened.dispose();
	});

	test('re-recording preserves saved marks and original discovery timestamps for stable finding IDs', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const finding = {
			id: 'finding:sha256:abcd', investigationId: 'inv-1', kind: 'string-reference', query: 'q',
			label: 'evidence', stringAddress: '0x5000', referenceAddress: '0x1010',
			functionAddress: '0x1000', functionName: 'func_a', encoding: 'ascii',
			evidenceJson: '{}', saved: false,
		};
		store.recordInvestigation({ id: 'inv-1', title: 't', kind: 'k', query: 'q', status: 'complete' }, [finding]);
		const original = store.getInvestigationFinding(finding.id);
		assert.ok(original);
		assert.strictEqual(store.setInvestigationFindingSaved(finding.id, true), true);

		// A re-run rediscovers the same finding under a different investigation.
		store.recordInvestigation({ id: 'inv-2', title: 't2', kind: 'k', query: 'q', status: 'complete' }, [{
			...finding,
			investigationId: 'inv-2',
			saved: false,
		}]);
		const rerecorded = store.getInvestigationFinding(finding.id);
		assert.ok(rerecorded);
		assert.strictEqual(rerecorded.saved, 1);
		assert.strictEqual(rerecorded.created_at, original.created_at);
		store.dispose();
	});

	test('engine manifest round-trips, binds into the session, and reports drift as diagnostics', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const recorded = store.recordEngineManifest([
			{ id: 'hikarisystem.hexcore-disassembler', version: '1.4.30' },
			{ id: 'hikarisystem.hexcore-helix', version: '0.9.3', buildSha256: 'a'.repeat(64) },
		], { 'pipeline.queue.poolSize': 2 });
		assert.strictEqual(recorded.engines.length, 2);
		assert.strictEqual(store.getAnalysisSession()?.engines.length, 2);

		const restored = store.getEngineManifest();
		assert.ok(restored);
		assert.strictEqual(restored.engines[1].id, 'hikarisystem.hexcore-helix');
		assert.deepStrictEqual(store.diffEngineManifest(recorded.engines), []);

		const drift = store.diffEngineManifest([
			{ id: 'hikarisystem.hexcore-disassembler', version: '1.4.31' },
			{ id: 'hikarisystem.hexcore-souper', version: '0.2.0' },
		]);
		assert.ok(drift.some(line => line.includes('1.4.30') && line.includes('1.4.31')));
		assert.ok(drift.some(line => line.includes('hexcore-helix') && line.includes('no longer installed')));
		assert.ok(drift.some(line => line.includes('hexcore-souper') && line.includes('installed after')));

		// Manifest survives close/reopen.
		store.dispose();
		const reopened = new SessionStore(binaryPath);
		bind(reopened);
		assert.strictEqual(reopened.getEngineManifest()?.engines.length, 2);
		assert.strictEqual(reopened.getAnalysisSession()?.engines.length, 2);
		reopened.dispose();
	});

	test('session metadata records the real product version, not a hardcoded one', () => {
		const store = new SessionStore(binaryPath);
		bind(store);
		const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf-8')) as { version: string };
		assert.strictEqual(store.getMeta('hexcore_version'), manifest.version);
		assert.notStrictEqual(store.getMeta('hexcore_version'), '3.7.4');
		store.dispose();
	});

	test('peekAnalysisContractState reads persisted state read-only and exposes wrong-target drift (3.8.4 C5)', () => {
		const store = new SessionStore(binaryPath);
		const target = bind(store);
		store.recordEngineManifest([{ id: 'hikarisystem.hexcore-disassembler', version: '1.4.31' }]);
		const session = store.getAnalysisSession();
		store.dispose();

		// Peek without a live SessionStore: same identity, same generation, manifest intact.
		const peeked = peekAnalysisContractState(binaryPath);
		assert.ok(peeked);
		assert.strictEqual(peeked.target.id, target.id);
		assert.strictEqual(peeked.session.id, session!.id);
		assert.strictEqual(peeked.session.generation, session!.generation);
		assert.strictEqual(peeked.manifest?.engines[0].version, '1.4.31');

		// Replacing the binary content changes the target: the peeked (stale)
		// state no longer matches, which is exactly what the runner's adoption
		// guard checks before trusting persisted provenance.
		fs.writeFileSync(binaryPath, Buffer.from([9, 9, 9, 9]));
		const stalePeek = peekAnalysisContractState(binaryPath);
		assert.ok(stalePeek);
		const fresh = new SessionStore(binaryPath);
		const freshTarget = bind(fresh);
		assert.notStrictEqual(stalePeek.target.id, freshTarget.id);
		fresh.dispose();

		// No session DB -> undefined, never a throw. The DB lives beside the
		// binary (one per directory), so use a genuinely empty directory here.
		const emptyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-peek-empty-'));
		try {
			assert.strictEqual(peekAnalysisContractState(path.join(emptyDir, 'missing.bin')), undefined);
		} finally {
			fs.rmSync(emptyDir, { recursive: true, force: true });
		}
	});
});
