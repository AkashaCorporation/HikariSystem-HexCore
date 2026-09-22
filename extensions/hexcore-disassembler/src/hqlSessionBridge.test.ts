import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { scanTargetFunctions } from './hqlScanner';

void (async () => {
	const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hql-bridge-'));
	const dbPath = path.join(directory, '.hexcore_session.db');
	const targetIdentity = `target:sha256:${'a'.repeat(64)}`;
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const sqlite = require(path.resolve(__dirname, '..', '..', 'hexcore-better-sqlite3', 'index.js'));
	const db = sqlite.openDatabase(dbPath);
	db.exec(`
		CREATE TABLE functions(address TEXT PRIMARY KEY, name TEXT, return_type TEXT);
		CREATE TABLE variables(func_address TEXT, original_name TEXT, new_name TEXT, new_type TEXT);
		CREATE TABLE hxdb_meta(key TEXT PRIMARY KEY, value TEXT);
		CREATE TABLE function_prototypes(target_identity TEXT, function_identity TEXT, function_address TEXT, record_json TEXT);
		CREATE TABLE type_bindings(target_identity TEXT, function_identity TEXT, record_json TEXT);
		CREATE TABLE reference_edges(analysis_target_identity TEXT, active INTEGER, owner_function_identity TEXT, target_identity_value TEXT, record_json TEXT);
		CREATE TABLE propagation_summaries(analysis_target_identity TEXT, function_identity TEXT, record_json TEXT);
		CREATE TABLE fact_conflicts(target_identity TEXT, fact_kind TEXT, fact_key TEXT, reason TEXT, winner_hash TEXT, loser_hash TEXT);
	`);
	db.prepare(`INSERT INTO hxdb_meta VALUES ('target_identity', ?)`).run(targetIdentity);
	const address = '0xfedcba9876543210';
	const evidence = { producer: 'pdb:bridge-test', source: 'debug-info', strength: 'debug', generation: 4 };
	db.prepare(`INSERT INTO function_prototypes VALUES (?, ?, ?, ?)`).run(
		targetIdentity,
		`function:${address}`,
		address,
		JSON.stringify({
			functionIdentity: `function:${address}`,
			callingConventionId: 'win64',
			returnTypeId: 'type:void',
			variadic: false,
			noreturn: false,
			method: false,
			evidence,
			evidenceSet: [evidence],
		}),
	);
	db.close();

	try {
		const astBuffer = fs.readFileSync(path.resolve(__dirname, '..', '..', 'hexcore-hql', 'test', 'fixtures', 'semantic-quality-v1_1.fb'));
		const decompile = async () => ({ success: true, status: 'ok' as const, architecture: 'arm64', securityEvidenceUsable: true, code: '', address, error: '', astBuffer });
		const results = await scanTargetFunctions(
			{ address },
			decompile,
			{ session: { dbPath, expectedTargetIdentity: targetIdentity } },
		);
		assert.strictEqual(results.length, 1);
		assert.strictEqual(results[0].status, 'ok');
		assert.strictEqual(results[0].semanticFactCount, 1);
		assert.match(results[0].semanticFactsSha256 ?? '', /^[0-9a-f]{64}$/);
		const standaloneIr = await scanTargetFunctions(
			{ irText: '; standalone Remill fixture' },
			decompile,
			{ session: {
				getSnapshotIdentity: () => ({
					targetIdentity,
					sessionId: 'standalone-test',
					generation: 1,
					universeSha256: 'b'.repeat(64),
					snapshotSha256: 'c'.repeat(64),
					architecture: 'arm64',
					format: 'pe',
					propagationGeneration: null,
					referenceGeneration: null,
					engines: [],
				}),
				getTargetIdentity: () => targetIdentity,
				getFunctionName: () => undefined,
				getFunctionReturnType: () => undefined,
				getVariableRenames: () => [],
				getSemanticFacts: () => { throw new Error('foreign HXDB must not be read'); },
				getSemanticReadErrors: () => [],
				dispose: () => undefined,
			} },
		);
		assert.notStrictEqual(standaloneIr[0].status, 'error');
		assert.strictEqual(standaloneIr[0].semanticFactCount, 0);
		const partial = await scanTargetFunctions({ address }, async () => ({
			...await decompile(), status: 'partial', warning: 'function boundary not reached',
		}), { session: { dbPath, expectedTargetIdentity: targetIdentity } });
		assert.strictEqual(partial[0].status, 'partial');
		assert.strictEqual(partial[0].hast?.semanticEligible, false);
		assert.strictEqual(partial[0].semanticFactCount, 1, 'facts remain inspectable, not promoted');
		assert.strictEqual(partial[0].evaluatedSignatureCount, 0);
		assert.ok(partial[0].partialReasons?.some(reason => reason.includes('boundary not reached')));
		const wrongArch = await scanTargetFunctions({ address }, async () => ({ ...await decompile(), architecture: 'x64' }));
		assert.strictEqual(wrongArch[0].status, 'partial');
		assert.strictEqual(wrongArch[0].hast?.semanticEligible, false);
		const inherited = await scanTargetFunctions({ address }, decompile, { inputPartialReasons: ['Partial persisted input'] });
		assert.strictEqual(inherited[0].status, 'partial');
		assert.strictEqual(inherited[0].hast?.semanticEligible, false);
		assert.strictEqual(inherited[0].evaluatedSignatureCount, 0);

		const mismatch = await scanTargetFunctions(
			{ address },
			decompile,
			{ session: { dbPath, expectedTargetIdentity: `target:sha256:${'b'.repeat(64)}` } },
		);
		assert.strictEqual(mismatch[0].status, 'error');
		assert.match(mismatch[0].error ?? '', /HXDB target mismatch/);
		console.log('hqlSessionBridge: target-bound real HXDB facts reach installed HQL - OK');
	} finally {
		fs.rmSync(directory, { recursive: true, force: true });
	}
})().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
