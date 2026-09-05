/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { loadNativeModule } from 'hexcore-common';
import { SESSION_SCHEMA_VERSION, SessionStore } from './sessionStore';

interface TestStatement {
	run(...params: unknown[]): unknown;
	get(...params: unknown[]): unknown;
}

interface TestDatabase {
	exec(sql: string): void;
	prepare(sql: string): TestStatement;
	close(): void;
}

interface TestSqliteModule {
	openDatabase(filename: string): TestDatabase;
}

function openRawDatabase(filename: string): TestDatabase {
	const loaded = loadNativeModule<TestSqliteModule>({
		moduleName: 'hexcore-better-sqlite3',
		candidatePaths: [path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')],
	});
	assert.ok(loaded.module, loaded.errorMessage);
	return loaded.module.openDatabase(filename);
}

suite('SessionStore schema migrations', () => {
	let tempDir = '';

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-session-migration-'));
	});

	teardown(() => {
		const resolved = path.resolve(tempDir);
		const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempRoot)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('migrates a legacy schema-0 database transactionally without losing analyst data', () => {
		const binaryPath = path.join(tempDir, 'legacy.bin');
		const dbPath = path.join(tempDir, '.hexcore_session.db');
		fs.writeFileSync(binaryPath, Buffer.from([1, 2, 3, 4]));

		const legacy = new SessionStore(binaryPath);
		legacy.renameFunction('0x401000', 'verify_flag');
		legacy.retypeFunction('0x401000', 'bool');
		legacy.renameVariable('0x401000', 'v1', 'candidate');
		legacy.retypeVariable('0x401000', 'v1', 'const char *');
		legacy.setField('context', 8, 'state', 'uint32_t');
		legacy.setComment('0x401000', 'legacy analyst comment');
		legacy.setBookmark('0x401000', 'legacy entry');
		legacy.recordInvestigation({
			id: 'investigation:legacy',
			title: 'Legacy finding',
			kind: 'string-reference',
			query: 'flag',
			status: 'complete',
		}, [{
			id: 'finding:sha256:legacy',
			investigationId: 'investigation:legacy',
			kind: 'string-reference',
			query: 'flag',
			label: 'flag reference',
			stringAddress: '0x402000',
			referenceAddress: '0x401010',
			functionAddress: '0x401000',
			functionName: 'verify_flag',
			encoding: 'ascii',
			evidenceJson: '{}',
			saved: true,
		}]);
		legacy.dispose();

		const raw = openRawDatabase(dbPath);
		raw.exec(`
			PRAGMA foreign_keys = OFF;
			DROP TABLE IF EXISTS legacy_migrations;
			DROP TABLE IF EXISTS fact_generations;
			DROP TABLE IF EXISTS fact_conflicts;
			DROP TABLE IF EXISTS fact_dependencies;
			DROP TABLE IF EXISTS type_bindings;
			DROP TABLE IF EXISTS function_parameters;
			DROP TABLE IF EXISTS function_prototypes;
			DROP TABLE IF EXISTS type_dependencies;
			DROP TABLE IF EXISTS type_aliases;
			DROP TABLE IF EXISTS enum_members;
			DROP TABLE IF EXISTS type_members;
			DROP TABLE IF EXISTS types;
			DROP TABLE IF EXISTS hxdb_meta;
			PRAGMA user_version = 1;
		`);
		raw.close();

		const migrated = new SessionStore(binaryPath);
		assert.strictEqual(migrated.getSchemaVersion(), SESSION_SCHEMA_VERSION);
		assert.deepStrictEqual(migrated.getFunction('0x401000')?.name, 'verify_flag');
		assert.deepStrictEqual(migrated.getFunction('0x401000')?.return_type, 'bool');
		assert.deepStrictEqual(migrated.getVariables('0x401000')[0]?.new_name, 'candidate');
		assert.deepStrictEqual(migrated.getVariables('0x401000')[0]?.new_type, 'const char *');
		assert.deepStrictEqual(migrated.getFields('context')[0]?.name, 'state');
		assert.strictEqual(migrated.getComment('0x401000'), 'legacy analyst comment');
		assert.strictEqual(migrated.getAllBookmarks()[0]?.label, 'legacy entry');
		assert.strictEqual(migrated.getInvestigationFinding('finding:sha256:legacy')?.saved, 1);
		const semantic = migrated.getSemanticStore();
		assert.strictEqual(semantic.getPrototype('0x401000')?.callingConventionId, 'win64');
		assert.strictEqual(semantic.getType(semantic.getPrototype('0x401000')!.returnTypeId)?.kind, 'bool');
		assert.ok(semantic.findTypeBindings('0x401000', 'local').some(binding => binding.valueIdentity === 'v1'));
		assert.ok(semantic.listLegacyMigrations().some(record => record.sourceKind === 'comment'));
		assert.ok(semantic.listLegacyMigrations().some(record => record.sourceKind === 'bookmark'));
		migrated.dispose();
		const migrationBackups = fs.readdirSync(tempDir)
			.filter(name => name.startsWith('.hexcore_session.db.migration-backup-v1-to-v2-') && !name.endsWith('-wal') && !name.endsWith('-shm'));
		assert.strictEqual(migrationBackups.length, 1);
	});

	test('quarantines the complete old database when the binary hash changes', () => {
		const binaryPath = path.join(tempDir, 'mutable.bin');
		fs.writeFileSync(binaryPath, Buffer.from([1, 1, 1, 1]));
		const first = new SessionStore(binaryPath);
		const oldHash = first.getBinarySha256();
		first.renameFunction('0x401000', 'old_binary_function');
		first.setComment('0x401000', 'must not cross target identity');
		first.retypeFunction('0x401000', 'uint64_t');
		first.dispose();

		fs.writeFileSync(binaryPath, Buffer.from([2, 2, 2, 2]));
		const second = new SessionStore(binaryPath);
		assert.notStrictEqual(second.getBinarySha256(), oldHash);
		assert.strictEqual(second.getFunction('0x401000'), undefined);
		assert.strictEqual(second.getComment('0x401000'), undefined);
		assert.strictEqual(second.getSemanticStore().listPrototypes().length, 0);
		second.dispose();

		const quarantined = fs.readdirSync(tempDir)
			.filter(name => name.startsWith(`.hexcore_session.db.target-mismatch-${oldHash.slice(0, 12)}-`) && !name.endsWith('-wal') && !name.endsWith('-shm'));
		assert.strictEqual(quarantined.length, 1);
		const archived = openRawDatabase(path.join(tempDir, quarantined[0]));
		const owner = archived.prepare(`SELECT value FROM session_meta WHERE key = 'binary_sha256'`).get() as { value: string };
		assert.strictEqual(owner.value, oldHash);
		archived.close();
	});

	test('backs up an incompatible schema-0 database and rebuilds a usable schema', () => {
		const binaryPath = path.join(tempDir, 'corrupt.bin');
		const dbPath = path.join(tempDir, '.hexcore_session.db');
		fs.writeFileSync(binaryPath, Buffer.from([5, 6, 7, 8]));

		const raw = openRawDatabase(dbPath);
		raw.exec('CREATE TABLE session_meta (broken TEXT); PRAGMA user_version = 0;');
		raw.close();

		const recovered = new SessionStore(binaryPath);
		assert.strictEqual(recovered.getSchemaVersion(), SESSION_SCHEMA_VERSION);
		recovered.setComment('0x5000', 'recovered database is writable');
		assert.strictEqual(recovered.getComment('0x5000'), 'recovered database is writable');
		recovered.dispose();

		const backups = fs.readdirSync(tempDir)
			.filter(name => name.startsWith('.hexcore_session.db.migration-backup-') && !name.endsWith('-wal') && !name.endsWith('-shm'));
		assert.strictEqual(backups.length, 1);
		assert.ok(fs.statSync(path.join(tempDir, backups[0])).size > 0);
	});
});
