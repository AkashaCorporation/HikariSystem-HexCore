/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	SemanticTypeCatalog,
	canonicalSerialize,
	canonicalizeFunctionPrototype,
	canonicalizeSemanticType,
	canonicalizeTypeBinding,
	type EvidenceStrength,
	type SemanticEvidence,
} from './semanticModel';
import {
	HXDB_SEMANTIC_SCHEMA_VERSION,
	SemanticStore,
	SemanticTargetMismatchError,
	type SemanticSqliteDatabase,
	type SemanticSqliteFactory,
} from './semanticStore';

function loadNativeSqlite(): SemanticSqliteFactory {
	// Use the same local native package that SessionStore loads in production.
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	return require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')) as SemanticSqliteFactory;
}

function evidence(
	strength: EvidenceStrength = 'derived',
	generation = 1,
	producer = 'semantic-store-test',
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

function tableNames(db: SemanticSqliteDatabase): string[] {
	return db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).all()
		.map(row => String((row as { name: unknown }).name));
}

suite('HXDB semantic store R31', function () {
	this.timeout(20_000);
	const targetIdentity = `target:sha256:${'a'.repeat(64)}`;
	let tempDir = '';

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-semantic-store-'));
	});

	teardown(() => {
		const resolved = path.resolve(tempDir);
		const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempRoot)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('initializes every v2 semantic table and round-trips complete prototypes through injected native SQLite', () => {
		const sqlite = loadNativeSqlite();
		const db = sqlite.openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		assert.strictEqual(store.getOwnership().schemaVersion, HXDB_SEMANTIC_SCHEMA_VERSION);
		assert.deepStrictEqual(
			[
				'hxdb_meta', 'types', 'type_members', 'enum_members', 'type_aliases', 'type_dependencies',
				'function_prototypes', 'function_parameters', 'type_bindings', 'fact_dependencies',
				'fact_conflicts', 'fact_generations', 'legacy_migrations',
			].filter(name => !tableNames(db).includes(name)),
			[],
		);

		const ev = evidence('debug', 7, 'pdb:fixture');
		const uint64 = canonicalizeSemanticType({ kind: 'integer', name: 'uint64_t', sizeBits: 64, alignBits: 64, signed: false }, ev);
		const uint8 = canonicalizeSemanticType({ kind: 'integer', name: 'uint8_t', sizeBits: 8, alignBits: 8, signed: false }, ev);
		const pointer = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: uint8.typeId, sizeBits: 64, alignBits: 64 }, ev);
		const context = new SemanticTypeCatalog(targetIdentity, 'pdb:tpi').defineNominal({
			kind: 'struct', name: 'Context', sizeBits: 128, alignBits: 64,
			members: [
				{ name: 'flags', typeId: uint64.typeId, bitOffset: 0, evidence: ev },
				{ name: 'data', typeId: pointer.typeId, bitOffset: 64, evidence: ev },
			],
			aliases: [{ name: 'CTX', targetTypeId: 'type:legacy:ctx', evidence: ev }],
		}, ev);
		const contextPointer = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: context.typeId, sizeBits: 64, alignBits: 64 }, ev);

		store.writeBatch({ types: [uint64, uint8, pointer, context, contextPointer] });
		const prototype = canonicalizeFunctionPrototype({
			targetIdentity,
			functionIdentity: 'function:0x140001000',
			functionAddress: '0x140001000',
			returnTypeId: uint64.typeId,
			callingConventionId: 'usercall',
			method: true,
			parameters: [
				{
					ordinal: 0, stableIdentity: 'this', name: 'this', typeId: contextPointer.typeId,
					location: { kind: 'implicit', role: 'this', register: 'rcx' }, hiddenThis: true,
					ownership: 'borrow', lifetime: 'call',
				},
				{
					ordinal: 1, stableIdentity: 'buffer', stableIdentityAliases: ['pdb:param:buffer'], name: 'buffer', typeId: pointer.typeId,
					location: { kind: 'register', registers: ['rdx'] }, direction: 'inout', nullable: true,
					buffer: { kind: 'bytes', countParameterOrdinal: 2 }, ownership: 'borrow', lifetime: 'call',
				},
				{
					ordinal: 2, stableIdentity: 'size', name: 'size', typeId: uint64.typeId,
					location: { kind: 'split', parts: [
						{ kind: 'register', registers: ['r8'] },
						{ kind: 'stack', base: 'entry-sp', offsetBytes: 40, sizeBytes: 8 },
					] },
				},
				{
					ordinal: 3, stableIdentity: 'sret', name: 'result_storage', typeId: pointer.typeId,
					location: { kind: 'implicit', role: 'sret', register: 'r9' }, hiddenSret: true,
					ownership: 'borrow', lifetime: 'caller',
				},
			],
			hiddenReturn: { kind: 'sret-parameter', location: { kind: 'implicit', role: 'sret', register: 'r9' } },
			hiddenStorage: { parameterOrdinal: 3, callerAllocated: true, calleeReturnsPointer: false },
			evidence: ev,
		});
		const binding = canonicalizeTypeBinding({
			targetIdentity,
			scope: 'function-parameter',
			valueIdentity: prototype.parameters[1].parameterId,
			functionIdentity: prototype.functionIdentity,
			typeId: pointer.typeId,
			invalidationDependencies: ['generation:cfg:9', 'generation:prototype:7'],
			evidence: ev,
		});
		store.writeBatch({ prototypes: [prototype], typeBindings: [binding] });

		assert.strictEqual(canonicalSerialize(store.getPrototype(prototype.functionIdentity)), canonicalSerialize(prototype));
		assert.strictEqual(canonicalSerialize(store.getTypeBinding(binding.bindingId)), canonicalSerialize(binding));
		assert.strictEqual(store.getPrototypeAtAddress('0x140001000')?.prototypeId, prototype.prototypeId);
		assert.strictEqual(store.findTypeBindings(prototype.functionIdentity, 'function-parameter').length, 1);
		assert.deepStrictEqual(
			store.listDependencies('prototype', prototype.functionIdentity)
				.filter(item => item.dependencyKind === 'type')
				.map(item => item.dependencyKey),
			[contextPointer.typeId, pointer.typeId, uint64.typeId].sort(),
		);
		assert.ok(store.listDependencies('type-binding', binding.bindingId)
			.some(item => item.dependencyKind === 'invalidation' && item.dependencyKey === 'generation:cfg:9'));
		assert.strictEqual((db.prepare(
			`SELECT COUNT(*) AS count FROM function_parameters WHERE target_identity = ? AND function_identity = ?`,
		).get(targetIdentity, prototype.functionIdentity) as { count: number }).count, 4);
		const split = db.prepare(`
			SELECT location_kind, location_json, buffer_json FROM function_parameters
			WHERE target_identity = ? AND function_identity = ? AND ordinal = 2
		`).get(targetIdentity, prototype.functionIdentity) as Record<string, unknown>;
		assert.strictEqual(split.location_kind, 'split');
		assert.match(String(split.location_json), /entry-sp/);
		assert.strictEqual(split.buffer_json, null);
		const aliases = db.prepare(`
			SELECT stable_identity_aliases_json FROM function_parameters
			WHERE target_identity = ? AND function_identity = ? AND ordinal = 1
		`).get(targetIdentity, prototype.functionIdentity) as { stable_identity_aliases_json: string };
		assert.deepStrictEqual(JSON.parse(aliases.stable_identity_aliases_json), prototype.parameters[1].stableIdentityAliases);
		const storedEvidence = db.prepare(`
			SELECT evidence_source, evidence_strength, evidence_producer, evidence_generation
			FROM function_prototypes WHERE target_identity = ? AND function_identity = ?
		`).get(targetIdentity, prototype.functionIdentity) as Record<string, unknown>;
		assert.deepStrictEqual(storedEvidence, {
			evidence_source: 'debug-info', evidence_strength: 'debug', evidence_producer: 'pdb:fixture', evidence_generation: 7,
		});
		assert.ok(store.queryHash('prototype', prototype.functionIdentity));
		assert.strictEqual(store.exportHash().length, 64);
		store.dispose();
	});

	test('batch and export hashes are independent of insertion order', () => {
		const sqlite = loadNativeSqlite();
		const left = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const right = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const first = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, alignBits: 32, signed: true }, evidence());
		const second = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: first.typeId, sizeBits: 64, alignBits: 64 }, evidence());
		const leftWrite = left.writeBatch({ types: [first, second] });
		const rightWrite = right.writeBatch({ types: [second, first] });
		assert.strictEqual(leftWrite.transactionHash, rightWrite.transactionHash);
		assert.strictEqual(left.exportCanonical(), right.exportCanonical());
		assert.strictEqual(left.exportHash(), right.exportHash());

		const weak = new SemanticTypeCatalog(targetIdentity, 'batch-order').defineNominal({
			kind: 'struct', name: 'OrderSensitive', sizeBits: 32, alignBits: 32,
		}, evidence('derived', 1, 'batch:weak'));
		const strong = new SemanticTypeCatalog(targetIdentity, 'batch-order').defineNominal({
			kind: 'struct', name: 'OrderSensitive', sizeBits: 64, alignBits: 64,
		}, evidence('debug', 2, 'batch:strong'));
		assert.strictEqual(weak.typeId, strong.typeId);
		const leftConflict = left.writeBatch({ types: [weak, strong] });
		const rightConflict = right.writeBatch({ types: [strong, weak] });
		assert.strictEqual(leftConflict.transactionHash, rightConflict.transactionHash);
		assert.strictEqual(left.exportCanonical(), right.exportCanonical());
		assert.strictEqual(left.exportHash(), right.exportHash());
		left.dispose();
		right.dispose();
	});

	test('rejects an incompatible partial schema instead of silently accepting missing v2 columns', () => {
		const sqlite = loadNativeSqlite();
		const db = sqlite.openDatabase(':memory:');
		db.exec(`CREATE TABLE types (type_id TEXT PRIMARY KEY);`);
		assert.throws(() => new SemanticStore(db, targetIdentity), /table types is incompatible; missing columns/i);
		assert.deepStrictEqual(tableNames(db), ['types']);
		db.close?.();
	});

	test('preserves exact int64 enum values in canonical records and relational rows', () => {
		const sqlite = loadNativeSqlite();
		const db = sqlite.openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const enumType = canonicalizeSemanticType({
			kind: 'enum', name: 'UnsignedBoundary', sizeBits: 64, alignBits: 64, signed: false,
			enumMembers: [
				{ name: 'Max', value: 18_446_744_073_709_551_615n },
				{ name: 'BeyondSafeInteger', value: '9007199254740993' },
			],
		}, evidence('debug'));
		store.putType(enumType);
		assert.strictEqual(store.getType(enumType.typeId)?.enumMembers?.find(member => member.name === 'Max')?.value, '18446744073709551615');
		const rows = db.prepare(`
			SELECT name, value_text FROM enum_members WHERE target_identity = ? AND owner_type_id = ? ORDER BY name
		`).all(targetIdentity, enumType.typeId) as Array<{ name: string; value_text: string }>;
		assert.deepStrictEqual(rows, [
			{ name: 'BeyondSafeInteger', value_text: '9007199254740993' },
			{ name: 'Max', value_text: '18446744073709551615' },
		]);
		store.dispose();
	});

	test('reopening the same target reproduces canonical exports and exact query hashes', () => {
		const sqlite = loadNativeSqlite();
		const dbPath = path.join(tempDir, 'roundtrip.hxdb');
		const store = SemanticStore.open(dbPath, targetIdentity, sqlite);
		const type = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, alignBits: 32, signed: true }, evidence());
		store.putType(type);
		const beforeCanonical = store.exportCanonical();
		const beforeHash = store.exportHash();
		const queryHash = store.queryHash('type', type.typeId);
		const generationCount = store.listGenerations().length;
		store.dispose();

		const reopened = SemanticStore.open(dbPath, targetIdentity, sqlite);
		assert.strictEqual(reopened.exportCanonical(), beforeCanonical);
		assert.strictEqual(reopened.exportHash(), beforeHash);
		assert.strictEqual(reopened.queryHash('type', type.typeId), queryHash);
		assert.strictEqual(reopened.listGenerations().length, generationCount);
		// An exact rerun is idempotent and must not manufacture another generation.
		reopened.putType(type);
		assert.strictEqual(reopened.exportHash(), beforeHash);
		assert.strictEqual(reopened.listGenerations().length, generationCount);
		reopened.dispose();
	});

	test('rolls back a batch completely when a later canonical record is invalid', () => {
		const sqlite = loadNativeSqlite();
		const store = SemanticStore.open(path.join(tempDir, 'rollback.hxdb'), targetIdentity, sqlite);
		const first = canonicalizeSemanticType({ kind: 'integer', sizeBits: 16, alignBits: 16, signed: true }, evidence());
		const second = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, alignBits: 32, signed: false }, evidence());
		const corrupt = { ...second, canonicalHash: '0'.repeat(64) };
		assert.throws(
			() => store.writeBatch({ types: [first, corrupt] }),
			/Canonical semantic type integrity failure/,
		);
		assert.strictEqual(store.getType(first.typeId), undefined);
		assert.strictEqual(store.listTypes().length, 0);
		assert.strictEqual(store.listGenerations().length, 0);
		store.dispose();
	});

	test('arbitrates conflicting nominal facts by evidence strength and persists conflicts deterministically', () => {
		const sqlite = loadNativeSqlite();
		const store = SemanticStore.open(path.join(tempDir, 'evidence.hxdb'), targetIdentity, sqlite);
		const derived = new SemanticTypeCatalog(targetIdentity, 'dwarf-cu:10').defineNominal({
			kind: 'struct', name: 'Header', sizeBits: 32, alignBits: 32,
		}, evidence('derived', 1, 'dataflow:layout'));
		const debug = new SemanticTypeCatalog(targetIdentity, 'dwarf-cu:10').defineNominal({
			kind: 'struct', name: 'Header', sizeBits: 64, alignBits: 64,
		}, evidence('debug', 2, 'dwarf:layout'));
		const lateWeak = new SemanticTypeCatalog(targetIdentity, 'dwarf-cu:10').defineNominal({
			kind: 'struct', name: 'Header', sizeBits: 128, alignBits: 64,
		}, evidence('derived', 99, 'dataflow:late'));
		assert.strictEqual(derived.typeId, debug.typeId);
		assert.strictEqual(store.putType(derived).status, 'accepted-new');
		assert.strictEqual(store.putType(debug).status, 'replaced-stronger');
		assert.strictEqual(store.putType(lateWeak).status, 'rejected-weaker');
		assert.strictEqual(store.getType(derived.typeId)?.sizeBits, 64);
		assert.strictEqual(store.getType(derived.typeId)?.evidence.strength, 'debug');
		assert.strictEqual(store.listConflicts().length, 2);
		const firstHash = store.exportHash();
		store.putType(lateWeak);
		assert.strictEqual(store.exportHash(), firstHash);
		assert.strictEqual(store.listConflicts().length, 2);
		store.dispose();
	});

	test('migrates legacy v1 type strings or opaque declarations without losing raw facts', () => {
		const sqlite = loadNativeSqlite();
		const store = SemanticStore.open(path.join(tempDir, 'legacy.hxdb'), targetIdentity, sqlite);
		const opaqueReturn = 'void (__declspec(unsupported_magic) * callback)(int, ...)';
		const result = store.migrateLegacyV1({
			functions: [{
				address: '0x401000', name: 'legacy_callback', return_type: opaqueReturn,
				calling_convention: '__stdcall',
			}],
			variables: [{
				func_address: '0x401000', original_name: 'large_counter', new_name: 'total',
				new_type: 'unsigned __int64',
			}],
			fields: [{ struct_type: 'LegacyContext', offset: 8, name: 'name', type: 'const char *' }],
			additionalFacts: [{ kind: 'comment', key: '0x401000', value: 'analyst note preserved verbatim' }],
		});
		assert.ok(result.typeCount >= 4);
		assert.strictEqual(result.prototypeCount, 1);
		assert.strictEqual(result.bindingCount, 1);
		assert.strictEqual(result.preservedRecordCount, 4);
		const prototype = store.getPrototype('0x401000');
		assert.strictEqual(prototype?.callingConventionId, 'stdcall');
		assert.strictEqual(store.getType(prototype?.returnTypeId ?? '')?.kind, 'opaque-c-declaration');
		const migrations = store.listLegacyMigrations();
		const functionMigration = migrations.find(item => item.sourceKind === 'function');
		assert.strictEqual(JSON.parse(functionMigration?.rawJson ?? '{}').return_type, opaqueReturn);
		assert.ok(migrations.some(item => item.sourceKind === 'comment' && item.status === 'preserved-only'));
		assert.ok(migrations.every(item => item.rawJson.length > 0));
		const before = store.exportHash();
		const repeat = store.migrateLegacyV1({
			functions: [{ address: '0x401000', name: 'legacy_callback', return_type: opaqueReturn, calling_convention: '__stdcall' }],
			variables: [{ func_address: '0x401000', original_name: 'large_counter', new_name: 'total', new_type: 'unsigned __int64' }],
			fields: [{ struct_type: 'LegacyContext', offset: 8, name: 'name', type: 'const char *' }],
			additionalFacts: [{ kind: 'comment', key: '0x401000', value: 'analyst note preserved verbatim' }],
		});
		assert.strictEqual(repeat.migrationHash, result.migrationHash);
		assert.strictEqual(store.exportHash(), before);
		store.dispose();
	});

	test('refuses wrong-target ownership on reopen and on incoming semantic facts', () => {
		const sqlite = loadNativeSqlite();
		const dbPath = path.join(tempDir, 'ownership.hxdb');
		const store = SemanticStore.open(dbPath, targetIdentity, sqlite);
		store.dispose();
		const otherTarget = `target:sha256:${'b'.repeat(64)}`;
		assert.throws(
			() => SemanticStore.open(dbPath, otherTarget, sqlite),
			(error: unknown) => error instanceof SemanticTargetMismatchError
				&& error.expectedTargetIdentity === otherTarget
				&& error.actualTargetIdentity === targetIdentity,
		);

		const correct = SemanticStore.open(dbPath, targetIdentity, sqlite);
		const foreignNominal = new SemanticTypeCatalog(otherTarget, 'pdb:tpi').defineNominal({
			kind: 'struct', name: 'ForeignObject', sizeBits: 64, alignBits: 64,
		}, evidence('debug'));
		assert.throws(() => correct.putType(foreignNominal), /target mismatch/i);
		assert.strictEqual(correct.listTypes().length, 0);
		assert.throws(() => correct.putPrototype({
			targetIdentity: otherTarget,
			functionIdentity: 'function:foreign',
			returnTypeId: 'type:foreign',
			callingConventionId: 'win64',
			parameters: [],
			evidence: evidence(),
		}), /target mismatch/i);
		assert.strictEqual(correct.listPrototypes().length, 0);
		assert.throws(() => correct.putTypeBinding({
			targetIdentity: otherTarget,
			scope: 'global',
			valueIdentity: 'global:foreign',
			typeId: 'type:foreign',
			evidence: evidence(),
		}), /target mismatch/i);
		assert.strictEqual(correct.findTypeBindings().length, 0);
		correct.dispose();
	});
});
