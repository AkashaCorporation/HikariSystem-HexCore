/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	SEMANTIC_SCHEMA_VERSION,
	SemanticTypeCatalog,
	arbitrateSemanticValue,
	canonicalSerialize,
	canonicalizeFunctionPrototype,
	canonicalizeSemanticType,
	canonicalizeTypeBinding,
	type ArbitrationResult,
	type CallingConventionId,
	type CanonicalFunctionPrototype,
	type CanonicalSemanticType,
	type CanonicalTypeBinding,
	type FunctionParameterSpec,
	type FunctionPrototypeSpec,
	type LegacyCTypeOptions,
	type SemanticEvidence,
	type SemanticTypeMemberSpec,
	type TypeBindingScope,
	type TypeBindingSpec,
} from './semanticModel';
import { TypedReferenceGraph, type ReferenceGraphSnapshot } from './typedReferenceGraph';
import {
	WholeProgramPropagationStore,
	type PropagationStoreSnapshot,
} from './wholeProgramPropagation';

export const HXDB_SEMANTIC_SCHEMA_VERSION = SEMANTIC_SCHEMA_VERSION;

export interface SemanticSqliteRunResult {
	changes: number;
	lastInsertRowid: number | bigint;
}

export interface SemanticSqliteStatement {
	run(...params: unknown[]): SemanticSqliteRunResult;
	get(...params: unknown[]): unknown;
	all(...params: unknown[]): unknown[];
}

export interface SemanticSqliteDatabase {
	exec(sql: string): unknown;
	prepare(sql: string): SemanticSqliteStatement;
	close?(): unknown;
	readonly open?: boolean;
}

export interface SemanticSqliteFactory {
	openDatabase(filename: string, options?: { readonly?: boolean; fileMustExist?: boolean }): SemanticSqliteDatabase;
}

export interface SemanticStoreOwnership {
	schemaVersion: number;
	targetIdentity: string;
}

export interface SemanticWriteBatch {
	types?: readonly CanonicalSemanticType[];
	prototypes?: readonly (FunctionPrototypeSpec | CanonicalFunctionPrototype)[];
	typeBindings?: readonly (TypeBindingSpec | CanonicalTypeBinding)[];
}

export interface SemanticWriteBatchResult {
	transactionHash: string;
	typeResults: readonly ArbitrationResult<CanonicalSemanticType>[];
	prototypeResults: readonly ArbitrationResult<CanonicalFunctionPrototype>[];
	bindingResults: readonly ArbitrationResult<CanonicalTypeBinding>[];
}

export interface SemanticSnapshot {
	schemaVersion: number;
	targetIdentity: string;
	types: readonly CanonicalSemanticType[];
	prototypes: readonly CanonicalFunctionPrototype[];
	typeBindings: readonly CanonicalTypeBinding[];
	dependencies: readonly SemanticFactDependency[];
	conflicts: readonly SemanticStoredConflict[];
	generations: readonly SemanticStoredGeneration[];
	history: readonly SemanticStoredFactHistory[];
	legacyMigrations: readonly LegacyMigrationRecord[];
	referenceGraph: ReferenceGraphSnapshot;
	wholeProgramPropagation: PropagationStoreSnapshot;
}

export interface SemanticStoredConflict {
	conflictHash: string;
	factKind: SemanticFactKind;
	factKey: string;
	reason: string;
	winnerHash: string;
	loserHash: string;
	winnerJson: string;
	loserJson: string;
}

export interface SemanticStoredGeneration {
	generationHash: string;
	transactionHash: string;
	factKind: SemanticFactKind;
	factKey: string;
	status: string;
	acceptedHash: string;
	incomingHash: string;
	evidenceGeneration: number;
}

export interface SemanticStoredFactHistory {
	historyHash: string;
	transactionHash: string;
	factKind: SemanticFactKind;
	factKey: string;
	role: 'incoming' | 'accepted';
	canonicalHash: string;
	recordJson: string;
	evidenceGeneration: number;
}

export interface SemanticTypeDeleteResult {
	status: 'removed' | 'not-found' | 'blocked';
	changed: boolean;
	typeId: string;
	transactionHash?: string;
	blockers: readonly SemanticFactDependency[];
}

export interface SemanticPrototypeOverrideClearResult {
	status: 'no-override' | 'restored' | 'removed';
	changed: boolean;
	functionIdentity: string;
	previousPrototype?: CanonicalFunctionPrototype;
	restoredPrototype?: CanonicalFunctionPrototype;
	transactionHash?: string;
}

export interface SemanticFactDependency {
	factKind: SemanticFactKind;
	factKey: string;
	dependencyKind: string;
	dependencyKey: string;
}

export type SemanticFactKind = 'type' | 'prototype' | 'type-binding';

export interface LegacyV1FunctionFact {
	address: string;
	name?: string | null;
	return_type?: string | null;
	calling_convention?: string | null;
	parameters?: readonly FunctionParameterSpec[];
}

export interface LegacyV1VariableFact {
	func_address: string;
	original_name: string;
	new_name?: string | null;
	new_type?: string | null;
	scope?: TypeBindingScope;
}

export interface LegacyV1FieldFact {
	struct_type: string;
	offset: number;
	name?: string | null;
	type?: string | null;
}

export interface LegacyV1SemanticFacts {
	functions?: readonly LegacyV1FunctionFact[];
	variables?: readonly LegacyV1VariableFact[];
	fields?: readonly LegacyV1FieldFact[];
	additionalFacts?: readonly { kind: string; key: string; value: unknown }[];
}

export interface LegacyV1MigrationOptions extends LegacyCTypeOptions {
	evidence?: SemanticEvidence;
	defaultCallingConventionId?: CallingConventionId;
}

export interface LegacyMigrationRecord {
	migrationId: string;
	sourceKind: string;
	sourceKey: string;
	rawJson: string;
	status: 'migrated' | 'preserved-only';
	typeId?: string;
	factKind?: SemanticFactKind;
	factKey?: string;
}

export interface LegacyV1MigrationResult {
	migrationHash: string;
	typeCount: number;
	prototypeCount: number;
	bindingCount: number;
	preservedRecordCount: number;
}

export class SemanticTargetMismatchError extends Error {
	constructor(
		readonly expectedTargetIdentity: string,
		readonly actualTargetIdentity: string,
	) {
		super(`HXDB target mismatch: database belongs to ${actualTargetIdentity}, not ${expectedTargetIdentity}.`);
		this.name = 'SemanticTargetMismatchError';
	}
}

const REQUIRED_COLUMNS: Readonly<Record<string, readonly string[]>> = {
	hxdb_meta: ['key', 'value'],
	types: [
		'target_identity', 'type_id', 'kind', 'name', 'nominal_identity', 'incomplete', 'size_bits', 'align_bits',
		'signed', 'element_count', 'target_type_id', 'is_const', 'is_volatile', 'is_restrict', 'opaque_declaration',
		'canonical_serialization', 'canonical_hash', 'record_json', 'evidence_json', 'evidence_set_json',
		'evidence_source', 'evidence_strength', 'evidence_producer', 'confidence', 'calibration_json',
		'evidence_generation', 'user_defined',
	],
	type_members: [
		'target_identity', 'owner_type_id', 'member_index', 'name', 'type_id', 'bit_offset', 'bit_size',
		'array_stride_bits', 'anonymous', 'nested', 'bitfield', 'evidence_json', 'evidence_set_json',
		'evidence_source', 'evidence_strength', 'evidence_producer', 'evidence_generation', 'confidence', 'calibration_json',
	],
	enum_members: [
		'target_identity', 'owner_type_id', 'member_index', 'name', 'value_text', 'evidence_json', 'evidence_set_json',
		'evidence_source', 'evidence_strength', 'evidence_producer', 'evidence_generation', 'confidence', 'calibration_json',
	],
	type_aliases: [
		'target_identity', 'owner_type_id', 'alias_index', 'name', 'target_type_id', 'evidence_json', 'evidence_set_json',
		'evidence_source', 'evidence_strength', 'evidence_producer', 'evidence_generation', 'confidence', 'calibration_json',
	],
	type_dependencies: ['target_identity', 'owner_type_id', 'dependency_type_id'],
	function_prototypes: [
		'target_identity', 'function_identity', 'function_address', 'prototype_id', 'return_type_id',
		'calling_convention_id', 'variadic', 'noreturn', 'method', 'static_method', 'hidden_return_json',
		'hidden_storage_json', 'canonical_serialization', 'canonical_hash', 'record_json', 'evidence_json',
		'evidence_set_json', 'evidence_source', 'evidence_strength', 'evidence_producer', 'confidence',
		'calibration_json', 'evidence_generation', 'user_defined',
	],
	function_parameters: [
		'target_identity', 'function_identity', 'ordinal', 'parameter_id', 'stable_identity', 'stable_identity_aliases_json', 'name', 'type_id',
		'location_kind', 'location_json', 'direction', 'optional', 'nullable', 'buffer_json', 'ownership',
		'lifetime', 'hidden_this', 'hidden_sret', 'compiler_generated',
	],
	type_bindings: [
		'target_identity', 'binding_id', 'scope', 'value_identity', 'function_identity', 'type_id',
		'canonical_serialization', 'canonical_hash', 'record_json', 'evidence_json', 'evidence_set_json',
		'evidence_source', 'evidence_strength', 'evidence_producer', 'confidence', 'calibration_json',
		'evidence_generation', 'user_defined',
	],
	fact_dependencies: ['target_identity', 'fact_kind', 'fact_key', 'dependency_kind', 'dependency_key'],
	fact_conflicts: [
		'target_identity', 'conflict_hash', 'fact_kind', 'fact_key', 'reason', 'winner_hash', 'loser_hash',
		'winner_json', 'loser_json',
	],
	fact_generations: [
		'target_identity', 'generation_hash', 'transaction_hash', 'fact_kind', 'fact_key', 'status',
		'accepted_hash', 'incoming_hash', 'evidence_generation',
	],
	fact_history: [
		'target_identity', 'history_hash', 'transaction_hash', 'fact_kind', 'fact_key', 'role',
		'canonical_hash', 'record_json', 'evidence_generation',
	],
	legacy_migrations: [
		'target_identity', 'migration_id', 'source_kind', 'source_key', 'raw_json', 'status', 'type_id',
		'fact_kind', 'fact_key',
	],
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS hxdb_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS types (
	target_identity TEXT NOT NULL,
	type_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	name TEXT,
	nominal_identity TEXT,
	incomplete INTEGER NOT NULL,
	size_bits INTEGER,
	align_bits INTEGER,
	signed INTEGER,
	element_count INTEGER,
	target_type_id TEXT,
	is_const INTEGER NOT NULL,
	is_volatile INTEGER NOT NULL,
	is_restrict INTEGER NOT NULL,
	opaque_declaration TEXT,
	canonical_serialization TEXT NOT NULL,
	canonical_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	evidence_generation INTEGER NOT NULL,
	user_defined INTEGER NOT NULL,
	PRIMARY KEY (target_identity, type_id)
);

CREATE TABLE IF NOT EXISTS type_members (
	target_identity TEXT NOT NULL,
	owner_type_id TEXT NOT NULL,
	member_index INTEGER NOT NULL,
	name TEXT NOT NULL,
	type_id TEXT NOT NULL,
	bit_offset INTEGER NOT NULL,
	bit_size INTEGER,
	array_stride_bits INTEGER,
	anonymous INTEGER NOT NULL,
	nested INTEGER NOT NULL,
	bitfield INTEGER NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	PRIMARY KEY (target_identity, owner_type_id, member_index),
	FOREIGN KEY (target_identity, owner_type_id) REFERENCES types(target_identity, type_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS enum_members (
	target_identity TEXT NOT NULL,
	owner_type_id TEXT NOT NULL,
	member_index INTEGER NOT NULL,
	name TEXT NOT NULL,
	value_text TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	PRIMARY KEY (target_identity, owner_type_id, member_index),
	FOREIGN KEY (target_identity, owner_type_id) REFERENCES types(target_identity, type_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS type_aliases (
	target_identity TEXT NOT NULL,
	owner_type_id TEXT NOT NULL,
	alias_index INTEGER NOT NULL,
	name TEXT NOT NULL,
	target_type_id TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	PRIMARY KEY (target_identity, owner_type_id, alias_index),
	FOREIGN KEY (target_identity, owner_type_id) REFERENCES types(target_identity, type_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS type_dependencies (
	target_identity TEXT NOT NULL,
	owner_type_id TEXT NOT NULL,
	dependency_type_id TEXT NOT NULL,
	PRIMARY KEY (target_identity, owner_type_id, dependency_type_id),
	FOREIGN KEY (target_identity, owner_type_id) REFERENCES types(target_identity, type_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS function_prototypes (
	target_identity TEXT NOT NULL,
	function_identity TEXT NOT NULL,
	function_address TEXT,
	prototype_id TEXT NOT NULL,
	return_type_id TEXT NOT NULL,
	calling_convention_id TEXT NOT NULL,
	variadic INTEGER NOT NULL,
	noreturn INTEGER NOT NULL,
	method INTEGER NOT NULL,
	static_method INTEGER NOT NULL,
	hidden_return_json TEXT,
	hidden_storage_json TEXT,
	canonical_serialization TEXT NOT NULL,
	canonical_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	evidence_generation INTEGER NOT NULL,
	user_defined INTEGER NOT NULL,
	PRIMARY KEY (target_identity, function_identity)
);

CREATE TABLE IF NOT EXISTS function_parameters (
	target_identity TEXT NOT NULL,
	function_identity TEXT NOT NULL,
	ordinal INTEGER NOT NULL,
	parameter_id TEXT NOT NULL,
	stable_identity TEXT,
	stable_identity_aliases_json TEXT NOT NULL,
	name TEXT NOT NULL,
	type_id TEXT NOT NULL,
	location_kind TEXT NOT NULL,
	location_json TEXT NOT NULL,
	direction TEXT NOT NULL,
	optional INTEGER NOT NULL,
	nullable INTEGER NOT NULL,
	buffer_json TEXT,
	ownership TEXT NOT NULL,
	lifetime TEXT NOT NULL,
	hidden_this INTEGER NOT NULL,
	hidden_sret INTEGER NOT NULL,
	compiler_generated INTEGER NOT NULL,
	PRIMARY KEY (target_identity, function_identity, ordinal),
	UNIQUE (target_identity, parameter_id),
	FOREIGN KEY (target_identity, function_identity) REFERENCES function_prototypes(target_identity, function_identity) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS type_bindings (
	target_identity TEXT NOT NULL,
	binding_id TEXT NOT NULL,
	scope TEXT NOT NULL,
	value_identity TEXT NOT NULL,
	function_identity TEXT,
	type_id TEXT NOT NULL,
	canonical_serialization TEXT NOT NULL,
	canonical_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	evidence_generation INTEGER NOT NULL,
	user_defined INTEGER NOT NULL,
	PRIMARY KEY (target_identity, binding_id)
);

CREATE TABLE IF NOT EXISTS fact_dependencies (
	target_identity TEXT NOT NULL,
	fact_kind TEXT NOT NULL,
	fact_key TEXT NOT NULL,
	dependency_kind TEXT NOT NULL,
	dependency_key TEXT NOT NULL,
	PRIMARY KEY (target_identity, fact_kind, fact_key, dependency_kind, dependency_key)
);

CREATE TABLE IF NOT EXISTS fact_conflicts (
	target_identity TEXT NOT NULL,
	conflict_hash TEXT NOT NULL,
	fact_kind TEXT NOT NULL,
	fact_key TEXT NOT NULL,
	reason TEXT NOT NULL,
	winner_hash TEXT NOT NULL,
	loser_hash TEXT NOT NULL,
	winner_json TEXT NOT NULL,
	loser_json TEXT NOT NULL,
	PRIMARY KEY (target_identity, conflict_hash)
);

CREATE TABLE IF NOT EXISTS fact_generations (
	target_identity TEXT NOT NULL,
	generation_hash TEXT NOT NULL,
	transaction_hash TEXT NOT NULL,
	fact_kind TEXT NOT NULL,
	fact_key TEXT NOT NULL,
	status TEXT NOT NULL,
	accepted_hash TEXT NOT NULL,
	incoming_hash TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	PRIMARY KEY (target_identity, generation_hash)
);

CREATE TABLE IF NOT EXISTS fact_history (
	target_identity TEXT NOT NULL,
	history_hash TEXT NOT NULL,
	transaction_hash TEXT NOT NULL,
	fact_kind TEXT NOT NULL,
	fact_key TEXT NOT NULL,
	role TEXT NOT NULL CHECK (role IN ('incoming', 'accepted')),
	canonical_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	PRIMARY KEY (target_identity, history_hash)
);

CREATE TABLE IF NOT EXISTS legacy_migrations (
	target_identity TEXT NOT NULL,
	migration_id TEXT NOT NULL,
	source_kind TEXT NOT NULL,
	source_key TEXT NOT NULL,
	raw_json TEXT NOT NULL,
	status TEXT NOT NULL,
	type_id TEXT,
	fact_kind TEXT,
	fact_key TEXT,
	PRIMARY KEY (target_identity, migration_id)
);

`;

const INDEX_SQL = `
CREATE INDEX IF NOT EXISTS semantic_types_kind_idx ON types(target_identity, kind, name);
CREATE INDEX IF NOT EXISTS semantic_members_owner_idx ON type_members(target_identity, owner_type_id, bit_offset);
CREATE INDEX IF NOT EXISTS semantic_prototypes_address_idx ON function_prototypes(target_identity, function_address);
CREATE INDEX IF NOT EXISTS semantic_bindings_value_idx ON type_bindings(target_identity, function_identity, scope, value_identity);
CREATE INDEX IF NOT EXISTS semantic_dependencies_fact_idx ON fact_dependencies(target_identity, fact_kind, fact_key);
CREATE INDEX IF NOT EXISTS semantic_generations_fact_idx ON fact_generations(target_identity, fact_kind, fact_key);
CREATE INDEX IF NOT EXISTS semantic_history_fact_idx ON fact_history(target_identity, fact_kind, fact_key, evidence_generation);
`;

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function compareCanonicalRecords(left: unknown, right: unknown): number {
	const leftSerialized = canonicalSerialize(left);
	const rightSerialized = canonicalSerialize(right);
	return compareAscii(leftSerialized, rightSerialized);
}

function hashText(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function canonicalHash(value: unknown): string {
	return hashText(canonicalSerialize(value));
}

function requireIdentity(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) {
		throw new Error(`${label} must not be empty.`);
	}
	return normalized;
}

function boolInt(value: boolean | undefined): number {
	return value === true ? 1 : 0;
}

function nullableBoolInt(value: boolean | undefined): number | null {
	return value === undefined ? null : boolInt(value);
}

function evidenceColumns(evidence: SemanticEvidence): readonly unknown[] {
	return [
		evidence.source,
		evidence.strength,
		evidence.producer,
		evidence.confidence ?? null,
		evidence.calibration ? canonicalSerialize(evidence.calibration) : null,
	];
}

function childEvidenceColumns(evidence: SemanticEvidence): readonly unknown[] {
	return [
		evidence.source,
		evidence.strength,
		evidence.producer,
		evidence.generation,
		evidence.confidence ?? null,
		evidence.calibration ? canonicalSerialize(evidence.calibration) : null,
	];
}

function parseJson<T>(value: unknown, label: string): T {
	if (typeof value !== 'string') {
		throw new Error(`${label} is not stored as JSON text.`);
	}
	try {
		return JSON.parse(value) as T;
	} catch (error) {
		throw new Error(`${label} contains invalid JSON: ${error instanceof Error ? error.message : String(error)}`);
	}
}

function rowString(row: unknown, key: string): string {
	const value = (row as Record<string, unknown> | undefined)?.[key];
	if (typeof value !== 'string') {
		throw new Error(`HXDB row is missing text column ${key}.`);
	}
	return value;
}

function rowNumber(row: unknown, key: string): number {
	const value = (row as Record<string, unknown> | undefined)?.[key];
	if (typeof value === 'number' && Number.isSafeInteger(value)) {
		return value;
	}
	if (typeof value === 'bigint' && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
		return Number(value);
	}
	throw new Error(`HXDB row is missing safe integer column ${key}.`);
}

function isCanonicalType(value: CanonicalSemanticType): boolean {
	return typeof value.typeId === 'string'
		&& typeof value.canonicalHash === 'string'
		&& typeof value.canonicalSerialization === 'string';
}

function validateCanonicalType(value: CanonicalSemanticType): CanonicalSemanticType {
	if (!isCanonicalType(value)) {
		throw new Error('HXDB type writes require a canonical semantic type.');
	}
	const reproduced = canonicalizeSemanticType(value, value.evidence);
	if (reproduced.typeId !== value.typeId
		|| reproduced.canonicalHash !== value.canonicalHash
		|| reproduced.canonicalSerialization !== value.canonicalSerialization) {
		throw new Error(`Canonical semantic type integrity failure for ${value.typeId}.`);
	}
	if (value.nominalIdentity?.trim().startsWith('{')) {
		try {
			const nominal = JSON.parse(value.nominalIdentity) as { targetIdentity?: unknown };
			if (nominal.targetIdentity !== undefined && typeof nominal.targetIdentity !== 'string') {
				throw new Error(`Nominal type ${value.typeId} has a malformed target identity.`);
			}
		} catch (error) {
			throw new Error(
				`Nominal type ${value.typeId} has a malformed identity: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}
	return value;
}

function assertRecordHash(record: { canonicalHash: string; canonicalSerialization: string }, label: string): void {
	if (hashText(record.canonicalSerialization) !== record.canonicalHash) {
		throw new Error(`${label} canonical hash does not match its serialization.`);
	}
}

function defaultLegacyEvidence(): SemanticEvidence {
	return {
		strength: 'definitive',
		source: 'analyst',
		producer: 'hxdb:migrate-v1',
		generation: 1,
		userDefined: true,
	};
}

function normalizeLegacyCallingConvention(
	value: string | null | undefined,
	fallback: CallingConventionId,
): CallingConventionId {
	const normalized = value?.trim().toLowerCase();
	const aliases: Readonly<Record<string, CallingConventionId>> = {
		'__cdecl': 'cdecl', cdecl: 'cdecl',
		'__stdcall': 'stdcall', stdcall: 'stdcall',
		'__fastcall': 'fastcall', fastcall: 'fastcall',
		'__thiscall': 'thiscall', thiscall: 'thiscall',
		'__vectorcall': 'vectorcall', vectorcall: 'vectorcall',
		usercall: 'usercall', win64: 'win64', msx64: 'win64',
		sysv64: 'sysv64', aapcs32: 'aapcs32', aapcs64: 'aapcs64',
	};
	return normalized ? aliases[normalized] ?? fallback : fallback;
}

function semanticFactKey(kind: SemanticFactKind, value: CanonicalSemanticType | CanonicalFunctionPrototype | CanonicalTypeBinding): string {
	switch (kind) {
		case 'type': return (value as CanonicalSemanticType).typeId;
		case 'prototype': return (value as CanonicalFunctionPrototype).functionIdentity;
		case 'type-binding': return (value as CanonicalTypeBinding).bindingId;
	}
}

export class SemanticStore {
	private transactionCounter = 0;
	readonly targetIdentity: string;
	readonly referenceGraph: TypedReferenceGraph;
	readonly wholeProgramPropagation: WholeProgramPropagationStore;
	private disposed = false;

	constructor(
		private readonly db: SemanticSqliteDatabase,
		targetIdentity: string,
	) {
		this.targetIdentity = requireIdentity(targetIdentity, 'HXDB target identity');
		this.initializeAndValidate();
		this.referenceGraph = new TypedReferenceGraph(db, this.targetIdentity);
		this.wholeProgramPropagation = new WholeProgramPropagationStore(db, this.targetIdentity);
	}

	static open(filename: string, targetIdentity: string, sqlite: SemanticSqliteFactory): SemanticStore {
		const db = sqlite.openDatabase(filename);
		try {
			return new SemanticStore(db, targetIdentity);
		} catch (error) {
			try { db.close?.(); } catch { /* preserve the constructor failure */ }
			throw error;
		}
	}

	static inspectOwnership(db: SemanticSqliteDatabase): SemanticStoreOwnership | undefined {
		try {
			const version = db.prepare(`SELECT value FROM hxdb_meta WHERE key = 'semantic_schema_version'`).get();
			const target = db.prepare(`SELECT value FROM hxdb_meta WHERE key = 'target_identity'`).get();
			if (!version && !target) {
				return undefined;
			}
			if (!version || !target) {
				throw new Error('HXDB ownership metadata is incomplete.');
			}
			const schemaVersion = Number(rowString(version, 'value'));
			if (!Number.isSafeInteger(schemaVersion)) {
				throw new Error('HXDB semantic schema version is not a safe integer.');
			}
			return { schemaVersion, targetIdentity: rowString(target, 'value') };
		} catch (error) {
			if (error instanceof Error && /no such table/i.test(error.message)) {
				return undefined;
			}
			throw error;
		}
	}

	getOwnership(): SemanticStoreOwnership {
		return { schemaVersion: HXDB_SEMANTIC_SCHEMA_VERSION, targetIdentity: this.targetIdentity };
	}

	isOwnedBy(targetIdentity: string): boolean {
		return this.targetIdentity === targetIdentity.trim();
	}

	assertOwnedBy(targetIdentity: string): void {
		const expected = requireIdentity(targetIdentity, 'Expected target identity');
		if (expected !== this.targetIdentity) {
			throw new SemanticTargetMismatchError(expected, this.targetIdentity);
		}
	}

	getReferenceGraph(): TypedReferenceGraph {
		this.ensureOpen();
		return this.referenceGraph;
	}

	getWholeProgramPropagationStore(): WholeProgramPropagationStore {
		this.ensureOpen();
		return this.wholeProgramPropagation;
	}

	putType(type: CanonicalSemanticType): ArbitrationResult<CanonicalSemanticType> {
		const transactionHash = canonicalHash({ operation: 'put-type', targetIdentity: this.targetIdentity, type });
		return this.inTransaction(() => this.putTypeInternal(type, transactionHash));
	}

	putPrototype(spec: FunctionPrototypeSpec | CanonicalFunctionPrototype): ArbitrationResult<CanonicalFunctionPrototype> {
		const transactionHash = canonicalHash({ operation: 'put-prototype', targetIdentity: this.targetIdentity, spec });
		return this.inTransaction(() => this.putPrototypeInternal(spec, transactionHash));
	}

	putTypeBinding(spec: TypeBindingSpec | CanonicalTypeBinding): ArbitrationResult<CanonicalTypeBinding> {
		const transactionHash = canonicalHash({ operation: 'put-type-binding', targetIdentity: this.targetIdentity, spec });
		return this.inTransaction(() => this.putBindingInternal(spec, transactionHash));
	}

	/**
	 * Remove an accepted analyst prototype without discarding semantic history.
	 * The strongest previously rejected non-user prototype is restored in the
	 * same transaction. If no such candidate exists, the accepted fact is
	 * removed so downstream recovery can infer it again.
	 */
	clearUserPrototypeOverride(functionIdentity: string): SemanticPrototypeOverrideClearResult {
		this.ensureOpen();
		const key = requireIdentity(functionIdentity, 'Function identity');
		const current = this.getPrototype(key);
		if (!current || current.evidence.userDefined !== true) {
			return {
				status: 'no-override',
				changed: false,
				functionIdentity: key,
				...(current ? { previousPrototype: current } : {}),
			};
		}

		const candidates = new Map<string, CanonicalFunctionPrototype>();
		const addHistoricalCandidate = (serialized: string): void => {
			let stored: CanonicalFunctionPrototype;
			try {
				stored = parseJson<CanonicalFunctionPrototype>(serialized, `Prototype history for ${key}`);
			} catch {
				return;
			}
			// Evidence sets may contain provenance from a competing value. Only a
			// record whose accepted evidence itself is non-user can restore its
			// associated semantic shape.
			if (stored.evidence?.userDefined === true) { return; }
			const nonUserEvidence = [stored.evidence, ...(stored.evidenceSet ?? [])]
				.filter((evidence, index, all) => evidence?.userDefined !== true
					&& all.findIndex(item => canonicalSerialize(item) === canonicalSerialize(evidence)) === index);
			if (nonUserEvidence.length === 0) { return; }
			const {
				evidence: _storedEvidence,
				evidenceSet: _storedEvidenceSet,
				...semanticShape
			} = stored;
			let candidate: CanonicalFunctionPrototype;
			try {
				candidate = canonicalizeFunctionPrototype({
					...semanticShape,
					evidence: nonUserEvidence[0],
					corroboratingEvidence: nonUserEvidence.slice(1),
				});
			} catch {
				return;
			}
			if (candidate.targetIdentity !== this.targetIdentity || candidate.functionIdentity !== key) { return; }
			candidates.set(`${candidate.canonicalHash}\u0000${canonicalSerialize(candidate.evidence)}`, candidate);
		};
		for (const historical of this.listHistory('prototype', key)) {
			addHistoricalCandidate(historical.recordJson);
		}
		for (const conflict of this.listConflicts()) {
			if (conflict.factKind !== 'prototype' || conflict.factKey !== key) { continue; }
			for (const serialized of [conflict.winnerJson, conflict.loserJson]) {
				addHistoricalCandidate(serialized);
			}
		}

		let restored: CanonicalFunctionPrototype | undefined;
		for (const candidate of [...candidates.values()]
			.sort((left, right) => compareAscii(left.canonicalHash, right.canonicalHash))) {
			restored = restored ? arbitrateSemanticValue(restored, candidate).accepted : candidate;
		}
		const transactionHash = canonicalHash({
			operation: 'clear-user-prototype-override',
			targetIdentity: this.targetIdentity,
			functionIdentity: key,
			previousHash: current.canonicalHash,
			restoredHash: restored?.canonicalHash ?? null,
		});
		const eventGeneration = Math.max(
			current.evidence.generation,
			restored?.evidence.generation ?? 0,
		) + 1;

		this.inTransaction(() => {
			if (restored) {
				this.persistPrototype(restored);
				this.persistFactHistory('prototype', key, restored, transactionHash, 'accepted');
				this.persistPrototypeRestorationGeneration(
					key, restored, eventGeneration, transactionHash,
				);
			} else {
				this.db.prepare(`DELETE FROM function_parameters WHERE target_identity = ? AND function_identity = ?`)
					.run(this.targetIdentity, key);
				this.db.prepare(`DELETE FROM function_prototypes WHERE target_identity = ? AND function_identity = ?`)
					.run(this.targetIdentity, key);
				this.replaceFactDependencies('prototype', key, []);
				this.persistPrototypeRemovalGeneration(key, current, eventGeneration, transactionHash);
			}
		});

		return {
			status: restored ? 'restored' : 'removed',
			changed: true,
			functionIdentity: key,
			previousPrototype: current,
			...(restored ? { restoredPrototype: restored } : {}),
			transactionHash,
		};
	}

	writeBatch(batch: SemanticWriteBatch): SemanticWriteBatchResult {
		const orderedTypes = [...(batch.types ?? [])]
			.sort((left, right) => compareCanonicalRecords(left, right));
		const orderedPrototypes = [...(batch.prototypes ?? [])]
			.sort((left, right) => compareCanonicalRecords(
				canonicalizeFunctionPrototype(left), canonicalizeFunctionPrototype(right)));
		const orderedBindings = [...(batch.typeBindings ?? [])]
			.sort((left, right) => compareCanonicalRecords(
				canonicalizeTypeBinding(left), canonicalizeTypeBinding(right)));
		const prototypeDescriptors = orderedPrototypes.map(item => canonicalSerialize(canonicalizeFunctionPrototype(item)));
		const bindingDescriptors = orderedBindings.map(item => canonicalSerialize(canonicalizeTypeBinding(item)));
		const typeDescriptors = orderedTypes.map(item => canonicalSerialize(item));
		const transactionHash = canonicalHash({
			operation: 'semantic-batch',
			targetIdentity: this.targetIdentity,
			types: typeDescriptors,
			prototypes: prototypeDescriptors,
			typeBindings: bindingDescriptors,
		});
		return this.inTransaction(() => ({
			transactionHash,
			typeResults: orderedTypes.map(type => this.putTypeInternal(type, transactionHash)),
			prototypeResults: orderedPrototypes.map(prototype => this.putPrototypeInternal(prototype, transactionHash)),
			bindingResults: orderedBindings.map(binding => this.putBindingInternal(binding, transactionHash)),
		}));
	}

	getType(typeId: string): CanonicalSemanticType | undefined {
		this.ensureOpen();
		const row = this.db.prepare(
			`SELECT record_json FROM types WHERE target_identity = ? AND type_id = ?`,
		).get(this.targetIdentity, requireIdentity(typeId, 'Type ID'));
		return row ? this.readTypeRow(row) : undefined;
	}

	listTypes(): CanonicalSemanticType[] {
		this.ensureOpen();
		return this.db.prepare(
			`SELECT record_json FROM types WHERE target_identity = ? ORDER BY type_id`,
		).all(this.targetIdentity).map(row => this.readTypeRow(row));
	}

	deleteType(typeId: string, evidenceGeneration: number): SemanticTypeDeleteResult {
		this.ensureOpen();
		const key = requireIdentity(typeId, 'Type ID');
		if (!Number.isSafeInteger(evidenceGeneration) || evidenceGeneration < 0) {
			throw new Error('Type deletion evidence generation must be a non-negative safe integer.');
		}
		const current = this.getType(key);
		if (!current) { return { status: 'not-found', changed: false, typeId: key, blockers: [] }; }
		const blockers = this.db.prepare(`
			SELECT fact_kind, fact_key, dependency_kind, dependency_key
			FROM fact_dependencies
			WHERE target_identity = ? AND dependency_kind = 'type' AND dependency_key = ?
				AND NOT (fact_kind = 'type' AND fact_key = ?)
			ORDER BY fact_kind, fact_key, dependency_kind, dependency_key
		`).all(this.targetIdentity, key, key).map(row => ({
			factKind: rowString(row, 'fact_kind') as SemanticFactKind,
			factKey: rowString(row, 'fact_key'),
			dependencyKind: rowString(row, 'dependency_kind'),
			dependencyKey: rowString(row, 'dependency_key'),
		}));
		if (blockers.length > 0) { return { status: 'blocked', changed: false, typeId: key, blockers }; }
		const transactionHash = canonicalHash({ operation: 'delete-type', targetIdentity: this.targetIdentity, typeId: key, evidenceGeneration });
		this.inTransaction(() => {
			this.persistFactHistory('type', key, current, transactionHash, 'accepted');
			this.db.prepare(`DELETE FROM fact_dependencies WHERE target_identity = ? AND fact_kind = 'type' AND fact_key = ?`).run(this.targetIdentity, key);
			this.db.prepare(`DELETE FROM types WHERE target_identity = ? AND type_id = ?`).run(this.targetIdentity, key);
			const absentHash = canonicalHash({ factKind: 'type', typeId: key, absent: true });
			const generationHash = canonicalHash({ transactionHash, kind: 'type', key, status: 'removed', acceptedHash: absentHash, incomingHash: current.canonicalHash, evidenceGeneration });
			this.db.prepare(`
				INSERT OR IGNORE INTO fact_generations (
					target_identity, generation_hash, transaction_hash, fact_kind, fact_key, status,
					accepted_hash, incoming_hash, evidence_generation
				) VALUES (?, ?, ?, 'type', ?, 'removed', ?, ?, ?)
			`).run(this.targetIdentity, generationHash, transactionHash, key, absentHash, current.canonicalHash, evidenceGeneration);
		});
		return { status: 'removed', changed: true, typeId: key, transactionHash, blockers: [] };
	}

	getPrototype(functionIdentity: string): CanonicalFunctionPrototype | undefined {
		this.ensureOpen();
		const row = this.db.prepare(
			`SELECT record_json FROM function_prototypes WHERE target_identity = ? AND function_identity = ?`,
		).get(this.targetIdentity, requireIdentity(functionIdentity, 'Function identity'));
		return row ? this.readPrototypeRow(row) : undefined;
	}

	getPrototypeAtAddress(functionAddress: string): CanonicalFunctionPrototype | undefined {
		this.ensureOpen();
		const row = this.db.prepare(
			`SELECT record_json FROM function_prototypes WHERE target_identity = ? AND function_address = ? ORDER BY function_identity LIMIT 1`,
		).get(this.targetIdentity, functionAddress.toLowerCase());
		return row ? this.readPrototypeRow(row) : undefined;
	}

	listPrototypes(): CanonicalFunctionPrototype[] {
		this.ensureOpen();
		return this.db.prepare(
			`SELECT record_json FROM function_prototypes WHERE target_identity = ? ORDER BY function_identity`,
		).all(this.targetIdentity).map(row => this.readPrototypeRow(row));
	}

	getTypeBinding(bindingId: string): CanonicalTypeBinding | undefined {
		this.ensureOpen();
		const row = this.db.prepare(
			`SELECT record_json FROM type_bindings WHERE target_identity = ? AND binding_id = ?`,
		).get(this.targetIdentity, requireIdentity(bindingId, 'Binding ID'));
		return row ? this.readBindingRow(row) : undefined;
	}

	findTypeBindings(functionIdentity?: string, scope?: TypeBindingScope): CanonicalTypeBinding[] {
		this.ensureOpen();
		let sql = `SELECT record_json FROM type_bindings WHERE target_identity = ?`;
		const params: unknown[] = [this.targetIdentity];
		if (functionIdentity !== undefined) {
			sql += ` AND function_identity = ?`;
			params.push(requireIdentity(functionIdentity, 'Function identity'));
		}
		if (scope !== undefined) {
			sql += ` AND scope = ?`;
			params.push(scope);
		}
		sql += ` ORDER BY binding_id`;
		return this.db.prepare(sql).all(...params).map(row => this.readBindingRow(row));
	}

	listConflicts(): SemanticStoredConflict[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT conflict_hash, fact_kind, fact_key, reason, winner_hash, loser_hash, winner_json, loser_json
			FROM fact_conflicts WHERE target_identity = ? ORDER BY conflict_hash
		`).all(this.targetIdentity).map(row => ({
			conflictHash: rowString(row, 'conflict_hash'),
			factKind: rowString(row, 'fact_kind') as SemanticFactKind,
			factKey: rowString(row, 'fact_key'),
			reason: rowString(row, 'reason'),
			winnerHash: rowString(row, 'winner_hash'),
			loserHash: rowString(row, 'loser_hash'),
			winnerJson: rowString(row, 'winner_json'),
			loserJson: rowString(row, 'loser_json'),
		}));
	}

	listGenerations(): SemanticStoredGeneration[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT generation_hash, transaction_hash, fact_kind, fact_key, status, accepted_hash, incoming_hash, evidence_generation
			FROM fact_generations WHERE target_identity = ? ORDER BY generation_hash
		`).all(this.targetIdentity).map(row => ({
			generationHash: rowString(row, 'generation_hash'),
			transactionHash: rowString(row, 'transaction_hash'),
			factKind: rowString(row, 'fact_kind') as SemanticFactKind,
			factKey: rowString(row, 'fact_key'),
			status: rowString(row, 'status'),
			acceptedHash: rowString(row, 'accepted_hash'),
			incomingHash: rowString(row, 'incoming_hash'),
			evidenceGeneration: rowNumber(row, 'evidence_generation'),
		}));
	}

	listHistory(kind?: SemanticFactKind, key?: string): SemanticStoredFactHistory[] {
		this.ensureOpen();
		let sql = `
			SELECT history_hash, transaction_hash, fact_kind, fact_key, role, canonical_hash, record_json, evidence_generation
			FROM fact_history WHERE target_identity = ?
		`;
		const params: unknown[] = [this.targetIdentity];
		if (kind !== undefined) {
			sql += ` AND fact_kind = ?`;
			params.push(kind);
		}
		if (key !== undefined) {
			sql += ` AND fact_key = ?`;
			params.push(requireIdentity(key, 'Fact key'));
		}
		sql += ` ORDER BY evidence_generation, history_hash`;
		return this.db.prepare(sql).all(...params).map(row => ({
			historyHash: rowString(row, 'history_hash'),
			transactionHash: rowString(row, 'transaction_hash'),
			factKind: rowString(row, 'fact_kind') as SemanticFactKind,
			factKey: rowString(row, 'fact_key'),
			role: rowString(row, 'role') as SemanticStoredFactHistory['role'],
			canonicalHash: rowString(row, 'canonical_hash'),
			recordJson: rowString(row, 'record_json'),
			evidenceGeneration: rowNumber(row, 'evidence_generation'),
		}));
	}

	listDependencies(kind?: SemanticFactKind, key?: string): SemanticFactDependency[] {
		this.ensureOpen();
		let sql = `
			SELECT fact_kind, fact_key, dependency_kind, dependency_key
			FROM fact_dependencies WHERE target_identity = ?
		`;
		const params: unknown[] = [this.targetIdentity];
		if (kind !== undefined) {
			sql += ` AND fact_kind = ?`;
			params.push(kind);
		}
		if (key !== undefined) {
			sql += ` AND fact_key = ?`;
			params.push(requireIdentity(key, 'Fact key'));
		}
		sql += ` ORDER BY fact_kind, fact_key, dependency_kind, dependency_key`;
		return this.db.prepare(sql).all(...params).map(row => ({
			factKind: rowString(row, 'fact_kind') as SemanticFactKind,
			factKey: rowString(row, 'fact_key'),
			dependencyKind: rowString(row, 'dependency_kind'),
			dependencyKey: rowString(row, 'dependency_key'),
		}));
	}

	listLegacyMigrations(): LegacyMigrationRecord[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT migration_id, source_kind, source_key, raw_json, status, type_id, fact_kind, fact_key
			FROM legacy_migrations WHERE target_identity = ? ORDER BY migration_id
		`).all(this.targetIdentity).map(row => {
			const value = row as Record<string, unknown>;
			return {
				migrationId: rowString(row, 'migration_id'),
				sourceKind: rowString(row, 'source_kind'),
				sourceKey: rowString(row, 'source_key'),
				rawJson: rowString(row, 'raw_json'),
				status: rowString(row, 'status') as LegacyMigrationRecord['status'],
				...(typeof value.type_id === 'string' ? { typeId: value.type_id } : {}),
				...(typeof value.fact_kind === 'string' ? { factKind: value.fact_kind as SemanticFactKind } : {}),
				...(typeof value.fact_key === 'string' ? { factKey: value.fact_key } : {}),
			};
		});
	}

	queryHash(kind: SemanticFactKind, key: string): string | undefined {
		let value: CanonicalSemanticType | CanonicalFunctionPrototype | CanonicalTypeBinding | undefined;
		switch (kind) {
			case 'type': value = this.getType(key); break;
			case 'prototype': value = this.getPrototype(key); break;
			case 'type-binding': value = this.getTypeBinding(key); break;
		}
		return value ? canonicalHash(value) : undefined;
	}

	exportSnapshot(): SemanticSnapshot {
		return {
			schemaVersion: HXDB_SEMANTIC_SCHEMA_VERSION,
			targetIdentity: this.targetIdentity,
			types: this.listTypes(),
			prototypes: this.listPrototypes(),
			typeBindings: this.findTypeBindings(),
			dependencies: this.listDependencies(),
			conflicts: this.listConflicts(),
			generations: this.listGenerations(),
			history: this.listHistory(),
			legacyMigrations: this.listLegacyMigrations(),
			referenceGraph: this.referenceGraph.exportSnapshot(),
			wholeProgramPropagation: this.wholeProgramPropagation.exportSnapshot(),
		};
	}

	exportCanonical(): string {
		return canonicalSerialize(this.exportSnapshot());
	}

	exportHash(): string {
		return hashText(this.exportCanonical());
	}

	migrateLegacyV1(facts: LegacyV1SemanticFacts, options: LegacyV1MigrationOptions = {}): LegacyV1MigrationResult {
		const evidence = options.evidence ?? defaultLegacyEvidence();
		const catalog = new SemanticTypeCatalog(this.targetIdentity, options.nominalScope ?? 'legacy-v1');
		const prototypes: CanonicalFunctionPrototype[] = [];
		const bindings: CanonicalTypeBinding[] = [];
		const migrationRecords: LegacyMigrationRecord[] = [];
		const resolvedTypes = new Map<string, CanonicalSemanticType>();

		const record = (
			sourceKind: string,
			sourceKey: string,
			raw: unknown,
			link?: { typeId?: string; factKind?: SemanticFactKind; factKey?: string },
		): void => {
			const rawJson = canonicalSerialize(raw);
			const migrationId = `migration:sha256:${canonicalHash({ sourceKind, sourceKey, rawJson })}`;
			migrationRecords.push({
				migrationId, sourceKind, sourceKey, rawJson,
				status: link ? 'migrated' : 'preserved-only',
				...link,
			});
		};

		const resolveType = (declaration: string | null | undefined, sourceKey: string): CanonicalSemanticType => {
			const exact = declaration ?? '';
			const cacheKey = `${sourceKey}\u0000${exact}`;
			const cached = resolvedTypes.get(cacheKey);
			if (cached) { return cached; }
			let type: CanonicalSemanticType;
			if (!exact.trim()) {
				type = catalog.intern({ kind: 'unknown', name: `legacy-empty:${hashText(sourceKey).slice(0, 12)}` }, evidence);
			} else {
				type = catalog.parseLegacyCType(exact, evidence, {
					...options,
					targetIdentity: this.targetIdentity,
					nominalScope: options.nominalScope ?? 'legacy-v1',
				}).type;
			}
			resolvedTypes.set(cacheKey, type);
			return type;
		};

		for (const legacyFunction of facts.functions ?? []) {
			const functionIdentity = requireIdentity(legacyFunction.address, 'Legacy function address').toLowerCase();
			if (legacyFunction.return_type !== undefined && legacyFunction.return_type !== null) {
				const returnType = resolveType(legacyFunction.return_type, `function:${functionIdentity}:return`);
				const prototype = canonicalizeFunctionPrototype({
					targetIdentity: this.targetIdentity,
					functionIdentity,
					functionAddress: functionIdentity,
					returnTypeId: returnType.typeId,
					callingConventionId: normalizeLegacyCallingConvention(
						legacyFunction.calling_convention,
						options.defaultCallingConventionId ?? 'win64',
					),
					parameters: legacyFunction.parameters ?? [],
					evidence,
				});
				prototypes.push(prototype);
				record('function', functionIdentity, legacyFunction, {
					typeId: returnType.typeId, factKind: 'prototype', factKey: functionIdentity,
				});
			} else {
				record('function', functionIdentity, legacyFunction);
			}
		}

		for (const legacyVariable of facts.variables ?? []) {
			const functionIdentity = requireIdentity(legacyVariable.func_address, 'Legacy variable function address').toLowerCase();
			const valueIdentity = requireIdentity(legacyVariable.original_name, 'Legacy variable identity');
			if (legacyVariable.new_type !== undefined && legacyVariable.new_type !== null) {
				const type = resolveType(legacyVariable.new_type, `variable:${functionIdentity}:${valueIdentity}`);
				const binding = canonicalizeTypeBinding({
					targetIdentity: this.targetIdentity,
					scope: legacyVariable.scope ?? 'local',
					valueIdentity,
					functionIdentity,
					typeId: type.typeId,
					evidence,
				});
				bindings.push(binding);
				record('variable', `${functionIdentity}:${valueIdentity}`, legacyVariable, {
					typeId: type.typeId, factKind: 'type-binding', factKey: binding.bindingId,
				});
			} else {
				record('variable', `${functionIdentity}:${valueIdentity}`, legacyVariable);
			}
		}

		const groupedFields = new Map<string, LegacyV1FieldFact[]>();
		for (const field of facts.fields ?? []) {
			const structName = requireIdentity(field.struct_type, 'Legacy struct type');
			if (!Number.isSafeInteger(field.offset) || field.offset < 0 || field.offset > Math.floor(Number.MAX_SAFE_INTEGER / 8)) {
				throw new Error(`Legacy field offset for ${structName} must be a non-negative safe byte offset.`);
			}
			const group = groupedFields.get(structName) ?? [];
			group.push(field);
			groupedFields.set(structName, group);
		}
		for (const [structName, fields] of [...groupedFields].sort(([left], [right]) => compareAscii(left, right))) {
			const members: SemanticTypeMemberSpec[] = fields
				.map((field, index) => ({
					name: field.name?.trim() || `field_${field.offset.toString(16)}`,
					typeId: resolveType(field.type, `field:${structName}:${field.offset}:${index}`).typeId,
					bitOffset: field.offset * 8,
					evidence,
				}))
				.sort((left, right) => left.bitOffset - right.bitOffset || compareAscii(left.name, right.name));
			const owner = catalog.defineNominal({
				kind: 'struct', name: structName, members,
			}, evidence, `legacy-v1:${structName}`);
			for (const [index, field] of fields.entries()) {
				record('field', `${structName}:${field.offset}:${index}`, field, {
					typeId: owner.typeId, factKind: 'type', factKey: owner.typeId,
				});
			}
		}

		for (const extra of facts.additionalFacts ?? []) {
			record(requireIdentity(extra.kind, 'Legacy fact kind'), requireIdentity(extra.key, 'Legacy fact key'), extra.value);
		}

		const types = catalog.list();
		const orderedMigrationRecords = [...new Map(migrationRecords.map(item => [item.migrationId, item])).values()]
			.sort((left, right) => compareAscii(left.migrationId, right.migrationId));
		const migrationHash = canonicalHash({
			targetIdentity: this.targetIdentity,
			types: types.map(type => type.canonicalHash).sort(),
			prototypes: prototypes.map(item => item.canonicalHash).sort(),
			bindings: bindings.map(item => item.canonicalHash).sort(),
			migrationRecords: orderedMigrationRecords,
		});

		this.inTransaction(() => {
			for (const type of types) { this.putTypeInternal(type, migrationHash); }
			for (const prototype of prototypes) { this.putPrototypeInternal(prototype, migrationHash); }
			for (const binding of bindings) { this.putBindingInternal(binding, migrationHash); }
			for (const item of orderedMigrationRecords) { this.persistLegacyMigration(item); }
		});

		return {
			migrationHash,
			typeCount: types.length,
			prototypeCount: prototypes.length,
			bindingCount: bindings.length,
			preservedRecordCount: orderedMigrationRecords.length,
		};
	}

	dispose(): void {
		if (this.disposed) { return; }
		this.disposed = true;
		this.wholeProgramPropagation.dispose();
		this.referenceGraph.dispose();
		this.db.close?.();
	}

	private initializeAndValidate(): void {
		this.db.exec('PRAGMA foreign_keys = ON;');
		this.inTransaction(() => {
			this.db.exec(SCHEMA_SQL);
			for (const [table, expectedColumns] of Object.entries(REQUIRED_COLUMNS)) {
				const rows = this.db.prepare(`PRAGMA table_info(${table})`).all();
				const actual = new Set(rows.map(row => rowString(row, 'name')));
				const missing = expectedColumns.filter(column => !actual.has(column));
				if (missing.length > 0) {
					throw new Error(`HXDB table ${table} is incompatible; missing columns: ${missing.join(', ')}.`);
				}
			}
			this.db.exec(INDEX_SQL);

			const ownership = SemanticStore.inspectOwnership(this.db);
			if (ownership) {
				if (ownership.schemaVersion !== HXDB_SEMANTIC_SCHEMA_VERSION) {
					throw new Error(
						`HXDB semantic schema ${ownership.schemaVersion} is not supported by schema ${HXDB_SEMANTIC_SCHEMA_VERSION}.`,
					);
				}
				if (ownership.targetIdentity !== this.targetIdentity) {
					throw new SemanticTargetMismatchError(this.targetIdentity, ownership.targetIdentity);
				}
			} else {
				const putMeta = this.db.prepare(`INSERT INTO hxdb_meta (key, value) VALUES (?, ?)`);
				putMeta.run('semantic_schema_version', String(HXDB_SEMANTIC_SCHEMA_VERSION));
				putMeta.run('target_identity', this.targetIdentity);
			}
		});
	}

	private putTypeInternal(
		input: CanonicalSemanticType,
		transactionHash: string,
	): ArbitrationResult<CanonicalSemanticType> {
		const incoming = validateCanonicalType(input);
		if (incoming.nominalIdentity?.trim().startsWith('{')) {
			const nominal = JSON.parse(incoming.nominalIdentity) as { targetIdentity?: unknown };
			if (typeof nominal.targetIdentity === 'string') {
				this.assertOwnedBy(nominal.targetIdentity);
			}
		}
		const current = this.getType(incoming.typeId);
		let result = arbitrateSemanticValue(current, incoming);
		if (current && current.canonicalHash === incoming.canonicalHash) {
			const merger = new SemanticTypeCatalog();
			merger.intern(current, current.evidence);
			const accepted = merger.intern(incoming, incoming.evidence);
			result = { ...result, accepted };
		}
		const changed = current === undefined || canonicalSerialize(current) !== canonicalSerialize(result.accepted);
		if (result.conflict) {
			this.persistConflict('type', incoming.typeId, result.conflict);
		}
		if (!result.status.startsWith('rejected') && changed) {
			this.persistType(result.accepted);
		}
		if (changed || result.conflict) {
			this.persistGeneration('type', incoming.typeId, result, incoming.canonicalHash, incoming.evidence.generation, transactionHash);
		}
		this.persistFactHistory('type', incoming.typeId, incoming, transactionHash, 'incoming');
		return result;
	}

	private putPrototypeInternal(
		spec: FunctionPrototypeSpec | CanonicalFunctionPrototype,
		transactionHash: string,
	): ArbitrationResult<CanonicalFunctionPrototype> {
		const incoming = canonicalizeFunctionPrototype(spec);
		this.assertOwnedBy(incoming.targetIdentity);
		const current = this.getPrototype(incoming.functionIdentity);
		const result = arbitrateSemanticValue(current, incoming);
		const changed = current === undefined || canonicalSerialize(current) !== canonicalSerialize(result.accepted);
		if (result.conflict) {
			this.persistConflict('prototype', incoming.functionIdentity, result.conflict);
		}
		if (!result.status.startsWith('rejected') && changed) {
			this.persistPrototype(result.accepted);
		}
		if (changed || result.conflict) {
			this.persistGeneration('prototype', incoming.functionIdentity, result, incoming.canonicalHash, incoming.evidence.generation, transactionHash);
		}
		this.persistFactHistory('prototype', incoming.functionIdentity, incoming, transactionHash, 'incoming');
		return result;
	}

	private putBindingInternal(
		spec: TypeBindingSpec | CanonicalTypeBinding,
		transactionHash: string,
	): ArbitrationResult<CanonicalTypeBinding> {
		const incoming = canonicalizeTypeBinding(spec);
		this.assertOwnedBy(incoming.targetIdentity);
		const current = this.getTypeBinding(incoming.bindingId);
		const result = arbitrateSemanticValue(current, incoming);
		const changed = current === undefined || canonicalSerialize(current) !== canonicalSerialize(result.accepted);
		if (result.conflict) {
			this.persistConflict('type-binding', incoming.bindingId, result.conflict);
		}
		if (!result.status.startsWith('rejected') && changed) {
			this.persistBinding(result.accepted);
		}
		if (changed || result.conflict) {
			this.persistGeneration('type-binding', incoming.bindingId, result, incoming.canonicalHash, incoming.evidence.generation, transactionHash);
		}
		this.persistFactHistory('type-binding', incoming.bindingId, incoming, transactionHash, 'incoming');
		return result;
	}

	private persistType(type: CanonicalSemanticType): void {
		this.db.prepare(`
			INSERT INTO types (
				target_identity, type_id, kind, name, nominal_identity, incomplete, size_bits, align_bits,
				signed, element_count, target_type_id, is_const, is_volatile, is_restrict, opaque_declaration,
				canonical_serialization, canonical_hash, record_json, evidence_json, evidence_set_json,
				evidence_source, evidence_strength, evidence_producer, confidence, calibration_json,
				evidence_generation, user_defined
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(target_identity, type_id) DO UPDATE SET
				kind=excluded.kind, name=excluded.name, nominal_identity=excluded.nominal_identity,
				incomplete=excluded.incomplete, size_bits=excluded.size_bits, align_bits=excluded.align_bits,
				signed=excluded.signed, element_count=excluded.element_count, target_type_id=excluded.target_type_id,
				is_const=excluded.is_const, is_volatile=excluded.is_volatile, is_restrict=excluded.is_restrict,
				opaque_declaration=excluded.opaque_declaration, canonical_serialization=excluded.canonical_serialization,
				canonical_hash=excluded.canonical_hash, record_json=excluded.record_json,
				evidence_json=excluded.evidence_json, evidence_set_json=excluded.evidence_set_json,
				evidence_source=excluded.evidence_source, evidence_strength=excluded.evidence_strength,
				evidence_producer=excluded.evidence_producer, confidence=excluded.confidence,
				calibration_json=excluded.calibration_json,
				evidence_generation=excluded.evidence_generation, user_defined=excluded.user_defined
		`).run(
			this.targetIdentity, type.typeId, type.kind, type.name ?? null, type.nominalIdentity ?? null,
			boolInt(type.incomplete), type.sizeBits ?? null, type.alignBits ?? null, nullableBoolInt(type.signed),
			type.count ?? null, type.targetTypeId ?? null, boolInt(type.const), boolInt(type.volatile), boolInt(type.restrict),
			type.opaqueDeclaration ?? null, type.canonicalSerialization, type.canonicalHash, canonicalSerialize(type),
			canonicalSerialize(type.evidence), canonicalSerialize(type.evidenceSet),
			...evidenceColumns(type.evidence), type.evidence.generation, boolInt(type.evidence.userDefined),
		);

		for (const table of ['type_members', 'enum_members', 'type_aliases', 'type_dependencies']) {
			this.db.prepare(`DELETE FROM ${table} WHERE target_identity = ? AND owner_type_id = ?`)
				.run(this.targetIdentity, type.typeId);
		}
		const insertMember = this.db.prepare(`
			INSERT INTO type_members (
				target_identity, owner_type_id, member_index, name, type_id, bit_offset, bit_size,
				array_stride_bits, anonymous, nested, bitfield, evidence_json, evidence_set_json
				, evidence_source, evidence_strength, evidence_producer, evidence_generation, confidence, calibration_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
		for (const [index, member] of (type.members ?? []).entries()) {
			const memberEvidence = member.evidence ?? type.evidence;
			insertMember.run(
				this.targetIdentity, type.typeId, index, member.name, member.typeId, member.bitOffset,
				member.bitSize ?? null, member.arrayStrideBits ?? null, boolInt(member.anonymous), boolInt(member.nested),
				boolInt(member.bitfield), canonicalSerialize(memberEvidence),
				canonicalSerialize(member.evidenceSet ?? [memberEvidence]), ...childEvidenceColumns(memberEvidence),
			);
		}
		const insertEnum = this.db.prepare(`
			INSERT INTO enum_members (
				target_identity, owner_type_id, member_index, name, value_text, evidence_json, evidence_set_json,
				evidence_source, evidence_strength, evidence_producer, evidence_generation, confidence, calibration_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
		for (const [index, member] of (type.enumMembers ?? []).entries()) {
			const memberEvidence = member.evidence ?? type.evidence;
			insertEnum.run(
				this.targetIdentity, type.typeId, index, member.name, String(member.value),
				canonicalSerialize(memberEvidence),
				canonicalSerialize(member.evidenceSet ?? [memberEvidence]), ...childEvidenceColumns(memberEvidence),
			);
		}
		const insertAlias = this.db.prepare(`
			INSERT INTO type_aliases (
				target_identity, owner_type_id, alias_index, name, target_type_id, evidence_json, evidence_set_json,
				evidence_source, evidence_strength, evidence_producer, evidence_generation, confidence, calibration_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
		for (const [index, alias] of (type.aliases ?? []).entries()) {
			const aliasEvidence = alias.evidence ?? type.evidence;
			insertAlias.run(
				this.targetIdentity, type.typeId, index, alias.name, alias.targetTypeId,
				canonicalSerialize(aliasEvidence),
				canonicalSerialize(alias.evidenceSet ?? [aliasEvidence]), ...childEvidenceColumns(aliasEvidence),
			);
		}
		const insertDependency = this.db.prepare(`
			INSERT INTO type_dependencies (target_identity, owner_type_id, dependency_type_id) VALUES (?, ?, ?)
		`);
		for (const dependency of type.dependencies) {
			insertDependency.run(this.targetIdentity, type.typeId, dependency);
		}
		this.replaceFactDependencies('type', type.typeId, type.dependencies.map(dependency => ['type', dependency]));
	}

	private persistPrototype(prototype: CanonicalFunctionPrototype): void {
		this.db.prepare(`
			INSERT INTO function_prototypes (
				target_identity, function_identity, function_address, prototype_id, return_type_id,
				calling_convention_id, variadic, noreturn, method, static_method, hidden_return_json,
				hidden_storage_json, canonical_serialization, canonical_hash, record_json, evidence_json,
				evidence_set_json, evidence_source, evidence_strength, evidence_producer, confidence,
				calibration_json, evidence_generation, user_defined
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(target_identity, function_identity) DO UPDATE SET
				function_address=excluded.function_address, prototype_id=excluded.prototype_id,
				return_type_id=excluded.return_type_id, calling_convention_id=excluded.calling_convention_id,
				variadic=excluded.variadic, noreturn=excluded.noreturn, method=excluded.method,
				static_method=excluded.static_method, hidden_return_json=excluded.hidden_return_json,
				hidden_storage_json=excluded.hidden_storage_json,
				canonical_serialization=excluded.canonical_serialization, canonical_hash=excluded.canonical_hash,
				record_json=excluded.record_json, evidence_json=excluded.evidence_json,
				evidence_set_json=excluded.evidence_set_json,
				evidence_source=excluded.evidence_source, evidence_strength=excluded.evidence_strength,
				evidence_producer=excluded.evidence_producer, confidence=excluded.confidence,
				calibration_json=excluded.calibration_json, evidence_generation=excluded.evidence_generation,
				user_defined=excluded.user_defined
		`).run(
			this.targetIdentity, prototype.functionIdentity, prototype.functionAddress ?? null, prototype.prototypeId,
			prototype.returnTypeId, prototype.callingConventionId, boolInt(prototype.variadic), boolInt(prototype.noreturn),
			boolInt(prototype.method), boolInt(prototype.staticMethod),
			prototype.hiddenReturn ? canonicalSerialize(prototype.hiddenReturn) : null,
			prototype.hiddenStorage ? canonicalSerialize(prototype.hiddenStorage) : null,
			prototype.canonicalSerialization, prototype.canonicalHash, canonicalSerialize(prototype),
			canonicalSerialize(prototype.evidence), canonicalSerialize(prototype.evidenceSet),
			...evidenceColumns(prototype.evidence), prototype.evidence.generation, boolInt(prototype.evidence.userDefined),
		);
		this.db.prepare(`DELETE FROM function_parameters WHERE target_identity = ? AND function_identity = ?`)
			.run(this.targetIdentity, prototype.functionIdentity);
		const insertParameter = this.db.prepare(`
			INSERT INTO function_parameters (
				target_identity, function_identity, ordinal, parameter_id, stable_identity, stable_identity_aliases_json, name, type_id,
				location_kind, location_json, direction, optional, nullable, buffer_json, ownership,
				lifetime, hidden_this, hidden_sret, compiler_generated
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`);
		for (const parameter of prototype.parameters) {
			insertParameter.run(
				this.targetIdentity, prototype.functionIdentity, parameter.ordinal, parameter.parameterId,
				parameter.stableIdentity ?? null, canonicalSerialize(parameter.stableIdentityAliases ?? []), parameter.name, parameter.typeId, parameter.location.kind,
				canonicalSerialize(parameter.location), parameter.direction, boolInt(parameter.optional), boolInt(parameter.nullable),
				parameter.buffer ? canonicalSerialize(parameter.buffer) : null, parameter.ownership, parameter.lifetime,
				boolInt(parameter.hiddenThis), boolInt(parameter.hiddenSret), boolInt(parameter.compilerGenerated),
			);
		}
		const dependencies: [string, string][] = [
			['type', prototype.returnTypeId],
			...prototype.parameters.map(parameter => ['type', parameter.typeId] as [string, string]),
		];
		this.replaceFactDependencies('prototype', prototype.functionIdentity, dependencies);
	}

	private persistBinding(binding: CanonicalTypeBinding): void {
		this.db.prepare(`
			INSERT INTO type_bindings (
				target_identity, binding_id, scope, value_identity, function_identity, type_id,
				canonical_serialization, canonical_hash, record_json, evidence_json, evidence_set_json,
				evidence_source, evidence_strength, evidence_producer, confidence, calibration_json,
				evidence_generation, user_defined
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(target_identity, binding_id) DO UPDATE SET
				scope=excluded.scope, value_identity=excluded.value_identity, function_identity=excluded.function_identity,
				type_id=excluded.type_id, canonical_serialization=excluded.canonical_serialization,
				canonical_hash=excluded.canonical_hash, record_json=excluded.record_json,
				evidence_json=excluded.evidence_json, evidence_set_json=excluded.evidence_set_json,
				evidence_source=excluded.evidence_source, evidence_strength=excluded.evidence_strength,
				evidence_producer=excluded.evidence_producer, confidence=excluded.confidence,
				calibration_json=excluded.calibration_json,
				evidence_generation=excluded.evidence_generation, user_defined=excluded.user_defined
		`).run(
			this.targetIdentity, binding.bindingId, binding.scope, binding.valueIdentity, binding.functionIdentity ?? null,
			binding.typeId, binding.canonicalSerialization, binding.canonicalHash, canonicalSerialize(binding),
			canonicalSerialize(binding.evidence), canonicalSerialize(binding.evidenceSet),
			...evidenceColumns(binding.evidence), binding.evidence.generation, boolInt(binding.evidence.userDefined),
		);
		this.replaceFactDependencies('type-binding', binding.bindingId, [
			['type', binding.typeId],
			...binding.invalidationDependencies.map(dependency => ['invalidation', dependency] as [string, string]),
		]);
	}

	private replaceFactDependencies(kind: SemanticFactKind, key: string, dependencies: readonly (readonly [string, string])[]): void {
		this.db.prepare(`DELETE FROM fact_dependencies WHERE target_identity = ? AND fact_kind = ? AND fact_key = ?`)
			.run(this.targetIdentity, kind, key);
		const insert = this.db.prepare(`
			INSERT INTO fact_dependencies (target_identity, fact_kind, fact_key, dependency_kind, dependency_key)
			VALUES (?, ?, ?, ?, ?)
		`);
		const unique = new Map(dependencies.map(([dependencyKind, dependencyKey]) => [
			canonicalSerialize([dependencyKind, dependencyKey]), [dependencyKind, dependencyKey] as const,
		]));
		for (const [dependencyKind, dependencyKey] of [...unique.values()]
			.sort(([leftKind, leftKey], [rightKind, rightKey]) => compareAscii(leftKind, rightKind) || compareAscii(leftKey, rightKey))) {
			insert.run(this.targetIdentity, kind, key, dependencyKind, dependencyKey);
		}
	}

	private persistConflict<T extends { canonicalHash: string }>(
		kind: SemanticFactKind,
		key: string,
		conflict: { winner: T; loser: T; reason: string },
	): void {
		const winnerJson = canonicalSerialize(conflict.winner);
		const loserJson = canonicalSerialize(conflict.loser);
		const conflictHash = canonicalHash({ kind, key, reason: conflict.reason, winnerJson, loserJson });
		this.db.prepare(`
			INSERT OR IGNORE INTO fact_conflicts (
				target_identity, conflict_hash, fact_kind, fact_key, reason, winner_hash, loser_hash, winner_json, loser_json
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.targetIdentity, conflictHash, kind, key, conflict.reason,
			conflict.winner.canonicalHash, conflict.loser.canonicalHash, winnerJson, loserJson,
		);
	}

	private persistGeneration<T extends { canonicalHash: string; evidence: SemanticEvidence }>(
		kind: SemanticFactKind,
		key: string,
		result: ArbitrationResult<T>,
		incomingHash: string,
		evidenceGeneration: number,
		transactionHash: string,
	): void {
		const generationHash = canonicalHash({
			transactionHash, kind, key, status: result.status,
			acceptedHash: result.accepted.canonicalHash, incomingHash, evidenceGeneration,
		});
		this.db.prepare(`
			INSERT OR IGNORE INTO fact_generations (
				target_identity, generation_hash, transaction_hash, fact_kind, fact_key, status,
				accepted_hash, incoming_hash, evidence_generation
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.targetIdentity, generationHash, transactionHash, kind, key, result.status,
			result.accepted.canonicalHash, incomingHash, evidenceGeneration,
		);
	}

	private persistFactHistory<T extends { canonicalHash: string; evidence: SemanticEvidence }>(
		factKind: SemanticFactKind,
		factKey: string,
		record: T,
		transactionHash: string,
		role: SemanticStoredFactHistory['role'],
	): void {
		const recordJson = canonicalSerialize(record);
		const historyHash = canonicalHash({
			transactionHash,
			factKind,
			factKey,
			role,
			canonicalHash: record.canonicalHash,
			recordJson,
			evidenceGeneration: record.evidence.generation,
		});
		this.db.prepare(`
			INSERT OR IGNORE INTO fact_history (
				target_identity, history_hash, transaction_hash, fact_kind, fact_key, role,
				canonical_hash, record_json, evidence_generation
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.targetIdentity, historyHash, transactionHash, factKind, factKey, role,
			record.canonicalHash, recordJson, record.evidence.generation,
		);
	}

	private persistPrototypeRemovalGeneration(
		functionIdentity: string,
		previous: CanonicalFunctionPrototype,
		evidenceGeneration: number,
		transactionHash: string,
	): void {
		const absentHash = canonicalHash({ factKind: 'prototype', functionIdentity, absent: true });
		const generationHash = canonicalHash({
			transactionHash,
			kind: 'prototype',
			key: functionIdentity,
			status: 'removed-user-override',
			acceptedHash: absentHash,
			incomingHash: previous.canonicalHash,
			evidenceGeneration,
		});
		this.db.prepare(`
			INSERT OR IGNORE INTO fact_generations (
				target_identity, generation_hash, transaction_hash, fact_kind, fact_key, status,
				accepted_hash, incoming_hash, evidence_generation
			) VALUES (?, ?, ?, 'prototype', ?, 'removed-user-override', ?, ?, ?)
		`).run(
			this.targetIdentity, generationHash, transactionHash, functionIdentity,
			absentHash, previous.canonicalHash, evidenceGeneration,
		);
	}

	private persistPrototypeRestorationGeneration(
		functionIdentity: string,
		restored: CanonicalFunctionPrototype,
		evidenceGeneration: number,
		transactionHash: string,
	): void {
		const generationHash = canonicalHash({
			transactionHash,
			kind: 'prototype',
			key: functionIdentity,
			status: 'restored-after-override',
			acceptedHash: restored.canonicalHash,
			incomingHash: restored.canonicalHash,
			evidenceGeneration,
		});
		this.db.prepare(`
			INSERT OR IGNORE INTO fact_generations (
				target_identity, generation_hash, transaction_hash, fact_kind, fact_key, status,
				accepted_hash, incoming_hash, evidence_generation
			) VALUES (?, ?, ?, 'prototype', ?, 'restored-after-override', ?, ?, ?)
		`).run(
			this.targetIdentity, generationHash, transactionHash, functionIdentity,
			restored.canonicalHash, restored.canonicalHash, evidenceGeneration,
		);
	}

	private persistLegacyMigration(item: LegacyMigrationRecord): void {
		this.db.prepare(`
			INSERT OR REPLACE INTO legacy_migrations (
				target_identity, migration_id, source_kind, source_key, raw_json, status, type_id, fact_kind, fact_key
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.targetIdentity, item.migrationId, item.sourceKind, item.sourceKey, item.rawJson, item.status,
			item.typeId ?? null, item.factKind ?? null, item.factKey ?? null,
		);
	}

	private readTypeRow(row: unknown): CanonicalSemanticType {
		const stored = parseJson<CanonicalSemanticType>(rowString(row, 'record_json'), 'Semantic type');
		assertRecordHash(stored, `Semantic type ${stored.typeId}`);
		validateCanonicalType(stored);
		const catalog = new SemanticTypeCatalog();
		const type = catalog.intern(stored, stored.evidence);
		if (canonicalSerialize(type) !== canonicalSerialize(stored)) {
			throw new Error(`Semantic type ${stored.typeId} did not reproduce from its stored record.`);
		}
		return type;
	}

	private readPrototypeRow(row: unknown): CanonicalFunctionPrototype {
		const stored = parseJson<CanonicalFunctionPrototype>(rowString(row, 'record_json'), 'Function prototype');
		assertRecordHash(stored, `Function prototype ${stored.functionIdentity}`);
		const prototype = canonicalizeFunctionPrototype(stored);
		if (canonicalSerialize(prototype) !== canonicalSerialize(stored)) {
			throw new Error(`Function prototype ${stored.functionIdentity} did not reproduce from its stored record.`);
		}
		this.assertOwnedBy(prototype.targetIdentity);
		return prototype;
	}

	private readBindingRow(row: unknown): CanonicalTypeBinding {
		const stored = parseJson<CanonicalTypeBinding>(rowString(row, 'record_json'), 'Type binding');
		assertRecordHash(stored, `Type binding ${stored.bindingId}`);
		const binding = canonicalizeTypeBinding(stored);
		if (canonicalSerialize(binding) !== canonicalSerialize(stored)) {
			throw new Error(`Type binding ${stored.bindingId} did not reproduce from its stored record.`);
		}
		this.assertOwnedBy(binding.targetIdentity);
		return binding;
	}

	private inTransaction<T>(action: () => T): T {
		this.ensureOpen();
		const savepoint = `hxdb_semantic_${++this.transactionCounter}`;
		this.db.exec(`SAVEPOINT ${savepoint};`);
		try {
			const result = action();
			this.db.exec(`RELEASE SAVEPOINT ${savepoint};`);
			return result;
		} catch (error) {
			try {
				this.db.exec(`ROLLBACK TO SAVEPOINT ${savepoint};`);
				this.db.exec(`RELEASE SAVEPOINT ${savepoint};`);
			} catch { /* preserve the original failure */ }
			throw error;
		}
	}

	private ensureOpen(): void {
		if (this.disposed || this.db.open === false) {
			throw new Error('HXDB semantic store is closed.');
		}
	}
}

export function migrateLegacyV1SemanticFacts(
	store: SemanticStore,
	facts: LegacyV1SemanticFacts,
	options: LegacyV1MigrationOptions = {},
): LegacyV1MigrationResult {
	return store.migrateLegacyV1(facts, options);
}
