/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	arbitrateSemanticValue,
	canonicalSerialize,
	normalizeSemanticEvidence,
	type ArbitrationStatus,
	type EvidenceStrength,
	type SemanticConflict,
	type SemanticEvidence,
} from './semanticModel';
import type { SemanticSqliteDatabase } from './semanticStore';

export const REFERENCE_GRAPH_SCHEMA_VERSION = 1 as const;

export type ReferenceRelationFamily = 'code' | 'data' | 'type' | 'import' | 'string';

export type ReferenceRelationKind =
	| 'code-call-near'
	| 'code-call-far'
	| 'code-tail-call'
	| 'code-jump'
	| 'code-flow'
	| 'code-exception'
	| 'code-unwind'
	| 'code-indirect-candidate'
	| 'code-indirect-resolved'
	| 'data-read'
	| 'data-write'
	| 'data-read-write'
	| 'data-address-taken'
	| 'data-offset-pointer-construction'
	| 'type-reference'
	| 'type-member-reference'
	| 'type-symbolic-constant-reference'
	| 'type-vtable-slot-reference'
	| 'type-function-pointer-slot-reference'
	| 'import-relocation'
	| 'import-iat'
	| 'import-plt'
	| 'string-reference';

export type ReferenceTargetKind =
	| 'address'
	| 'function'
	| 'basic-block'
	| 'instruction'
	| 'type'
	| 'type-member'
	| 'import'
	| 'string'
	| 'global'
	| 'stack-slot'
	| 'enum-member'
	| 'vtable-slot'
	| 'function-pointer-slot'
	| 'unknown';

export type IndirectResolutionSource =
	| 'import-table'
	| 'relocation'
	| 'jump-table'
	| 'constant-function-pointer'
	| 'address-taken-function'
	| 'callback-registration'
	| 'vtable'
	| 'points-to-set'
	| 'runtime-trace';

export type ReferenceDependencyKind =
	| 'analysis-generation'
	| 'function-body'
	| 'prototype'
	| 'type'
	| 'type-member'
	| 'import-table'
	| 'relocation-table'
	| 'runtime-trace'
	| 'user-override'
	| 'custom';

export interface ReferenceSourceLocation {
	address: string;
	ownerFunctionIdentity: string;
	basicBlockIdentity: string;
	operandIndex: number;
}

export interface ReferenceTarget {
	kind: ReferenceTargetKind;
	identity: string;
	address?: string;
	typeId?: string;
	memberIdentity?: string;
}

export interface ReferenceProvenance {
	sourceEngine: string;
	sourceEngineVersion?: string;
	sourceArtifactSha256?: string;
	evidenceAddress: string;
}

export interface ReferenceInvalidationDependency {
	kind: ReferenceDependencyKind;
	key: string;
	generation?: number;
	contentSha256?: string;
}

export interface IndirectResolutionEvidence {
	status: 'candidate' | 'resolved';
	candidateSetId: string;
	source: IndirectResolutionSource;
	reason: string;
	runtimeTraceCorroborated?: boolean;
}

export interface ReferenceEdgeSpec {
	analysisTargetIdentity: string;
	relation: ReferenceRelationKind;
	source: ReferenceSourceLocation;
	target: ReferenceTarget;
	/** Explicit null means the relation has no meaningful memory access width. */
	accessWidthBits: number | null;
	provenance: ReferenceProvenance;
	corroboratingProvenance?: readonly ReferenceProvenance[];
	provenanceSet?: readonly ReferenceProvenance[];
	evidence: SemanticEvidence;
	corroboratingEvidence?: readonly SemanticEvidence[];
	evidenceSet?: readonly SemanticEvidence[];
	invalidationDependencies?: readonly ReferenceInvalidationDependency[];
	indirectResolution?: IndirectResolutionEvidence;
	indirectResolutionSet?: readonly IndirectResolutionEvidence[];
}

export interface CanonicalReferenceEdge extends Omit<ReferenceEdgeSpec,
	'corroboratingEvidence' | 'corroboratingProvenance' | 'evidenceSet' | 'provenanceSet' |
	'invalidationDependencies' | 'indirectResolutionSet'> {
	schemaVersion: typeof REFERENCE_GRAPH_SCHEMA_VERSION;
	edgeId: string;
	family: ReferenceRelationFamily;
	evidence: SemanticEvidence;
	evidenceSet: readonly SemanticEvidence[];
	provenanceSet: readonly ReferenceProvenance[];
	userDefined: boolean;
	generation: number;
	invalidationDependencies: readonly ReferenceInvalidationDependency[];
	indirectResolutionSet: readonly IndirectResolutionEvidence[];
	canonicalSerialization: string;
	canonicalHash: string;
}

export interface StoredReferenceEdge {
	edge: CanonicalReferenceEdge;
	active: boolean;
	validFromGeneration: number;
	invalidatedAtGeneration?: number;
	invalidationReason?: string;
	recordHash: string;
}

export type ReferenceWriteStatus = ArbitrationStatus | 'reactivated' | 'rejected-stale';

export interface ReferenceWriteResult {
	status: ReferenceWriteStatus;
	accepted: CanonicalReferenceEdge;
	changed: boolean;
	transactionHash: string;
	conflict?: SemanticConflict<CanonicalReferenceEdge>;
}

export interface ReferenceBatchResult {
	transactionHash: string;
	results: readonly ReferenceWriteResult[];
}

export interface ReferenceStoredConflict {
	conflictHash: string;
	edgeId: string;
	reason: string;
	winnerHash: string;
	loserHash: string;
	winnerJson: string;
	loserJson: string;
	generation: number;
}

export interface ReferenceEdgeVersion {
	edgeId: string;
	generation: number;
	state: 'active' | 'invalidated';
	stateHash: string;
	recordHash: string;
	recordJson: string;
	reason?: string;
}

export interface ReferenceGraphSnapshot {
	schemaVersion: typeof REFERENCE_GRAPH_SCHEMA_VERSION;
	analysisTargetIdentity: string;
	edges: readonly StoredReferenceEdge[];
	versions: readonly ReferenceEdgeVersion[];
	conflicts: readonly ReferenceStoredConflict[];
}

export interface ReferenceQuery {
	direction?: 'incoming' | 'outgoing' | 'both';
	address?: string;
	functionIdentity?: string;
	typeId?: string;
	memberIdentity?: string;
	targetKind?: ReferenceTargetKind;
	targetIdentity?: string;
	families?: readonly ReferenceRelationFamily[];
	relations?: readonly ReferenceRelationKind[];
	minimumEvidenceStrength?: EvidenceStrength;
	includeInvalidated?: boolean;
	atGeneration?: number;
}

export interface ExactCallReference {
	edgeId: string;
	relation: Extract<ReferenceRelationKind,
		'code-call-near' | 'code-call-far' | 'code-tail-call' | 'code-indirect-resolved' | 'code-indirect-candidate'>;
	callerFunctionIdentity: string;
	calleeIdentity: string;
	callsiteAddress: string;
	basicBlockIdentity: string;
	operandIndex: number;
	indirectResolution?: IndirectResolutionEvidence;
	indirectResolutionSet: readonly IndirectResolutionEvidence[];
}

export interface ReferenceGenerationDiff {
	fromGeneration: number;
	toGeneration: number;
	added: readonly CanonicalReferenceEdge[];
	removed: readonly CanonicalReferenceEdge[];
	changed: readonly { before: CanonicalReferenceEdge; after: CanonicalReferenceEdge }[];
	diffHash: string;
}

export interface ReferencePathFilter {
	families?: readonly ReferenceRelationFamily[];
	relations?: readonly ReferenceRelationKind[];
	targetKinds?: readonly ReferenceTargetKind[];
	minimumEvidenceStrength?: EvidenceStrength;
}

export interface ReferencePathQuery {
	startIdentity: string;
	goalIdentity: string;
	direction?: 'outgoing' | 'incoming' | 'both';
	maxDepth: number;
	maxPaths: number;
	maxVisitedStates?: number;
	filter?: ReferencePathFilter;
}

export interface ReferencePathStep {
	edge: CanonicalReferenceEdge;
	fromIdentity: string;
	toIdentity: string;
	reversed: boolean;
}

export interface ReferencePath {
	nodes: readonly string[];
	steps: readonly ReferencePathStep[];
}

const RELATION_FAMILY: Readonly<Record<ReferenceRelationKind, ReferenceRelationFamily>> = {
	'code-call-near': 'code',
	'code-call-far': 'code',
	'code-tail-call': 'code',
	'code-jump': 'code',
	'code-flow': 'code',
	'code-exception': 'code',
	'code-unwind': 'code',
	'code-indirect-candidate': 'code',
	'code-indirect-resolved': 'code',
	'data-read': 'data',
	'data-write': 'data',
	'data-read-write': 'data',
	'data-address-taken': 'data',
	'data-offset-pointer-construction': 'data',
	'type-reference': 'type',
	'type-member-reference': 'type',
	'type-symbolic-constant-reference': 'type',
	'type-vtable-slot-reference': 'type',
	'type-function-pointer-slot-reference': 'type',
	'import-relocation': 'import',
	'import-iat': 'import',
	'import-plt': 'import',
	'string-reference': 'string',
};

const RELATIONS = new Set<ReferenceRelationKind>(Object.keys(RELATION_FAMILY) as ReferenceRelationKind[]);
const FAMILIES = new Set<ReferenceRelationFamily>(Object.values(RELATION_FAMILY));
const TARGET_KINDS = new Set<ReferenceTargetKind>([
	'address', 'function', 'basic-block', 'instruction', 'type', 'type-member', 'import', 'string',
	'global', 'stack-slot', 'enum-member', 'vtable-slot', 'function-pointer-slot', 'unknown',
]);
const INDIRECT_SOURCES = new Set<IndirectResolutionSource>([
	'import-table', 'relocation', 'jump-table', 'constant-function-pointer', 'address-taken-function',
	'callback-registration', 'vtable', 'points-to-set', 'runtime-trace',
]);
const DEPENDENCY_KINDS = new Set<ReferenceDependencyKind>([
	'analysis-generation', 'function-body', 'prototype', 'type', 'type-member', 'import-table',
	'relocation-table', 'runtime-trace', 'user-override', 'custom',
]);
const CALL_RELATIONS = new Set<ReferenceRelationKind>([
	'code-call-near', 'code-call-far', 'code-tail-call', 'code-indirect-resolved', 'code-indirect-candidate',
]);
const INDIRECT_RELATIONS = new Set<ReferenceRelationKind>(['code-indirect-candidate', 'code-indirect-resolved']);
const MEMORY_ACCESS_RELATIONS = new Set<ReferenceRelationKind>(['data-read', 'data-write', 'data-read-write']);
const STRENGTH_RANK: Readonly<Record<EvidenceStrength, number>> = {
	guessed: 0,
	derived: 1,
	signature: 2,
	debug: 3,
	definitive: 4,
};

const REQUIRED_COLUMNS: Readonly<Record<string, readonly string[]>> = {
	reference_edges: [
		'analysis_target_identity', 'edge_id', 'family', 'relation', 'from_address', 'owner_function_identity',
		'basic_block_identity', 'operand_index', 'target_kind', 'target_identity_value', 'target_address',
		'target_type_id', 'target_member_identity', 'access_width_bits', 'source_engine', 'source_engine_version',
		'source_artifact_sha256', 'evidence_address', 'candidate_set_id', 'indirect_resolution_source',
		'indirect_reason', 'runtime_trace_corroborated', 'canonical_serialization', 'canonical_hash', 'record_json',
		'record_hash', 'evidence_json', 'evidence_set_json', 'evidence_source', 'evidence_strength',
		'evidence_producer', 'evidence_generation', 'confidence', 'calibration_json', 'user_defined', 'active',
		'valid_from_generation', 'invalidated_at_generation', 'invalidation_reason',
	],
	reference_edge_dependencies: [
		'analysis_target_identity', 'edge_id', 'dependency_kind', 'dependency_key', 'dependency_generation',
		'dependency_content_sha256',
	],
	reference_edge_versions: [
		'analysis_target_identity', 'edge_id', 'generation', 'state', 'state_hash', 'record_hash', 'record_json', 'reason',
	],
	reference_edge_conflicts: [
		'analysis_target_identity', 'conflict_hash', 'edge_id', 'reason', 'winner_hash', 'loser_hash',
		'winner_json', 'loser_json', 'generation',
	],
};

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS reference_edges (
	analysis_target_identity TEXT NOT NULL,
	edge_id TEXT NOT NULL,
	family TEXT NOT NULL,
	relation TEXT NOT NULL,
	from_address TEXT NOT NULL,
	owner_function_identity TEXT NOT NULL,
	basic_block_identity TEXT NOT NULL,
	operand_index INTEGER NOT NULL,
	target_kind TEXT NOT NULL,
	target_identity_value TEXT NOT NULL,
	target_address TEXT,
	target_type_id TEXT,
	target_member_identity TEXT,
	access_width_bits INTEGER,
	source_engine TEXT NOT NULL,
	source_engine_version TEXT,
	source_artifact_sha256 TEXT,
	evidence_address TEXT NOT NULL,
	candidate_set_id TEXT,
	indirect_resolution_source TEXT,
	indirect_reason TEXT,
	runtime_trace_corroborated INTEGER,
	canonical_serialization TEXT NOT NULL,
	canonical_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	record_hash TEXT NOT NULL,
	evidence_json TEXT NOT NULL,
	evidence_set_json TEXT NOT NULL,
	evidence_source TEXT NOT NULL,
	evidence_strength TEXT NOT NULL,
	evidence_producer TEXT NOT NULL,
	evidence_generation INTEGER NOT NULL,
	confidence REAL,
	calibration_json TEXT,
	user_defined INTEGER NOT NULL,
	active INTEGER NOT NULL,
	valid_from_generation INTEGER NOT NULL,
	invalidated_at_generation INTEGER,
	invalidation_reason TEXT,
	PRIMARY KEY (analysis_target_identity, edge_id)
);

CREATE TABLE IF NOT EXISTS reference_edge_dependencies (
	analysis_target_identity TEXT NOT NULL,
	edge_id TEXT NOT NULL,
	dependency_kind TEXT NOT NULL,
	dependency_key TEXT NOT NULL,
	dependency_generation INTEGER,
	dependency_content_sha256 TEXT,
	PRIMARY KEY (analysis_target_identity, edge_id, dependency_kind, dependency_key),
	FOREIGN KEY (analysis_target_identity, edge_id)
		REFERENCES reference_edges(analysis_target_identity, edge_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS reference_edge_versions (
	analysis_target_identity TEXT NOT NULL,
	edge_id TEXT NOT NULL,
	generation INTEGER NOT NULL,
	state TEXT NOT NULL,
	state_hash TEXT NOT NULL,
	record_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	reason TEXT,
	PRIMARY KEY (analysis_target_identity, edge_id, generation)
);

CREATE TABLE IF NOT EXISTS reference_edge_conflicts (
	analysis_target_identity TEXT NOT NULL,
	conflict_hash TEXT NOT NULL,
	edge_id TEXT NOT NULL,
	reason TEXT NOT NULL,
	winner_hash TEXT NOT NULL,
	loser_hash TEXT NOT NULL,
	winner_json TEXT NOT NULL,
	loser_json TEXT NOT NULL,
	generation INTEGER NOT NULL,
	PRIMARY KEY (analysis_target_identity, conflict_hash)
);

CREATE INDEX IF NOT EXISTS reference_edges_from_idx
	ON reference_edges(analysis_target_identity, from_address, active, edge_id);
CREATE INDEX IF NOT EXISTS reference_edges_owner_idx
	ON reference_edges(analysis_target_identity, owner_function_identity, active, edge_id);
CREATE INDEX IF NOT EXISTS reference_edges_target_idx
	ON reference_edges(analysis_target_identity, target_kind, target_identity_value, active, edge_id);
CREATE INDEX IF NOT EXISTS reference_edges_type_idx
	ON reference_edges(analysis_target_identity, target_type_id, target_member_identity, active, edge_id);
CREATE INDEX IF NOT EXISTS reference_edges_relation_idx
	ON reference_edges(analysis_target_identity, family, relation, active, edge_id);
CREATE INDEX IF NOT EXISTS reference_dependencies_idx
	ON reference_edge_dependencies(analysis_target_identity, dependency_kind, dependency_key, edge_id);
CREATE INDEX IF NOT EXISTS reference_versions_generation_idx
	ON reference_edge_versions(analysis_target_identity, generation, edge_id);
`;

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function hashValue(value: unknown): string {
	return sha256(canonicalSerialize(value));
}

function requireIdentity(value: string, label: string): string {
	if (typeof value !== 'string') {
		throw new Error(`${label} must be text.`);
	}
	const normalized = value.trim();
	if (!normalized) {
		throw new Error(`${label} must not be empty.`);
	}
	return normalized;
}

function requireAddress(value: string, label: string): string {
	const normalized = requireIdentity(value, label).toLowerCase();
	if (!/^0x[0-9a-f]+$/.test(normalized)) {
		throw new Error(`${label} must be hexadecimal with a 0x prefix.`);
	}
	return `0x${BigInt(normalized).toString(16)}`;
}

function requireSha256(value: string, label: string): string {
	const normalized = requireIdentity(value, label).toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(normalized)) {
		throw new Error(`${label} must be a 64-character SHA-256 digest.`);
	}
	return normalized;
}

function requireNonNegativeInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer.`);
	}
	return value;
}

function normalizeAccessWidth(value: number | null, relation: ReferenceRelationKind): number | null {
	if (value === null) {
		if (MEMORY_ACCESS_RELATIONS.has(relation)) {
			throw new Error(`${relation} requires a positive access width.`);
		}
		return null;
	}
	if (!Number.isSafeInteger(value) || value <= 0) {
		throw new Error('Reference access width must be a positive safe integer or explicit null.');
	}
	return value;
}

function normalizeEvidenceSet(spec: ReferenceEdgeSpec): readonly SemanticEvidence[] {
	const unique = new Map<string, SemanticEvidence>();
	for (const item of [spec.evidence, ...(spec.corroboratingEvidence ?? []), ...(spec.evidenceSet ?? [])]) {
		const normalized = normalizeSemanticEvidence(item);
		unique.set(canonicalSerialize(normalized), normalized);
	}
	return Object.freeze([...unique.values()].sort(compareEvidence).reverse());
}

function compareEvidence(left: SemanticEvidence, right: SemanticEvidence): number {
	if ((left.userDefined === true) !== (right.userDefined === true)) {
		return left.userDefined === true ? 1 : -1;
	}
	const strength = STRENGTH_RANK[left.strength] - STRENGTH_RANK[right.strength];
	if (strength !== 0) {
		return strength;
	}
	if (left.generation !== right.generation) {
		return left.generation - right.generation;
	}
	const confidence = (left.confidence ?? -1) - (right.confidence ?? -1);
	if (confidence !== 0) {
		return confidence;
	}
	const a = canonicalSerialize(left);
	const b = canonicalSerialize(right);
	return a < b ? -1 : a > b ? 1 : 0;
}

function normalizeDependency(value: ReferenceInvalidationDependency): ReferenceInvalidationDependency {
	if (!DEPENDENCY_KINDS.has(value.kind)) {
		throw new Error(`Unknown reference dependency kind: ${String(value.kind)}`);
	}
	return Object.freeze({
		kind: value.kind,
		key: requireIdentity(value.key, 'Reference dependency key'),
		...(value.generation !== undefined
			? { generation: requireNonNegativeInteger(value.generation, 'Reference dependency generation') }
			: {}),
		...(value.contentSha256 ? { contentSha256: requireSha256(value.contentSha256, 'Reference dependency hash') } : {}),
	});
}

function normalizeDependencies(values: readonly ReferenceInvalidationDependency[]): readonly ReferenceInvalidationDependency[] {
	const unique = new Map<string, ReferenceInvalidationDependency>();
	for (const value of values) {
		const normalized = normalizeDependency(value);
		const identity = `${normalized.kind}\0${normalized.key}`;
		const previous = unique.get(identity);
		if (previous && canonicalSerialize(previous) !== canonicalSerialize(normalized)) {
			throw new Error(`Conflicting duplicate invalidation dependency ${normalized.kind}:${normalized.key}.`);
		}
		unique.set(identity, normalized);
	}
	return Object.freeze([...unique.values()].sort((left, right) => {
		const a = canonicalSerialize(left);
		const b = canonicalSerialize(right);
		return a < b ? -1 : a > b ? 1 : 0;
	}));
}

function normalizeIndirect(
	relation: ReferenceRelationKind,
	value: IndirectResolutionEvidence | undefined,
): IndirectResolutionEvidence | undefined {
	if (!INDIRECT_RELATIONS.has(relation)) {
		if (value !== undefined) {
			throw new Error(`${relation} must not carry indirect-resolution metadata.`);
		}
		return undefined;
	}
	if (!value) {
		throw new Error(`${relation} requires explicit candidate provenance.`);
	}
	const expected = relation === 'code-indirect-candidate' ? 'candidate' : 'resolved';
	if (value.status !== expected) {
		throw new Error(`${relation} requires indirect status ${expected}.`);
	}
	if (!INDIRECT_SOURCES.has(value.source)) {
		throw new Error(`Unknown indirect resolution source: ${String(value.source)}`);
	}
	if (value.runtimeTraceCorroborated !== undefined && typeof value.runtimeTraceCorroborated !== 'boolean') {
		throw new Error('Runtime-trace corroboration must be boolean when present.');
	}
	return Object.freeze({
		status: value.status,
		candidateSetId: requireIdentity(value.candidateSetId, 'Indirect candidate-set identity'),
		source: value.source,
		reason: requireIdentity(value.reason, 'Indirect candidate reason'),
		...(value.runtimeTraceCorroborated === true ? { runtimeTraceCorroborated: true } : {}),
	});
}

function validateTargetForRelation(relation: ReferenceRelationKind, target: ReferenceTarget): void {
	const unresolvedDirectAddress = ['code-call-near', 'code-call-far', 'code-tail-call'].includes(relation) && target.kind === 'address';
	const qualifiedIndirectJumpTarget = relation === 'code-indirect-candidate' && ['address', 'basic-block'].includes(target.kind);
	if (CALL_RELATIONS.has(relation) && !unresolvedDirectAddress && !qualifiedIndirectJumpTarget && !['function', 'import', 'function-pointer-slot'].includes(target.kind)) {
		throw new Error(`${relation} must target a function, import, function-pointer slot, or an exact unresolved direct address.`);
	}
	if (relation === 'string-reference' && target.kind !== 'string') {
		throw new Error('string-reference must target a string identity.');
	}
	if (relation === 'type-reference' && target.kind !== 'type') {
		throw new Error('type-reference must target a type identity.');
	}
	if (relation === 'type-member-reference' && target.kind !== 'type-member') {
		throw new Error('type-member-reference must target a type member.');
	}
	if (relation === 'type-symbolic-constant-reference' && target.kind !== 'enum-member') {
		throw new Error('type-symbolic-constant-reference must target an enum member.');
	}
	if (relation === 'type-vtable-slot-reference' && target.kind !== 'vtable-slot') {
		throw new Error('type-vtable-slot-reference must target a vtable slot.');
	}
	if (relation === 'type-function-pointer-slot-reference' && target.kind !== 'function-pointer-slot') {
		throw new Error('type-function-pointer-slot-reference must target a function-pointer slot.');
	}
	if (RELATION_FAMILY[relation] === 'import' && !['import', 'address', 'function', 'global'].includes(target.kind)) {
		throw new Error(`${relation} has an incompatible target kind ${target.kind}.`);
	}
}

function normalizeTarget(value: ReferenceTarget): ReferenceTarget {
	if (!TARGET_KINDS.has(value.kind)) {
		throw new Error(`Unknown reference target kind: ${String(value.kind)}`);
	}
	return Object.freeze({
		kind: value.kind,
		identity: requireIdentity(value.identity, 'Reference target identity'),
		...(value.address ? { address: requireAddress(value.address, 'Reference target address') } : {}),
		...(value.typeId ? { typeId: requireIdentity(value.typeId, 'Reference target type ID') } : {}),
		...(value.memberIdentity ? { memberIdentity: requireIdentity(value.memberIdentity, 'Reference target member identity') } : {}),
	});
}

function normalizeProvenance(value: ReferenceProvenance): ReferenceProvenance {
	return Object.freeze({
		sourceEngine: requireIdentity(value.sourceEngine, 'Reference source engine'),
		...(value.sourceEngineVersion ? { sourceEngineVersion: requireIdentity(value.sourceEngineVersion, 'Reference source engine version') } : {}),
		...(value.sourceArtifactSha256 ? { sourceArtifactSha256: requireSha256(value.sourceArtifactSha256, 'Reference source artifact hash') } : {}),
		evidenceAddress: requireAddress(value.evidenceAddress, 'Reference evidence address'),
	});
}

function normalizeProvenanceSet(spec: ReferenceEdgeSpec): readonly ReferenceProvenance[] {
	const unique = new Map<string, ReferenceProvenance>();
	for (const item of [spec.provenance, ...(spec.corroboratingProvenance ?? []), ...(spec.provenanceSet ?? [])]) {
		const normalized = normalizeProvenance(item);
		unique.set(canonicalSerialize(normalized), normalized);
	}
	return Object.freeze([...unique.values()].sort((left, right) => {
		const a = canonicalSerialize(left);
		const b = canonicalSerialize(right);
		return a < b ? -1 : a > b ? 1 : 0;
	}));
}

function normalizeIndirectSet(
	relation: ReferenceRelationKind,
	spec: ReferenceEdgeSpec,
): readonly IndirectResolutionEvidence[] {
	const values = [
		...(spec.indirectResolution ? [spec.indirectResolution] : []),
		...(spec.indirectResolutionSet ?? []),
	];
	if (!INDIRECT_RELATIONS.has(relation)) {
		if (values.length > 0) {
			throw new Error(`${relation} must not carry indirect-resolution metadata.`);
		}
		return Object.freeze([]);
	}
	if (values.length === 0) {
		throw new Error(`${relation} requires explicit candidate provenance.`);
	}
	const unique = new Map<string, IndirectResolutionEvidence>();
	for (const value of values) {
		const normalized = normalizeIndirect(relation, value)!;
		unique.set(canonicalSerialize(normalized), normalized);
	}
	const result = [...unique.values()].sort((left, right) => {
		const a = canonicalSerialize(left);
		const b = canonicalSerialize(right);
		return a < b ? -1 : a > b ? 1 : 0;
	});
	const candidateSets = new Set(result.map(item => item.candidateSetId));
	if (candidateSets.size !== 1) {
		throw new Error('One logical indirect edge cannot belong to multiple candidate sets.');
	}
	return Object.freeze(result);
}

export function canonicalizeReferenceEdge(spec: ReferenceEdgeSpec): CanonicalReferenceEdge {
	if (!RELATIONS.has(spec.relation)) {
		throw new Error(`Unknown reference relation: ${String(spec.relation)}`);
	}
	const analysisTargetIdentity = requireIdentity(spec.analysisTargetIdentity, 'Reference analysis target identity');
	const source: ReferenceSourceLocation = Object.freeze({
		address: requireAddress(spec.source.address, 'Reference source address'),
		ownerFunctionIdentity: requireIdentity(spec.source.ownerFunctionIdentity, 'Reference owner function'),
		basicBlockIdentity: requireIdentity(spec.source.basicBlockIdentity, 'Reference basic block'),
		operandIndex: requireNonNegativeInteger(spec.source.operandIndex, 'Reference operand index'),
	});
	const target = normalizeTarget(spec.target);
	validateTargetForRelation(spec.relation, target);
	const accessWidthBits = normalizeAccessWidth(spec.accessWidthBits, spec.relation);
	const provenanceSet = normalizeProvenanceSet(spec);
	const provenance = normalizeProvenance(spec.provenance);
	const evidenceSet = normalizeEvidenceSet(spec);
	const evidence = evidenceSet[0];
	const invalidationDependencies = normalizeDependencies(spec.invalidationDependencies ?? []);
	const indirectResolutionSet = normalizeIndirectSet(spec.relation, spec);
	const indirectResolution = indirectResolutionSet[0];
	const identityPayload = {
		schemaVersion: REFERENCE_GRAPH_SCHEMA_VERSION,
		analysisTargetIdentity,
		relation: spec.relation,
		source,
		target,
		...(indirectResolution ? { candidateSetId: indirectResolution.candidateSetId } : {}),
	};
	const edgeId = `reference-edge:sha256:${hashValue(identityPayload)}`;
	const payload = {
		...identityPayload,
		family: RELATION_FAMILY[spec.relation],
		edgeId,
		accessWidthBits,
	};
	const canonicalSerialization = canonicalSerialize(payload);
	const canonicalHash = sha256(canonicalSerialization);
	return Object.freeze({
		schemaVersion: REFERENCE_GRAPH_SCHEMA_VERSION,
		analysisTargetIdentity,
		edgeId,
		family: RELATION_FAMILY[spec.relation],
		relation: spec.relation,
		source,
		target,
		accessWidthBits,
		provenance,
		provenanceSet,
		evidence,
		evidenceSet,
		userDefined: evidence.userDefined === true,
		generation: evidence.generation,
		invalidationDependencies,
		...(indirectResolution ? { indirectResolution } : {}),
		indirectResolutionSet,
		canonicalSerialization,
		canonicalHash,
	});
}

function mergeEquivalentReferenceEdges(
	preferred: CanonicalReferenceEdge,
	other: CanonicalReferenceEdge,
): CanonicalReferenceEdge {
	if (preferred.edgeId !== other.edgeId || preferred.canonicalHash !== other.canonicalHash) {
		return preferred;
	}
	const activeDependencies = new Map<string, ReferenceInvalidationDependency>();
	for (const dependency of other.invalidationDependencies) {
		activeDependencies.set(`${dependency.kind}\0${dependency.key}`, dependency);
	}
	// Dependencies describe the accepted active record. A later observation may
	// legitimately carry a newer generation/body hash for the same semantic edge;
	// keep the old dependency in edge-version history, not beside the winner.
	for (const dependency of preferred.invalidationDependencies) {
		activeDependencies.set(`${dependency.kind}\0${dependency.key}`, dependency);
	}
	return canonicalizeReferenceEdge({
		...preferred,
		provenanceSet: [...preferred.provenanceSet, ...other.provenanceSet],
		evidenceSet: [...preferred.evidenceSet, ...other.evidenceSet],
		invalidationDependencies: [...activeDependencies.values()],
		indirectResolutionSet: [
			...preferred.indirectResolutionSet,
			...other.indirectResolutionSet,
		],
	});
}

function recordHash(edge: CanonicalReferenceEdge): string {
	return hashValue(edge);
}

function rowString(row: unknown, key: string): string {
	const value = (row as Record<string, unknown> | undefined)?.[key];
	if (typeof value !== 'string') {
		throw new Error(`Reference graph row is missing text column ${key}.`);
	}
	return value;
}

function rowOptionalString(row: unknown, key: string): string | undefined {
	const value = (row as Record<string, unknown> | undefined)?.[key];
	if (value === null || value === undefined) {
		return undefined;
	}
	if (typeof value !== 'string') {
		throw new Error(`Reference graph row has invalid optional text column ${key}.`);
	}
	return value;
}

function rowInteger(row: unknown, key: string): number {
	const value = (row as Record<string, unknown> | undefined)?.[key];
	if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
		return value;
	}
	if (typeof value === 'bigint' && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
		return Number(value);
	}
	throw new Error(`Reference graph row is missing safe integer column ${key}.`);
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

function booleanInt(value: boolean): number {
	return value ? 1 : 0;
}

function relationSet(values: readonly ReferenceRelationKind[] | undefined): Set<ReferenceRelationKind> | undefined {
	if (!values) {
		return undefined;
	}
	const result = new Set<ReferenceRelationKind>();
	for (const value of values) {
		if (!RELATIONS.has(value)) {
			throw new Error(`Unknown reference relation filter: ${String(value)}`);
		}
		result.add(value);
	}
	return result;
}

function familySet(values: readonly ReferenceRelationFamily[] | undefined): Set<ReferenceRelationFamily> | undefined {
	if (!values) {
		return undefined;
	}
	const result = new Set<ReferenceRelationFamily>();
	for (const value of values) {
		if (!FAMILIES.has(value)) {
			throw new Error(`Unknown reference family filter: ${String(value)}`);
		}
		result.add(value);
	}
	return result;
}

function strengthAtLeast(edge: CanonicalReferenceEdge, minimum: EvidenceStrength | undefined): boolean {
	if (minimum === undefined) {
		return true;
	}
	if (!(minimum in STRENGTH_RANK)) {
		throw new Error(`Unknown minimum evidence strength: ${String(minimum)}`);
	}
	return STRENGTH_RANK[edge.evidence.strength] >= STRENGTH_RANK[minimum];
}

function edgeSort(left: CanonicalReferenceEdge, right: CanonicalReferenceEdge): number {
	return left.edgeId < right.edgeId ? -1 : left.edgeId > right.edgeId ? 1 : 0;
}

function functionIdentityAliases(value: string): readonly [string, string] {
	const identity = requireIdentity(value, 'Function identity');
	if (/^0x[0-9a-f]+$/i.test(identity)) {
		const address = requireAddress(identity, 'Function address');
		return [address, `function:${address}`];
	}
	const match = /^function:(0x[0-9a-f]+)$/i.exec(identity);
	if (match) {
		const address = requireAddress(match[1], 'Function address');
		return [`function:${address}`, address];
	}
	return [identity, identity];
}

export class TypedReferenceGraph {
	private transactionCounter = 0;
	private disposed = false;
	readonly analysisTargetIdentity: string;

	constructor(
		private readonly db: SemanticSqliteDatabase,
		analysisTargetIdentity: string,
	) {
		this.analysisTargetIdentity = requireIdentity(analysisTargetIdentity, 'Reference graph target identity');
		this.initializeAndValidate();
	}

	putEdge(spec: ReferenceEdgeSpec | CanonicalReferenceEdge): ReferenceWriteResult {
		const edge = canonicalizeReferenceEdge(spec);
		const transactionHash = hashValue({ operation: 'put-reference-edge', edge });
		return this.inTransaction(() => this.putEdgeInternal(edge, transactionHash));
	}

	writeBatch(specs: readonly (ReferenceEdgeSpec | CanonicalReferenceEdge)[]): ReferenceBatchResult {
		const edges = specs.map(spec => canonicalizeReferenceEdge(spec)).sort(edgeSort);
		const duplicateIds = new Set<string>();
		for (let index = 1; index < edges.length; index++) {
			if (edges[index - 1].edgeId === edges[index].edgeId) {
				duplicateIds.add(edges[index].edgeId);
			}
		}
		if (duplicateIds.size > 0) {
			throw new Error(`Reference batch contains duplicate logical edges: ${[...duplicateIds].join(', ')}.`);
		}
		const transactionHash = hashValue({ operation: 'reference-edge-batch', edges });
		return this.inTransaction(() => ({
			transactionHash,
			results: edges.map(edge => this.putEdgeInternal(edge, transactionHash)),
		}));
	}

	writeIndirectCandidateSet(
		specs: readonly (ReferenceEdgeSpec | CanonicalReferenceEdge)[],
		maxCandidates: number,
	): ReferenceBatchResult {
		const budget = requireNonNegativeInteger(maxCandidates, 'Indirect candidate budget');
		if (budget < 1 || budget > 4_096) {
			throw new Error('Indirect candidate budget must be between 1 and 4096.');
		}
		if (specs.length === 0) {
			throw new Error('Indirect candidate sets must contain at least one qualified edge.');
		}
		if (specs.length > budget) {
			throw new Error(`Indirect candidate set exceeds its explicit budget (${specs.length} > ${budget}).`);
		}
		const edges = specs.map(spec => canonicalizeReferenceEdge(spec));
		const first = edges[0];
		if (!INDIRECT_RELATIONS.has(first.relation) || !first.indirectResolution) {
			throw new Error('Indirect candidate-set writes require qualified indirect relations.');
		}
		for (const item of edges) {
			if (!INDIRECT_RELATIONS.has(item.relation)
				|| item.relation !== first.relation
				|| item.source.address !== first.source.address
				|| item.source.ownerFunctionIdentity !== first.source.ownerFunctionIdentity
				|| item.source.operandIndex !== first.source.operandIndex
				|| item.indirectResolution?.candidateSetId !== first.indirectResolution.candidateSetId) {
				throw new Error('Indirect candidate-set edges must share one callsite, relation, and candidate-set identity.');
			}
		}
		return this.writeBatch(edges);
	}

	getEdge(edgeId: string): StoredReferenceEdge | undefined {
		this.ensureOpen();
		const row = this.db.prepare(`
			SELECT record_json, record_hash, active, valid_from_generation, invalidated_at_generation, invalidation_reason
			FROM reference_edges WHERE analysis_target_identity = ? AND edge_id = ?
		`).get(this.analysisTargetIdentity, requireIdentity(edgeId, 'Reference edge ID'));
		return row ? this.readStoredEdge(row) : undefined;
	}

	listStoredEdges(includeInvalidated = false): StoredReferenceEdge[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT record_json, record_hash, active, valid_from_generation, invalidated_at_generation, invalidation_reason
			FROM reference_edges
			WHERE analysis_target_identity = ? ${includeInvalidated ? '' : 'AND active = 1'}
			ORDER BY edge_id
		`).all(this.analysisTargetIdentity).map(row => this.readStoredEdge(row));
	}

	query(query: ReferenceQuery = {}): CanonicalReferenceEdge[] {
		this.ensureOpen();
		const direction = query.direction ?? 'both';
		if (!['incoming', 'outgoing', 'both'].includes(direction)) {
			throw new Error(`Unknown reference query direction: ${String(direction)}`);
		}
		const relations = relationSet(query.relations);
		const families = familySet(query.families);
		if (query.targetKind !== undefined && !TARGET_KINDS.has(query.targetKind)) {
			throw new Error(`Unknown target-kind filter: ${String(query.targetKind)}`);
		}
		const atGeneration = query.atGeneration;
		if (atGeneration !== undefined) {
			requireNonNegativeInteger(atGeneration, 'Reference query generation');
		}
		const candidates = atGeneration !== undefined
			? this.snapshotAtGeneration(atGeneration)
			: this.listStoredEdges(query.includeInvalidated === true).map(item => item.edge);
		const normalizedAddress = query.address ? requireAddress(query.address, 'Reference query address') : undefined;
		const functionIdentity = query.functionIdentity !== undefined
			? requireIdentity(query.functionIdentity, 'Reference query function identity') : undefined;
		const typeId = query.typeId !== undefined ? requireIdentity(query.typeId, 'Reference query type ID') : undefined;
		const memberIdentity = query.memberIdentity !== undefined
			? requireIdentity(query.memberIdentity, 'Reference query member identity') : undefined;
		const targetIdentity = query.targetIdentity !== undefined
			? requireIdentity(query.targetIdentity, 'Reference query target identity') : undefined;
		return candidates.filter(edge => {
			if (families && !families.has(edge.family)) { return false; }
			if (relations && !relations.has(edge.relation)) { return false; }
			if (!strengthAtLeast(edge, query.minimumEvidenceStrength)) { return false; }
			if (query.targetKind && edge.target.kind !== query.targetKind) { return false; }
			if (targetIdentity && edge.target.identity !== targetIdentity) { return false; }
			if (typeId && edge.target.identity !== typeId && edge.target.typeId !== typeId) { return false; }
			if (memberIdentity && edge.target.identity !== memberIdentity && edge.target.memberIdentity !== memberIdentity) { return false; }
			if (normalizedAddress) {
				const outgoing = edge.source.address === normalizedAddress;
				const incoming = edge.target.address === normalizedAddress;
				if (direction === 'outgoing' && !outgoing) { return false; }
				if (direction === 'incoming' && !incoming) { return false; }
				if (direction === 'both' && !outgoing && !incoming) { return false; }
			}
			if (functionIdentity) {
				const outgoing = edge.source.ownerFunctionIdentity === functionIdentity;
				const incoming = edge.target.kind === 'function' && edge.target.identity === functionIdentity;
				if (direction === 'outgoing' && !outgoing) { return false; }
				if (direction === 'incoming' && !incoming) { return false; }
				if (direction === 'both' && !outgoing && !incoming) { return false; }
			}
			return true;
		}).sort(edgeSort);
	}

	getCallers(calleeIdentity: string, includeCandidates = false): ExactCallReference[] {
		const relations = includeCandidates
			? [...CALL_RELATIONS]
			: [...CALL_RELATIONS].filter(value => value !== 'code-indirect-candidate');
		return this.query({
			direction: 'incoming', functionIdentity: requireIdentity(calleeIdentity, 'Callee identity'),
			relations,
		}).map(edge => this.toCallReference(edge));
	}

	getCallees(callerIdentity: string, includeCandidates = false): ExactCallReference[] {
		const relations = includeCandidates
			? [...CALL_RELATIONS]
			: [...CALL_RELATIONS].filter(value => value !== 'code-indirect-candidate');
		return this.query({
			direction: 'outgoing', functionIdentity: requireIdentity(callerIdentity, 'Caller identity'),
			relations,
		}).map(edge => this.toCallReference(edge));
	}

	findDataAccesses(targetKind: 'global' | 'stack-slot' | 'type-member', targetIdentity: string): CanonicalReferenceEdge[] {
		return this.query({
			targetKind,
			targetIdentity: requireIdentity(targetIdentity, 'Data target identity'),
			relations: ['data-read', 'data-write', 'data-read-write'],
		});
	}

	findTypeUses(typeId: string): CanonicalReferenceEdge[] {
		return this.query({ typeId: requireIdentity(typeId, 'Type ID') });
	}

	findMemberUses(memberIdentity: string): CanonicalReferenceEdge[] {
		return this.query({ memberIdentity: requireIdentity(memberIdentity, 'Member identity') });
	}

	listIndirectCandidates(candidateSetId?: string): CanonicalReferenceEdge[] {
		const normalizedSet = candidateSetId === undefined
			? undefined
			: requireIdentity(candidateSetId, 'Indirect candidate-set identity');
		return this.query({ relations: ['code-indirect-candidate', 'code-indirect-resolved'] })
			.filter(edge => normalizedSet === undefined || edge.indirectResolution?.candidateSetId === normalizedSet);
	}

	findPaths(query: ReferencePathQuery): ReferencePath[] {
		const start = requireIdentity(query.startIdentity, 'Reference path start');
		const goal = requireIdentity(query.goalIdentity, 'Reference path goal');
		const maxDepth = requireNonNegativeInteger(query.maxDepth, 'Reference path max depth');
		const maxPaths = requireNonNegativeInteger(query.maxPaths, 'Reference path max paths');
		const maxVisitedStates = requireNonNegativeInteger(query.maxVisitedStates ?? 10_000, 'Reference path state budget');
		if (maxDepth < 1 || maxDepth > 64) {
			throw new Error('Reference path max depth must be between 1 and 64.');
		}
		if (maxPaths < 1 || maxPaths > 1_000) {
			throw new Error('Reference path max paths must be between 1 and 1000.');
		}
		if (maxVisitedStates < 1 || maxVisitedStates > 1_000_000) {
			throw new Error('Reference path state budget must be between 1 and 1000000.');
		}
		const direction = query.direction ?? 'outgoing';
		if (!['outgoing', 'incoming', 'both'].includes(direction)) {
			throw new Error(`Unknown reference path direction: ${String(direction)}`);
		}
		const families = familySet(query.filter?.families);
		const relations = relationSet(query.filter?.relations);
		const targetKinds = query.filter?.targetKinds ? new Set(query.filter.targetKinds) : undefined;
		if (targetKinds && [...targetKinds].some(kind => !TARGET_KINDS.has(kind))) {
			throw new Error('Reference path target-kind filter contains an unknown kind.');
		}
		const edges = this.query().filter(edge =>
			(!families || families.has(edge.family))
			&& (!relations || relations.has(edge.relation))
			&& (!targetKinds || targetKinds.has(edge.target.kind))
			&& strengthAtLeast(edge, query.filter?.minimumEvidenceStrength));
		const adjacency = new Map<string, ReferencePathStep[]>();
		const add = (node: string, step: ReferencePathStep): void => {
			const items = adjacency.get(node) ?? [];
			items.push(step);
			adjacency.set(node, items);
		};
		for (const edge of edges) {
			const fromIdentity = edge.source.ownerFunctionIdentity;
			const toIdentity = edge.target.identity;
			if (direction !== 'incoming') {
				add(fromIdentity, { edge, fromIdentity, toIdentity, reversed: false });
			}
			if (direction !== 'outgoing') {
				add(toIdentity, { edge, fromIdentity: toIdentity, toIdentity: fromIdentity, reversed: true });
			}
		}
		for (const steps of adjacency.values()) {
			steps.sort((left, right) => {
				if (left.toIdentity !== right.toIdentity) { return left.toIdentity < right.toIdentity ? -1 : 1; }
				return edgeSort(left.edge, right.edge);
			});
		}
		const paths: ReferencePath[] = [];
		const queue: Array<{ node: string; nodes: string[]; steps: ReferencePathStep[] }> = [{ node: start, nodes: [start], steps: [] }];
		let visitedStates = 0;
		while (queue.length > 0 && paths.length < maxPaths) {
			visitedStates++;
			if (visitedStates > maxVisitedStates) {
				throw new Error(`Reference path search exceeded its explicit state budget (${maxVisitedStates}).`);
			}
			const current = queue.shift()!;
			if (current.steps.length >= maxDepth) { continue; }
			for (const step of adjacency.get(current.node) ?? []) {
				if (current.nodes.includes(step.toIdentity)) { continue; }
				const nodes = [...current.nodes, step.toIdentity];
				const steps = [...current.steps, step];
				if (step.toIdentity === goal) {
					paths.push(Object.freeze({ nodes: Object.freeze(nodes), steps: Object.freeze(steps) }));
					if (paths.length >= maxPaths) { break; }
				} else {
					queue.push({ node: step.toIdentity, nodes, steps });
				}
			}
		}
		return paths;
	}

	invalidateByDependency(
		kind: ReferenceDependencyKind,
		key: string,
		invalidationGeneration: number,
		reason: string,
		includeUserDefined = false,
	): number {
		this.ensureOpen();
		if (!DEPENDENCY_KINDS.has(kind)) {
			throw new Error(`Unknown invalidation dependency kind: ${String(kind)}`);
		}
		const normalizedKey = requireIdentity(key, 'Invalidation dependency key');
		const edgeIds = this.db.prepare(`
			SELECT d.edge_id
			FROM reference_edge_dependencies d
			JOIN reference_edges e
			  ON e.analysis_target_identity = d.analysis_target_identity AND e.edge_id = d.edge_id
			WHERE d.analysis_target_identity = ? AND d.dependency_kind = ? AND d.dependency_key = ?
			  AND e.active = 1 ${includeUserDefined ? '' : 'AND e.user_defined = 0'}
			ORDER BY d.edge_id
		`).all(this.analysisTargetIdentity, kind, normalizedKey).map(row => rowString(row, 'edge_id'));
		return this.invalidateEdgeIds(edgeIds, invalidationGeneration, reason, includeUserDefined);
	}

	invalidateFunction(
		functionIdentity: string,
		invalidationGeneration: number,
		reason: string,
		includeUserDefined = false,
	): number {
		this.ensureOpen();
		const [identity, alias] = functionIdentityAliases(functionIdentity);
		const edgeIds = this.db.prepare(`
			SELECT edge_id FROM reference_edges
			WHERE analysis_target_identity = ? AND active = 1
			  AND (owner_function_identity IN (?, ?) OR (target_kind = 'function' AND target_identity_value IN (?, ?)))
			  ${includeUserDefined ? '' : 'AND user_defined = 0'}
			UNION
			SELECT d.edge_id
			FROM reference_edge_dependencies d
			JOIN reference_edges e
			  ON e.analysis_target_identity = d.analysis_target_identity AND e.edge_id = d.edge_id
			WHERE d.analysis_target_identity = ? AND d.dependency_kind IN ('function-body', 'prototype')
			  AND d.dependency_key IN (?, ?) AND e.active = 1 ${includeUserDefined ? '' : 'AND e.user_defined = 0'}
			ORDER BY edge_id
		`).all(
			this.analysisTargetIdentity, identity, alias, identity, alias,
			this.analysisTargetIdentity, identity, alias,
		)
			.map(row => rowString(row, 'edge_id'));
		return this.invalidateEdgeIds(edgeIds, invalidationGeneration, reason, includeUserDefined);
	}

	invalidateAllDerived(invalidationGeneration: number, reason: string): number {
		this.ensureOpen();
		const edgeIds = this.db.prepare(`
			SELECT edge_id FROM reference_edges
			WHERE analysis_target_identity = ? AND active = 1 AND user_defined = 0 ORDER BY edge_id
		`).all(this.analysisTargetIdentity).map(row => rowString(row, 'edge_id'));
		return this.invalidateEdgeIds(edgeIds, invalidationGeneration, reason, false);
	}

	/** Invalidate an exact producer-owned set without touching unrelated derived edges. */
	invalidateEdges(edgeIds: readonly string[], invalidationGeneration: number, reason: string): number {
		return this.invalidateEdgeIds(edgeIds, invalidationGeneration, reason, false);
	}

	snapshotAtGeneration(generation: number): CanonicalReferenceEdge[] {
		this.ensureOpen();
		const normalizedGeneration = requireNonNegativeInteger(generation, 'Reference snapshot generation');
		const versions = this.listVersions().filter(version => version.generation <= normalizedGeneration);
		const latest = new Map<string, ReferenceEdgeVersion>();
		for (const version of versions) {
			const current = latest.get(version.edgeId);
			if (!current || version.generation > current.generation) {
				latest.set(version.edgeId, version);
			}
		}
		return [...latest.values()]
			.filter(version => version.state === 'active')
			.map(version => this.readCanonicalEdge(version.recordJson, version.recordHash))
			.sort(edgeSort);
	}

	diffGenerations(fromGeneration: number, toGeneration: number): ReferenceGenerationDiff {
		const from = requireNonNegativeInteger(fromGeneration, 'Reference diff source generation');
		const to = requireNonNegativeInteger(toGeneration, 'Reference diff target generation');
		const before = new Map(this.snapshotAtGeneration(from).map(edge => [edge.edgeId, edge]));
		const after = new Map(this.snapshotAtGeneration(to).map(edge => [edge.edgeId, edge]));
		const added: CanonicalReferenceEdge[] = [];
		const removed: CanonicalReferenceEdge[] = [];
		const changed: Array<{ before: CanonicalReferenceEdge; after: CanonicalReferenceEdge }> = [];
		for (const [edgeId, edge] of before) {
			const next = after.get(edgeId);
			if (!next) {
				removed.push(edge);
			} else if (recordHash(edge) !== recordHash(next)) {
				changed.push({ before: edge, after: next });
			}
		}
		for (const [edgeId, edge] of after) {
			if (!before.has(edgeId)) {
				added.push(edge);
			}
		}
		added.sort(edgeSort);
		removed.sort(edgeSort);
		changed.sort((left, right) => edgeSort(left.after, right.after));
		const payload = { fromGeneration: from, toGeneration: to, added, removed, changed };
		return Object.freeze({ ...payload, diffHash: hashValue(payload) });
	}

	listVersions(): ReferenceEdgeVersion[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT edge_id, generation, state, state_hash, record_hash, record_json, reason
			FROM reference_edge_versions WHERE analysis_target_identity = ?
			ORDER BY edge_id, generation
		`).all(this.analysisTargetIdentity).map(row => {
			const state = rowString(row, 'state');
			if (state !== 'active' && state !== 'invalidated') {
				throw new Error(`Reference edge version has invalid state ${state}.`);
			}
			const version: ReferenceEdgeVersion = {
				edgeId: rowString(row, 'edge_id'),
				generation: rowInteger(row, 'generation'),
				state,
				stateHash: rowString(row, 'state_hash'),
				recordHash: rowString(row, 'record_hash'),
				recordJson: rowString(row, 'record_json'),
				...(rowOptionalString(row, 'reason') ? { reason: rowOptionalString(row, 'reason') } : {}),
			};
			const reproduced = hashValue({
				edgeId: version.edgeId,
				generation: version.generation,
				state: version.state,
				recordHash: version.recordHash,
				reason: version.reason,
			});
			if (reproduced !== version.stateHash) {
				throw new Error(`Reference edge version state hash mismatch for ${version.edgeId}.`);
			}
			return version;
		});
	}

	listConflicts(): ReferenceStoredConflict[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT conflict_hash, edge_id, reason, winner_hash, loser_hash, winner_json, loser_json, generation
			FROM reference_edge_conflicts WHERE analysis_target_identity = ? ORDER BY conflict_hash
		`).all(this.analysisTargetIdentity).map(row => ({
			conflictHash: rowString(row, 'conflict_hash'),
			edgeId: rowString(row, 'edge_id'),
			reason: rowString(row, 'reason'),
			winnerHash: rowString(row, 'winner_hash'),
			loserHash: rowString(row, 'loser_hash'),
			winnerJson: rowString(row, 'winner_json'),
			loserJson: rowString(row, 'loser_json'),
			generation: rowInteger(row, 'generation'),
		}));
	}

	exportSnapshot(): ReferenceGraphSnapshot {
		return Object.freeze({
			schemaVersion: REFERENCE_GRAPH_SCHEMA_VERSION,
			analysisTargetIdentity: this.analysisTargetIdentity,
			edges: Object.freeze(this.listStoredEdges(true)),
			versions: Object.freeze(this.listVersions()),
			conflicts: Object.freeze(this.listConflicts()),
		});
	}

	exportCanonical(): string {
		return canonicalSerialize(this.exportSnapshot());
	}

	exportHash(): string {
		return sha256(this.exportCanonical());
	}

	dispose(): void {
		this.disposed = true;
	}

	private initializeAndValidate(): void {
		const targetRow = this.db.prepare(`SELECT value FROM hxdb_meta WHERE key = 'target_identity'`).get();
		if (!targetRow) {
			throw new Error('Typed reference graph requires an initialized HXDB semantic store.');
		}
		const actualTarget = rowString(targetRow, 'value');
		if (actualTarget !== this.analysisTargetIdentity) {
			throw new Error(`Reference graph target mismatch: database belongs to ${actualTarget}, not ${this.analysisTargetIdentity}.`);
		}
		for (const [table, required] of Object.entries(REQUIRED_COLUMNS)) {
			const exists = this.db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`).get(table);
			if (!exists) { continue; }
			const columns = new Set(this.db.prepare(`PRAGMA table_info(${table})`).all().map(row => rowString(row, 'name')));
			const missing = required.filter(column => !columns.has(column));
			if (missing.length > 0) {
				throw new Error(`Reference graph table ${table} is incompatible; missing columns: ${missing.join(', ')}.`);
			}
		}
		this.db.exec(SCHEMA_SQL);
		const versionRow = this.db.prepare(`SELECT value FROM hxdb_meta WHERE key = 'reference_graph_schema_version'`).get();
		if (versionRow && Number(rowString(versionRow, 'value')) !== REFERENCE_GRAPH_SCHEMA_VERSION) {
			throw new Error(`Unsupported typed reference graph schema ${rowString(versionRow, 'value')}.`);
		}
		this.db.prepare(`INSERT OR REPLACE INTO hxdb_meta(key, value) VALUES (?, ?)`).run(
			'reference_graph_schema_version', String(REFERENCE_GRAPH_SCHEMA_VERSION),
		);
	}

	private putEdgeInternal(edge: CanonicalReferenceEdge, transactionHash: string): ReferenceWriteResult {
		if (edge.analysisTargetIdentity !== this.analysisTargetIdentity) {
			throw new Error(`Reference edge target mismatch: expected ${this.analysisTargetIdentity}, received ${edge.analysisTargetIdentity}.`);
		}
		const stored = this.getEdge(edge.edgeId);
		if (stored && !stored.active) {
			const invalidatedAt = stored.invalidatedAtGeneration ?? stored.validFromGeneration;
			if (edge.generation <= invalidatedAt) {
				return { status: 'rejected-stale', accepted: stored.edge, changed: false, transactionHash };
			}
			this.persistCurrentEdge(edge, true, edge.generation);
			this.persistVersion(edge, edge.generation, 'active');
			return { status: 'reactivated', accepted: edge, changed: true, transactionHash };
		}

		const arbitration = arbitrateSemanticValue(stored?.edge, edge);
		const accepted = stored?.edge && arbitration.accepted.canonicalHash === stored.edge.canonicalHash
			? mergeEquivalentReferenceEdges(arbitration.accepted, arbitration.accepted === stored.edge ? edge : stored.edge)
			: arbitration.accepted;
		const oldHash = stored?.recordHash;
		const newHash = recordHash(accepted);
		const changed = oldHash !== newHash;
		if (arbitration.conflict) {
			this.persistConflict(accepted.edgeId, arbitration.conflict, edge.generation);
		}
		if (!stored || changed) {
			const validFrom = stored?.validFromGeneration ?? accepted.generation;
			this.persistCurrentEdge(accepted, true, validFrom);
			this.persistVersion(accepted, accepted.generation, 'active');
		}
		return { ...arbitration, accepted, changed, transactionHash };
	}

	private persistCurrentEdge(edge: CanonicalReferenceEdge, active: boolean, validFromGeneration: number): void {
		const recordJson = canonicalSerialize(edge);
		const fullHash = sha256(recordJson);
		const indirect = edge.indirectResolution;
		this.db.prepare(`
			INSERT OR REPLACE INTO reference_edges (
				analysis_target_identity, edge_id, family, relation, from_address, owner_function_identity,
				basic_block_identity, operand_index, target_kind, target_identity_value, target_address,
				target_type_id, target_member_identity, access_width_bits, source_engine, source_engine_version,
				source_artifact_sha256, evidence_address, candidate_set_id, indirect_resolution_source,
				indirect_reason, runtime_trace_corroborated, canonical_serialization, canonical_hash, record_json,
				record_hash, evidence_json, evidence_set_json, evidence_source, evidence_strength,
				evidence_producer, evidence_generation, confidence, calibration_json, user_defined, active,
				valid_from_generation, invalidated_at_generation, invalidation_reason
			) VALUES (
				?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
				?, ?, ?, ?, ?, ?, ?, NULL, NULL
			)
		`).run(
			this.analysisTargetIdentity, edge.edgeId, edge.family, edge.relation, edge.source.address,
			edge.source.ownerFunctionIdentity, edge.source.basicBlockIdentity, edge.source.operandIndex,
			edge.target.kind, edge.target.identity, edge.target.address ?? null, edge.target.typeId ?? null,
			edge.target.memberIdentity ?? null, edge.accessWidthBits, edge.provenance.sourceEngine,
			edge.provenance.sourceEngineVersion ?? null, edge.provenance.sourceArtifactSha256 ?? null,
			edge.provenance.evidenceAddress, indirect?.candidateSetId ?? null, indirect?.source ?? null,
			indirect?.reason ?? null, indirect ? booleanInt(indirect.runtimeTraceCorroborated === true) : null,
			edge.canonicalSerialization, edge.canonicalHash, recordJson, fullHash,
			canonicalSerialize(edge.evidence), canonicalSerialize(edge.evidenceSet), edge.evidence.source,
			edge.evidence.strength, edge.evidence.producer, edge.evidence.generation,
			edge.evidence.confidence ?? null, edge.evidence.calibration ? canonicalSerialize(edge.evidence.calibration) : null,
			booleanInt(edge.userDefined), booleanInt(active), validFromGeneration,
		);
		this.db.prepare(`
			DELETE FROM reference_edge_dependencies WHERE analysis_target_identity = ? AND edge_id = ?
		`).run(this.analysisTargetIdentity, edge.edgeId);
		const insertDependency = this.db.prepare(`
			INSERT INTO reference_edge_dependencies (
				analysis_target_identity, edge_id, dependency_kind, dependency_key, dependency_generation,
				dependency_content_sha256
			) VALUES (?, ?, ?, ?, ?, ?)
		`);
		for (const dependency of edge.invalidationDependencies) {
			insertDependency.run(
				this.analysisTargetIdentity, edge.edgeId, dependency.kind, dependency.key,
				dependency.generation ?? null, dependency.contentSha256 ?? null,
			);
		}
	}

	private persistVersion(
		edge: CanonicalReferenceEdge,
		generation: number,
		state: ReferenceEdgeVersion['state'],
		reason?: string,
	): void {
		const recordJson = canonicalSerialize(edge);
		const fullHash = sha256(recordJson);
		const normalizedReason = reason ? requireIdentity(reason, 'Reference invalidation reason') : undefined;
		const stateHash = hashValue({ edgeId: edge.edgeId, generation, state, recordHash: fullHash, reason: normalizedReason });
		this.db.prepare(`
			INSERT OR REPLACE INTO reference_edge_versions (
				analysis_target_identity, edge_id, generation, state, state_hash, record_hash, record_json, reason
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.analysisTargetIdentity, edge.edgeId, generation, state, stateHash, fullHash, recordJson, normalizedReason ?? null,
		);
	}

	private persistConflict(
		edgeId: string,
		conflict: SemanticConflict<CanonicalReferenceEdge>,
		generation: number,
	): void {
		const winnerJson = canonicalSerialize(conflict.winner);
		const loserJson = canonicalSerialize(conflict.loser);
		const conflictHash = hashValue({
			edgeId,
			reason: conflict.reason,
			winnerHash: conflict.winner.canonicalHash,
			loserHash: conflict.loser.canonicalHash,
			winnerJson,
			loserJson,
		});
		this.db.prepare(`
			INSERT OR IGNORE INTO reference_edge_conflicts (
				analysis_target_identity, conflict_hash, edge_id, reason, winner_hash, loser_hash,
				winner_json, loser_json, generation
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		`).run(
			this.analysisTargetIdentity, conflictHash, edgeId, conflict.reason, conflict.winner.canonicalHash,
			conflict.loser.canonicalHash, winnerJson, loserJson, generation,
		);
	}

	private invalidateEdgeIds(
		edgeIds: readonly string[],
		invalidationGeneration: number,
		reason: string,
		includeUserDefined: boolean,
	): number {
		const generation = requireNonNegativeInteger(invalidationGeneration, 'Reference invalidation generation');
		const normalizedReason = requireIdentity(reason, 'Reference invalidation reason');
		const unique = [...new Set(edgeIds)].sort();
		return this.inTransaction(() => {
			let changed = 0;
			for (const edgeId of unique) {
				const stored = this.getEdge(edgeId);
				if (!stored?.active || (stored.edge.userDefined && !includeUserDefined)) { continue; }
				if (generation < stored.validFromGeneration || generation < stored.edge.generation) {
					throw new Error(`Cannot invalidate ${edgeId} before its active generation.`);
				}
				this.db.prepare(`
					UPDATE reference_edges
					SET active = 0, invalidated_at_generation = ?, invalidation_reason = ?
					WHERE analysis_target_identity = ? AND edge_id = ? AND active = 1
				`).run(generation, normalizedReason, this.analysisTargetIdentity, edgeId);
				this.persistVersion(stored.edge, generation, 'invalidated', normalizedReason);
				changed++;
			}
			return changed;
		});
	}

	private readStoredEdge(row: unknown): StoredReferenceEdge {
		const recordJson = rowString(row, 'record_json');
		const fullHash = rowString(row, 'record_hash');
		const edge = this.readCanonicalEdge(recordJson, fullHash);
		const activeValue = rowInteger(row, 'active');
		if (activeValue !== 0 && activeValue !== 1) {
			throw new Error('Reference edge active flag must be 0 or 1.');
		}
		const active = activeValue === 1;
		const raw = row as Record<string, unknown>;
		return Object.freeze({
			edge,
			active,
			validFromGeneration: rowInteger(row, 'valid_from_generation'),
			...(raw.invalidated_at_generation !== null && raw.invalidated_at_generation !== undefined
				? { invalidatedAtGeneration: rowInteger(row, 'invalidated_at_generation') }
				: {}),
			...(rowOptionalString(row, 'invalidation_reason') ? { invalidationReason: rowOptionalString(row, 'invalidation_reason') } : {}),
			recordHash: fullHash,
		});
	}

	private readCanonicalEdge(recordJson: string, expectedRecordHash: string): CanonicalReferenceEdge {
		if (sha256(recordJson) !== expectedRecordHash) {
			throw new Error('Reference edge record hash does not match persisted JSON.');
		}
		const parsed = parseJson<CanonicalReferenceEdge>(recordJson, 'Reference edge record');
		if (parsed.schemaVersion !== REFERENCE_GRAPH_SCHEMA_VERSION) {
			throw new Error(`Unsupported reference edge record schema ${String(parsed.schemaVersion)}.`);
		}
		const canonical = canonicalizeReferenceEdge(parsed);
		if (canonical.edgeId !== parsed.edgeId
			|| canonical.canonicalHash !== parsed.canonicalHash
			|| canonical.canonicalSerialization !== parsed.canonicalSerialization) {
			throw new Error(`Reference edge canonical integrity failure for ${String(parsed.edgeId)}.`);
		}
		if (canonicalSerialize(canonical) !== recordJson) {
			throw new Error(`Reference edge record is not in canonical form for ${parsed.edgeId}.`);
		}
		return canonical;
	}

	private toCallReference(edge: CanonicalReferenceEdge): ExactCallReference {
		if (!CALL_RELATIONS.has(edge.relation)) {
			throw new Error(`${edge.edgeId} is not a call relation.`);
		}
		return Object.freeze({
			edgeId: edge.edgeId,
			relation: edge.relation as ExactCallReference['relation'],
			callerFunctionIdentity: edge.source.ownerFunctionIdentity,
			calleeIdentity: edge.target.identity,
			callsiteAddress: edge.source.address,
			basicBlockIdentity: edge.source.basicBlockIdentity,
			operandIndex: edge.source.operandIndex,
			...(edge.indirectResolution ? { indirectResolution: edge.indirectResolution } : {}),
			indirectResolutionSet: edge.indirectResolutionSet,
		});
	}

	private inTransaction<T>(fn: () => T): T {
		this.ensureOpen();
		const savepoint = `hxdb_reference_graph_${++this.transactionCounter}`;
		this.db.exec(`SAVEPOINT ${savepoint}`);
		try {
			const result = fn();
			this.db.exec(`RELEASE SAVEPOINT ${savepoint}`);
			return result;
		} catch (error) {
			try {
				this.db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
				this.db.exec(`RELEASE SAVEPOINT ${savepoint}`);
			} catch {
				// Preserve the original write failure.
			}
			throw error;
		}
	}

	private ensureOpen(): void {
		if (this.disposed || this.db.open === false) {
			throw new Error('Typed reference graph is closed.');
		}
	}
}
