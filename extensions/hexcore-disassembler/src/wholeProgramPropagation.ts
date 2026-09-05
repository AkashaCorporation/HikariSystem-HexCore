/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	canonicalSerialize,
	canonicalizeTypeBinding,
	normalizeSemanticEvidence,
	type CanonicalFunctionPrototype,
	type CanonicalSemanticType,
	type CanonicalTypeBinding,
	type SemanticEvidence,
	type TypeBindingScope,
} from './semanticModel';
import type { SemanticSqliteDatabase, SemanticStore, SemanticWriteBatchResult } from './semanticStore';
import type { CanonicalReferenceEdge, ReferenceQuery, TypedReferenceGraph } from './typedReferenceGraph';

export const WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION = 1 as const;

export type PropagationValueKind =
	| 'parameter'
	| 'return'
	| 'ssa'
	| 'register'
	| 'stack-slot'
	| 'global'
	| 'memory-region'
	| 'field'
	| 'function-pointer'
	| 'constant';

export interface PropagationValueRef {
	kind: PropagationValueKind;
	identity: string;
	functionIdentity?: string;
	typeId?: string;
	widthBits?: number;
	evidence?: SemanticEvidence;
	pointsTo?: readonly string[];
}

export interface PropagationSeedFact {
	value: PropagationValueRef;
	typeId?: string;
	pointsTo?: readonly string[];
	evidence: SemanticEvidence;
}

export interface ParameterEffect {
	ordinal: number;
	value: PropagationValueRef;
	reads: boolean;
	writes: boolean;
	escapes: boolean;
}

export interface ReturnRelationship {
	value: PropagationValueRef;
	relation: 'copy' | 'alias' | 'allocated-object' | 'function-pointer' | 'unknown';
}

export interface TypedCallBinding {
	ordinal: number;
	argument: PropagationValueRef;
}

export interface OutParameterBinding {
	ordinal: number;
	value: PropagationValueRef;
}

export interface CallEffect {
	callsiteIdentity: string;
	calleeIdentity: string;
	arguments: readonly TypedCallBinding[];
	result?: PropagationValueRef;
	outParameters?: readonly OutParameterBinding[];
	indirectCandidates?: readonly string[];
}

export interface GlobalEffect {
	globalIdentity: string;
	access: 'read' | 'write' | 'read-write';
	value?: PropagationValueRef;
	relocationIdentity?: string;
}

export interface OwnershipEffect {
	kind: 'allocate' | 'free' | 'acquire' | 'release' | 'transfer' | 'escape';
	value: PropagationValueRef;
	objectIdentity?: string;
}

export interface FieldAccessEffect {
	fieldIdentity: string;
	base: PropagationValueRef;
	offsetBytes: number;
	access: 'read' | 'write' | 'read-write' | 'address';
	value?: PropagationValueRef;
	typeId?: string;
}

export interface FunctionPointerEffect {
	value: PropagationValueRef;
	targets: readonly string[];
	resolved: boolean;
}

export interface SummaryBarrier {
	identity: string;
	reason: string;
	values?: readonly PropagationValueRef[];
	lossy: boolean;
}

interface ConstraintBase {
	id: string;
	evidence: SemanticEvidence;
}

export type PropagationConstraint =
	| (ConstraintBase & { kind: 'copy'; from: PropagationValueRef; to: PropagationValueRef })
	| (ConstraintBase & { kind: 'phi' | 'select'; inputs: readonly PropagationValueRef[]; to: PropagationValueRef })
	| (ConstraintBase & { kind: 'cast'; from: PropagationValueRef; to: PropagationValueRef; fromWidthBits?: number; toWidthBits?: number; lossy?: boolean })
	| (ConstraintBase & { kind: 'load'; pointer: PropagationValueRef; to: PropagationValueRef; memory?: PropagationValueRef })
	| (ConstraintBase & { kind: 'store'; from: PropagationValueRef; pointer: PropagationValueRef; memory?: PropagationValueRef })
	| (ConstraintBase & { kind: 'stack-spill'; from: PropagationValueRef; slot: PropagationValueRef })
	| (ConstraintBase & { kind: 'stack-reload'; slot: PropagationValueRef; to: PropagationValueRef })
	| (ConstraintBase & { kind: 'base-offset'; base: PropagationValueRef; to: PropagationValueRef; offsetBytes: number; fieldIdentity?: string; fieldTypeId?: string })
	| (ConstraintBase & { kind: 'call'; call: CallEffect })
	| (ConstraintBase & { kind: 'return'; from: PropagationValueRef })
	| (ConstraintBase & { kind: 'out-parameter'; ordinal: number; from: PropagationValueRef })
	| (ConstraintBase & { kind: 'global-read'; globalIdentity: string; to: PropagationValueRef })
	| (ConstraintBase & { kind: 'global-write'; globalIdentity: string; from: PropagationValueRef })
	| (ConstraintBase & { kind: 'relocation'; relocationIdentity: string; to: PropagationValueRef; targets: readonly string[]; typeId?: string })
	| (ConstraintBase & { kind: 'allocator-result'; allocatorIdentity: string; result: PropagationValueRef; allocationIdentity?: string; resultTypeId?: string })
	| (ConstraintBase & { kind: 'free'; deallocatorIdentity: string; value: PropagationValueRef })
	| (ConstraintBase & { kind: 'field-read'; field: FieldAccessEffect; to: PropagationValueRef })
	| (ConstraintBase & { kind: 'field-write'; field: FieldAccessEffect; from: PropagationValueRef })
	| (ConstraintBase & { kind: 'function-pointer'; value: PropagationValueRef; targets: readonly string[]; resolved: boolean })
	| (ConstraintBase & { kind: 'points-to'; value: PropagationValueRef; targets: readonly string[] })
	| (ConstraintBase & { kind: 'barrier'; reason: string; values: readonly PropagationValueRef[]; lossy: boolean });

export interface FunctionSummaryInput {
	analysisTargetIdentity: string;
	functionIdentity: string;
	functionBodySha256: string;
	generation: number;
	materialized: true;
	parameters?: readonly ParameterEffect[];
	returnRelationships?: readonly ReturnRelationship[];
	calls?: readonly CallEffect[];
	globalEffects?: readonly GlobalEffect[];
	ownershipEffects?: readonly OwnershipEffect[];
	fieldAccesses?: readonly FieldAccessEffect[];
	functionPointerTargets?: readonly FunctionPointerEffect[];
	barriers?: readonly SummaryBarrier[];
	seedFacts?: readonly PropagationSeedFact[];
	constraints: readonly PropagationConstraint[];
}

export interface PropagationTypeHypothesis {
	typeId: string;
	evidence: SemanticEvidence;
	evidenceSet: readonly SemanticEvidence[];
	origins: readonly string[];
	rank: number;
}

export interface PropagationConflict {
	valueIdentity: string;
	typeIds: readonly string[];
	strongestTypeIds: readonly string[];
	reason: 'competing-type-hypotheses';
	blocker: true;
	conflictHash: string;
}

export interface PropagatedValueFact {
	value: PropagationValueRef;
	typeHypotheses: readonly PropagationTypeHypothesis[];
	acceptedTypeId?: string;
	pointsTo: readonly string[];
	sources: readonly string[];
	blockedReasons: readonly string[];
	conflict?: PropagationConflict;
	factHash: string;
}

export interface FunctionPropagationSummary {
	schemaVersion: typeof WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION;
	analysisTargetIdentity: string;
	functionIdentity: string;
	functionBodySha256: string;
	generation: number;
	parameterEffects: readonly ParameterEffect[];
	returnRelationships: readonly ReturnRelationship[];
	calls: readonly CallEffect[];
	globalEffects: readonly GlobalEffect[];
	ownershipEffects: readonly OwnershipEffect[];
	fieldAccesses: readonly FieldAccessEffect[];
	functionPointerTargets: readonly FunctionPointerEffect[];
	barriers: readonly SummaryBarrier[];
	dependencies: readonly string[];
	referenceEdgeHashes: readonly string[];
	valueFacts: readonly PropagatedValueFact[];
	conflicts: readonly PropagationConflict[];
	inputHash: string;
	outputHash: string;
}

export interface PropagationDirtyRecord {
	functionIdentity: string;
	generation: number;
	reason: string;
}

export interface PropagationStoreSnapshot {
	schemaVersion: typeof WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION;
	analysisTargetIdentity: string;
	summaries: readonly FunctionPropagationSummary[];
	dependencies: readonly { consumerFunctionIdentity: string; dependencyFunctionIdentity: string }[];
	dirty: readonly PropagationDirtyRecord[];
}

export interface PropagationCancellationToken {
	readonly isCancellationRequested: boolean;
}

export interface PropagationSolveOptions {
	generation: number;
	changedFunctions?: readonly string[];
	maxIterations?: number;
	maxMilliseconds?: number;
	maxValues?: number;
	maxTypeHypothesesPerValue?: number;
	maxPointsToPerValue?: number;
	cancellationToken?: PropagationCancellationToken;
	now?: () => number;
	onProgress?: (event: PropagationProgressEvent) => void;
}

export interface PropagationProgressEvent {
	phase: 'prepare' | 'seed' | 'iterate' | 'summarize' | 'complete';
	iteration: number;
	affectedFunctions: number;
}

interface PropagationSemanticReadView {
	readonly targetIdentity: string;
	getPrototype(functionIdentity: string): CanonicalFunctionPrototype | undefined;
	findTypeBindings(functionIdentity?: string, scope?: TypeBindingScope): CanonicalTypeBinding[];
	listTypes(): CanonicalSemanticType[];
	listPrototypes(): CanonicalFunctionPrototype[];
	getType(typeId: string): CanonicalSemanticType | undefined;
}

interface PropagationPersistenceReadView {
	listSummaries(): FunctionPropagationSummary[];
	listDirty(): PropagationDirtyRecord[];
	latestAcceptedGeneration(): number | undefined;
}

interface PropagationReferenceReadView {
	query(query?: ReferenceQuery): CanonicalReferenceEdge[];
	getCallees(functionIdentity: string, includeCandidates?: boolean): Array<{ calleeIdentity: string }>;
	exportHash(): string;
}

export interface PropagationSolverContext {
	semanticStore: PropagationSemanticReadView;
	persistence: PropagationPersistenceReadView;
	referenceGraph: PropagationReferenceReadView;
	commitAcceptedRun?: (
		run: PropagationRunResult,
		bindings: readonly CanonicalTypeBinding[],
	) => SemanticWriteBatchResult;
}

export interface PropagationSolverSnapshot {
	schemaVersion: 1;
	targetIdentity: string;
	types: CanonicalSemanticType[];
	prototypes: CanonicalFunctionPrototype[];
	bindings: CanonicalTypeBinding[];
	referenceEdges: CanonicalReferenceEdge[];
	referenceGraphHash: string;
	persistedSummaries: FunctionPropagationSummary[];
	dirty: PropagationDirtyRecord[];
	latestAcceptedGeneration?: number;
	snapshotHash: string;
}

function propagationSnapshotHash(snapshot: Omit<PropagationSolverSnapshot, 'snapshotHash'>): string {
	return hashValue({
		schemaVersion: snapshot.schemaVersion,
		targetIdentity: snapshot.targetIdentity,
		types: snapshot.types.map(item => item.canonicalHash).sort(),
		prototypes: snapshot.prototypes.map(item => item.canonicalHash).sort(),
		bindings: snapshot.bindings.map(item => item.canonicalHash).sort(),
		referenceEdges: snapshot.referenceEdges.map(item => item.canonicalHash).sort(),
		referenceGraphHash: snapshot.referenceGraphHash,
		persistedSummaries: snapshot.persistedSummaries.map(item => ({
			functionIdentity: item.functionIdentity,
			generation: item.generation,
			inputHash: item.inputHash,
			outputHash: item.outputHash,
		})).sort((left, right) => compareAscii(left.functionIdentity, right.functionIdentity)),
		dirty: [...snapshot.dirty].sort((left, right) => compareAscii(left.functionIdentity, right.functionIdentity)),
		latestAcceptedGeneration: snapshot.latestAcceptedGeneration ?? null,
	});
}

export type PropagationRunStatus = 'committed' | 'cancelled' | 'timeout' | 'budget-exhausted';

export interface PropagationRunResult {
	status: PropagationRunStatus;
	committed: boolean;
	generation: number;
	priorAcceptedGeneration?: number;
	affectedFunctions: readonly string[];
	recomputedFunctions: readonly string[];
	iterations: number;
	inputHash: string;
	outputHash?: string;
	runHash: string;
	summaries: readonly FunctionPropagationSummary[];
	semanticWrites?: SemanticWriteBatchResult;
	reason?: string;
}

const PROPAGATION_SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS propagation_summaries (
	analysis_target_identity TEXT NOT NULL,
	function_identity TEXT NOT NULL,
	generation INTEGER NOT NULL,
	input_hash TEXT NOT NULL,
	output_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	PRIMARY KEY (analysis_target_identity, function_identity)
);
CREATE TABLE IF NOT EXISTS propagation_summary_versions (
	analysis_target_identity TEXT NOT NULL,
	function_identity TEXT NOT NULL,
	generation INTEGER NOT NULL,
	input_hash TEXT NOT NULL,
	output_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	PRIMARY KEY (analysis_target_identity, function_identity, generation, output_hash)
);
CREATE TABLE IF NOT EXISTS propagation_dependencies (
	analysis_target_identity TEXT NOT NULL,
	consumer_function_identity TEXT NOT NULL,
	dependency_function_identity TEXT NOT NULL,
	PRIMARY KEY (analysis_target_identity, consumer_function_identity, dependency_function_identity)
);
CREATE TABLE IF NOT EXISTS propagation_dirty (
	analysis_target_identity TEXT NOT NULL,
	function_identity TEXT NOT NULL,
	generation INTEGER NOT NULL,
	reason TEXT NOT NULL,
	PRIMARY KEY (analysis_target_identity, function_identity)
);
CREATE TABLE IF NOT EXISTS propagation_runs (
	analysis_target_identity TEXT NOT NULL,
	run_hash TEXT NOT NULL,
	generation INTEGER NOT NULL,
	input_hash TEXT NOT NULL,
	output_hash TEXT NOT NULL,
	record_json TEXT NOT NULL,
	PRIMARY KEY (analysis_target_identity, run_hash)
);
CREATE INDEX IF NOT EXISTS propagation_dependencies_dependency_idx
	ON propagation_dependencies(analysis_target_identity, dependency_function_identity, consumer_function_identity);
CREATE INDEX IF NOT EXISTS propagation_versions_generation_idx
	ON propagation_summary_versions(analysis_target_identity, generation, function_identity);
`;

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function hashValue(value: unknown): string {
	return sha256(canonicalSerialize(value));
}

function compareAscii(left: string, right: string): number {
	return left < right ? -1 : left > right ? 1 : 0;
}

function requireIdentity(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) {
		throw new Error(`${label} must not be empty.`);
	}
	return normalized;
}

function requireSafeNonNegativeInteger(value: number, label: string): number {
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new Error(`${label} must be a non-negative safe integer.`);
	}
	return value;
}

function parseSummary(row: unknown): FunctionPropagationSummary {
	const record = row as { record_json?: unknown };
	if (typeof record.record_json !== 'string') {
		throw new Error('Stored propagation summary is missing record_json.');
	}
	return JSON.parse(record.record_json) as FunctionPropagationSummary;
}

export class WholeProgramPropagationStore {
	private transactionCounter = 0;
	private disposed = false;
	readonly analysisTargetIdentity: string;

	constructor(private readonly db: SemanticSqliteDatabase, analysisTargetIdentity: string) {
		this.analysisTargetIdentity = requireIdentity(analysisTargetIdentity, 'Propagation target identity');
		this.db.exec(PROPAGATION_SCHEMA_SQL);
	}

	getSummary(functionIdentity: string): FunctionPropagationSummary | undefined {
		this.ensureOpen();
		const row = this.db.prepare(`
			SELECT record_json FROM propagation_summaries
			WHERE analysis_target_identity = ? AND function_identity = ?
		`).get(this.analysisTargetIdentity, requireIdentity(functionIdentity, 'Function identity'));
		return row ? parseSummary(row) : undefined;
	}

	listSummaries(): FunctionPropagationSummary[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT record_json FROM propagation_summaries
			WHERE analysis_target_identity = ? ORDER BY function_identity
		`).all(this.analysisTargetIdentity).map(parseSummary);
	}

	listDependencies(): { consumerFunctionIdentity: string; dependencyFunctionIdentity: string }[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT consumer_function_identity, dependency_function_identity
			FROM propagation_dependencies WHERE analysis_target_identity = ?
			ORDER BY consumer_function_identity, dependency_function_identity
		`).all(this.analysisTargetIdentity).map(row => {
			const value = row as Record<string, unknown>;
			return {
				consumerFunctionIdentity: String(value.consumer_function_identity),
				dependencyFunctionIdentity: String(value.dependency_function_identity),
			};
		});
	}

	listDirty(): PropagationDirtyRecord[] {
		this.ensureOpen();
		return this.db.prepare(`
			SELECT function_identity, generation, reason FROM propagation_dirty
			WHERE analysis_target_identity = ? ORDER BY function_identity
		`).all(this.analysisTargetIdentity).map(row => {
			const value = row as Record<string, unknown>;
			return {
				functionIdentity: String(value.function_identity),
				generation: Number(value.generation),
				reason: String(value.reason),
			};
		});
	}

	latestAcceptedGeneration(): number | undefined {
		this.ensureOpen();
		const row = this.db.prepare(`
			SELECT MAX(generation) AS generation FROM propagation_summaries
			WHERE analysis_target_identity = ?
		`).get(this.analysisTargetIdentity) as { generation?: unknown } | undefined;
		return typeof row?.generation === 'number' ? row.generation : undefined;
	}

	markDirty(functionIdentities: readonly string[], generation: number, reason: string): readonly string[] {
		this.ensureOpen();
		requireSafeNonNegativeInteger(generation, 'Dirty generation');
		const normalizedReason = requireIdentity(reason, 'Dirty reason');
		const consumers = new Map<string, Set<string>>();
		for (const dependency of this.listDependencies()) {
			const values = consumers.get(dependency.dependencyFunctionIdentity) ?? new Set<string>();
			values.add(dependency.consumerFunctionIdentity);
			consumers.set(dependency.dependencyFunctionIdentity, values);
		}
		const queue = [...new Set(functionIdentities.map(item => requireIdentity(item, 'Dirty function identity')))].sort();
		const affected = new Set(queue);
		while (queue.length > 0) {
			const current = queue.shift()!;
			for (const consumer of [...(consumers.get(current) ?? [])].sort()) {
				if (!affected.has(consumer)) {
					affected.add(consumer);
					queue.push(consumer);
				}
			}
		}
		this.inTransaction(() => {
			const statement = this.db.prepare(`
				INSERT INTO propagation_dirty (analysis_target_identity, function_identity, generation, reason)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(analysis_target_identity, function_identity) DO UPDATE SET
					generation = MAX(propagation_dirty.generation, excluded.generation), reason = excluded.reason
			`);
			for (const functionIdentity of [...affected].sort()) {
				statement.run(this.analysisTargetIdentity, functionIdentity, generation, normalizedReason);
			}
		});
		return [...affected].sort();
	}

	markAllDirty(generation: number, reason: string): readonly string[] {
		return this.markDirty(this.listSummaries().map(item => item.functionIdentity), generation, reason);
	}

	/** Remove unsafe current summaries while retaining immutable version history. */
	invalidateCurrentSummaries(functionIdentities: readonly string[], generation: number, reason: string): number {
		this.ensureOpen();
		requireSafeNonNegativeInteger(generation, 'Invalidation generation');
		const normalizedReason = requireIdentity(reason, 'Invalidation reason');
		const identities = [...new Set(functionIdentities.map(item => requireIdentity(item, 'Invalidated function identity')))].sort();
		if (identities.length === 0) { return 0; }
		const removed = new Set(identities);
		const consumers = new Map<string, Set<string>>();
		for (const dependency of this.listDependencies()) {
			const values = consumers.get(dependency.dependencyFunctionIdentity) ?? new Set<string>();
			values.add(dependency.consumerFunctionIdentity);
			consumers.set(dependency.dependencyFunctionIdentity, values);
		}
		const queue = [...identities];
		const affectedConsumers = new Set<string>();
		while (queue.length > 0) {
			const current = queue.shift()!;
			for (const consumer of [...(consumers.get(current) ?? [])].sort()) {
				if (!removed.has(consumer) && !affectedConsumers.has(consumer)) {
					affectedConsumers.add(consumer);
					queue.push(consumer);
				}
			}
		}
		const placeholders = identities.map(() => '?').join(', ');
		return this.inTransaction(() => {
			const result = this.db.prepare(`
				DELETE FROM propagation_summaries WHERE analysis_target_identity = ?
				AND function_identity IN (${placeholders})
			`).run(this.analysisTargetIdentity, ...identities);
			this.db.prepare(`
				DELETE FROM propagation_dependencies WHERE analysis_target_identity = ?
				AND (consumer_function_identity IN (${placeholders}) OR dependency_function_identity IN (${placeholders}))
			`).run(this.analysisTargetIdentity, ...identities, ...identities);
			this.db.prepare(`
				DELETE FROM propagation_dirty WHERE analysis_target_identity = ?
				AND function_identity IN (${placeholders})
			`).run(this.analysisTargetIdentity, ...identities);
			const mark = this.db.prepare(`
				INSERT INTO propagation_dirty (analysis_target_identity, function_identity, generation, reason)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(analysis_target_identity, function_identity) DO UPDATE SET
					generation = MAX(propagation_dirty.generation, excluded.generation), reason = excluded.reason
			`);
			for (const consumer of [...affectedConsumers].sort()) {
				mark.run(this.analysisTargetIdentity, consumer, generation, normalizedReason);
			}
			return Number(result.changes);
		});
	}

	commitAcceptedRun<T>(
		run: PropagationRunResult,
		semanticWrite: () => T,
	): T {
		if (run.status !== 'committed' || !run.committed || !run.outputHash) {
			throw new Error('Only complete propagation runs can be committed.');
		}
		return this.inTransaction(() => {
			const semanticResult = semanticWrite();
			const putCurrent = this.db.prepare(`
				INSERT OR REPLACE INTO propagation_summaries
				(analysis_target_identity, function_identity, generation, input_hash, output_hash, record_json)
				VALUES (?, ?, ?, ?, ?, ?)
			`);
			const putVersion = this.db.prepare(`
				INSERT OR IGNORE INTO propagation_summary_versions
				(analysis_target_identity, function_identity, generation, input_hash, output_hash, record_json)
				VALUES (?, ?, ?, ?, ?, ?)
			`);
			const clearDependencies = this.db.prepare(`
				DELETE FROM propagation_dependencies
				WHERE analysis_target_identity = ? AND consumer_function_identity = ?
			`);
			const putDependency = this.db.prepare(`
				INSERT OR IGNORE INTO propagation_dependencies
				(analysis_target_identity, consumer_function_identity, dependency_function_identity)
				VALUES (?, ?, ?)
			`);
			for (const summary of [...run.summaries].sort((a, b) => compareAscii(a.functionIdentity, b.functionIdentity))) {
				const recordJson = canonicalSerialize(summary);
				putCurrent.run(this.analysisTargetIdentity, summary.functionIdentity, summary.generation, summary.inputHash, summary.outputHash, recordJson);
				putVersion.run(this.analysisTargetIdentity, summary.functionIdentity, summary.generation, summary.inputHash, summary.outputHash, recordJson);
				clearDependencies.run(this.analysisTargetIdentity, summary.functionIdentity);
				for (const dependency of summary.dependencies) {
					putDependency.run(this.analysisTargetIdentity, summary.functionIdentity, dependency);
				}
			}
			if (run.recomputedFunctions.length > 0) {
				const placeholders = run.recomputedFunctions.map(() => '?').join(', ');
				this.db.prepare(`
					DELETE FROM propagation_dirty WHERE analysis_target_identity = ?
					AND function_identity IN (${placeholders})
				`).run(this.analysisTargetIdentity, ...run.recomputedFunctions);
			}
			this.db.prepare(`
				INSERT OR IGNORE INTO propagation_runs
				(analysis_target_identity, run_hash, generation, input_hash, output_hash, record_json)
				VALUES (?, ?, ?, ?, ?, ?)
			`).run(
				this.analysisTargetIdentity,
				run.runHash,
				run.generation,
				run.inputHash,
				run.outputHash,
				canonicalSerialize({
					generation: run.generation,
					affectedFunctions: run.affectedFunctions,
					recomputedFunctions: run.recomputedFunctions,
					iterations: run.iterations,
					inputHash: run.inputHash,
					outputHash: run.outputHash,
					runHash: run.runHash,
				}),
			);
			return semanticResult;
		});
	}

	exportSnapshot(): PropagationStoreSnapshot {
		return {
			schemaVersion: WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION,
			analysisTargetIdentity: this.analysisTargetIdentity,
			summaries: this.listSummaries(),
			dependencies: this.listDependencies(),
			dirty: this.listDirty(),
		};
	}

	exportHash(): string {
		return hashValue(this.exportSnapshot());
	}

	dispose(): void {
		this.disposed = true;
	}

	private inTransaction<T>(action: () => T): T {
		const savepoint = `whole_program_propagation_${++this.transactionCounter}`;
		this.db.exec(`SAVEPOINT ${savepoint}`);
		try {
			const result = action();
			this.db.exec(`RELEASE SAVEPOINT ${savepoint}`);
			return result;
		} catch (error) {
			try {
				this.db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}`);
				this.db.exec(`RELEASE SAVEPOINT ${savepoint}`);
			} catch { /* preserve the original error */ }
			throw error;
		}
	}

	private ensureOpen(): void {
		if (this.disposed) {
			throw new Error('Whole-program propagation store is disposed.');
		}
	}
}

class PropagationBudgetError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'PropagationBudgetError';
	}
}

interface MutableTypeHypothesis {
	typeId: string;
	evidenceSet: SemanticEvidence[];
	origins: Set<string>;
}

interface MutableValueFact {
	value: PropagationValueRef;
	typeHypotheses: Map<string, MutableTypeHypothesis>;
	pointsTo: Set<string>;
	sources: Set<string>;
	blockedReasons: Set<string>;
}

interface CanonicalInput {
	input: FunctionSummaryInput;
	staticInputHash: string;
}

interface SolverBudgets {
	maxIterations: number;
	maxMilliseconds: number;
	maxValues: number;
	maxTypeHypothesesPerValue: number;
	maxPointsToPerValue: number;
}

function evidenceRank(evidence: SemanticEvidence): number {
	if (evidence.userDefined === true && evidence.source === 'analyst' && evidence.strength === 'definitive') { return 700; }
	if (evidence.strength === 'debug' && evidence.source === 'debug-info') { return 600; }
	if (evidence.strength === 'signature' && (evidence.source === 'import' || evidence.source === 'signature')) { return 500; }
	if (evidence.strength === 'derived' && evidence.source === 'abi-recovery') { return 400; }
	if (evidence.strength === 'derived' && evidence.source === 'dataflow') { return 300; }
	if (evidence.strength === 'guessed') { return 200; }
	return 100;
}

function evidenceSort(left: SemanticEvidence, right: SemanticEvidence): number {
	const rank = evidenceRank(right) - evidenceRank(left);
	return rank !== 0 ? rank : compareAscii(canonicalSerialize(left), canonicalSerialize(right));
}

function mergeEvidenceSet(values: readonly SemanticEvidence[]): SemanticEvidence[] {
	const unique = new Map<string, SemanticEvidence>();
	for (const raw of values) {
		const evidence = normalizeSemanticEvidence(raw);
		unique.set(canonicalSerialize(evidence), evidence);
	}
	return [...unique.values()].sort(evidenceSort);
}

function normalizeValueRef(value: PropagationValueRef, ownerFunctionIdentity: string): PropagationValueRef {
	const kind = value.kind;
	const identity = requireIdentity(value.identity, 'Propagation value identity');
	const global = kind === 'global' || kind === 'memory-region' || kind === 'constant';
	const functionIdentity = global
		? value.functionIdentity?.trim() || undefined
		: requireIdentity(value.functionIdentity ?? ownerFunctionIdentity, 'Propagation value function identity');
	const widthBits = value.widthBits === undefined ? undefined : requireSafeNonNegativeInteger(value.widthBits, 'Value width');
	return {
		kind,
		identity,
		...(functionIdentity ? { functionIdentity } : {}),
		...(value.typeId ? { typeId: requireIdentity(value.typeId, 'Value type ID') } : {}),
		...(widthBits !== undefined ? { widthBits } : {}),
		...(value.evidence ? { evidence: normalizeSemanticEvidence(value.evidence) } : {}),
		...(value.pointsTo ? { pointsTo: [...new Set(value.pointsTo.map(item => requireIdentity(item, 'Points-to target')))].sort() } : {}),
	};
}

function valueKey(value: PropagationValueRef, ownerFunctionIdentity: string): string {
	const normalized = normalizeValueRef(value, ownerFunctionIdentity);
	if (normalized.kind === 'global' || normalized.kind === 'memory-region' || normalized.kind === 'constant') {
		return `${normalized.kind}:${normalized.identity}`;
	}
	return `${normalized.functionIdentity}:${normalized.kind}:${normalized.identity}`;
}

function parameterRef(functionIdentity: string, ordinal: number): PropagationValueRef {
	return { kind: 'parameter', identity: `parameter:${ordinal}`, functionIdentity };
}

function returnRef(functionIdentity: string): PropagationValueRef {
	return { kind: 'return', identity: 'return', functionIdentity };
}

function globalRef(globalIdentity: string): PropagationValueRef {
	return { kind: 'global', identity: globalIdentity };
}

function memoryRef(identity: string): PropagationValueRef {
	return { kind: 'memory-region', identity };
}

function normalizeOffset(value: number, label: string): number {
	if (!Number.isSafeInteger(value)) {
		throw new Error(`${label} must be a safe integer.`);
	}
	return value;
}

function sortCanonical<T>(values: readonly T[]): T[] {
	return [...values].sort((left, right) => compareAscii(canonicalSerialize(left), canonicalSerialize(right)));
}

function normalizeCall(call: CallEffect, owner: string): CallEffect {
	return {
		callsiteIdentity: requireIdentity(call.callsiteIdentity, 'Callsite identity'),
		calleeIdentity: requireIdentity(call.calleeIdentity, 'Callee identity'),
		arguments: sortCanonical(call.arguments.map(binding => ({
			ordinal: requireSafeNonNegativeInteger(binding.ordinal, 'Call parameter ordinal'),
			argument: normalizeValueRef(binding.argument, owner),
		}))),
		...(call.result ? { result: normalizeValueRef(call.result, owner) } : {}),
		...(call.outParameters ? { outParameters: sortCanonical(call.outParameters.map(binding => ({
			ordinal: requireSafeNonNegativeInteger(binding.ordinal, 'Out parameter ordinal'),
			value: normalizeValueRef(binding.value, owner),
		}))) } : {}),
		...(call.indirectCandidates ? { indirectCandidates: [...new Set(call.indirectCandidates.map(item => requireIdentity(item, 'Indirect candidate')))].sort() } : {}),
	};
}

function normalizeField(field: FieldAccessEffect, owner: string): FieldAccessEffect {
	return {
		fieldIdentity: requireIdentity(field.fieldIdentity, 'Field identity'),
		base: normalizeValueRef(field.base, owner),
		offsetBytes: normalizeOffset(field.offsetBytes, 'Field offset'),
		access: field.access,
		...(field.value ? { value: normalizeValueRef(field.value, owner) } : {}),
		...(field.typeId ? { typeId: requireIdentity(field.typeId, 'Field type ID') } : {}),
	};
}

function normalizeConstraint(constraint: PropagationConstraint, owner: string): PropagationConstraint {
	const base = { id: requireIdentity(constraint.id, 'Constraint ID'), evidence: normalizeSemanticEvidence(constraint.evidence) };
	switch (constraint.kind) {
		case 'copy': return { ...base, kind: constraint.kind, from: normalizeValueRef(constraint.from, owner), to: normalizeValueRef(constraint.to, owner) };
		case 'phi':
		case 'select': return { ...base, kind: constraint.kind, inputs: sortCanonical(constraint.inputs.map(item => normalizeValueRef(item, owner))), to: normalizeValueRef(constraint.to, owner) };
		case 'cast': return {
			...base, kind: constraint.kind, from: normalizeValueRef(constraint.from, owner), to: normalizeValueRef(constraint.to, owner),
			...(constraint.fromWidthBits !== undefined ? { fromWidthBits: requireSafeNonNegativeInteger(constraint.fromWidthBits, 'Cast source width') } : {}),
			...(constraint.toWidthBits !== undefined ? { toWidthBits: requireSafeNonNegativeInteger(constraint.toWidthBits, 'Cast target width') } : {}),
			...(constraint.lossy !== undefined ? { lossy: constraint.lossy } : {}),
		};
		case 'load': return { ...base, kind: constraint.kind, pointer: normalizeValueRef(constraint.pointer, owner), to: normalizeValueRef(constraint.to, owner), ...(constraint.memory ? { memory: normalizeValueRef(constraint.memory, owner) } : {}) };
		case 'store': return { ...base, kind: constraint.kind, from: normalizeValueRef(constraint.from, owner), pointer: normalizeValueRef(constraint.pointer, owner), ...(constraint.memory ? { memory: normalizeValueRef(constraint.memory, owner) } : {}) };
		case 'stack-spill': return { ...base, kind: constraint.kind, from: normalizeValueRef(constraint.from, owner), slot: normalizeValueRef(constraint.slot, owner) };
		case 'stack-reload': return { ...base, kind: constraint.kind, slot: normalizeValueRef(constraint.slot, owner), to: normalizeValueRef(constraint.to, owner) };
		case 'base-offset': return {
			...base, kind: constraint.kind, base: normalizeValueRef(constraint.base, owner), to: normalizeValueRef(constraint.to, owner),
			offsetBytes: normalizeOffset(constraint.offsetBytes, 'Base-plus-offset displacement'),
			...(constraint.fieldIdentity ? { fieldIdentity: requireIdentity(constraint.fieldIdentity, 'Field identity') } : {}),
			...(constraint.fieldTypeId ? { fieldTypeId: requireIdentity(constraint.fieldTypeId, 'Field type ID') } : {}),
		};
		case 'call': return { ...base, kind: constraint.kind, call: normalizeCall(constraint.call, owner) };
		case 'return': return { ...base, kind: constraint.kind, from: normalizeValueRef(constraint.from, owner) };
		case 'out-parameter': return { ...base, kind: constraint.kind, ordinal: requireSafeNonNegativeInteger(constraint.ordinal, 'Out parameter ordinal'), from: normalizeValueRef(constraint.from, owner) };
		case 'global-read': return { ...base, kind: constraint.kind, globalIdentity: requireIdentity(constraint.globalIdentity, 'Global identity'), to: normalizeValueRef(constraint.to, owner) };
		case 'global-write': return { ...base, kind: constraint.kind, globalIdentity: requireIdentity(constraint.globalIdentity, 'Global identity'), from: normalizeValueRef(constraint.from, owner) };
		case 'relocation': return { ...base, kind: constraint.kind, relocationIdentity: requireIdentity(constraint.relocationIdentity, 'Relocation identity'), to: normalizeValueRef(constraint.to, owner), targets: [...new Set(constraint.targets.map(item => requireIdentity(item, 'Relocation target')))].sort(), ...(constraint.typeId ? { typeId: requireIdentity(constraint.typeId, 'Relocation type ID') } : {}) };
		case 'allocator-result': return { ...base, kind: constraint.kind, allocatorIdentity: requireIdentity(constraint.allocatorIdentity, 'Allocator identity'), result: normalizeValueRef(constraint.result, owner), ...(constraint.allocationIdentity ? { allocationIdentity: requireIdentity(constraint.allocationIdentity, 'Allocation identity') } : {}), ...(constraint.resultTypeId ? { resultTypeId: requireIdentity(constraint.resultTypeId, 'Allocator result type') } : {}) };
		case 'free': return { ...base, kind: constraint.kind, deallocatorIdentity: requireIdentity(constraint.deallocatorIdentity, 'Deallocator identity'), value: normalizeValueRef(constraint.value, owner) };
		case 'field-read': return { ...base, kind: constraint.kind, field: normalizeField(constraint.field, owner), to: normalizeValueRef(constraint.to, owner) };
		case 'field-write': return { ...base, kind: constraint.kind, field: normalizeField(constraint.field, owner), from: normalizeValueRef(constraint.from, owner) };
		case 'function-pointer': return { ...base, kind: constraint.kind, value: normalizeValueRef(constraint.value, owner), targets: [...new Set(constraint.targets.map(item => requireIdentity(item, 'Function target')))].sort(), resolved: constraint.resolved };
		case 'points-to': return { ...base, kind: constraint.kind, value: normalizeValueRef(constraint.value, owner), targets: [...new Set(constraint.targets.map(item => requireIdentity(item, 'Points-to target')))].sort() };
		case 'barrier': return { ...base, kind: constraint.kind, reason: requireIdentity(constraint.reason, 'Barrier reason'), values: sortCanonical(constraint.values.map(item => normalizeValueRef(item, owner))), lossy: constraint.lossy };
	}
}

function canonicalizeInput(input: FunctionSummaryInput): CanonicalInput {
	const analysisTargetIdentity = requireIdentity(input.analysisTargetIdentity, 'Analysis target identity');
	const functionIdentity = requireIdentity(input.functionIdentity, 'Function identity');
	const functionBodySha256 = input.functionBodySha256.toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(functionBodySha256)) {
		throw new Error(`Function ${functionIdentity} body hash must be SHA-256.`);
	}
	const generation = requireSafeNonNegativeInteger(input.generation, 'Summary generation');
	const normalized: FunctionSummaryInput = {
		analysisTargetIdentity,
		functionIdentity,
		functionBodySha256,
		generation,
		materialized: true,
		parameters: sortCanonical((input.parameters ?? []).map(item => ({
			ordinal: requireSafeNonNegativeInteger(item.ordinal, 'Parameter ordinal'),
			value: normalizeValueRef(item.value, functionIdentity), reads: item.reads, writes: item.writes, escapes: item.escapes,
		}))),
		returnRelationships: sortCanonical((input.returnRelationships ?? []).map(item => ({ value: normalizeValueRef(item.value, functionIdentity), relation: item.relation }))),
		calls: sortCanonical((input.calls ?? []).map(item => normalizeCall(item, functionIdentity))),
		globalEffects: sortCanonical((input.globalEffects ?? []).map(item => ({
			globalIdentity: requireIdentity(item.globalIdentity, 'Global identity'), access: item.access,
			...(item.value ? { value: normalizeValueRef(item.value, functionIdentity) } : {}),
			...(item.relocationIdentity ? { relocationIdentity: requireIdentity(item.relocationIdentity, 'Relocation identity') } : {}),
		}))),
		ownershipEffects: sortCanonical((input.ownershipEffects ?? []).map(item => ({
			kind: item.kind, value: normalizeValueRef(item.value, functionIdentity),
			...(item.objectIdentity ? { objectIdentity: requireIdentity(item.objectIdentity, 'Object identity') } : {}),
		}))),
		fieldAccesses: sortCanonical((input.fieldAccesses ?? []).map(item => normalizeField(item, functionIdentity))),
		functionPointerTargets: sortCanonical((input.functionPointerTargets ?? []).map(item => ({
			value: normalizeValueRef(item.value, functionIdentity), targets: [...new Set(item.targets.map(target => requireIdentity(target, 'Function target')))].sort(), resolved: item.resolved,
		}))),
		barriers: sortCanonical((input.barriers ?? []).map(item => ({
			identity: requireIdentity(item.identity, 'Barrier identity'), reason: requireIdentity(item.reason, 'Barrier reason'), lossy: item.lossy,
			...(item.values ? { values: sortCanonical(item.values.map(value => normalizeValueRef(value, functionIdentity))) } : {}),
		}))),
		seedFacts: sortCanonical((input.seedFacts ?? []).map(item => ({
			value: normalizeValueRef(item.value, functionIdentity),
			...(item.typeId ? { typeId: requireIdentity(item.typeId, 'Seed type ID') } : {}),
			...(item.pointsTo ? { pointsTo: [...new Set(item.pointsTo.map(target => requireIdentity(target, 'Seed points-to target')))].sort() } : {}),
			evidence: normalizeSemanticEvidence(item.evidence),
		}))),
		constraints: sortCanonical(input.constraints.map(item => normalizeConstraint(item, functionIdentity))),
	};
	const constraintIds = normalized.constraints.map(item => item.id);
	if (new Set(constraintIds).size !== constraintIds.length) {
		throw new Error(`Function ${functionIdentity} contains duplicate propagation constraint IDs.`);
	}
	const { generation: _generation, ...stableInput } = normalized;
	return { input: normalized, staticInputHash: hashValue(stableInput) };
}

function normalizeFunctionIdentity(value: string): string {
	const normalized = requireIdentity(value, 'Function identity');
	return /^0x[0-9a-f]+$/i.test(normalized) ? `function:${normalized.toLowerCase()}` : normalized;
}

function functionTargetIdentity(value: string): string {
	const normalized = normalizeFunctionIdentity(value);
	return normalized.startsWith('function:') ? normalized : `function:${normalized}`;
}

function canonicalFact(
	fact: MutableValueFact,
	owner: string,
): PropagatedValueFact {
	const hypotheses = [...fact.typeHypotheses.values()].map(item => {
		const evidenceSet = mergeEvidenceSet(item.evidenceSet);
		return {
			typeId: item.typeId,
			evidence: evidenceSet[0],
			evidenceSet,
			origins: [...item.origins].sort(),
			rank: Math.max(...evidenceSet.map(evidenceRank)),
		};
	}).sort((left, right) => right.rank - left.rank || compareAscii(left.typeId, right.typeId));
	const strongestRank = hypotheses[0]?.rank;
	const strongestTypeIds = hypotheses.filter(item => item.rank === strongestRank).map(item => item.typeId).sort();
	const acceptedTypeId = strongestTypeIds.length === 1 ? strongestTypeIds[0] : undefined;
	const conflict = hypotheses.length > 1 ? {
		valueIdentity: valueKey(fact.value, owner),
		typeIds: hypotheses.map(item => item.typeId).sort(),
		strongestTypeIds,
		reason: 'competing-type-hypotheses' as const,
		blocker: true as const,
		conflictHash: hashValue({ valueIdentity: valueKey(fact.value, owner), typeIds: hypotheses.map(item => item.typeId).sort(), strongestTypeIds }),
	} : undefined;
	const payload = {
		value: fact.value,
		typeHypotheses: hypotheses,
		...(acceptedTypeId ? { acceptedTypeId } : {}),
		pointsTo: [...fact.pointsTo].sort(),
		sources: [...fact.sources].sort(),
		blockedReasons: [...fact.blockedReasons].sort(),
		...(conflict ? { conflict } : {}),
	};
	return { ...payload, factHash: hashValue(payload) };
}

function tarjanScc(nodes: readonly string[], dependencies: ReadonlyMap<string, ReadonlySet<string>>): string[][] {
	let index = 0;
	const stack: string[] = [];
	const onStack = new Set<string>();
	const indices = new Map<string, number>();
	const lowLinks = new Map<string, number>();
	const components: string[][] = [];
	const visit = (node: string): void => {
		indices.set(node, index);
		lowLinks.set(node, index++);
		stack.push(node);
		onStack.add(node);
		for (const dependency of [...(dependencies.get(node) ?? [])].filter(item => nodes.includes(item)).sort()) {
			if (!indices.has(dependency)) {
				visit(dependency);
				lowLinks.set(node, Math.min(lowLinks.get(node)!, lowLinks.get(dependency)!));
			} else if (onStack.has(dependency)) {
				lowLinks.set(node, Math.min(lowLinks.get(node)!, indices.get(dependency)!));
			}
		}
		if (lowLinks.get(node) === indices.get(node)) {
			const component: string[] = [];
			while (stack.length > 0) {
				const member = stack.pop()!;
				onStack.delete(member);
				component.push(member);
				if (member === node) { break; }
			}
			components.push(component.sort());
		}
	};
	for (const node of [...nodes].sort()) {
		if (!indices.has(node)) { visit(node); }
	}
	return components.sort((left, right) => compareAscii(left[0], right[0]));
}

export class WholeProgramPropagationEngine {
	private readonly semanticStore: PropagationSemanticReadView;
	private readonly persistence: PropagationPersistenceReadView;
	private readonly referenceGraph: PropagationReferenceReadView;
	private readonly commitAcceptedRun?: PropagationSolverContext['commitAcceptedRun'];
	private pendingBindings: readonly CanonicalTypeBinding[] = [];

	constructor(source: SemanticStore | PropagationSolverContext) {
		if ('semanticStore' in source) {
			this.semanticStore = source.semanticStore;
			this.persistence = source.persistence;
			this.referenceGraph = source.referenceGraph;
			this.commitAcceptedRun = source.commitAcceptedRun;
		} else {
			this.semanticStore = source;
			this.persistence = source.getWholeProgramPropagationStore();
			this.referenceGraph = source.getReferenceGraph();
			this.commitAcceptedRun = (run, bindings) =>
				this.persistence instanceof WholeProgramPropagationStore
					? this.persistence.commitAcceptedRun(run, () => source.writeBatch({ typeBindings: bindings }))
					: source.writeBatch({ typeBindings: bindings });
		}
	}

	getPendingBindings(): readonly CanonicalTypeBinding[] {
		return this.pendingBindings;
	}

	solve(rawInputs: readonly FunctionSummaryInput[], options: PropagationSolveOptions): PropagationRunResult {
		this.pendingBindings = [];
		const generation = requireSafeNonNegativeInteger(options.generation, 'Propagation generation');
		const budgets: SolverBudgets = {
			maxIterations: options.maxIterations ?? 64,
			maxMilliseconds: options.maxMilliseconds ?? 30_000,
			maxValues: options.maxValues ?? 200_000,
			maxTypeHypothesesPerValue: options.maxTypeHypothesesPerValue ?? 16,
			maxPointsToPerValue: options.maxPointsToPerValue ?? 64,
		};
		for (const [label, value] of Object.entries(budgets)) {
			if (!Number.isSafeInteger(value) || value < 1) { throw new Error(`${label} must be a positive safe integer.`); }
		}
		const now = options.now ?? Date.now;
		const startedAt = now();
		const deadline = startedAt + budgets.maxMilliseconds;
		const inputs = rawInputs.map(canonicalizeInput).sort((a, b) => compareAscii(a.input.functionIdentity, b.input.functionIdentity));
		const targetIdentities = new Set(inputs.map(item => item.input.analysisTargetIdentity));
		if (targetIdentities.size > 1 || (targetIdentities.size === 1 && !targetIdentities.has(this.semanticStore.targetIdentity))) {
			throw new Error('Propagation summaries must belong to the SemanticStore target identity.');
		}
		const duplicateFunctions = inputs.filter((item, index) => index > 0 && item.input.functionIdentity === inputs[index - 1].input.functionIdentity);
		if (duplicateFunctions.length > 0) {
			throw new Error(`Duplicate function summaries: ${duplicateFunctions.map(item => item.input.functionIdentity).join(', ')}.`);
		}
		const inputMap = new Map(inputs.map(item => [item.input.functionIdentity, item]));
		const dependencies = this.buildDependencies(inputs);
		const allFunctions = [...inputMap.keys()].sort();
		const persisted = new Map(this.persistence.listSummaries().map(item => [item.functionIdentity, item]));
		const dirty = this.persistence.listDirty().map(item => item.functionIdentity).filter(item => inputMap.has(item));
		const missingBaseline = allFunctions.some(functionIdentity => !persisted.has(functionIdentity));
		const requested = options.changedFunctions?.map(normalizeFunctionIdentity)
			?? (missingBaseline ? allFunctions : dirty.length > 0 ? dirty : allFunctions);
		const affected = this.computeAffected(allFunctions, dependencies, requested);
		options.onProgress?.({ phase: 'prepare', iteration: 0, affectedFunctions: affected.length });
		const inputHash = hashValue({
			targetIdentity: this.semanticStore.targetIdentity,
			inputs: inputs.map(item => ({ functionIdentity: item.input.functionIdentity, staticInputHash: item.staticInputHash })),
			requested: [...new Set(requested)].sort(),
			semanticStoreHash: this.semanticSeedSnapshotHash(),
			referenceGraphHash: this.referenceGraph.exportHash(),
		});
		const priorAcceptedGeneration = this.persistence.latestAcceptedGeneration();
		const abortResult = (status: Exclude<PropagationRunStatus, 'committed'>, reason: string, iterations: number): PropagationRunResult => {
			const payload = { status, generation, inputHash, affectedFunctions: affected, iterations, reason };
			return {
				status, committed: false, generation, ...(priorAcceptedGeneration !== undefined ? { priorAcceptedGeneration } : {}),
				affectedFunctions: affected, recomputedFunctions: [], iterations, inputHash, runHash: hashValue(payload),
				summaries: [...persisted.values()].sort((a, b) => compareAscii(a.functionIdentity, b.functionIdentity)), reason,
			};
		};
		const checkAbort = (iterations: number): PropagationRunResult | undefined => {
			if (options.cancellationToken?.isCancellationRequested) {
				return abortResult('cancelled', 'Propagation cancelled before an atomic generation could be committed.', iterations);
			}
			if (now() >= deadline) {
				return abortResult('timeout', 'Propagation deadline expired before an atomic generation could be committed.', iterations);
			}
			return undefined;
		};
		const preflightAbort = checkAbort(0);
		if (preflightAbort) { return preflightAbort; }

		const facts = new Map<string, MutableValueFact>();
		const factOwner = new Map<string, string>();
		const affectedSet = new Set(affected);
		try {
			for (const summary of persisted.values()) {
				if (affectedSet.has(summary.functionIdentity)) { continue; }
				for (const fact of summary.valueFacts) {
					this.importCanonicalFact(facts, factOwner, fact, summary.functionIdentity, budgets);
				}
			}
			for (const item of inputs) {
				if (!affectedSet.has(item.input.functionIdentity)) { continue; }
				this.seedFunction(facts, factOwner, item.input, generation, budgets);
			}
		} catch (error) {
			if (error instanceof PropagationBudgetError) { return abortResult('budget-exhausted', error.message, 0); }
			throw error;
		}
		options.onProgress?.({ phase: 'seed', iteration: 0, affectedFunctions: affected.length });

		let iterations = 0;
		let changed = true;
		try {
			while (changed && iterations < budgets.maxIterations) {
				const aborted = checkAbort(iterations);
				if (aborted) { return aborted; }
				changed = false;
				iterations++;
				options.onProgress?.({ phase: 'iterate', iteration: iterations, affectedFunctions: affected.length });
				for (const functionIdentity of affected) {
					const item = inputMap.get(functionIdentity);
					if (!item) { continue; }
					changed = this.applySummaryEffects(facts, factOwner, item.input, generation, budgets) || changed;
					for (const constraint of item.input.constraints ?? []) {
						const innerAbort = checkAbort(iterations);
						if (innerAbort) { return innerAbort; }
						changed = this.applyConstraint(facts, factOwner, item.input, constraint, generation, budgets) || changed;
					}
				}
			}
		} catch (error) {
			if (error instanceof PropagationBudgetError) { return abortResult('budget-exhausted', error.message, iterations); }
			throw error;
		}
		if (changed) {
			return abortResult('budget-exhausted', `Fixed point did not converge within ${budgets.maxIterations} iterations.`, iterations);
		}

		const summaries: FunctionPropagationSummary[] = [];
		options.onProgress?.({ phase: 'summarize', iteration: iterations, affectedFunctions: affected.length });
		const semanticInputsByFunction = this.semanticInputHashes(inputs);
		for (const functionIdentity of affected) {
			const item = inputMap.get(functionIdentity)!;
			const functionFacts = [...facts.entries()]
				.filter(([key]) => factOwner.get(key) === functionIdentity || this.factReferencedByInput(key, item.input, functionIdentity))
				.map(([, fact]) => canonicalFact(fact, functionIdentity))
				.sort((a, b) => compareAscii(valueKey(a.value, functionIdentity), valueKey(b.value, functionIdentity)));
			const functionDependencies = [...(dependencies.get(functionIdentity) ?? [])].sort();
			const referenceEdges = this.referenceGraph.query({ direction: 'outgoing', functionIdentity, includeInvalidated: false });
			const dependencyOutputHashes = functionDependencies.map(dependency => ({
				functionIdentity: dependency,
				outputHash: this.outputHashForFunction(dependency, facts, factOwner, persisted),
			}));
			const summaryInputHash = hashValue({
				staticInputHash: item.staticInputHash,
				semanticInputHashes: semanticInputsByFunction.get(functionIdentity) ?? [],
				referenceEdgeHashes: referenceEdges.map(edge => edge.canonicalHash).sort(),
				dependencyOutputHashes,
			});
			const payload = {
				functionIdentity,
				functionBodySha256: item.input.functionBodySha256,
				parameterEffects: item.input.parameters ?? [],
				returnRelationships: item.input.returnRelationships ?? [],
				calls: item.input.calls ?? [],
				globalEffects: item.input.globalEffects ?? [],
				ownershipEffects: item.input.ownershipEffects ?? [],
				fieldAccesses: item.input.fieldAccesses ?? [],
				functionPointerTargets: item.input.functionPointerTargets ?? [],
				barriers: item.input.barriers ?? [],
				dependencies: functionDependencies,
				referenceEdgeHashes: referenceEdges.map(edge => edge.canonicalHash).sort(),
				valueFacts: functionFacts,
				conflicts: functionFacts.flatMap(fact => fact.conflict ? [fact.conflict] : []).sort((a, b) => compareAscii(a.conflictHash, b.conflictHash)),
			};
			summaries.push({
				schemaVersion: WHOLE_PROGRAM_PROPAGATION_SCHEMA_VERSION,
				analysisTargetIdentity: this.semanticStore.targetIdentity,
				generation,
				...payload,
				inputHash: summaryInputHash,
				outputHash: hashValue(payload),
			});
		}
		summaries.sort((a, b) => compareAscii(a.functionIdentity, b.functionIdentity));
		const outputHash = hashValue(summaries.map(item => ({ functionIdentity: item.functionIdentity, outputHash: item.outputHash })));
		const runHash = hashValue({ generation, inputHash, outputHash, affectedFunctions: affected, iterations });
		const complete: PropagationRunResult = {
			status: 'committed', committed: true, generation,
			...(priorAcceptedGeneration !== undefined ? { priorAcceptedGeneration } : {}),
			affectedFunctions: affected, recomputedFunctions: summaries.map(item => item.functionIdentity), iterations,
			inputHash, outputHash, runHash, summaries,
		};
		const bindings = this.derivedBindings(summaries);
		this.pendingBindings = bindings;
		const semanticWrites = this.commitAcceptedRun?.(complete, bindings);
		options.onProgress?.({ phase: 'complete', iteration: iterations, affectedFunctions: affected.length });
		return semanticWrites ? { ...complete, semanticWrites } : complete;
	}

	private buildDependencies(inputs: readonly CanonicalInput[]): Map<string, Set<string>> {
		const known = new Set(inputs.map(item => item.input.functionIdentity));
		const result = new Map<string, Set<string>>();
		for (const item of inputs) {
			const dependencies = new Set<string>();
			for (const call of item.input.calls ?? []) { dependencies.add(call.calleeIdentity); }
			for (const constraint of item.input.constraints) {
				if (constraint.kind === 'call') { dependencies.add(constraint.call.calleeIdentity); }
			}
			for (const callee of this.referenceGraph.getCallees(item.input.functionIdentity, true)) {
				dependencies.add(callee.calleeIdentity);
			}
			result.set(item.input.functionIdentity, new Set([...dependencies].filter(dependency => known.has(dependency)).sort()));
		}
		return result;
	}

	private computeAffected(
		functions: readonly string[],
		dependencies: ReadonlyMap<string, ReadonlySet<string>>,
		requested: readonly string[],
	): string[] {
		const components = tarjanScc(functions, dependencies);
		const componentByFunction = new Map<string, string[]>();
		for (const component of components) {
			for (const member of component) { componentByFunction.set(member, component); }
		}
		const consumers = new Map<string, Set<string>>();
		for (const [consumer, values] of dependencies) {
			for (const dependency of values) {
				const set = consumers.get(dependency) ?? new Set<string>();
				set.add(consumer);
				consumers.set(dependency, set);
			}
		}
		const affected = new Set<string>();
		const queue: string[] = [];
		const addComponent = (functionIdentity: string): void => {
			for (const member of componentByFunction.get(functionIdentity) ?? []) {
				if (!affected.has(member)) { affected.add(member); queue.push(member); }
			}
		};
		for (const requestedFunction of [...new Set(requested)].sort()) {
			if (componentByFunction.has(requestedFunction)) { addComponent(requestedFunction); }
		}
		while (queue.length > 0) {
			const dependency = queue.shift()!;
			for (const consumer of [...(consumers.get(dependency) ?? [])].sort()) { addComponent(consumer); }
		}
		return [...affected].sort();
	}

	private seedFunction(
		facts: Map<string, MutableValueFact>,
		factOwner: Map<string, string>,
		input: FunctionSummaryInput,
		generation: number,
		budgets: SolverBudgets,
	): void {
		for (const seed of input.seedFacts ?? []) {
			this.seedFact(facts, factOwner, input.functionIdentity, seed.value, seed.typeId ?? seed.value.typeId, seed.pointsTo ?? seed.value.pointsTo, seed.evidence, `seed:${input.functionIdentity}`, budgets);
		}
		const prototype = this.semanticStore.getPrototype(input.functionIdentity);
		if (prototype) {
			this.seedFact(facts, factOwner, input.functionIdentity, returnRef(input.functionIdentity), prototype.returnTypeId, [], prototype.evidence, `prototype:${prototype.prototypeId}:return`, budgets, prototype.evidenceSet);
			for (const parameter of prototype.parameters) {
				const declared = (input.parameters ?? []).find(item => item.ordinal === parameter.ordinal)?.value ?? parameterRef(input.functionIdentity, parameter.ordinal);
				this.seedFact(facts, factOwner, input.functionIdentity, declared, parameter.typeId, [], prototype.evidence, `prototype:${prototype.prototypeId}:parameter:${parameter.ordinal}`, budgets, prototype.evidenceSet);
			}
		}
		for (const binding of this.semanticStore.findTypeBindings(input.functionIdentity).filter(item => this.isExternalSemanticBinding(item))) {
			const value = this.refFromBinding(binding, input.functionIdentity);
			this.seedFact(facts, factOwner, input.functionIdentity, value, binding.typeId, [], binding.evidence, `binding:${binding.bindingId}`, budgets, binding.evidenceSet);
		}
		for (const binding of this.semanticStore.findTypeBindings(undefined, 'global').filter(item => this.isExternalSemanticBinding(item))) {
			this.seedFact(facts, factOwner, input.functionIdentity, this.refFromBinding(binding, input.functionIdentity), binding.typeId, [], binding.evidence, `binding:${binding.bindingId}`, budgets, binding.evidenceSet);
		}
		const derivedEvidence: SemanticEvidence = { strength: 'derived', source: 'dataflow', producer: 'whole-program-propagation', generation };
		for (const effect of input.functionPointerTargets ?? []) {
			this.seedFact(facts, factOwner, input.functionIdentity, effect.value, effect.value.typeId, effect.targets.map(functionTargetIdentity), effect.value.evidence ?? derivedEvidence, `function-pointer:${input.functionIdentity}`, budgets);
		}
		for (const edge of this.referenceGraph.query({
			direction: 'outgoing',
			functionIdentity: input.functionIdentity,
			relations: ['code-indirect-candidate', 'code-indirect-resolved'],
		})) {
			this.seedFact(
				facts,
				factOwner,
				input.functionIdentity,
				{ kind: 'function-pointer', identity: `callsite:${edge.source.address}`, functionIdentity: input.functionIdentity },
				undefined,
				[functionTargetIdentity(edge.target.identity)],
				edge.evidence,
				`reference-edge:${edge.edgeId}`,
				budgets,
				edge.evidenceSet,
			);
		}
		for (const barrier of input.barriers ?? []) {
			for (const value of barrier.values ?? []) {
				const fact = this.getFact(facts, factOwner, input.functionIdentity, value, budgets);
				fact.blockedReasons.add(`${barrier.lossy ? 'lossy' : 'unresolved'}:${barrier.identity}:${barrier.reason}`);
			}
		}
	}

	private refFromBinding(binding: CanonicalTypeBinding, functionIdentity: string): PropagationValueRef {
		const kind: PropagationValueKind = binding.scope === 'function-parameter' ? 'parameter'
			: binding.scope === 'stack-slot' ? 'stack-slot'
				: binding.scope === 'register-value' ? 'register'
					: binding.scope === 'global' ? 'global'
						: binding.scope === 'memory-region' ? 'memory-region'
							: binding.scope === 'struct-field' ? 'field'
								: binding.scope === 'return-value' ? 'return' : 'ssa';
		return { kind, identity: binding.valueIdentity, ...(binding.functionIdentity ?? functionIdentity ? { functionIdentity: binding.functionIdentity ?? functionIdentity } : {}) };
	}

	private getFact(
		facts: Map<string, MutableValueFact>,
		factOwner: Map<string, string>,
		owner: string,
		value: PropagationValueRef,
		budgets: SolverBudgets,
	): MutableValueFact {
		const normalized = normalizeValueRef(value, owner);
		const key = valueKey(normalized, owner);
		let fact = facts.get(key);
		if (!fact) {
			if (facts.size >= budgets.maxValues) { throw new PropagationBudgetError(`Propagation value budget exceeded (${budgets.maxValues}).`); }
			fact = { value: normalized, typeHypotheses: new Map(), pointsTo: new Set(), sources: new Set(), blockedReasons: new Set() };
			facts.set(key, fact);
			const globallyScoped = normalized.kind === 'global' || normalized.kind === 'memory-region' || normalized.kind === 'constant';
			factOwner.set(key, normalized.functionIdentity ?? (globallyScoped ? '<global>' : owner));
		}
		return fact;
	}

	private seedFact(
		facts: Map<string, MutableValueFact>, factOwner: Map<string, string>, owner: string, value: PropagationValueRef,
		typeId: string | undefined, pointsTo: readonly string[] | undefined, evidence: SemanticEvidence,
		origin: string, budgets: SolverBudgets, corroboratingEvidence: readonly SemanticEvidence[] = [],
	): boolean {
		const fact = this.getFact(facts, factOwner, owner, value, budgets);
		let changed = false;
		if (typeId) {
			changed = this.addTypeHypothesis(fact, typeId, [evidence, ...corroboratingEvidence], origin, budgets) || changed;
		}
		changed = this.addPointsTo(fact, pointsTo ?? [], budgets) || changed;
		return changed;
	}

	private addTypeHypothesis(
		fact: MutableValueFact, typeId: string, evidence: readonly SemanticEvidence[], origin: string, budgets: SolverBudgets,
	): boolean {
		const normalizedType = requireIdentity(typeId, 'Propagation type ID');
		let hypothesis = fact.typeHypotheses.get(normalizedType);
		if (!hypothesis) {
			if (fact.typeHypotheses.size >= budgets.maxTypeHypothesesPerValue) {
				throw new PropagationBudgetError(`Type-hypothesis budget exceeded for ${fact.value.identity}.`);
			}
			hypothesis = { typeId: normalizedType, evidenceSet: [], origins: new Set() };
			fact.typeHypotheses.set(normalizedType, hypothesis);
		}
		const before = canonicalSerialize({ evidence: hypothesis.evidenceSet, origins: [...hypothesis.origins].sort() });
		hypothesis.evidenceSet = mergeEvidenceSet([...hypothesis.evidenceSet, ...evidence]);
		hypothesis.origins.add(origin);
		return before !== canonicalSerialize({ evidence: hypothesis.evidenceSet, origins: [...hypothesis.origins].sort() });
	}

	private addPointsTo(fact: MutableValueFact, targets: readonly string[], budgets: SolverBudgets): boolean {
		const normalized = [...new Set(targets.map(item => requireIdentity(item, 'Points-to target')))];
		if (new Set([...fact.pointsTo, ...normalized]).size > budgets.maxPointsToPerValue) {
			throw new PropagationBudgetError(`Points-to budget exceeded for ${fact.value.identity}.`);
		}
		const before = fact.pointsTo.size;
		for (const target of normalized) { fact.pointsTo.add(target); }
		return fact.pointsTo.size !== before;
	}

	private mergeFact(
		facts: Map<string, MutableValueFact>, factOwner: Map<string, string>, owner: string,
		fromValue: PropagationValueRef, toValue: PropagationValueRef, evidence: SemanticEvidence,
		origin: string, budgets: SolverBudgets, markLossy?: string,
	): boolean {
		const from = this.getFact(facts, factOwner, owner, fromValue, budgets);
		const to = this.getFact(facts, factOwner, owner, toValue, budgets);
		let changed = false;
		for (const hypothesis of from.typeHypotheses.values()) {
			changed = this.addTypeHypothesis(to, hypothesis.typeId, [...hypothesis.evidenceSet, evidence], origin, budgets) || changed;
		}
		changed = this.addPointsTo(to, [...from.pointsTo], budgets) || changed;
		const sourceKey = valueKey(from.value, owner);
		if (!to.sources.has(sourceKey)) { to.sources.add(sourceKey); changed = true; }
		for (const blocked of from.blockedReasons) {
			if (!to.blockedReasons.has(blocked)) { to.blockedReasons.add(blocked); changed = true; }
		}
		if (markLossy && !to.blockedReasons.has(markLossy)) { to.blockedReasons.add(markLossy); changed = true; }
		return changed;
	}

	private applyConstraint(
		facts: Map<string, MutableValueFact>, factOwner: Map<string, string>, input: FunctionSummaryInput,
		constraint: PropagationConstraint, generation: number, budgets: SolverBudgets,
	): boolean {
		const owner = input.functionIdentity;
		const evidence = normalizeSemanticEvidence({ ...constraint.evidence, generation: Math.max(constraint.evidence.generation, generation) });
		const origin = `constraint:${owner}:${constraint.id}:${constraint.kind}`;
		switch (constraint.kind) {
			case 'copy': return this.mergeFact(facts, factOwner, owner, constraint.from, constraint.to, evidence, origin, budgets);
			case 'phi':
			case 'select': return constraint.inputs.reduce((changed, value) => this.mergeFact(facts, factOwner, owner, value, constraint.to, evidence, origin, budgets) || changed, false);
			case 'cast': {
				const narrowing = constraint.fromWidthBits !== undefined && constraint.toWidthBits !== undefined && constraint.toWidthBits < constraint.fromWidthBits;
				return this.mergeFact(facts, factOwner, owner, constraint.from, constraint.to, evidence, origin, budgets, constraint.lossy || narrowing ? `lossy-cast:${constraint.id}` : undefined);
			}
			case 'stack-spill': return this.mergeFact(facts, factOwner, owner, constraint.from, constraint.slot, evidence, origin, budgets);
			case 'stack-reload': return this.mergeFact(facts, factOwner, owner, constraint.slot, constraint.to, evidence, origin, budgets);
			case 'store': {
				let changed = false;
				const pointer = this.getFact(facts, factOwner, owner, constraint.pointer, budgets);
				const memories = constraint.memory ? [constraint.memory] : [...pointer.pointsTo].map(memoryRef);
				for (const memory of memories) { changed = this.mergeFact(facts, factOwner, owner, constraint.from, memory, evidence, origin, budgets) || changed; }
				return changed;
			}
			case 'load': {
				let changed = false;
				const pointer = this.getFact(facts, factOwner, owner, constraint.pointer, budgets);
				const memories = constraint.memory ? [constraint.memory] : [...pointer.pointsTo].map(memoryRef);
				for (const memory of memories) { changed = this.mergeFact(facts, factOwner, owner, memory, constraint.to, evidence, origin, budgets) || changed; }
				return changed;
			}
			case 'base-offset': {
				let changed = this.mergeFact(facts, factOwner, owner, constraint.base, constraint.to, evidence, origin, budgets);
				const base = this.getFact(facts, factOwner, owner, constraint.base, budgets);
				const to = this.getFact(facts, factOwner, owner, constraint.to, budgets);
				const targets = [...base.pointsTo].map(target => `${target}+${constraint.offsetBytes}`);
				if (constraint.fieldIdentity) { targets.push(`field:${constraint.fieldIdentity}`); }
				changed = this.addPointsTo(to, targets, budgets) || changed;
				if (constraint.fieldTypeId) { changed = this.addTypeHypothesis(to, constraint.fieldTypeId, [evidence], origin, budgets) || changed; }
				return changed;
			}
			case 'call': return this.applyCall(facts, factOwner, owner, constraint.call, evidence, budgets);
			case 'return': return this.mergeFact(facts, factOwner, owner, constraint.from, returnRef(owner), evidence, origin, budgets);
			case 'out-parameter': return this.mergeFact(facts, factOwner, owner, constraint.from, parameterRef(owner, constraint.ordinal), evidence, origin, budgets);
			case 'global-read': return this.mergeFact(facts, factOwner, owner, globalRef(constraint.globalIdentity), constraint.to, evidence, origin, budgets);
			case 'global-write': return this.mergeFact(facts, factOwner, owner, constraint.from, globalRef(constraint.globalIdentity), evidence, origin, budgets);
			case 'relocation': {
				const fact = this.getFact(facts, factOwner, owner, constraint.to, budgets);
				let changed = this.addPointsTo(fact, constraint.targets, budgets);
				if (constraint.typeId) { changed = this.addTypeHypothesis(fact, constraint.typeId, [evidence], origin, budgets) || changed; }
				return changed;
			}
			case 'allocator-result': {
				const fact = this.getFact(facts, factOwner, owner, constraint.result, budgets);
				let changed = this.addPointsTo(fact, [constraint.allocationIdentity ?? `allocation:${owner}:${constraint.id}`], budgets);
				if (constraint.resultTypeId) { changed = this.addTypeHypothesis(fact, constraint.resultTypeId, [evidence], origin, budgets) || changed; }
				return changed;
			}
			case 'free': return false;
			case 'field-read': {
				const field = memoryRef(`field:${constraint.field.fieldIdentity}`);
				let changed = this.mergeFact(facts, factOwner, owner, field, constraint.to, evidence, origin, budgets);
				if (constraint.field.typeId) {
					changed = this.addTypeHypothesis(this.getFact(facts, factOwner, owner, constraint.to, budgets), constraint.field.typeId, [evidence], origin, budgets) || changed;
				}
				return changed;
			}
			case 'field-write': return this.mergeFact(facts, factOwner, owner, constraint.from, memoryRef(`field:${constraint.field.fieldIdentity}`), evidence, origin, budgets);
			case 'function-pointer': {
				const fact = this.getFact(facts, factOwner, owner, constraint.value, budgets);
				return this.addPointsTo(fact, constraint.targets.map(functionTargetIdentity), budgets);
			}
			case 'points-to': return this.addPointsTo(this.getFact(facts, factOwner, owner, constraint.value, budgets), constraint.targets, budgets);
			case 'barrier': {
				let changed = false;
				for (const value of constraint.values) {
					const fact = this.getFact(facts, factOwner, owner, value, budgets);
					const reason = `${constraint.lossy ? 'lossy' : 'unresolved'}:${constraint.id}:${constraint.reason}`;
					if (!fact.blockedReasons.has(reason)) { fact.blockedReasons.add(reason); changed = true; }
				}
				return changed;
			}
		}
	}

	private applyCall(
		facts: Map<string, MutableValueFact>, factOwner: Map<string, string>, owner: string,
		call: CallEffect, evidence: SemanticEvidence, budgets: SolverBudgets,
	): boolean {
		let changed = false;
		for (const argument of call.arguments) {
			changed = this.mergeFact(facts, factOwner, owner, argument.argument, parameterRef(call.calleeIdentity, argument.ordinal), evidence, `call:${call.callsiteIdentity}:arg:${argument.ordinal}`, budgets) || changed;
		}
		if (call.result) {
			changed = this.mergeFact(facts, factOwner, owner, returnRef(call.calleeIdentity), call.result, evidence, `call:${call.callsiteIdentity}:return`, budgets) || changed;
		}
		for (const output of call.outParameters ?? []) {
			changed = this.mergeFact(facts, factOwner, owner, parameterRef(call.calleeIdentity, output.ordinal), output.value, evidence, `call:${call.callsiteIdentity}:out:${output.ordinal}`, budgets) || changed;
		}
		if (call.indirectCandidates && call.indirectCandidates.length > 0) {
			const callsite = this.getFact(facts, factOwner, owner, { kind: 'function-pointer', identity: call.callsiteIdentity, functionIdentity: owner }, budgets);
			changed = this.addPointsTo(callsite, call.indirectCandidates.map(functionTargetIdentity), budgets) || changed;
		}
		return changed;
	}

	private applySummaryEffects(
		facts: Map<string, MutableValueFact>,
		factOwner: Map<string, string>,
		input: FunctionSummaryInput,
		generation: number,
		budgets: SolverBudgets,
	): boolean {
		const owner = input.functionIdentity;
		const evidence: SemanticEvidence = {
			strength: 'derived',
			source: 'dataflow',
			producer: 'whole-program-function-summary',
			generation,
		};
		let changed = false;
		for (const parameter of input.parameters ?? []) {
			const canonical = parameterRef(owner, parameter.ordinal);
			changed = this.mergeFact(facts, factOwner, owner, canonical, parameter.value, evidence, `summary:${owner}:parameter:${parameter.ordinal}`, budgets) || changed;
			changed = this.mergeFact(facts, factOwner, owner, parameter.value, canonical, evidence, `summary:${owner}:parameter:${parameter.ordinal}`, budgets) || changed;
			if (parameter.escapes) {
				const fact = this.getFact(facts, factOwner, owner, parameter.value, budgets);
				if (!fact.blockedReasons.has(`escape:parameter:${parameter.ordinal}`)) {
					fact.blockedReasons.add(`escape:parameter:${parameter.ordinal}`);
					changed = true;
				}
			}
		}
		for (const relationship of input.returnRelationships ?? []) {
			changed = this.mergeFact(facts, factOwner, owner, relationship.value, returnRef(owner), evidence, `summary:${owner}:return:${relationship.relation}`, budgets) || changed;
		}
		for (const call of input.calls ?? []) {
			changed = this.applyCall(facts, factOwner, owner, call, evidence, budgets) || changed;
		}
		for (const global of input.globalEffects ?? []) {
			if (!global.value) { continue; }
			if (global.access === 'read' || global.access === 'read-write') {
				changed = this.mergeFact(facts, factOwner, owner, globalRef(global.globalIdentity), global.value, evidence, `summary:${owner}:global-read:${global.globalIdentity}`, budgets) || changed;
			}
			if (global.access === 'write' || global.access === 'read-write') {
				changed = this.mergeFact(facts, factOwner, owner, global.value, globalRef(global.globalIdentity), evidence, `summary:${owner}:global-write:${global.globalIdentity}`, budgets) || changed;
			}
		}
		for (const field of input.fieldAccesses ?? []) {
			const stored = memoryRef(`field:${field.fieldIdentity}`);
			if (field.value && (field.access === 'read' || field.access === 'read-write')) {
				changed = this.mergeFact(facts, factOwner, owner, stored, field.value, evidence, `summary:${owner}:field-read:${field.fieldIdentity}`, budgets) || changed;
			}
			if (field.value && (field.access === 'write' || field.access === 'read-write')) {
				changed = this.mergeFact(facts, factOwner, owner, field.value, stored, evidence, `summary:${owner}:field-write:${field.fieldIdentity}`, budgets) || changed;
			}
			if (field.typeId && field.value) {
				changed = this.addTypeHypothesis(this.getFact(facts, factOwner, owner, field.value, budgets), field.typeId, [evidence], `summary:${owner}:field-type:${field.fieldIdentity}`, budgets) || changed;
			}
			if (field.access === 'address') {
				const base = this.getFact(facts, factOwner, owner, field.base, budgets);
				const target = field.value ? this.getFact(facts, factOwner, owner, field.value, budgets) : base;
				changed = this.addPointsTo(target, [
					...([...base.pointsTo].map(item => `${item}+${field.offsetBytes}`)),
					`field:${field.fieldIdentity}`,
				], budgets) || changed;
			}
		}
		for (const pointer of input.functionPointerTargets ?? []) {
			changed = this.addPointsTo(
				this.getFact(facts, factOwner, owner, pointer.value, budgets),
				pointer.targets.map(functionTargetIdentity),
				budgets,
			) || changed;
		}
		for (const ownership of input.ownershipEffects ?? []) {
			if (ownership.kind !== 'allocate' && ownership.kind !== 'acquire') { continue; }
			changed = this.addPointsTo(
				this.getFact(facts, factOwner, owner, ownership.value, budgets),
				[ownership.objectIdentity ?? `owned-object:${owner}:${ownership.kind}:${ownership.value.identity}`],
				budgets,
			) || changed;
		}
		return changed;
	}

	private importCanonicalFact(
		facts: Map<string, MutableValueFact>, factOwner: Map<string, string>, fact: PropagatedValueFact,
		owner: string, budgets: SolverBudgets,
	): void {
		const mutable = this.getFact(facts, factOwner, owner, fact.value, budgets);
		for (const hypothesis of fact.typeHypotheses) {
			this.addTypeHypothesis(mutable, hypothesis.typeId, hypothesis.evidenceSet, `persisted:${fact.factHash}`, budgets);
		}
		this.addPointsTo(mutable, fact.pointsTo, budgets);
		for (const source of fact.sources) { mutable.sources.add(source); }
		for (const reason of fact.blockedReasons) { mutable.blockedReasons.add(reason); }
	}

	private outputHashForFunction(
		functionIdentity: string,
		facts: ReadonlyMap<string, MutableValueFact>,
		factOwner: ReadonlyMap<string, string>,
		persisted: ReadonlyMap<string, FunctionPropagationSummary>,
	): string | null {
		const values = [...facts.entries()].filter(([key]) => factOwner.get(key) === functionIdentity)
			.map(([, fact]) => canonicalFact(fact, functionIdentity))
			.sort((a, b) => compareAscii(a.factHash, b.factHash));
		return values.length > 0 ? hashValue(values) : persisted.get(functionIdentity)?.outputHash ?? null;
	}

	private semanticInputHashes(inputs: readonly CanonicalInput[]): Map<string, readonly string[]> {
		const result = new Map<string, readonly string[]>();
		const globals = this.semanticStore.findTypeBindings(undefined, 'global').filter(item => this.isExternalSemanticBinding(item)).map(item => item.canonicalHash);
		for (const item of inputs) {
			const hashes = [
				...(this.semanticStore.getPrototype(item.input.functionIdentity) ? [this.semanticStore.getPrototype(item.input.functionIdentity)!.canonicalHash] : []),
				...this.semanticStore.findTypeBindings(item.input.functionIdentity).filter(binding => this.isExternalSemanticBinding(binding)).map(binding => binding.canonicalHash),
				...globals,
			].sort();
			result.set(item.input.functionIdentity, hashes);
		}
		return result;
	}

	private semanticSeedSnapshotHash(): string {
		return hashValue({
			types: this.semanticStore.listTypes().map(item => item.canonicalHash).sort(),
			prototypes: this.semanticStore.listPrototypes().map(item => item.canonicalHash).sort(),
			bindings: this.semanticStore.findTypeBindings().filter(item => this.isExternalSemanticBinding(item)).map(item => item.canonicalHash).sort(),
		});
	}

	private isExternalSemanticBinding(binding: CanonicalTypeBinding): boolean {
		return !binding.invalidationDependencies.some(item => item.startsWith('propagation-input:'));
	}

	private factReferencedByInput(key: string, input: FunctionSummaryInput, owner: string): boolean {
		const globals = new Set([
			...(input.globalEffects ?? []).map(item => valueKey(globalRef(item.globalIdentity), owner)),
			...(input.fieldAccesses ?? []).map(item => valueKey(memoryRef(`field:${item.fieldIdentity}`), owner)),
		]);
		return globals.has(key);
	}

	private derivedBindings(summaries: readonly FunctionPropagationSummary[]): CanonicalTypeBinding[] {
		const bindings: CanonicalTypeBinding[] = [];
		for (const summary of summaries) {
			for (const fact of summary.valueFacts) {
				if (!fact.acceptedTypeId || fact.conflict || fact.blockedReasons.length > 0 || !this.semanticStore.getType(fact.acceptedTypeId)) { continue; }
				const hypothesis = fact.typeHypotheses.find(item => item.typeId === fact.acceptedTypeId)!;
				const scope = this.bindingScope(fact.value.kind);
				if (!scope) { continue; }
				bindings.push(canonicalizeTypeBinding({
					targetIdentity: this.semanticStore.targetIdentity,
					scope,
					valueIdentity: fact.value.identity,
					...(!['global', 'memory-region', 'struct-field'].includes(scope) ? { functionIdentity: fact.value.functionIdentity ?? summary.functionIdentity } : {}),
					typeId: fact.acceptedTypeId,
					invalidationDependencies: [
						`propagation-input:${summary.inputHash}`,
						`function-body:${summary.functionBodySha256}`,
						...summary.dependencies.map(item => `function-summary:${item}`),
					],
					evidence: hypothesis.evidence,
					corroboratingEvidence: hypothesis.evidenceSet.slice(1),
				}));
			}
		}
		const unique = new Map(bindings.map(binding => [binding.bindingId, binding]));
		return [...unique.values()].sort((a, b) => compareAscii(a.bindingId, b.bindingId));
	}

	private bindingScope(kind: PropagationValueKind): TypeBindingScope | undefined {
		switch (kind) {
			case 'parameter': return 'function-parameter';
			case 'return': return 'return-value';
			case 'ssa':
			case 'function-pointer': return 'ssa-value';
			case 'register': return 'register-value';
			case 'stack-slot': return 'stack-slot';
			case 'global': return 'global';
			case 'memory-region': return 'memory-region';
			case 'field': return 'struct-field';
			case 'constant': return undefined;
		}
	}
}

export function referenceGraphInputHash(edges: readonly CanonicalReferenceEdge[]): string {
	return hashValue([...edges].map(edge => edge.canonicalHash).sort());
}

export function createPropagationSolverSnapshot(store: SemanticStore): PropagationSolverSnapshot {
	const propagation = store.getWholeProgramPropagationStore();
	const graph = store.getReferenceGraph();
	const latestAcceptedGeneration = propagation.latestAcceptedGeneration();
	const payload = {
		schemaVersion: 1 as const,
		targetIdentity: store.targetIdentity,
		types: store.listTypes(),
		prototypes: store.listPrototypes(),
		bindings: store.findTypeBindings(),
		referenceEdges: graph.listStoredEdges(false).map(item => item.edge),
		referenceGraphHash: graph.exportHash(),
		persistedSummaries: propagation.listSummaries(),
		dirty: propagation.listDirty(),
		...(latestAcceptedGeneration !== undefined ? { latestAcceptedGeneration } : {}),
	};
	return { ...payload, snapshotHash: propagationSnapshotHash(payload) };
}

export function createPropagationSolverContext(snapshot: PropagationSolverSnapshot): PropagationSolverContext {
	if (snapshot.schemaVersion !== 1) { throw new Error(`Unsupported propagation snapshot schema: ${String((snapshot as any).schemaVersion)}`); }
	const { snapshotHash, ...payload } = snapshot;
	if (propagationSnapshotHash(payload) !== snapshotHash) { throw new Error('Propagation snapshot hash mismatch.'); }
	const types = new Map(snapshot.types.map(type => [type.typeId, type]));
	const prototypes = new Map(snapshot.prototypes.map(prototype => [prototype.functionIdentity, prototype]));
	const bindings = [...snapshot.bindings];
	const edges = [...snapshot.referenceEdges];
	const bindingsByFunction = new Map<string, CanonicalTypeBinding[]>();
	for (const binding of bindings) {
		if (!binding.functionIdentity) continue;
		const indexed = bindingsByFunction.get(binding.functionIdentity) ?? [];
		indexed.push(binding);
		bindingsByFunction.set(binding.functionIdentity, indexed);
	}
	const outgoingByFunction = new Map<string, CanonicalReferenceEdge[]>();
	const incomingByIdentity = new Map<string, CanonicalReferenceEdge[]>();
	for (const edge of edges) {
		const outgoing = outgoingByFunction.get(edge.source.ownerFunctionIdentity) ?? [];
		outgoing.push(edge);
		outgoingByFunction.set(edge.source.ownerFunctionIdentity, outgoing);
		const incoming = incomingByIdentity.get(edge.target.identity) ?? [];
		incoming.push(edge);
		incomingByIdentity.set(edge.target.identity, incoming);
	}
	const filterEdges = (query: ReferenceQuery = {}): CanonicalReferenceEdge[] => {
		const direction = query.direction ?? 'both';
		let candidates: readonly CanonicalReferenceEdge[] = edges;
		if (query.functionIdentity) {
			if (direction === 'outgoing') {
				candidates = outgoingByFunction.get(query.functionIdentity) ?? [];
			} else if (direction === 'incoming') {
				candidates = incomingByIdentity.get(query.functionIdentity) ?? [];
			} else {
				const unique = new Map<string, CanonicalReferenceEdge>();
				for (const edge of outgoingByFunction.get(query.functionIdentity) ?? []) unique.set(edge.edgeId, edge);
				for (const edge of incomingByIdentity.get(query.functionIdentity) ?? []) unique.set(edge.edgeId, edge);
				candidates = [...unique.values()];
			}
		}
		return candidates.filter(edge => {
			if (query.functionIdentity) {
				const outgoing = edge.source.ownerFunctionIdentity === query.functionIdentity;
				const incoming = edge.target.identity === query.functionIdentity;
				if (direction === 'outgoing' ? !outgoing : direction === 'incoming' ? !incoming : !(outgoing || incoming)) return false;
			}
			if (query.address && edge.source.address !== query.address && edge.target.address !== query.address) return false;
			if (query.relations && !query.relations.includes(edge.relation)) return false;
			if (query.families && !query.families.includes(edge.family)) return false;
			if (query.targetKind && edge.target.kind !== query.targetKind) return false;
			if (query.targetIdentity && edge.target.identity !== query.targetIdentity) return false;
			if (query.typeId && edge.target.typeId !== query.typeId) return false;
			if (query.memberIdentity && edge.target.memberIdentity !== query.memberIdentity) return false;
			return true;
		}).sort((left, right) => compareAscii(left.edgeId, right.edgeId));
	};
	const callRelations = new Set(['code-call-near', 'code-call-far', 'code-tail-call', 'code-indirect-resolved', 'code-indirect-candidate']);
	return {
		semanticStore: {
			targetIdentity: snapshot.targetIdentity,
			getPrototype: functionIdentity => prototypes.get(functionIdentity),
			findTypeBindings: (functionIdentity, scope) => (functionIdentity === undefined
				? bindings
				: bindingsByFunction.get(functionIdentity) ?? []).filter(binding =>
				(functionIdentity === undefined || binding.functionIdentity === functionIdentity) &&
				(scope === undefined || binding.scope === scope)),
			listTypes: () => [...snapshot.types],
			listPrototypes: () => [...snapshot.prototypes],
			getType: typeId => types.get(typeId),
		},
		persistence: {
			listSummaries: () => [...snapshot.persistedSummaries],
			listDirty: () => [...snapshot.dirty],
			latestAcceptedGeneration: () => snapshot.latestAcceptedGeneration,
		},
		referenceGraph: {
			query: filterEdges,
			getCallees: (functionIdentity, includeCandidates = false) => filterEdges({
				direction: 'outgoing', functionIdentity,
			}).filter(edge => callRelations.has(edge.relation) && (includeCandidates || edge.relation !== 'code-indirect-candidate'))
				.map(edge => ({ calleeIdentity: edge.target.identity })),
			exportHash: () => snapshot.referenceGraphHash,
		},
	};
}

export function commitPropagationComputation(
	store: SemanticStore,
	run: PropagationRunResult,
	bindings: readonly CanonicalTypeBinding[],
): PropagationRunResult {
	if (run.status !== 'committed' || !run.committed) return run;
	const semanticWrites = store.getWholeProgramPropagationStore().commitAcceptedRun(
		run,
		() => store.writeBatch({ typeBindings: bindings }),
	);
	return { ...run, semanticWrites };
}
