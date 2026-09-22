/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import type { AnalysisEngineIdentity } from 'hexcore-common';
import type { SessionStore } from './sessionStore';
import { canonicalSerialize } from './semanticModel';
import type { SemanticQueryData } from './semanticStore';
import { filterReferenceEdges, type ReferenceQuery, type ReferenceGenerationDiff } from './typedReferenceGraph';

export interface SemanticQueryIdentity {
	targetIdentity: string;
	architecture: string;
	format: string;
	sessionId: string;
	generation: number;
	universeSha256: string;
	snapshotSha256: string;
	propagationGeneration: number | null;
	referenceGeneration: number | null;
	engineGeneration?: number;
	engines: readonly AnalysisEngineIdentity[];
}

export interface SemanticQueryOptions {
	expectedTargetIdentity?: string;
	expectedGeneration?: number;
	expectedUniverseSha256?: string;
	expectedSnapshotSha256?: string;
	engineGeneration?: number;
	maxRows?: number;
	maxBytes?: number;
}

type Annotations = ReturnType<SessionStore['readSemanticQueryAnnotations']>;
export interface SemanticQueryCoverage {
	status: 'ok' | 'partial';
	/** These counts describe persisted index/replay state, not complete binary coverage. */
	knownFunctions: number | null;
	universeMaterializations: number;
	dirtySummaries: number;
	semanticReadErrors: number;
	negativeEvidenceUsable: false;
	unavailableCollections: readonly string[];
	errors: readonly { collection: string; code: string; detail: string }[];
}

export interface SemanticQuerySnapshot {
	identity: SemanticQueryIdentity;
	coverage: SemanticQueryCoverage;
	data: SemanticQueryData;
	annotations: Annotations;
	generationDiff?: ReferenceGenerationDiff;
}

function freeze<T>(value: T): T {
	if (value && typeof value === 'object' && !Object.isFrozen(value)) {
		for (const child of Object.values(value)) { freeze(child); }
		Object.freeze(value);
	}
	return value;
}

function digest(value: unknown): string { return crypto.createHash('sha256').update(canonicalSerialize(value)).digest('hex'); }

export class SemanticQueryView {
	readonly identity: Readonly<SemanticQueryIdentity>;
	readonly #unavailable: ReadonlySet<string>;
	readonly #snapshot: SemanticQuerySnapshot;
	constructor(snapshot: SemanticQuerySnapshot, token: typeof constructionToken) {
		if (token !== constructionToken) { throw new Error('Use openSemanticQueryView to capture a validated snapshot'); }
		this.#snapshot = freeze(JSON.parse(canonicalSerialize(snapshot)) as SemanticQuerySnapshot);
		this.identity = this.#snapshot.identity;
		this.#unavailable = new Set(this.#snapshot.coverage.unavailableCollections);
		Object.freeze(this);
	}

	assertIdentity(expected: Pick<SemanticQueryIdentity, 'targetIdentity' | 'generation' | 'universeSha256'> & { snapshotSha256?: string }): void {
		for (const key of ['targetIdentity', 'generation', 'universeSha256', 'snapshotSha256'] as const) {
			if (expected[key] !== undefined && expected[key] !== this.identity[key]) { throw new Error(`semantic-query-identity-mismatch: ${key}`); }
		}
	}

	getCoverage(): Readonly<SemanticQueryCoverage> { return this.#snapshot.coverage; }
	exportSnapshot(): Readonly<SemanticQuerySnapshot> { return this.#snapshot; }
	private collection<K extends keyof SemanticQueryData>(name: K): Readonly<SemanticQueryData[K]> {
		if (this.#unavailable.has(name)) { throw new Error(`semantic-query-collection-unavailable: ${name}`); }
		return this.#snapshot.data[name];
	}
	listTypes() { return this.collection('types'); }
	listPrototypes() { return this.collection('prototypes'); }
	getPrototype(functionIdentity: string) { return this.collection('prototypes').find(record => record.functionIdentity === functionIdentity); }
	getPrototypeAtAddress(address: string) {
		return this.collection('prototypes').find(record => record.functionAddress?.toLowerCase() === address.toLowerCase());
	}
	findTypeBindings(functionIdentity?: string) {
		return Object.freeze(this.collection('bindings').filter(record => functionIdentity === undefined || record.functionIdentity === functionIdentity));
	}
	queryReferences(query: ReferenceQuery = {}) {
		if (query.includeInvalidated) { throw new Error('semantic-query: this view exposes accepted active references, not invalidated history'); }
		if (query.atGeneration !== undefined && query.atGeneration !== this.identity.referenceGeneration) { throw new Error('semantic-query-identity-mismatch: reference generation'); }
		return Object.freeze(filterReferenceEdges(this.collection('references'), query));
	}
	getPropagationSummary(functionIdentity: string) {
		if (this.collection('dirty').some(record => record.functionIdentity === functionIdentity)) { throw new Error(`semantic-query-stale-summary: ${functionIdentity}`); }
		return this.collection('summaries').find(record => record.functionIdentity === functionIdentity);
	}
	listPropagationSummaries() {
		const dirty = new Set(this.collection('dirty').map(record => record.functionIdentity));
		return Object.freeze(this.collection('summaries').filter(record => !dirty.has(record.functionIdentity)));
	}
	listConflicts(functionIdentity?: string) {
		return Object.freeze(this.collection('conflicts').filter(record => functionIdentity === undefined || record.factKey === functionIdentity || `function:${record.factKey}` === functionIdentity));
	}
	listReferenceConflicts() { return this.collection('referenceConflicts'); }
	listPropagationConflicts(functionIdentity?: string) {
		return Object.freeze(this.collection('summaries').filter(summary => !functionIdentity || summary.functionIdentity === functionIdentity)
			.flatMap(summary => summary.conflicts.map(conflict => freeze({ functionIdentity: summary.functionIdentity, conflict }))));
	}
	listBarriers(functionIdentity?: string) {
		return Object.freeze(this.collection('summaries').filter(summary => !functionIdentity || summary.functionIdentity === functionIdentity)
			.flatMap(summary => summary.barriers.map(barrier => freeze({ functionIdentity: summary.functionIdentity, barrier }))));
	}
	getFunction(address: string) {
		if (this.#unavailable.has('annotations')) { throw new Error('semantic-query-collection-unavailable: annotations'); }
		return this.#snapshot.annotations.functions.find(record => record.address.toLowerCase() === address.toLowerCase());
	}
	getVariables(address: string) {
		if (this.#unavailable.has('annotations')) { throw new Error('semantic-query-collection-unavailable: annotations'); }
		return Object.freeze(this.#snapshot.annotations.variables.filter(record => record.func_address.toLowerCase() === address.toLowerCase()));
	}
	page<K extends keyof SemanticQueryData>(collection: K, options: { offset?: number; limit?: number; snapshotSha256?: string } = {}) {
		if (options.snapshotSha256 && options.snapshotSha256 !== this.identity.snapshotSha256) { throw new Error('semantic-query-identity-mismatch: pagination snapshot'); }
		const offset = options.offset ?? 0;
		const limit = options.limit ?? 100;
		if (!Number.isSafeInteger(offset) || offset < 0 || !Number.isSafeInteger(limit) || limit < 1 || limit > 10000) { throw new Error('semantic-query: invalid page bounds'); }
		const rows = this.collection(collection);
		return freeze({ snapshotSha256: this.identity.snapshotSha256, total: rows.length, offset,
			nextOffset: offset + limit < rows.length ? offset + limit : null, rows: rows.slice(offset, offset + limit) });
	}
}

const constructionToken = Symbol('semantic-query-view');
const cache = new WeakMap<SessionStore, { revision: string; options: string; view: SemanticQueryView }>();

export function openSemanticQueryView(session: SessionStore, options: SemanticQueryOptions = {}): SemanticQueryView {
	const maxRows = options.maxRows ?? 100000;
	const maxBytes = options.maxBytes ?? 64 * 1024 * 1024;
	if (!Number.isSafeInteger(maxRows) || maxRows < 1 || maxRows > 1000000 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 256 * 1024 * 1024) { throw new Error('semantic-query: invalid snapshot budget'); }
	const revision = session.getSemanticReadRevision();
	const optionKey = canonicalSerialize(options);
	const existing = cache.get(session);
	if (existing?.revision === revision && existing.options === optionKey) { return existing.view; }
	const view = session.withSemanticReadSnapshot(() => {
		const target = session.getAnalysisTarget();
		const bound = session.getAnalysisSession();
		if (!target || !bound) { throw new Error('semantic-query: target/session identity unavailable'); }
		const persisted = JSON.parse(session.getMeta('analysis_session_json') ?? 'null');
		const persistedTarget = JSON.parse(session.getMeta('analysis_target_json') ?? 'null');
		const universe = session.getAnalysisUniverseManifest();
		const binding = JSON.parse(session.getMeta('analysis_generation_universe_json') ?? 'null');
		if (persisted?.id !== bound.id || persisted?.generation !== bound.generation || persisted?.targetId !== target.id || persistedTarget?.id !== target.id ||
			persistedTarget?.architecture !== target.architecture || persistedTarget?.format !== target.format) { throw new Error('semantic-query: stale live session or wrong target'); }
		if (!universe || universe.binarySha256 !== target.binarySha256 || binding?.generation !== bound.generation || binding?.universeSha256 !== universe.universeSha256) { throw new Error('semantic-query: unbound or stale replay universe'); }
		const universeDigest = crypto.createHash('sha256').update(JSON.stringify({ schemaVersion: 1, binarySha256: universe.binarySha256, materializedFunctions: universe.materializedFunctions })).digest('hex');
		if (universeDigest !== universe.universeSha256) { throw new Error('semantic-query: replay universe digest mismatch'); }
		if (options.expectedTargetIdentity !== undefined && options.expectedTargetIdentity !== target.id) { throw new Error('semantic-query-identity-mismatch: targetIdentity'); }
		if (options.expectedGeneration !== undefined && options.expectedGeneration !== bound.generation) { throw new Error('semantic-query-identity-mismatch: generation'); }
		if (options.expectedUniverseSha256 !== undefined && options.expectedUniverseSha256 !== universe.universeSha256) { throw new Error('semantic-query-identity-mismatch: universeSha256'); }
		const store = session.getSemanticStore(); store.assertOwnedBy(target.id);
		let annotations: Annotations = { functions: [], variables: [], cachedFunctions: 0 };
		const errors: Array<{ collection: string; code: string; detail: string }> = [];
		try { annotations = session.readSemanticQueryAnnotations(maxRows, maxBytes); }
		catch (error) { errors.push({ collection: 'annotations', code: 'read-failed', detail: error instanceof Error ? error.message : String(error) }); }
		const annotationBytes = Buffer.byteLength(canonicalSerialize(annotations));
		const read = store.readQueryData(Math.max(0, maxRows - annotations.functions.length - annotations.variables.length), Math.max(0, maxBytes - annotationBytes));
		errors.push(...read.errors);
		const data = read.data;
		const referenceGenerations = [...new Set([...data.referenceVersions.map(record => record.generation), ...data.references.map(record => record.generation)])].sort((a, b) => a - b);
		let generationDiff: ReferenceGenerationDiff | undefined;
		if (referenceGenerations.length > 1 && !read.errors.some(error => error.collection === 'referenceVersions')) {
			try { generationDiff = store.getReferenceGraph().diffGenerations(referenceGenerations[referenceGenerations.length - 2], referenceGenerations[referenceGenerations.length - 1]); }
			catch (error) { errors.push({ collection: 'generationDiff', code: 'read-failed', detail: error instanceof Error ? error.message : String(error) }); }
		}
		const identityBase = {
			targetIdentity: target.id, sessionId: bound.id, generation: bound.generation, universeSha256: universe.universeSha256,
			architecture: target.architecture ?? 'unknown', format: target.format,
			propagationGeneration: data.summaries.reduce<number | null>((maximum, summary) => maximum === null ? summary.generation : Math.max(maximum, summary.generation), null),
			referenceGeneration: referenceGenerations[referenceGenerations.length - 1] ?? null,
			engines: [...bound.engines].sort((a, b) => { const left = canonicalSerialize(a), right = canonicalSerialize(b); return left < right ? -1 : left > right ? 1 : 0; }),
		};
		const coverage: SemanticQueryCoverage = { status: errors.length || data.dirty.length ? 'partial' : 'ok',
			knownFunctions: annotations.cachedFunctions || null, universeMaterializations: universe.materializedFunctions.length,
			dirtySummaries: data.dirty.length, semanticReadErrors: errors.length, negativeEvidenceUsable: false,
			unavailableCollections: errors.map(error => error.collection), errors };
		const hashPayload = { identity: identityBase, data, annotations, generationDiff, coverage: { ...coverage, errors: errors.map(({ collection, code }) => ({ collection, code })) } };
		if (Buffer.byteLength(canonicalSerialize(hashPayload)) > maxBytes) { throw new Error('semantic-query: final snapshot byte budget exceeded'); }
		const snapshotSha256 = digest(hashPayload);
		if (options.expectedSnapshotSha256 !== undefined && options.expectedSnapshotSha256 !== snapshotSha256) { throw new Error('semantic-query-identity-mismatch: snapshotSha256'); }
		return new SemanticQueryView({ identity: { ...identityBase, snapshotSha256, ...(options.engineGeneration !== undefined ? { engineGeneration: options.engineGeneration } : {}) }, coverage, data, annotations, ...(generationDiff ? { generationDiff } : {}) }, constructionToken);
	});
	cache.set(session, { revision, options: optionKey, view });
	return view;
}
