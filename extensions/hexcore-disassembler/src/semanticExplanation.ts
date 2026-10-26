/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import { canonicalSerialize, type SemanticEvidence } from './semanticModel';
import type { SemanticQueryIdentity, SemanticQueryView } from './semanticQueryView';
import type { FunctionPropagationSummary } from './wholeProgramPropagation';

export type SemanticExplanationKind = 'prototype' | 'type-binding' | 'typed-reference' | 'propagation-effect' | 'semantic-conflict' | 'hql-semantic-match';
export interface SemanticExplanationRequest {
	kind: SemanticExplanationKind;
	identity: string;
	expected?: Partial<Pick<SemanticQueryIdentity, 'targetIdentity' | 'sessionId' | 'generation' | 'universeSha256' | 'snapshotSha256'>>;
	maxNodes?: number;
	maxEdges?: number;
	maxBytes?: number;
}
export interface ExplanationNode { id: string; kind: string; label: string; data: unknown; proofStatus?: 'signal' | 'candidate' | 'proven' }
export interface ExplanationEdge { from: string; to: string; relation: string; source: 'persisted-field' | 'record-origin' }
export interface SemanticExplanationResult {
	success: boolean;
	status: 'ok' | 'partial' | 'unknown' | 'error';
	identity: Readonly<SemanticQueryIdentity>;
	request: { kind: SemanticExplanationKind; identity: string };
	claim: ExplanationNode | null;
	nodes: ExplanationNode[];
	edges: ExplanationEdge[];
	evidenceChain: Array<{ stage: string; nodeId: string; proofStatus?: 'signal' | 'candidate' | 'proven'; producer?: string; source?: string; strength?: string; generation?: number; functionIdentity?: string; address?: string }>;
	conflicts: unknown[];
	barriers: unknown[];
	missingLinks: string[];
	navigation: Array<{ functionIdentity: string; address?: string }>;
	truncated: boolean;
	explanationSha256: string;
	error?: string;
}

const sha256 = (value: unknown) => crypto.createHash('sha256').update(typeof value === 'string' ? value : canonicalSerialize(value)).digest('hex');
const strength = (value: string | undefined): 'signal' | 'candidate' | 'proven' => value === 'debug' || value === 'definitive' ? 'proven' : value === 'signature' || value === 'derived' ? 'candidate' : 'signal';
function lower(left: 'signal' | 'candidate' | 'proven', right: 'signal' | 'candidate' | 'proven') { return ({ signal: 0, candidate: 1, proven: 2 }[left] <= { signal: 0, candidate: 1, proven: 2 }[right] ? left : right); }
function record(value: unknown): value is Record<string, any> { return !!value && typeof value === 'object' && !Array.isArray(value); }
function addressFromFunction(identity: string): string | undefined { const match = /^function:(0x[0-9a-f]+)$/i.exec(identity); return match?.[1].toLowerCase(); }

export function propagationEffectIdentity(functionIdentity: string, generation: number, category: string, effect: unknown): string {
	return `effect:${category}:sha256:${sha256({ functionIdentity, generation, category, effect })}`;
}
export function hqlSemanticExplanationIdentity(origin: { snapshotSha256: string; collection: string; recordSha256: string }, effectIdentity?: string): string {
	return `hql-semantic:${origin.snapshotSha256}:${origin.collection}:${origin.recordSha256}${effectIdentity ? `:${effectIdentity}` : ''}`;
}

class Graph {
	readonly nodes = new Map<string, ExplanationNode>();
	readonly edges = new Map<string, ExplanationEdge>();
	readonly missing = new Set<string>();
	readonly conflicts: unknown[] = [];
	readonly barriers: unknown[] = [];
	readonly navigation = new Map<string, { functionIdentity: string; address?: string }>();
	truncated = false;
	constructor(readonly maxNodes: number, readonly maxEdges: number) {}
	addNode(node: ExplanationNode): ExplanationNode | undefined {
		const existing = this.nodes.get(node.id); if (existing) { return existing; }
		if (this.nodes.size >= this.maxNodes) { this.truncated = true; this.missing.add('node budget exhausted'); return undefined; }
		this.nodes.set(node.id, node); return node;
	}
	addEdge(from: string, to: string, relation: string, source: ExplanationEdge['source'] = 'persisted-field'): void {
		if (!this.nodes.has(from) || !this.nodes.has(to)) { return; }
		const edge = { from, to, relation, source };
		const key = canonicalSerialize(edge); if (this.edges.has(key)) { return; }
		if (this.edges.size >= this.maxEdges) { this.truncated = true; this.missing.add('edge budget exhausted'); return; }
		this.edges.set(key, edge);
	}
	addNavigation(functionIdentity: string, address?: string): void {
		if (!functionIdentity) { return; }
		const at = address ?? addressFromFunction(functionIdentity);
		this.navigation.set(`${functionIdentity}:${at ?? ''}`, { functionIdentity, ...(at ? { address: at } : {}) });
	}
}

function evidenceNodes(graph: Graph, owner: ExplanationNode, evidenceSet: readonly SemanticEvidence[] | undefined): 'signal' | 'candidate' | 'proven' {
	let proof: 'signal' | 'candidate' | 'proven' = 'proven';
	if (!evidenceSet?.length) { graph.missing.add(`producer provenance missing for ${owner.id}`); return 'signal'; }
	for (const evidence of evidenceSet) {
		const normalized = { producer: evidence.producer, source: evidence.source, strength: evidence.strength, generation: evidence.generation,
			...(evidence.userDefined ? { userDefined: true } : {}), ...(evidence.confidence !== undefined ? { confidence: evidence.confidence } : {}) };
		const id = `evidence:sha256:${sha256(normalized)}`;
		const status = strength(evidence.strength); proof = lower(proof, status);
		graph.addNode({ id, kind: 'evidence', label: `${evidence.producer} / ${evidence.source}`, data: normalized, proofStatus: status });
		graph.addEdge(id, owner.id, 'supports');
	}
	return proof;
}

function functionNode(graph: Graph, identity: string, address?: string): ExplanationNode | undefined {
	const at = address ?? addressFromFunction(identity);
	const node = graph.addNode({ id: identity, kind: 'function', label: identity, data: { functionIdentity: identity, ...(at ? { address: at } : {}) } });
	graph.addNavigation(identity, at); return node;
}
function typeNode(graph: Graph, typeId: string, allTypes: readonly any[]): ExplanationNode | undefined {
	const type = allTypes.find(candidate => candidate.typeId === typeId);
	if (!type) { graph.missing.add(`type record unavailable: ${typeId}`); return undefined; }
	const node = graph.addNode({ id: typeId, kind: 'type', label: type.name ?? typeId, data: type });
	if (node) node.proofStatus = evidenceNodes(graph, node, type.evidenceSet ?? (type.evidence ? [type.evidence] : []));
	return node;
}

const effectCollections = [
	['parameter', 'parameterEffects'], ['return', 'returnRelationships'], ['call', 'calls'], ['global', 'globalEffects'],
	['ownership', 'ownershipEffects'], ['field', 'fieldAccesses'], ['function-pointer', 'functionPointerTargets'],
] as const;
function findEffect(summaries: readonly FunctionPropagationSummary[], identity: string) {
	for (const summary of summaries) for (const [category, field] of effectCollections) for (const effect of summary[field] as readonly unknown[]) {
		if (propagationEffectIdentity(summary.functionIdentity, summary.generation, category, effect) === identity) return { summary, category, effect };
	}
	return undefined;
}

/** Bind the claim to the selected persisted effect and its owning summary. */
function addEffectClaim(graph: Graph, request: SemanticExplanationRequest, found: NonNullable<ReturnType<typeof findEffect>>, references: readonly any[]): ExplanationNode | null {
	const claim = graph.addNode({ id: request.identity, kind: request.kind, label: found.category, data: found.effect }) ?? null;
	if (claim) {
		const raw = found.effect as any;
		const evidence = raw?.evidence ? [raw.evidence] : raw?.value?.evidence ? [raw.value.evidence] : raw?.base?.evidence ? [raw.base.evidence] : [];
		claim.proofStatus = evidenceNodes(graph, claim, evidence);
		addSummaryContext(graph, claim, found.summary, references);
	}
	return claim;
}

function addSummaryContext(graph: Graph, owner: ExplanationNode, summary: FunctionPropagationSummary, references: readonly any[]): void {
	const summaryId = `summary:${summary.functionIdentity}:sha256:${summary.outputHash}`;
	graph.addNode({ id: summaryId, kind: 'propagation-summary', label: summary.functionIdentity, data: { functionIdentity: summary.functionIdentity, generation: summary.generation, inputHash: summary.inputHash, outputHash: summary.outputHash } });
	graph.addEdge(summaryId, owner.id, 'contains');
	const fn = functionNode(graph, summary.functionIdentity); if (fn) graph.addEdge(fn.id, summaryId, 'summarized-by');
	for (const hash of summary.referenceEdgeHashes) {
		const edge = references.find(reference => reference.canonicalHash === hash);
		if (!edge) { graph.missing.add(`referenced edge unavailable: ${hash}`); continue; }
		const id = edge.edgeId;
		graph.addNode({ id, kind: 'typed-reference', label: edge.relation, data: edge, proofStatus: strength(edge.evidence?.strength) });
		graph.addEdge(id, summaryId, 'summary-input');
	}
	for (const dependency of summary.dependencies) {
		const fn = functionNode(graph, dependency); if (fn) graph.addEdge(fn.id, summaryId, 'depends-on');
	}
	for (const barrier of summary.barriers) {
		const id = `barrier:${summary.functionIdentity}:sha256:${sha256(barrier)}`;
		const node = graph.addNode({ id, kind: 'barrier', label: barrier.reason, data: barrier, proofStatus: 'signal' });
		if (node) { graph.addEdge(id, summaryId, 'blocks'); graph.barriers.push(barrier); if (barrier.lossy) graph.missing.add(`lossy propagation barrier: ${barrier.reason}`); }
	}
	for (const conflict of summary.conflicts.slice(0, graph.maxNodes)) { graph.conflicts.push(conflict); graph.missing.add(`propagation conflict: ${conflict.valueIdentity}`); }
	if (summary.conflicts.length > graph.maxNodes) { graph.truncated = true; graph.missing.add('conflict budget exhausted'); }
}

function finalize(view: SemanticQueryView, request: SemanticExplanationRequest, graph: Graph, claim: ExplanationNode | null, status?: SemanticExplanationResult['status'], error?: string): SemanticExplanationResult {
	const nodes = [...graph.nodes.values()].sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
	const edges = [...graph.edges.values()].sort((a, b) => { const left = canonicalSerialize(a), right = canonicalSerialize(b); return left < right ? -1 : left > right ? 1 : 0; });
	const missingLinks = [...graph.missing].sort();
	const navigation = [...graph.navigation.values()].sort((a, b) => { const left = `${a.functionIdentity}:${a.address ?? ''}`, right = `${b.functionIdentity}:${b.address ?? ''}`; return left < right ? -1 : left > right ? 1 : 0; });
	const evidenceChain = nodes.filter(node => ['evidence', 'reference-origin', 'function', 'typed-reference', 'propagation-summary', 'barrier'].includes(node.kind)).map(node => {
		const data = record(node.data) ? node.data : {};
		return { stage: node.kind, nodeId: node.id, ...(node.proofStatus ? { proofStatus: node.proofStatus } : {}),
			...(typeof data.producer === 'string' ? { producer: data.producer } : typeof data.sourceEngine === 'string' ? { producer: data.sourceEngine } : {}),
			...(typeof data.source === 'string' ? { source: data.source } : {}), ...(typeof data.strength === 'string' ? { strength: data.strength } : {}),
			...(Number.isSafeInteger(data.generation) ? { generation: data.generation } : {}), ...(typeof data.functionIdentity === 'string' ? { functionIdentity: data.functionIdentity } : {}),
			...(typeof data.address === 'string' ? { address: data.address } : typeof data.evidenceAddress === 'string' ? { address: data.evidenceAddress } : {}) };
	});
	const resolvedStatus = status ?? (!claim ? 'unknown' : graph.truncated || missingLinks.length || graph.conflicts.length || graph.barriers.some((barrier: any) => barrier?.lossy) ? 'partial' : 'ok');
	const base = { success: resolvedStatus !== 'error', status: resolvedStatus, identity: view.identity, request: { kind: request.kind, identity: request.identity }, claim, nodes, edges, evidenceChain,
		conflicts: graph.conflicts, barriers: graph.barriers, missingLinks, navigation, truncated: graph.truncated, ...(error ? { error } : {}) };
	const { engineGeneration: _observation, ...logicalIdentity } = base.identity;
	return { ...base, explanationSha256: sha256({ ...base, identity: logicalIdentity }) };
}

export function explainSemanticEntity(view: SemanticQueryView, request: SemanticExplanationRequest): SemanticExplanationResult {
	if (!request || !['prototype', 'type-binding', 'typed-reference', 'propagation-effect', 'semantic-conflict', 'hql-semantic-match'].includes(request.kind) || typeof request.identity !== 'string' || !request.identity || request.identity.length > 4096) {
		const graph = new Graph(1, 1); return finalize(view, request ?? { kind: 'prototype', identity: '' }, graph, null, 'error', 'invalid semantic explanation request');
	}
	for (const [key, expected] of Object.entries(request.expected ?? {})) if (expected !== undefined && (view.identity as any)[key] !== expected) {
		const graph = new Graph(1, 1); return finalize(view, request, graph, null, 'error', `semantic explanation identity mismatch: ${key}`);
	}
	const bounded = (value: number | undefined, fallback: number, maximum: number, name: string) => { const result = value ?? fallback; if (!Number.isSafeInteger(result) || result < 1 || result > maximum) throw new Error(`invalid ${name}`); return result; };
	let maxNodes: number, maxEdges: number, maxBytes: number;
	try { maxNodes = bounded(request.maxNodes, 256, 4096, 'maxNodes'); maxEdges = bounded(request.maxEdges, 512, 8192, 'maxEdges'); maxBytes = bounded(request.maxBytes, 4 * 1024 * 1024, 16 * 1024 * 1024, 'maxBytes'); if (maxBytes < 4096) throw new Error('maxBytes must be at least 4096'); }
	catch (error) { return finalize(view, request, new Graph(1, 1), null, 'error', error instanceof Error ? error.message : String(error)); }
	const graph = new Graph(maxNodes, maxEdges);
	const snapshot = view.exportSnapshot(); const data = snapshot.data;
	let claim: ExplanationNode | null = null;
	try {
		if (request.kind === 'prototype') {
			const item = view.listPrototypes().find(record => record.prototypeId === request.identity);
			if (item) {
				claim = graph.addNode({ id: item.prototypeId, kind: request.kind, label: item.functionIdentity, data: item }) ?? null;
				if (claim) { claim.proofStatus = evidenceNodes(graph, claim, item.evidenceSet); const fn = functionNode(graph, item.functionIdentity, item.functionAddress); if (fn) graph.addEdge(claim.id, fn.id, 'describes'); const type = typeNode(graph, item.returnTypeId, data.types); if (type) graph.addEdge(claim.id, type.id, 'returns'); for (const parameter of item.parameters) { const ptype = typeNode(graph, parameter.typeId, data.types); if (ptype) graph.addEdge(claim.id, ptype.id, `parameter-${parameter.ordinal}`); } }
			}
		} else if (request.kind === 'type-binding') {
			const item = view.findTypeBindings().find(record => record.bindingId === request.identity);
			if (item) {
				claim = graph.addNode({ id: item.bindingId, kind: request.kind, label: item.valueIdentity, data: item }) ?? null;
				if (claim) { claim.proofStatus = evidenceNodes(graph, claim, item.evidenceSet); if (item.functionIdentity) { const fn = functionNode(graph, item.functionIdentity); if (fn) graph.addEdge(claim.id, fn.id, 'scoped-to'); } const type = typeNode(graph, item.typeId, data.types); if (type) graph.addEdge(claim.id, type.id, 'binds-type'); for (const dependency of item.invalidationDependencies) { const node = graph.addNode({ id: `dependency:${dependency}`, kind: 'invalidation-dependency', label: dependency, data: { key: dependency } }); if (node) graph.addEdge(node.id, claim.id, 'validates'); } }
			}
		} else if (request.kind === 'typed-reference') {
			const item = view.queryReferences().find(record => record.edgeId === request.identity);
			if (item) {
				claim = graph.addNode({ id: item.edgeId, kind: request.kind, label: item.relation, data: item }) ?? null;
				if (claim) {
					claim.proofStatus = evidenceNodes(graph, claim, item.evidenceSet);
					const fn = functionNode(graph, item.source.ownerFunctionIdentity, item.source.address); if (fn) graph.addEdge(fn.id, claim.id, 'source');
					const target = graph.addNode({ id: item.target.identity, kind: item.target.kind, label: item.target.identity, data: item.target }); if (target) graph.addEdge(claim.id, target.id, 'targets');
					for (const provenance of item.provenanceSet) { const id = `reference-origin:sha256:${sha256(provenance)}`; graph.addNode({ id, kind: 'reference-origin', label: provenance.sourceEngine, data: provenance }); graph.addEdge(id, claim.id, 'decoded-from', 'record-origin'); }
					if (!item.provenanceSet.length) graph.missing.add(`reference origin missing for ${item.edgeId}`);
					for (const dependency of item.invalidationDependencies) { const id = `dependency:${dependency.kind}:${dependency.key}`; graph.addNode({ id, kind: 'invalidation-dependency', label: dependency.key, data: dependency }); graph.addEdge(id, claim.id, 'validates'); }
				}
			}
		} else if (request.kind === 'propagation-effect') {
			const found = findEffect(view.listPropagationSummaries(), request.identity);
			if (found) { claim = addEffectClaim(graph, request, found, data.references); }
		} else if (request.kind === 'semantic-conflict') {
			const item = data.conflicts.find(conflict => conflict.conflictHash === request.identity) ?? data.referenceConflicts.find(conflict => conflict.conflictHash === request.identity);
			if (item) { claim = graph.addNode({ id: item.conflictHash, kind: request.kind, label: item.reason, data: item, proofStatus: 'signal' }) ?? null; graph.conflicts.push(item); graph.missing.add(`conflicting semantic records: ${item.winnerHash} / ${item.loserHash}`); }
		} else {
			const match = /^hql-semantic:([a-f0-9]{64}):([A-Za-z]+):([a-f0-9]{64})(?::(effect:[a-z-]+:sha256:[a-f0-9]{64}))?$/.exec(request.identity);
			if (!match || match[1] !== view.identity.snapshotSha256) { graph.missing.add('HQL semantic match identity is stale or malformed'); }
			else {
				const collection = match[2] as keyof typeof data; const rows = (data as any)[collection];
				if (!Array.isArray(rows)) graph.missing.add(`HQL origin collection unavailable: ${collection}`);
				else {
					const item = rows.find((record: unknown) => sha256(record) === match[3]);
					if (item && match[4]) {
						const found = collection === 'summaries' ? findEffect([item], match[4]) : undefined;
						if (found) { claim = addEffectClaim(graph, request, found, data.references); }
						else { graph.missing.add('HQL effect identity is not present in the selected summary'); }
					} else if (item && collection === 'summaries') {
						claim = graph.addNode({ id: request.identity, kind: request.kind, label: item.functionIdentity, data: item, proofStatus: 'signal' }) ?? null;
						if (claim) addSummaryContext(graph, claim, item, data.references);
						graph.missing.add('HQL match-specific summary effect identity is not persisted');
					} else if (item) {
						const kind = collection === 'prototypes' ? 'prototype' : collection === 'bindings' ? 'type-binding' : collection === 'references' ? 'typed-reference' : collection === 'conflicts' ? 'semantic-conflict' : undefined;
						if (kind) {
							const nested = explainSemanticEntity(view, { ...request, kind, identity: kind === 'prototype' ? item.prototypeId : kind === 'type-binding' ? item.bindingId : kind === 'typed-reference' ? item.edgeId : item.conflictHash, maxNodes, maxEdges, maxBytes });
							const rebound = { ...nested, request: { kind: request.kind, identity: request.identity }, explanationSha256: '' };
							const { engineGeneration: _observation, ...logicalIdentity } = rebound.identity;
							return { ...rebound, explanationSha256: sha256({ ...rebound, identity: logicalIdentity, explanationSha256: undefined }) };
						}
					}
					if (!item) graph.missing.add('HQL semantic origin record is not present in this snapshot');
				}
			}
		}
		if (!claim) {
			const collection = request.kind === 'prototype' ? 'prototypes' : request.kind === 'type-binding' ? 'bindings' : request.kind === 'typed-reference' ? 'references' : request.kind === 'semantic-conflict' ? 'conflicts' : request.kind === 'propagation-effect' ? 'summaries' : undefined;
			if (collection && view.getCoverage().unavailableCollections.includes(collection)) graph.missing.add(`semantic collection unavailable: ${collection}`);
			graph.missing.add(`semantic entity not found: ${request.kind}:${request.identity}`);
		}
		for (const conflict of data.conflicts) if (claim && (conflict.winnerHash === (claim.data as any)?.canonicalHash || conflict.loserHash === (claim.data as any)?.canonicalHash)) { graph.conflicts.push(conflict); graph.missing.add(`semantic conflict: ${conflict.conflictHash}`); }
		for (const conflict of data.referenceConflicts) if (claim && conflict.edgeId === claim.id) { graph.conflicts.push(conflict); graph.missing.add(`reference conflict: ${conflict.conflictHash}`); }
		const result = finalize(view, request, graph, claim);
		if (Buffer.byteLength(canonicalSerialize(result)) > maxBytes) {
			const compact = new Graph(2, 1); compact.truncated = true; compact.missing.add('explanation byte budget exhausted');
			const summary = claim ? compact.addNode({ id: claim.id, kind: claim.kind, label: claim.label, data: { recordSha256: sha256(claim.data) }, proofStatus: claim.proofStatus }) ?? null : null;
			return finalize(view, request, compact, summary, 'partial');
		}
		return result;
	} catch (error) { return finalize(view, request, graph, claim, 'error', error instanceof Error ? error.message : String(error)); }
}
