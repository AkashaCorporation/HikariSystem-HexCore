/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import { canonicalSerialize } from './semanticModel';

export type QueryMaterializationMode = 'never' | 'needed' | 'bounded';

export interface QueryMaterializationPolicy {
	mode: Exclude<QueryMaterializationMode, 'never'>;
	maxFunctions: number;
	maxBytes: number;
	maxMilliseconds: number;
	maxDepth: number;
}

export interface QueryMaterializationQuery {
	condition: unknown;
	addresses?: readonly string[];
	functions?: readonly string[];
}

export interface QueryMaterializationUnknownReason {
	function: string;
	reason:
		| 'function-not-indexed'
		| 'function-name-not-indexed'
		| 'function-name-ambiguous'
		| 'dependency-function-not-indexed'
		| 'dependency-body-unavailable'
		| 'unresolved-indirect-target'
		| 'maxFunctions'
		| 'maxBytes'
		| 'maxDepth'
		| 'explicit-scope-required';
	detail?: string;
}

export interface QueryMaterializationPlanEntry {
	address: number;
	addressHex: string;
	functionIdentity: string;
	name: string;
	depth: number;
	spanBytes: number;
	currentState: string;
	reason: 'explicit' | 'reference' | 'propagation' | 'call-graph';
}

export interface QueryMaterializationPlan {
	schemaVersion: 1;
	mode: QueryMaterializationPolicy['mode'];
	targetIdentity: string;
	initialGeneration: number;
	initialUniverseSha256: string;
	maxFunctions: number;
	maxBytes: number;
	maxMilliseconds: number;
	maxDepth: number;
	bodyRequired: boolean;
	semanticDependenciesRequired: boolean;
	requested: readonly QueryMaterializationPlanEntry[];
	visitedFunctions: readonly string[];
	estimatedBytes: number;
	budgetExhausted: boolean;
	budgetReason?: 'maxFunctions' | 'maxBytes' | 'maxDepth';
	unknownReasons: readonly QueryMaterializationUnknownReason[];
	planSha256: string;
}

interface FunctionRecord {
	address: number;
	name: string;
	endAddress: number;
	callees: readonly number[];
}

interface PlanningReferenceEdge {
	relation: string;
	source: { ownerFunctionIdentity: string };
	target: { kind: string; identity: string; address?: string };
	indirectResolution?: { reason?: string };
}

interface PlanningStore {
	readonly targetIdentity: string;
	getReferenceGraph(): { listStoredEdges(includeInvalidated?: boolean): Array<{ edge: PlanningReferenceEdge; active: boolean }> };
	getWholeProgramPropagationStore(): { listDependencies(): Array<{ consumerFunctionIdentity: string; dependencyFunctionIdentity: string }> };
}

export interface MaterializationPlanningEngine {
	getFunctions(): readonly FunctionRecord[];
	getFunctionAt(address: number): FunctionRecord | undefined;
	peekFunctionBodyCompleteness(address: number): { state: string; boundaryReached?: boolean } | undefined;
	getAnalysisGeneration(): number;
	getSessionStore(): {
		getAnalysisTarget(): { id: string } | undefined;
		getAnalysisSession(): { generation: number } | undefined;
		getAnalysisUniverseManifest(): { universeSha256: string } | undefined;
		getSemanticStore(): PlanningStore;
	} | undefined;
}

interface Dependency {
	identity: string;
	reason: QueryMaterializationPlanEntry['reason'];
}

export function planQueryMaterialization(
	engine: MaterializationPlanningEngine,
	query: QueryMaterializationQuery,
	policy: QueryMaterializationPolicy,
): QueryMaterializationPlan {
	validatePolicy(policy);
	const session = engine.getSessionStore();
	const target = session?.getAnalysisTarget();
	const analysisSession = session?.getAnalysisSession();
	const universe = session?.getAnalysisUniverseManifest();
	if (!session || !target || !analysisSession || !universe) throw new Error('Query materialization requires a bound target, session, and universe.');
	const store = session.getSemanticStore();
	if (store.targetIdentity !== target.id) throw new Error('Query materialization semantic target differs from the active analysis target.');
	const functions = [...engine.getFunctions()].sort((left, right) => left.address - right.address);
	const byAddress = new Map(functions.map(fn => [fn.address, fn]));
	const byIdentity = new Map(functions.map(fn => [functionIdentity(fn.address), fn]));
	const byName = new Map<string, FunctionRecord[]>();
	for (const fn of functions) {
		const values = byName.get(fn.name) ?? [];
		values.push(fn);
		byName.set(fn.name, values);
	}
	const unknownReasons: QueryMaterializationUnknownReason[] = [];
	const seeds = new Map<string, { fn: FunctionRecord; reason: QueryMaterializationPlanEntry['reason'] }>();
	for (const raw of query.addresses ?? []) {
		const address = parseAddress(raw);
		const fn = byAddress.get(address);
		if (!fn) {
			unknownReasons.push({ function: canonicalAddress(address), reason: 'function-not-indexed' });
			continue;
		}
		seeds.set(functionIdentity(fn.address), { fn, reason: 'explicit' });
	}
	for (const name of query.functions ?? []) {
		const matches = byName.get(name) ?? [];
		if (matches.length === 0) {
			unknownReasons.push({ function: name, reason: 'function-name-not-indexed' });
			continue;
		}
		if (matches.length > 1) {
			unknownReasons.push({ function: name, reason: 'function-name-ambiguous', detail: `${matches.length} exact entries` });
			continue;
		}
		const fn = matches[0];
		seeds.set(functionIdentity(fn.address), { fn, reason: 'explicit' });
	}
	if (seeds.size === 0 && (query.addresses?.length ?? 0) === 0 && (query.functions?.length ?? 0) === 0) {
		unknownReasons.push({ function: '<query-scope>', reason: 'explicit-scope-required' });
	}
	const structuralBodyRequired = conditionUsesAst(query.condition);
	const semanticDependenciesRequired = conditionRequiresSemanticBodies(query.condition);
	const bodyRequired = structuralBodyRequired || semanticDependenciesRequired;
	const dependencies = dependencyMap(functions, store, byIdentity);
	const unresolvedByOwner = unresolvedIndirects(store);
	const requested: QueryMaterializationPlanEntry[] = [];
	const visited = new Set<string>();
	const queued = new Set<string>();
	const queue: Array<{ fn: FunctionRecord; depth: number; reason: QueryMaterializationPlanEntry['reason'] }> = [];
	for (const seed of [...seeds.values()].sort((left, right) => left.fn.address - right.fn.address)) {
		queue.push({ fn: seed.fn, depth: 0, reason: seed.reason });
		queued.add(functionIdentity(seed.fn.address));
	}
	let estimatedBytes = 0;
	let budgetReason: QueryMaterializationPlan['budgetReason'];
	while (queue.length > 0) {
		const current = queue.shift()!;
		const identity = functionIdentity(current.fn.address);
		if (visited.has(identity)) continue;
		visited.add(identity);
		for (const detail of unresolvedByOwner.get(identity) ?? []) {
			unknownReasons.push({ function: identity, reason: 'unresolved-indirect-target', detail });
		}
		const completeness = engine.peekFunctionBodyCompleteness(current.fn.address);
		const complete = completeness?.state === 'complete' && completeness.boundaryReached === true;
		if (!complete && bodyRequired) {
			const spanBytes = current.fn.endAddress - current.fn.address;
			if (!Number.isSafeInteger(spanBytes) || spanBytes <= 0) {
				unknownReasons.push({ function: identity, reason: 'dependency-body-unavailable', detail: 'authoritative function span is unavailable' });
			} else if (requested.length >= policy.maxFunctions) {
				budgetReason ??= 'maxFunctions';
				unknownReasons.push({ function: identity, reason: 'maxFunctions' });
			} else if (estimatedBytes + spanBytes > policy.maxBytes) {
				budgetReason ??= 'maxBytes';
				unknownReasons.push({ function: identity, reason: 'maxBytes', detail: `span=${spanBytes}, remaining=${policy.maxBytes - estimatedBytes}` });
			} else {
				requested.push({
					address: current.fn.address,
					addressHex: canonicalAddress(current.fn.address),
					functionIdentity: identity,
					name: current.fn.name,
					depth: current.depth,
					spanBytes,
					currentState: completeness?.state ?? 'unavailable',
					reason: current.reason,
				});
				estimatedBytes += spanBytes;
			}
		}
		if (!semanticDependenciesRequired) continue;
		const next = dependencies.get(identity) ?? [];
		if (current.depth >= policy.maxDepth) {
			if (next.some(dependency => !visited.has(dependency.identity))) {
				budgetReason ??= 'maxDepth';
				for (const dependency of next.filter(item => !visited.has(item.identity))) {
					unknownReasons.push({ function: dependency.identity, reason: 'maxDepth', detail: `required by ${identity}` });
				}
			}
			continue;
		}
		for (const dependency of next) {
			if (visited.has(dependency.identity) || queued.has(dependency.identity)) continue;
			const fn = byIdentity.get(dependency.identity);
			if (!fn) {
				unknownReasons.push({ function: dependency.identity, reason: 'dependency-function-not-indexed', detail: `required by ${identity}` });
				continue;
			}
			queue.push({ fn, depth: current.depth + 1, reason: dependency.reason });
			queued.add(dependency.identity);
		}
	}
	const logical = {
		schemaVersion: 1 as const,
		mode: policy.mode,
		targetIdentity: target.id,
		initialGeneration: analysisSession.generation,
		initialUniverseSha256: universe.universeSha256,
		maxFunctions: policy.maxFunctions,
		maxBytes: policy.maxBytes,
		maxMilliseconds: policy.maxMilliseconds,
		maxDepth: policy.maxDepth,
		bodyRequired,
		semanticDependenciesRequired,
		requested,
		visitedFunctions: [...visited].sort(),
		estimatedBytes,
		budgetExhausted: budgetReason !== undefined,
		...(budgetReason ? { budgetReason } : {}),
		unknownReasons: deduplicateUnknownReasons(unknownReasons),
	};
	return { ...logical, planSha256: sha256(logical) };
}

function dependencyMap(
	functions: readonly FunctionRecord[],
	store: PlanningStore,
	byIdentity: ReadonlyMap<string, FunctionRecord>,
): Map<string, Dependency[]> {
	const result = new Map<string, Map<string, Dependency['reason']>>();
	const add = (owner: string, dependency: string, reason: Dependency['reason']) => {
		if (owner === dependency) return;
		const values = result.get(owner) ?? new Map<string, Dependency['reason']>();
		const current = values.get(dependency);
		const priority: Dependency['reason'][] = ['reference', 'propagation', 'call-graph', 'explicit'];
		if (!current || priority.indexOf(reason) < priority.indexOf(current)) values.set(dependency, reason);
		result.set(owner, values);
	};
	for (const fn of functions) {
		for (const callee of fn.callees) {
			if (byIdentity.has(functionIdentity(callee))) add(functionIdentity(fn.address), functionIdentity(callee), 'call-graph');
		}
	}
	for (const stored of store.getReferenceGraph().listStoredEdges(false)) {
		if (!stored.active) continue;
		const edge = stored.edge;
		if (!['code-call-near', 'code-call-far', 'code-tail-call', 'code-indirect-resolved'].includes(edge.relation)) continue;
		if (edge.target?.kind !== 'function') continue;
		const dependency = normalizeFunctionIdentity(edge.target.identity, edge.target.address);
		if (dependency) add(normalizeFunctionIdentity(edge.source.ownerFunctionIdentity) ?? edge.source.ownerFunctionIdentity.toLowerCase(), dependency, 'reference');
	}
	for (const dependency of store.getWholeProgramPropagationStore().listDependencies()) {
		const owner = normalizeFunctionIdentity(dependency.consumerFunctionIdentity) ?? dependency.consumerFunctionIdentity.toLowerCase();
		const required = normalizeFunctionIdentity(dependency.dependencyFunctionIdentity) ?? dependency.dependencyFunctionIdentity.toLowerCase();
		add(owner, required, 'propagation');
	}
	return new Map([...result.entries()].map(([owner, values]) => [owner,
		[...values.entries()].map(([identity, reason]) => ({ identity, reason })).sort((left, right) => {
			const leftFn = byIdentity.get(left.identity), rightFn = byIdentity.get(right.identity);
			return (leftFn?.address ?? Number.MAX_SAFE_INTEGER) - (rightFn?.address ?? Number.MAX_SAFE_INTEGER) || left.identity.localeCompare(right.identity);
		})]));
}

function unresolvedIndirects(store: PlanningStore): Map<string, string[]> {
	const result = new Map<string, string[]>();
	for (const stored of store.getReferenceGraph().listStoredEdges(false)) {
		const edge = stored.edge;
		if (!stored.active || edge.relation !== 'code-indirect-candidate') continue;
		const owner = normalizeFunctionIdentity(edge.source.ownerFunctionIdentity) ?? edge.source.ownerFunctionIdentity.toLowerCase();
		const values = result.get(owner) ?? [];
		values.push(edge.indirectResolution?.reason ?? edge.target?.identity ?? 'unresolved indirect candidate');
		result.set(owner, values.sort());
	}
	return result;
}

function conditionUsesAst(condition: unknown): boolean {
	const pending = [condition];
	while (pending.length > 0) {
		const current = pending.pop();
		if (!current || typeof current !== 'object' || Array.isArray(current)) continue;
		const record = current as Record<string, unknown>;
		if ('query' in record || record.count && typeof record.count === 'object' && 'query' in (record.count as Record<string, unknown>)) return true;
		if (Array.isArray(record.all)) pending.push(...record.all);
		if (Array.isArray(record.any)) pending.push(...record.any);
		if (record.not) pending.push(record.not);
	}
	return false;
}

function conditionRequiresSemanticBodies(condition: unknown): boolean {
	const bodyFacts = new Set([
		'xref', 'indirect-target', 'summary-call', 'summary-global', 'summary-ownership',
		'summary-field', 'summary-barrier',
	]);
	const pending = [condition];
	while (pending.length > 0) {
		const current = pending.pop();
		if (!current || typeof current !== 'object' || Array.isArray(current)) continue;
		const record = current as Record<string, unknown>;
		const leaf = 'fact' in record ? record.fact
			: record.count && typeof record.count === 'object' ? (record.count as Record<string, unknown>).fact : undefined;
		if (leaf && typeof leaf === 'object' && bodyFacts.has(String((leaf as Record<string, unknown>).fact))) return true;
		if (Array.isArray(record.all)) pending.push(...record.all);
		if (Array.isArray(record.any)) pending.push(...record.any);
		if (record.not) pending.push(record.not);
	}
	return false;
}

function validatePolicy(policy: QueryMaterializationPolicy): void {
	if (!['needed', 'bounded'].includes(policy.mode)) throw new Error(`Unsupported query materialization mode: ${String(policy.mode)}`);
	for (const [key, value] of Object.entries(policy)) {
		if (key === 'mode') continue;
		if (!Number.isSafeInteger(value) || value < 1) throw new Error(`Invalid query materialization budget: ${key}`);
	}
	if (policy.mode === 'needed' && policy.maxDepth !== 1) throw new Error('Needed query materialization requires maxDepth=1.');
}

function parseAddress(value: string): number {
	if (!/^0x[0-9a-f]{1,16}$/i.test(value)) throw new Error(`Invalid query materialization address: ${value}`);
	const parsed = BigInt(value);
	if (parsed > BigInt(Number.MAX_SAFE_INTEGER) || parsed <= 0n) throw new Error(`Query materialization address exceeds engine precision: ${value}`);
	return Number(parsed);
}

function canonicalAddress(address: number): string { return `0x${address.toString(16)}`; }
function functionIdentity(address: number): string { return `function:${canonicalAddress(address)}`; }

function normalizeFunctionIdentity(identity: unknown, address?: unknown): string | undefined {
	if (typeof identity === 'string') {
		const match = /^function:(0x[0-9a-f]{1,16})$/i.exec(identity);
		if (match) return `function:0x${BigInt(match[1]).toString(16)}`;
	}
	if (typeof address === 'string' && /^0x[0-9a-f]{1,16}$/i.test(address)) return `function:0x${BigInt(address).toString(16)}`;
	return undefined;
}

function deduplicateUnknownReasons(reasons: readonly QueryMaterializationUnknownReason[]): QueryMaterializationUnknownReason[] {
	const byKey = new Map<string, QueryMaterializationUnknownReason>();
	for (const reason of reasons) {
		const key = canonicalSerialize(reason);
		byKey.set(key, reason);
	}
	return [...byKey.values()].sort((left, right) => left.function.localeCompare(right.function) || left.reason.localeCompare(right.reason) || (left.detail ?? '').localeCompare(right.detail ?? ''));
}

function sha256(value: unknown): string { return crypto.createHash('sha256').update(canonicalSerialize(value)).digest('hex'); }
