/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { HQLMatcher, getChildren } from '../engine/matcher.js';
import { C_NODE_KINDS } from '../types/ast.js';
import type { CNode } from '../types/ast.js';
import type { HQLSemanticFact, HQLEvidenceLevel } from '../types/hql.js';
import { canonicalAddress, canonicalJson, queryDigest, validateQueryIdentity } from './contract.js';
import type { AdHocCondition, AdHocQuery, AdHocQueryResult, QueryFunctionInput, QueryInput, QueryLimits, QueryState, QueryRow } from './contract.js';

interface Evaluation { state: QueryState; nodes: CNode[]; facts: HQLSemanticFact[] }
function empty(state: QueryState): Evaluation { return { state, nodes: [], facts: [] }; }

function conditionDomains(condition: AdHocCondition): { ast: boolean; semantic: boolean } {
	if ('query' in condition || 'count' in condition && 'query' in condition.count) return { ast: true, semantic: false };
	if ('fact' in condition || 'count' in condition && 'fact' in condition.count) return { ast: false, semantic: true };
	if ('not' in condition) return conditionDomains(condition.not);
	const children = 'all' in condition ? condition.all : 'any' in condition ? condition.any : [];
	return children.map(conditionDomains).reduce((result, item) => ({ ast: result.ast || item.ast, semantic: result.semantic || item.semantic }), { ast: false, semantic: false });
}

function checkAst(root: CNode, maxNodes: number): boolean {
	const pending = [{ node: root, depth: 0 }];
	let visited = 0;
	let lossy = false;
	while (pending.length) {
		const { node, depth } = pending.pop()!;
		if (++visited > maxNodes) throw new Error('query-node-limit');
		if (depth > 128) throw new Error('query-ast-depth-limit');
		if (!node || !C_NODE_KINDS.includes(node.kind)) throw new Error('query-invalid-ast-node');
		if (node.kind === 'CUnknownExpr' || node.kind === 'CUnknownStmt' || node.kind === 'CAsmStmt') lossy = true;
		const children = getChildren(node);
		if (children.length + visited + pending.length > maxNodes) throw new Error('query-node-limit');
		for (const child of children) pending.push({ node: child, depth: depth + 1 });
	}
	return lossy;
}

function evaluate(condition: AdHocCondition, fn: QueryFunctionInput, matcher: HQLMatcher): Evaluation {
	if ('not' in condition) {
		const child = evaluate(condition.not, fn, matcher);
		return empty(child.state === 'unknown' ? 'unknown' : child.state === 'matched' ? 'negative' : 'matched');
	}
	if ('all' in condition || 'any' in condition) {
		const all = 'all' in condition;
		const children = (all ? condition.all : condition.any).map(child => evaluate(child, fn, matcher));
		const state = all
			? children.some(child => child.state === 'negative') ? 'negative' : children.some(child => child.state === 'unknown') ? 'unknown' : 'matched'
			: children.some(child => child.state === 'matched') ? 'matched' : children.some(child => child.state === 'unknown') ? 'unknown' : 'negative';
		const witnesses = state === 'matched' ? children.filter(child => child.state === 'matched') : [];
		return { state, nodes: [...new Set(witnesses.flatMap(child => child.nodes))], facts: [...new Set(witnesses.flatMap(child => child.facts))] };
	}
	const leaf = 'count' in condition ? condition.count : condition;
	const structural = 'query' in leaf;
	if (structural ? !fn.astAvailable || !fn.ast : !fn.semanticAvailable || fn.semanticReadErrors.length > 0) return empty('unknown');
	const complete = structural ? fn.astComplete && fn.ast?.hast?.semanticEligible === true && fn.ast?.adapterCoverage?.coverage === 1 && !fn.ast.adapterCoverage.errors?.length : fn.semanticComplete;
	const nodes = structural ? matcher.scan(fn.ast!, leaf.query) : [];
	const facts = !structural ? matcher.evaluateSemanticCondition(fn.semanticFacts, { fact: leaf.fact }).matches : [];
	const size = structural ? nodes.length : facts.length;
	let state: QueryState;
	if ('count' in condition) {
		const { min, max, exactly } = condition.count;
		const lower = exactly ?? min ?? 1;
		const upper = exactly ?? max ?? Infinity;
		// Incomplete collections are lower bounds, not closed-world counts.
		state = size > upper ? 'negative' : size < lower ? complete ? 'negative' : 'unknown'
			: !complete && upper !== Infinity ? 'unknown' : 'matched';
	} else state = size ? 'matched' : complete ? 'negative' : 'unknown';
	return state === 'matched' ? { state, nodes, facts } : empty(state);
}

function level(result: Evaluation): HQLEvidenceLevel {
	if (result.nodes.length || !result.facts.length) return 'signal';
	if (result.facts.some(fact => fact.proofStatus === 'signal')) return 'signal';
	if (result.facts.some(fact => fact.proofStatus === 'candidate')) return 'candidate';
	return 'proven';
}

export function newQueryResult(input: QueryInput, query: AdHocQuery, requestedFunctions: number): AdHocQueryResult {
	const { targetIdentity, sessionId, generation, universeSha256, snapshotSha256 } = input.identity;
	return { success: true, status: 'ok', identity: { targetIdentity, sessionId, generation, universeSha256, snapshotSha256 }, querySha256: queryDigest(query), resultSha256: '', resultCount: 0, rows: [], evaluations: [], truncated: false, partialReasons: [],
		coverage: { requestedFunctions, evaluatedFunctions: 0, matchedFunctions: 0, negativeFunctions: 0, unknownFunctions: 0, unevaluatedFunctions: requestedFunctions } };
}

export function selectQueryFunctions(input: QueryInput, query: AdHocQuery) {
	const all = new Set(input.functions.map(fn => canonicalAddress(fn.address)));
	const selected = input.functions.filter(fn => (!query.addresses || query.addresses.includes(canonicalAddress(fn.address))) && (!query.functions || query.functions.includes(fn.function)));
	const missing = (query.addresses ?? []).filter(address => !all.has(address));
	const missingNames = (query.functions ?? []).filter(name => !selected.some(fn => fn.function === name));
	return { selected, missing, missingNames, requested: selected.length + missing.length + missingNames.length };
}
export function finalizeQueryResult(result: AdHocQueryResult): AdHocQueryResult {
	result.resultCount = result.rows.length;
	result.coverage.unevaluatedFunctions = result.coverage.requestedFunctions - result.evaluations.length;
	result.partialReasons = [...new Set(result.partialReasons)].sort();
	if (result.status !== 'error' && (result.partialReasons.length || result.evaluations.some(item => item.status === 'partial') || result.coverage.unevaluatedFunctions)) result.status = 'partial';
	result.resultSha256 = queryDigest({ ...result, resultSha256: undefined });
	return result;
}

/** Runs only in the terminable query worker; no database, hydration or native engine calls. */
export function evaluateQueryBatch(input: QueryInput, query: AdHocQuery, limits: QueryLimits): AdHocQueryResult {
	validateQueryIdentity(input.identity);
	const domains = conditionDomains(query.condition);
	const effectCategories = new Map([
		['summary-call', 'call'], ['summary-global', 'global'],
		['summary-ownership', 'ownership'], ['summary-field', 'field'],
	]);
	const byAddress = new Map<string, QueryFunctionInput>();
	for (const fn of input.functions) {
		if (typeof fn.function !== 'string' || fn.function.length > 1024) throw new Error('query: invalid function name');
		for (const key of ['astAvailable', 'astComplete', 'semanticAvailable', 'semanticComplete'] as const) if (typeof fn[key] !== 'boolean') throw new Error(`query: invalid quality flag ${key}`);
		if (!Array.isArray(fn.semanticReadErrors) || !Array.isArray(fn.partialReasons) || [...fn.semanticReadErrors, ...fn.partialReasons].some(item => typeof item !== 'string')) throw new Error('query: invalid quality reasons');
		if (fn.truncationReasons !== undefined && (!Array.isArray(fn.truncationReasons) || fn.truncationReasons.some(item => typeof item !== 'string'))) throw new Error('query: invalid truncation reasons');
		if (!Array.isArray(fn.semanticFacts)) throw new Error('query: invalid semantic facts');
		for (const fact of fn.semanticFacts) {
			if (!fact || !['signal', 'candidate', 'proven'].includes(fact.proofStatus) || !Array.isArray(fact.provenance) || !fact.attributes || typeof fact.attributes !== 'object') throw new Error('query: invalid semantic evidence');
			for (const item of fact.provenance) if (!item || typeof item.producer !== 'string' || typeof item.source !== 'string' || typeof item.strength !== 'string' || !Number.isSafeInteger(item.generation) || item.generation < 0) throw new Error('query: invalid semantic provenance');
			if (fact.origin && (fact.origin.targetIdentity !== input.identity.targetIdentity || fact.origin.snapshotSha256 !== input.identity.snapshotSha256 || typeof fact.origin.recordSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(fact.origin.recordSha256) || typeof fact.origin.recordIdentity !== 'string' || !fact.origin.recordIdentity || typeof fact.origin.collection !== 'string' || !fact.origin.collection)) throw new Error('query: semantic fact origin mismatch');
			if (fact.explainIdentity !== undefined) {
				if (!fact.origin || typeof fact.explainIdentity !== 'string') throw new Error('query: semantic explanation identity mismatch');
				const base = `hql-semantic:${fact.origin.snapshotSha256}:${fact.origin.collection}:${fact.origin.recordSha256}`;
				if (fact.explainIdentity !== base) {
					const category = effectCategories.get(fact.kind);
					const prefix = `${base}:effect:${category}:sha256:`;
					if (fact.origin.collection !== 'summaries' || !category || !fact.explainIdentity.startsWith(prefix) ||
						!/^[a-f0-9]{64}$/.test(fact.explainIdentity.slice(prefix.length))) throw new Error('query: semantic explanation identity mismatch');
				}
			}
		}
		const address = canonicalAddress(fn.address);
		if (byAddress.has(address)) throw new Error('query: duplicate function address');
		if (fn.snapshotSha256 !== input.identity.snapshotSha256) throw new Error('query: mixed snapshot identities');
		if (fn.ast && (!fn.ast.address || canonicalAddress(fn.ast.address) !== address)) throw new Error('query: HAST function identity mismatch');
		const lacksProvenance = domains.semantic && fn.semanticFacts.some(fact => fact.proofStatus !== 'signal' && fact.provenance.length === 0);
		byAddress.set(address, { ...fn, address,
			semanticFacts: fn.semanticFacts.map(fact => fact.provenance.length === 0 ? { ...fact, proofStatus: 'signal' } : fact),
			partialReasons: lacksProvenance ? [...fn.partialReasons, 'semantic-fact-without-provenance'] : fn.partialReasons,
		});
	}
	const scope = selectQueryFunctions({ ...input, functions: [...byAddress.values()] }, query);
	const { missing, missingNames } = scope;
	const selected = scope.selected.sort((a, b) => BigInt(a.address) < BigInt(b.address) ? -1 : BigInt(a.address) > BigInt(b.address) ? 1 : 0);
	if (input.requestedFunctions !== undefined && (!Number.isSafeInteger(input.requestedFunctions) || input.requestedFunctions < scope.requested)) throw new Error('query: invalid requested function count');
	if (input.partialReasons !== undefined && (!Array.isArray(input.partialReasons) || input.partialReasons.some(reason => typeof reason !== 'string'))) throw new Error('query: invalid input partial reasons');
	const result = newQueryResult(input, query, input.requestedFunctions ?? scope.requested);
	result.partialReasons.push(...(input.partialReasons ?? []));
	if (missing.length) { result.partialReasons.push('requested-address-unavailable'); }
	for (const name of missingNames) result.partialReasons.push(`requested-function-unavailable:${name}`);
	let operations = 0;
	const deadline = performance.now() + limits.timeoutMs;
	const matcher = new HQLMatcher(() => {
		if (++operations > limits.maxOperations) throw new Error('query-operation-limit');
		if (performance.now() >= deadline) throw new Error('query-timeout');
	});
	let outputBytes = Buffer.byteLength(canonicalJson(result)) + 1024;
	for (const fn of selected) {
		if (result.evaluations.length >= limits.maxFunctions) { result.truncated = true; result.partialReasons.push('query-function-limit'); break; }
		const reasons = [...fn.partialReasons];
		const truncationReasons = [...(fn.truncationReasons ?? [])];
		if (truncationReasons.length) { result.truncated = true; result.partialReasons.push(...truncationReasons); reasons.push(...truncationReasons); }
		if (domains.ast && fn.astAvailable && (!fn.astComplete || fn.ast?.adapterCoverage?.coverage !== 1)) reasons.push('incomplete-ast');
		if (domains.semantic && fn.semanticAvailable && !fn.semanticComplete) reasons.push('open-semantic-collection');
		if (domains.semantic) reasons.push(...fn.semanticReadErrors.map(error => `semantic-read-error:${error}`));
		let evaluated: Evaluation;
		try {
			if (fn.ast && (!Number.isSafeInteger(fn.ast.adapterCoverage?.totalNodes) || fn.ast.adapterCoverage!.totalNodes > limits.maxNodes)) throw new Error('query-node-limit');
			const actualLoss = fn.ast ? checkAst(fn.ast, limits.maxNodes) || !fn.ast.body : false;
			if (actualLoss) reasons.push('incomplete-ast');
			evaluated = evaluate(query.condition, actualLoss ? { ...fn, astComplete: false } : fn, matcher);
		} catch (error) {
			evaluated = empty('unknown');
			const reason = error instanceof Error ? error.message : String(error);
			reasons.push(reason);
			result.partialReasons.push(reason);
			result.truncated = true;
		}
		if (evaluated.state === 'unknown') reasons.push('condition-not-decided');
		let row: QueryRow | undefined;
		if (evaluated.state === 'matched') {
			const count = evaluated.nodes.length + evaluated.facts.length;
			if (count > limits.maxEvidencePerRow) { reasons.push('query-evidence-limit'); result.truncated = true; }
			const full: QueryRow = { function: fn.function, address: fn.address, proofStatus: reasons.length ? 'signal' : level(evaluated), evidence: {
				nodes: evaluated.nodes.slice(0, limits.maxEvidencePerRow).map(node => ({ kind: node.kind, ...(node.nodeId !== undefined ? { nodeId: node.nodeId } : {}), ...(node.sourceAddress !== undefined ? { sourceAddress: node.sourceAddress } : {}) })),
				facts: evaluated.facts.slice(0, Math.max(0, limits.maxEvidencePerRow - evaluated.nodes.length)),
			} };
			row = { ...Object.fromEntries(query.select.map(key => [key, full[key]])), proofStatus: full.proofStatus, evidence: full.evidence };
			if (result.rows.length >= limits.maxRows) { result.truncated = true; result.partialReasons.push('query-row-limit'); break; }
		}
		const entry = { function: fn.function, address: fn.address, state: evaluated.state, status: reasons.length ? 'partial' as const : 'ok' as const, partialReasons: [...new Set(reasons)].sort(), truncationReasons, semanticReadErrors: fn.semanticReadErrors, adapterCoverage: fn.ast?.adapterCoverage ?? null,
			astSha256: fn.hastSource?.sha256 ?? (fn.ast ? queryDigest(fn.ast) : null), semanticFactsSha256: queryDigest(fn.semanticFacts) };
		const size = Buffer.byteLength(canonicalJson({ entry, row }));
		if (outputBytes + size > limits.maxOutputBytes) { result.truncated = true; result.partialReasons.push('query-output-byte-limit'); break; }
		outputBytes += size;
		result.evaluations.push(entry);
		if (row) result.rows.push(row);
		if (evaluated.state === 'unknown') result.coverage.unknownFunctions++;
		else {
			result.coverage.evaluatedFunctions++;
			if (evaluated.state === 'matched') result.coverage.matchedFunctions++;
			else result.coverage.negativeFunctions++;
		}
		if (operations > limits.maxOperations || performance.now() >= deadline) break;
	}
	finalizeQueryResult(result);
	if (Buffer.byteLength(canonicalJson(result)) > limits.maxOutputBytes) {
		const bounded = newQueryResult(input, query, scope.requested);
		bounded.truncated = true;
		bounded.partialReasons = ['query-output-byte-limit'];
		return finalizeQueryResult(bounded);
	}
	return result;
}
