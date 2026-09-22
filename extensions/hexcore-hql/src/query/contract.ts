/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { createHash } from 'crypto';
import type { CFunctionDecl, HASTAdapterCoverage } from '../types/ast.js';
import type { HQLQuery, HQLSemanticQuery, HQLSemanticFact, HQLEvidenceLevel } from '../types/hql.js';
import { validateQuery, validateSemanticQuery } from '../signatures/schema.js';

export type AdHocCondition =
	| { query: HQLQuery } | { fact: HQLSemanticQuery }
	| { all: AdHocCondition[] } | { any: AdHocCondition[] } | { not: AdHocCondition }
	| { count: ({ query: HQLQuery } | { fact: HQLSemanticQuery }) & { min?: number; max?: number; exactly?: number } };
export type QueryProjection = 'function' | 'address' | 'proofStatus' | 'evidence';
export interface AdHocQuery {
	schemaVersion: 1;
	condition: AdHocCondition;
	addresses?: string[];
	functions?: string[];
	select: QueryProjection[];
	materialization: 'never';
}
export interface QueryIdentity {
	targetIdentity: string;
	sessionId: string;
	generation: number;
	universeSha256: string;
	snapshotSha256: string;
}
/** Only the bound producer constructs these records; they are not job arguments. */
export interface QueryFunctionInput {
	function: string;
	address: string;
	snapshotSha256: string;
	ast?: CFunctionDecl;
	hastSource?: QueryHastSource;
	astAvailable: boolean;
	astComplete: boolean;
	semanticFacts: HQLSemanticFact[];
	semanticAvailable: boolean;
	/** Closed collection for this function, never inferred from a successful SQL read. */
	semanticComplete: boolean;
	semanticReadErrors: string[];
	partialReasons: string[];
	truncationReasons?: string[];
}
export interface QueryHastSource {
	base64: string;
	sha256: string;
	identity: QueryIdentity;
	targetArchitecture: string;
	producerArchitecture: string;
	producerStatus: 'ok' | 'partial' | 'error';
	semanticEligible: boolean;
	qualityIssues: string[];
	warning?: string;
	annotations?: { returnType?: string; variables: Array<{ original_name: string; new_name: string | null; new_type: string | null }> };
}
export interface QueryInput { identity: QueryIdentity; functions: QueryFunctionInput[]; requestedFunctions?: number; partialReasons?: string[] }
export interface QueryLimits {
	maxFunctions: number;
	maxNodes: number;
	maxRows: number;
	maxEvidencePerRow: number;
	maxOperations: number;
	maxInputBytes: number;
	maxOutputBytes: number;
	timeoutMs: number;
}
export type QueryState = 'matched' | 'negative' | 'unknown';
export interface QueryEvidence {
	nodes: Array<{ kind: string; nodeId?: string; sourceAddress?: string }>;
	facts: HQLSemanticFact[];
}
export interface QueryEvaluation {
	function: string;
	address: string;
	state: QueryState;
	status: 'ok' | 'partial';
	partialReasons: string[];
	truncationReasons: string[];
	semanticReadErrors: string[];
	adapterCoverage: HASTAdapterCoverage | null;
	astSha256: string | null;
	semanticFactsSha256: string;
}
export interface QueryRow {
	function?: string;
	address?: string;
	proofStatus?: HQLEvidenceLevel;
	evidence?: QueryEvidence;
}
export interface AdHocQueryResult {
	success: boolean;
	status: 'ok' | 'partial' | 'error';
	identity: QueryIdentity;
	querySha256: string;
	resultSha256: string;
	resultCount: number;
	rows: QueryRow[];
	evaluations: QueryEvaluation[];
	truncated: boolean;
	partialReasons: string[];
	coverage: { requestedFunctions: number; evaluatedFunctions: number; matchedFunctions: number; negativeFunctions: number; unknownFunctions: number; unevaluatedFunctions: number };
}

export function canonicalJson(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
	if (value && typeof value === 'object') return `{${Object.keys(value).filter(key => (value as any)[key] !== undefined).sort().map(key => `${JSON.stringify(key)}:${canonicalJson((value as any)[key])}`).join(',')}}`;
	return JSON.stringify(value);
}
export function queryDigest(value: unknown): string { return createHash('sha256').update(canonicalJson(value)).digest('hex'); }

/** Preflight before recursive schema validation, hashing, or worker serialization. */
export function checkJsonBudget(value: unknown, maxBytes: number, maxDepth = 256, maxValues = 2000000): void {
	let bytes = 0, values = 0;
	const seen = new Set<object>();
	const pending: Array<{ value: unknown; depth: number; exit?: boolean }> = [{ value, depth: 0 }];
	while (pending.length) {
		const item = pending.pop()!;
		if (item.exit) { seen.delete(item.value as object); continue; }
		if (++values > maxValues || item.depth > maxDepth) throw new Error('query-input-complexity-limit');
		const child = item.value;
		if (child && typeof child === 'object') {
			if (seen.has(child)) throw new Error('query-input-cyclic-object');
			seen.add(child);
			pending.push({ value: child, depth: item.depth, exit: true });
			if (!Array.isArray(child) && Object.getPrototypeOf(child) !== Object.prototype && Object.getPrototypeOf(child) !== null) throw new Error('query-input-not-json');
			const entries = Object.entries(child);
			if (entries.length + pending.length + values > maxValues) throw new Error('query-input-complexity-limit');
			bytes += 2;
			for (const [key, entry] of entries) {
				bytes += Buffer.byteLength(JSON.stringify(key)) + 2;
				if (entry !== undefined) pending.push({ value: entry, depth: item.depth + 1 });
			}
		} else {
			if (!['string', 'number', 'boolean'].includes(typeof child) && child !== null) throw new Error('query-input-not-json');
			if (typeof child === 'number' && (!Number.isFinite(child) || Number.isInteger(child) && !Number.isSafeInteger(child))) throw new Error('query-input-unsafe-number');
			bytes += Buffer.byteLength(JSON.stringify(child)) + 1;
		}
		if (bytes > maxBytes) throw new Error('query-input-byte-limit');
	}
}

export function canonicalAddress(value: string): string {
	if (!/^0x[0-9a-f]{1,16}$/i.test(value)) throw new Error('query: expected hexadecimal address (up to 64 bits)');
	return `0x${BigInt(value).toString(16)}`;
}
function record(value: unknown): value is Record<string, any> { return !!value && typeof value === 'object' && !Array.isArray(value); }
function keys(value: Record<string, any>, allowed: string[]): void {
	for (const key of Object.keys(value)) if (!allowed.includes(key)) throw new Error(`query: unknown field ${key}`);
}
function validateCondition(value: unknown): void {
	if (!record(value) || Object.keys(value).length !== 1) throw new Error('query: expected one condition operator');
	if ('all' in value || 'any' in value) {
		const children = value.all ?? value.any;
		if (!Array.isArray(children) || !children.length) throw new Error('query: expected nonempty conditions');
		children.forEach(validateCondition); return;
	}
	if ('not' in value) { validateCondition(value.not); return; }
	const leaf = 'count' in value ? value.count : value;
	if (!record(leaf)) throw new Error('query: expected condition leaf');
	keys(leaf, 'count' in value ? ['query', 'fact', 'min', 'max', 'exactly'] : ['query', 'fact']);
	if (('query' in leaf) === ('fact' in leaf)) throw new Error('query: expected exactly one query/fact leaf');
	const errors: string[] = [];
	if ('query' in leaf) validateQuery(leaf.query, '$.query', errors);
	else validateSemanticQuery(leaf.fact, '$.fact', errors);
	if (errors.length) throw new Error(errors.join('; '));
	for (const key of ['min', 'max', 'exactly']) if (leaf[key] !== undefined && (!Number.isSafeInteger(leaf[key]) || leaf[key] < 0)) throw new Error('query: invalid count bound');
	if (leaf.exactly !== undefined && (leaf.min !== undefined || leaf.max !== undefined)) throw new Error('query: exactly conflicts with min/max');
	if (leaf.min !== undefined && leaf.max !== undefined && leaf.min > leaf.max) throw new Error('query: min exceeds max');
}

export function normalizeAdHocQuery(value: unknown): AdHocQuery {
	checkJsonBudget(value, 65536, 32, 4096);
	if (!record(value)) throw new Error('query: expected JSON query IR');
	keys(value, ['schemaVersion', 'condition', 'addresses', 'functions', 'select', 'materialization']);
	if (value.schemaVersion !== undefined && value.schemaVersion !== 1) throw new Error('query: unsupported schema version');
	if (value.materialization !== undefined && value.materialization !== 'never') throw new Error('query: only read-only materialization=never is supported');
	validateCondition(value.condition);
	const normalized: AdHocQuery = { schemaVersion: 1, condition: JSON.parse(canonicalJson(value.condition)), materialization: 'never', select: ['function', 'address', 'proofStatus', 'evidence'] };
	for (const key of ['addresses', 'functions'] as const) {
		if (value[key] === undefined) continue;
		if (!Array.isArray(value[key]) || !value[key].length || value[key].some((item: unknown) => typeof item !== 'string' || !item.length)) throw new Error(`query: invalid ${key}`);
		normalized[key] = [...new Set<string>(value[key].map((item: string) => key === 'addresses' ? canonicalAddress(item) : item))].sort();
	}
	if (value.select !== undefined) {
		if (!Array.isArray(value.select) || !value.select.length || value.select.some((item: unknown) => !normalized.select.includes(item as QueryProjection))) throw new Error('query: invalid projection');
		normalized.select = normalized.select.filter(item => value.select.includes(item));
	}
	return normalized;
}

export function queryLimits(options: Partial<QueryLimits> = {}): QueryLimits {
	const defaults: QueryLimits = { maxFunctions: 256, maxNodes: 250000, maxRows: 256, maxEvidencePerRow: 64, maxOperations: 2000000, maxInputBytes: 16 * 1024 * 1024, maxOutputBytes: 4 * 1024 * 1024, timeoutMs: 30000 };
	const ceilings: QueryLimits = { maxFunctions: 4096, maxNodes: 1000000, maxRows: 4096, maxEvidencePerRow: 1024, maxOperations: 20000000, maxInputBytes: 64 * 1024 * 1024, maxOutputBytes: 16 * 1024 * 1024, timeoutMs: 300000 };
	for (const key of Object.keys(options)) if (!Object.hasOwn(defaults, key)) throw new Error(`query: unknown limit ${key}`);
	for (const key of Object.keys(defaults) as Array<keyof QueryLimits>) {
		const value = options[key] ?? defaults[key];
		if (!Number.isSafeInteger(value) || value < 1 || value > ceilings[key]) throw new Error(`query: invalid ${key}`);
		defaults[key] = value;
	}
	if (defaults.maxOutputBytes < 4096) throw new Error('query: maxOutputBytes must allow the 4096-byte terminal envelope');
	return defaults;
}

export function validateQueryIdentity(identity: QueryIdentity): void {
	if (!identity || typeof identity.targetIdentity !== 'string' || !identity.targetIdentity || identity.targetIdentity.length > 512 || typeof identity.sessionId !== 'string' || !identity.sessionId || identity.sessionId.length > 256 || !Number.isSafeInteger(identity.generation) || identity.generation < 0) throw new Error('query: invalid snapshot identity');
	for (const key of ['universeSha256', 'snapshotSha256'] as const) if (typeof identity[key] !== 'string' || !/^[0-9a-f]{64}$/.test(identity[key])) throw new Error(`query: invalid ${key}`);
}
