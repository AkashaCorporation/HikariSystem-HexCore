/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { createHqlSnapshotReader, loadHql, type HqlSemanticFact } from './hqlScanner';
import type { SemanticQueryIdentity, SemanticQueryView } from './semanticQueryView';

export interface HqlQuerySelection { address: string; name?: string; partialReasons?: readonly string[] }
/** This envelope is supplied by the verified producer, never copied from job args. */
export interface HqlQueryHastSource {
	base64: string;
	sha256: string;
	identity: Readonly<SemanticQueryIdentity>;
	targetArchitecture: string;
	producerArchitecture: string;
	producerStatus: 'ok' | 'partial' | 'error';
	semanticEligible: boolean;
	qualityIssues: string[];
	warning?: string;
}
export interface HqlQueryFunctionInput {
	function: string;
	address: string;
	snapshotSha256: string;
	astAvailable: false;
	astComplete: false;
	semanticFacts: HqlSemanticFact[];
	semanticAvailable: boolean;
	semanticComplete: false;
	semanticReadErrors: string[];
	partialReasons: string[];
	hastSource?: HqlQueryHastSource & { annotations: { returnType?: string; variables: Array<{ original_name: string; new_name: string | null; new_type: string | null }> } };
}
export interface HqlQueryInput { identity: Readonly<SemanticQueryIdentity>; functions: HqlQueryFunctionInput[]; requestedFunctions?: number; partialReasons?: string[] }

function address(value: string): string {
	if (typeof value !== 'string' || !/^0x[0-9a-f]{1,16}$/i.test(value)) throw new Error('HQL query selection requires an exact 64-bit hexadecimal address');
	return `0x${BigInt(value).toString(16)}`;
}

/** A bounded snapshot adapter. It does not load files, lift, materialize, or write. */
export function createHqlQueryInput(view: SemanticQueryView, selections: readonly HqlQuerySelection[], sources: ReadonlyMap<string, HqlQueryHastSource> = new Map(), inputPartialReasons: readonly string[] = []): HqlQueryInput {
	if (!Array.isArray(selections) || selections.length > 4096) throw new Error('HQL query selection budget exceeded');
	const reader = createHqlSnapshotReader(view);
	const seen = new Set<string>();
	const functions = selections.map(selection => {
		const at = address(selection.address);
		if (seen.has(at)) throw new Error('Duplicate HQL query selection');
		seen.add(at);
		const source = sources.get(at);
		if (source) {
			view.assertIdentity(source.identity);
			if (source.identity.sessionId !== view.identity.sessionId || source.targetArchitecture !== view.identity.architecture) throw new Error('HQL query producer differs from pinned session/architecture');
		}
		const semanticFacts = reader.getSemanticFacts(at) as HqlSemanticFact[];
		const semanticReadErrors = reader.getSemanticReadErrors();
		let name = selection.name ?? `sub_${at.slice(2)}`;
		let returnType: string | undefined;
		let variables: ReturnType<typeof reader.getVariableRenames> = [];
		try { name = reader.getFunctionName(at) ?? name; returnType = reader.getFunctionReturnType(at); variables = reader.getVariableRenames(at); }
		catch (error) { semanticReadErrors.push(`annotations: ${error instanceof Error ? error.message : String(error)}`); }
		const partialReasons = [...inputPartialReasons, ...(selection.partialReasons ?? [])];
		const fn: HqlQueryFunctionInput = { function: name, address: at, snapshotSha256: view.identity.snapshotSha256, astAvailable: false, astComplete: false,
			semanticFacts, semanticReadErrors, semanticAvailable: semanticReadErrors.length === 0 && inputPartialReasons.length === 0, semanticComplete: false, partialReasons,
			...(source ? { hastSource: { ...source, qualityIssues: [...source.qualityIssues, ...inputPartialReasons], annotations: { returnType, variables } } } : {}),
		};
		return fn;
	});
	for (const key of sources.keys()) if (!seen.has(key)) throw new Error('HQL HAST source has no matching selection');
	return { identity: view.identity, functions };
}

interface AdHocHqlModule {
	normalizeAdHocQuery(query: unknown): unknown;
	runAdHocQuery(input: HqlQueryInput, query: unknown, options?: { limits?: Record<string, number>; signal?: AbortSignal }): Promise<unknown>;
}

export interface NormalizedHqlAdHocQuery {
	schemaVersion: 1;
	condition: unknown;
	addresses?: string[];
	functions?: string[];
	select: string[];
	materialization: 'never';
}

export function normalizeHqlSnapshotQuery(query: unknown): NormalizedHqlAdHocQuery {
	const hql = loadHql() as unknown as Partial<AdHocHqlModule> | undefined;
	if (typeof hql?.normalizeAdHocQuery !== 'function') { throw new Error('HQL ad-hoc query executor is unavailable'); }
	return hql.normalizeAdHocQuery(query) as NormalizedHqlAdHocQuery;
}

export function hqlQueryRequiresHast(query: NormalizedHqlAdHocQuery): boolean {
	const pending: unknown[] = [query.condition];
	while (pending.length) {
		const condition = pending.pop();
		if (!condition || typeof condition !== 'object') { continue; }
		const record = condition as Record<string, unknown>;
		if ('query' in record || typeof record.count === 'object' && record.count !== null && 'query' in (record.count as Record<string, unknown>)) { return true; }
		if (Array.isArray(record.all)) { pending.push(...record.all); }
		if (Array.isArray(record.any)) { pending.push(...record.any); }
		if (record.not) { pending.push(record.not); }
	}
	return false;
}

/** Shared UI/headless entry point; registration and read-only producer routing follow. */
export async function runHqlSnapshotQuery(view: SemanticQueryView, selections: readonly HqlQuerySelection[], query: unknown, options: {
	sources?: ReadonlyMap<string, HqlQueryHastSource>;
	inputPartialReasons?: readonly string[];
	limits?: Record<string, number>;
	requestedFunctions?: number;
	partialReasons?: readonly string[];
	signal?: AbortSignal;
} = {}): Promise<unknown> {
	const hql = loadHql() as unknown as Partial<AdHocHqlModule> | undefined;
	if (typeof hql?.normalizeAdHocQuery !== 'function' || typeof hql.runAdHocQuery !== 'function') throw new Error('HQL ad-hoc query executor is unavailable');
	const normalized = hql.normalizeAdHocQuery(query);
	const input = createHqlQueryInput(view, selections, options.sources, options.inputPartialReasons);
	if (options.requestedFunctions !== undefined) { input.requestedFunctions = options.requestedFunctions; }
	if (options.partialReasons?.length) { input.partialReasons = [...options.partialReasons]; }
	return hql.runAdHocQuery(input, normalized, { limits: options.limits, signal: options.signal });
}
