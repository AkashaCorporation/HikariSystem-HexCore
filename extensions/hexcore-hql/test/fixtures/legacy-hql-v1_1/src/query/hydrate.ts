/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { createHash } from 'crypto';
import { hydrateHAST, HASTHydrationBudgetError } from '../adapter/flatbuf.js';
import type { SessionDbReader } from '../adapter/sessionDb.js';
import { canonicalAddress, canonicalJson, validateQueryIdentity } from './contract.js';
import type { QueryInput, QueryLimits, QueryFunctionInput, AdHocQuery } from './contract.js';
import { selectQueryFunctions } from './evaluate.js';

function architecture(value: string): string {
	const key = value.toLowerCase();
	return key === 'x64' || key === 'amd64' ? 'x86_64' : key === 'arm64' ? 'aarch64' : /^i[3-6]86$/.test(key) ? 'x86' : key;
}

/** Reuses the scanner adapter, but only inside the deadline-controlled worker. */
export function hydrateQueryInput(input: QueryInput, limits: QueryLimits, query: AdHocQuery): QueryInput {
	const functions: QueryFunctionInput[] = [];
	const selected = new Set(selectQueryFunctions(input, query).selected
		.sort((a, b) => BigInt(a.address) < BigInt(b.address) ? -1 : BigInt(a.address) > BigInt(b.address) ? 1 : 0).slice(0, limits.maxFunctions));
	for (const fn of input.functions) {
		const source = fn.hastSource;
		if (!source || !selected.has(fn)) { functions.push(fn); continue; }
		if (fn.ast) throw new Error('query: ambiguous hydrated AST and HAST source');
		validateQueryIdentity(source.identity);
		for (const key of ['targetIdentity', 'sessionId', 'generation', 'universeSha256', 'snapshotSha256'] as const) if (source.identity[key] !== input.identity[key]) throw new Error(`query: HAST source identity mismatch: ${key}`);
		if (typeof source.base64 !== 'string' || typeof source.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(source.sha256)) throw new Error('query: invalid HAST source bytes/hash');
		const bytes = Buffer.from(source.base64, 'base64');
		if (bytes.toString('base64') !== source.base64 || createHash('sha256').update(bytes).digest('hex') !== source.sha256) throw new Error('query: HAST source digest mismatch');
		if (typeof source.targetArchitecture !== 'string' || typeof source.producerArchitecture !== 'string' || !source.targetArchitecture || !source.producerArchitecture || architecture(source.targetArchitecture) === 'unknown' || architecture(source.targetArchitecture) !== architecture(source.producerArchitecture)) throw new Error('query: HAST producer architecture mismatch');
		if (!['ok', 'partial', 'error'].includes(source.producerStatus) || typeof source.semanticEligible !== 'boolean' || !Array.isArray(source.qualityIssues) || source.qualityIssues.some(issue => typeof issue !== 'string')) throw new Error('query: invalid HAST producer quality');
		const reasons = [...fn.partialReasons, ...source.qualityIssues];
		if (source.producerStatus !== 'ok') reasons.push(`hast-producer-${source.producerStatus}`);
		if (!source.semanticEligible) reasons.push('hast-producer-ineligible');
		if (source.warning) reasons.push(source.warning);
		try {
			const reader = {
				getFunctionName: (address: string) => canonicalAddress(address) === canonicalAddress(fn.address) ? fn.function : undefined,
				getFunctionReturnType: (address: string) => canonicalAddress(address) === canonicalAddress(fn.address) ? source.annotations?.returnType : undefined,
				getVariableRenames: (address: string) => canonicalAddress(address) === canonicalAddress(fn.address) ? source.annotations?.variables ?? [] : [],
			} as SessionDbReader;
			const hydrated = hydrateHAST(bytes, reader, { maxFunctions: limits.maxFunctions, maxTables: limits.maxNodes * 8 });
			const candidates = hydrated.filter(candidate => candidate.address?.toLowerCase() === canonicalAddress(fn.address));
			if (candidates.length !== 1) throw new Error('HAST must contain exactly one requested function');
			const ast = candidates[0];
			if (!ast.hast?.architecture || architecture(ast.hast.architecture) !== architecture(source.targetArchitecture)) throw new Error('HAST metadata architecture mismatch');
			if (!ast.hast.semanticEligible) reasons.push('hast-schema-ineligible');
			const eligible = source.producerStatus === 'ok' && source.semanticEligible && source.qualityIssues.length === 0 && !source.warning && ast.hast.semanticEligible;
			if (Buffer.byteLength(canonicalJson(ast)) > limits.maxInputBytes) throw new HASTHydrationBudgetError('Hydrated HAST byte budget exceeded');
			functions.push({ ...fn, ast, astAvailable: eligible, astComplete: eligible && ast.adapterCoverage?.coverage === 1 && !ast.adapterCoverage.errors?.length, partialReasons: reasons });
		} catch (error) {
			const reason = error instanceof Error ? error.message : String(error);
			functions.push({ ...fn, astAvailable: false, astComplete: false, partialReasons: [...reasons, `hast-hydration-failed:${reason.slice(0, 512)}`],
				...(error instanceof HASTHydrationBudgetError ? { truncationReasons: [...(fn.truncationReasons ?? []), 'hast-hydration-budget'] } : {}),
			});
		}
	}
	return { ...input, functions };
}
