/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import type { DisassemblerEngine, FunctionBodyStatus } from './disassemblerEngine';
import { canonicalSerialize } from './semanticModel';

export interface FunctionReachabilityOptions {
	roots: Array<'entry' | string | number>;
	scope?: 'functionStarts';
	emit?: 'list' | 'count' | Array<'list' | 'count'>;
	limit?: number;
}

function hex(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

function parseAddress(value: string | number): number {
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value) || value <= 0) { throw new Error(`Invalid reachability root: ${String(value)}`); }
		return value;
	}
	const text = value.trim();
	const match = /^(?:function:)?0x([0-9a-f]+)$/i.exec(text);
	if (!match) { throw new Error(`Invalid reachability root: ${value}`); }
	const parsed = Number.parseInt(match[1], 16);
	if (!Number.isSafeInteger(parsed) || parsed <= 0) { throw new Error(`Invalid reachability root: ${value}`); }
	return parsed;
}

function normalizeEmit(value: FunctionReachabilityOptions['emit']): ReadonlySet<'list' | 'count'> {
	const raw: Array<'list' | 'count'> = value === undefined
		? ['list', 'count']
		: Array.isArray(value) ? [...value] : [value];
	if (raw.length === 0 || raw.some(item => item !== 'list' && item !== 'count')) {
		throw new Error('Reachability emit must contain list and/or count.');
	}
	return new Set<'list' | 'count'>(raw);
}

function bodyCounts(statuses: readonly FunctionBodyStatus[]) {
	const count = (status: FunctionBodyStatus) => statuses.filter(value => value === status).length;
	return {
		materialized: count('materialized'),
		partial: count('partial'),
		lazy: count('lazy'),
		decodeEmpty: count('decode-empty'),
	};
}

export function runFunctionReachability(
	engine: DisassemblerEngine,
	mode: 'reachable' | 'unreachable',
	options: FunctionReachabilityOptions,
) {
	if (!Array.isArray(options.roots) || options.roots.length === 0) {
		throw new Error('Reachability requires a non-empty roots array.');
	}
	if (options.scope !== undefined && options.scope !== 'functionStarts') {
		throw new Error('Reachability currently supports scope:"functionStarts" only.');
	}
	const limit = options.limit === undefined ? 100_000 : Number(options.limit);
	if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1_000_000) {
		throw new Error('Reachability limit must be an integer in the range 1..1000000.');
	}
	const emit = normalizeEmit(options.emit);
	const functions = engine.getFunctions();
	const byAddress = new Map(functions.map(fn => [fn.address, fn]));
	const entry = engine.getFileInfo()?.entryPoint;
	const rootAddresses: number[] = [];
	const seenRoots = new Set<number>();
	for (const root of options.roots) {
		const address = root === 'entry'
			? entry
			: parseAddress(root);
		if (address === undefined || !byAddress.has(address)) {
			throw new Error(`Reachability root is not a known function start: ${root}`);
		}
		if (!seenRoots.has(address)) { seenRoots.add(address); rootAddresses.push(address); }
	}

	const reachable = new Set<number>();
	const pending = [...rootAddresses];
	while (pending.length > 0) {
		const address = pending.shift()!;
		if (reachable.has(address)) { continue; }
		reachable.add(address);
		const fn = byAddress.get(address);
		if (!fn) { continue; }
		for (const callee of new Set(fn.callees)) {
			if (byAddress.has(callee) && !reachable.has(callee)) { pending.push(callee); }
		}
	}

	const selected = functions.filter(fn => mode === 'reachable'
		? reachable.has(fn.address)
		: !reachable.has(fn.address));
	const statuses = functions.map(fn => engine.getFunctionBodyStatus(fn.address));
	const coverage = bodyCounts(statuses);
	const barriers: string[] = [];
	if (!engine.isAnalysisComplete()) { barriers.push('analysis-not-complete'); }
	if (coverage.lazy > 0) { barriers.push(`lazy-functions:${coverage.lazy}`); }
	if (coverage.partial > 0) { barriers.push(`partial-functions:${coverage.partial}`); }
	if (coverage.decodeEmpty > 0) { barriers.push(`decode-empty-functions:${coverage.decodeEmpty}`); }
	const returned = Math.min(selected.length, limit);
	const truncated = returned < selected.length;
	if (truncated) { barriers.push(`result-limit:${limit}`); }
	const negativeEvidenceUsable = mode === 'unreachable' && barriers.length === 0;
	const payload = {
		schemaVersion: 1 as const,
		status: barriers.length === 0 ? 'ok' as const : 'partial' as const,
		semanticStatus: barriers.length === 0 ? 'ok' as const : 'partial' as const,
		mode,
		scope: 'functionStarts' as const,
		target: engine.getFilePath(),
		analysisGeneration: engine.getAnalysisGeneration(),
		roots: rootAddresses.map(hex),
		totalFunctions: functions.length,
		reachableFunctions: reachable.size,
		selectedFunctions: selected.length,
		...(emit.has('count') ? { count: selected.length } : {}),
		...(emit.has('list') ? {
			returned,
			truncated,
			functions: selected.slice(0, limit).map(fn => ({
				address: hex(fn.address),
				endExclusive: hex(fn.endAddress),
				name: fn.name,
				bodyStatus: engine.getFunctionBodyStatus(fn.address),
			})),
		} : {}),
		coverage: {
			...coverage,
			completeRatio: functions.length === 0 ? 0 : coverage.materialized / functions.length,
		},
		negativeEvidenceUsable,
		barriers,
	};
	return Object.freeze({
		...payload,
		outputHash: crypto.createHash('sha256').update(canonicalSerialize(payload), 'utf8').digest('hex'),
	});
}
