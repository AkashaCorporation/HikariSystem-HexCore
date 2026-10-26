/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { canonicalSerialize } from './semanticModel';
import { filterReferenceEdges, type CanonicalReferenceEdge, type ReferenceQuery } from './typedReferenceGraph';
import {
	syncTypedReferenceGraph,
	type ReferenceGraphProducerBudgets,
	type ReferenceGraphSyncResult,
} from './typedReferenceGraphProducer';
import {
	normalizeReferenceGraphQueryOptions,
	type ReferenceGraphQueryCommandOptions,
} from './referenceQueryOptions';
export { normalizeReferenceGraphQueryOptions } from './referenceQueryOptions';
export type { ReferenceGraphQueryCommandOptions } from './referenceQueryOptions';

export interface ReferenceGraphExportCommandOptions {
	includeInvalidated?: boolean;
	maxEdges?: number;
	maxVersions?: number;
	maxConflicts?: number;
	producerBudgets?: Partial<ReferenceGraphProducerBudgets>;
}

export interface ReferenceGraphQueryEnvelope {
	schemaVersion: 1;
	status: 'ok' | 'partial';
	analysisTargetIdentity: string;
	sync: ReferenceGraphSyncResult;
	query: ReferenceQuery;
	totalMatched: number;
	returned: number;
	truncated: boolean;
	edges: readonly unknown[];
	outputHash: string;
}

export interface ReferenceGraphExportEnvelope {
	schemaVersion: 1;
	status: 'ok' | 'partial';
	analysisTargetIdentity: string;
	graphHash: string;
	sync: ReferenceGraphSyncResult;
	counts: {
		edges: number;
		versions: number;
		conflicts: number;
	};
	returned: {
		edges: number;
		versions: number;
		conflicts: number;
	};
	truncated: boolean;
	edges: readonly unknown[];
	versions: readonly unknown[];
	conflicts: readonly unknown[];
	outputHash: string;
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

function boundedInteger(value: unknown, fallback: number, maximum: number, label: string): number {
	const parsed = value === undefined ? fallback : Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1 || parsed > maximum) {
		throw new Error(`${label} must be an integer between 1 and ${maximum}.`);
	}
	return parsed;
}

function withOutputHash<T extends object>(payload: T): T & { outputHash: string } {
	return Object.freeze({ ...payload, outputHash: sha256(canonicalSerialize(payload)) });
}

function graphFor(engine: DisassemblerEngine) {
	const session = engine.getSessionStore();
	if (!session) {
		throw new Error('Reference graph commands require a loaded target with a bound HXDB session.');
	}
	return session.getSemanticStore().getReferenceGraph();
}

function parseAddressIdentity(value: string | undefined): number | undefined {
	if (!value) { return undefined; }
	const match = /(?:^|:)0x([0-9a-f]+)$/i.exec(value);
	if (!match) { return undefined; }
	const parsed = Number.parseInt(match[1], 16);
	return Number.isSafeInteger(parsed) ? parsed : undefined;
}

function resolveThunkView(engine: DisassemblerEngine, edge: CanonicalReferenceEdge) {
	const address = parseAddressIdentity(edge.target.address ?? edge.target.identity);
	if (address === undefined) { return { edge, targetAddress: undefined, targetIdentity: undefined }; }
	const resolution = engine.resolveKnownLinkerThunk(address);
	if (resolution.chain.length === 0) {
		return { edge, targetAddress: address, targetIdentity: edge.target.identity };
	}
	const finalFunction = engine.getFunctionAt(resolution.target);
	const targetIdentity = finalFunction
		? `function:0x${resolution.target.toString(16)}`
		: `address:0x${resolution.target.toString(16)}`;
	return {
		edge: Object.freeze({
			...edge,
			thunkResolution: Object.freeze({
				status: resolution.complete ? 'resolved' : 'partial',
				physicalTarget: edge.target,
				chain: Object.freeze(resolution.chain.map(item => Object.freeze({
					from: `0x${item.from.toString(16)}`,
					to: `0x${item.to.toString(16)}`,
				}))),
				resolvedTarget: Object.freeze({
					kind: finalFunction ? 'function' : 'address',
					identity: targetIdentity,
					address: `0x${resolution.target.toString(16)}`,
				}),
			}),
		}),
		targetAddress: resolution.target,
		targetIdentity,
	};
}

function queryWithThunkResolution(engine: DisassemblerEngine, graph: ReturnType<typeof graphFor>, query: ReferenceQuery) {
	const baseQuery: ReferenceQuery = { ...query };
	delete baseQuery.address;
	delete baseQuery.functionIdentity;
	delete baseQuery.targetIdentity;
	const candidates = graph.query(baseQuery);
	const desiredAddress = query.address ? parseAddressIdentity(query.address) : undefined;
	const desiredFunction = parseAddressIdentity(query.functionIdentity);
	const desiredTarget = parseAddressIdentity(query.targetIdentity);
	const hasResolvedEndpoint = desiredAddress !== undefined || desiredFunction !== undefined || desiredTarget !== undefined;
	return candidates.flatMap(candidate => {
		const view = resolveThunkView(engine, candidate);
		const originalMatches = filterReferenceEdges([candidate], query).length > 0;
		const directionAllowsIncoming = (query.direction ?? 'both') !== 'outgoing';
		const resolvedMatches = directionAllowsIncoming && hasResolvedEndpoint && view.targetAddress !== undefined &&
			(desiredAddress === undefined || desiredAddress === view.targetAddress) &&
			(desiredFunction === undefined || desiredFunction === view.targetAddress) &&
			(desiredTarget === undefined || desiredTarget === view.targetAddress);
		return originalMatches || resolvedMatches ? [view.edge] : [];
	});
}

export function runReferenceGraphQuery(
	engine: DisassemblerEngine,
	options: ReferenceGraphQueryCommandOptions = {},
): ReferenceGraphQueryEnvelope {
	const maxResults = boundedInteger(options.maxResults, 1_000, 100_000, 'maxResults');
	const sync = syncTypedReferenceGraph(engine, options.producerBudgets);
	const graph = graphFor(engine);
	const query = normalizeReferenceGraphQueryOptions(options);
	const matched = options.resolveThunks === true
		? queryWithThunkResolution(engine, graph, query)
		: graph.query(query);
	const edges = Object.freeze(matched.slice(0, maxResults));
	const truncated = edges.length < matched.length;
	return withOutputHash({
		schemaVersion: 1 as const,
		status: sync.status === 'partial' || truncated ? 'partial' as const : 'ok' as const,
		analysisTargetIdentity: graph.analysisTargetIdentity,
		sync,
		query,
		totalMatched: matched.length,
		returned: edges.length,
		truncated,
		edges,
	});
}

export function runReferenceGraphExport(
	engine: DisassemblerEngine,
	options: ReferenceGraphExportCommandOptions = {},
): ReferenceGraphExportEnvelope {
	const maxEdges = boundedInteger(options.maxEdges, 50_000, 500_000, 'maxEdges');
	const maxVersions = boundedInteger(options.maxVersions, 100_000, 1_000_000, 'maxVersions');
	const maxConflicts = boundedInteger(options.maxConflicts, 10_000, 100_000, 'maxConflicts');
	const sync = syncTypedReferenceGraph(engine, options.producerBudgets);
	const graph = graphFor(engine);
	const allEdges = graph.listStoredEdges(options.includeInvalidated === true);
	const allVersions = graph.listVersions();
	const allConflicts = graph.listConflicts();
	const edges = Object.freeze(allEdges.slice(0, maxEdges));
	const versions = Object.freeze(allVersions.slice(0, maxVersions));
	const conflicts = Object.freeze(allConflicts.slice(0, maxConflicts));
	const truncated = edges.length < allEdges.length
		|| versions.length < allVersions.length
		|| conflicts.length < allConflicts.length;
	return withOutputHash({
		schemaVersion: 1 as const,
		status: sync.status === 'partial' || truncated ? 'partial' as const : 'ok' as const,
		analysisTargetIdentity: graph.analysisTargetIdentity,
		graphHash: graph.exportHash(),
		sync,
		counts: { edges: allEdges.length, versions: allVersions.length, conflicts: allConflicts.length },
		returned: { edges: edges.length, versions: versions.length, conflicts: conflicts.length },
		truncated,
		edges,
		versions,
		conflicts,
	});
}
