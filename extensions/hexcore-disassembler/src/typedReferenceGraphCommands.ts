/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { canonicalSerialize } from './semanticModel';
import type { ReferenceQuery } from './typedReferenceGraph';
import {
	syncTypedReferenceGraph,
	type ReferenceGraphProducerBudgets,
	type ReferenceGraphSyncResult,
} from './typedReferenceGraphProducer';

export interface ReferenceGraphQueryCommandOptions {
	query?: ReferenceQuery;
	maxResults?: number;
	producerBudgets?: Partial<ReferenceGraphProducerBudgets>;
}

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

export function runReferenceGraphQuery(
	engine: DisassemblerEngine,
	options: ReferenceGraphQueryCommandOptions = {},
): ReferenceGraphQueryEnvelope {
	const maxResults = boundedInteger(options.maxResults, 1_000, 100_000, 'maxResults');
	const sync = syncTypedReferenceGraph(engine, options.producerBudgets);
	const graph = graphFor(engine);
	const query = Object.freeze({ ...(options.query ?? {}) });
	const matched = graph.query(query);
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
