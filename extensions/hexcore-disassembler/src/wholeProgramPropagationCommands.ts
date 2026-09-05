/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { canonicalSerialize } from './semanticModel';
import { syncWholeProgramPropagationIsolated } from './wholeProgramPropagationProducer';
import type { PropagationSolveOptions } from './wholeProgramPropagation';

export interface PropagationCommandOptions extends Omit<PropagationSolveOptions, 'generation' | 'cancellationToken' | 'now'> {
	file?: string;
	output?: string | { path?: string };
	quiet?: boolean;
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function requireSession(engine: DisassemblerEngine) {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Propagation command requires a bound HXDB session.'); }
	return session;
}

export async function runPropagationSolve(engine: DisassemblerEngine, options: PropagationCommandOptions = {}) {
	const result = await syncWholeProgramPropagationIsolated(engine, options);
	const semantic = {
		ok: result.run.committed,
		command: 'hexcore.propagation.solve',
		semanticStatus: result.run.committed && result.collection.status === 'ok' && result.references.status === 'ok'
			? 'ok' as const : 'partial' as const,
		references: result.references,
		collection: {
			...result.collection,
			inputs: result.collection.inputs.map(input => ({
				functionIdentity: input.functionIdentity,
				functionBodySha256: input.functionBodySha256,
				constraintCount: input.constraints.length,
				barrierCount: input.barriers?.length ?? 0,
			})),
		},
		incompleteSummariesInvalidated: result.incompleteSummariesInvalidated,
		run: result.run,
	};
	return Object.freeze({
		...semantic,
		worker: result.worker,
		preparation: result.preparation,
		// Thread id, timings, and heartbeat cadence are operational evidence;
		// they must not make an otherwise identical semantic rerun hash-different.
		outputHash: sha256(canonicalSerialize(semantic)),
	});
}

export function runPropagationStatus(engine: DisassemblerEngine) {
	const session = requireSession(engine);
	const store = session.getSemanticStore();
	const propagation = store.getWholeProgramPropagationStore();
	const logical = {
		ok: true,
		command: 'hexcore.propagation.status',
		targetIdentity: store.targetIdentity,
		analysisGeneration: engine.getAnalysisGeneration(),
		latestAcceptedGeneration: propagation.latestAcceptedGeneration() ?? null,
		summaryCount: propagation.listSummaries().length,
		dirty: propagation.listDirty(),
		referenceGraphHash: store.getReferenceGraph().exportHash(),
		semanticStoreHash: store.exportHash(),
	};
	return Object.freeze({ ...logical, outputHash: sha256(canonicalSerialize(logical)) });
}

export function runPropagationExport(engine: DisassemblerEngine) {
	const session = requireSession(engine);
	const store = session.getSemanticStore();
	const payload = {
		schemaVersion: 1,
		targetIdentity: store.targetIdentity,
		analysisGeneration: engine.getAnalysisGeneration(),
		referenceGraphHash: store.getReferenceGraph().exportHash(),
		semanticStoreHash: store.exportHash(),
		propagation: store.getWholeProgramPropagationStore().exportSnapshot(),
	};
	const contentHash = sha256(canonicalSerialize(payload));
	return Object.freeze({ ok: true, command: 'hexcore.propagation.export', contentHash, payload });
}
