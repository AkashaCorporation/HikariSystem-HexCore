/*---------------------------------------------------------------------------------------------
 *  Parent-side controller for the pure TypeScript propagation worker.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as path from 'path';
import { Worker } from 'worker_threads';
import type { CanonicalTypeBinding } from './semanticModel';
import type { SemanticStore } from './semanticStore';
import {
	commitPropagationComputation,
	createPropagationSolverSnapshot,
	type FunctionSummaryInput,
	type PropagationRunResult,
	type PropagationSolveOptions,
} from './wholeProgramPropagation';
import {
	PerseusState,
	PerseusWord,
	createPerseusPropagationChannel,
	requestPerseusCancellation,
} from './perseusPropagation';

export interface PropagationWorkerDiagnostics {
	transport: 'perseus-sab-v1';
	snapshotPreparationMs: number;
	workerThreadId: number;
	durationMs: number;
	heartbeats: number;
	lastPhase: number;
	lastIteration: number;
	affectedFunctions: number;
	finalState: number;
	hardTerminated: boolean;
	snapshotHash: string;
}

export interface PropagationWorkerOutcome {
	run: PropagationRunResult;
	diagnostics: PropagationWorkerDiagnostics;
}

interface WorkerSuccess {
	ok: true;
	snapshotHash: string;
	run: PropagationRunResult;
	bindings: CanonicalTypeBinding[];
}

interface WorkerFailure {
	ok: false;
	snapshotHash: string;
	error: string;
	stack?: string;
}

function sha256(value: unknown): string {
	return crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function terminalRun(
	status: 'cancelled' | 'timeout' | 'budget-exhausted',
	reason: string,
	generation: number,
	snapshotHash: string,
	inputs: readonly FunctionSummaryInput[],
	priorAcceptedGeneration?: number,
): PropagationRunResult {
	const affectedFunctions = inputs.map(input => input.functionIdentity).sort();
	const payload = { status, reason, generation, snapshotHash, affectedFunctions };
	return {
		status,
		committed: false,
		generation,
		...(priorAcceptedGeneration !== undefined ? { priorAcceptedGeneration } : {}),
		affectedFunctions,
		recomputedFunctions: [],
		iterations: 0,
		inputHash: snapshotHash,
		runHash: sha256(payload),
		summaries: [],
		reason,
	};
}

export async function runPropagationInWorker(
	store: SemanticStore,
	inputs: readonly FunctionSummaryInput[],
	options: Omit<PropagationSolveOptions, 'generation' | 'now' | 'onProgress'> & {
		generation: number;
		/** Focused-test override; production callers use maxMilliseconds + grace. */
		hardTimeoutMs?: number;
	},
): Promise<PropagationWorkerOutcome> {
	const controllerStartedAt = Date.now();
	const snapshot = createPropagationSolverSnapshot(store);
	const snapshotPreparationMs = Date.now() - controllerStartedAt;
	const { buffer, words } = createPerseusPropagationChannel();
	const workerOptions = {
		generation: options.generation,
		...(options.changedFunctions ? { changedFunctions: [...options.changedFunctions] } : {}),
		...(options.maxIterations !== undefined ? { maxIterations: options.maxIterations } : {}),
		...(options.maxMilliseconds !== undefined ? { maxMilliseconds: options.maxMilliseconds } : {}),
		...(options.maxValues !== undefined ? { maxValues: options.maxValues } : {}),
		...(options.maxTypeHypothesesPerValue !== undefined ? { maxTypeHypothesesPerValue: options.maxTypeHypothesesPerValue } : {}),
		...(options.maxPointsToPerValue !== undefined ? { maxPointsToPerValue: options.maxPointsToPerValue } : {}),
	};
	const startedAt = Date.now();
	const hardDeadlineMs = options.hardTimeoutMs !== undefined
		? Math.max(10, options.hardTimeoutMs)
		: Math.max(1_000, (options.maxMilliseconds ?? 30_000) + 2_000);
	const worker = new Worker(path.join(__dirname, 'wholeProgramPropagationWorker.js'), {
		workerData: { snapshot, inputs: [...inputs], options: workerOptions, control: buffer },
		resourceLimits: { maxOldGenerationSizeMb: 2048, stackSizeMb: 8 },
	});
	const workerThreadId = worker.threadId;
	let hardTerminated = false;
	let settled = false;
	let cancelPoll: NodeJS.Timeout | undefined;
	let hardTimer: NodeJS.Timeout | undefined;

	const diagnostics = (): PropagationWorkerDiagnostics => ({
		transport: 'perseus-sab-v1',
		snapshotPreparationMs,
		workerThreadId,
		durationMs: Date.now() - startedAt,
		heartbeats: Atomics.load(words, PerseusWord.Heartbeat),
		lastPhase: Atomics.load(words, PerseusWord.Phase),
		lastIteration: Atomics.load(words, PerseusWord.Iteration),
		affectedFunctions: Atomics.load(words, PerseusWord.AffectedFunctions),
		finalState: Atomics.load(words, PerseusWord.State),
		hardTerminated,
		snapshotHash: snapshot.snapshotHash,
	});

	try {
		const message = await new Promise<WorkerSuccess | WorkerFailure | undefined>((resolve, reject) => {
			const finish = (value: WorkerSuccess | WorkerFailure | undefined): void => {
				if (settled) return;
				settled = true;
				resolve(value);
			};
			worker.once('message', value => finish(value as WorkerSuccess | WorkerFailure));
			worker.once('error', reject);
			worker.once('exit', code => {
				if (!settled && code !== 0 && !hardTerminated) reject(new Error(`Propagation worker exited with code ${code}.`));
				else if (!settled) finish(undefined);
			});
			cancelPoll = setInterval(() => {
				if (options.cancellationToken?.isCancellationRequested) requestPerseusCancellation(words);
			}, 50);
			hardTimer = setTimeout(() => {
				hardTerminated = true;
				Atomics.store(words, PerseusWord.State, PerseusState.TimedOut);
				requestPerseusCancellation(words);
				// The terminal job contract must not depend on how quickly V8 tears down a
				// CPU-bound worker. Publish timeout immediately, then reap it in the
				// background. No result can commit after `finish` settles this controller.
				finish(undefined);
				void worker.terminate();
			}, hardDeadlineMs);
		});

		if (!message) {
			return {
				run: terminalRun('timeout', 'Propagation worker exceeded its hard deadline and was terminated.', options.generation, snapshot.snapshotHash, inputs, snapshot.latestAcceptedGeneration),
				diagnostics: diagnostics(),
			};
		}
		if (message.snapshotHash !== snapshot.snapshotHash) throw new Error('Propagation worker returned a different snapshot identity.');
		if (!message.ok) throw new Error(`Propagation worker failed: ${message.error}`);
		if (message.run.status !== 'committed' || !message.run.committed) {
			return { run: message.run, diagnostics: diagnostics() };
		}
		const current = createPropagationSolverSnapshot(store);
		if (current.snapshotHash !== snapshot.snapshotHash) {
			return {
				run: terminalRun('cancelled', 'HXDB semantic state changed while propagation was running; worker result was not committed.', options.generation, snapshot.snapshotHash, inputs, snapshot.latestAcceptedGeneration),
				diagnostics: diagnostics(),
			};
		}
		return {
			run: commitPropagationComputation(store, message.run, message.bindings),
			diagnostics: diagnostics(),
		};
	} finally {
		if (cancelPoll) clearInterval(cancelPoll);
		if (hardTimer) clearTimeout(hardTimer);
		if (!settled) void worker.terminate();
	}
}
