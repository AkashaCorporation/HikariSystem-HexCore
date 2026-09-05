/*---------------------------------------------------------------------------------------------
 *  Pure TypeScript fixed-point worker. It never opens or writes HXDB.
 *--------------------------------------------------------------------------------------------*/

import { parentPort, workerData } from 'worker_threads';
import {
	WholeProgramPropagationEngine,
	createPropagationSolverContext,
	type FunctionSummaryInput,
	type PropagationSolveOptions,
	type PropagationSolverSnapshot,
} from './wholeProgramPropagation';
import {
	PERSEUS_PROPAGATION_MAGIC,
	PerseusPhase,
	PerseusState,
	PerseusWord,
	perseusCancellationRequested,
} from './perseusPropagation';

interface WorkerRequest {
	snapshot: PropagationSolverSnapshot;
	inputs: FunctionSummaryInput[];
	options: Omit<PropagationSolveOptions, 'cancellationToken' | 'now' | 'onProgress'>;
	control: SharedArrayBuffer;
}

const request = workerData as WorkerRequest;
const words = new Int32Array(request.control);

function phaseCode(phase: string): PerseusPhase {
	switch (phase) {
		case 'prepare': return PerseusPhase.Prepare;
		case 'seed': return PerseusPhase.Seed;
		case 'iterate': return PerseusPhase.Iterate;
		case 'summarize': return PerseusPhase.Summarize;
		case 'complete': return PerseusPhase.Complete;
		default: return PerseusPhase.Created;
	}
}

try {
	if (Atomics.load(words, PerseusWord.Magic) !== PERSEUS_PROPAGATION_MAGIC) {
		throw new Error('Perseus propagation control header mismatch.');
	}
	Atomics.store(words, PerseusWord.State, PerseusState.Running);
	Atomics.add(words, PerseusWord.Heartbeat, 1);
	const engine = new WholeProgramPropagationEngine(createPropagationSolverContext(request.snapshot));
	const run = engine.solve(request.inputs, {
		...request.options,
		cancellationToken: {
			get isCancellationRequested() { return perseusCancellationRequested(words); },
		},
		onProgress: event => {
			Atomics.store(words, PerseusWord.Phase, phaseCode(event.phase));
			Atomics.store(words, PerseusWord.Iteration, event.iteration);
			Atomics.store(words, PerseusWord.AffectedFunctions, event.affectedFunctions);
			Atomics.add(words, PerseusWord.Heartbeat, 1);
		},
	});
	Atomics.store(words, PerseusWord.State,
		run.status === 'cancelled' ? PerseusState.Cancelled
			: run.status === 'timeout' ? PerseusState.TimedOut : PerseusState.Completed);
	Atomics.add(words, PerseusWord.Heartbeat, 1);
	parentPort?.postMessage({
		ok: true,
		snapshotHash: request.snapshot.snapshotHash,
		run,
		bindings: engine.getPendingBindings(),
	});
} catch (error) {
	Atomics.store(words, PerseusWord.State, PerseusState.Failed);
	Atomics.add(words, PerseusWord.Heartbeat, 1);
	parentPort?.postMessage({
		ok: false,
		snapshotHash: request.snapshot.snapshotHash,
		error: error instanceof Error ? error.message : String(error),
		stack: error instanceof Error ? error.stack : undefined,
	});
}
