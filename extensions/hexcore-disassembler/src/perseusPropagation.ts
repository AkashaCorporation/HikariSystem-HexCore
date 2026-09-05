/*---------------------------------------------------------------------------------------------
 *  Perseus Fabric v1 -- propagation worker control channel.
 *--------------------------------------------------------------------------------------------*/

export const PERSEUS_PROPAGATION_MAGIC = 0x50525331;
export const PERSEUS_PROPAGATION_WORDS = 8;

export const enum PerseusWord {
	Magic = 0,
	State = 1,
	Heartbeat = 2,
	Phase = 3,
	Iteration = 4,
	AffectedFunctions = 5,
	CancelRequested = 6,
	Reserved = 7,
}

export const enum PerseusState {
	Created = 0,
	Running = 1,
	Completed = 2,
	Failed = 3,
	Cancelled = 4,
	TimedOut = 5,
}

export const enum PerseusPhase {
	Created = 0,
	Prepare = 1,
	Seed = 2,
	Iterate = 3,
	Summarize = 4,
	Complete = 5,
}

export function createPerseusPropagationChannel(): { buffer: SharedArrayBuffer; words: Int32Array } {
	const buffer = new SharedArrayBuffer(Int32Array.BYTES_PER_ELEMENT * PERSEUS_PROPAGATION_WORDS);
	const words = new Int32Array(buffer);
	Atomics.store(words, PerseusWord.Magic, PERSEUS_PROPAGATION_MAGIC);
	Atomics.store(words, PerseusWord.State, PerseusState.Created);
	return { buffer, words };
}

export function requestPerseusCancellation(words: Int32Array): void {
	Atomics.store(words, PerseusWord.CancelRequested, 1);
	Atomics.notify(words, PerseusWord.CancelRequested);
}

export function perseusCancellationRequested(words: Int32Array): boolean {
	return Atomics.load(words, PerseusWord.CancelRequested) !== 0;
}
