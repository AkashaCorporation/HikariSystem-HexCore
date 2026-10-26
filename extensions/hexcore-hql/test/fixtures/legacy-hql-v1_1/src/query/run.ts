/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { Worker } from 'worker_threads';
import * as path from 'path';
import { checkJsonBudget, normalizeAdHocQuery, queryLimits, validateQueryIdentity } from './contract.js';
import type { QueryInput, QueryLimits, AdHocQueryResult } from './contract.js';
import { finalizeQueryResult, newQueryResult, selectQueryFunctions } from './evaluate.js';

export interface AdHocExecutionOptions { limits?: Partial<QueryLimits>; signal?: AbortSignal }

/** Read-only executor. The host owns the deadline; a blocked matcher cannot delay it. */
export async function runAdHocQuery(input: QueryInput, rawQuery: unknown, options: AdHocExecutionOptions = {}): Promise<AdHocQueryResult> {
	const query = normalizeAdHocQuery(rawQuery);
	const limits = queryLimits(options.limits);
	const started = performance.now();
	checkJsonBudget(input, limits.maxInputBytes);
	validateQueryIdentity(input.identity);
	if (!Array.isArray(input.functions)) throw new Error('query: functions must be an array');
	const requested = input.requestedFunctions ?? selectQueryFunctions(input, query).requested;
	const identity = { ...input.identity };
	const failed = (reason: string, error = false) => {
		const result = newQueryResult({ identity, functions: [] }, query, requested);
		result.success = !error;
		result.status = error ? 'error' : 'partial';
		result.truncated = true;
		result.partialReasons = [reason];
		return finalizeQueryResult(result);
	};
	if (options.signal?.aborted) return failed('query-cancelled');
	const remaining = limits.timeoutMs - (performance.now() - started);
	if (remaining <= 0) return failed('query-timeout');
	return new Promise(resolve => {
		let done = false;
		let worker: Worker;
		let timer: NodeJS.Timeout | undefined;
		const finish = async (result: AdHocQueryResult) => {
			if (done) return;
			done = true;
			if (timer) clearTimeout(timer);
			options.signal?.removeEventListener('abort', abort);
			// Do not report completion while the computation is still live.
			if (worker) await worker.terminate();
			resolve(result);
		};
		const abort = () => { void finish(failed('query-cancelled')); };
		try {
			worker = new Worker(path.join(__dirname, 'worker.js'), { workerData: { input, query, limits }, resourceLimits: { maxOldGenerationSizeMb: 256, stackSizeMb: 4 } });
		} catch (error) { resolve(failed(`query-worker-start-failed:${error instanceof Error ? error.message : String(error)}`, true)); return; }
		worker.once('message', message => { void finish(message.result ?? failed(`query-worker-failed:${message.error ?? 'invalid response'}`, true)); });
		worker.once('error', error => { void finish(failed(`query-worker-failed:${error.message}`, true)); });
		worker.once('exit', code => { if (!done) void finish(failed(`query-worker-exited:${code}`, true)); });
		timer = setTimeout(() => { void finish(failed('query-timeout')); }, Math.max(1, limits.timeoutMs - (performance.now() - started)));
		options.signal?.addEventListener('abort', abort, { once: true });
		if (options.signal?.aborted) abort();
	});
}
