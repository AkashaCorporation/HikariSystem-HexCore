/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { parentPort, workerData } from 'worker_threads';
import { evaluateQueryBatch } from './evaluate.js';
import { normalizeAdHocQuery, queryLimits } from './contract.js';
import { hydrateQueryInput } from './hydrate.js';

if (parentPort) {
	try {
		const limits = queryLimits(workerData.limits);
		const query = normalizeAdHocQuery(workerData.query);
		parentPort.postMessage({ result: evaluateQueryBatch(hydrateQueryInput(workerData.input, limits, query), query, limits) });
	} catch (error) {
		parentPort.postMessage({ error: error instanceof Error ? error.message : String(error) });
	}
	parentPort.close();
}
