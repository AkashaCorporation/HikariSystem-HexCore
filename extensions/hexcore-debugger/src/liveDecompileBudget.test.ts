/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { resolveLiveDecompileWorkerBudget } from './liveDecompileBudget';

suite('live-memory decompile budget', () => {
	test('defaults inside the 300-second pipeline deadline', () => {
		assert.strictEqual(resolveLiveDecompileWorkerBudget(undefined, 0), 295_000);
	});

	test('subtracts work already spent reading and lifting memory', () => {
		assert.strictEqual(resolveLiveDecompileWorkerBudget(300_000, 12_500), 282_500);
	});

	test('keeps a terminal one-millisecond budget when the outer budget is exhausted', () => {
		assert.strictEqual(resolveLiveDecompileWorkerBudget(3_000, 10_000), 1);
	});
});
