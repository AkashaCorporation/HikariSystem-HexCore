/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import {
	parseMaterializationAddress,
	runFunctionMaterializationCommand,
	type FunctionMaterializationCommandEngine,
} from './functionMaterializationCommand';

suite('explicit function materialization command', () => {
	test('parses exact numeric and hexadecimal addresses', () => {
		assert.strictEqual(parseMaterializationAddress(0x140001000), 0x140001000);
		assert.strictEqual(parseMaterializationAddress('0x140001000'), 0x140001000);
		assert.throws(() => parseMaterializationAddress('140001000'));
		assert.throws(() => parseMaterializationAddress(0));
	});

	test('deduplicates, bounds work and reports partial outcomes honestly', async () => {
		let generation = 4;
		const calls: Array<{ address: number; maxBytes?: number }> = [];
		const engine: FunctionMaterializationCommandEngine = {
			getAnalysisGeneration: () => generation,
			getFilePath: () => 'C:\\fixture.exe',
			getSessionStore: () => ({
				getAnalysisSession: () => ({ id: 'session-1', generation: 8 }),
				getAnalysisUniverseManifest: () => ({ universeSha256: 'abc', materializedFunctions: [{}] }),
			}),
			materializeFunctionForAnalysis: async (address, options) => {
				calls.push({ address, maxBytes: options?.maxBytes });
				const before = generation;
				if (address === 0x2000) {
					return { status: 'unknown-function', changed: false, instructionsAdded: 0,
						engineGenerationBefore: before, engineGenerationAfter: before };
				}
				generation++;
				return { status: 'committed', changed: true, instructionsAdded: 7,
					engineGenerationBefore: before, engineGenerationAfter: generation };
			},
		};
		const result = await runFunctionMaterializationCommand(engine, {
			addresses: ['0x1000', '0x1000', '0x2000', '0x3000'],
			maxFunctions: 2,
			maxBytesPerFn: 4096,
		});
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.requested, 4);
		assert.strictEqual(result.uniqueRequested, 3);
		assert.strictEqual(result.processed, 2);
		assert.strictEqual(result.truncated, true);
		assert.strictEqual(result.committed, 1);
		assert.strictEqual(result.unknownFunctions, 1);
		assert.deepStrictEqual(calls, [
			{ address: 0x1000, maxBytes: 4096 },
			{ address: 0x2000, maxBytes: 4096 },
		]);
	});

	test('rejects invalid budgets before doing work', async () => {
		const engine = {
			getAnalysisGeneration: () => 0,
			getFilePath: () => undefined,
			getSessionStore: () => undefined,
			materializeFunctionForAnalysis: async () => { throw new Error('must not run'); },
		} as FunctionMaterializationCommandEngine;
		await assert.rejects(() => runFunctionMaterializationCommand(engine, {
			addresses: ['0x1000'], maxBytesPerFn: 0,
		}));
	});
});
