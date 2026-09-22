/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import type { DisassemblerEngine, Function, FunctionBodyStatus } from './disassemblerEngine';
import { runFunctionReachability } from './functionReachability';

suite('function reachability command', () => {
	function engine(statuses: Record<number, FunctionBodyStatus>, complete = true): DisassemblerEngine {
		const fn = (address: number, callees: number[]): Function => ({
			address, endAddress: address + 0x10, size: 0x10, name: `sub_${address.toString(16)}`,
			instructions: [], callers: [], callees,
		});
		const functions = [fn(0x1000, [0x2000]), fn(0x2000, [0x3000]), fn(0x3000, []), fn(0x4000, [])];
		return {
			getFunctions: () => functions,
			getFunctionBodyStatus: (address: number) => statuses[address] ?? 'materialized',
			getFileInfo: () => ({ format: 'PE64', architecture: 'x64', entryPoint: 0x1000, baseAddress: 0, imageSize: 0x5000 }),
			getFilePath: () => 'C:\\fixture.exe',
			getAnalysisGeneration: () => 7,
			isAnalysisComplete: () => complete,
		} as unknown as DisassemblerEngine;
	}

	test('finds deterministic reachable and unreachable function starts', () => {
		const e = engine({});
		const reachable = runFunctionReachability(e, 'reachable', { roots: ['entry'] });
		const unreachable = runFunctionReachability(e, 'unreachable', { roots: ['entry'] });
		assert.deepStrictEqual(reachable.functions!.map(item => item.address), ['0x1000', '0x2000', '0x3000']);
		assert.deepStrictEqual(unreachable.functions!.map(item => item.address), ['0x4000']);
		assert.strictEqual(unreachable.negativeEvidenceUsable, true);
		assert.strictEqual(reachable.outputHash, runFunctionReachability(e, 'reachable', { roots: ['entry'] }).outputHash);
	});

	test('downgrades unreachable results when any body is lazy or results truncate', () => {
		const lazy = runFunctionReachability(engine({ 0x2000: 'lazy' }), 'unreachable', { roots: ['entry'] });
		assert.strictEqual(lazy.status, 'partial');
		assert.strictEqual(lazy.negativeEvidenceUsable, false);
		assert.ok(lazy.barriers.includes('lazy-functions:1'));
		const truncated = runFunctionReachability(engine({}), 'unreachable', { roots: ['entry'], limit: 1 });
		assert.strictEqual(truncated.truncated, false, 'one unreachable function fits exactly');
		const allButEntry = runFunctionReachability(engine({}), 'unreachable', { roots: ['0x4000'], limit: 1 });
		assert.strictEqual(allButEntry.truncated, true);
		assert.strictEqual(allButEntry.negativeEvidenceUsable, false);
	});

	test('rejects unknown or non-function roots', () => {
		assert.throws(() => runFunctionReachability(engine({}), 'reachable', { roots: ['0x1234'] }));
		assert.throws(() => runFunctionReachability(engine({}), 'reachable', { roots: [] }));
	});
});
