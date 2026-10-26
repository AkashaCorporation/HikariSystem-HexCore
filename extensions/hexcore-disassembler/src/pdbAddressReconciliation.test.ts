/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { reconcilePdbFunctionAddress } from './pdbSemanticImport';

suite('PDB function-address reconciliation', () => {
	test('accepts only an exact known boundary and extent', () => {
		const engine = {
			getExports: () => [],
			getFunctionAt: (address: number) => address === 0x140001000
				? { address, endAddress: address + 5, size: 5, instructions: [] }
				: undefined,
		};
		assert.deepStrictEqual(reconcilePdbFunctionAddress(engine as any, {
			name: 'add', address: '0x140001000', size: 5,
		}), { status: 'exact', address: 0x140001000 });
		assert.strictEqual(reconcilePdbFunctionAddress(engine as any, {
			name: 'calculate', address: '0x140001000', size: 68,
		}).status, 'unreconciled');
		assert.strictEqual(reconcilePdbFunctionAddress(engine as any, {
			name: 'missing', address: '0x140002000', size: 5,
		}).status, 'unreconciled');
	});

	test('reconciles an exported linker thunk to its exact body target', () => {
		const engine = {
			getExports: () => [{ name: '_bench_xor_buffer', address: 0x180001000, isForwarder: false }],
			getFunctionAt: () => ({
				address: 0x180001000, endAddress: 0x180001005, size: 5,
				instructions: [{ isJump: true, isConditional: false, targetAddress: 0x180002000 }],
			}),
		};
		assert.deepStrictEqual(reconcilePdbFunctionAddress(engine as any, {
			name: 'bench_xor_buffer', address: '0x180009000', size: 100,
		}), { status: 'export', address: 0x180002000 });
	});
});
