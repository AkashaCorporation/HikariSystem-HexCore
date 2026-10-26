/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { RemillWrapper } from './remillWrapper';

suite('Remill external symbol initialization', () => {
	test('retains symbols before first lift and clears them before target reuse', async () => {
		const maps: any[] = [];
		class Lifter {
			setExternalSymbols(map: unknown) { maps.push(map); }
			clearExternalSymbols() { maps.push('clear'); }
			liftBytes() { return { success: true, ir: 'fixture', bytesConsumed: 1 }; }
			close() {}
		}
		const wrapper: RemillWrapper = Object.create(RemillWrapper.prototype);
		Object.assign(wrapper, { available: true, module: { RemillLifter: Lifter }, externalSymbols: {} });
		wrapper.setExternalSymbols(new Map([[4096, 'first']]));
		assert.deepStrictEqual(maps, []);
		await wrapper.liftBytes(Buffer.from([0xc3]), 4096, 'x64', 'windows');
		assert.deepStrictEqual(maps, [{ '4096': 'first' }]);
		wrapper.clearExternalSymbols();
		await wrapper.liftBytes(Buffer.from([0xc3]), 4096, 'x86', 'windows');
		assert.deepStrictEqual(maps, [{ '4096': 'first' }, 'clear']);
		wrapper.setExternalSymbols(new Map([[8192, 'second']]));
		assert.deepStrictEqual(maps.slice(-2), ['clear', { '8192': 'second' }]);
		wrapper.dispose();
		await wrapper.liftBytes(Buffer.from([0xc3]), 4096, 'x64', 'linux');
		assert.deepStrictEqual(maps.slice(-2), ['clear', { '8192': 'second' }]);
		wrapper.dispose();
	});
});
