/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { FunctionSeedRegistry } from './functionSeeds';

suite('Function seed evidence', () => {
	test('keeps control-flow labels weak and confirmed entries strong', () => {
		const registry = new FunctionSeedRegistry();
		registry.record(0x1000, { kind: 'entry' });
		registry.record(0x1010, { kind: 'prologue' });
		registry.record(0x1020, { kind: 'direct-call', sourceAddress: 0x1005 });
		assert.strictEqual(registry.isStrong(0x1000), true);
		assert.strictEqual(registry.isStrong(0x1010), false);
		assert.strictEqual(registry.isStrong(0x1020), true);
		assert.deepStrictEqual(registry.strongAddresses(), [0x1000, 0x1020]);
	});

	test('deduplicates identical evidence without losing independent sources', () => {
		const registry = new FunctionSeedRegistry();
		registry.record(0x2000, { kind: 'direct-call', sourceAddress: 0x1100 });
		registry.record(0x2000, { kind: 'direct-call', sourceAddress: 0x1100 });
		registry.record(0x2000, { kind: 'direct-call', sourceAddress: 0x1200 });
		assert.strictEqual(registry.get(0x2000).length, 2);
	});
});
