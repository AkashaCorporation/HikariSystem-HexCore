import * as assert from 'assert';
import { mergeMappedMemoryRegions } from './memoryRegionMerge';

suite('Debugger mapped memory regions', () => {
	test('keeps raw image and stack while naming the tracked heap', () => {
		const result = mergeMappedMemoryRegions(
			[
				{ address: 0x7fff0000n, size: 0x10000n, permissions: 'rw' },
				{ address: 0x400000n, size: 0x1000n, permissions: 'rx' },
				{ address: 0x05000000n, size: 0x01000000n, permissions: 'rw' }
			],
			[
				{ address: 0x05000000n, size: 0x01000000, name: 'heap' }
			]
		);

		assert.deepStrictEqual(result, [
			{ address: 0x400000n, size: 0x1000, permissions: 'rx' },
			{ address: 0x05000000n, size: 0x01000000, permissions: 'rw', name: 'heap' },
			{ address: 0x7fff0000n, size: 0x10000, permissions: 'rw' }
		]);
	});
});
