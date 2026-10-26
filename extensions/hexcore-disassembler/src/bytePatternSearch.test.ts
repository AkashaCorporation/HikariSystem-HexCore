import * as assert from 'assert';
import { scanBytePatternPage } from './bytePatternSearch';

suite('byte pattern search pagination', () => {
	const exact = (value: number) => [{ value, wildcard: false }];

	test('distinguishes an exact full page from truncation', () => {
		assert.deepStrictEqual(scanBytePatternPage(Uint8Array.from([1, 2, 1]), exact(1), 2), {
			offsets: [0, 2],
			truncated: false,
		});
	});

	test('returns the first omitted match as a lossless continuation offset', () => {
		assert.deepStrictEqual(scanBytePatternPage(Uint8Array.from([1, 2, 1, 1]), exact(1), 2), {
			offsets: [0, 2],
			truncated: true,
			nextOffset: 3,
		});
	});

	test('resumes inclusively at nextOffset', () => {
		assert.deepStrictEqual(scanBytePatternPage(Uint8Array.from([1, 2, 1, 1]), exact(1), 2, 3), {
			offsets: [3],
			truncated: false,
		});
	});

	test('supports wildcard bytes', () => {
		assert.deepStrictEqual(scanBytePatternPage(
			Uint8Array.from([0x48, 0x8b, 0x01, 0x48, 0x8b, 0xff]),
			[
				{ value: 0x48, wildcard: false },
				{ value: 0x8b, wildcard: false },
				{ value: 0, wildcard: true },
			],
			10,
		), {
			offsets: [0, 3],
			truncated: false,
		});
	});
});
