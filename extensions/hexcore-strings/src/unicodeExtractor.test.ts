import * as assert from 'assert';
import { extractUnicodeFromChunk } from './unicodeExtractor';

suite('UTF-16LE extractor boundaries', () => {
	test('finds a wide string starting at an odd file offset', () => {
		const prefix = Buffer.from([0xCC]);
		const path = 'C:\\Windows\\System32\\notepad.exe';
		const buffer = Buffer.concat([prefix, Buffer.from(path + '\0', 'utf16le')]);
		const result = extractUnicodeFromChunk(buffer, 0, 4, Buffer.alloc(0), 0, true);

		assert.deepStrictEqual(result.strings, [
			{ offset: 1, value: path, encoding: 'UTF-16LE' }
		]);
	});

	test('preserves a wide string split across chunks', () => {
		const bytes = Buffer.from('cross-chunk\0', 'utf16le');
		const first = extractUnicodeFromChunk(bytes.subarray(0, 9), 0x2001, 4, Buffer.alloc(0), 0x2001);
		assert.deepStrictEqual(first.strings, []);

		const second = extractUnicodeFromChunk(
			bytes.subarray(9),
			0x2001 + 9,
			4,
			first.carryover,
			first.carryoverOffset,
			true
		);
		assert.deepStrictEqual(second.strings, [
			{ offset: 0x2001, value: 'cross-chunk', encoding: 'UTF-16LE' }
		]);
	});

	test('flushes a final wide string without a NUL terminator', () => {
		const buffer = Buffer.from('unterminated', 'utf16le');
		const result = extractUnicodeFromChunk(buffer, 0x3000, 4, Buffer.alloc(0), 0x3000, true);
		assert.deepStrictEqual(result.strings, [
			{ offset: 0x3000, value: 'unterminated', encoding: 'UTF-16LE' }
		]);
	});
});
