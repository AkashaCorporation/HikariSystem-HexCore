import * as assert from 'assert';
import { extractASCIIFromChunk } from './asciiExtractor';

suite('ASCII extractor boundaries', () => {
	test('splits adjacent messages at LF and preserves their offsets', () => {
		const welcome = 'Welcome to callfuscated crackme.';
		const prompt = 'To register enter your password: ';
		const buffer = Buffer.from(`${welcome}\n${prompt}\0`, 'ascii');
		const result = extractASCIIFromChunk(buffer, 0xD008, 4, '', 0xD008);

		assert.deepStrictEqual(result.strings, [
			{ offset: 0xD008, value: welcome, encoding: 'ASCII' },
			{ offset: 0xD008 + welcome.length + 1, value: prompt.trim(), encoding: 'ASCII' }
		]);
		assert.strictEqual(result.carryover, '');
	});

	test('preserves a string split across read chunks', () => {
		const first = extractASCIIFromChunk(Buffer.from('cross-', 'ascii'), 0x2000, 4, '', 0x2000);
		assert.deepStrictEqual(first.strings, []);

		const second = extractASCIIFromChunk(
			Buffer.from('chunk\0', 'ascii'),
			0x2006,
			4,
			first.carryover,
			first.carryoverOffset
		);
		assert.deepStrictEqual(second.strings, [
			{ offset: 0x2000, value: 'cross-chunk', encoding: 'ASCII' }
		]);
	});

	test('treats CRLF as one logical boundary without empty findings', () => {
		const result = extractASCIIFromChunk(Buffer.from('first\r\nsecond\0', 'ascii'), 0x3000, 4, '', 0x3000);
		assert.deepStrictEqual(result.strings.map(s => s.value), ['first', 'second']);
	});
});
