/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { multiByteXorScan } from './multiByteXor';

// ---------------------------------------------------------------------------
// Encoding Helpers
// ---------------------------------------------------------------------------

/** Multi-byte XOR encode: each byte XOR'd with key[i % key.length]. */
function xorEncode(buf: Buffer, key: Buffer): Buffer {
	const out = Buffer.alloc(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ key[i % key.length];
	}
	return out;
}

/** Rolling XOR encode (inverse of decode): out[0] = buf[0] ^ seed, out[i] = buf[i] ^ out[i-1]. */
function rollingXorEncode(buf: Buffer, seed: number): Buffer {
	const out = Buffer.alloc(buf.length);
	out[0] = buf[0] ^ seed;
	for (let i = 1; i < buf.length; i++) {
		out[i] = buf[i] ^ out[i - 1];
	}
	return out;
}

/** Increment XOR encode: out[i] = buf[i] ^ ((baseKey + i) & 0xFF). */
function incrementXorEncode(buf: Buffer, baseKey: number): Buffer {
	const out = Buffer.alloc(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ ((baseKey + i) & 0xFF);
	}
	return out;
}

// ---------------------------------------------------------------------------
// Unit Tests — Task 9.10
// ---------------------------------------------------------------------------

suite('multiByteXorScan — unit tests', () => {

	/**
	 * **Validates: Requirements 6.1**
	 * Multi-byte XOR with a known 4-byte key should detect the original text.
	 */
	test('detects string encoded with known 4-byte XOR key', () => {
		// For frequency analysis to work, space (0x20) must be the most frequent
		// byte at every position modulo keySize. We achieve this by using words
		// of varying lengths (1-3 chars) so spaces land at all positions mod 4.
		const parts: string[] = [];
		const shortWords = ['a', 'I', 'an', 'be', 'do', 'go', 'he', 'if', 'in', 'is',
			'it', 'me', 'my', 'no', 'of', 'on', 'or', 'so', 'to', 'up',
			'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had'];
		for (let i = 0; i < 300; i++) {
			parts.push(shortWords[i % shortWords.length]);
		}
		const plaintext = parts.join(' ');
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const key = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
		const encoded = xorEncode(plaintextBuf, key);

		const results = multiByteXorScan(encoded, 0, {
			keySizes: [4],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: false,
			enableIncrement: false,
		});

		assert.ok(results.length > 0, 'Should find at least one result');

		// Verify result structure
		const match = results[0];
		assert.strictEqual(match.method, 'multi-byte');
		assert.strictEqual(match.keySize, 4);
		assert.ok(Buffer.isBuffer(match.key) && match.key.length === 4);
		assert.ok(typeof match.keyHex === 'string' && match.keyHex.startsWith('0x'));
		assert.ok(match.confidence >= 0.3);
		assert.ok(match.value.length >= 6, 'Decoded value should be at least 6 chars');
	});

	/**
	 * **Validates: Requirements 6.4**
	 * Rolling XOR with a known seed should detect the original text.
	 */
	test('detects string encoded with rolling XOR (seed=0x42)', () => {
		const plaintext = 'This is a rolling XOR encoded string that should be detected by the scanner easily';
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const seed = 0x42;
		const encoded = rollingXorEncode(plaintextBuf, seed);

		const results = multiByteXorScan(encoded, 0, {
			keySizes: [],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: true,
			enableIncrement: false,
		});

		// Should find at least one rolling result
		const rollingResults = results.filter(r => r.method === 'rolling');
		assert.ok(rollingResults.length > 0, 'Should find at least one rolling XOR result');

		// At least one result should contain part of the original text
		const hasOriginal = rollingResults.some(r => plaintext.includes(r.value));
		assert.ok(hasOriginal, `Expected rolling result containing original text, got: ${rollingResults.map(r => r.value).join(', ')}`);
	});

	/**
	 * **Validates: Requirements 6.5**
	 * Increment XOR with a known base key should detect the original text.
	 */
	test('detects string encoded with increment XOR (baseKey=0x10)', () => {
		const plaintext = 'Increment XOR encoded string for detection testing with known base key value here';
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const baseKey = 0x10;
		const encoded = incrementXorEncode(plaintextBuf, baseKey);

		const results = multiByteXorScan(encoded, 0, {
			keySizes: [],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: false,
			enableIncrement: true,
		});

		// Should find at least one increment result
		const incrementResults = results.filter(r => r.method === 'increment');
		assert.ok(incrementResults.length > 0, 'Should find at least one increment XOR result');

		// At least one result should contain part of the original text
		const hasOriginal = incrementResults.some(r => plaintext.includes(r.value));
		assert.ok(hasOriginal, `Expected increment result containing original text, got: ${incrementResults.map(r => r.value).join(', ')}`);
	});

	/**
	 * **Validates: Requirements 6.6**
	 * A buffer with no valid printable strings should return an empty array.
	 */
	test('returns empty array for buffer with no valid strings', () => {
		// A very short buffer (shorter than minLength=6) cannot produce any
		// printable run of length >= 6, regardless of XOR key.
		const buf = Buffer.from([0x01, 0x02, 0x03, 0x04]);

		const results = multiByteXorScan(buf, 0, {
			keySizes: [2, 4],
			minLength: 6,
			minConfidence: 0.6,
			enableRolling: false,
			enableIncrement: false,
		});

		assert.strictEqual(results.length, 0, 'Should return empty array for buffer shorter than minLength');
	});

	/**
	 * **Validates: Requirements 6.6**
	 * Results are deduplicated by offset:value key — the same decoded string
	 * at the same offset should not appear twice even if found by different methods.
	 */
	test('deduplicates results across methods', () => {
		// Use a long English-like string with spaces
		const plaintext = 'the quick brown fox jumps over the lazy dog and then some more text here for padding';
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const key = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
		const encoded = xorEncode(plaintextBuf, key);

		const results = multiByteXorScan(encoded, 0, {
			keySizes: [4],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: true,
			enableIncrement: true,
		});

		// Check that no two results share the same offset:value pair
		const dedupKeys = results.map(r => `${r.offset}:${r.value}`);
		const uniqueKeys = new Set(dedupKeys);
		assert.strictEqual(dedupKeys.length, uniqueKeys.size,
			`Found duplicate offset:value pairs in results: ${dedupKeys.filter((k, i) => dedupKeys.indexOf(k) !== i).join(', ')}`);
	});

	/**
	 * Verify results are sorted by confidence descending, then offset ascending.
	 */
	test('results are sorted by confidence desc then offset asc', () => {
		const plaintext = 'Hello World this is a test string for XOR detection and analysis purposes here';
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const key = Buffer.from([0xAB, 0xCD]);
		const encoded = xorEncode(plaintextBuf, key);

		const results = multiByteXorScan(encoded, 0, {
			keySizes: [2],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: true,
			enableIncrement: true,
		});

		for (let i = 1; i < results.length; i++) {
			const prev = results[i - 1];
			const curr = results[i];
			const sortOk = prev.confidence > curr.confidence ||
				(prev.confidence === curr.confidence && prev.offset <= curr.offset);
			assert.ok(sortOk,
				`Results not sorted at index ${i}: prev(conf=${prev.confidence}, off=${prev.offset}) vs curr(conf=${curr.confidence}, off=${curr.offset})`);
		}
	});

	/**
	 * Verify baseOffset is correctly applied to result offsets.
	 */
	test('baseOffset is added to result offsets', () => {
		const plaintext = 'Hello World this is a test string for XOR detection and analysis purposes here';
		const plaintextBuf = Buffer.from(plaintext, 'ascii');
		const key = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
		const encoded = xorEncode(plaintextBuf, key);
		const baseOffset = 0x1000;

		const results = multiByteXorScan(encoded, baseOffset, {
			keySizes: [4],
			minLength: 6,
			minConfidence: 0.3,
			enableRolling: false,
			enableIncrement: false,
		});

		assert.ok(results.length > 0, 'Should find at least one result');
		for (const r of results) {
			assert.ok(r.offset >= baseOffset,
				`Result offset ${r.offset} should be >= baseOffset ${baseOffset}`);
		}
	});
});
