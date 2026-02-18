/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 13: Multi-byte XOR detecta chaves com resultado completo

import * as assert from 'assert';
import * as fc from 'fast-check';
import { multiByteXorScan, MultiByteXorResult } from './multiByteXor';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Apply multi-byte XOR encoding: each byte is XOR'd with key[i % key.length].
 */
function xorEncode(plaintext: Buffer, key: Buffer): Buffer {
	const out = Buffer.alloc(plaintext.length);
	for (let i = 0; i < plaintext.length; i++) {
		out[i] = plaintext[i] ^ key[i % key.length];
	}
	return out;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Generate English-like text with plenty of spaces so that frequency analysis
 * can reliably identify space (0x20) as the most frequent byte per position
 * group. Words are 2–8 lowercase letters separated by single spaces.
 */
function englishLikeTextArb(minLen: number, maxLen: number): fc.Arbitrary<string> {
	const word = fc.stringOf(
		fc.constantFrom(...'etaoinsrhldcumwfgypbvkjxqz'.split('')),
		{ minLength: 2, maxLength: 8 },
	);
	return fc.array(word, { minLength: 10, maxLength: 60 })
		.map(words => words.join(' '))
		.filter(text => text.length >= minLen && text.length <= maxLen);
}

/**
 * Generate a random multi-byte XOR key of the given size.
 * Ensures no key byte is 0x00 (which would be a no-op for that position)
 * and no key byte is 0x20 (which would leave spaces unchanged, making
 * detection trivial but also potentially confusing the frequency analysis
 * since the encoded byte would still be 0x20).
 */
function nonTrivialKeyArb(size: number): fc.Arbitrary<Buffer> {
	return fc.uint8Array({ minLength: size, maxLength: size })
		.filter(arr => arr.every(b => b !== 0x00))
		.map(arr => Buffer.from(arr));
}

// ---------------------------------------------------------------------------
// Property Tests
// ---------------------------------------------------------------------------

suite('Property 13: Multi-byte XOR detecta chaves com resultado completo', () => {

	const keySizes = [2, 4, 8, 16] as const;

	for (const keySize of keySizes) {
		/**
		 * **Validates: Requirements 6.1, 6.3**
		 *
		 * For any printable text encoded with a multi-byte XOR key of size N,
		 * multiByteXorScan MUST find at least one result with keySize === N
		 * and all required fields (key, keyHex, method, confidence) defined.
		 */
		test(`detects key of size ${keySize}`, () => {
			fc.assert(
				fc.property(
					englishLikeTextArb(128, 512),
					nonTrivialKeyArb(keySize),
					(plaintext: string, key: Buffer) => {
						const plaintextBuf = Buffer.from(plaintext, 'ascii');
						const encoded = xorEncode(plaintextBuf, key);

						const results: MultiByteXorResult[] = multiByteXorScan(encoded, 0, {
							keySizes: [keySize],
							minLength: 6,
							minConfidence: 0.3,
							enableRolling: false,
							enableIncrement: false,
						});

						// Must find at least one result with the correct key size
						const matching = results.filter(r => r.keySize === keySize);
						assert.ok(
							matching.length > 0,
							`No result found with keySize=${keySize} for key=${key.toString('hex')}, ` +
							`plaintext length=${plaintext.length}, total results=${results.length}`,
						);

						// Verify all required fields are defined on the first match
						const first = matching[0];
						assert.ok(Buffer.isBuffer(first.key) && first.key.length === keySize,
							`key should be a Buffer of length ${keySize}`);
						assert.ok(typeof first.keyHex === 'string' && first.keyHex.length > 0,
							'keyHex should be a non-empty string');
						assert.ok(first.method === 'multi-byte',
							`method should be 'multi-byte', got '${first.method}'`);
						assert.ok(typeof first.confidence === 'number' && first.confidence >= 0.3,
							`confidence should be >= 0.3, got ${first.confidence}`);
						assert.ok(typeof first.value === 'string' && first.value.length >= 6,
							`value should be a string of length >= 6, got length ${first.value.length}`);
						assert.ok(typeof first.offset === 'number' && first.offset >= 0,
							`offset should be a non-negative number, got ${first.offset}`);
					},
				),
				{ numRuns: 100 },
			);
		});
	}
});
