/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 14: Rolling XOR detecta encoding

import * as assert from 'assert';
import * as fc from 'fast-check';
import { multiByteXorScan, MultiByteXorResult } from './multiByteXor';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Apply rolling XOR encoding (inverse of the rolling XOR decode).
 *
 * Decode is: decoded[0] = buffer[0] ^ seed, decoded[i] = buffer[i] ^ buffer[i-1]
 * Encode is: encoded[0] = plain[0] ^ seed, encoded[i] = plain[i] ^ encoded[i-1]
 */
function rollingXorEncode(plaintext: Buffer, seed: number): Buffer {
	const out = Buffer.alloc(plaintext.length);
	out[0] = plaintext[0] ^ seed;
	for (let i = 1; i < plaintext.length; i++) {
		out[i] = plaintext[i] ^ out[i - 1];
	}
	return out;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Generate English-like printable text with spaces. Words are 2–8 lowercase
 * letters separated by single spaces, producing text long enough (64+ chars)
 * for the rolling XOR scanner to detect reliably.
 */
function englishLikeTextArb(minLen: number, maxLen: number): fc.Arbitrary<string> {
	const word = fc.stringOf(
		fc.constantFrom(...'etaoinsrhldcumwfgypbvkjxqz'.split('')),
		{ minLength: 2, maxLength: 8 },
	);
	return fc.array(word, { minLength: 12, maxLength: 80 })
		.map(words => words.join(' '))
		.filter(text => text.length >= minLen && text.length <= maxLen);
}

// ---------------------------------------------------------------------------
// Property Tests
// ---------------------------------------------------------------------------

suite('Property 14: Rolling XOR detecta encoding', () => {

	/**
	 * **Validates: Requirements 6.4**
	 *
	 * For any printable text encoded with rolling XOR (each byte XOR'd with
	 * the previous encoded byte, first byte XOR'd with a seed), multiByteXorScan
	 * with enableRolling: true MUST find at least one result with method === 'rolling'.
	 */
	test('detects rolling XOR encoded text', () => {
		fc.assert(
			fc.property(
				englishLikeTextArb(64, 512),
				fc.integer({ min: 0x00, max: 0xFF }),
				(plaintext: string, seed: number) => {
					const plaintextBuf = Buffer.from(plaintext, 'ascii');
					const encoded = rollingXorEncode(plaintextBuf, seed);

					const results: MultiByteXorResult[] = multiByteXorScan(encoded, 0, {
						keySizes: [],
						minLength: 6,
						minConfidence: 0.3,
						enableRolling: true,
						enableIncrement: false,
					});

					// Must find at least one result with method === 'rolling'
					const rolling = results.filter(r => r.method === 'rolling');
					assert.ok(
						rolling.length > 0,
						`No rolling XOR result found for seed=0x${seed.toString(16).padStart(2, '0')}, ` +
						`plaintext length=${plaintext.length}, total results=${results.length}`,
					);
				},
			),
			{ numRuns: 100 },
		);
	});
});
