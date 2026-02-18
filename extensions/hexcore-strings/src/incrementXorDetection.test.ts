/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 15: XOR com incremento detecta encoding

import * as assert from 'assert';
import * as fc from 'fast-check';
import { multiByteXorScan, MultiByteXorResult } from './multiByteXor';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Apply increment XOR encoding.
 *
 * Decode is: decoded[i] = buffer[i] ^ ((baseKey + i) & 0xFF)
 * Encode is: encoded[i] = plain[i] ^ ((baseKey + i) & 0xFF)   (XOR is its own inverse)
 */
function incrementXorEncode(plaintext: Buffer, baseKey: number): Buffer {
	const out = Buffer.alloc(plaintext.length);
	for (let i = 0; i < plaintext.length; i++) {
		out[i] = plaintext[i] ^ ((baseKey + i) & 0xFF);
	}
	return out;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Generate English-like printable text with spaces. Words are 2–8 lowercase
 * letters separated by single spaces, producing text long enough (64+ chars)
 * for the increment XOR scanner to detect reliably.
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

suite('Property 15: XOR com incremento detecta encoding', () => {

	/**
	 * **Validates: Requirements 6.5**
	 *
	 * For any printable text encoded with increment XOR (key + i for each byte i),
	 * multiByteXorScan with enableIncrement: true MUST find at least one result
	 * with method === 'increment'.
	 */
	test('detects increment XOR encoded text', () => {
		fc.assert(
			fc.property(
				englishLikeTextArb(64, 512),
				fc.integer({ min: 0x00, max: 0xFF }),
				(plaintext: string, baseKey: number) => {
					const plaintextBuf = Buffer.from(plaintext, 'ascii');
					const encoded = incrementXorEncode(plaintextBuf, baseKey);

					const results: MultiByteXorResult[] = multiByteXorScan(encoded, 0, {
						keySizes: [],
						minLength: 6,
						minConfidence: 0.3,
						enableRolling: false,
						enableIncrement: true,
					});

					// Must find at least one result with method === 'increment'
					const increment = results.filter(r => r.method === 'increment');
					assert.ok(
						increment.length > 0,
						`No increment XOR result found for baseKey=0x${baseKey.toString(16).padStart(2, '0')}, ` +
						`plaintext length=${plaintext.length}, total results=${results.length}`,
					);
				},
			),
			{ numRuns: 100 },
		);
	});
});
