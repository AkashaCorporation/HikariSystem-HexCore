/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fc from 'fast-check';
import { detectKeyLengths } from './kasiskiDetector';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 10: Kasiski Key Length Detection
// **Validates: Requirements 1.1, 1.3**
//
// For any buffer of at least 256 bytes of English-like text (printable ASCII
// with spaces), encrypted with a repeating XOR key of length L (2 ≤ L ≤ 32),
// the Kasiski detector should include L (or a factor of L, or a multiple of L
// up to maxKeyLength) in its candidate key lengths.
// ---------------------------------------------------------------------------

/**
 * Generate a printable ASCII buffer with spaces that mimics English-like text.
 * Uses lowercase letters weighted toward common English letters plus spaces.
 */
function englishLikeArb(minLen: number, maxLen: number): fc.Arbitrary<Buffer> {
	// Common English letters weighted: e, t, a, o, i, n, s, h, r + space
	const commonChars = 'etaoinshrdlcumwfgypbvkjxqz';
	return fc.integer({ min: minLen, max: maxLen }).chain(len =>
		fc.array(
			fc.integer({ min: 0, max: 99 }),
			{ minLength: len, maxLength: len }
		).map(nums => {
			const bytes = Buffer.alloc(len);
			for (let i = 0; i < len; i++) {
				const r = nums[i];
				if (r < 20) {
					// 20% spaces
					bytes[i] = 0x20;
				} else {
					// 80% letters, biased toward common ones
					const idx = r < 60
						? (r - 20) % 10  // first 10 common letters (40%)
						: (r - 60) % commonChars.length; // all letters (40%)
					bytes[i] = commonChars.charCodeAt(idx);
				}
			}
			return bytes;
		})
	);
}

/**
 * Generate a random XOR key of a given length with no all-zero bytes.
 */
function xorKeyArb(keyLen: number): fc.Arbitrary<Buffer> {
	return fc.uint8Array({ minLength: keyLen, maxLength: keyLen })
		.filter(arr => arr.some(b => b !== 0))
		.map(arr => Buffer.from(arr));
}

/**
 * Encrypt a buffer with a repeating XOR key.
 */
function xorEncrypt(plaintext: Buffer, key: Buffer): Buffer {
	const encrypted = Buffer.alloc(plaintext.length);
	for (let i = 0; i < plaintext.length; i++) {
		encrypted[i] = plaintext[i] ^ key[i % key.length];
	}
	return encrypted;
}

/**
 * Check if a value is a factor of target, or target is a factor of value,
 * or they share a common factor relationship (value is a multiple of target
 * up to maxKeyLength).
 */
function isRelatedKeyLength(candidate: number, actualKeyLen: number, maxKeyLength: number): boolean {
	// Exact match
	if (candidate === actualKeyLen) {
		return true;
	}
	// Candidate is a factor of actual key length
	if (actualKeyLen % candidate === 0) {
		return true;
	}
	// Candidate is a multiple of actual key length (within maxKeyLength)
	if (candidate % actualKeyLen === 0 && candidate <= maxKeyLength) {
		return true;
	}
	return false;
}

suite('Kasiski Detector Properties', () => {

	test('P10: Kasiski detects key length L (or factor/multiple) for XOR-encrypted English-like text', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 2, max: 32 }).chain(keyLen =>
					fc.tuple(
						fc.constant(keyLen),
						englishLikeArb(256, 512),
						xorKeyArb(keyLen),
					)
				),
				([keyLen, plaintext, key]) => {
					const encrypted = xorEncrypt(plaintext, key);
					const result = detectKeyLengths(encrypted, 64);

					// At least one candidate should be related to the actual key length
					const hasRelated = result.candidateLengths.some(
						c => isRelatedKeyLength(c, keyLen, 64)
					);

					return hasRelated;
				}
			),
			{ numRuns: 100 }
		);
	});

	// -------------------------------------------------------------------
	// Edge case: buffer too small returns empty candidates
	// -------------------------------------------------------------------
	test('Buffer smaller than 32 bytes returns empty candidates', () => {
		const small = Buffer.alloc(16, 0x41);
		const result = detectKeyLengths(small);
		assert.deepStrictEqual(result.candidateLengths, []);
	});

	// -------------------------------------------------------------------
	// Edge case: detectionMethod is set correctly
	// -------------------------------------------------------------------
	test('detectionMethod is one of kasiski, ic, or both', () => {
		const buf = Buffer.alloc(256);
		for (let i = 0; i < buf.length; i++) {
			buf[i] = (i % 3 === 0) ? 0x20 : (0x61 + (i % 26));
		}
		// XOR with key [0xAB, 0xCD]
		const key = Buffer.from([0xAB, 0xCD]);
		const encrypted = xorEncrypt(buf, key);
		const result = detectKeyLengths(encrypted);
		assert.ok(
			result.detectionMethod === 'kasiski' ||
			result.detectionMethod === 'ic' ||
			result.detectionMethod === 'both'
		);
	});

	// -------------------------------------------------------------------
	// Edge case: at most 10 candidates returned
	// -------------------------------------------------------------------
	test('Returns at most 10 candidate lengths', () => {
		const buf = Buffer.alloc(512);
		for (let i = 0; i < buf.length; i++) {
			buf[i] = Math.floor(Math.random() * 256);
		}
		const result = detectKeyLengths(buf);
		assert.ok(result.candidateLengths.length <= 10);
	});
});
