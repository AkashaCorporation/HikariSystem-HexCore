/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 16: XOR round-trip

import * as assert from 'assert';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Inline XOR helpers (internal functions are not exported from multiByteXor.ts)
// ---------------------------------------------------------------------------

/**
 * Apply multi-byte XOR: each byte is XOR'd with key[i % key.length].
 */
function xorMultiByte(buf: Buffer, key: Buffer): Buffer {
	const out = Buffer.alloc(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ key[i % key.length];
	}
	return out;
}

/**
 * Apply rolling XOR encoding.
 *
 * The scanner's decode is:
 *   decoded[0] = encoded[0] ^ seed
 *   decoded[i] = encoded[i] ^ encoded[i-1]   (i > 0)
 *
 * So the inverse (encode) is:
 *   encoded[0] = plain[0] ^ seed
 *   encoded[i] = plain[i] ^ encoded[i-1]     (i > 0)
 */
function rollingXorEncode(buf: Buffer, seed: number): Buffer {
	const out = Buffer.alloc(buf.length);
	if (buf.length === 0) {
		return out;
	}
	out[0] = buf[0] ^ seed;
	for (let i = 1; i < buf.length; i++) {
		out[i] = buf[i] ^ out[i - 1];
	}
	return out;
}

/**
 * Decode rolling XOR (matches scanRolling in multiByteXor.ts):
 *   decoded[0] = encoded[0] ^ seed
 *   decoded[i] = encoded[i] ^ encoded[i-1]   (i > 0)
 */
function rollingXorDecode(encoded: Buffer, seed: number): Buffer {
	const out = Buffer.alloc(encoded.length);
	if (encoded.length === 0) {
		return out;
	}
	out[0] = encoded[0] ^ seed;
	for (let i = 1; i < encoded.length; i++) {
		out[i] = encoded[i] ^ encoded[i - 1];
	}
	return out;
}

/**
 * Apply XOR with increment: decoded[i] = buf[i] ^ ((baseKey + i) & 0xFF).
 */
function xorIncrement(buf: Buffer, baseKey: number): Buffer {
	const out = Buffer.alloc(buf.length);
	for (let i = 0; i < buf.length; i++) {
		out[i] = buf[i] ^ ((baseKey + i) & 0xFF);
	}
	return out;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/** Arbitrary non-empty buffer of bytes (1–512 bytes). */
function bufferArb(maxLen = 512): fc.Arbitrary<Buffer> {
	return fc.uint8Array({ minLength: 1, maxLength: maxLen })
		.map(arr => Buffer.from(arr));
}

/** Arbitrary single-byte key (0x00–0xFF). */
function singleByteKeyArb(): fc.Arbitrary<Buffer> {
	return fc.integer({ min: 0, max: 255 }).map(b => Buffer.from([b]));
}

/** Arbitrary multi-byte key of a given size. */
function multiByteKeyArb(size: number): fc.Arbitrary<Buffer> {
	return fc.uint8Array({ minLength: size, maxLength: size })
		.map(arr => Buffer.from(arr));
}

/** Arbitrary seed byte for rolling XOR. */
function seedArb(): fc.Arbitrary<number> {
	return fc.integer({ min: 0, max: 255 });
}

// ---------------------------------------------------------------------------
// Property Tests
// ---------------------------------------------------------------------------

suite('Property 16: XOR round-trip', () => {

	/**
	 * **Validates: Requirements 6.7**
	 *
	 * Single-byte XOR round-trip: xor(xor(buf, key), key) === buf
	 */
	test('single-byte key round-trip', () => {
		fc.assert(
			fc.property(bufferArb(), singleByteKeyArb(), (buf, key) => {
				const encrypted = xorMultiByte(buf, key);
				const decrypted = xorMultiByte(encrypted, key);
				assert.ok(buf.equals(decrypted),
					`Round-trip failed for key=${key.toString('hex')}, bufLen=${buf.length}`);
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 6.7**
	 *
	 * Multi-byte XOR round-trip for key sizes 2, 4, 8, 16.
	 */
	test('multi-byte key round-trip (2, 4, 8, 16 bytes)', () => {
		const keySizes = [2, 4, 8, 16];
		for (const keySize of keySizes) {
			fc.assert(
				fc.property(bufferArb(), multiByteKeyArb(keySize), (buf, key) => {
					const encrypted = xorMultiByte(buf, key);
					const decrypted = xorMultiByte(encrypted, key);
					assert.ok(buf.equals(decrypted),
						`Round-trip failed for keySize=${keySize}, key=${key.toString('hex')}, bufLen=${buf.length}`);
				}),
				{ numRuns: 100 }
			);
		}
	});

	/**
	 * **Validates: Requirements 6.7**
	 *
	 * Rolling XOR round-trip: decode(encode(buf, seed), seed) === buf
	 */
	test('rolling XOR round-trip', () => {
		fc.assert(
			fc.property(bufferArb(), seedArb(), (buf, seed) => {
				const encoded = rollingXorEncode(buf, seed);
				const decoded = rollingXorDecode(encoded, seed);
				assert.ok(buf.equals(decoded),
					`Rolling XOR round-trip failed for seed=0x${seed.toString(16)}, bufLen=${buf.length}`);
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 6.7**
	 *
	 * Increment XOR round-trip: xorInc(xorInc(buf, key), key) === buf
	 */
	test('increment XOR round-trip', () => {
		fc.assert(
			fc.property(bufferArb(), seedArb(), (buf, baseKey) => {
				const encrypted = xorIncrement(buf, baseKey);
				const decrypted = xorIncrement(encrypted, baseKey);
				assert.ok(buf.equals(decrypted),
					`Increment XOR round-trip failed for baseKey=0x${baseKey.toString(16)}, bufLen=${buf.length}`);
			}),
			{ numRuns: 100 }
		);
	});
});
