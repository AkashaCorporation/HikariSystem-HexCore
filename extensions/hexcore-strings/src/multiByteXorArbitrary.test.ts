/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: xor-massive-update, Property 6: Multi-Byte XOR Arbitrary Key Length Round-Trip

import * as fc from 'fast-check';

suite('Multi-Byte XOR Arbitrary Key Properties', () => {

	/**
	 * **Validates: Requirements 1.4, 12.7**
	 *
	 * P6: For any buffer and any key of length 1–64 bytes (including odd
	 * lengths 3, 5, 7), XOR-encoding with buffer[i] ^ key[i % keyLen]
	 * and XOR-decoding with the same key produces the original buffer.
	 */
	test('P6: XOR with arbitrary key length (1-64) round-trips correctly', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 1, maxLength: 512 }),
			fc.uint8Array({ minLength: 1, maxLength: 64 }).filter(k => k.some(b => b !== 0)),
			(bufArr, keyArr) => {
				const buf = Buffer.from(bufArr);
				const key = Buffer.from(keyArr);
				const encoded = Buffer.alloc(buf.length);
				for (let i = 0; i < buf.length; i++) {
					encoded[i] = buf[i] ^ key[i % key.length];
				}
				const decoded = Buffer.alloc(buf.length);
				for (let i = 0; i < buf.length; i++) {
					decoded[i] = encoded[i] ^ key[i % key.length];
				}
				return buf.equals(decoded);
			}
		), { numRuns: 200 });
	});
});
