/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fc from 'fast-check';
import { addEncode, addDecode, subEncode, subDecode, rotEncode, rotDecode } from './compositeCipher';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 1: ADD/SUB Round-Trip
// **Validates: Requirements 3.1, 3.2, 3.6**
// ---------------------------------------------------------------------------

suite('Composite Cipher Properties', () => {

	test('P1: ADD encode then ADD decode = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.integer({ min: 1, max: 255 }),
				(arr, key) => {
					const buf = Buffer.from(arr);
					const encoded = addEncode(buf, key);
					const decoded = addDecode(encoded, key);
					return buf.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});

	test('P1: SUB encode then SUB decode = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.integer({ min: 1, max: 255 }),
				(arr, key) => {
					const buf = Buffer.from(arr);
					const encoded = subEncode(buf, key);
					const decoded = subDecode(encoded, key);
					return buf.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});

	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 2: ROT Round-Trip
	// **Validates: Requirements 3.3, 3.7**
	// -----------------------------------------------------------------------

	test('P2: ROT-N encode then ROT-N decode = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.integer({ min: 1, max: 25 }),
				(arr, n) => {
					const buf = Buffer.from(arr);
					const encoded = rotEncode(buf, n);
					const decoded = rotDecode(encoded, n);
					return buf.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});

	test('P2: ROT-N preserves non-alphabetic bytes unchanged', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.integer({ min: 1, max: 25 }),
				(arr, n) => {
					const buf = Buffer.from(arr);
					const encoded = rotEncode(buf, n);
					for (let i = 0; i < buf.length; i++) {
						const byte = buf[i];
						const isAlpha = (byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A);
						if (!isAlpha) {
							if (encoded[i] !== byte) { return false; }
						}
					}
					return true;
				}
			),
			{ numRuns: 200 }
		);
	});
});
