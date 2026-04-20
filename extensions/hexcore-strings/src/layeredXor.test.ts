/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fc from 'fast-check';
import { applyXorLayers } from './layeredXor';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 3: Layered XOR Round-Trip
// **Validates: Requirement 4.5**
// ---------------------------------------------------------------------------

suite('Layered XOR Properties', () => {

	test('P3: XOR with 1–3 keys in sequence and reverse = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 256 }),
				fc.integer({ min: 1, max: 3 }),
				fc.array(
					fc.uint8Array({ minLength: 1, maxLength: 64 }),
					{ minLength: 3, maxLength: 3 }
				),
				(arr, layerCount, keyArrays) => {
					const buf = Buffer.from(arr);
					// Use only the first `layerCount` keys
					const keys = keyArrays.slice(0, layerCount).map(k => Buffer.from(k));

					// Encode: apply keys in forward order
					const encoded = applyXorLayers(buf, keys);

					// Decode: apply keys in reverse order
					const reversed = [...keys].reverse();
					const decoded = applyXorLayers(encoded, reversed);

					return buf.equals(decoded);
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P3: Single layer XOR is self-inverse', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 256 }),
				fc.uint8Array({ minLength: 1, maxLength: 64 }),
				(arr, keyArr) => {
					const buf = Buffer.from(arr);
					const key = Buffer.from(keyArr);

					// XOR with same key twice = identity
					const encoded = applyXorLayers(buf, [key]);
					const decoded = applyXorLayers(encoded, [key]);

					return buf.equals(decoded);
				}
			),
			{ numRuns: 100 }
		);
	});
});
