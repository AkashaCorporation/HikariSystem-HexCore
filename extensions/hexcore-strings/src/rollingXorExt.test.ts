/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fc from 'fast-check';
import { rollingXorExtEncode, rollingXorExtDecode } from './rollingXorExt';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 5: Rolling XOR Extended Round-Trip
// **Validates: Requirements 7.1, 7.4**
// ---------------------------------------------------------------------------

suite('Rolling XOR Ext Properties', () => {

	test('P5: encode then decode with same seed and windowSize = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 5, maxLength: 512 }),
				fc.integer({ min: 0, max: 255 }),
				fc.integer({ min: 1, max: 4 }),
				(arr, seed, windowSize) => {
					const plaintext = Buffer.from(arr);
					const encoded = rollingXorExtEncode(plaintext, seed, windowSize);
					const decoded = rollingXorExtDecode(encoded, seed, windowSize);
					return plaintext.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});
});
