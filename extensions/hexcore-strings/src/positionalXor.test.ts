/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as fc from 'fast-check';
import { counterLinearApply, blockRotateApply } from './positionalXor';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 4: Positional XOR Round-Trip
// **Validates: Requirements 6.1, 6.2, 6.5**
// ---------------------------------------------------------------------------

suite('Positional XOR Properties', () => {

	test('P4: counter-linear encode then decode = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.integer({ min: 0, max: 255 }),
				fc.integer({ min: 1, max: 8 }),
				(arr, base, step) => {
					const buf = Buffer.from(arr);
					const encoded = counterLinearApply(buf, base, step);
					const decoded = counterLinearApply(encoded, base, step);
					return buf.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});

	test('P4: block-rotate encode then decode = original buffer', () => {
		fc.assert(
			fc.property(
				fc.uint8Array({ minLength: 1, maxLength: 512 }),
				fc.oneof(
					fc.uint8Array({ minLength: 2, maxLength: 2 }),
					fc.uint8Array({ minLength: 4, maxLength: 4 }),
					fc.uint8Array({ minLength: 8, maxLength: 8 }),
				),
				fc.constantFrom(16, 32, 64, 128, 256),
				(arr, keyArr, blockSize) => {
					const buf = Buffer.from(arr);
					const key = Buffer.from(keyArr);
					const encoded = blockRotateApply(buf, key, blockSize);
					const decoded = blockRotateApply(encoded, key, blockSize);
					return buf.equals(decoded);
				}
			),
			{ numRuns: 200 }
		);
	});
});
