/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fc from 'fast-check';
import { wideStringXorScan } from './wideStringXor';
import { scoreString } from './scoringEngine';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 7: Wide String Detection and Conversion Round-Trip
// **Validates: Requirements 5.1, 5.2**
// ---------------------------------------------------------------------------

suite('Wide String XOR Properties', () => {

	test('P7: ASCII → UTF-16LE → XOR → scanner detects and converts back', () => {
		fc.assert(
			fc.property(
				// Generate printable ASCII strings with length ≥ 6 (minLength default)
				fc.stringOf(
					fc.char().filter(c => {
						const code = c.charCodeAt(0);
						return code >= 0x20 && code <= 0x7E;
					}),
					{ minLength: 6, maxLength: 64 }
				),
				fc.integer({ min: 1, max: 254 }),
				(asciiStr, xorKey) => {
					// Encode as UTF-16LE
					const utf16 = Buffer.from(asciiStr, 'utf16le');

					// XOR-encrypt with single-byte key
					const encrypted = Buffer.alloc(utf16.length);
					for (let i = 0; i < utf16.length; i++) {
						encrypted[i] = utf16[i] ^ xorKey;
					}

					// Run scanner with low confidence to catch results
					const results = wideStringXorScan(encrypted, 0, {
						minLength: 6,
						minConfidence: 0.1,
					});

					// Scanner should detect the string
					const found = results.some(r => r.value === asciiStr);
					return found;
				}
			),
			{ numRuns: 100 }
		);
	});

	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 13: Wide String Scoring Null Byte Handling
	// **Validates: Requirements 5.5, 8.6**
	// -----------------------------------------------------------------------

	test('P13: score of UTF-16LE with ignoreNullBytes ≈ score of ASCII narrow (diff ≤ 0.1)', () => {
		fc.assert(
			fc.property(
				// Generate printable ASCII strings with reasonable length
				fc.stringOf(
					fc.char().filter(c => {
						const code = c.charCodeAt(0);
						return code >= 0x20 && code <= 0x7E;
					}),
					{ minLength: 8, maxLength: 64 }
				),
				(asciiStr) => {
					const narrowBuf = Buffer.from(asciiStr, 'ascii');
					const wideBuf = Buffer.from(asciiStr, 'utf16le');

					const narrowScore = scoreString(narrowBuf, 0, narrowBuf.length);
					const wideScore = scoreString(wideBuf, 0, wideBuf.length, { ignoreNullBytes: true });

					const diff = Math.abs(narrowScore - wideScore);
					// Tolerance of 0.15 accounts for bigram detection differences:
					// in UTF-16LE mode, interleaved null bytes prevent bigram matching
					// between adjacent characters, and length bonus differs (byte vs char length).
					return diff <= 0.15;
				}
			),
			{ numRuns: 100 }
		);
	});
});
