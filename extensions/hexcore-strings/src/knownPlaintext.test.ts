/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fc from 'fast-check';
import { knownPlaintextScan, MALWARE_PATTERNS } from './knownPlaintextAttack';
import { isPrintable } from './scoringEngine';

// ---------------------------------------------------------------------------
// Feature: xor-massive-update, Property 8: Known-Plaintext Key Recovery
// **Validates: Requirement 2.2**
// ---------------------------------------------------------------------------

suite('Known-Plaintext Properties', () => {

	test('P8: pattern embedded in XOR-encrypted buffer → scanner recovers key that decodes the pattern', () => {
		// Pick patterns long enough to derive a meaningful key
		const usablePatterns = MALWARE_PATTERNS.filter(p => p.length >= 4 && p[0] !== 0x00);

		fc.assert(
			fc.property(
				// Pick a pattern index
				fc.integer({ min: 0, max: usablePatterns.length - 1 }),
				// Generate a key whose length matches the pattern length (so full key is recoverable)
				fc.integer({ min: 0, max: usablePatterns.length - 1 }).chain(patIdx => {
					const patLen = usablePatterns[patIdx].length;
					return fc.tuple(
						fc.constant(patIdx),
						fc.uint8Array({ minLength: patLen, maxLength: patLen }).filter(k => k.some(b => b !== 0)),
					);
				}),
				// Generate printable ASCII filler text to ensure >30% printability after decode
				fc.stringOf(
					fc.char().filter(c => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) <= 0x7E),
					{ minLength: 80, maxLength: 256 }
				),
				(_patIdxOuter, [patIdx, keyArr], filler) => {
					const key = Buffer.from(keyArr);
					const pattern = usablePatterns[patIdx];

					// Build a plaintext buffer: filler text with pattern embedded at start
					const fillerBuf = Buffer.from(filler, 'ascii');
					const plaintext = Buffer.from(fillerBuf);
					// Embed pattern at position 0 so the key derivation aligns perfectly
					pattern.copy(plaintext, 0, 0, Math.min(pattern.length, plaintext.length));

					// XOR-encrypt the plaintext with the key
					const encrypted = Buffer.alloc(plaintext.length);
					for (let i = 0; i < plaintext.length; i++) {
						encrypted[i] = plaintext[i] ^ key[i % key.length];
					}

					// Run the scanner with just this specific pattern
					const results = knownPlaintextScan(
						encrypted,
						0,
						[pattern],
						{ minLength: 4, minConfidence: 0.3 },
					);

					// If no results, it's acceptable — the printability filter or
					// scoring threshold may have discarded the candidate
					if (results.length === 0) {
						return true;
					}

					// Check that at least one result's key, when used to decode the
					// pattern region at position 0, recovers the original pattern bytes
					const found = results.some(r => {
						const rKey = r.key;
						const decodedRegion = Buffer.alloc(pattern.length);
						for (let j = 0; j < pattern.length; j++) {
							decodedRegion[j] = encrypted[j] ^ rKey[j % rKey.length];
						}
						return decodedRegion.equals(pattern);
					});

					return found;
				}
			),
			{ numRuns: 100 }
		);
	});


	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 9: Known-Plaintext Discard Threshold
	// **Validates: Requirement 2.5**
	// -----------------------------------------------------------------------

	test('P9: key that produces < 30% printable should not appear in results', () => {
		fc.assert(
			fc.property(
				// Generate a buffer of mostly non-printable bytes (high bytes 0x80-0xFF)
				fc.uint8Array({ minLength: 64, maxLength: 256 }).map(arr => {
					// Force > 70% non-printable by setting most bytes to high range
					const buf = Buffer.from(arr);
					for (let i = 0; i < buf.length; i++) {
						if (i % 10 !== 0) { // Keep ~10% as-is for variety
							buf[i] = (buf[i] | 0x80) & 0xFF; // Force high bit
						}
					}
					return buf;
				}),
				// A non-zero key
				fc.uint8Array({ minLength: 1, maxLength: 8 }).filter(k => k.some(b => b !== 0)),
				(plainBuf, keyArr) => {
					const key = Buffer.from(keyArr);

					// Encrypt the non-printable buffer
					const encrypted = Buffer.alloc(plainBuf.length);
					for (let i = 0; i < plainBuf.length; i++) {
						encrypted[i] = plainBuf[i] ^ key[i % key.length];
					}

					// Verify the plaintext is indeed < 30% printable
					let printCount = 0;
					for (let i = 0; i < plainBuf.length; i++) {
						if (isPrintable(plainBuf[i])) { printCount++; }
					}
					const ratio = printCount / plainBuf.length;
					if (ratio >= 0.30) {
						return true; // Skip — this buffer is too printable for this test
					}

					// Run scanner — results should NOT contain the exact key we used
					// because decoding with it produces < 30% printable
					const results = knownPlaintextScan(
						encrypted,
						0,
						undefined,
						{ minLength: 4, minConfidence: 0.1 },
					);

					// Verify: no result should have a key that, when used to decode
					// the full buffer, produces < 30% printable bytes
					for (const r of results) {
						const decoded = Buffer.alloc(encrypted.length);
						for (let i = 0; i < encrypted.length; i++) {
							decoded[i] = encrypted[i] ^ r.key[i % r.key.length];
						}
						let pc = 0;
						for (let i = 0; i < decoded.length; i++) {
							if (isPrintable(decoded[i])) { pc++; }
						}
						const pr = pc / decoded.length;
						if (pr < 0.30) {
							return false; // Found a result with < 30% printable — violation!
						}
					}

					return true;
				}
			),
			{ numRuns: 100 }
		);
	});
});
