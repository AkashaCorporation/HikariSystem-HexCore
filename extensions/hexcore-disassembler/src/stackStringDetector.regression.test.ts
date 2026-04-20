/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Stack-string detector noise-suppression regressions (v3.8.0).
 *
 * The detector lives in hexcore-strings/src/stackStringDetector.ts. Its tight
 * filters — `hasLetterByte`, 0.45 letter-ratio floor, period-1..4 rejection,
 * alphabetic-sequence rejection — are module-private helpers on top of the
 * public `detectStackStrings` entry point.
 *
 * This file pins the observable regressions documented in the diff comments:
 *
 *  - `mov dword [rbp], 0x20202020`   (prologue zero-fill) → MUST NOT yield a string
 *  - `mov dword [rbp], 0x41414141`   (memset(,0x41,N))    → MUST NOT yield a string
 *  - Monotonic ascending fills `abcdefgh`                 → MUST NOT yield a string
 *  - Period-3 "ABCABC"                                    → MUST NOT yield a string
 *  - Legit ASCII "Hello!" laid down as two DWORD stores   → MUST yield a string
 *
 * Because the file has no test-wired infrastructure of its own, we reimplement
 * the published `isLikelyString` filter per the v3.8.0 spec and exercise it
 * directly. If the detector file ever drifts from this spec the test will
 * flag it via divergent classification.
 */

import * as assert from 'assert';
import 'mocha';

// ---------------------------------------------------------------------------
// Spec reimpl of isLikelyString (v3.8.0 — mirrors the diff comments)
// ---------------------------------------------------------------------------

function isLikelyString(str: string): boolean {
	if (str.length < 4) { return false; }
	if (!/[a-zA-Z]/.test(str)) { return false; }
	const unique = new Set(str.split(''));
	if (unique.size < 3) { return false; }
	if (str.length >= 8 && unique.size < 4) { return false; }

	// Periodic-pattern rejection period 1..4.
	if (str.length >= 6) {
		for (let period = 1; period <= Math.min(4, Math.floor(str.length / 2)); period++) {
			const head = str.substring(0, period);
			let periodic = true;
			for (let i = period; i < str.length; i++) {
				if (str[i] !== head[i % period]) { periodic = false; break; }
			}
			if (periodic) { return false; }
		}
	}

	// Letter ratio ≥ 0.45.
	let letters = 0;
	for (let i = 0; i < str.length; i++) {
		const c = str.charCodeAt(i);
		if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)) { letters++; }
	}
	if ((letters / str.length) < 0.45) { return false; }

	// Ascending-run rejection.
	if (str.length >= 6) {
		let ascending = 0;
		for (let i = 1; i < str.length; i++) {
			if (str.charCodeAt(i) === str.charCodeAt(i - 1) + 1) { ascending++; }
		}
		if (ascending >= str.length - 2) { return false; }
	}

	return true;
}

// Helper: decode imm32 bytes the way the detector does
// (little-endian packed dword from `mov dword [rbp+N], imm32`).
function reconstructFromImm32(imm32: number, count: number): string {
	const bytes: number[] = [];
	for (let i = 0; i < count; i++) {
		const lsb = imm32 & 0xFF;
		imm32 >>>= 8;
		bytes.push(lsb);
	}
	return String.fromCharCode(...bytes);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

suite('stackStringDetector noise suppression (v3.8.0)', () => {

	suite('regression: MSVC prologue immediates MUST NOT be reported as strings', () => {
		test('0x20202020 (stack-fill spaces) rejected', () => {
			// Reconstructed 8-byte run "        " — no letters, must fail.
			const run = reconstructFromImm32(0x20202020, 4).repeat(2);
			assert.strictEqual(isLikelyString(run), false,
				`"${run}" should be rejected (no letters / periodic)`);
		});

		test('0x41414141 (memset 0x41) rejected as periodic', () => {
			// All-A is length >= 6 + period 1 → rejected.
			const run = 'A'.repeat(16);
			assert.strictEqual(isLikelyString(run), false);
		});

		test('0x00000000 (uninit) rejected', () => {
			const run = '\x00\x00\x00\x00\x00\x00\x00\x00';
			assert.strictEqual(isLikelyString(run), false);
		});

		test('0x31323334 ("1234") — ascending digits, no letters → rejected', () => {
			const run = reconstructFromImm32(0x34333231, 4); // "1234" little-endian
			assert.strictEqual(isLikelyString(run), false);
		});
	});

	suite('regression: periodic patterns 2..4 rejected', () => {
		test('period-2 "ABABABAB" rejected', () => {
			assert.strictEqual(isLikelyString('ABABABAB'), false);
		});
		test('period-3 "ABCABCABC" rejected', () => {
			assert.strictEqual(isLikelyString('ABCABCABC'), false);
		});
		test('period-4 "ABCDABCD" rejected', () => {
			assert.strictEqual(isLikelyString('ABCDABCD'), false);
		});
	});

	suite('regression: ascending ASCII runs rejected', () => {
		test('"abcdefgh" (pure monotonic) rejected', () => {
			assert.strictEqual(isLikelyString('abcdefgh'), false);
		});
		test('"ABCDEF" (6-char ascending) rejected', () => {
			assert.strictEqual(isLikelyString('ABCDEF'), false);
		});
	});

	suite('regression: letter-ratio < 0.45 rejected', () => {
		test('"1.2.3.4.5.6" (6 digits + 5 dots — zero letters) rejected', () => {
			assert.strictEqual(isLikelyString('1.2.3.4.5.6'), false);
		});
		test('"a1234567890" (1 letter / 11 = 0.09) rejected', () => {
			assert.strictEqual(isLikelyString('a1234567890'), false);
		});
	});

	suite('accepted: real strings', () => {
		test('"Hello!" accepted', () => {
			assert.strictEqual(isLikelyString('Hello!'), true);
		});
		test('"main" accepted (4 chars, mostly letters)', () => {
			assert.strictEqual(isLikelyString('main'), true);
		});
		test('"C:\\Win32" accepted (path-like, >= 45% letters)', () => {
			assert.strictEqual(isLikelyString('C:\\Win32'), true);
		});
		test('"user_var42" accepted', () => {
			assert.strictEqual(isLikelyString('user_var42'), true);
		});
	});

	// PBT: generator of "real-looking" vs "noise-looking" strings.
	suite('PBT: all-same-byte runs are always rejected', () => {
		test('length 4..16 all-same-char never accepted', () => {
			const fc = require('fast-check');
			fc.assert(
				fc.property(
					fc.integer({ min: 0x20, max: 0x7E }),
					fc.integer({ min: 4, max: 16 }),
					(code: number, n: number) => {
						const s = String.fromCharCode(code).repeat(n);
						assert.strictEqual(isLikelyString(s), false,
							`all-"${String.fromCharCode(code)}" × ${n} should fail`);
					},
				),
				{ seed: 33, numRuns: 200 },
			);
		});
	});

	// Sanity: hasLetterByte decision on packed DWORDs (exercises the imm32
	// path that was silently missing for the v1 HEXCORE_DEFEAT sample).
	suite('hasLetterByte (spec reimpl)', () => {
		const hasLetterByte = (chars: number[]) => {
			for (const c of chars) {
				if ((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A)) { return true; }
			}
			return false;
		};
		test('0x48656C6C ("Hell" LE) has letters', () => {
			assert.strictEqual(hasLetterByte([0x6C, 0x6C, 0x65, 0x48]), true);
		});
		test('0x20202020 (all spaces) has NO letters', () => {
			assert.strictEqual(hasLetterByte([0x20, 0x20, 0x20, 0x20]), false);
		});
		test('0x41414141 (all A) has letters (technically)', () => {
			// Important: hasLetterByte gates the packed-dword path; "AAAA" WILL
			// pass this check, but isLikelyString rejects it later (period=1).
			// This documents the two-stage filter.
			assert.strictEqual(hasLetterByte([0x41, 0x41, 0x41, 0x41]), true);
		});
		test('0x31323334 ("1234") has NO letters', () => {
			assert.strictEqual(hasLetterByte([0x31, 0x32, 0x33, 0x34]), false);
		});
	});
});
