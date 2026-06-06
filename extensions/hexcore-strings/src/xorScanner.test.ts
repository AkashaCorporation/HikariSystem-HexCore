/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: xor-bruteforce crib + bounded sample-window adoption (CyberChef parity).
// Covers: happy-path crib filtering, lone/valid sample windows, integer-flooring of
// fractional window args, NaN/negative/Infinity full-buffer fallback, and the two
// input-validation edges hardened in round 2:
//   (a) {sampleLength:0} must NOT silently return [] (full-buffer fallback), and
//   (b) {sampleOffset:invalid, sampleLength:valid} must scan the FULL buffer
//       (honor neither a coerced-to-0 offset nor the lone length).
// The default (no-crib / no-window) path is proven deep-equal to the baseline so the
// adoption is provably non-regressing.

import * as assert from 'assert';
import { xorBruteForce, XorResult } from './xorScanner';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** XOR-encode plaintext bytes under a single-byte key. */
function xorEncode(plain: Buffer, key: number): Buffer {
	const out = Buffer.alloc(plain.length);
	for (let i = 0; i < plain.length; i++) {
		out[i] = plain[i] ^ key;
	}
	return out;
}

/**
 * Build a buffer that decodes (under `key`) to natural-language text so the
 * brute-force scanner's confidence gate is satisfied and runs are produced.
 * Leading bytes are filler that also decode to printable text so quickCheck
 * (first 256 bytes) passes for `key`.
 */
function buildEncodedBuffer(opts: {
	totalLength: number;
	key: number;
	token: string;
	tokenOffset: number;
}): Buffer {
	const { totalLength, key, token, tokenOffset } = opts;
	// Filler is a long natural-language sentence repeated; decodes to printable
	// English so both quickCheck and the confidence scorer accept it.
	const filler = 'the quick brown fox jumps over the lazy dog while the river flows. ';
	const plain = Buffer.alloc(totalLength, 0x20); // spaces => printable filler
	for (let i = 0; i < totalLength; i++) {
		plain[i] = filler.charCodeAt(i % filler.length);
	}
	// Embed the token at the requested offset (with space padding so it forms
	// its own clean printable run boundary if needed).
	const tokenBuf = Buffer.from(` ${token} `, 'ascii');
	tokenBuf.copy(plain, tokenOffset);
	return xorEncode(plain, key);
}

/** Does any result contain `needle` in its decoded value? */
function hasValue(results: XorResult[], needle: string): boolean {
	return results.some(r => r.value.includes(needle));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

suite('xorBruteForce: crib + bounded sample-window adoption', () => {

	const KEY = 0x42;

	// -----------------------------------------------------------------------
	// Default-path / regression: no crib, no window => unchanged behavior
	// -----------------------------------------------------------------------

	test('default path: no crib / no window returns a non-empty baseline', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		assert.ok(baseline.length > 0, 'baseline scan should produce results');
	});

	test('default path is unchanged when sampleOffset/sampleLength are absent (deep-equal)', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		const withUndefinedWindow = xorBruteForce(buf, 0, { minLength: 6, sampleOffset: undefined, sampleLength: undefined });
		assert.deepStrictEqual(withUndefinedWindow, baseline);
	});

	test('default path is unchanged when cribs is undefined or empty (deep-equal)', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		assert.deepStrictEqual(xorBruteForce(buf, 0, { minLength: 6, cribs: undefined }), baseline);
		assert.deepStrictEqual(xorBruteForce(buf, 0, { minLength: 6, cribs: [] }), baseline);
	});

	// -----------------------------------------------------------------------
	// Crib filtering (CyberChef parity)
	// -----------------------------------------------------------------------

	test('crib filter prunes to decodes containing the crib (case-insensitive)', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'SuperSecretToken', tokenOffset: 64 });
		const filtered = xorBruteForce(buf, 0, { minLength: 6, cribs: ['supersecret'] });
		assert.ok(filtered.length > 0, 'crib hit should survive filtering');
		assert.ok(filtered.every(r => r.value.toLowerCase().includes('supersecret')),
			'every surviving result must contain the crib');
	});

	test('crib filter never invents results: a non-matching crib yields an empty set', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const filtered = xorBruteForce(buf, 0, { minLength: 6, cribs: ['zzz_no_such_substring_zzz'] });
		assert.strictEqual(filtered.length, 0);
	});

	// -----------------------------------------------------------------------
	// Valid windows: absolute offsets preserved
	// -----------------------------------------------------------------------

	test('lone valid sampleOffset bounds [offset, end) with ABSOLUTE offsets', () => {
		// Token within the first 256 bytes of the window so quickCheck passes.
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'WindowAnchor', tokenOffset: 2050 });
		const results = xorBruteForce(buf, 0, { minLength: 6, sampleOffset: 2000 });
		const hit = results.find(r => r.value.includes('WindowAnchor'));
		assert.ok(hit, 'token inside the window must be found');
		// Absolute offset = sampleStart(2000) + run.start; the token sits at file
		// offset 2050 (2049 = leading space), so the reported offset is >= 2000.
		assert.ok(hit!.offset >= 2000, `expected absolute offset >= 2000, got ${hit!.offset}`);
		assert.ok(Number.isInteger(hit!.offset), 'offsets must be integers');
	});

	test('fractional sampleOffset is floored => integer absolute offsets', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'FloorMe', tokenOffset: 2050 });
		const results = xorBruteForce(buf, 0, { minLength: 6, sampleOffset: 2000.7, sampleLength: 300.9 });
		assert.ok(results.every(r => Number.isInteger(r.offset)), 'all offsets must be integers after flooring');
	});

	// -----------------------------------------------------------------------
	// HARDENING (round 2) — the two MAJOR input-validation edges
	// -----------------------------------------------------------------------

	test('REGRESSION GUARD: {sampleLength:0} falls back to full buffer (NOT silent-empty)', () => {
		// A zero-length window selects no bytes; the catch-all must fall back to a
		// full-buffer scan rather than silently returning [] and losing every hit.
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		assert.ok(baseline.length > 0, 'precondition: baseline must be non-empty');

		const zeroLength = xorBruteForce(buf, 0, { minLength: 6, sampleLength: 0 });
		assert.ok(zeroLength.length > 0, '{sampleLength:0} must NOT silently return []');
		assert.deepStrictEqual(zeroLength, baseline,
			'{sampleLength:0} must produce the SAME result as the full-buffer baseline');
	});

	test('REGRESSION GUARD: invalid sampleOffset + valid sampleLength scans the FULL buffer', () => {
		// sampleOffset is present-but-invalid (NaN). A valid sampleLength must NOT
		// be honored alone with a coerced-to-0 offset (which would silently scan
		// [0, sampleLength) and drop the requested offset). The whole window is
		// treated as absent => full-buffer scan; a token past sampleLength is found.
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'DeepToken', tokenOffset: 2050 });

		// Confirm the token lives PAST the would-be bogus [0, 500) window.
		const bogusWindow = xorBruteForce(buf, 0, { minLength: 6, sampleOffset: 0, sampleLength: 500 });
		assert.ok(!hasValue(bogusWindow, 'DeepToken'),
			'precondition: token at 2050 is outside [0,500), so a relocated window would miss it');

		const result = xorBruteForce(buf, 0, { minLength: 6, sampleOffset: NaN, sampleLength: 500 });
		assert.ok(hasValue(result, 'DeepToken'),
			'invalid offset + valid length must scan the FULL buffer and find the token at 2050, not [0,500)');

		// And it must equal the full-buffer baseline (present-but-invalid offset
		// makes the entire window absent).
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		assert.deepStrictEqual(result, baseline,
			'present-but-invalid offset must yield the full-buffer baseline');
	});

	test('NaN / negative / Infinity window args fall back to full-buffer (deep-equal baseline)', () => {
		const buf = buildEncodedBuffer({ totalLength: 4096, key: KEY, token: 'HelloWorld', tokenOffset: 64 });
		const baseline = xorBruteForce(buf, 0, { minLength: 6 });
		assert.ok(baseline.length > 0, 'precondition: baseline must be non-empty');

		const invalids: Array<{ sampleOffset?: number; sampleLength?: number }> = [
			{ sampleOffset: NaN },
			{ sampleOffset: -5 },
			{ sampleOffset: Infinity },
			{ sampleOffset: -Infinity },
			{ sampleLength: NaN },
			{ sampleLength: -10 },
			{ sampleLength: Infinity },
		];
		for (const w of invalids) {
			const r = xorBruteForce(buf, 0, { minLength: 6, ...w });
			assert.deepStrictEqual(r, baseline,
				`invalid window ${JSON.stringify(w)} must fall back to the full-buffer baseline`);
		}
	});
});
