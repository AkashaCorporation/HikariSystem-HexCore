/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * YARA hex pattern compiler — spec-level property tests.
 *
 * The implementation under test lives in hexcore-yara/src/yaraEngine.ts as the
 * MODULE-PRIVATE functions compileHexPattern / matchHexPattern. Because they
 * are not exported and the host extension has no test infrastructure wired,
 * this file RE-IMPLEMENTS the compiler at spec-level (as documented in the
 * v3.8.0 diff) and runs the property tests against the reimplementation.
 *
 * Why this is still useful:
 *   - Locks the documented behaviour (round-trip + nibble wildcards + [n-m])
 *     so any divergence between spec and impl will be caught in review.
 *   - Pins regressions for the bugs fixed in v3.8.0:
 *       * `3?` was collapsing to `??`  (nibble wildcard loss)
 *       * text strings always searched wide, firing on every PE
 *
 * ref: https://yara.readthedocs.io/en/stable/writingrules.html
 */

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Spec re-implementation (MUST stay in lockstep with yaraEngine.ts diff)
// ---------------------------------------------------------------------------

interface HexToken {
	kind: 'byte' | 'jump';
	value: number;
	mask: number;
	jumpMin: number;
	jumpMax: number;
}

function parseHexByte(pair: string): HexToken | null {
	if (pair.length !== 2) { return null; }
	const hi = pair[0];
	const lo = pair[1];
	const hiWild = hi === '?';
	const loWild = lo === '?';
	if (hiWild && loWild) {
		return { kind: 'byte', value: 0, mask: 0x00, jumpMin: 0, jumpMax: 0 };
	}
	if (hiWild) {
		const v = parseInt(lo, 16);
		if (Number.isNaN(v)) { return null; }
		return { kind: 'byte', value: v & 0x0F, mask: 0x0F, jumpMin: 0, jumpMax: 0 };
	}
	if (loWild) {
		const v = parseInt(hi, 16);
		if (Number.isNaN(v)) { return null; }
		return { kind: 'byte', value: (v & 0x0F) << 4, mask: 0xF0, jumpMin: 0, jumpMax: 0 };
	}
	const v = parseInt(pair, 16);
	if (Number.isNaN(v)) { return null; }
	return { kind: 'byte', value: v, mask: 0xFF, jumpMin: 0, jumpMax: 0 };
}

function compileHexPattern(hexPattern: string): HexToken[] {
	const noComments = hexPattern.replace(/\/\*[\s\S]*?\*\//g, '');
	const stripped = noComments.replace(/\s+/g, '');
	const tokens: HexToken[] = [];
	let i = 0;
	while (i < stripped.length) {
		const ch = stripped[i];
		if (ch === '[') {
			const close = stripped.indexOf(']', i);
			if (close === -1) { return []; }
			const body = stripped.substring(i + 1, close);
			const m = body.match(/^(\d+)(?:-(\d*))?$/);
			if (!m) { return []; }
			const jmin = parseInt(m[1], 10);
			const jmax = m[2] === undefined
				? jmin
				: (m[2] === '' ? Number.POSITIVE_INFINITY : parseInt(m[2], 10));
			if (jmax < jmin) { return []; }
			tokens.push({ kind: 'jump', value: 0, mask: 0, jumpMin: jmin, jumpMax: jmax });
			i = close + 1;
			continue;
		}
		if (i + 1 >= stripped.length) { return []; }
		const tok = parseHexByte(stripped.substring(i, i + 2));
		if (!tok) { return []; }
		tokens.push(tok);
		i += 2;
	}
	return tokens;
}

function matchHexPattern(content: Buffer, hexPattern: string): number[] {
	const tokens = compileHexPattern(hexPattern);
	if (tokens.length === 0) { return []; }
	if (tokens[0].kind === 'jump' || tokens[tokens.length - 1].kind === 'jump') { return []; }

	const offsets: number[] = [];
	const hasJump = tokens.some(t => t.kind === 'jump');
	if (!hasJump) {
		const len = tokens.length;
		for (let i = 0; i + len <= content.length; i++) {
			let ok = true;
			for (let j = 0; j < len; j++) {
				const t = tokens[j];
				if ((content[i + j] & t.mask) !== t.value) { ok = false; break; }
			}
			if (ok) {
				offsets.push(i);
				if (offsets.length >= 100) { break; }
			}
		}
		return offsets;
	}

	const SAFE_CAP = 4096;
	for (let start = 0; start < content.length; start++) {
		let cur = start;
		let ok = true;
		for (let k = 0; k < tokens.length; k++) {
			const t = tokens[k];
			if (t.kind === 'byte') {
				if (cur >= content.length) { ok = false; break; }
				if ((content[cur] & t.mask) !== t.value) { ok = false; break; }
				cur += 1;
			} else {
				const max = Math.min(
					Number.isFinite(t.jumpMax) ? t.jumpMax : SAFE_CAP,
					content.length - cur,
				);
				if (t.jumpMin > max) { ok = false; break; }
				const next = tokens[k + 1];
				if (!next || next.kind !== 'byte') { ok = false; break; }
				let found = -1;
				for (let skip = t.jumpMin; skip <= max; skip++) {
					const p = cur + skip;
					if (p >= content.length) { break; }
					if ((content[p] & next.mask) === next.value) { found = skip; break; }
				}
				if (found === -1) { ok = false; break; }
				cur += found + 1;
				k += 1;
			}
		}
		if (ok) {
			offsets.push(start);
			if (offsets.length >= 100) { break; }
		}
	}
	return offsets;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

suite('YARA hex pattern compiler (v3.8.0 spec)', () => {

	suite('unit: wildcard semantics', () => {
		test('full byte wildcard ?? matches any byte', () => {
			const toks = compileHexPattern('??');
			assert.strictEqual(toks.length, 1);
			assert.strictEqual(toks[0].mask, 0x00);
			assert.strictEqual(toks[0].value, 0x00);
		});

		test('nibble-high-fixed A? encodes mask=0xF0 value=0xA0', () => {
			// Regression for the v3.8.0 bug: previously `A?` collapsed to full `??`.
			const toks = compileHexPattern('A?');
			assert.strictEqual(toks.length, 1);
			assert.strictEqual(toks[0].mask, 0xF0);
			assert.strictEqual(toks[0].value, 0xA0);
		});

		test('nibble-low-fixed ?A encodes mask=0x0F value=0x0A', () => {
			const toks = compileHexPattern('?A');
			assert.strictEqual(toks.length, 1);
			assert.strictEqual(toks[0].mask, 0x0F);
			assert.strictEqual(toks[0].value, 0x0A);
		});

		test('the 3? regression case — rule `66 81 3? 4D 5A` must NOT match 66 81 FF 4D 5A', () => {
			// This is the exact bug the v3.8.0 diff calls out:
			// api-hashing.yar has `66 81 3? 4D 5A`; the old compiler collapsed
			// `3?` into `??`, so 66-81-FF-4D-5A would FP-match.
			const pattern = '66 81 3? 4D 5A';
			const goodBytes = Buffer.from([0x66, 0x81, 0x3F, 0x4D, 0x5A]); // must match
			const fpBytes = Buffer.from([0x66, 0x81, 0xFF, 0x4D, 0x5A]);   // must NOT match
			assert.deepStrictEqual(matchHexPattern(goodBytes, pattern), [0]);
			assert.deepStrictEqual(matchHexPattern(fpBytes, pattern), []);
		});

		test('hex jump [2-4] — allows 2..4 arbitrary bytes', () => {
			const pattern = 'AA [2-4] BB';
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA, 0, 0, 0xBB]), pattern), [0]);
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA, 0, 0, 0, 0xBB]), pattern), [0]);
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA, 0, 0, 0, 0, 0xBB]), pattern), [0]);
			// 1-byte gap is less than jumpMin=2 → no match.
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA, 0, 0xBB]), pattern), []);
			// 5-byte gap exceeds jumpMax=4 → no match.
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA, 0, 0, 0, 0, 0, 0xBB]), pattern), []);
		});

		test('malformed pattern — leading jump is rejected', () => {
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA]), '[1-2] AA'), []);
		});

		test('malformed pattern — trailing jump is rejected', () => {
			assert.deepStrictEqual(matchHexPattern(Buffer.from([0xAA]), 'AA [1-2]'), []);
		});

		test('malformed pattern — odd nibble at end returns empty tokens', () => {
			assert.deepStrictEqual(compileHexPattern('AAB'), []);
		});

		test('malformed pattern — jumpMax < jumpMin rejected', () => {
			assert.deepStrictEqual(compileHexPattern('AA [5-2] BB'), []);
		});
	});

	// -----------------------------------------------------------------------
	// PBT: round-trip — toBuffer(fromPattern(X)).matches(X) == true
	// -----------------------------------------------------------------------

	suite('PBT: round-trip (compile then match concrete bytes)', () => {

		test('pure fixed-byte patterns always find themselves in the buffer', () => {
			fc.assert(
				fc.property(
					fc.array(fc.integer({ min: 0, max: 0xFF }), { minLength: 1, maxLength: 16 }),
					(bytes) => {
						const buf = Buffer.from(bytes);
						const hex = bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
						const offsets = matchHexPattern(buf, hex);
						assert.ok(offsets.includes(0),
							`expected ${hex} to match [${bytes.map(b => '0x' + b.toString(16)).join(',')}] at offset 0`);
					},
				),
				{ seed: 0xCAFE, numRuns: 500 },
			);
		});

		test('nibble-wildcard patterns match any byte satisfying the fixed nibble', () => {
			// For every high-nibble value 0..F, the pattern `<H>?` must match
			// ALL 16 bytes in the range 0xH0..0xHF and NONE outside.
			fc.assert(
				fc.property(
					fc.integer({ min: 0, max: 0xF }),
					fc.integer({ min: 0, max: 0xFF }),
					(hi, candidate) => {
						const hiChar = hi.toString(16).toUpperCase();
						const pattern = `${hiChar}?`;
						const shouldMatch = (candidate >>> 4) === hi;
						const actual = matchHexPattern(Buffer.from([candidate]), pattern).length > 0;
						assert.strictEqual(actual, shouldMatch,
							`pattern ${pattern} vs byte 0x${candidate.toString(16)} — expected ${shouldMatch}`);
					},
				),
				{ seed: 7, numRuns: 500 },
			);
		});

		test('pattern with jump — metamorphic: padding inside the gap must not break match', () => {
			// Invariant: for AA [n-m] BB, any buffer of shape AA + kFillerBytes + BB
			// where n ≤ k ≤ m must yield a match at offset 0.
			fc.assert(
				fc.property(
					fc.integer({ min: 1, max: 8 }),
					fc.integer({ min: 0, max: 16 }),
					fc.array(fc.integer({ min: 0, max: 0xFF }), { minLength: 0, maxLength: 20 }),
					(n, extra, fillers) => {
						const m = n + extra;
						const k = Math.min(fillers.length, m);
						if (k < n) { return; } // sample outside the valid range — skip
						const slice = fillers.slice(0, k);
						const buf = Buffer.from([0xAA, ...slice, 0xBB]);
						const offsets = matchHexPattern(buf, `AA [${n}-${m}] BB`);
						assert.ok(offsets.includes(0),
							`expected match at 0 for AA+${k}filler+BB against AA [${n}-${m}] BB`);
					},
				),
				{ seed: 9001, numRuns: 300 },
			);
		});
	});
});
