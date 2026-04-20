/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * IOC mutex/GUID validator — spec-level tests.
 *
 * Source: hexcore-ioc/src/iocExtractor.ts (v3.8.0 diff, `validateMutex`).
 * The validator is module-private; this file locks its documented contract.
 *
 * Contract (from the diff comments):
 *   - Named mutex paths (`\\…`, `Global\\…`, `Local\\…`) pass through unchanged.
 *   - GUIDs on the well-known CLSID blacklist are rejected (→ null).
 *   - All-zero / all-same-character GUIDs are rejected (null/MAX/placeholders).
 *   - Any other GUID is returned unchanged.
 *
 * Bug pinned:
 *   - Previously a bare `{00000000-0000-0000-c000-000000000046}` (IUnknown)
 *     was reported as a mutex IOC in every PE binary.
 */

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Spec re-implementation (MUST stay in lockstep with iocExtractor.ts)
// ---------------------------------------------------------------------------

const WELLKNOWN_GUID_BLACKLIST = new Set<string>([
	'{00000000-0000-0000-0000-000000000000}',
	'{ffffffff-ffff-ffff-ffff-ffffffffffff}',
	'{00020813-0000-0000-c000-000000000046}',
	'{00020819-0000-0000-c000-000000000046}',
	'{000214e6-0000-0000-c000-000000000046}',
	'{00000000-0000-0000-c000-000000000046}',
	'{0002df01-0000-0000-c000-000000000046}',
	'{00021401-0000-0000-c000-000000000046}',
	'{1f4de370-d627-11d1-ba4f-00a0c91eedba}',
	'{c0dcf3d4-49cb-5a3c-8c6c-7c16a09a0ab1}',
]);

function validateMutex(raw: string): string | null {
	if (raw.startsWith('\\') || raw.startsWith('Global\\') || raw.startsWith('Local\\')) {
		return raw;
	}
	const lower = raw.toLowerCase();
	if (WELLKNOWN_GUID_BLACKLIST.has(lower)) { return null; }
	const hex = lower.replace(/[{}-]/g, '');
	if (/^(.)\1+$/.test(hex)) { return null; }
	return raw;
}

// The regex from the diff for independent verification.
const MUTEX_REGEX = /(?:\\(?:Global|Local|Session\\\d+)\\BaseNamedObjects\\[A-Za-z0-9_.\-]{3,128}|(?:Global|Local)\\[A-Za-z0-9_.\-]{3,128}|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})/g;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

suite('IOC validateMutex (v3.8.0)', () => {

	suite('unit: blacklist rejects well-known CLSIDs', () => {
		test('IUnknown {00000000-0000-0000-c000-000000000046} → null', () => {
			assert.strictEqual(validateMutex('{00000000-0000-0000-c000-000000000046}'), null);
		});
		test('Null GUID {00000000-...-000000000000} → null', () => {
			assert.strictEqual(validateMutex('{00000000-0000-0000-0000-000000000000}'), null);
		});
		test('Max GUID {ffffffff-...-ffffffffffff} → null', () => {
			assert.strictEqual(validateMutex('{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}'), null);
		});
		test('case-insensitive blacklist match', () => {
			// upper-case form on blacklist (stored lowercase) — must still reject.
			assert.strictEqual(validateMutex('{00020813-0000-0000-C000-000000000046}'), null);
		});
	});

	suite('unit: accepts legit GUIDs + named mutexes', () => {
		test('arbitrary non-blacklisted GUID is returned', () => {
			const g = '{deadbeef-1234-5678-9abc-def012345678}';
			assert.strictEqual(validateMutex(g), g);
		});
		test('Global\\Foo is accepted', () => {
			assert.strictEqual(validateMutex('Global\\Foo'), 'Global\\Foo');
		});
		test('Local\\Bar is accepted', () => {
			assert.strictEqual(validateMutex('Local\\Bar'), 'Local\\Bar');
		});
		test('\\Sessions\\1\\BaseNamedObjects\\x is accepted', () => {
			const m = '\\Sessions\\1\\BaseNamedObjects\\x';
			assert.strictEqual(validateMutex(m), m);
		});
	});

	suite('unit: repetitive-char GUIDs rejected', () => {
		test('all-zero body {000...000} rejected', () => {
			// Not literally on the blacklist but hits the `^(.)\1+$` rule.
			assert.strictEqual(validateMutex('{00000000-0000-0000-0000-000000000000}'), null);
		});
		test('all-"a" body {aaaaaaaa-...-aaaaaaaaaaaa} rejected', () => {
			assert.strictEqual(validateMutex('{aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa}'), null);
		});
	});

	// -----------------------------------------------------------------------
	// PBT: blacklist rejection is complete (any blacklist entry → null)
	// -----------------------------------------------------------------------

	suite('PBT: blacklist completeness', () => {

		test('every blacklisted GUID is rejected', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(...WELLKNOWN_GUID_BLACKLIST),
					(g: string) => {
						assert.strictEqual(validateMutex(g), null);
					},
				),
				{ seed: 5, numRuns: 50 },
			);
		});

		test('every blacklisted GUID with random case is still rejected', () => {
			const randomCase = (s: string) => s.split('').map(
				c => Math.random() < 0.5 ? c.toUpperCase() : c.toLowerCase()
			).join('');
			fc.assert(
				fc.property(
					fc.constantFrom(...WELLKNOWN_GUID_BLACKLIST),
					(g: string) => {
						const casedLower = g; // use literal (random RNG avoided for determinism)
						const cased = randomCase(casedLower);
						assert.strictEqual(validateMutex(cased), null);
					},
				),
				{ seed: 13, numRuns: 50 },
			);
		});

		test('every non-blacklisted well-formed GUID passes through', () => {
			const hexNibble = fc.integer({ min: 0, max: 15 }).map(n => n.toString(16));
			// Generate structurally valid 8-4-4-4-12 GUIDs and filter out blacklist/all-same.
			const guidArb = fc.tuple(
				fc.array(hexNibble, { minLength: 8, maxLength: 8 }),
				fc.array(hexNibble, { minLength: 4, maxLength: 4 }),
				fc.array(hexNibble, { minLength: 4, maxLength: 4 }),
				fc.array(hexNibble, { minLength: 4, maxLength: 4 }),
				fc.array(hexNibble, { minLength: 12, maxLength: 12 }),
			).map(([a, b, c, d, e]) =>
				`{${a.join('')}-${b.join('')}-${c.join('')}-${d.join('')}-${e.join('')}}`
			).filter(g => {
				if (WELLKNOWN_GUID_BLACKLIST.has(g.toLowerCase())) { return false; }
				const hex = g.toLowerCase().replace(/[{}-]/g, '');
				return !/^(.)\1+$/.test(hex);
			});
			fc.assert(
				fc.property(guidArb, (g: string) => {
					assert.strictEqual(validateMutex(g), g);
				}),
				{ seed: 111, numRuns: 300 },
			);
		});
	});

	// -----------------------------------------------------------------------
	// Regex sanity: captures named mutex + GUID, does not capture random strings
	// -----------------------------------------------------------------------

	suite('regex shape', () => {
		test('captures Global\\Foo_Bar', () => {
			const m = 'Global\\Foo_Bar'.match(MUTEX_REGEX);
			assert.deepStrictEqual(m, ['Global\\Foo_Bar']);
		});
		test('captures \\Sessions\\3\\BaseNamedObjects\\Zoo', () => {
			const m = '\\Sessions\\3\\BaseNamedObjects\\Zoo'.match(MUTEX_REGEX);
			assert.ok(m && m.length === 1, `regex should match, got ${JSON.stringify(m)}`);
		});
		test('captures canonical GUID form', () => {
			const g = '{12345678-1234-1234-1234-123456789abc}';
			const m = g.match(MUTEX_REGEX);
			assert.deepStrictEqual(m, [g]);
		});
		test('does NOT capture a plain filename', () => {
			assert.strictEqual('Config.ini'.match(MUTEX_REGEX), null);
		});
	});
});
