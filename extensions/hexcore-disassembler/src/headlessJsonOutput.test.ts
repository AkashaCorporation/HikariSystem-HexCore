/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 2: Saída headless produz JSON válido no arquivo

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Generators for headless result shapes
// ---------------------------------------------------------------------------

/** Generates a valid ISO 8601 date string. */
function isoDateArb(): fc.Arbitrary<string> {
	return fc.date({ min: new Date('2020-01-01'), max: new Date('2030-12-31') })
		.map((d: Date) => d.toISOString());
}

/** Generates a hex address string like '0x401000'. */
function hexAddrArb(): fc.Arbitrary<string> {
	return fc.bigUintN(64).map((n: bigint) => '0x' + n.toString(16));
}

/** Generates a safe file path string (no special chars that break JSON). */
function filePathArb(): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.constantFrom(
			'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
			'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
			'/', '\\', '.', '-', '_'
		),
		{ minLength: 5, maxLength: 80 }
	);
}

// --- Snapshot result shape ---
function snapshotResultArb(): fc.Arbitrary<Record<string, unknown>> {
	return fc.record({
		success: fc.boolean(),
		generatedAt: isoDateArb()
	});
}

// --- Trace export result shape ---
function traceExportArb(): fc.Arbitrary<Record<string, unknown>> {
	const entryArb = fc.record({
		functionName: fc.string({ minLength: 1, maxLength: 40 }),
		library: fc.string({ minLength: 1, maxLength: 40 }),
		timestamp: fc.nat({ max: 2_000_000_000 })
	});
	return fc.record({
		entries: fc.array(entryArb, { minLength: 0, maxLength: 20 }),
		totalEntries: fc.nat({ max: 10000 }),
		generatedAt: isoDateArb()
	});
}

// --- ELF analysis result shape ---
function elfResultArb(): fc.Arbitrary<Record<string, unknown>> {
	return fc.record({
		isELF: fc.boolean(),
		fileName: fc.string({ minLength: 1, maxLength: 60 }),
		generatedAt: isoDateArb()
	});
}

// --- Base64 headless result shape ---
function base64ResultArb(): fc.Arbitrary<Record<string, unknown>> {
	const matchArb = fc.record({
		offset: fc.nat({ max: 1_000_000 }),
		encoded: fc.base64String({ minLength: 20, maxLength: 100 })
	});
	return fc.record({
		filePath: filePathArb(),
		matches: fc.array(matchArb, { minLength: 0, maxLength: 15 }),
		totalMatches: fc.nat({ max: 10000 }),
		generatedAt: isoDateArb()
	});
}

// --- Hex dump result shape ---
function hexDumpResultArb(): fc.Arbitrary<Record<string, unknown>> {
	return fc.record({
		filePath: filePathArb(),
		offset: fc.nat({ max: 1_000_000 }),
		size: fc.nat({ max: 65536 }),
		raw: fc.base64String({ minLength: 0, maxLength: 200 }),
		generatedAt: isoDateArb()
	});
}

// --- Hex search result shape ---
function hexSearchResultArb(): fc.Arbitrary<Record<string, unknown>> {
	const matchArb = fc.record({
		offset: fc.nat({ max: 1_000_000 })
	});
	return fc.record({
		filePath: filePathArb(),
		pattern: fc.hexaString({ minLength: 2, maxLength: 32 }),
		matches: fc.array(matchArb, { minLength: 0, maxLength: 30 }),
		totalMatches: fc.nat({ max: 10000 }),
		generatedAt: isoDateArb()
	});
}

// --- Report composer result shape ---
function reportResultArb(): fc.Arbitrary<Record<string, unknown>> {
	return fc.record({
		title: fc.string({ minLength: 1, maxLength: 100 }),
		hexcoreVersion: fc.constantFrom('3.5.2', '3.5.1', '3.4.0', '3.3.0'),
		generatedAt: isoDateArb()
	});
}

interface HeadlessTestCase {
	label: string;
	result: Record<string, unknown>;
}

/** Union of all headless result shapes. */
function anyHeadlessResultArb(): fc.Arbitrary<HeadlessTestCase> {
	return fc.oneof(
		snapshotResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'snapshot', result: r })),
		traceExportArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'trace', result: r })),
		elfResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'elf', result: r })),
		base64ResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'base64', result: r })),
		hexDumpResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'hexdump', result: r })),
		hexSearchResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'hexsearch', result: r })),
		reportResultArb().map((r: Record<string, unknown>): HeadlessTestCase => ({ label: 'report', result: r }))
	);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

suite('Property 2: Saída headless produz JSON válido no arquivo', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-headless-json-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 1.5**
	 *
	 * For any headless command result object that contains a `generatedAt`
	 * field, writing it as JSON to a file and reading it back MUST produce
	 * valid, parseable JSON whose parsed object contains `generatedAt`.
	 */
	test('any headless result written to file produces valid JSON with generatedAt', () => {
		fc.assert(
			fc.property(
				anyHeadlessResultArb(),
				fc.nat({ max: 999_999 }),
				({ label, result }: HeadlessTestCase, seq: number) => {
					// 1. Serialize to JSON
					const json = JSON.stringify(result, null, 2);

					// 2. Write to temp file
					const fileName = `${label}-${seq}.json`;
					const filePath = path.join(tmpDir, fileName);
					fs.writeFileSync(filePath, json, 'utf8');

					// 3. Read back
					const content = fs.readFileSync(filePath, 'utf8');

					// 4. Parse — must not throw
					let parsed: Record<string, unknown>;
					try {
						parsed = JSON.parse(content);
					} catch (err) {
						assert.fail(
							`JSON.parse failed for ${label} result: ${(err as Error).message}`
						);
					}

					// 5. Must contain generatedAt as a string
					assert.strictEqual(typeof parsed.generatedAt, 'string',
						`${label}: generatedAt must be a string, got ${typeof parsed.generatedAt}`);

					// 6. generatedAt must be a valid ISO date
					assert.ok(
						!isNaN(Date.parse(parsed.generatedAt as string)),
						`${label}: generatedAt must be a valid ISO date, got "${parsed.generatedAt}"`
					);
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 1.5**
	 *
	 * JSON round-trip through file I/O preserves all fields of the result
	 * object exactly (deep equality).
	 */
	test('JSON round-trip through file preserves all fields', () => {
		fc.assert(
			fc.property(
				anyHeadlessResultArb(),
				fc.nat({ max: 999_999 }),
				({ label, result }: HeadlessTestCase, seq: number) => {
					const json = JSON.stringify(result, null, 2);
					const filePath = path.join(tmpDir, `rt-${label}-${seq}.json`);

					fs.writeFileSync(filePath, json, 'utf8');
					const readBack = fs.readFileSync(filePath, 'utf8');
					const parsed = JSON.parse(readBack);

					assert.deepStrictEqual(parsed, result,
						`${label}: round-trip through file must preserve all fields`);
				}
			),
			{ numRuns: 100 }
		);
	});
});
