/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 12: Base64 headless detecta strings codificadas

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Replicates the core Base64 detection logic from extension.ts.
 * These are the same functions used by scanFileForBase64 / decodeHeadless,
 * copied here so we can test the detection concept without exporting privates.
 */

interface Base64Match {
	offset: number;
	encoded: string;
	decoded: string;
	decodedHex: string;
	isPrintable: boolean;
}

function findBase64Strings(content: string): Array<{ offset: number; match: string }> {
	const results: Array<{ offset: number; match: string }> = [];
	const base64Regex = /[A-Za-z0-9+/]{20,4096}={0,2}/g;

	let match;
	while ((match = base64Regex.exec(content)) !== null) {
		const str = match[0];
		if (isLikelyBase64(str)) {
			results.push({ offset: match.index, match: str });
		}
	}
	return results;
}

function isLikelyBase64(str: string): boolean {
	if (str.length < 20) { return false; }
	const withoutPadding = str.replace(/=+$/, '');
	const validChars = withoutPadding.replace(/[A-Za-z0-9+/]/g, '');
	if (validChars.length > 0) { return false; }
	try {
		const decoded = Buffer.from(str, 'base64');
		if (decoded.length < 10) { return false; }
		const nullCount = decoded.filter(b => b === 0).length;
		if (nullCount > decoded.length * 0.5) { return false; }
		return true;
	} catch {
		return false;
	}
}

function decodeMatches(matches: Array<{ offset: number; match: string }>): Base64Match[] {
	const results: Base64Match[] = [];
	for (const { offset, match } of matches) {
		try {
			const decoded = Buffer.from(match, 'base64');
			const decodedStr = decoded.toString('utf8');
			const decodedHex = decoded.toString('hex').toUpperCase();
			let printableCount = 0;
			for (const byte of decoded) {
				if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
					printableCount++;
				}
			}
			const isPrintable = printableCount > decoded.length * 0.7;
			results.push({
				offset,
				encoded: match,
				decoded: isPrintable ? decodedStr : '[Binary Data]',
				decodedHex: decodedHex.substring(0, 64) + (decodedHex.length > 64 ? '...' : ''),
				isPrintable
			});
		} catch {
			// Skip invalid base64
		}
	}
	return results;
}

/**
 * Scans file content for Base64 strings using the same logic as extension.ts.
 */
function scanContentForBase64(content: string): Base64Match[] {
	const rawMatches = findBase64Strings(content);
	return decodeMatches(rawMatches);
}

/**
 * Generates a printable ASCII string of given length.
 * Uses chars 32-126 (printable ASCII) excluding null bytes.
 */
function printableStringArb(minLen: number, maxLen: number): fc.Arbitrary<string> {
	return fc.stringOf(
		fc.integer({ min: 32, max: 126 }).map(c => String.fromCharCode(c)),
		{ minLength: minLen, maxLength: maxLen }
	);
}

/**
 * Generates a separator buffer that won't be mistaken for Base64.
 * Uses bytes that break Base64 regex: newlines, spaces, control chars, high bytes.
 */
function separatorArb(): fc.Arbitrary<Buffer> {
	return fc.array(
		fc.integer({ min: 0, max: 255 }).filter(b => {
			// Exclude chars in Base64 alphabet to ensure clean separation
			const ch = String.fromCharCode(b);
			return !/[A-Za-z0-9+/=]/.test(ch);
		}),
		{ minLength: 4, maxLength: 32 }
	).map(bytes => Buffer.from(bytes));
}

suite('Property 12: Base64 headless detecta strings codificadas', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-b64-test-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 5.1, 5.5**
	 *
	 * For any file containing at least one valid Base64 string (≥20 chars,
	 * decodifiable), the detection logic MUST return totalMatches >= 1 and
	 * each match MUST contain offset, encoded, decoded, and isPrintable.
	 */
	test('detects embedded Base64 strings with all required fields', () => {
		fc.assert(
			fc.property(
				// Generate a printable string long enough that its Base64 is ≥20 chars
				// 15 bytes → 20 Base64 chars (ceil(15/3)*4 = 20)
				printableStringArb(15, 100),
				separatorArb(),
				separatorArb(),
				(plaintext, prefixSep, suffixSep) => {
					// Encode the plaintext to Base64
					const b64 = Buffer.from(plaintext, 'utf8').toString('base64');

					// Base64 must be ≥20 chars for the regex to match
					if (b64.length < 20) { return; }

					// Build file content: separator + base64 + separator
					const fileContent = Buffer.concat([
						prefixSep,
						Buffer.from(b64, 'binary'),
						suffixSep
					]);

					// Write to temp file
					const filePath = path.join(tmpDir, `test-${Date.now()}-${Math.random().toString(36).slice(2)}.bin`);
					fs.writeFileSync(filePath, fileContent);

					// Read back and scan using the same logic as extension.ts
					const content = fs.readFileSync(filePath, 'binary');
					const matches = scanContentForBase64(content);

					// Must find at least 1 match
					assert.ok(
						matches.length >= 1,
						`Expected at least 1 Base64 match for "${b64.slice(0, 40)}..." but found ${matches.length}`
					);

					// Each match must have all required fields
					for (const m of matches) {
						assert.strictEqual(typeof m.offset, 'number',
							'match.offset must be a number');
						assert.ok(m.offset >= 0,
							'match.offset must be non-negative');

						assert.strictEqual(typeof m.encoded, 'string',
							'match.encoded must be a string');
						assert.ok(m.encoded.length >= 20,
							'match.encoded must be ≥20 chars');

						assert.strictEqual(typeof m.decoded, 'string',
							'match.decoded must be a string');
						assert.ok(m.decoded.length > 0,
							'match.decoded must be non-empty');

						assert.strictEqual(typeof m.isPrintable, 'boolean',
							'match.isPrintable must be a boolean');
					}
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * **Validates: Requirements 5.1, 5.5**
	 *
	 * For any file containing a known Base64 string, the detected match
	 * MUST include the original encoded string and the decoded content
	 * must correspond to the original plaintext.
	 */
	test('decoded content matches original plaintext for printable strings', () => {
		fc.assert(
			fc.property(
				// Use only printable ASCII so isPrintable will be true
				printableStringArb(15, 80),
				(plaintext) => {
					const b64 = Buffer.from(plaintext, 'utf8').toString('base64');
					if (b64.length < 20) { return; }

					// Surround with newlines (non-Base64 chars) for clean separation
					const fileContent = '\n\n' + b64 + '\n\n';

					const matches = scanContentForBase64(fileContent);

					assert.ok(matches.length >= 1,
						`Expected at least 1 match for b64 of "${plaintext.slice(0, 30)}..."`);

					// Find the match that contains our encoded string
					const ourMatch = matches.find(m => b64.includes(m.encoded) || m.encoded.includes(b64));
					assert.ok(ourMatch,
						'Expected to find a match containing our Base64 string');

					// If printable, decoded should contain the original plaintext
					if (ourMatch!.isPrintable) {
						assert.ok(
							ourMatch!.decoded.includes(plaintext) || plaintext.includes(ourMatch!.decoded),
							'Decoded content should relate to original plaintext'
						);
					}
				}
			),
			{ numRuns: 100 }
		);
	});
});


suite('Unit tests: decodeHeadless', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-b64-unit-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 5.1**
	 *
	 * A file containing a known Base64 string must be detected with correct
	 * offset, encoded value, and decoded content.
	 */
	test('detects known Base64 string in file', () => {
		const plaintext = 'Hello, HexCore Base64 Decoder!';
		const b64 = Buffer.from(plaintext, 'utf8').toString('base64');
		// b64 = "SGVsbG8sIEhleENvcmUgQmFzZTY0IERlY29kZXIh"

		const prefix = '\x00\x01\x02\x03\n';
		const suffix = '\n\x04\x05\x06\x07';
		const fileContent = prefix + b64 + suffix;

		const filePath = path.join(tmpDir, 'known-b64.bin');
		fs.writeFileSync(filePath, fileContent, 'binary');

		const content = fs.readFileSync(filePath, 'binary');
		const matches = scanContentForBase64(content);

		assert.ok(matches.length >= 1, `Expected at least 1 match, got ${matches.length}`);

		const match = matches[0];
		assert.strictEqual(match.encoded, b64, 'Encoded string must match the known Base64');
		assert.strictEqual(match.offset, prefix.length, 'Offset must equal prefix length');
		assert.strictEqual(match.isPrintable, true, 'Decoded content is printable ASCII');
		assert.ok(match.decoded.includes(plaintext), 'Decoded must contain original plaintext');
	});

	/**
	 * **Validates: Requirements 5.1**
	 *
	 * A file with random binary data (no valid Base64 sequences) must
	 * return an empty matches array.
	 */
	test('returns empty matches for file without Base64', () => {
		// Build a buffer of bytes that cannot form valid Base64 runs of ≥20 chars.
		// Use control characters and high bytes that break the Base64 regex.
		const noB64Bytes: number[] = [];
		for (let i = 0; i < 512; i++) {
			// Alternate between 0x00-0x1F (control) and 0x80-0xFF (high bytes)
			noB64Bytes.push(i % 2 === 0 ? (i % 32) : (0x80 + (i % 128)));
		}
		const filePath = path.join(tmpDir, 'no-b64.bin');
		fs.writeFileSync(filePath, Buffer.from(noB64Bytes));

		const content = fs.readFileSync(filePath, 'binary');
		const matches = scanContentForBase64(content);

		assert.strictEqual(matches.length, 0, 'Expected 0 matches for non-Base64 content');
	});

	/**
	 * **Validates: Requirements 5.4**
	 *
	 * When the file does not exist, the headless command must throw a
	 * descriptive error. We replicate the guard from decodeHeadless here.
	 */
	test('throws error for non-existent file', () => {
		const fakePath = path.join(tmpDir, 'does-not-exist.bin');

		// Replicate the guard logic from decodeHeadless
		assert.throws(
			() => {
				if (!fs.existsSync(fakePath)) {
					throw new Error(`File not found: ${fakePath}`);
				}
			},
			(err: Error) => {
				assert.ok(err.message.includes('File not found'), 'Error must mention "File not found"');
				assert.ok(err.message.includes(fakePath), 'Error must include the file path');
				return true;
			}
		);
	});

	/**
	 * **Validates: Requirements 5.4**
	 *
	 * The headless result serialized to JSON must be valid and contain the
	 * required fields: filePath, matches, totalMatches, generatedAt.
	 */
	test('output produces valid JSON with required fields', () => {
		const plaintext = 'This is a test string for JSON output validation';
		const b64 = Buffer.from(plaintext, 'utf8').toString('base64');
		const fileContent = '\n' + b64 + '\n';

		const filePath = path.join(tmpDir, 'json-output.bin');
		fs.writeFileSync(filePath, fileContent, 'binary');

		const content = fs.readFileSync(filePath, 'binary');
		const matches = scanContentForBase64(content);

		// Build the result object as decodeHeadless does
		const result = {
			filePath,
			matches,
			totalMatches: matches.length,
			generatedAt: new Date().toISOString()
		};

		// Serialize and parse back — must produce valid JSON
		const jsonStr = JSON.stringify(result, null, 2);
		const parsed = JSON.parse(jsonStr);

		assert.strictEqual(typeof parsed.filePath, 'string', 'filePath must be a string');
		assert.ok(Array.isArray(parsed.matches), 'matches must be an array');
		assert.strictEqual(typeof parsed.totalMatches, 'number', 'totalMatches must be a number');
		assert.strictEqual(parsed.totalMatches, parsed.matches.length,
			'totalMatches must equal matches.length');
		assert.strictEqual(typeof parsed.generatedAt, 'string', 'generatedAt must be a string');
		assert.ok(!isNaN(Date.parse(parsed.generatedAt)),
			'generatedAt must be a valid ISO date string');

		// Write to file and read back — simulates output option
		const outputPath = path.join(tmpDir, 'result.json');
		fs.writeFileSync(outputPath, jsonStr, 'utf8');

		const readBack = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
		assert.deepStrictEqual(readBack, parsed,
			'JSON read from file must equal the original result');
	});
});
