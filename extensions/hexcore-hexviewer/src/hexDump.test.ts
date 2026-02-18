/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 17: Hex dump retorna bytes corretos

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hexDumpRange } from './hexDump';

suite('Property 17: Hex dump retorna bytes corretos', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hexdump-test-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 7.1**
	 *
	 * For any file with random content and any valid (offset, size) pair
	 * within the file bounds, the base64-decoded `raw` field from
	 * hexDumpRange MUST be identical to the bytes read directly from the
	 * file at the same range.
	 */
	test('base64 raw matches file bytes for arbitrary offset/size', () => {
		fc.assert(
			fc.property(
				// Generate random file content: 16–1024 bytes
				fc.uint8Array({ minLength: 16, maxLength: 1024 }),
				// Generate a seed for offset/size derivation
				fc.nat(),
				fc.nat(),
				(content, offsetSeed, sizeSeed) => {
					const contentBuf = Buffer.from(content);

					// Derive valid offset: 0 to content.length - 1
					const offset = offsetSeed % contentBuf.length;
					// Derive valid size: 1 to content.length - offset
					const maxSize = contentBuf.length - offset;
					const size = (sizeSeed % maxSize) + 1;

					// Write content to temp file
					const filePath = path.join(tmpDir, `test-${offsetSeed}-${sizeSeed}.bin`);
					fs.writeFileSync(filePath, contentBuf);

					try {
						// Call hexDumpRange
						const result = hexDumpRange(filePath, offset, size);

						// Decode raw from base64
						const decodedRaw = Buffer.from(result.raw, 'base64');

						// Read expected bytes directly from file
						const expected = contentBuf.subarray(offset, offset + size);

						// Verify decoded raw matches expected bytes
						assert.strictEqual(
							decodedRaw.length,
							expected.length,
							`Length mismatch: raw=${decodedRaw.length}, expected=${expected.length} (offset=${offset}, size=${size})`
						);
						assert.ok(
							decodedRaw.equals(expected),
							`Bytes mismatch at offset=${offset}, size=${size}`
						);

						// Verify result metadata
						assert.strictEqual(result.offset, offset, 'Result offset must match requested offset');
						assert.strictEqual(result.size, size, 'Result size must match requested size');
						assert.strictEqual(result.filePath, filePath, 'Result filePath must match');
						assert.strictEqual(typeof result.generatedAt, 'string', 'generatedAt must be a string');
					} finally {
						fs.unlinkSync(filePath);
					}
				}
			),
			{ numRuns: 100 }
		);
	});
});
