/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.5.2-pipeline-maturity, Property 18: Hex search encontra todas as ocorrências

import * as assert from 'assert';
import * as fc from 'fast-check';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hexSearchPattern } from './hexSearch';

suite('Property 18: Hex search encontra todas as ocorrências', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hexsearch-test-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * **Validates: Requirements 7.3**
	 *
	 * For any file with a needle inserted at K known positions,
	 * hexSearchPattern MUST return exactly K offsets, and each
	 * known insertion position MUST appear in the results.
	 */
	test('finds all occurrences of a pattern inserted at known positions', () => {
		fc.assert(
			fc.property(
				// Needle: 1-4 random bytes
				fc.uint8Array({ minLength: 1, maxLength: 4 }),
				// Number of insertions: 1-5
				fc.integer({ min: 1, max: 5 }),
				// File size: 256-2048
				fc.integer({ min: 256, max: 2048 }),
				// Seed for position generation
				fc.integer({ min: 0, max: 2 ** 31 - 1 }),
				(needleArr, insertCount, fileSize, posSeed) => {
					const needle = Buffer.from(needleArr);

					// Pick a fill byte that does NOT appear in the needle.
					// This guarantees the background never accidentally contains the needle.
					const needleSet = new Set(needle);
					let fillByte = 0x00;
					for (let b = 0; b <= 0xFF; b++) {
						if (!needleSet.has(b)) {
							fillByte = b;
							break;
						}
					}

					// Build background buffer filled with the safe byte
					const buf = Buffer.alloc(fileSize, fillByte);

					// Generate non-overlapping insertion positions.
					// We need at least needle.length bytes per insertion, so cap insertCount.
					const maxInsertions = Math.min(insertCount, Math.floor(fileSize / (needle.length + 1)));
					if (maxInsertions < 1) {
						return; // skip degenerate case
					}

					// Divide the file into slots to avoid overlapping insertions
					const slotSize = Math.floor(fileSize / maxInsertions);
					const positions: number[] = [];
					let rng = posSeed;
					for (let i = 0; i < maxInsertions; i++) {
						const slotStart = i * slotSize;
						// Ensure the needle fits within this slot
						const maxOffset = Math.min(slotStart + slotSize - needle.length, fileSize - needle.length);
						if (maxOffset < slotStart) {
							continue; // slot too small for needle
						}
						// Simple deterministic pseudo-random within slot
						rng = ((rng * 1103515245 + 12345) & 0x7FFFFFFF) >>> 0;
						const offset = slotStart + (rng % (maxOffset - slotStart + 1));
						positions.push(offset);
					}

					if (positions.length === 0) {
						return; // skip degenerate case
					}

					// Insert needle at each position
					for (const pos of positions) {
						needle.copy(buf, pos);
					}

					// Write to temp file
					const filePath = path.join(tmpDir, `search-${posSeed}.bin`);
					fs.writeFileSync(filePath, buf);

					try {
						// Build hex pattern string from needle
						const patternHex = needle.toString('hex').toUpperCase();

						// Call hexSearchPattern
						const result = hexSearchPattern(filePath, patternHex);

						// Assert totalMatches equals number of insertions
						assert.strictEqual(
							result.totalMatches,
							positions.length,
							`Expected ${positions.length} matches but got ${result.totalMatches} ` +
							`(needle=${patternHex}, positions=[${positions.join(',')}], fileSize=${fileSize})`
						);

						// Assert each known position appears in the results
						const foundOffsets = new Set(result.matches.map(m => m.offset));
						for (const pos of positions) {
							assert.ok(
								foundOffsets.has(pos),
								`Expected offset ${pos} not found in results. ` +
								`Found: [${[...foundOffsets].join(',')}]`
							);
						}

						// Verify result metadata
						assert.strictEqual(result.pattern, patternHex, 'Pattern must match');
						assert.strictEqual(result.filePath, filePath, 'filePath must match');
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
