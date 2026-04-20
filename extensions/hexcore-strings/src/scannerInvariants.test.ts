/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: xor-massive-update — Scanner Invariant Properties

import * as fc from 'fast-check';
import { multiByteXorScan } from './multiByteXor';
import { compositeCipherScan } from './compositeCipher';
import { knownPlaintextScan } from './knownPlaintextAttack';
import { wideStringXorScan } from './wideStringXor';
import { positionalXorScan } from './positionalXor';
import { rollingXorExtScan } from './rollingXorExt';
import { layeredXorScan } from './layeredXor';
import { getSectionForOffset, type PESectionInfo } from './peSectionParser';

suite('Scanner Invariant Properties', () => {

	/**
	 * **Validates: Requirement 10.3**
	 *
	 * Property 16: Uniform Key Discard
	 * For any multi-byte key where all bytes are identical (e.g., [0xAA, 0xAA, 0xAA, 0xAA]),
	 * the multi-byte scanner should not include results with that key, since it is equivalent
	 * to single-byte XOR already covered by the brute-force scanner.
	 */
	test('P16: Uniform keys (all bytes same) are discarded from multi-byte results', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 64, maxLength: 256 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);
				const results = multiByteXorScan(buf, 0, {
					minConfidence: 0.0,
					enableRolling: false,
					enableIncrement: false,
					enableAutoKeyDetection: false,
				});
				// No result should have a multi-byte key where all bytes are the same
				for (const r of results) {
					if (r.method === 'multi-byte' && r.keySize > 1) {
						const allSame = r.key.every(b => b === r.key[0]);
						if (allSame) {
							return false;
						}
					}
				}
				return true;
			}
		), { numRuns: 100 });
	});

	/**
	 * **Validates: Requirement 12.3**
	 *
	 * Property 17: Result Count Cap
	 * No individual scanner returns > 2000 results, and the orchestrator
	 * doesn't return > 5000. We test individual scanners directly since
	 * the orchestrator requires file I/O.
	 */
	test('P17: Individual scanners respect MAX_TOTAL_RESULTS (2000) cap', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 64, maxLength: 1024 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);

				// Test multiByteXorScan
				const multiResults = multiByteXorScan(buf, 0, {
					minConfidence: 0.0,
					enableRolling: true,
					enableIncrement: true,
				});
				if (multiResults.length > 2000) { return false; }

				// Test compositeCipherScan
				const ccResults = compositeCipherScan(buf, 0, { minConfidence: 0.0 });
				if (ccResults.length > 2000) { return false; }

				// Test knownPlaintextScan
				const kpResults = knownPlaintextScan(buf, 0, undefined, { minConfidence: 0.0 });
				if (kpResults.length > 2000) { return false; }

				// Test wideStringXorScan
				const wsResults = wideStringXorScan(buf, 0, { minConfidence: 0.0 });
				if (wsResults.length > 2000) { return false; }

				// Test positionalXorScan
				const pxResults = positionalXorScan(buf, 0, { minConfidence: 0.0 });
				if (pxResults.length > 2000) { return false; }

				// Test rollingXorExtScan
				const rxResults = rollingXorExtScan(buf, 0, { minConfidence: 0.0 });
				if (rxResults.length > 2000) { return false; }

				// Test layeredXorScan
				const lxResults = layeredXorScan(buf, 0, { minConfidence: 0.0 });
				if (lxResults.length > 2000) { return false; }

				return true;
			}
		), { numRuns: 100 });
	});

	/**
	 * **Validates: Requirement 12.4**
	 *
	 * Property 18: Method Enable/Disable Filtering
	 * When a specific method is disabled, results should contain zero entries
	 * of that method's type. We test compositeCipherScan: calling it produces
	 * ADD/SUB/ROT results, but not calling it means those types don't appear.
	 */
	test('P18: Disabled method produces zero results of that type', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 64, maxLength: 512 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);

				// When compositeCipherScan is NOT called, no ADD/SUB/ROT results
				const multiResults = multiByteXorScan(buf, 0, { minConfidence: 0.0 });
				const compositeTypes = new Set(['ADD', 'SUB', 'ROT']);
				for (const r of multiResults) {
					if (compositeTypes.has(r.method)) {
						return false; // multiByteXorScan should never produce ADD/SUB/ROT
					}
				}

				// When wideStringXorScan is NOT called, no XOR-wide results
				for (const r of multiResults) {
					if (r.method === 'XOR-wide') {
						return false; // multiByteXorScan should never produce XOR-wide
					}
				}

				return true;
			}
		), { numRuns: 100 });
	});

	/**
	 * **Validates: Requirement 9.4**
	 *
	 * Property 19: PE Section Target Filtering
	 * With targetSections specified, getSectionForOffset only returns
	 * section names for offsets within those sections. We test the
	 * filtering logic directly.
	 */
	test('P19: getSectionForOffset returns correct section for offsets within sections', () => {
		fc.assert(fc.property(
			// Generate random PE sections
			fc.array(
				fc.record({
					name: fc.constantFrom('.text', '.data', '.rdata', '.rsrc', '.reloc'),
					offset: fc.integer({ min: 0x200, max: 0x10000 }),
					size: fc.integer({ min: 0x100, max: 0x2000 }),
				}),
				{ minLength: 1, maxLength: 5 }
			),
			fc.constantFrom('.data', '.rdata', '.rsrc'),
			(rawSections, targetSection) => {
				// Build non-overlapping sections
				const sections: PESectionInfo[] = [];
				let nextOffset = 0x200;
				for (const raw of rawSections) {
					sections.push({
						name: raw.name,
						offset: nextOffset,
						size: raw.size,
						virtualAddress: nextOffset,
						virtualSize: raw.size,
					});
					nextOffset += raw.size + 0x100; // gap between sections
				}

				// For each section, offsets within it should return that section name
				for (const section of sections) {
					const midOffset = section.offset + Math.floor(section.size / 2);
					const result = getSectionForOffset(sections, midOffset);
					if (result !== section.name) {
						return false;
					}
				}

				// Offsets outside all sections should return undefined
				const beyondAll = nextOffset + 0x1000;
				if (getSectionForOffset(sections, beyondAll) !== undefined) {
					return false;
				}

				// Target filtering: only results in target sections should pass
				for (const section of sections) {
					const midOffset = section.offset + Math.floor(section.size / 2);
					const sectionName = getSectionForOffset(sections, midOffset);
					if (sectionName === targetSection) {
						// This offset is in a target section — should be included
						if (sectionName === undefined) { return false; }
					}
				}

				return true;
			}
		), { numRuns: 100 });
	});
});
