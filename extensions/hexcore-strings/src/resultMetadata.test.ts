/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: xor-massive-update — Result Metadata Properties

import * as fc from 'fast-check';
import { compositeCipherScan } from './compositeCipher';
import { layeredXorScan } from './layeredXor';
import { positionalXorScan } from './positionalXor';
import { rollingXorExtScan } from './rollingXorExt';
import { getSectionForOffset, type PESectionInfo } from './peSectionParser';

suite('Result Metadata Properties', () => {

	/**
	 * **Validates: Requirements 3.4, 4.3, 6.3, 7.2, 9.3**
	 *
	 * Property 15: Result Metadata Completeness
	 * Each result type contains required method-specific fields:
	 * (a) composite ciphers: cipherOp and cipherKey fields
	 * (b) layered XOR: layerKeys array with length equal to layerCount
	 * (c) positional XOR: derivationParams with type and relevant parameters
	 * (d) rolling-ext: windowSize field >= 1
	 * (e) PE section results: section field when offset falls within a known section
	 */
	test('P15: Composite cipher results contain cipherOp and cipherKey', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 32, maxLength: 512 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);
				const results = compositeCipherScan(buf, 0, { minConfidence: 0.0 });

				for (const r of results) {
					// Every composite cipher result must have cipherOp and cipherKey
					if (r.cipherOp === undefined || r.cipherKey === undefined) {
						return false;
					}
					// cipherOp must be one of ADD, SUB, ROT
					if (!['ADD', 'SUB', 'ROT'].includes(r.cipherOp)) {
						return false;
					}
					// method must match cipherOp
					if (r.method !== r.cipherOp) {
						return false;
					}
					// ROT results must have rotValue
					if (r.method === 'ROT' && r.rotValue === undefined) {
						return false;
					}
				}
				return true;
			}
		), { numRuns: 100 });
	});

	test('P15: Layered XOR results contain layerKeys with correct length', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 64, maxLength: 512 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);
				const results = layeredXorScan(buf, 0, { minConfidence: 0.0 });

				for (const r of results) {
					// layerKeys must be present and be an array
					if (!Array.isArray(r.layerKeys)) {
						return false;
					}
					// layerCount must be present and >= 1
					if (r.layerCount === undefined || r.layerCount < 1) {
						return false;
					}
					// layerKeys length must equal layerCount
					if (r.layerKeys.length !== r.layerCount) {
						return false;
					}
				}
				return true;
			}
		), { numRuns: 100 });
	});

	test('P15: Positional XOR results contain derivationParams with type', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 64, maxLength: 512 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);
				const results = positionalXorScan(buf, 0, { minConfidence: 0.0 });

				for (const r of results) {
					// derivationParams must be present
					if (r.derivationParams === undefined) {
						return false;
					}
					// type must be counter-linear or block-rotate
					if (!['counter-linear', 'block-rotate'].includes(r.derivationParams.type)) {
						return false;
					}
					// counter-linear must have base and step
					if (r.derivationParams.type === 'counter-linear') {
						if (r.derivationParams.base === undefined || r.derivationParams.step === undefined) {
							return false;
						}
					}
					// block-rotate must have blockSize
					if (r.derivationParams.type === 'block-rotate') {
						if (r.derivationParams.blockSize === undefined) {
							return false;
						}
					}
				}
				return true;
			}
		), { numRuns: 100 });
	});

	test('P15: Rolling XOR ext results contain windowSize >= 1', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 32, maxLength: 512 }),
			(bufArr) => {
				const buf = Buffer.from(bufArr);
				const results = rollingXorExtScan(buf, 0, { minConfidence: 0.0 });

				for (const r of results) {
					// windowSize must be present and >= 1
					if (r.windowSize === undefined || r.windowSize < 1) {
						return false;
					}
				}
				return true;
			}
		), { numRuns: 100 });
	});

	test('P15: getSectionForOffset returns section name for offsets within sections', () => {
		fc.assert(fc.property(
			fc.integer({ min: 0x200, max: 0x1000 }),
			fc.integer({ min: 0x100, max: 0x2000 }),
			fc.integer({ min: 0, max: 100 }),
			(sectionOffset, sectionSize, offsetDelta) => {
				const sections: PESectionInfo[] = [{
					name: '.data',
					offset: sectionOffset,
					size: sectionSize,
					virtualAddress: sectionOffset,
					virtualSize: sectionSize,
				}];

				// Offset within section should return section name
				const withinOffset = sectionOffset + (offsetDelta % sectionSize);
				const result = getSectionForOffset(sections, withinOffset);
				if (result !== '.data') {
					return false;
				}

				// Offset outside section should return undefined
				const outsideOffset = sectionOffset + sectionSize + 1000;
				if (getSectionForOffset(sections, outsideOffset) !== undefined) {
					return false;
				}

				return true;
			}
		), { numRuns: 100 });
	});
});
