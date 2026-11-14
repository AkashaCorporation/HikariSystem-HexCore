/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { calculateExecutableOwnershipCoverage } from './executableOwnershipCoverage';

suite('executable ownership coverage', () => {
	test('reports complete only for disjoint full ownership with resolved transfers', () => {
		const coverage = calculateExecutableOwnershipCoverage({
			executableRanges: [{ start: 0x1000, end: 0x1100 }],
			functionRanges: [{ start: 0x1000, end: 0x1080 }, { start: 0x1080, end: 0x1100 }],
			decodedInstructionRanges: [{ start: 0x1000, end: 0x1100 }],
			unresolvedIndirectTransfers: 0,
			discoveryBudgetPartial: false,
		});
		assert.strictEqual(coverage.status, 'complete');
		assert.strictEqual(coverage.rangeOwnershipRatio, 1);
		assert.strictEqual(coverage.overlappingOwnedBytes, 0);
		assert.deepStrictEqual(coverage.reasonCodes, []);
	});

	test('keeps unowned, overlap, decode, and indirect evidence separate', () => {
		const coverage = calculateExecutableOwnershipCoverage({
			executableRanges: [{ start: 0x1000, end: 0x1100 }],
			functionRanges: [{ start: 0x1000, end: 0x1080 }, { start: 0x1070, end: 0x10c0 }],
			decodedInstructionRanges: [{ start: 0x1000, end: 0x1040 }],
			unresolvedIndirectTransfers: 2,
			discoveryBudgetPartial: true,
		});
		assert.strictEqual(coverage.status, 'partial');
		assert.strictEqual(coverage.ownedRangeBytes, 0xc0);
		assert.strictEqual(coverage.unownedExecutableBytes, 0x40);
		assert.strictEqual(coverage.overlappingOwnedBytes, 0x10);
		assert.strictEqual(coverage.decodedInstructionBytes, 0x40);
		assert.deepStrictEqual(coverage.reasonCodes, [
			'unowned-executable-bytes',
			'overlapping-function-ownership',
			'unresolved-indirect-transfer',
			'discovery-budget-partial',
		]);
	});
});
