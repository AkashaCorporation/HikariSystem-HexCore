import * as assert from 'assert';
import { assessInstructionBoundary, resolveInstructionBoundaryContract } from './disassemblyBoundary';

suite('disassembly instruction boundary', () => {
	const instructions = [
		{ address: 0x1406890c3, size: 7 },
		{ address: 0x1406890ca, size: 3 },
	];

	test('accepts an exact materialized instruction start', () => {
		assert.deepStrictEqual(assessInstructionBoundary(0x1406890c3, instructions), {
			status: 'aligned',
			source: 'materialized-function-body',
			suggestedAddress: 0x1406890c3,
		});
	});

	test('rejects an address inside a materialized instruction', () => {
		assert.deepStrictEqual(assessInstructionBoundary(0x1406890c4, instructions), {
			status: 'mid-instruction',
			source: 'materialized-function-body',
			suggestedAddress: 0x1406890c3,
		});
	});

	test('does not invent a verdict outside the materialized body', () => {
		assert.deepStrictEqual(assessInstructionBoundary(0x1406890d0, instructions), {
			status: 'unassessed',
			source: 'none',
		});
	});

	test('makes an unresolved mid-instruction request partial', () => {
		const result = resolveInstructionBoundaryContract({
			requestedAddress: 0x1406890c4,
			effectiveAddress: 0x1406890c4,
			autoBacktrack: false,
			instructions,
			lookbehindAligned: true,
		});
		assert.strictEqual(result.status, 'mid-instruction');
		assert.strictEqual(result.recoveredByAutoBacktrack, false);
		assert.strictEqual(result.requiresPartial, true);
		assert.strictEqual(result.suggestedAddress, 0x1406890c3);
	});

	test('accepts a mid-instruction request only when auto-backtrack recovered it', () => {
		const result = resolveInstructionBoundaryContract({
			requestedAddress: 0x1406890c4,
			effectiveAddress: 0x140689070,
			autoBacktrack: true,
			instructions,
			lookbehindAligned: false,
		});
		assert.strictEqual(result.status, 'mid-instruction');
		assert.strictEqual(result.recoveredByAutoBacktrack, true);
		assert.strictEqual(result.requiresPartial, false);
	});
});
