/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P10.1–P10.3: Rellic Optimization Passes & Souper Hook

import * as assert from 'assert';
import * as fc from 'fast-check';

/**
 * The default LLVM passes applied by the native module when no specific
 * passes are provided. This mirrors the native rellic_decompile_pipeline.cpp.
 */
const DEFAULT_PASSES = ['dce', 'constfold', 'instsimplify'];

/**
 * Simulates the optimizationPasses filtering logic from RellicWrapper.decompile():
 * - When optimizationPasses is provided and non-empty, only those passes are forwarded
 * - When omitted/empty, all default passes are applied
 */
function resolveOptimizationPasses(
	optimizerStep: 'none' | 'llvm-passes' | 'souper',
	optimizationPasses?: string[]
): string[] | undefined {
	if (optimizerStep === 'souper') {
		// Souper not implemented — falls through, no passes
		return undefined;
	}
	if (optimizerStep === 'none') {
		return undefined;
	}
	// llvm-passes
	if (optimizationPasses && optimizationPasses.length > 0) {
		return optimizationPasses;
	}
	return DEFAULT_PASSES;
}

suite('Property P10: Rellic Optimization Passes', () => {

	/**
	 * P10.1: optimizationPasses filters to only specified passes.
	 */
	test('specific passes are forwarded exactly', () => {
		fc.assert(
			fc.property(
				fc.uniqueArray(
					fc.constantFrom('dce', 'constfold', 'instsimplify', 'junk-filter', 'mem2reg', 'gvn'),
					{ minLength: 1, maxLength: 6 }
				),
				(passes) => {
					const resolved = resolveOptimizationPasses('llvm-passes', passes);
					assert.ok(resolved !== undefined, 'must return passes for llvm-passes step');
					assert.deepStrictEqual(resolved, passes, 'must forward exactly the specified passes');
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P10.2: Omitted optimizationPasses applies all default passes.
	 */
	test('omitted passes yields all defaults', () => {
		const resolved = resolveOptimizationPasses('llvm-passes', undefined);
		assert.deepStrictEqual(resolved, DEFAULT_PASSES);

		const resolvedEmpty = resolveOptimizationPasses('llvm-passes', []);
		assert.deepStrictEqual(resolvedEmpty, DEFAULT_PASSES);
	});

	/**
	 * P10.3: 'souper' step returns undefined (falls through, logs warning).
	 */
	test('souper step returns undefined (not yet implemented)', () => {
		fc.assert(
			fc.property(
				fc.oneof(
					fc.constant(undefined),
					fc.uniqueArray(fc.constantFrom('dce', 'constfold'), { minLength: 0, maxLength: 3 })
				),
				(passes) => {
					const resolved = resolveOptimizationPasses('souper', passes as string[] | undefined);
					assert.strictEqual(resolved, undefined,
						'souper must return undefined (not implemented)');
				}
			),
			{ numRuns: 50 }
		);
	});

	/**
	 * P10.3 (additional): 'none' step returns undefined regardless of passes.
	 */
	test('none step returns undefined regardless of passes', () => {
		fc.assert(
			fc.property(
				fc.oneof(
					fc.constant(undefined),
					fc.uniqueArray(fc.constantFrom('dce', 'constfold'), { minLength: 1, maxLength: 3 })
				),
				(passes) => {
					const resolved = resolveOptimizationPasses('none', passes as string[] | undefined);
					assert.strictEqual(resolved, undefined);
				}
			),
			{ numRuns: 50 }
		);
	});
});
