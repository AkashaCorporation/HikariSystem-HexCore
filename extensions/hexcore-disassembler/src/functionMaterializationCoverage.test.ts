/*---------------------------------------------------------------------------------------------
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	assessFunctionMaterialization,
	normalizeFunctionMaterializationPolicy,
} from './functionMaterializationCoverage';

suite('function materialization coverage', () => {
	test('labels accepted lazy discovery as reconnaissance without claiming negative evidence', () => {
		const result = assessFunctionMaterialization({ totalFunctions: 27916, materializedFunctions: 2,
			lazyFunctions: 27914, decodeEmptyFunctions: 0, allowLazy: true });
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.analysisDepth, 'reconnaissance-only');
		assert.strictEqual(result.negativeEvidenceUsable, false);
	});
	test('partial bodies cannot satisfy a complete materialization contract', () => {
		const result = assessFunctionMaterialization({ totalFunctions: 2, materializedFunctions: 1,
			partialFunctions: 1, lazyFunctions: 0, decodeEmptyFunctions: 0, allowLazy: true });
		assert.strictEqual(result.status, 'partial');
		assert.match(result.reason ?? '', /decoded partially/);
	});
	test('retains explicit headless policy fields and rejects malformed values', () => {
		assert.deepStrictEqual(normalizeFunctionMaterializationPolicy({
			allowLazy: true,
			allowDecodeEmpty: false,
			minMaterializedRatio: 0.25,
		}), {
			allowLazy: true,
			allowDecodeEmpty: false,
			minMaterializedRatio: 0.25,
		});
		assert.throws(
			() => normalizeFunctionMaterializationPolicy({ allowLazy: 'yes' }),
			/expected boolean/,
		);
		assert.throws(
			() => normalizeFunctionMaterializationPolicy({ minMaterializedRatio: 1.1 }),
			/between 0 and 1/,
		);
	});
	test('marks the Backblaze 5558/19770 population partial by default', () => {
		const result = assessFunctionMaterialization({
			totalFunctions: 19_770,
			materializedFunctions: 5_558,
			lazyFunctions: 14_212,
			decodeEmptyFunctions: 0,
		});
		assert.strictEqual(result.status, 'partial');
		assert.ok(Math.abs(result.materializedFunctionRatio - 5_558 / 19_770) < 1e-12);
		assert.match(result.reason ?? '', /14212 function body\/bodies remain lazy/);
	});

	test('requires explicit allowLazy for reconnaissance jobs', () => {
		const result = assessFunctionMaterialization({
			totalFunctions: 19_770,
			materializedFunctions: 5_558,
			lazyFunctions: 14_212,
			decodeEmptyFunctions: 0,
			allowLazy: true,
		});
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.policy.allowLazy, true);
	});

	test('enforces a configured minimum even when lazy bodies are allowed', () => {
		const result = assessFunctionMaterialization({
			totalFunctions: 100,
			materializedFunctions: 80,
			lazyFunctions: 20,
			decodeEmptyFunctions: 0,
			allowLazy: true,
			minMaterializedRatio: 0.9,
		});
		assert.strictEqual(result.status, 'partial');
		assert.match(result.reason ?? '', /below required 90.00%/);
	});

	test('decode-empty remains partial unless separately acknowledged', () => {
		const strict = assessFunctionMaterialization({
			totalFunctions: 2,
			materializedFunctions: 1,
			lazyFunctions: 0,
			decodeEmptyFunctions: 1,
			allowLazy: true,
		});
		assert.strictEqual(strict.status, 'partial');

		const accepted = assessFunctionMaterialization({
			totalFunctions: 2,
			materializedFunctions: 1,
			lazyFunctions: 0,
			decodeEmptyFunctions: 1,
			allowLazy: true,
			allowDecodeEmpty: true,
		});
		assert.strictEqual(accepted.status, 'ok');
	});
});
