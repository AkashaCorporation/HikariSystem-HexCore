/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { applyDeobfuscationBudget } from './deobfuscationBudget';

suite('deobfuscation output budget', () => {
	test('filters low-confidence candidates and reports discard counts', () => {
		const filtered = applyDeobfuscationBudget([
			{ value: 'noise', offset: 1, confidence: 0.4 },
			{ value: 'https://c2.invalid/a', offset: 2, confidence: 0.9 },
		], { minConfidence: 0.7 });
		assert.deepStrictEqual(filtered.results.map(item => item.offset), [2]);
		assert.strictEqual(filtered.stats.discardedLowConfidence, 1);
	});

	test('high-signal mode keeps strong scores and explicit security indicators', () => {
		const filtered = applyDeobfuscationBudget([
			{ value: 'ordinary dictionary words', offset: 1, confidence: 0.7 },
			{ value: 'VirtualAlloc', offset: 2 },
			{ value: 'strong candidate', offset: 3, confidence: 0.91 },
		], { highSignalOnly: true });
		assert.deepStrictEqual(filtered.results.map(item => item.offset), [2, 3]);
		assert.strictEqual(filtered.stats.discardedLowSignal, 1);
	});

	test('caps output deterministically without changing accepted order', () => {
		const filtered = applyDeobfuscationBudget([
			{ value: 'one', offset: 1 },
			{ value: 'two', offset: 2 },
			{ value: 'three', offset: 3 },
		], { maxResults: 2 });
		assert.deepStrictEqual(filtered.results.map(item => item.offset), [1, 2]);
		assert.strictEqual(filtered.stats.discardedBudget, 1);
	});
});
