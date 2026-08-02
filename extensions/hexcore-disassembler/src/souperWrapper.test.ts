/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import {
	computeSouperDensity,
	decideSouperGate,
	SOUPER_AUTO_DEFAULT_MIN_OPS,
} from './souperWrapper';

suite('Souper activation gate', () => {
	const ordinaryIr = [
		'define i64 @ordinary(i64 %a, i64 %b) {',
		'entry:',
		'  %sum = add i64 %a, %b',
		'  %same = icmp eq i64 %sum, %a',
		'  br i1 %same, label %yes, label %no',
		'yes:',
		'  ret i64 %sum',
		'no:',
		'  ret i64 %b',
		'}',
	].join('\n');

	const denseIr = [
		'define i64 @dense(i64 %a, i64 %b) {',
		'entry:',
		'  %v0 = xor i64 %a, %b',
		'  %v1 = and i64 %v0, %a',
		'  %v2 = or i64 %v1, %b',
		'  %v3 = shl i64 %v2, 3',
		'  %v4 = lshr i64 %v3, 1',
		'  %v5 = ashr i64 %v4, 2',
		'  %v6 = xor i64 %v5, %a',
		'  %v7 = and i64 %v6, %b',
		'  ret i64 %v7',
		'}',
	].join('\n');

	test('absent option defaults to auto and skips ordinary IR', () => {
		const decision = decideSouperGate(undefined, ordinaryIr);
		assert.strictEqual(decision.run, false);
		assert.strictEqual(decision.mode, 'auto-skip');
		assert.ok(decision.density);
	});

	test('auto runs only when both density and minimum-op gates pass', () => {
		const density = computeSouperDensity(denseIr);
		assert.strictEqual(density.signalOps, SOUPER_AUTO_DEFAULT_MIN_OPS);
		const decision = decideSouperGate('auto', denseIr);
		assert.strictEqual(decision.run, true);
		assert.strictEqual(decision.mode, 'auto-run');
	});

	test('explicit true and false bypass the heuristic', () => {
		assert.strictEqual(decideSouperGate(true, ordinaryIr).mode, 'forced-on');
		assert.strictEqual(decideSouperGate(true, ordinaryIr).run, true);
		assert.strictEqual(decideSouperGate(false, denseIr).mode, 'forced-off');
		assert.strictEqual(decideSouperGate(false, denseIr).run, false);
	});

	test('unknown values use auto instead of forcing the solver', () => {
		const decision = decideSouperGate('unexpected', ordinaryIr);
		assert.strictEqual(decision.mode, 'auto-skip');
		assert.strictEqual(decision.run, false);
	});
});
