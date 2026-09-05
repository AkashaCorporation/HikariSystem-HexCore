/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { scorePathfinderConfidence } from './pathfinder';

suite('Pathfinder evidence-gated confidence', () => {
	test('does not award 90% merely because random bytes decode', () => {
		const score = scorePathfinderConfidence({
			hasBoundary: false,
			instructionsDecoded: 6,
			terminalPaths: 0,
			decodeFailures: 0,
			unresolvedIndirects: 0,
			resolvedIndirects: 0,
			hitIterationLimit: false,
		});
		assert.ok(score.confidence <= 65);
		assert.ok(score.reasons.includes('no-known-function-boundary'));
		assert.ok(score.reasons.includes('no-return-or-tail-terminal'));
	});

	test('keeps independently useful axes for a bounded terminating CFG', () => {
		const score = scorePathfinderConfidence({
			hasBoundary: true,
			instructionsDecoded: 7,
			terminalPaths: 1,
			decodeFailures: 0,
			unresolvedIndirects: 0,
			resolvedIndirects: 0,
			hitIterationLimit: false,
		});
		assert.deepStrictEqual(score.axes, {
			boundary: 85,
			decode: 80,
			termination: 85,
			indirectResolution: 100,
		});
		assert.strictEqual(score.confidence, 86);
		assert.deepStrictEqual(score.reasons, []);
	});

	test('caps a run that exhausts the recursive-descent budget', () => {
		const score = scorePathfinderConfidence({
			hasBoundary: true,
			instructionsDecoded: 50_000,
			terminalPaths: 10,
			decodeFailures: 0,
			unresolvedIndirects: 0,
			resolvedIndirects: 3,
			hitIterationLimit: true,
		});
		assert.ok(score.confidence <= 45);
		assert.ok(score.reasons.includes('recursive-descent-iteration-limit'));
	});
});
