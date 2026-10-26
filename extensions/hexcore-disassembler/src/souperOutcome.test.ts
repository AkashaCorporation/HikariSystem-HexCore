import * as assert from 'assert';
import { classifySouperOutcome, stampSouperOutcome } from './souperOutcome';

suite('Souper outcome contract', () => {
	test('labels a native reprint with zero replacements as a semantic no-op', () => {
		const input = '; ModuleID = \'input\'\ndefine i32 @f() { ret i32 0 }\n';
		const output = '; ModuleID = \'souper-input\'\ndefine i32 @f() { ret i32 0 }\n';
		const stats = { candidatesFound: 4, candidatesAttempted: 4, candidatesInferred: 0, candidatesReplaced: 0, solverTimeouts: 0 };
		const outcome = classifySouperOutcome(input, output, stats);
		assert.strictEqual(outcome.status, 'no-op');
		assert.strictEqual(outcome.semanticChanged, false);
		assert.strictEqual(outcome.textChanged, true);
		assert.strictEqual(outcome.noOpReason, 'no-replacements');
		const stamped = stampSouperOutcome(output, outcome, stats);
		assert.match(stamped, /^; HexCore-Souper: status=no-op semanticChanged=false textChanged=true /);
	});

	test('marks incomplete solver coverage partial instead of clean no-op', () => {
		const outcome = classifySouperOutcome('x', 'x', {
			candidatesFound: 10,
			candidatesAttempted: 5,
			candidatesInferred: 0,
			candidatesReplaced: 0,
			solverTimeouts: 2,
		});
		assert.strictEqual(outcome.status, 'partial');
		assert.strictEqual(outcome.partialReasons.length, 2);
	});

	test('labels actual replacements optimized', () => {
		const outcome = classifySouperOutcome('add', 'ret', {
			candidatesFound: 1,
			candidatesAttempted: 1,
			candidatesInferred: 1,
			candidatesReplaced: 1,
			solverTimeouts: 0,
		});
		assert.strictEqual(outcome.status, 'optimized');
		assert.strictEqual(outcome.semanticChanged, true);
	});
});
