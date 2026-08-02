import * as assert from 'assert';
import { evaluateYaraCondition } from './yaraEngine';

const identifiers = ['$peb64', '$mz_a', '$mz_b', '$pe_a', '$vm1', '$vm2', '$reg', '$load'];

function evaluate(condition: string, counts: Record<string, number>): boolean {
	const result = evaluateYaraCondition(condition, counts, identifiers);
	assert.strictEqual(result.supported, true, result.error);
	return result.result;
}

suite('YARA condition evaluator (3.8.3 RC)', () => {
	test('a fragment cannot satisfy a composite conjunction', () => {
		assert.strictEqual(evaluate(
			'$peb64 and (any of ($mz_*) or any of ($pe_*))',
			{ '$mz_a': 1 },
		), false);
		assert.strictEqual(evaluate(
			'$peb64 and (any of ($mz_*) or any of ($pe_*))',
			{ '$peb64': 1, '$mz_a': 1 },
		), true);
	});

	test('wildcard groups and numeric quantifiers preserve boolean precedence', () => {
		const condition = '$peb64 and 2 of ($vm*) and $reg and $load';
		assert.strictEqual(evaluate(condition, {
			'$peb64': 1, '$vm1': 1, '$vm2': 1, '$reg': 1, '$load': 1,
		}), true);
		assert.strictEqual(evaluate(condition, {
			'$peb64': 1, '$vm1': 1, '$reg': 1, '$load': 1,
		}), false);
	});

	test('count comparisons use occurrence counts, not presence only', () => {
		assert.strictEqual(evaluate('#peb64 >= 2', { '$peb64': 2 }), true);
		assert.strictEqual(evaluate('#peb64 >= 2', { '$peb64': 1 }), false);
	});

	test('unsupported syntax fails closed', () => {
		const result = evaluateYaraCondition('for any i in (1..3) : ($x)', { '$x': 1 }, ['$x']);
		assert.strictEqual(result.supported, false);
		assert.strictEqual(result.result, false);
	});
});
