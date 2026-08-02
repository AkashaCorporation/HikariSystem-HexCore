import * as assert from 'assert';
import { summarizeHqlResults } from './hqlScanner';

suite('HQL headless semantic contract (3.8.3 RC)', () => {
	test('all completed targets are ok', () => {
		assert.deepStrictEqual(summarizeHqlResults([
			{ address: '0x1', function: 'a', findings: [] },
			{ address: '0x2', function: 'b', findings: [] },
		]), {
			status: 'ok', success: true, completedTargetCount: 2, failedTargetCount: 0,
		});
	});

	test('mixed completed and failed targets are partial', () => {
		assert.deepStrictEqual(summarizeHqlResults([
			{ address: '0x1', function: 'a', findings: [] },
			{ address: '0x2', function: '', findings: [], error: 'decompile failed' },
		]), {
			status: 'partial', success: true, completedTargetCount: 1, failedTargetCount: 1,
		});
	});

	test('all failed targets fail the command', () => {
		assert.deepStrictEqual(summarizeHqlResults([
			{ address: '0x1', function: '', findings: [], error: 'decompile failed' },
		]), {
			status: 'failed', success: false, completedTargetCount: 0, failedTargetCount: 1,
		});
	});
});
