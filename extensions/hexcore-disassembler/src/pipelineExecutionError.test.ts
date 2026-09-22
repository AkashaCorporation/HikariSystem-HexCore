import * as assert from 'assert';
import { normalizePipelineExecutionError } from './pipelineExecutionError';

suite('pipeline execution error normalization', () => {
	test('preserves owner activation diagnostics for unavailable commands', () => {
		const source = new Error(
			'Command is not available in Extension Host: hexcore.helix.decompileIR. ' +
			'Owner state: hikarisystem.hexcore-helix=activate-failed(native addon missing)',
		);
		const normalized = normalizePipelineExecutionError(source, 'hexcore.helix.decompileIR');
		assert.match(normalized, /^Command is not available: hexcore\.helix\.decompileIR\./);
		assert.match(normalized, /Owner state:/);
		assert.match(normalized, /activate-failed\(native addon missing\)/);
	});

	test('leaves unrelated execution errors unchanged', () => {
		assert.strictEqual(
			normalizePipelineExecutionError(new Error('IR input does not exist'), 'hexcore.helix.decompileIR'),
			'IR input does not exist',
		);
	});
});
