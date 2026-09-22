import * as assert from 'assert';
import { resolveDrcovOutputPaths } from './drcovOutputPaths';

suite('Elixir DRCOV output paths', () => {
	test('preserves an explicit DRCOV path and moves metadata to a sidecar', () => {
		assert.deepStrictEqual(resolveDrcovOutputPaths('out/trace.drcov'), {
			drcovPath: 'out/trace.drcov',
			metadataPath: 'out/trace.drcov.json',
		});
	});

	test('preserves an explicit JSON path and emits DRCOV beside it', () => {
		assert.deepStrictEqual(resolveDrcovOutputPaths('out/trace.json'), {
			drcovPath: 'out/trace.drcov',
			metadataPath: 'out/trace.json',
		});
	});

	test('keeps an extensionless requested metadata path distinct', () => {
		assert.deepStrictEqual(resolveDrcovOutputPaths('out/trace'), {
			drcovPath: 'out/trace.drcov',
			metadataPath: 'out/trace',
		});
	});
});
