import * as assert from 'assert';
import { canonicalArtifactJson, canonicalArtifactSha256, describeCanonicalArtifactIdentity } from './artifactNormalization';

suite('canonical artifact normalization', () => {
	test('ignores generatedAt, normalization, and object key order', () => {
		const first = { b: 2, generatedAt: 'a', nested: { z: 1, a: 2 }, analysisContext: { engineGeneration: 8, closureRestoration: { status: 'none' }, sessionGeneration: 6 } };
		const second = { nested: { a: 2, z: 1 }, normalization: { sha256: 'ignored' }, generatedAt: 'b', b: 2, analysisContext: { engineGeneration: 2, closureRestoration: { status: 'restored' }, sessionGeneration: 6 } };
		assert.strictEqual(canonicalArtifactJson(first), canonicalArtifactJson(second));
		assert.strictEqual(canonicalArtifactSha256(first), canonicalArtifactSha256(second));
	});

	test('publishes an exact reproducible algorithm contract', () => {
		const value = { status: 'partial', generatedAt: 'volatile' };
		assert.deepStrictEqual(describeCanonicalArtifactIdentity(value), {
			algorithm: 'hexcore-canonical-json-v1',
			excludedJsonPointers: ['/generatedAt', '/normalization', '/analysisContext/engineGeneration', '/analysisContext/closureRestoration'],
			sha256: canonicalArtifactSha256(value),
		});
	});
});
