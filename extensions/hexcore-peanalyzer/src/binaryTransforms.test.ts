import * as assert from 'assert';
import { decodeTransformKey, normalizeTransformLimit, rc4Transform } from './binaryTransforms';

suite('pipeline-safe binary transforms', () => {
	test('matches the canonical RC4 Key/Plaintext vector', () => {
		const encrypted = rc4Transform(Buffer.from('Plaintext', 'ascii'), Buffer.from('Key', 'ascii'));
		assert.strictEqual(encrypted.toString('hex').toUpperCase(), 'BBF316E8D940AF0AD3');
		assert.strictEqual(rc4Transform(encrypted, Buffer.from('Key', 'ascii')).toString('ascii'), 'Plaintext');
	});

	test('accepts explicit byte-array keys used by managed loaders', () => {
		assert.deepStrictEqual(decodeTransformKey({ key: [1, 2, 3, 4] }),
			Buffer.from([1, 2, 3, 4]));
	});

	test('rejects ambiguous keys and unbounded transform limits', () => {
		assert.throws(() => decodeTransformKey({ key: 'a', keyHex: '61' }), /exactly one/);
		assert.throws(() => normalizeTransformLimit(Number.MAX_SAFE_INTEGER), /maxBytes/);
	});
});
