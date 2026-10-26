/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { normalizeReferenceGraphQueryOptions } from './referenceQueryOptions';

suite('reference query command options', () => {
	test('maps top-level incoming and outgoing addresses to exact graph filters', () => {
		assert.deepStrictEqual(normalizeReferenceGraphQueryOptions({ to: '0x140006BD8' }), {
			direction: 'incoming', address: '0x140006bd8',
		});
		assert.deepStrictEqual(normalizeReferenceGraphQueryOptions({ from: 0x1400014e0 }), {
			direction: 'outgoing', address: '0x1400014e0',
		});
	});

	test('maps function ownership and friendly kinds without discarding nested filters', () => {
		const query = normalizeReferenceGraphQueryOptions({
			query: { minimumEvidenceStrength: 'derived' },
			functionIdentity: 'function:0x1400014e0',
			kinds: ['call', 'string'],
		});
		assert.strictEqual(query.functionIdentity, 'function:0x1400014e0');
		assert.strictEqual(query.minimumEvidenceStrength, 'derived');
		assert.deepStrictEqual(query.relations, [
			'code-call-near', 'code-call-far', 'code-indirect-candidate', 'code-indirect-resolved', 'string-reference',
		]);
	});

	test('supports exact target identities and rejects ambiguous or unsupported requests', () => {
		assert.deepStrictEqual(normalizeReferenceGraphQueryOptions({ to: 'string:usage' }), {
			direction: 'incoming', targetIdentity: 'string:usage',
		});
		assert.throws(() => normalizeReferenceGraphQueryOptions({ from: '0x1000', to: '0x2000' }));
		assert.throws(() => normalizeReferenceGraphQueryOptions({ kinds: ['bogus'] }));
		assert.deepStrictEqual(normalizeReferenceGraphQueryOptions({ resolveThunks: true, to: '0x2000' }), {
			direction: 'incoming', address: '0x2000',
		});
	});
});
