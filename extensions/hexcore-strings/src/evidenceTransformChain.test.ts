/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { detectEvidenceTransformChains } from './evidenceTransformChain';

suite('evidence transform chains', () => {
	test('recovers the Foreigner JWT evidence chain with provenance', () => {
		const result = detectEvidenceTransformChains([{
			value: '6579416964486c77496a6f67496b705856434973',
			offset: 0x41e100,
			source: 'extracted',
		}]);
		assert.strictEqual(result.chains.length, 1);
		assert.strictEqual(result.chains[0].asciiPreview, 'eyAidHlwIjogIkpXVCIs');
		assert.strictEqual(result.chains[0].decodedPreview, '{ "typ": "JWT",');
		assert.strictEqual(result.chains[0].jsonValid, false);
		assert.strictEqual(result.chains[0].confidence, 0.8);
		assert.match(result.chains[0].decodedSha256, /^[0-9a-f]{64}$/);
	});

	test('rejects printable lookup-table fragments and ordinary hex', () => {
		const result = detectEvidenceTransformChains([
			{ value: 'Qkkbal', offset: 1, source: 'extracted' },
			{ value: '00112233445566778899aabbccddeeff', offset: 2, source: 'extracted' },
		]);
		assert.deepStrictEqual(result.chains, []);
		assert.strictEqual(result.budget.candidates, 2);
		assert.strictEqual(result.budget.accountedCandidates, 2);
		assert.strictEqual(result.budget.unaccountedCandidates, 0);
		assert.strictEqual(result.budget.rejectedInvalidHex, 1);
		assert.strictEqual(result.budget.rejectedNonPrintableHex, 1);
	});

	test('enforces the chain output budget', () => {
		const hex = '6579416964486c77496a6f67496b705856434973';
		const candidates = [1, 2, 3].map(offset => ({ value: hex, offset, source: 'extracted' as const }));
		const result = detectEvidenceTransformChains(candidates, 2);
		assert.strictEqual(result.chains.length, 2);
		assert.strictEqual(result.budget.discardedBudget, 1);
		assert.strictEqual(result.budget.accountedCandidates, 3);
		assert.strictEqual(result.budget.unaccountedCandidates, 0);
	});
});
