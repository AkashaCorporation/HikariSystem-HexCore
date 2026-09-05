/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import fixture from './test/fixtures/raceWorker.fixture.json';

function parseAddress(value: string): number {
	return Number.parseInt(value.slice(2), 16);
}

suite('race_worker release-gating fixture', () => {
	test('freezes the authorized binary and source provenance', () => {
		assert.strictEqual(fixture.binarySha256, '6e7f2c6a45509297265ec677835532dcf4a40c3abac6e29d20a5e0c9c88fb09b');
		assert.strictEqual(fixture.sourceSha256, '322c0fedf58ec47e8cbcb217de44f41803e7dd43dc075b3ccf410350e51f7509');
		assert.match(fixture.sourceFunction, /^void race_worker\(/);
	});

	test('freezes the exact half-open worker extent and adjacent function', () => {
		const start = parseAddress(fixture.worker.start);
		const endExclusive = parseAddress(fixture.worker.endExclusive);
		const bytes = Buffer.from(fixture.worker.bytesHex, 'hex');

		assert.strictEqual(start, 0x140001200);
		assert.strictEqual(endExclusive, 0x140001210);
		assert.strictEqual(bytes.length, endExclusive - start);
		assert.strictEqual(bytes[0x0e], 0xc3, 'semantic body terminates with ret');
		assert.strictEqual(bytes[0x0f], 0xcc, 'the byte before the next function is int3 padding');
		assert.strictEqual(parseAddress(fixture.adjacentFunction.start), endExclusive);
	});

	test('proves the RIP-relative LEA materializes the worker address before the store', () => {
		const leaAddress = parseAddress(fixture.callbackEvidence.leaAddress);
		const lea = Buffer.from(fixture.callbackEvidence.leaHex, 'hex');
		const displacement = lea.readInt32LE(3);
		const target = leaAddress + lea.length + displacement;

		assert.strictEqual(target, parseAddress(fixture.worker.start));
		assert.strictEqual(parseAddress(fixture.callbackEvidence.storeAddress), leaAddress + lea.length);
		assert.deepStrictEqual(Buffer.from(fixture.callbackEvidence.storeHex, 'hex'), Buffer.from([0x48, 0x89, 0x58, 0x10]));
	});
});
