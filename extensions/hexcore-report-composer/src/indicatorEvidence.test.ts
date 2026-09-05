/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { indicatorRejection } from './indicatorEvidence';

suite('indicator evidence validation', () => {
	test('does not classify OID fragments or build versions as IPs', () => {
		assert.ok(indicatorRejection('ipv4', '12.2.2.8', '.3.6.1.4.1.1722.12.2.2.8..BLAKE2B'));
		assert.ok(indicatorRejection('ipv4', '1.3.101.110', 'X25519:1.3.101.110'));
		assert.ok(indicatorRejection('ipv4', '1.12.5.54', 'vs2022.1.12.5.54\\build\\native'));
		assert.strictEqual(indicatorRejection('ipv4', '12.2.2.8', 'connect 12.2.2.8:443'), undefined);
	});
	test('rejects times while preserving actual IPv6 literals', () => {
		for (const time of ['00:00:00', '23:59:59', '19:14:07']) assert.ok(indicatorRejection('ipv6', time));
		assert.strictEqual(indicatorRejection('ipv6', '2001:db8::1'), undefined);
	});
	test('GUIDs require mutex context and Bitcoin-like wallets require checksum', () => {
		const guid = '{12345678-1234-1234-1234-1234567890ab}';
		assert.ok(indicatorRejection('mutex', guid));
		assert.strictEqual(indicatorRejection('mutex', guid, 'CreateMutex'), undefined);
		for (const fragment of ['3euvAgMBAAGjQjBAMA8GA1UdEwEB', '3qszWY19zjNoFmag4qMsXeDZR', '3ppCustomScanPathPatterns']) assert.ok(indicatorRejection('cryptoWallet', fragment));
		assert.strictEqual(indicatorRejection('cryptoWallet', '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), undefined);
	});
	test('retains the raw malformed URL instead of inventing a trimmed endpoint', () => {
		assert.ok(indicatorRejection('url', 'https://example.test/a\u0086'));
		assert.strictEqual(indicatorRejection('url', 'https://example.test/a'), undefined);
	});
});
