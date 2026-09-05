/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import { isIP } from 'net';
import { createHash } from 'crypto';

function validBase58Check(value: string): boolean {
	const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
	let number = 0n;
	for (const character of value) {
		const digit = alphabet.indexOf(character);
		if (digit < 0) return false;
		number = number * 58n + BigInt(digit);
	}
	let hex = number.toString(16);
	if (hex.length % 2) hex = `0${hex}`;
	const bytes = Buffer.concat([Buffer.alloc(value.match(/^1*/)?.[0].length ?? 0), Buffer.from(hex, 'hex')]);
	if (bytes.length !== 25 || ![0, 5].includes(bytes[0])) return false;
	const digest = createHash('sha256').update(createHash('sha256').update(bytes.subarray(0, 21)).digest()).digest();
	return digest.subarray(0, 4).equals(bytes.subarray(21));
}

/** Rejection means unsuitable as an IOC assertion; the raw attachment is retained. */
export function indicatorRejection(kind: string, value: string, context = ''): string | undefined {
	const category = kind.toLowerCase();
	if (category === 'ipv4' || category === 'ipv6') {
		if (isIP(value) !== (category === 'ipv4' ? 4 : 6)) return 'invalid-ip-syntax';
		if (category === 'ipv4') {
			const dotted = context.match(/\d+(?:\.\d+){4,}/g) ?? [];
			if (dotted.some(token => token.includes(value))) return 'component-of-longer-dotted-identifier';
			if (/X25519|X448|ED25519|ED448|ASN\.?1|\bOID\b|BLAKE|SHA\d*|RIPEMD|CAMELLIA/i.test(context)) return 'cryptographic-identifier-context';
			if (/vs20\d\d|[\\/]build[\\/]|version\s*[:=]|\bbuild\s*[:=]/i.test(context)) return 'version-or-build-context';
		}
	}
	if (category === 'mutex' && /^\{?[a-f\d]{8}-(?:[a-f\d]{4}-){3}[a-f\d]{12}\}?$/i.test(value) &&
		!/CreateMutex|OpenMutex|mutex/i.test(context)) return 'guid-without-mutex-evidence';
	if (category === 'cryptowallet') {
		if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(value)) {
			if (!validBase58Check(value)) return 'invalid-base58check-wallet';
		} else return 'wallet-format-not-validated';
	}
	if (category === 'url') {
		if (/[^\x21-\x7e]/.test(value)) return 'url-with-binary-or-whitespace-suffix';
		try {
			const url = new URL(value);
			if (!['http:', 'https:'].includes(url.protocol) || !url.hostname) return 'invalid-http-url';
		} catch { return 'invalid-http-url'; }
	}
	return undefined;
}
