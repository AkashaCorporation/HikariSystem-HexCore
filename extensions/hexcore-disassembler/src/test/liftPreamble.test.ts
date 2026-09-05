/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { planLiftPreamble } from '../liftPreamble';

suite('lift preamble planning', () => {
	test('preserves call $+5 in raw and PE code', () => {
		const bytes = Buffer.from([0xe8, 0, 0, 0, 0, 0x5b, 0xc3]);
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x500000, false), {
			skipBytes: 0,
			transformations: [],
		});
	});

	test('skips and records an ftrace placeholder only for relocatable ELF', () => {
		const bytes = Buffer.from([0xe8, 0, 0, 0, 0, 0x55]);
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x1000, true), {
			skipBytes: 5,
			transformations: [
				{ kind: 'ftrace-preamble', address: 0x1000, bytes: 5 },
			],
		});
	});

	test('records CET, ftrace, and the exact kernel NOP independently', () => {
		const bytes = Buffer.from([
			0xf3, 0x0f, 0x1e, 0xfa,
			0xe8, 0, 0, 0, 0,
			0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0,
			0x55,
		]);
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x2000, true), {
			skipBytes: 18,
			transformations: [
				{ kind: 'cet-preamble', address: 0x2000, bytes: 4 },
				{ kind: 'ftrace-preamble', address: 0x2004, bytes: 5 },
				{ kind: 'nop-preamble', address: 0x2009, bytes: 9 },
			],
		});
	});

	test('does not cut through an unrecognized 66 0f instruction', () => {
		const bytes = Buffer.from([0x66, 0x0f, 0xef, 0xc0]);
		assert.strictEqual(planLiftPreamble(bytes, 0x3000, true).skipBytes, 0);
	});
});
