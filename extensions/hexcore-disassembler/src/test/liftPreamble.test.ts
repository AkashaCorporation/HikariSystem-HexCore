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
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x500000, false, { architecture: 'x86' }), {
			skipBytes: 0,
			transformations: [],
		});
	});

	test('skips and records ftrace only with a matching relocation', () => {
		const bytes = Buffer.from([0xe8, 0, 0, 0, 0, 0x55]);
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x1000, true, { architecture: 'x64', textSectionAddress: 0x1000,
			textRelocations: new Map([[1, { name: '__fentry__', type: 4, addend: -4 }]]) }), {
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
		assert.deepStrictEqual(planLiftPreamble(bytes, 0x2000, true, { architecture: 'x64', textSectionAddress: 0x2000,
			textRelocations: new Map([[5, { name: '__fentry__', type: 4, addend: -4 }]]) }), {
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
		assert.strictEqual(planLiftPreamble(bytes, 0x3000, true, { architecture: 'x64' }).skipBytes, 0);
	});
	test('does not erase unresolved real ELF calls or assume missing evidence', () => {
		const bytes = Buffer.from([0xe8, 0, 0, 0, 0, 0xc3]);
		assert.strictEqual(planLiftPreamble(bytes, 0, true).skipBytes, 0);
		for (const relocation of [{ name: 'real_function', type: 4, addend: -4 }, { name: '__fentry__', type: 4, addend: 0 }, { name: '__fentry__', type: 10, addend: -4 }]) {
			assert.strictEqual(planLiftPreamble(bytes, 0, true, { architecture: 'x64', textSectionAddress: 0, textRelocations: new Map([[1, relocation]]) }).skipBytes, 0);
		}
	});
	test('x86 patterns cannot be interpreted in another architecture or mode', () => {
		const cet64 = Buffer.from('f30f1efa660f1f840000000000c3', 'hex');
		assert.strictEqual(planLiftPreamble(cet64, 0, false, { architecture: 'arm64' }).skipBytes, 0);
		assert.strictEqual(planLiftPreamble(cet64, 0, false, { architecture: 'x86' }).skipBytes, 0);
		assert.strictEqual(planLiftPreamble(cet64, 0, false, { architecture: 'x64' }).skipBytes, 13);
		assert.strictEqual(planLiftPreamble(Buffer.from('f30f1efbc3', 'hex'), 0, false, { architecture: 'x86' }).skipBytes, 4);
	});
});
