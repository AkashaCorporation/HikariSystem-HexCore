/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { CapstoneWrapper } from './capstoneWrapper';

suite('Capstone structured detail preservation', () => {
	test('keeps RIP-relative LEA operands and register access in the analysis wrapper', async () => {
		const capstone = new CapstoneWrapper();
		try {
			await capstone.initialize('x64', { detail: true });
			const instructions = await capstone.disassemble(
				Buffer.from('488d1d9af3ffff48895810', 'hex'),
				0x140001e5f,
				2,
			);
			assert.strictEqual(instructions.length, 2);
			const lea = instructions[0];
			assert.strictEqual(lea.mnemonic, 'lea');
			assert.ok(lea.detail?.x86, 'x86 detail must survive the high-level wrapper');
			assert.strictEqual(lea.detail.x86.operands.length, 2);
			assert.strictEqual(capstone.getRegisterName(lea.detail.x86.operands[0].reg!), 'rbx');
			assert.strictEqual(capstone.getRegisterName(lea.detail.x86.operands[1].mem!.base), 'rip');
			assert.strictEqual(lea.detail.x86.operands[1].mem!.disp, -0xc66);
			assert.ok(lea.detail.x86.operands[0].access > 0, 'explicit destination access must be present');
		} finally {
			capstone.dispose();
		}
	});
});
