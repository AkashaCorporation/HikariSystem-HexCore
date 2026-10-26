/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import type { Instruction } from './disassemblerEngine';
import { buildInstructionFormula } from './formulaBuilder';

function instruction(address: number, mnemonic: string, opStr: string): Instruction {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic,
		opStr,
		size: 1,
		isCall: false,
		isJump: false,
		isRet: mnemonic === 'ret',
		isConditional: false,
	};
}

suite('formula builder semantic honesty', () => {
	test('tracks the x86 xor/and/lea MBA add expression without stale registers', () => {
		const result = buildInstructionFormula([
			instruction(0x1000, 'mov', 'rax, rcx'),
			instruction(0x1003, 'xor', 'rcx, rdx'),
			instruction(0x1006, 'and', 'rax, rdx'),
			instruction(0x1009, 'lea', 'rax, [rcx + rax*2]'),
			instruction(0x100d, 'ret', ''),
		], 'rax');

		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.formulaStatus, 'complete');
		assert.strictEqual(result.unsupportedInstructions.length, 0);
		assert.match(result.expression, /rcx \^ rdx/);
		assert.match(result.expression, /rcx & rdx/);
	});

	test('tracks one-operand x86 neg before xor/and', () => {
		const result = buildInstructionFormula([
			instruction(0x2000, 'neg', 'rdx'),
			instruction(0x2003, 'mov', 'rax, rdx'),
			instruction(0x2006, 'xor', 'rdx, rcx'),
			instruction(0x2009, 'and', 'rax, rcx'),
			instruction(0x200c, 'lea', 'rax, [rdx + rax*2]'),
		], 'rax');

		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.formulaStatus, 'complete');
		assert.match(result.expression, /- \(rdx\)/);
		assert.match(result.expression, /\^ rcx/);
	});

	test('marks an expression partial when a math instruction is unsupported', () => {
		const result = buildInstructionFormula([
			instruction(0x3000, 'mov', 'rax, rcx'),
			instruction(0x3003, 'not', 'rax'),
		], 'rax');

		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.formulaStatus, 'partial-expression');
		assert.strictEqual(result.unsupportedInstructions.length, 1);
		assert.match(result.reportMarkdown, /Do not treat it as semantically equivalent/);
	});
});
