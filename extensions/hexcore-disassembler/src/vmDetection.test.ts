import * as assert from 'assert';
import { detectCompareDispatcherLadder, type VmLadderInstruction } from './vmDetection';

function cmp(address: number, operands: string): VmLadderInstruction {
	return { address, mnemonic: 'cmp', opStr: operands, isConditional: false, isJump: false };
}

function jcc(address: number, target: number): VmLadderInstruction {
	return {
		address,
		mnemonic: 'je',
		opStr: `0x${target.toString(16)}`,
		isConditional: true,
		isJump: true,
		targetAddress: target
	};
}

suite('VM compare-ladder detection', () => {
	test('accepts a stable opcode operand with distinct handler targets', () => {
		const instructions: VmLadderInstruction[] = [];
		for (let i = 0; i < 6; i++) {
			instructions.push(cmp(0x401000 + i * 4, `eax, ${i}`));
			instructions.push(jcc(0x401002 + i * 4, 0x402000 + i * 0x20));
		}
		assert.deepStrictEqual(detectCompareDispatcherLadder(instructions), {
			address: 0x401000,
			opcodeCount: 6
		});
	});

	test('rejects anti-sandbox guards with unrelated operands and one failure target', () => {
		const comparisons = [
			'ax, 0x4a',
			'word ptr [esp + 0x9a], 0x6f',
			'dword ptr [esp + 0x44], 7',
			'si, 0x65',
			'word ptr [esp + 0x290], 0x48',
			'word ptr [esp + 0x296], 0x39'
		];
		const instructions: VmLadderInstruction[] = [];
		for (let i = 0; i < comparisons.length; i++) {
			instructions.push(cmp(0x403000 + i * 8, comparisons[i]));
			instructions.push(jcc(0x403004 + i * 8, 0x404000));
		}
		assert.deepStrictEqual(detectCompareDispatcherLadder(instructions), {
			address: null,
			opcodeCount: 0
		});
	});
});
