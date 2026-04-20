/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Properties P7.1–P7.2: Junk Filtering

import * as assert from 'assert';
import * as fc from 'fast-check';

/** Minimal Instruction shape for filterJunkInstructions */
interface Instruction {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

/**
 * Generates a "real" (non-junk) instruction that won't match any junk pattern.
 */
function realInstructionArb(addr: number): fc.Arbitrary<Instruction> {
	return fc.constantFrom(
		{ mnemonic: 'mov', opStr: 'eax, ebx' },
		{ mnemonic: 'add', opStr: 'eax, 1' },
		{ mnemonic: 'sub', opStr: 'ecx, 5' },
		{ mnemonic: 'cmp', opStr: 'eax, 0' },
		{ mnemonic: 'jmp', opStr: '0x401000' },
		{ mnemonic: 'ret', opStr: '' },
		{ mnemonic: 'xor', opStr: 'eax, ebx' },
		{ mnemonic: 'and', opStr: 'edx, 0xff' },
		{ mnemonic: 'shl', opStr: 'eax, 2' },
		{ mnemonic: 'imul', opStr: 'eax, ecx' },
	).map(({ mnemonic, opStr }) => ({
		address: addr,
		bytes: Buffer.from([0x90]),
		mnemonic,
		opStr,
		size: 1,
		isCall: mnemonic === 'call',
		isJump: mnemonic === 'jmp',
		isRet: mnemonic === 'ret',
		isConditional: false,
	}));
}

/**
 * Generates a known junk instruction.
 */
function junkInstructionArb(addr: number): fc.Arbitrary<Instruction> {
	return fc.constantFrom(
		{ mnemonic: 'nop', opStr: '' },
		{ mnemonic: 'add', opStr: 'eax, 0' },
		{ mnemonic: 'sub', opStr: 'ecx, 0' },
		{ mnemonic: 'mov', opStr: 'eax, eax' },
		{ mnemonic: 'xchg', opStr: 'eax, eax' },
	).map(({ mnemonic, opStr }) => ({
		address: addr,
		bytes: Buffer.from([0x90]),
		mnemonic,
		opStr,
		size: 1,
		isCall: false,
		isJump: false,
		isRet: false,
		isConditional: false,
	}));
}

/**
 * Reimplements the core junk filtering logic from DisassemblerEngine
 * for unit-level property testing without needing vscode/capstone.
 */
function filterJunkInstructions(instructions: Instruction[]): { filtered: Instruction[]; junkCount: number; junkRatio: number } {
	const filtered: Instruction[] = [];
	let junkCount = 0;
	const len = instructions.length;

	for (let i = 0; i < len; i++) {
		const curr = instructions[i];
		const next = i + 1 < len ? instructions[i + 1] : null;
		const mn = curr.mnemonic.toLowerCase();
		const op = curr.opStr.toLowerCase().replace(/\s+/g, '');

		if (mn === 'call' && next) {
			const nextMn = next.mnemonic.toLowerCase();
			if (nextMn === 'pop' && curr.targetAddress === next.address) {
				junkCount += 2; i++; continue;
			}
		}
		if ((mn === 'add' || mn === 'sub') && (op.endsWith(',0') || op.endsWith(',0x0'))) {
			junkCount++; continue;
		}
		if (mn === 'nop') { junkCount++; continue; }
		if (mn === 'push' && next && next.mnemonic.toLowerCase() === 'pop') {
			const pushReg = op.trim();
			const popReg = next.opStr.toLowerCase().replace(/\s+/g, '').trim();
			if (pushReg === popReg) { junkCount += 2; i++; continue; }
		}
		if (mn === 'xchg') {
			const parts = op.split(',');
			if (parts.length === 2 && parts[0].trim() === parts[1].trim()) { junkCount++; continue; }
		}
		if (mn === 'mov') {
			const parts = op.split(',');
			if (parts.length === 2 && parts[0].trim() === parts[1].trim()) { junkCount++; continue; }
		}
		if (mn === 'lea') {
			const parts = op.split(',');
			if (parts.length === 2) {
				const dst = parts[0].trim();
				const src = parts[1].trim();
				const leaMatch = src.match(/^\[(\w+)(?:\+0(?:x0)?)?\]$/);
				if (leaMatch && leaMatch[1] === dst) { junkCount++; continue; }
			}
		}
		filtered.push(curr);
	}
	return { filtered, junkCount, junkRatio: len > 0 ? junkCount / len : 0 };
}

suite('Property P7: Junk Filtering', () => {

	/**
	 * P7.1: filterJunk reduces instruction count (or keeps same if no junk).
	 */
	test('filterJunk reduces instruction count when junk is present', () => {
		fc.assert(
			fc.property(
				fc.integer({ min: 1, max: 20 }),
				fc.integer({ min: 1, max: 10 }),
				(realCount, junkCount) => {
					const instrs: Instruction[] = [];
					let addr = 0x401000;
					// Add real instructions
					for (let i = 0; i < realCount; i++) {
						instrs.push({
							address: addr, bytes: Buffer.from([0x89, 0xc3]),
							mnemonic: 'mov', opStr: 'eax, ebx', size: 2,
							isCall: false, isJump: false, isRet: false, isConditional: false,
						});
						addr += 2;
					}
					// Add junk instructions
					for (let i = 0; i < junkCount; i++) {
						instrs.push({
							address: addr, bytes: Buffer.from([0x90]),
							mnemonic: 'nop', opStr: '', size: 1,
							isCall: false, isJump: false, isRet: false, isConditional: false,
						});
						addr += 1;
					}

					const result = filterJunkInstructions(instrs);
					assert.ok(result.filtered.length <= instrs.length,
						'filtered count must not exceed original');
					assert.ok(result.filtered.length < instrs.length,
						'filtered count must be less when junk is present');
					assert.strictEqual(result.junkCount, junkCount);
				}
			),
			{ numRuns: 100 }
		);
	});

	/**
	 * P7.2: junkRatio is always between 0.0 and 1.0 inclusive.
	 */
	test('junkRatio is between 0 and 1', () => {
		fc.assert(
			fc.property(
				fc.array(
					fc.oneof(
						fc.constant({ mnemonic: 'mov', opStr: 'eax, ebx' }),
						fc.constant({ mnemonic: 'nop', opStr: '' }),
						fc.constant({ mnemonic: 'add', opStr: 'eax, 0' }),
						fc.constant({ mnemonic: 'ret', opStr: '' }),
					),
					{ minLength: 0, maxLength: 50 }
				),
				(mnemonics) => {
					let addr = 0x401000;
					const instrs: Instruction[] = mnemonics.map(m => {
						const i: Instruction = {
							address: addr, bytes: Buffer.from([0x90]),
							mnemonic: m.mnemonic, opStr: m.opStr, size: 1,
							isCall: false, isJump: false, isRet: false, isConditional: false,
						};
						addr += 1;
						return i;
					});

					const result = filterJunkInstructions(instrs);
					assert.ok(result.junkRatio >= 0, `junkRatio must be >= 0, got ${result.junkRatio}`);
					assert.ok(result.junkRatio <= 1, `junkRatio must be <= 1, got ${result.junkRatio}`);
				}
			),
			{ numRuns: 200 }
		);
	});
});
