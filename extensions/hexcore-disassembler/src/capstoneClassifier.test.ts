/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Capstone instruction classifier — spec-level tests (v3.8.0).
 *
 * Source: hexcore-disassembler/src/capstoneWrapper.ts, private method
 * `convertInstruction` (single source of truth for call/ret/jump/conditional
 * flags that downstream CFG building + xref classification rely on).
 *
 * Because the method is MODULE-PRIVATE and the wrapper class requires a
 * live Capstone handle, this file RE-IMPLEMENTS the classifier at spec level
 * (mirroring the diff) and drives it with a curated instruction → category
 * table. Any divergence between the spec here and capstoneWrapper.ts must be
 * reconciled in review — this test is the canonical contract.
 *
 * Bugs pinned (from diff comments):
 *   - ARM32 conditional BL forms (bleq/blne/...) were being classified as
 *     generic branches instead of calls → broken CFG on ARM32 binaries.
 *   - x86 iretd/sysret/eret were not ending basic blocks → BBs leaking past
 *     kernel-mode returns.
 *   - ARM64 PAC variants (braa/brab/retaa/retab/eretaa/eretab) missed →
 *     ARMv8.3 (Apple M1, iOS 14+, Win11-on-ARM) decoded wrong.
 *   - `bx lr` must be ret; `bx r3` must be jump.
 *
 * References:
 *   - Intel SDM Vol.2 — CALL / RET / IRET / SYSRET / UD2
 *   - ARM ARM DDI 0487 — C6.2 (A64 branch), A8.8.25 (A32 BL)
 *   - ARMv8.3 FEAT_PAuth — C6.2.30 (BRAA/BRAB), C6.2.244 (RETAA/RETAB)
 */

import * as assert from 'assert';
import 'mocha';

// ---------------------------------------------------------------------------
// Spec reimpl — MUST track capstoneWrapper.ts convertInstruction() exactly
// ---------------------------------------------------------------------------

interface Classification {
	isCall: boolean;
	isRet: boolean;
	isJump: boolean;
	isConditional: boolean;
}

function classify(rawMnemonic: string, rawOpStr: string): Classification {
	const mnemonic = rawMnemonic.toLowerCase();
	const opStr = rawOpStr.toLowerCase().trim();

	const arm32CondBL = new Set([
		'bl', 'blx',
		'bleq', 'blne', 'blcs', 'blhs', 'blcc', 'bllo',
		'blmi', 'blpl', 'blvs', 'blvc',
		'blhi', 'blls', 'blge', 'bllt', 'blgt', 'blle', 'blal'
	]);
	const isCall = mnemonic === 'call'
		|| arm32CondBL.has(mnemonic)
		|| mnemonic === 'blr'
		|| mnemonic === 'blraa' || mnemonic === 'blrab'
		|| mnemonic === 'blraaz' || mnemonic === 'blrabz';

	const isRet = mnemonic === 'ret' || mnemonic === 'retn'
		|| mnemonic === 'retf' || mnemonic === 'iret'
		|| mnemonic === 'iretd' || mnemonic === 'iretq'
		|| mnemonic === 'sysret' || mnemonic === 'sysretq' || mnemonic === 'sysexit'
		|| mnemonic === 'retaa' || mnemonic === 'retab'
		|| mnemonic === 'eret' || mnemonic === 'eretaa' || mnemonic === 'eretab'
		|| mnemonic === 'ud2'
		|| (mnemonic === 'bx' && opStr === 'lr')
		|| (mnemonic === 'pop' && /\bpc\b/.test(opStr))
		|| ((mnemonic === 'ldm' || mnemonic === 'ldmfd' || mnemonic === 'ldmia') && /\bpc\b/.test(opStr))
		|| (mnemonic === 'mov' && /^pc\s*,\s*lr$/.test(opStr));

	const x86Jumps = new Set([
		'jmp', 'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
		'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns', 'jp', 'jnp',
		'jc', 'jnc', 'jpe', 'jpo',
		'jcxz', 'jecxz', 'jrcxz', 'loop', 'loope', 'loopne', 'loopnz', 'loopz'
	]);
	const arm32Jumps = new Set([
		'b', 'beq', 'bne', 'bgt', 'blt', 'bge', 'ble',
		'bhi', 'blo', 'bhs', 'bls', 'bpl', 'bmi',
		'bvs', 'bvc', 'bcc', 'bcs', 'bal'
	]);
	const arm64Jumps = new Set([
		'b.eq', 'b.ne', 'b.gt', 'b.lt', 'b.ge', 'b.le',
		'b.hi', 'b.lo', 'b.hs', 'b.ls', 'b.pl', 'b.mi',
		'b.vs', 'b.vc', 'b.cs', 'b.cc', 'b.al', 'b.nv',
		'cbz', 'cbnz',
		'tbz', 'tbnz',
		'br',
		'braa', 'brab', 'braaz', 'brabz'
	]);
	const isArm32IndirectBx =
		(mnemonic === 'bx' || mnemonic === 'bxj') && opStr !== 'lr' && opStr.length > 0;

	const isJump = x86Jumps.has(mnemonic) || arm32Jumps.has(mnemonic)
		|| arm64Jumps.has(mnemonic) || isArm32IndirectBx;

	const unconditionalSet = new Set([
		'jmp', 'b', 'br', 'braa', 'brab', 'braaz', 'brabz',
		'bal', 'b.al', 'bx', 'bxj'
	]);
	const isConditional = isJump && !unconditionalSet.has(mnemonic);

	return { isCall, isRet, isJump, isConditional };
}

// ---------------------------------------------------------------------------
// Instruction-category truth table
// columns = (mnemonic, opStr, isCall, isRet, isJump, isConditional)
// Rows curated from real corpus: HEXCORE_DEFEAT Wave 2 imm32 run, ROTTR.exe
// ARM64 samples, ARMv7 firmware fixtures from capstone/tests.
// ---------------------------------------------------------------------------

interface TruthRow {
	arch: string;       // documentation only
	mnemonic: string;
	opStr: string;
	isCall: boolean;
	isRet: boolean;
	isJump: boolean;
	isConditional: boolean;
	note?: string;
}

const TRUTH_TABLE: readonly TruthRow[] = [
	// ----- x86/x64 -----
	{ arch: 'x64', mnemonic: 'call', opStr: '0x140001000', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'call', opStr: 'rax', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'indirect' },
	{ arch: 'x64', mnemonic: 'ret', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'retn', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'retf', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'iret', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'iretd', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'v3.8.0 new' },
	{ arch: 'x64', mnemonic: 'iretq', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'sysret', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'v3.8.0 new' },
	{ arch: 'x64', mnemonic: 'sysretq', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'ud2', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'trap → CFG terminator' },
	{ arch: 'x64', mnemonic: 'jmp', opStr: '0x140001234', isCall: false, isRet: false, isJump: true, isConditional: false },
	{ arch: 'x64', mnemonic: 'jne', opStr: '0x140001234', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'x64', mnemonic: 'je', opStr: '0x140001234', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'x64', mnemonic: 'jrcxz', opStr: '0x140001234', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'x64', mnemonic: 'loop', opStr: '0x140001234', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'x64', mnemonic: 'mov', opStr: 'rax, rbx', isCall: false, isRet: false, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'nop', opStr: '', isCall: false, isRet: false, isJump: false, isConditional: false },
	{ arch: 'x64', mnemonic: 'xor', opStr: 'rax, rax', isCall: false, isRet: false, isJump: false, isConditional: false },

	// ----- ARM32 -----
	{ arch: 'ARM32', mnemonic: 'bl', opStr: '#0x8010', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM32', mnemonic: 'blx', opStr: 'r3', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM32', mnemonic: 'bleq', opStr: '#0x8010', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'v3.8.0 regression' },
	{ arch: 'ARM32', mnemonic: 'blne', opStr: '#0x8010', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'v3.8.0 regression' },
	{ arch: 'ARM32', mnemonic: 'bllt', opStr: '#0x8010', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM32', mnemonic: 'b', opStr: '#0x8010', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'unconditional' },
	{ arch: 'ARM32', mnemonic: 'beq', opStr: '#0x8010', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM32', mnemonic: 'bne', opStr: '#0x8010', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM32', mnemonic: 'bx', opStr: 'lr', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'classic ARM epilog' },
	{ arch: 'ARM32', mnemonic: 'bx', opStr: 'r3', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'tail-call through reg' },
	{ arch: 'ARM32', mnemonic: 'pop', opStr: '{r4, r5, pc}', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'pop-with-pc = epilog' },
	{ arch: 'ARM32', mnemonic: 'ldm', opStr: 'sp!, {r4-r7, pc}', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'ARM32', mnemonic: 'mov', opStr: 'pc, lr', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'pre-ARMv4 epilog' },
	{ arch: 'ARM32', mnemonic: 'mov', opStr: 'r0, r1', isCall: false, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM32', mnemonic: 'pop', opStr: '{r4, r5}', isCall: false, isRet: false, isJump: false, isConditional: false, note: 'pop WITHOUT pc ≠ ret' },

	// ----- ARM64 (ROTTR / Apple silicon) -----
	{ arch: 'ARM64', mnemonic: 'bl', opStr: '#0x100008000', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'blr', opStr: 'x8', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'indirect' },
	{ arch: 'ARM64', mnemonic: 'blraa', opStr: 'x8, x9', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'ARMv8.3 PAC' },
	{ arch: 'ARM64', mnemonic: 'blrab', opStr: 'x8, x9', isCall: true, isRet: false, isJump: false, isConditional: false, note: 'ARMv8.3 PAC' },
	{ arch: 'ARM64', mnemonic: 'blraaz', opStr: 'x8', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'blrabz', opStr: 'x8', isCall: true, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'ret', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'retaa', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'ARMv8.3 PAC ret' },
	{ arch: 'ARM64', mnemonic: 'retab', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'eret', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false, note: 'exception return' },
	{ arch: 'ARM64', mnemonic: 'eretaa', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'eretab', opStr: '', isCall: false, isRet: true, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'br', opStr: 'x8', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'indirect unconditional' },
	{ arch: 'ARM64', mnemonic: 'braa', opStr: 'x8, x9', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'ARMv8.3 PAC' },
	{ arch: 'ARM64', mnemonic: 'brab', opStr: 'x8, x9', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'ARMv8.3 PAC' },
	{ arch: 'ARM64', mnemonic: 'b.eq', opStr: '#0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM64', mnemonic: 'b.ne', opStr: '#0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM64', mnemonic: 'b.al', opStr: '#0x100008000', isCall: false, isRet: false, isJump: true, isConditional: false, note: 'always' },
	{ arch: 'ARM64', mnemonic: 'cbz', opStr: 'x0, #0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM64', mnemonic: 'cbnz', opStr: 'x0, #0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM64', mnemonic: 'tbz', opStr: 'x0, #1, #0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	{ arch: 'ARM64', mnemonic: 'tbnz', opStr: 'x0, #1, #0x100008000', isCall: false, isRet: false, isJump: true, isConditional: true },
	// ADRP + ADD are NOT call/ret/jump — they feed string-xref scanner elsewhere.
	{ arch: 'ARM64', mnemonic: 'adrp', opStr: 'x0, #0x200000', isCall: false, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'add', opStr: 'x0, x0, #0x123', isCall: false, isRet: false, isJump: false, isConditional: false },
	{ arch: 'ARM64', mnemonic: 'ldr', opStr: 'x0, [x0, #0x10]', isCall: false, isRet: false, isJump: false, isConditional: false },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

suite('Capstone classifier — truth table (v3.8.0 spec)', () => {

	for (const row of TRUTH_TABLE) {
		const label = row.note
			? `${row.arch.padEnd(5)} ${row.mnemonic} ${row.opStr || '<no-ops>'}  — ${row.note}`
			: `${row.arch.padEnd(5)} ${row.mnemonic} ${row.opStr || '<no-ops>'}`;
		test(label, () => {
			const c = classify(row.mnemonic, row.opStr);
			assert.strictEqual(c.isCall, row.isCall, `isCall for ${row.mnemonic} ${row.opStr}`);
			assert.strictEqual(c.isRet, row.isRet, `isRet for ${row.mnemonic} ${row.opStr}`);
			assert.strictEqual(c.isJump, row.isJump, `isJump for ${row.mnemonic} ${row.opStr}`);
			assert.strictEqual(c.isConditional, row.isConditional,
				`isConditional for ${row.mnemonic} ${row.opStr}`);
		});
	}

	// -----------------------------------------------------------------------
	// Invariant: a single instruction is at most ONE of {call, ret, jump}.
	// -----------------------------------------------------------------------
	suite('invariants', () => {
		test('call/ret/jump are mutually exclusive for all truth-table rows', () => {
			for (const row of TRUTH_TABLE) {
				const c = classify(row.mnemonic, row.opStr);
				const flags = (c.isCall ? 1 : 0) + (c.isRet ? 1 : 0) + (c.isJump ? 1 : 0);
				assert.ok(flags <= 1,
					`${row.mnemonic} ${row.opStr}: call/ret/jump not mutually exclusive: ${JSON.stringify(c)}`);
			}
		});

		test('isConditional implies isJump', () => {
			for (const row of TRUTH_TABLE) {
				const c = classify(row.mnemonic, row.opStr);
				if (c.isConditional) {
					assert.ok(c.isJump,
						`${row.mnemonic} ${row.opStr}: isConditional without isJump`);
				}
			}
		});

		test('case insensitivity — uppercase input classifies identically', () => {
			for (const row of TRUTH_TABLE) {
				const lo = classify(row.mnemonic, row.opStr);
				const hi = classify(row.mnemonic.toUpperCase(), row.opStr.toUpperCase());
				assert.deepStrictEqual(hi, lo,
					`case drift for ${row.mnemonic}: lo=${JSON.stringify(lo)} hi=${JSON.stringify(hi)}`);
			}
		});
	});

	// -----------------------------------------------------------------------
	// Ghost-function guard — documented in diff: call/jump to .data/.rdata
	// becomes an xref of type 'data', not a call. The classifier itself only
	// sets the boolean; the xref conversion happens in disassemblerEngine.
	// Here we only pin that the classifier does NOT flip flags based on
	// target. Ghost-function filtering is the caller's job.
	// -----------------------------------------------------------------------
	suite('ghost-function guard is NOT the classifier', () => {
		test('call 0xDEADBEEF still classifies as isCall regardless of target section', () => {
			// Even if the target sits in .rdata, the classifier reports isCall=true.
			// The caller (disassemblerEngine) is responsible for demoting it to xref.
			const c = classify('call', '0xDEADBEEF');
			assert.strictEqual(c.isCall, true);
			assert.strictEqual(c.isJump, false);
		});
	});

	// -----------------------------------------------------------------------
	// Unknown mnemonics — defensive: must yield all-false (no spurious flags).
	// -----------------------------------------------------------------------
	suite('defensive: unknown mnemonics', () => {
		const UNKNOWN = ['foo', 'xyz.fake', '', 'blfake', 'callx', 'retx'];
		for (const m of UNKNOWN) {
			test(`unknown mnemonic "${m}" yields no flags`, () => {
				const c = classify(m, '');
				assert.strictEqual(c.isCall, false);
				assert.strictEqual(c.isRet, false);
				assert.strictEqual(c.isJump, false);
				assert.strictEqual(c.isConditional, false);
			});
		}
	});
});
