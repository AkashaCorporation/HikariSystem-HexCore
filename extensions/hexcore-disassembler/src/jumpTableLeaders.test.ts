/*---------------------------------------------------------------------------------------------
 * Issue #51 — jump-table case-target recovery unit tests
 *---------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	recoverJumpTableTargets,
	collectJumpTableLeaders,
	type DecodedInsnLike,
} from './jumpTableLeaders';

/**
 * Synthesize a minimal PIC jump table:
 *   base = 0x401000
 *   entries: +0x100, +0x200, +0x300, +0x400  → targets 0x401100..0x401400
 */
function makePicTable(base: number, offs: number[]): Buffer {
	const buf = Buffer.alloc(offs.length * 4);
	for (let i = 0; i < offs.length; i++) {
		buf.writeInt32LE(offs[i], i * 4);
	}
	// stash base for the mock reader
	(buf as any).__base = base;
	return buf;
}

suite('jumpTableLeaders (#51)', () => {
	test('recovers PIC jump-table targets from cmp+lea+jmp reg pattern', () => {
		const tableBase = 0x404000;
		const offs = [0x100, 0x200, 0x300, 0x50];
		const table = makePicTable(tableBase, offs);

		const insns: DecodedInsnLike[] = [
			{ address: 0x401000, size: 3, mnemonic: 'cmp', opStr: 'eax, 3' },
			{ address: 0x401003, size: 2, mnemonic: 'ja', opStr: '0x401050', isJump: true, isConditional: true, targetAddress: 0x401050 },
			{ address: 0x401005, size: 7, mnemonic: 'lea', opStr: 'rdx, [rip + 0x2ff4]' }, // 0x401005+7+0x2ff4 = 0x404000
			{ address: 0x40100c, size: 4, mnemonic: 'movsxd', opStr: 'rax, dword ptr [rdx + rcx*4]' },
			{ address: 0x401010, size: 3, mnemonic: 'add', opStr: 'rax, rdx' },
			{ address: 0x401013, size: 2, mnemonic: 'jmp', opStr: 'rax', isJump: true, isConditional: false },
		];
		// Fix LEA so tableBase is exact: address+size+rip = tableBase
		// 0x401005 + 7 + rip = 0x404000 → rip = 0x404000 - 0x40100c = 0x2ff4 ✓

		const readAbs = (va: number, size: number): Buffer | undefined => {
			if (va === tableBase) { return table.subarray(0, size); }
			return undefined;
		};

		const hits = recoverJumpTableTargets(insns, readAbs);
		assert.strictEqual(hits.length, 1, 'one dispatch');
		assert.strictEqual(hits[0].tableAddress, tableBase);
		assert.strictEqual(hits[0].entryCount, 4); // cmp 3 → 4 entries
		const expected = offs.map(o => tableBase + o);
		assert.deepStrictEqual(hits[0].targets.sort((a, b) => a - b), expected.sort((a, b) => a - b));
	});

	test('collectJumpTableLeaders filters to lift range', () => {
		const hits = [{
			jmpAddress: 0x401013,
			tableAddress: 0x404000,
			targets: [0x401100, 0x401200, 0x500000], // last outside
			entryCount: 3,
		}];
		const leaders = collectJumpTableLeaders(hits, { lo: 0x401000, hi: 0x402000 });
		assert.deepStrictEqual(leaders, [0x401100, 0x401200]);
	});

	test('ignores direct jmp with fixed target', () => {
		const insns: DecodedInsnLike[] = [
			{ address: 0x401000, size: 5, mnemonic: 'jmp', opStr: '0x401100', isJump: true, isConditional: false, targetAddress: 0x401100 },
		];
		const hits = recoverJumpTableTargets(insns, () => undefined);
		assert.strictEqual(hits.length, 0);
	});

	test('ignores jmp mem [rip] (not register dispatch)', () => {
		const insns: DecodedInsnLike[] = [
			{ address: 0x401000, size: 6, mnemonic: 'jmp', opStr: 'qword ptr [rip + 0x2000]', isJump: true, isConditional: false },
		];
		const hits = recoverJumpTableTargets(insns, () => undefined);
		assert.strictEqual(hits.length, 0);
	});

	test('recovers CET notrack jmp with table base in r12 (threadweaver pattern)', () => {
		// Real pattern from HTB threadweaver main menu:
		//   cmp rax, 7 / ja default / movsxd rax, [r12+rax*4] / add rax, r12 / notrack jmp rax
		//   (r12 loaded earlier via lea r12, [rip+TABLE])
		const tableBase = 0x555555558000;
		const offs = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
		const table = Buffer.alloc(offs.length * 4);
		for (let i = 0; i < offs.length; i++) { table.writeInt32LE(offs[i], i * 4); }

		const leaAddr = 0x555555554100;
		const leaSize = 7;
		const rip = tableBase - (leaAddr + leaSize);
		const insns: DecodedInsnLike[] = [
			{
				address: leaAddr, size: leaSize, mnemonic: 'lea',
				opStr: `r12, [rip + 0x${rip.toString(16)}]`,
			},
			// ... other code ...
			{ address: 0x555555554200, size: 4, mnemonic: 'cmp', opStr: 'rax, 7' },
			{ address: 0x555555554204, size: 2, mnemonic: 'ja', opStr: '0x555555554300', isJump: true, isConditional: true, targetAddress: 0x555555554300 },
			{ address: 0x555555554206, size: 4, mnemonic: 'movsxd', opStr: 'rax, dword ptr [r12 + rax*4]' },
			{ address: 0x55555555420a, size: 3, mnemonic: 'add', opStr: 'rax, r12' },
			// Capstone: isJump=false on notrack jmp — must still detect
			{ address: 0x55555555420d, size: 3, mnemonic: 'notrack jmp', opStr: 'rax', isJump: false, isConditional: false },
		];

		const hits = recoverJumpTableTargets(insns, (va, sz) => {
			if (va === tableBase) { return table.subarray(0, Math.min(sz, table.length)); }
			return undefined;
		});
		assert.strictEqual(hits.length, 1);
		assert.strictEqual(hits[0].entryCount, 8);
		assert.strictEqual(hits[0].targets.length, 8);
		assert.ok(hits[0].targets.includes(tableBase + 0x10));
		assert.ok(hits[0].targets.includes(tableBase + 0x80));
	});

	test('does not truncate PIE VAs above 4 GiB (no >>> 0)', () => {
		const tableBase = 0x555555558000;
		const offs = [0x10, 0x20];
		const table = Buffer.alloc(8);
		table.writeInt32LE(0x10, 0);
		table.writeInt32LE(0x20, 4);
		// Full PIC pattern so pass1 (movsxd) + pass2 (lea baseReg) fire — bare
		// lea+jmp is not a real switch dispatch and is intentionally ignored.
		const leaAddr = 0x555555554000;
		const leaSize = 7;
		const rip = tableBase - (leaAddr + leaSize);
		const insns: DecodedInsnLike[] = [
			{
				address: leaAddr, size: leaSize, mnemonic: 'lea',
				opStr: `rdx, [rip + 0x${rip.toString(16)}]`,
			},
			{ address: leaAddr + leaSize, size: 3, mnemonic: 'cmp', opStr: 'eax, 1' },
			{
				address: leaAddr + leaSize + 3, size: 4, mnemonic: 'movsxd',
				opStr: 'rax, dword ptr [rdx + rcx*4]',
			},
			{ address: leaAddr + leaSize + 7, size: 3, mnemonic: 'add', opStr: 'rax, rdx' },
			{
				address: leaAddr + leaSize + 10, size: 2, mnemonic: 'jmp',
				opStr: 'rax', isJump: true, isConditional: false,
			},
		];

		const hits = recoverJumpTableTargets(insns, (va, sz) => {
			if (va === tableBase) { return table.subarray(0, sz); }
			return undefined;
		});
		assert.ok(hits.length >= 1, 'hit');
		for (const t of hits[0].targets) {
			assert.ok(t > 0x100000000, `target 0x${t.toString(16)} must stay >4GiB`);
		}
	});
});
