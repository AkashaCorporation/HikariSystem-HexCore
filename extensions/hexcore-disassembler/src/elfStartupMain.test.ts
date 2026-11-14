/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { recoverElfX64StartupMain, type ElfStartupInstruction } from './elfStartupMain';

function instruction(address: number, mnemonic: string, opStr: string, size: number, callTarget?: number): ElfStartupInstruction {
	return { address, mnemonic, opStr, size, isCall: callTarget !== undefined, targetAddress: callTarget };
}

suite('ELF x64 startup main recovery', () => {
	test('recovers the runbook-style immediate main argument', () => {
		const entry = 0x4018b0;
		const code = [
			instruction(entry, 'xor', 'ebp, ebp', 2),
			instruction(entry + 2, 'mov', 'r9, rdx', 3),
			instruction(entry + 5, 'pop', 'rsi', 1),
			instruction(entry + 6, 'mov', 'rdx, rsp', 3),
			instruction(entry + 9, 'and', 'rsp, 0xfffffffffffffff0', 4),
			instruction(entry + 13, 'push', 'rax', 1),
			instruction(entry + 14, 'push', 'rsp', 1),
			instruction(entry + 15, 'xor', 'r8d, r8d', 3),
			instruction(entry + 18, 'xor', 'ecx, ecx', 2),
			instruction(entry + 20, 'mov', 'rdi, 0x401670', 7),
			instruction(entry + 27, 'call', '0x404bb0', 6, 0x404bb0),
		];
		const result = recoverElfX64StartupMain(entry, code, address => address >= 0x401000 && address < 0x470000);
		assert.deepStrictEqual(result, {
			mainAddress: 0x401670,
			assignmentAddress: 0x4018c4,
			callAddress: 0x4018cb,
			callTarget: 0x404bb0,
			evidence: 'sysv-x64-libc-startup',
		});
	});

	test('supports a PIE RIP-relative main address', () => {
		const entry = 0x555555555000;
		const code = [
			instruction(entry, 'xor', 'ebp, ebp', 2),
			instruction(entry + 2, 'pop', 'rsi', 1),
			instruction(entry + 3, 'mov', 'rdx, rsp', 3),
			instruction(entry + 6, 'and', 'rsp, 0xfffffffffffffff0', 4),
			instruction(entry + 10, 'lea', 'rdi, [rip + 0x1f]', 7),
			instruction(entry + 17, 'call', '0x555555556000', 5, 0x555555556000),
		];
		const result = recoverElfX64StartupMain(entry, code, address => address >= entry && address < entry + 0x2000);
		assert.strictEqual(result?.mainAddress, entry + 10 + 7 + 0x1f);
	});

	test('rejects a generic move-to-rdi call without the startup preamble', () => {
		const entry = 0x401000;
		const code = [
			instruction(entry, 'push', 'rbp', 1),
			instruction(entry + 1, 'mov', 'rbp, rsp', 3),
			instruction(entry + 4, 'mov', 'rdi, 0x402000', 7),
			instruction(entry + 11, 'call', '0x403000', 5, 0x403000),
			instruction(entry + 16, 'ret', '', 1),
			instruction(entry + 17, 'nop', '', 1),
		];
		assert.strictEqual(recoverElfX64StartupMain(entry, code, () => true), undefined);
	});

	test('rejects a main candidate outside executable mappings', () => {
		const entry = 0x401000;
		const code = [
			instruction(entry, 'xor', 'ebp, ebp', 2),
			instruction(entry + 2, 'pop', 'rsi', 1),
			instruction(entry + 3, 'mov', 'rdx, rsp', 3),
			instruction(entry + 6, 'and', 'rsp, -16', 4),
			instruction(entry + 10, 'mov', 'rdi, 0x600000', 7),
			instruction(entry + 17, 'call', '0x402000', 5, 0x402000),
		];
		assert.strictEqual(recoverElfX64StartupMain(entry, code, address => address < 0x500000), undefined);
	});
});
