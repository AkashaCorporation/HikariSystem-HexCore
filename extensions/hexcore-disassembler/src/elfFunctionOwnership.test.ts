/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

interface FakeInstruction {
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

function instruction(address: number, options: Partial<FakeInstruction> = {}): FakeInstruction {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic: 'nop',
		opStr: '',
		size: 1,
		isCall: false,
		isJump: false,
		isRet: false,
		isConditional: false,
		...options,
	};
}

function fakeFunction(address: number, endAddress: number, instructions: FakeInstruction[], callers: number[] = []) {
	return {
		address,
		name: `sub_${address.toString(16).toUpperCase()}`,
		size: endAddress - address,
		endAddress,
		instructions,
		callers,
		callees: [] as number[],
	};
}

suite('ELF x64 function ownership', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module');
		const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) {
			return request === 'vscode' ? '__elf_ownership__' : resolve.call(this, request, ...args);
		};
		require.cache.__elf_ownership__ = {
			id: '__elf_ownership__', filename: '__elf_ownership__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } },
		} as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});

	test('clamps overlapping stripped-ELF owners at strong starts', () => {
		const engine = new Engine() as any;
		engine.architecture = 'x64';
		engine.fileInfo = { format: 'ELF64', isRelocatable: false, entryPoint: 0x2000 };
		engine.peDataDirectories = { pdata: [] };
		const first = fakeFunction(0x1000, 0x1800, [instruction(0x1000), instruction(0x1007), instruction(0x1008)]);
		const second = fakeFunction(0x1008, 0x1800, [instruction(0x1008), instruction(0x100f), instruction(0x1010)]);
		const third = fakeFunction(0x1010, 0x1020, [instruction(0x1010), instruction(0x101f)]);
		engine.functions = new Map([[first.address, first], [second.address, second], [third.address, third]]);
		for (const fn of [first, second, third]) {
			engine.functionSeeds.record(fn.address, { kind: 'direct-call', sourceAddress: 0x3000 });
		}

		engine.reconcileFunctionsWithStrongSeeds();
		assert.strictEqual(first.endAddress, 0x1008);
		assert.strictEqual(first.size, 8);
		assert.ok(first.instructions.every((entry: FakeInstruction) => entry.address < 0x1008));
		assert.strictEqual(second.endAddress, 0x1010);
		assert.strictEqual(second.size, 8);
		assert.ok(second.instructions.every((entry: FakeInstruction) => entry.address < 0x1010));
		assert.strictEqual(third.endAddress, 0x1020);
	});

	test('follows recovered jump-table targets as internal blocks', () => {
		const engine = new Engine() as any;
		engine.architecture = 'x64';
		const instructions = [
			instruction(0x2000),
			instruction(0x2001, { mnemonic: 'jmp', opStr: 'rcx', isJump: true }),
			instruction(0x2002),
			instruction(0x2010),
			instruction(0x2011, { mnemonic: 'ret', isRet: true }),
			instruction(0x2020),
			instruction(0x2021, { mnemonic: 'ret', isRet: true }),
		];
		const result = engine.selectReachableFunctionInstructions(
			instructions,
			0x2000,
			new Map([[0x2001, [0x2010, 0x2020]]]),
		);
		assert.deepStrictEqual(result.instructions.map((entry: FakeInstruction) => entry.address),
			[0x2000, 0x2001, 0x2010, 0x2011, 0x2020, 0x2021]);
		assert.deepStrictEqual([...result.internalBlockTargets].sort((a, b) => a - b), [0x2010, 0x2020]);
	});

	test('recognizes every x86 PLT-family section and excludes normal text', () => {
		const engine = new Engine() as any;
		engine.architecture = 'x64';
		engine.sections = [
			{ name: '.plt', virtualAddress: 0x1000, virtualSize: 0x20 },
			{ name: '.plt.got', virtualAddress: 0x2000, virtualSize: 0x20 },
			{ name: '.plt.sec', virtualAddress: 0x3000, virtualSize: 0x20 },
			{ name: '.text', virtualAddress: 0x4000, virtualSize: 0x100 },
		];
		assert.strictEqual(engine.isPltFamilyAddress(0x1008), true);
		assert.strictEqual(engine.isPltFamilyAddress(0x2008), true);
		assert.strictEqual(engine.isPltFamilyAddress(0x3008), true);
		assert.strictEqual(engine.isPltFamilyAddress(0x4008), false);
	});

	test('drops a nested weak prologue even when an internal edge populated callers', () => {
		const engine = new Engine() as any;
		engine.architecture = 'x64';
		engine.fileInfo = { format: 'ELF64', isRelocatable: false, entryPoint: 0x1000 };
		engine.peDataDirectories = { pdata: [] };
		const owner = fakeFunction(0x1000, 0x1100, [
			instruction(0x1000),
			instruction(0x1040, { mnemonic: 'jmp', opStr: '0x1080', isJump: true, targetAddress: 0x1080 }),
		]);
		const weak = fakeFunction(0x1080, 0x1100, [instruction(0x1080)], [0x1040]);
		engine.functions = new Map([[owner.address, owner], [weak.address, weak]]);
		engine.functionSeeds.record(owner.address, { kind: 'direct-call', sourceAddress: 0x2000 });
		engine.functionSeeds.record(weak.address, { kind: 'prologue' });

		engine.dropInteriorGhostFunctions();
		assert.strictEqual(engine.functions.has(owner.address), true);
		assert.strictEqual(engine.functions.has(weak.address), false);
	});

	test('keeps a nested entry with independent direct-call evidence', () => {
		const engine = new Engine() as any;
		engine.architecture = 'x64';
		engine.fileInfo = { format: 'ELF64', isRelocatable: false, entryPoint: 0x1000 };
		engine.peDataDirectories = { pdata: [] };
		const owner = fakeFunction(0x1000, 0x1100, [instruction(0x1000)]);
		const nested = fakeFunction(0x1080, 0x1100, [instruction(0x1080)], [0x2004]);
		engine.functions = new Map([[owner.address, owner], [nested.address, nested]]);
		engine.functionSeeds.record(owner.address, { kind: 'direct-call', sourceAddress: 0x2000 });
		engine.functionSeeds.record(nested.address, { kind: 'direct-call', sourceAddress: 0x2004 });

		engine.dropInteriorGhostFunctions();
		assert.strictEqual(engine.functions.has(nested.address), true);
	});
});
