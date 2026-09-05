/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import type { DisassemblerEngine as DisassemblerEngineType, ELFSymbolEntry } from './disassemblerEngine';

function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (
		request: string,
		parent: unknown,
		isMain: boolean,
		options: unknown
	) {
		if (request === 'vscode') {
			return '__vscode_mock_elf_bounds__';
		}
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_elf_bounds__'] = {
		id: '__vscode_mock_elf_bounds__',
		filename: '__vscode_mock_elf_bounds__',
		loaded: true,
		exports: {
			workspace: {
				getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			},
		},
	} as unknown as NodeModule;
}

installVscodeMock();
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { DisassemblerEngine } = require('./disassemblerEngine') as {
	DisassemblerEngine: typeof DisassemblerEngineType;
};

interface MutableEngine {
	fileInfo: { isRelocatable: boolean; characteristics: string[] };
	elfAnalysis: {
		programHeaders: unknown[];
		symbols: ELFSymbolEntry[];
		relocations: unknown[];
		dynamicEntries: unknown[];
		neededLibraries: string[];
		elfType: string;
		elfTypeValue: number;
	};
	functions: Map<number, {
		address: number;
		name: string;
		size: number;
		endAddress: number;
		instructions: unknown[];
		callers: number[];
		callees: number[];
	}>;
	reconcileFunctionsWithElfSymbols(): void;
}

interface TestInstruction {
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

function instruction(
	address: number,
	options: Partial<TestInstruction> = {}
): TestInstruction {
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

function symbol(
	name: string,
	value: number,
	size: number,
	sectionName: string = '.text'
): ELFSymbolEntry {
	return {
		name,
		value,
		size,
		binding: 'GLOBAL',
		type: 'FUNC',
		visibility: 'DEFAULT',
		sectionIndex: 15,
		sectionName,
		isImport: false,
		isExport: true,
	};
}

function buildEngine(symbols: ELFSymbolEntry[]): {
	engine: DisassemblerEngineType;
	mutable: MutableEngine;
} {
	const engine = new DisassemblerEngine();
	const mutable = engine as unknown as MutableEngine;
	mutable.fileInfo = { isRelocatable: true, characteristics: ['ELF', 'ET_REL'] };
	mutable.elfAnalysis = {
		programHeaders: [],
		symbols,
		relocations: [],
		dynamicEntries: [],
		neededLibraries: [],
		elfType: 'ET_REL',
		elfTypeValue: 1,
	};
	mutable.functions = new Map([[
		0x3A20,
		{
			address: 0x3A20,
			name: 'kbase_jit_allocate',
			size: 997,
			endAddress: 0x3A20 + 997,
			instructions: [{ address: 0x3A20, mnemonic: 'endbr64' }],
			callers: [],
			callees: [],
		},
	]]);
	return { engine, mutable };
}

suite('ELF symbol function-boundary reconciliation', () => {
	test('STT_FUNC st_size replaces an interior-ud2 truncated inferred extent', () => {
		const { engine, mutable } = buildEngine([
			symbol('kbase_jit_allocate', 0x3A20, 2121),
		]);
		const originalInstructions = mutable.functions.get(0x3A20)!.instructions;

		mutable.reconcileFunctionsWithElfSymbols();

		const fn = engine.getFunctionAt(0x3A20)!;
		assert.strictEqual(fn.size, 2121);
		assert.strictEqual(fn.endAddress, 0x3A20 + 2121);
		assert.strictEqual(fn.instructions, originalInstructions, 'decoded prefix is preserved');
		assert.strictEqual(engine.getSymbolSizeAt(0x3A20), 2121);
		assert.strictEqual(engine.getRecommendedLiftSize(0x3A20, 4096), 2137);
	});

	test('ET_REL section-address collision prefers the matching function name', () => {
		const { engine, mutable } = buildEngine([
			symbol('other_init_function', 0x3A20, 4096, '.init.text'),
			symbol('kbase_jit_allocate', 0x3A20, 2121, '.text'),
		]);

		mutable.reconcileFunctionsWithElfSymbols();

		assert.strictEqual(engine.getFunctionAt(0x3A20)!.size, 2121);
		assert.strictEqual(engine.getSymbolSizeAt(0x3A20), 2121);
	});

	test('stripped/unsized ELF keeps the inferred boundary', () => {
		const { engine, mutable } = buildEngine([]);

		mutable.reconcileFunctionsWithElfSymbols();

		assert.strictEqual(engine.getFunctionAt(0x3A20)!.size, 997);
		assert.strictEqual(engine.getSymbolSizeAt(0x3A20), 997);
	});

	test('shrinks a wider discovery and discards tail call-graph state', () => {
		const { engine, mutable } = buildEngine([
			symbol('kbase_jit_allocate', 0x3A20, 800),
		]);
		const source = mutable.functions.get(0x3A20)!;
		source.instructions = [
			instruction(0x3A20),
			instruction(0x3D50, {
				mnemonic: 'call',
				isCall: true,
				targetAddress: 0x5000,
			}),
		];
		source.callees = [0x5000];
		mutable.functions.set(0x5000, {
			address: 0x5000,
			name: 'tail_target',
			size: 16,
			endAddress: 0x5010,
			instructions: [instruction(0x5000)],
			callers: [0x3D50],
			callees: [],
		});

		mutable.reconcileFunctionsWithElfSymbols();

		const reconciled = engine.getFunctionAt(0x3A20)!;
		assert.strictEqual(reconciled.size, 800);
		assert.strictEqual(reconciled.endAddress, 0x3A20 + 800);
		assert.deepStrictEqual(
			reconciled.instructions.map(inst => inst.address),
			[0x3A20]
		);
		assert.deepStrictEqual(reconciled.callees, []);
		assert.deepStrictEqual(engine.getFunctionAt(0x5000)!.callers, []);
		assert.strictEqual(engine.getSymbolSizeAt(0x3A20), 800);
	});

	test('keeps adjacent ftrace prefix and body at their exact symbol extents', () => {
		const { engine, mutable } = buildEngine([
			symbol('__pfx_kbase_regmap_term', 0x5A700, 16),
			symbol('kbase_regmap_term', 0x5A710, 84),
		]);
		mutable.functions.clear();
		mutable.functions.set(0x5A700, {
			address: 0x5A700,
			name: '__pfx_kbase_regmap_term',
			size: 7451,
			endAddress: 0x5A700 + 7451,
			instructions: [
				instruction(0x5A700),
				instruction(0x5A710),
			],
			callers: [],
			callees: [],
		});
		mutable.functions.set(0x5A710, {
			address: 0x5A710,
			name: 'kbase_regmap_term',
			size: 7543,
			endAddress: 0x5A710 + 7543,
			instructions: [
				instruction(0x5A710),
				instruction(0x5A764),
			],
			callers: [],
			callees: [],
		});

		mutable.reconcileFunctionsWithElfSymbols();

		assert.strictEqual(engine.getFunctionAt(0x5A700)!.size, 16);
		assert.strictEqual(engine.getFunctionAt(0x5A700)!.endAddress, 0x5A710);
		assert.deepStrictEqual(
			engine.getFunctionAt(0x5A700)!.instructions.map(inst => inst.address),
			[0x5A700]
		);
		assert.strictEqual(engine.getFunctionAt(0x5A710)!.size, 84);
		assert.strictEqual(engine.getFunctionAt(0x5A710)!.endAddress, 0x5A764);
		assert.deepStrictEqual(
			engine.getFunctionAt(0x5A710)!.instructions.map(inst => inst.address),
			[0x5A710]
		);
	});

	test('ET_REL canonicalizes the numeric table to .text and drops interior discoveries', () => {
		const { engine, mutable } = buildEngine([
			symbol('wrong_section_alias', 0x100, 0x90, '.init.text'),
			symbol('text_owner', 0x100, 0x40, '.text'),
			symbol('text_next', 0x140, 0x20, '.text'),
			symbol('text_missing', 0x180, 0x10, '.text'),
		]);
		mutable.functions.clear();
		mutable.functions.set(0x80, {
			address: 0x80, name: 'sub_80', size: 0x90, endAddress: 0x110,
			instructions: [instruction(0x80)], callers: [], callees: []
		});
		mutable.functions.set(0x100, {
			address: 0x100, name: 'wrong_section_alias', size: 0x90, endAddress: 0x190,
			instructions: [instruction(0x100), instruction(0x150)], callers: [], callees: []
		});
		mutable.functions.set(0x110, {
			address: 0x110, name: 'sub_110', size: 0x30, endAddress: 0x140,
			instructions: [instruction(0x110)], callers: [], callees: []
		});
		mutable.functions.set(0x140, {
			address: 0x140, name: 'text_next', size: 0x20, endAddress: 0x160,
			instructions: [instruction(0x140)], callers: [], callees: []
		});

		mutable.reconcileFunctionsWithElfSymbols();

		assert.strictEqual(engine.getFunctionAt(0x80), undefined, 'container spanning a real begin is removed');
		assert.strictEqual(engine.getFunctionAt(0x110), undefined, 'interior prologue discovery is removed');
		assert.strictEqual(engine.getFunctionAt(0x100)?.name, 'text_owner');
		assert.strictEqual(engine.getFunctionAt(0x100)?.endAddress, 0x140);
		assert.deepStrictEqual(engine.getFunctionAt(0x100)?.instructions.map(inst => inst.address), [0x100]);
		assert.strictEqual(engine.getFunctionAt(0x180)?.name, 'text_missing', 'missing .text symbol becomes a lazy stub');
		assert.strictEqual(engine.getFunctionAt(0x180)?.endAddress, 0x190);
	});
});
