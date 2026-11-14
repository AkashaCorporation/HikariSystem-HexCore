/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_g04_authoritative_types__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_g04_authoritative_types__ = {
	id: '__vscode_mock_g04_authoritative_types__', filename: '__vscode_mock_g04_authoritative_types__', loaded: true,
	exports: {
		workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), onDidChangeConfiguration: () => ({ dispose() {} }), workspaceFolders: undefined },
		commands: { executeCommand: async () => undefined, getCommands: async () => [] }, extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) }, window: {},
	},
} as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { scopeStructInfoForFunctions } = require('./elfBtfLoader') as typeof import('./elfBtfLoader');
const { runDebugTypeIngest } = require('./typeManagerCommands') as typeof import('./typeManagerCommands');

suite('G04 authoritative debug corpus', function () {
	this.timeout(600_000);

	test('ingests a real kernel DWARF prototype with target-bound ownership', async function () {
		const target = process.env.HEXCORE_G04_DWARF_TARGET;
		if (!target) { this.skip(); return; }
		const functionName = process.env.HEXCORE_G04_DWARF_FUNCTION ?? 'kbase_mem_alloc';
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(path.resolve(target)), true);
			await engine.ensureDebugInfoLoaded();
			const full = engine.getELFAnalysis()?.dwarfStructInfo;
			assert.ok(full, 'DWARF struct/signature payload was not loaded');
			const scoped = scopeStructInfoForFunctions(full!, [functionName]);
			assert.ok(scoped.functions[functionName], `DWARF has no signature for ${functionName}`);
			assert.strictEqual(scoped.boundaries?.length, 1, 'scoped DWARF boundary is not exact');
			let owner = engine.getFunctions().find(fn => fn.name === functionName);
			if (!owner) {
				await engine.analyzeAll();
				owner = engine.getFunctions().find(fn => fn.name === functionName);
			}
			assert.ok(owner, `function table has no exact owner for ${functionName}`);
			if (owner!.instructions.length === 0) {
				const materialized = await engine.materializeFunctionForAnalysis(owner!.address);
				assert.ok(['committed', 'already-current'].includes(materialized.status), JSON.stringify(materialized));
			}
			const result = await runDebugTypeIngest(engine, scoped, {
				provider: 'dwarf', unitIdentity: 'g04-kbase-dwarf', generation: engine.getAnalysisGeneration(),
			});
			assert.strictEqual(result.functionSignaturesApplied, 1, JSON.stringify({
				signature: scoped.functions[functionName], diagnostics: result.diagnostics,
			}));
			assert.strictEqual(result.functionSignaturesDeferred, 0, JSON.stringify(result.diagnostics));
			const prototype = engine.getSessionStore()!.getSemanticStore().getPrototype(
				`function:0x${owner!.address.toString(16)}`,
			);
			assert.strictEqual(prototype?.evidence.source, 'debug-info');
			assert.strictEqual(prototype?.evidence.producer, 'dwarf:g04-kbase-dwarf');
			assert.ok((prototype?.parameters.length ?? 0) > 0);
		} finally {
			engine.dispose();
		}
	});

	test('a stripped ELF cannot fabricate debug authority', async function () {
		const target = process.env.HEXCORE_G04_STRIPPED_TARGET;
		if (!target) { this.skip(); return; }
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(path.resolve(target)), true);
			await engine.ensureDebugInfoLoaded();
			const elf = engine.getELFAnalysis();
			assert.strictEqual(elf?.btfData, undefined);
			assert.strictEqual(elf?.dwarfStructInfo, undefined);
			const beforeFunctions = engine.getFunctions().length;
			const beforePrototypes = engine.getSessionStore()!.getSemanticStore().listPrototypes().length;
			await assert.rejects(() => runDebugTypeIngest(engine), /No BTF\/DWARF debug type payload/);
			assert.strictEqual(engine.getFunctions().length, beforeFunctions);
			assert.strictEqual(engine.getSessionStore()!.getSemanticStore().listPrototypes().length, beforePrototypes);
		} finally {
			engine.dispose();
		}
	});

	test('ingests a kernel-target BTF prototype with ABI widths', async function () {
		const target = process.env.HEXCORE_G04_BTF_TARGET;
		if (!target) { this.skip(); return; }
		const functionName = 'kbase_mem_alloc';
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(path.resolve(target)), true);
			await engine.ensureDebugInfoLoaded();
			const elf = engine.getELFAnalysis();
			assert.ok(elf?.btfData, 'BTF section was not loaded');
			assert.strictEqual(elf?.dwarfStructInfo, undefined);
			const signature = require('./elfBtfLoader').exportStructInfoJson(elf!.btfData!).functions[functionName] as import('./elfBtfLoader').FunctionSignatureInfo;
			assert.strictEqual(signature.params.length, 7);
			assert.strictEqual(signature.params[1].abiSizeBits, 64);
			assert.strictEqual(signature.params[6].abiSizeBits, 32);
			let owner = engine.getFunctions().find(fn => fn.name === functionName);
			if (!owner) {
				await engine.analyzeAll();
				owner = engine.getFunctions().find(fn => fn.name === functionName);
			}
			assert.ok(owner, `function table has no exact owner for ${functionName}`);
			if (owner!.instructions.length === 0) {
				const materialized = await engine.materializeFunctionForAnalysis(owner!.address);
				assert.ok(['committed', 'already-current'].includes(materialized.status), JSON.stringify(materialized));
			}
			const result = await runDebugTypeIngest(engine, undefined, {
				provider: 'btf', unitIdentity: 'g04-kbase-btf', generation: engine.getAnalysisGeneration(),
			});
			assert.strictEqual(result.functionSignaturesApplied, 1, JSON.stringify(result.diagnostics));
			assert.strictEqual(result.functionSignaturesDeferred, 0, JSON.stringify(result.diagnostics));
			const prototype = engine.getSessionStore()!.getSemanticStore().getPrototype(
				`function:0x${owner!.address.toString(16)}`,
			);
			assert.strictEqual(prototype?.evidence.producer, 'btf:g04-kbase-btf');
			assert.strictEqual(prototype?.parameters[1].abiSizeBits, 64);
			assert.strictEqual(prototype?.parameters[6].abiSizeBits, 32);
		} finally {
			engine.dispose();
		}
	});
});
