/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_semantic_providers__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache.__vscode_mock_semantic_providers__ = {
	id: '__vscode_mock_semantic_providers__', filename: '__vscode_mock_semantic_providers__', loaded: true,
	exports: {
		workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }), onDidChangeConfiguration: () => ({ dispose() {} }), workspaceFolders: undefined },
		commands: { executeCommand: async () => undefined, getCommands: async () => [] }, extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) }, window: {},
	},
} as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine') as typeof import('./disassemblerEngine');
const { importPdbSemantics } = require('./pdbSemanticImport') as typeof import('./pdbSemanticImport');
const { applyImportSignatureProvider } = require('./signatureProvider') as typeof import('./signatureProvider');

suite('R36 separated debug and signature providers', function () {
	this.timeout(180_000);

	test('declares PDB and signature commands exactly once in every automation surface', () => {
		const root = path.resolve(__dirname, '..');
		const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as { activationEvents: string[]; contributes: { commands: Array<{ command: string }> } };
		const extension = fs.readFileSync(path.join(root, 'src', 'extension.ts'), 'utf8');
		const runner = fs.readFileSync(path.join(root, 'src', 'automationPipelineRunner.ts'), 'utf8');
		for (const command of ['hexcore.pdb.importSemantics', 'hexcore.pdb.resolveSymbols', 'hexcore.signatures.apply']) {
			assert.strictEqual(manifest.activationEvents.filter(item => item === `onCommand:${command}`).length, 1);
			assert.strictEqual(manifest.contributes.commands.filter(item => item.command === command).length, 1);
			assert.strictEqual(extension.split(`registerCommand('${command}'`).length - 1, 1);
			assert.strictEqual(runner.split(`['${command}'`).length - 1, 2);
		}
	});

	test('imports validated PDB types/prototypes and keeps library signatures as separate evidence', async () => {
		const hql = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const build = path.join(hql, 'benchmarks', 'corpus', 'build', 'msvc-x64-O2-debug');
		const manifest = JSON.parse(fs.readFileSync(path.join(hql, 'benchmarks', 'corpus', 'build', 'build-manifest.json'), 'utf8').replace(/^\uFEFF/, '')) as {
			entries: Array<{ id: string; binaryPath: string }>;
		};
		const binary = manifest.entries.find(entry => entry.id === 'msvc-x64-O2-debug')!.binaryPath;
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-r36-provider-'));
		const target = path.join(directory, path.basename(binary));
		const pdb = path.join(directory, 'semantic_benchmark.pdb');
		fs.copyFileSync(binary, target);
		fs.copyFileSync(path.join(build, 'semantic_benchmark.pdb'), pdb);
		const engine = new DisassemblerEngine();
		try {
			assert.strictEqual(await engine.loadFile(target), true);
			const debug = await importPdbSemantics(engine, { pdbPath: pdb, maxFunctions: 500 });
			assert.ok(debug.prototypeCount > 0);
			const store = engine.getSessionStore()!.getSemanticStore();
			const xorFunction = debug.provider.functions.find(fn => fn.name === 'bench_xor_buffer')!;
			const xorExport = engine.getExports().find(item => item.name === 'bench_xor_buffer')!;
			const xorBody = engine.getFunctionAt(xorExport.address)?.instructions.find(instruction => instruction.isJump && instruction.targetAddress !== undefined)?.targetAddress ?? xorExport.address;
			const xorPrototype = store.getPrototype(`function:0x${xorBody.toString(16)}`);
			assert.ok(xorPrototype);
			assert.strictEqual(xorPrototype?.evidence.source, 'debug-info');
			assert.strictEqual(xorPrototype?.parameters.length, 3);
			assert.ok(store.listTypes().some(type => type.name === 'BenchObject' && type.kind === 'struct'));

			const signatures = applyImportSignatureProvider(engine);
			assert.ok(signatures.matchedCount > 0);
			const signaturePrototype = signatures.facts.map(fact => store.getPrototype(fact.functionIdentity)).find(Boolean);
			assert.ok(signaturePrototype, JSON.stringify({ facts: signatures.facts.slice(0, 5), prototypes: store.listPrototypes().slice(-5).map(item => item.functionIdentity) }));
			assert.strictEqual(signaturePrototype?.evidence.source, 'signature');
			assert.notStrictEqual(signaturePrototype?.evidence.producer, xorPrototype?.evidence.producer);
		} finally {
			engine.dispose();
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
