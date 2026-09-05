/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const Module = require('module');
const originalResolveFilename = Module._resolveFilename;
Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
	if (request === 'vscode') { return '__vscode_mock_function_ownership__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_function_ownership__'] = {
	id: '__vscode_mock_function_ownership__',
	filename: '__vscode_mock_function_ownership__',
	loaded: true,
	exports: {
		workspace: {
			getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }),
		},
		commands: { executeCommand: async () => undefined },
		extensions: { getExtension: () => undefined },
		Uri: { file: (file: string) => ({ fsPath: file, scheme: 'file' }) },
	},
} as unknown as NodeModule;

const { DisassemblerEngine } = require('./disassemblerEngine');

async function analyzeRaw(bytes: number[]) {
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-function-owner-'));
	const file = path.join(dir, 'sample.bin');
	const engine = new DisassemblerEngine();
	fs.writeFileSync(file, Buffer.from(bytes));
	try {
		assert.strictEqual(await engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }), true);
		await engine.analyzeAll();
		return engine.getFunctions().map((fn: { address: number; endAddress: number }) => ({
			address: Number(fn.address),
			endAddress: Number(fn.endAddress),
		})).sort((a: { address: number }, b: { address: number }) => a.address - b.address);
	} finally {
		engine.dispose();
		fs.rmSync(dir, { recursive: true, force: true });
	}
}

suite('Function ownership recovery', () => {
	test('keeps call-next PIC and branch targets inside one raw function', async () => {
		const functions = await analyzeRaw([
			0xe8, 0x00, 0x00, 0x00, 0x00, // call $+5: obtain EIP
			0xeb, 0x02,                   // internal jump
			0x90, 0x90,
			0x75, 0xfd,                   // internal conditional back-edge
			0xc3,
		]);
		assert.deepStrictEqual(functions.map((fn: { address: number }) => fn.address), [0x1000]);
	});

	test('keeps a branch-only block reachable past an early return in the same function', async () => {
		const functions = await analyzeRaw([
			0x85, 0xc0,       // test eax, eax
			0x74, 0x03,       // je 0x1007
			0xc3,             // fallthrough return
			0xcc, 0xcc,       // unreachable alignment
			0x31, 0xc0,       // xor eax, eax (branch-only block)
			0xc3,
		]);
		assert.deepStrictEqual(functions, [{ address: 0x1000, endAddress: 0x100a }]);
	});

	test('keeps a validated tail-call prologue as a separate non-overlapping function', async () => {
		const functions = await analyzeRaw([
			0xe9, 0x0b, 0x00, 0x00, 0x00, // jmp 0x1010
			0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
			0x55, 0x53, 0x57, 0x56, 0x83, 0xec, 0x10, 0xc3,
		]);
		assert.deepStrictEqual(functions.map((fn: { address: number }) => fn.address), [0x1000, 0x1010]);
		assert.ok(functions[0].endAddress <= functions[1].address);
	});
});
