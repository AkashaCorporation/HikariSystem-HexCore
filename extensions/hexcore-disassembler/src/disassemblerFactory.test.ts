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
	if (request === 'vscode') { return '__vscode_mock_disassembler_factory__'; }
	return originalResolveFilename.call(this, request, parent, isMain, options);
};
require.cache['__vscode_mock_disassembler_factory__'] = {
	id: '__vscode_mock_disassembler_factory__',
	filename: '__vscode_mock_disassembler_factory__',
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

const { DisassemblerFactory } = require('./disassemblerFactory');

suite('DisassemblerFactory engine leases', () => {
	test('serializes same-file leases and disposes the engine after the final release', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-engine-lease-'));
		const file = path.join(dir, 'sample.bin');
		fs.writeFileSync(file, Buffer.from([0x55, 0x8b, 0xec, 0xc3]));

		const factory = DisassemblerFactory.getInstance();
		factory.disposeEngine(file);
		const first = await factory.acquireEngine(file);
		assert.strictEqual(await first.engine.loadFile(file, { architecture: 'x86', baseAddress: 0x1000 }), true);

		let secondAcquired = false;
		const secondPromise = factory.acquireEngine(file).then((lease: { engine: unknown; dispose(): void }) => {
			secondAcquired = true;
			return lease;
		});
		await new Promise(resolve => setTimeout(resolve, 10));
		assert.strictEqual(secondAcquired, false, 'same-file work must wait for the active lease');

		first.dispose();
		const second = await secondPromise;
		assert.strictEqual(secondAcquired, true);
		assert.strictEqual(second.engine, first.engine, 'queued work should reuse the isolated per-file engine');
		second.dispose();

		const replacement = await factory.acquireEngine(file);
		assert.notStrictEqual(replacement.engine, first.engine, 'the final release must evict and dispose the engine');
		replacement.dispose();

		fs.rmSync(dir, { recursive: true, force: true });
	});
});
