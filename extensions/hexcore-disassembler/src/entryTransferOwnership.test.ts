/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

const base = 0x140001000;

suite('Image entry transfer ownership', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__entry_transfer__' : resolve.call(this, request, ...args); };
		require.cache.__entry_transfer__ = { id: '__entry_transfer__', filename: '__entry_transfer__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } } } as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});

	test('keeps a PE x64 entry jmp separate from a leaf destination without a prologue', async () => {
		// entry: jmp body; int3 padding; body: mov eax,1; ret.
		const bytes = Buffer.from('e903000000ccccccb801000000c3', 'hex');
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{ name: '.text', virtualAddress: base, virtualSize: bytes.length, rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false, isData: false, characteristics: 6, permissions: 'r-x' }];
		engine.functionSeeds.record(base, { kind: 'entry' });
		try {
			await engine.ensureCapstoneInitialized();
			const entry = await engine.analyzeFunction(base);
			const body = engine.getFunctionAt(base + 8);
			engine.addTailCallEdges();
			assert.strictEqual(entry.endAddress, base + 5);
			assert.strictEqual(entry.instructions.length, 1);
			assert.ok(body, 'direct entry destination promoted to a function');
			assert.strictEqual(body.endAddress, base + bytes.length);
			assert.deepStrictEqual(entry.callees, [base + 8]);
		} finally { engine.dispose(); }
	});
});
