/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

const base = 0x140001000;

suite('Padding-delimited PE64 leaf discovery', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__padding_leaf__' : resolve.call(this, request, ...args); };
		require.cache.__padding_leaf__ = { id: '__padding_leaf__', filename: '__padding_leaf__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } } } as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});

	test('recovers aligned SSE leaves outside pdata and rejects an unaligned lookalike', async () => {
		const bytes = Buffer.concat([
			Buffer.alloc(16, 0xcc), Buffer.from('f20f58c1c3', 'hex'), Buffer.alloc(11, 0xcc),
			Buffer.from('f20f59c1c3', 'hex'), Buffer.alloc(7, 0xcc),
			Buffer.from('f20f5cc1c3', 'hex'), Buffer.alloc(3, 0xcc),
		]);
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{ name: '.text', virtualAddress: base, virtualSize: bytes.length, rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false, isData: false, characteristics: 6, permissions: 'r-x' }];
		try {
			await engine.ensureCapstoneInitialized();
			await engine.discoverPaddingDelimitedLeafFunctions();
			assert.ok(engine.getFunctionAt(base + 0x10));
			assert.ok(engine.getFunctionAt(base + 0x20));
			assert.strictEqual(engine.getFunctionAt(base + 0x2c), undefined);
			assert.strictEqual(engine.functionSeeds.isStrong(base + 0x10), true);
		} finally { engine.dispose(); }
	});

	test('does not promote a padding-delimited sequence inside an unwind range', async () => {
		const bytes = Buffer.concat([
			Buffer.alloc(16, 0xcc), Buffer.from('f20f58c1c3', 'hex'), Buffer.alloc(3, 0xcc),
		]);
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{ name: '.text', virtualAddress: base, virtualSize: bytes.length, rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false, isData: false, characteristics: 6, permissions: 'r-x' }];
		engine.peDataDirectories = { pdata: [{ beginAddress: 0x10, endAddress: 0x18, unwindInfoAddress: 0 }] };
		try {
			await engine.ensureCapstoneInitialized();
			await engine.discoverPaddingDelimitedLeafFunctions();
			assert.strictEqual(engine.getFunctionAt(base + 0x10), undefined);
		} finally { engine.dispose(); }
	});
});
