/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

const base = 0x140001000;

suite('PE direct-jump linker thunk discovery', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__pe_linker_thunk__' : resolve.call(this, request, ...args); };
		require.cache.__pe_linker_thunk__ = { id: '__pe_linker_thunk__', filename: '__pe_linker_thunk__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } } } as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});

	function engineWithRun(count: number): any {
		const bytes = Buffer.alloc(0x200, 0x90);
		for (let index = 0; index < count; index++) {
			const offset = 0x10 + index * 5;
			const address = base + offset;
			const target = base + 0x100 + index * 4;
			bytes[offset] = 0xe9;
			bytes.writeInt32LE(target - (address + 5), offset + 1);
			bytes[target - base] = 0xc3;
		}
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{ name: '.text', virtualAddress: base, virtualSize: bytes.length, rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false, isData: false, characteristics: 6, permissions: 'r-x' }];
		return engine;
	}

	test('registers a contiguous run of four exact thunks and resolves their targets', async () => {
		const engine = engineWithRun(4);
		try {
			await engine.ensureCapstoneInitialized();
			await engine.discoverPeDirectJumpThunkRuns();
			for (let index = 0; index < 4; index++) {
				const address = base + 0x10 + index * 5;
				assert.strictEqual(engine.getFunctionAt(address)?.size, 5);
				assert.strictEqual(engine.getFunctionDiscoveryEvidence(address)[0]?.kind, 'linker-thunk');
				const resolved = engine.resolveKnownLinkerThunk(address);
				assert.strictEqual(resolved.target, base + 0x100 + index * 4);
				assert.strictEqual(resolved.chain.length, 1);
			}
		} finally { engine.dispose(); }
	});

	test('does not promote an isolated run shorter than four entries', async () => {
		const engine = engineWithRun(3);
		try {
			await engine.ensureCapstoneInitialized();
			await engine.discoverPeDirectJumpThunkRuns();
			assert.strictEqual(engine.getFunctionAt(base + 0x10), undefined);
		} finally { engine.dispose(); }
	});
});
