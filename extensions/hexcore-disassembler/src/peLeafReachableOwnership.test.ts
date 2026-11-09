/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

const base = 0x140001000;

function earlyReturnLeaf(): Buffer {
	return Buffer.concat([
		// test r8,r8; jne base+0x10; xor eax,eax; ret
		Buffer.from('4d85c0750b33c0c3', 'hex'),
		Buffer.alloc(8, 0xcc),
		// Forward branch island: mov eax,1; ret
		Buffer.from('b801000000c3', 'hex'),
	]);
}

suite('PE leaf reachable ownership', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) {
			return request === 'vscode' ? '__pe_leaf_reachable__' : resolve.call(this, request, ...args);
		};
		require.cache.__pe_leaf_reachable__ = {
			id: '__pe_leaf_reachable__', filename: '__pe_leaf_reachable__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } },
		} as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});

	function setup(): any {
		const bytes = earlyReturnLeaf();
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{
			name: '.text', virtualAddress: base, virtualSize: bytes.length,
			rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false,
			isData: false, characteristics: 6, permissions: 'r-x',
		}];
		// The image has an exception directory, but this optimized leaf does not.
		engine.peDataDirectories = { pdata: [{ beginAddress: 0x80, endAddress: 0x90, unwindInfoAddress: 0xa0 }] };
		engine.functionSeeds.record(base, { kind: 'direct-call', sourceAddress: base - 5 });
		return engine;
	}

	async function reconcile(engine: any): Promise<void> {
		await engine.analyzeFunction(base, 'ct_equal_fixture', { followChildren: false });
		await engine.reconcilePeLeafReachableOwnership();
	}

	test('follows a forward conditional island for a leaf omitted from pdata', async () => {
		const engine = setup();
		try {
			await reconcile(engine);
			const fn = engine.getFunctionAt(base);
			assert.strictEqual(fn.endAddress, base + 0x16);
			assert.strictEqual(fn.size, 0x16);
			const addresses = fn.instructions.map((instruction: { address: number }) => instruction.address);
			assert.ok(addresses.includes(base + 0x10), 'forward branch target is owned');
			assert.ok(addresses.includes(base + 0x15), 'forward branch return is owned');
			assert.ok(!addresses.some((address: number) => address >= base + 8 && address < base + 0x10),
				'unreachable padding between blocks is not owned');
		} finally { engine.dispose(); }
	});

	test('does not absorb a branch target with independent function evidence', async () => {
		const engine = setup();
		engine.functionSeeds.record(base + 0x10, { kind: 'direct-call', sourceAddress: base + 0x40 });
		try {
			await reconcile(engine);
			const fn = engine.getFunctionAt(base);
			assert.strictEqual(fn.endAddress, base + 8);
			assert.strictEqual(fn.size, 8);
			assert.ok(!fn.instructions.some((instruction: { address: number }) => instruction.address === base + 0x10));
		} finally { engine.dispose(); }
	});

	test('extends semantic ownership to a reachable block beyond the unwind range', async () => {
		const engine = setup();
		engine.functionSeeds.record(base, { kind: 'unwind' });
		engine.authoritativePdataRanges = [{ begin: base, end: base + 8 }];
		try {
			await reconcile(engine);
			const fn = engine.getFunctionAt(base);
			assert.strictEqual(fn.endAddress, base + 0x16);
			assert.strictEqual(fn.size, 0x16);
			assert.deepStrictEqual(engine.findAuthoritativePdataRangeContaining(base), { begin: base, end: base + 8 });
		} finally { engine.dispose(); }
	});

	test('extends a lazy pdata stub without materializing its body', async () => {
		const engine = setup();
		engine.functions.set(base, {
			address: base, name: 'lazy_unwind_owner', size: 8, endAddress: base + 8,
			instructions: [], callers: [], callees: [],
		});
		engine.unmaterializedStubs.add(base);
		engine.functionSeeds.record(base, { kind: 'unwind' });
		engine.authoritativePdataRanges = [{ begin: base, end: base + 8 }];
		try {
			await engine.reconcilePeLeafReachableOwnership();
			const fn = engine.getFunctionAt(base);
			assert.strictEqual(fn.endAddress, base + 0x16);
			assert.strictEqual(fn.instructions.length, 0);
			assert.strictEqual(engine.getFunctionBodyStatus(base), 'lazy');
		} finally { engine.dispose(); }
	});

	test('discovers a direct-call leaf omitted from pdata without materializing the caller', async () => {
		const source = base;
		const leaf = base + 0x20;
		const displacement = leaf - (source + 5);
		const bytes = Buffer.alloc(0x30, 0xcc);
		bytes[0] = 0xe8;
		bytes.writeInt32LE(displacement, 1);
		bytes[5] = 0xc3;
		Buffer.from('b801000000c3', 'hex').copy(bytes, 0x20);
		const engine = new Engine();
		engine.loadBuffer(bytes, base, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: source, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{
			name: '.text', virtualAddress: base, virtualSize: bytes.length,
			rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false,
			isData: false, characteristics: 6, permissions: 'r-x',
		}];
		engine.authoritativePdataRanges = [{ begin: source, end: source + 6 }];
		engine.functions.set(source, {
			address: source, name: 'lazy_caller', size: 6, endAddress: source + 6,
			instructions: [], callers: [], callees: [],
		});
		engine.unmaterializedStubs.add(source);
		try {
			const diagnostic = await engine.discoverPeDirectCallLeafTargets();
			assert.strictEqual(diagnostic.status, 'complete');
			assert.strictEqual(diagnostic.candidatesAccepted, 1);
			assert.strictEqual(engine.getFunctionAt(leaf)?.endAddress, leaf + 6);
			assert.deepStrictEqual(engine.getFunctionDiscoveryEvidence(leaf), [
				{ kind: 'direct-call', sourceAddress: source },
			]);
			assert.strictEqual(engine.getFunctionAt(source)?.instructions.length, 0);
			assert.strictEqual(engine.getFunctionBodyStatus(source), 'lazy');
		} finally { engine.dispose(); }
	});

	test('reports the large-image budget instead of silently skipping call leaves', async () => {
		const engine = setup();
		engine.sections[0].rawSize = 64 * 1024 * 1024;
		engine.authoritativePdataRanges = [{ begin: base, end: base + 8 }];
		try {
			const diagnostic = await engine.discoverPeDirectCallLeafTargets();
			assert.strictEqual(diagnostic.status, 'partial');
			assert.strictEqual(diagnostic.reason, 'large-image-budget');
			assert.strictEqual(diagnostic.candidatesAccepted, 0);
		} finally { engine.dispose(); }
	});
});
