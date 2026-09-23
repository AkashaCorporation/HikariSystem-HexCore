/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

function elfFixture(): Buffer {
	const bytes = Buffer.alloc(0x4000);
	bytes.set([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]);
	bytes.writeUInt16LE(3, 16); bytes.writeUInt16LE(183, 18); bytes.writeUInt32LE(1, 20);
	bytes.writeBigUInt64LE(0x1000n, 24); bytes.writeBigUInt64LE(64n, 32); bytes.writeBigUInt64LE(0x3000n, 40);
	bytes.writeUInt16LE(64, 52); bytes.writeUInt16LE(56, 54); bytes.writeUInt16LE(1, 56);
	bytes.writeUInt16LE(64, 58); bytes.writeUInt16LE(7, 60); bytes.writeUInt16LE(6, 62);
	bytes.writeUInt32LE(1, 64); bytes.writeUInt32LE(7, 68);
	bytes.writeBigUInt64LE(BigInt(bytes.length), 64 + 32); bytes.writeBigUInt64LE(BigInt(bytes.length), 64 + 40); bytes.writeBigUInt64LE(0x1000n, 64 + 48);
	const names = '\0.plt\0.got\0.rela.plt\0.dynsym\0.dynstr\0.shstrtab\0';
	bytes.write(names, 0x2b00);
	const section = (index: number, name: string, type: number, flags: number, offset: number, size: number, link = 0, entrySize = 0) => {
		const at = 0x3000 + index * 64;
		bytes.writeUInt32LE(names.indexOf(name), at); bytes.writeUInt32LE(type, at + 4);
		bytes.writeBigUInt64LE(BigInt(flags), at + 8); bytes.writeBigUInt64LE(BigInt(flags ? offset : 0), at + 16);
		bytes.writeBigUInt64LE(BigInt(offset), at + 24); bytes.writeBigUInt64LE(BigInt(size), at + 32);
		bytes.writeUInt32LE(link, at + 40); bytes.writeBigUInt64LE(8n, at + 48); bytes.writeBigUInt64LE(BigInt(entrySize), at + 56);
	};
	section(1, '.plt', 1, 6, 0x1000, 48);
	section(2, '.got', 1, 3, 0x2268, 16);
	section(3, '.rela.plt', 4, 2, 0x2800, 48, 4, 24);
	section(4, '.dynsym', 11, 2, 0x2900, 72, 5, 24);
	section(5, '.dynstr', 3, 2, 0x2a00, 14);
	section(6, '.shstrtab', 3, 0, 0x2b00, names.length);
	bytes.write('\0first\0second\0', 0x2a00);
	for (let index = 1; index <= 2; index++) {
		bytes.writeUInt32LE(index === 1 ? 1 : 7, 0x2900 + index * 24);
		bytes[0x2900 + index * 24 + 4] = 0x12;
		bytes.writeBigUInt64LE(BigInt(0x2268 + (index - 1) * 8), 0x2800 + (index - 1) * 24);
		bytes.writeBigUInt64LE((BigInt(index) << 32n) | 1026n, 0x2808 + (index - 1) * 24);
	}
	// Relocations name first/second, but the stubs load second/first.
	Buffer.from('100000b0113a41f910c2099120021fd61f2003d51f2003d5', 'hex').copy(bytes, 0x1000);
	Buffer.from('100000b0113641f910a2099120021fd61f2003d51f2003d5', 'hex').copy(bytes, 0x1018);
	return bytes;
}

suite('AArch64 ELF PLT import integration', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__aarch64_plt_integration__' : resolve.call(this, request, ...args); };
		require.cache.__aarch64_plt_integration__ = { id: '__aarch64_plt_integration__', filename: '__aarch64_plt_integration__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } } } as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});
	test('maps decoded entries through the linked relocation/symbol tables', async () => {
		const engine = new Engine();
		try {
			engine.loadBuffer(elfFixture(), 0, 'arm64'); engine.parseELFStructure();
			assert.strictEqual(engine._pltSymbolMap.size, 0, 'no ordinal-based names before decoding');
			await engine.ensureCapstoneInitialized(); await engine.resolveAarch64PltImports();
			assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1000), 'second');
			assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1018), 'first');
			assert.strictEqual(engine.getFileInfo().pltResolution.status, 'ok');
			const first = JSON.stringify([...engine._pltSymbolMap]);
			await engine.resolveAarch64PltImports();
			assert.strictEqual(JSON.stringify([...engine._pltSymbolMap]), first);
		} finally { engine.dispose(); }
	});
	test('does not fabricate import addresses when detail decoding is unavailable', async () => {
		const engine = new Engine();
		try {
			engine.loadBuffer(elfFixture(), 0, 'arm64'); engine.parseELFStructure();
			await engine.resolveAarch64PltImports();
			assert.strictEqual(engine._pltSymbolMap.size, 0);
			assert.strictEqual(engine.getFileInfo().pltResolution.status, 'partial');
		} finally { engine.dispose(); }
	});
	test('rejects non-JUMP_SLOT relocations instead of naming them by position', async () => {
		const bytes = elfFixture(); bytes.writeBigUInt64LE((1n << 32n) | 1027n, 0x2808);
		const engine = new Engine();
		try {
			engine.loadBuffer(bytes, 0, 'arm64'); engine.parseELFStructure();
			await engine.ensureCapstoneInitialized(); await engine.resolveAarch64PltImports();
			assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1018), undefined);
			assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1000), 'second');
		} finally { engine.dispose(); }
	});
	test('conflicting symbols for one GOT slot remain ambiguous', async () => {
		const bytes = elfFixture(); bytes.writeBigUInt64LE(0x2268n, 0x2818);
		const engine = new Engine();
		try {
			engine.loadBuffer(bytes, 0, 'arm64'); engine.parseELFStructure();
			await engine.ensureCapstoneInitialized(); await engine.resolveAarch64PltImports();
			assert.strictEqual(engine._pltSymbolMap.size, 0);
			assert.strictEqual(engine.getFileInfo().pltResolution.status, 'partial');
			assert.strictEqual(engine.getFileInfo().pltResolution.ambiguousGotSlots.length, 1);
		} finally { engine.dispose(); }
	});
	test('round-trips verified bindings and rejects legacy snapshots without mutating the target', async () => {
		const engine = new Engine();
		try {
			engine.loadBuffer(elfFixture(), 0, 'arm64'); engine.parseELFStructure();
			await engine.ensureCapstoneInitialized(); await engine.resolveAarch64PltImports();
			const snapshot = engine.exportAnalysisSnapshot();
			engine.importAnalysisSnapshot(snapshot);
			assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1000), 'second');
			delete snapshot.fileInfo.pltResolution;
			assert.throws(() => engine.importAnalysisSnapshot(snapshot), /stale-analysis-snapshot/);
			assert.strictEqual(engine.getFileInfo().pltResolution.version, 1);
		} finally { engine.dispose(); }
	});
	test('malformed symbol references leave diagnostics partial instead of hiding the lost slot', async () => {
		for (const corruptName of [false, true]) {
			const bytes = elfFixture();
			if (corruptName) { bytes.writeUInt32LE(0xffff, 0x2900 + 48); }
			else { bytes.writeBigUInt64LE((4096n << 32n) | 1026n, 0x2820); }
			const engine = new Engine();
			try {
				engine.loadBuffer(bytes, 0, 'arm64'); engine.parseELFStructure();
				await engine.ensureCapstoneInitialized(); await engine.resolveAarch64PltImports();
				assert.strictEqual(engine.getFileInfo().pltResolution.status, 'partial');
				assert.strictEqual(engine.getFileInfo().pltResolution.relocationReadErrors, 1);
				assert.strictEqual(engine.resolveStubSymbol(engine.baseAddress + 0x1000), undefined);
			} finally { engine.dispose(); }
		}
	});
});
