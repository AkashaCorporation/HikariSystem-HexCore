/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * PE IAT call-site naming. v3.8.5.
 *
 * HexCore already RESOLVES PE imports (parsePEImports records each import function's IAT-slot VA
 * in ImportFunction.address) but never wired those names onto the call sites, so PE disassembly
 * showed `call dword ptr [0x402000]` instead of `call ReadFile`. This is the PE analog of the
 * ELF `<symbol>@plt` naming (applyPltStubNames). applyIatCallNames builds a Map<iatVA, "<dll>!<api>">
 * from getImports() and stamps `instruction.comment` on every direct call/jmp through an IAT slot,
 * handling BOTH addressing forms:
 *   - PE32: `call/jmp dword ptr [<abs32>]`     -> iatVA is the absolute operand.
 *   - PE64: `call/jmp qword ptr [rip + <disp>]` -> iatVA = (addr of NEXT instruction) + disp.
 *
 * Two proofs:
 *   (1) SYNTHETIC buffers (always run) drive the engine via loadBuffer + a real Capstone decode:
 *       a PE32 absolute-IAT case and a PE64 rip-relative-IAT case.
 *   (2) The REAL IgniteMe.exe (PE32) binary (runs only when the fixture is present): all 7
 *       indirect calls carry ReadFile/WriteFile/ExitProcess/GetStdHandle.
 */

import * as assert from 'assert';
import * as fs from 'fs';

/** Minimal vscode mock -- DisassemblerEngine imports 'vscode' for configuration. */
function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_iat__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_iat__'] = {
		id: '__vscode_mock_iat__',
		filename: '__vscode_mock_iat__',
		loaded: true,
		exports: {
			commands: {
				getCommands: async () => [],
				executeCommand: async () => undefined,
				registerCommand: () => ({ dispose() { /* noop */ } })
			},
			workspace: {
				getConfiguration: () => ({ get: (_k: string, def: unknown) => def }),
				onDidChangeConfiguration: () => ({ dispose() { /* noop */ } }),
				workspaceFolders: undefined
			},
			extensions: { getExtension: () => undefined },
			Uri: { file: (f: string) => ({ fsPath: f, scheme: 'file' }) },
			window: {
				showInformationMessage: () => { },
				showWarningMessage: () => { },
				showErrorMessage: () => { },
				withProgress: async (_o: unknown, t: (p: { report: () => void }) => unknown) => t({ report: () => { } }),
				createOutputChannel: () => ({ appendLine: () => { }, append: () => { }, show: () => { }, clear: () => { }, replace: () => { }, dispose: () => { } })
			}
		}
	} as unknown as NodeModule;
}

installVscodeMock();
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { DisassemblerEngine } = require('./disassemblerEngine');

const REAL_IGNITE = 'C:\\Users\\Mazum\\Desktop\\New-Star\\Flare-On-1-5\\Flare-On4_Challenges\\02\\IgniteMe.exe';

/**
 * Build a synthetic PE32 image: a single code function that issues `call dword ptr [<abs32>]`
 * to each given IAT slot, then `ret`. The slots are absolute (no base/index register), the way
 * a 32-bit non-PIE PE references its IAT.
 *
 * Encoding: `FF 15 <abs32>` = `call dword ptr [abs32]` (5 bytes). `C3` = ret.
 */
function buildPe32Image(slots: { va: number; name?: string }[]): { buf: Buffer; codeVA: number; codeSize: number } {
	const codeVA = 0x401000;
	// Each `FF 15 abs32` is 6 bytes; lay them back-to-back (no per-call ret) so all calls land in
	// ONE function, then a single trailing `ret` terminates it.
	const buf = Buffer.alloc(slots.length * 6 + 1, 0x90);
	let off = 0;
	for (const s of slots) {
		buf[off + 0] = 0xff; buf[off + 1] = 0x15;          // call dword ptr [...]
		buf.writeUInt32LE(s.va >>> 0, off + 2);            // absolute IAT VA
		off += 6;
	}
	buf[off] = 0xc3;                                        // ret
	return { buf, codeVA, codeSize: off + 1 };
}

/**
 * Build a synthetic PE64 image: a single code function that issues `call qword ptr [rip + disp32]`
 * to each given IAT slot, then `ret`. RIP points at the next instruction, so disp = slotVA - nextVA.
 *
 * Encoding: `FF 15 <disp32>` = `call qword ptr [rip + disp32]` (6 bytes). `C3` = ret.
 */
function buildPe64Image(codeVA: number, slots: { va: number; name?: string }[]): { buf: Buffer; codeVA: number; codeSize: number } {
	// Each `FF 15 disp32` is 6 bytes; lay them back-to-back (no per-call ret) so all calls land in
	// ONE function, then a single trailing `ret` terminates it.
	const buf = Buffer.alloc(slots.length * 6 + 1, 0x90);
	let off = 0;
	for (const s of slots) {
		const insVA = codeVA + off;
		const nextVA = insVA + 6;             // FF 15 disp32 is 6 bytes; RIP = next instruction
		buf[off + 0] = 0xff; buf[off + 1] = 0x15;
		buf.writeInt32LE((s.va - nextVA) | 0, off + 2);
		off += 6;
	}
	buf[off] = 0xc3;                          // ret
	return { buf, codeVA, codeSize: off + 1 };
}

suite('PE IAT call-site naming (v3.8.5)', () => {

	test('resolveIatOperandVA: PE32 absolute, PE64 rip-relative, and rejects register operands', () => {
		const engine = new DisassemblerEngine() as any;
		// PE32 absolute: `dword ptr [0x402000]`
		assert.strictEqual(
			engine.resolveIatOperandVA({ address: 0x401000, size: 6, opStr: 'dword ptr [0x402000]' }),
			0x402000, 'PE32 absolute IAT VA');
		// PE64 rip-relative: nextVA = 0x40001090, + 0xcf90 = 0x4000e020
		assert.strictEqual(
			engine.resolveIatOperandVA({ address: 0x4000108a, size: 6, opStr: 'qword ptr [rip + 0xcf90]' }),
			0x4000e020, 'PE64 rip-relative IAT VA');
		// rip-relative negative displacement
		assert.strictEqual(
			engine.resolveIatOperandVA({ address: 0x401000, size: 6, opStr: 'qword ptr [rip - 0x10]' }),
			0x401000 + 6 - 0x10, 'PE64 rip-relative negative displacement');
		// register-indirect operands are NOT IAT references -> undefined
		assert.strictEqual(engine.resolveIatOperandVA({ address: 0, size: 2, opStr: 'rax' }), undefined, 'register operand');
		assert.strictEqual(engine.resolveIatOperandVA({ address: 0, size: 3, opStr: 'qword ptr [rax]' }), undefined, '[reg]');
		assert.strictEqual(engine.resolveIatOperandVA({ address: 0, size: 4, opStr: 'qword ptr [rsp + 0x20]' }), undefined, '[rsp+x]');
		assert.strictEqual(engine.resolveIatOperandVA({ address: 0, size: 4, opStr: 'qword ptr [rax + rcx*8]' }), undefined, '[base+index]');
	});

	test('PE32: `call dword ptr [<IAT>]` is annotated with <dll>!<api>', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const slots = [
			{ va: 0x402000, name: 'ReadFile' },
			{ va: 0x402004, name: 'WriteFile' },
			{ va: 0x402008, name: 'ExitProcess' }
		];
		const img = buildPe32Image(slots);
		const engine = new DisassemblerEngine() as any;
		engine.loadBuffer(img.buf, img.codeVA, 'x86');
		engine.fileInfo = { format: 'PE', architecture: 'x86', entryPoint: img.codeVA, baseAddress: 0x400000, imageSize: 0x10000 };
		engine.sections = [{
			name: '.text', virtualAddress: img.codeVA, virtualSize: img.codeSize,
			rawAddress: 0, rawSize: img.codeSize, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
		}];
		engine.imports = [{ name: 'KERNEL32.dll', functions: slots.map(s => ({ name: s.name, address: s.va })) }];
		await engine.ensureCapstoneInitialized();
		await engine.analyzeFunction(img.codeVA, undefined);
		engine.applyIatCallNames();

		const fn = engine.getFunctions().find((f: { address: number }) => f.address === img.codeVA);
		assert.ok(fn, 'function discovered');
		const calls = fn.instructions.filter((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'call');
		assert.strictEqual(calls.length, 3, 'three indirect calls');
		assert.strictEqual(calls[0].comment, 'KERNEL32.dll!ReadFile');
		assert.strictEqual(calls[1].comment, 'KERNEL32.dll!WriteFile');
		assert.strictEqual(calls[2].comment, 'KERNEL32.dll!ExitProcess');
	});

	test('PE64: `call qword ptr [rip + disp]` resolves the IAT VA and is annotated', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const codeVA = 0x140001000;
		const slots = [
			{ va: 0x14000e018, name: 'CreateRemoteThread' },
			{ va: 0x14000e020, name: 'OpenProcess' },
			{ va: 0x14000e028, name: 'VirtualAllocEx' }
		];
		const img = buildPe64Image(codeVA, slots);
		const engine = new DisassemblerEngine() as any;
		engine.loadBuffer(img.buf, codeVA, 'x64');
		engine.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: codeVA, baseAddress: 0x140000000, imageSize: 0x20000 };
		engine.sections = [{
			name: '.text', virtualAddress: codeVA, virtualSize: img.codeSize,
			rawAddress: 0, rawSize: img.codeSize, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
		}];
		engine.imports = [{ name: 'KERNEL32.dll', functions: slots.map(s => ({ name: s.name, address: s.va })) }];
		await engine.ensureCapstoneInitialized();
		await engine.analyzeFunction(codeVA, undefined);
		engine.applyIatCallNames();

		const fn = engine.getFunctions().find((f: { address: number }) => f.address === codeVA);
		assert.ok(fn, 'function discovered');
		const calls = fn.instructions.filter((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'call');
		assert.strictEqual(calls.length, 3, 'three rip-relative indirect calls');
		assert.strictEqual(calls[0].comment, 'KERNEL32.dll!CreateRemoteThread');
		assert.strictEqual(calls[1].comment, 'KERNEL32.dll!OpenProcess');
		assert.strictEqual(calls[2].comment, 'KERNEL32.dll!VirtualAllocEx');
	});

	test('a non-IAT indirect call (register / non-import pointer) is NOT annotated', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		// `call dword ptr [0x402000]` (IAT, annotated) followed by `call eax` (not IAT, skipped).
		const buf = Buffer.from([
			0xff, 0x15, 0x00, 0x20, 0x40, 0x00, // call dword ptr [0x402000]
			0xff, 0xd0,                         // call eax
			0xc3                                // ret
		]);
		const codeVA = 0x401000;
		const engine = new DisassemblerEngine() as any;
		engine.loadBuffer(buf, codeVA, 'x86');
		engine.fileInfo = { format: 'PE', architecture: 'x86', entryPoint: codeVA, baseAddress: 0x400000, imageSize: 0x10000 };
		engine.sections = [{
			name: '.text', virtualAddress: codeVA, virtualSize: buf.length,
			rawAddress: 0, rawSize: buf.length, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
		}];
		engine.imports = [{ name: 'KERNEL32.dll', functions: [{ name: 'ReadFile', address: 0x402000 }] }];
		await engine.ensureCapstoneInitialized();
		await engine.analyzeFunction(codeVA, undefined);
		engine.applyIatCallNames();

		const fn = engine.getFunctions().find((f: { address: number }) => f.address === codeVA);
		const calls = fn.instructions.filter((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'call');
		assert.strictEqual(calls[0].comment, 'KERNEL32.dll!ReadFile', 'IAT call annotated');
		assert.ok(!calls[1].comment, '`call eax` is NOT annotated');
	});

	test('no-op for non-PE (ELF): applyIatCallNames leaves comments empty', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const img = buildPe32Image([{ va: 0x402000 }]);
		const engine = new DisassemblerEngine() as any;
		engine.loadBuffer(img.buf, img.codeVA, 'x86');
		// ELF format -> the PE gate must short-circuit even though imports are present.
		engine.fileInfo = { format: 'ELF32', architecture: 'x86', entryPoint: img.codeVA, baseAddress: 0x400000, imageSize: 0x10000 };
		engine.sections = [{
			name: '.text', virtualAddress: img.codeVA, virtualSize: img.codeSize,
			rawAddress: 0, rawSize: img.codeSize, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
		}];
		engine.imports = [{ name: 'libc.so.6', functions: [{ name: 'ReadFile', address: 0x402000 }] }];
		await engine.ensureCapstoneInitialized();
		await engine.analyzeFunction(img.codeVA, undefined);
		engine.applyIatCallNames();

		const fn = engine.getFunctions().find((f: { address: number }) => f.address === img.codeVA);
		const call = fn.instructions.find((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'call');
		assert.ok(!call.comment, 'ELF: no IAT annotation (the @plt path handles ELF)');
	});

	// --- REAL IgniteMe.exe (PE32) binary (runs only if the fixture exists) ---
	const realTest = fs.existsSync(REAL_IGNITE) ? test : test.skip;
	realTest('REAL IgniteMe.exe: all 7 indirect calls carry their KERNEL32 import name', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(120000); }
		const engine = new DisassemblerEngine() as any;
		const loaded = await engine.loadFile(REAL_IGNITE);
		assert.strictEqual(loaded, true, 'IgniteMe must load');
		await engine.analyzeAll();

		// Collect every indirect (memory-operand) call/jmp across all functions.
		const indirect: { addr: number; comment?: string }[] = [];
		for (const f of engine.getFunctions()) {
			for (const ins of f.instructions) {
				const m = ins.mnemonic.toLowerCase();
				if ((m === 'call' || m === 'jmp') && (ins.opStr || '').includes('[')) {
					indirect.push({ addr: ins.address, comment: ins.comment });
				}
			}
		}
		assert.strictEqual(indirect.length, 7, `7 indirect call/jmp sites (found ${indirect.length})`);
		const annotated = indirect.filter(i => !!i.comment);
		assert.strictEqual(annotated.length, 7, `all 7 annotated (found ${annotated.length})`);

		// The specific names HexCore resolved (ReadFile/WriteFile/ExitProcess/GetStdHandle).
		const byAddr = new Map(indirect.map(i => [i.addr >>> 0, i.comment]));
		assert.strictEqual(byAddr.get(0x401145), 'KERNEL32.dll!ReadFile');
		assert.strictEqual(byAddr.get(0x4011bd), 'KERNEL32.dll!GetStdHandle');
		assert.strictEqual(byAddr.get(0x4011e9), 'KERNEL32.dll!WriteFile');
		assert.strictEqual(byAddr.get(0x401234), 'KERNEL32.dll!ExitProcess');
	});
});
