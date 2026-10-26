/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { CapstoneWrapper } from './capstoneWrapper';

const branchEncodings = ['800000b4', '81000035', '82001836', '830040b7'];
const base = 0x555555555000;

suite('AArch64 conditional targets and function ownership', () => {
	let Engine: any;
	suiteSetup(() => {
		const Module = require('module'); const resolve = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) { return request === 'vscode' ? '__arm64_ownership__' : resolve.call(this, request, ...args); };
		require.cache.__arm64_ownership__ = { id: '__arm64_ownership__', filename: '__arm64_ownership__', loaded: true,
			exports: { workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) } } } as NodeModule;
		Engine = require('./disassemblerEngine').DisassemblerEngine;
	});
	for (const detail of [true, false]) {
		test(`extracts the branch destination, not the register or bit index (detail=${detail})`, async () => {
			const capstone = new CapstoneWrapper();
			try {
				await capstone.initialize('arm64', { detail });
				for (const bytes of branchEncodings) {
					const [instruction] = await capstone.disassemble(Buffer.from(bytes, 'hex'), base, 1);
					assert.strictEqual(instruction.targetAddress, base + 16);
					assert.strictEqual(instruction.isConditional, true);
				}
			} finally { capstone.dispose(); }
		});
	}
	function engineFor(bytes: Buffer): any {
		const engine = new Engine(); engine.loadBuffer(bytes, base, 'arm64');
		engine.fileInfo = { format: 'ELF64', architecture: 'arm64', entryPoint: base, baseAddress: base, imageSize: bytes.length };
		engine.sections = [{ name: '.text', virtualAddress: base, virtualSize: bytes.length, rawAddress: 0, rawSize: bytes.length,
			isCode: true, isExecutable: true, isReadable: true, isWritable: false, isData: false, characteristics: 6, permissions: 'r-x' }];
		return engine;
	}
	for (const branch of branchEncodings) {
		test(`retains a reachable tail after RET/NOP without absorbing the next function (${branch})`, async () => {
			// cbz/cbnz/tbz/tbnz tail; mov w0,1; ret; nop; tail: mov w0,2; b ret; next: paciasp; ret.
			const engine = engineFor(Buffer.from(branch + '20008052c0035fd61f2003d540008052fdffff173f2303d5c0035fd6', 'hex'));
			try {
				await engine.ensureCapstoneInitialized();
				const fn = await engine.analyzeFunction(base);
				assert.strictEqual(fn.endAddress, base + 24);
				assert.ok(fn.instructions.some((instruction: any) => instruction.address === base + 16));
				assert.ok(fn.instructions.every((instruction: any) => instruction.address < base + 24));
			} finally { engine.dispose(); }
		});
	}
	test('does not absorb an independently seeded target of a conditional tail transfer', async () => {
		const engine = engineFor(Buffer.from('800000b420008052c0035fd61f2003d540008052c0035fd6', 'hex'));
		try {
			engine.functionSeeds.record(base + 16, { kind: 'symbol' });
			await engine.ensureCapstoneInitialized();
			const fn = await engine.analyzeFunction(base);
			assert.strictEqual(fn.endAddress, base + 12);
			assert.ok(fn.instructions.every((instruction: any) => instruction.address < base + 16));
		} finally { engine.dispose(); }
	});
	test('keeps an ELF entry trampoline separate from its direct branch destination', async () => {
		// entry: b body; unreachable nop; body: mov w0,1; ret.
		const engine = engineFor(Buffer.from('020000141f2003d520008052c0035fd6', 'hex'));
		try {
			engine.functionSeeds.record(base, { kind: 'entry' });
			await engine.ensureCapstoneInitialized();
			const entry = await engine.analyzeFunction(base);
			const body = engine.getFunctionAt(base + 8);
			engine.addTailCallEdges();
			assert.strictEqual(entry.endAddress, base + 4);
			assert.strictEqual(entry.instructions.length, 1);
			assert.ok(body, 'direct entry destination promoted to a function');
			assert.strictEqual(body.endAddress, base + 16);
			assert.deepStrictEqual(entry.callees, [base + 8]);
		} finally { engine.dispose(); }
	});
	test('follows a reachable branch island after invalid inline words', async () => {
		// nop; b body; invalid inline words; body: mov w0,1; ret.
		const engine = engineFor(Buffer.from('1f2003d503000014ffffffffffffffff20008052c0035fd6', 'hex'));
		try {
			engine.functionSeeds.record(base, { kind: 'entry' });
			await engine.ensureCapstoneInitialized();
			const fn = await engine.analyzeFunction(base);
			assert.strictEqual(fn.endAddress, base + 24);
			assert.deepStrictEqual(fn.instructions.map((instruction: any) => instruction.address),
				[base, base + 4, base + 16, base + 20]);
			assert.strictEqual(engine.getFunctionAt(base + 16), undefined, 'reachable island remains in the entry owner');
		} finally { engine.dispose(); }
	});
	test('retains nested fixed-width prologue seeds without callers and clamps the prior owner', async () => {
		// frame; bl outside-image (modeled no-return); nested frame; ret.
		const engine = engineFor(Buffer.from('fd7bbea93f000094fd7bbea9c0035fd6', 'hex'));
		try {
			await engine.ensureCapstoneInitialized();
			await engine.scanForFunctionPrologs();
			engine.reconcileFunctionsWithStrongSeeds();
			engine.dropInteriorGhostFunctions();
			const first = engine.getFunctionAt(base);
			const second = engine.getFunctionAt(base + 8);
			assert.ok(first && second);
			assert.strictEqual(first.endAddress, base + 8);
			assert.strictEqual(second.endAddress, base + 16);
			assert.strictEqual(engine.functionSeeds.isStrong(base + 8), true);
		} finally { engine.dispose(); }
	});
	test('recognizes a callee-saved pair stack frame as a fixed-width prologue', async () => {
		const engine = engineFor(Buffer.from('f353b9a9c0035fd6', 'hex'));
		try {
			await engine.ensureCapstoneInitialized();
			await engine.scanForFunctionPrologs();
			assert.ok(engine.getFunctionAt(base));
			assert.strictEqual(engine.functionSeeds.isStrong(base), true);
		} finally { engine.dispose(); }
	});
});
