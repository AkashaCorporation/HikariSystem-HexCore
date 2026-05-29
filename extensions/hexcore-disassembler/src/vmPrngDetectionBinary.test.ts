/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.2 - BINARY-DRIVEN detectVM / detectPRNG regression.
//
// The existing vmPrngDetectionProperties.test.ts only validates the RESULT SHAPE
// with fast-check arbitraries -- it NEVER runs the detectors against a binary, so
// the "no-op on obfuscated code" defects (detectVM/detectPRNG only walked
// this.functions, which collapses under callfuscation) were invisible to CI.
//
// This test actually loads code into the engine and asserts the detectors fire:
//   1. A self-contained SYNTHETIC ELF64 buffer (always runs) -- a tiny stub that
//      `mov edi, 1337 ; call srand@plt ; call rand@plt` reached only via a
//      callfuscation-style `call <node>` chain, plus operand-stack `[rbp+rax*4-d]`
//      accesses + an indirect dispatch, so neither detector can rely on function
//      discovery.
//   2. The REAL HTB "Callfuscated" crackme (runs only when the fixture is present),
//      asserting detectVM -> stack-machine and detectPRNG -> seedValue 1337.

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';

/** Minimal vscode mock -- DisassemblerEngine imports 'vscode' for configuration. */
function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_vmprng__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_vmprng__'] = {
		id: '__vscode_mock_vmprng__',
		filename: '__vscode_mock_vmprng__',
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

const REAL_CRACKME = 'C:\\Users\\Mazum\\Desktop\\HTB Challenge\\Call\\crackme';

suite('detectVM / detectPRNG - binary-driven (v3.8.2)', () => {

	// ── Synthetic obfuscated buffer (self-contained, always runs) ─────────────
	//
	// We build a raw x64 code buffer and load it via loadBuffer(). The detectors
	// byte-scan executable sections, so we install a single executable section
	// covering the whole buffer. The buffer encodes a PRNG seed + srand/rand calls
	// reachable only through a callfuscation `call <node>` chain (so a function
	// walk would miss them), plus VM operand-stack accesses + an indirect dispatch.

	test('detectPRNG fires on a synthetic callfuscated srand/rand chain (byte scan)', () => {
		const engine = new DisassemblerEngine();
		const BASE = 0x400000;
		const buf = Buffer.alloc(0x400, 0x90); // nop-filled

		// Lay out (file offset == VA - BASE for this synthetic image):
		//   0x100: rand PLT stub    (target of rand calls)
		//   0x110: srand PLT stub   (target of srand call)
		//   0x200: seed node:  mov edi, 1337 ; call <srand-call-node>
		//   0x210: srand-call-node: call <srand stub>
		//   0x220: rand-call-node:  call <rand stub>
		const E8 = 0xe8;
		const writeCall = (at: number, targetVA: number) => {
			const instrVA = BASE + at;
			buf[at] = E8;
			buf.writeInt32LE(targetVA - (instrVA + 5), at + 1);
		};

		// seed node: mov edi, 0x539 (1337) then call srand-call-node (0x210)
		buf[0x200] = 0xbf; buf.writeUInt32LE(1337, 0x201); // mov edi, 1337
		writeCall(0x205, BASE + 0x210);                    // call 0x...210
		// srand-call-node calls the srand stub
		writeCall(0x210, BASE + 0x110);
		// rand-call-node calls the rand stub
		writeCall(0x220, BASE + 0x100);
		writeCall(0x230, BASE + 0x100); // a second rand call

		engine.loadBuffer(buf, BASE, 'x64');
		// one executable section spanning the whole image
		(engine as any).sections = [{
			name: '.text', virtualAddress: BASE, virtualSize: buf.length,
			rawAddress: 0, rawSize: buf.length, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false,
			isReadable: true, isWritable: false, isExecutable: true
		}];
		// PLT symbol map: stub VA -> name (what the .rela.plt parse would produce)
		(engine as any)._pltSymbolMap = new Map<number, string>([
			[BASE + 0x100, 'rand'],
			[BASE + 0x110, 'srand'],
		]);

		const prng = engine.detectPRNG();
		assert.strictEqual(prng.prngDetected, true, 'PRNG must be detected via byte scan');
		assert.strictEqual(prng.seedValue, 1337, 'srand seed immediate must be recovered (chain-aware)');
		assert.ok(prng.randCallCount >= 2, `expected >=2 rand calls, got ${prng.randCallCount}`);
		assert.ok(
			prng.callSites.some((c: { function: string }) => c.function === 'srand'),
			'srand call site must be present'
		);
	});

	test('detectVM fires on a synthetic stack-VM signature (operand stack + indirect dispatch)', async function () {
		// buildExecScan runs a real Capstone sweep + leader recovery; allow time.
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const engine = new DisassemblerEngine();
		const BASE = 0x400000;
		const buf = Buffer.alloc(0x200, 0x90);

		// Encode several `mov eax, dword ptr [rbp + rax*4 - disp]` (operand stack) with
		// two distinct displacements, plus a `jmp rax` indirect dispatch.
		// mov eax, [rbp + rax*4 - 0x950] = 8B 84 85 B0 F6 FF FF
		const movStack = (at: number, disp: number) => {
			buf[at] = 0x8b; buf[at + 1] = 0x84; buf[at + 2] = 0x85;
			buf.writeInt32LE(-disp, at + 3);
		};
		let off = 0;
		for (let n = 0; n < 6; n++) { movStack(off, 0x950); off += 7; }
		for (let n = 0; n < 6; n++) { movStack(off, 0x18f0); off += 7; }
		// jmp rax = FF E0
		buf[off] = 0xff; buf[off + 1] = 0xe0; off += 2;

		engine.loadBuffer(buf, BASE, 'x64');
		(engine as any).sections = [{
			name: '.text', virtualAddress: BASE, virtualSize: buf.length,
			rawAddress: 0, rawSize: buf.length, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false,
			isReadable: true, isWritable: false, isExecutable: true
		}];
		// Force the engine to build the linear exec sweep so detectVM reads it.
		await (engine as any).buildExecScan();

		const vm = engine.detectVM();
		assert.strictEqual(vm.vmDetected, true, 'stack-VM signature must be detected');
		assert.strictEqual(vm.vmType, 'stack-machine', 'should classify as stack-machine');
		assert.ok(vm.stackArrays.length >= 2, `expected >=2 operand-stack arrays, got ${vm.stackArrays.length}`);
	});

	// ── Real HTB "Callfuscated" crackme (runs only if the fixture exists) ──────

	const realTest = fs.existsSync(REAL_CRACKME) ? test : test.skip;
	realTest('REAL crackme: detectVM -> stack-machine, detectPRNG -> seed 1337', async function () {
		// real Capstone decode + PLT parse can take a few seconds
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(120000); }
		const engine = new DisassemblerEngine();
		const loaded = await engine.loadFile(REAL_CRACKME);
		assert.strictEqual(loaded, true, 'crackme must load');
		await engine.analyzeAll({ detectVM: true, detectPRNG: true });

		// Function discovery collapses under callfuscation -- detection must NOT
		// depend on it. This is the exact regression the audit found.
		const vm = engine.detectVM();
		assert.strictEqual(vm.vmDetected, true, 'VM must be detected on the callfuscated crackme');
		assert.strictEqual(vm.vmType, 'stack-machine', 'crackme uses a stack VM');

		const prng = engine.detectPRNG();
		assert.strictEqual(prng.prngDetected, true, 'srand/rand must be detected');
		assert.strictEqual(prng.seedValue, 1337, 'decoy PRNG seed is 1337');
		assert.ok(prng.randCallCount >= 1, 'at least one rand call');
	});
});
