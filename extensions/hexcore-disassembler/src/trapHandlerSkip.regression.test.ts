/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Trap-handler skip: discovery must sweep PAST ud2/int3/hlt when the binary installs a
 * SIGILL/SIGTRAP/SIGSEGV handler that advances RIP past the faulting instruction (the
 * "behind the scenes" anti-disassembly idiom). v3.8.5.
 *
 * Root cause this pins: capstoneWrapper classifies ud2 as isRet (so __builtin_trap ends the
 * CFG cleanly), and analyzeFunction's end-finding loop treats that as the function end. On a
 * trap-handler binary the real body is interleaved between ud2 separators, so the function was
 * truncated at the FIRST ud2 and the rest of the body fell into a discovery hole covered by NO
 * function. The fix: a STRICT gate (a sigaction/signal-class installer is actually called, with
 * a trap-class signum where recoverable) makes ud2/int3/hlt NON-terminating during discovery.
 *
 * Reference (idiom): HTB "Behind the Scenes" (VeryEasy). main installs sigaction(SIGILL=4, ...);
 * segill_sigaction loads uc_mcontext.gregs[REG_RIP] (offset 0xa8), adds 2 (sizeof ud2 = 0F 0B),
 * writes it back -> execution resumes at trap_addr + 2.
 *
 * Two proofs:
 *   (1) SYNTHETIC buffers (always run) drive the engine via loadBuffer + a real Capstone decode:
 *       - installer present + trap signum  -> gate ON  -> sweep continues past ud2.
 *       - NO installer                     -> gate OFF -> function truncates at ud2 (baseline).
 *       This is the byte-identical guarantee for genuine-terminator binaries.
 *   (2) The REAL behindthescenes binary (runs only when the fixture is present): main grows
 *       from 135 bytes (truncated at the first ud2) to ~494 bytes covering the full body, and
 *       the strncmp/strlen/printf calls fall inside main.
 */

import * as assert from 'assert';
import * as fs from 'fs';

/** Minimal vscode mock -- DisassemblerEngine imports 'vscode' for configuration. */
function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_traphandler__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_traphandler__'] = {
		id: '__vscode_mock_traphandler__',
		filename: '__vscode_mock_traphandler__',
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

const REAL_BTS = 'C:\\Users\\Mazum\\Desktop\\New-Star\\VeryEasy\\rev_behindthescenes\\behindthescenes';

const BASE = 0x400000;

/**
 * Build a synthetic x64 image whose `entry` function is:
 *   [optional]  mov edi, <signum> ; call <sigaction .plt.sec stub>   (installs handler)
 *   mov eax, 1
 *   ud2                                  ; trap separator (0F 0B)
 *   mov eax, 2
 *   ud2                                  ; trap separator
 *   xor eax, eax
 *   ret
 *
 * The `.plt.sec` stub at `stubOff` is `endbr64 ; bnd jmp *got(%rip)`, and the GOT slot is mapped
 * to the symbol via _gotSymbolMap (what the .rela.plt/.dynsym parse would produce). When
 * `installer` is true, detectTrapHandlerGate must trip and analyzeFunction must sweep past both
 * ud2s to the final ret; when false, it must truncate at the first ud2.
 */
function buildImage(opts: { installer: boolean; signum?: number; symbol?: string }): {
	buf: Buffer; entryVA: number; stubVA: number; gotVA: number; retVA: number; firstUd2VA: number;
} {
	const buf = Buffer.alloc(0x400, 0x00);
	const sym = opts.symbol ?? 'sigaction';

	// --- .plt.sec stub @ 0x100: endbr64 ; bnd jmp *disp(%rip) ---
	const stubOff = 0x100;
	const gotOff = 0x300; // GOT slot lives in a (non-exec) data area of the same buffer
	buf[stubOff + 0] = 0xf3; buf[stubOff + 1] = 0x0f; buf[stubOff + 2] = 0x1e; buf[stubOff + 3] = 0xfa; // endbr64
	buf[stubOff + 4] = 0xf2; buf[stubOff + 5] = 0xff; buf[stubOff + 6] = 0x25;                          // bnd jmp [rip+disp32]
	// rip after the 6-byte (F2 counts as a prefix; FF 25 disp32 is the 6-byte ins) -> insVA = stub+5,
	// rip = insVA + 6. Solve disp so rip + disp == gotVA.
	const insVA = BASE + stubOff + 5;
	const gotVA = BASE + gotOff;
	buf.writeInt32LE(gotVA - (insVA + 6), stubOff + 7);

	// --- entry function @ 0x200 ---
	let p = 0x200;
	const entryVA = BASE + p;
	if (opts.installer) {
		buf[p] = 0xbf; buf.writeUInt32LE((opts.signum ?? 4) >>> 0, p + 1); p += 5;      // mov edi, signum
		const callInsVA = BASE + p;
		buf[p] = 0xe8; buf.writeInt32LE((BASE + stubOff) - (callInsVA + 5), p + 1); p += 5; // call stub
	}
	buf[p] = 0xb8; buf.writeUInt32LE(1, p + 1); p += 5;            // mov eax, 1
	const firstUd2VA = BASE + p;
	buf[p] = 0x0f; buf[p + 1] = 0x0b; p += 2;                     // ud2
	buf[p] = 0xb8; buf.writeUInt32LE(2, p + 1); p += 5;            // mov eax, 2
	buf[p] = 0x0f; buf[p + 1] = 0x0b; p += 2;                     // ud2
	buf[p] = 0x31; buf[p + 1] = 0xc0; p += 2;                     // xor eax, eax
	const retVA = BASE + p;
	buf[p] = 0xc3; p += 1;                                        // ret

	return { buf, entryVA, stubVA: BASE + stubOff, gotVA, retVA, firstUd2VA };
}

/** Load a synthetic image into a fresh engine with a single exec section + GOT symbol map. */
function loadSynthetic(img: { buf: Buffer; gotVA: number }, symbol: string): any {
	const engine = new DisassemblerEngine() as any;
	engine.loadBuffer(img.buf, BASE, 'x64');
	// .text covers the code; mark whole image executable so addressToOffset + scans work.
	engine.sections = [{
		name: '.text', virtualAddress: BASE, virtualSize: img.buf.length,
		rawAddress: 0, rawSize: img.buf.length, characteristics: 0,
		permissions: 'r-x', isCode: true, isData: false,
		isReadable: true, isWritable: false, isExecutable: true
	}];
	// What .rela.plt/.dynsym parsing would produce for the .plt.sec thunk.
	engine._gotSymbolMap = new Map<number, string>([[img.gotVA, symbol]]);
	engine._pltSymbolMap = new Map<number, string>();
	return engine;
}

suite('Trap-handler skip: ud2/int3/hlt non-terminating under a SIGILL/SIGTRAP handler (v3.8.5)', () => {

	test('isTrapMnemonic recognises ud2/int3/hlt only', () => {
		const engine = new DisassemblerEngine() as any;
		for (const m of ['ud2', 'ud2a', 'ud2b', 'int3', 'hlt', 'UD2', 'Int3', 'HLT']) {
			assert.strictEqual(engine.isTrapMnemonic(m), true, `${m} is a trap mnemonic`);
		}
		for (const m of ['ret', 'jmp', 'call', 'nop', 'int', 'int1', 'mov', 'ud0']) {
			assert.strictEqual(engine.isTrapMnemonic(m), false, `${m} is NOT a trap mnemonic`);
		}
	});

	test('resolveStubSymbol follows an IBT .plt.sec thunk (endbr64 ; bnd jmp *got) to its import', () => {
		const img = buildImage({ installer: true, signum: 4 });
		const engine = loadSynthetic(img, 'sigaction');
		assert.strictEqual(engine.resolveStubSymbol(img.stubVA), 'sigaction',
			'.plt.sec stub resolves through its GOT reference');
		assert.strictEqual(engine.resolveStubSymbol(img.entryVA), undefined,
			'a non-stub address resolves to undefined');
	});

	test('GATE ON: installer (sigaction) called with SIGILL=4 -> detectTrapHandlerGate trips', () => {
		const img = buildImage({ installer: true, signum: 4 });
		const engine = loadSynthetic(img, 'sigaction');
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), true, 'gate ON when sigaction(SIGILL) is installed');
	});

	test('GATE ON: signal() with SIGTRAP=5 also trips the gate', () => {
		const img = buildImage({ installer: true, signum: 5, symbol: 'signal' });
		const engine = loadSynthetic(img, 'signal');
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), true, 'gate ON for signal(SIGTRAP)');
	});

	test('GATE OFF: no installer linked -> gate stays off (genuine-terminator binaries untouched)', () => {
		const img = buildImage({ installer: false });
		// No sigaction/signal in the GOT map at all.
		const engine = loadSynthetic(img, 'strlen');
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), false, 'gate OFF without a handler installer');
	});

	test('GATE OFF: installer present but never CALLED -> gate stays off', () => {
		// Build an image WITHOUT the call site, but still advertise sigaction in the GOT map.
		const img = buildImage({ installer: false });
		const engine = loadSynthetic(img, 'sigaction');
		// _pltSymbolMap advertises it as linked (fast-reject passes) but no E8 targets the stub.
		engine._pltSymbolMap = new Map<number, string>([[img.stubVA, 'sigaction']]);
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), false,
			'gate OFF when the installer is linked but never called');
	});

	test('analyzeFunction sweeps PAST ud2 when the gate is ON (synthetic, real Capstone)', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const img = buildImage({ installer: true, signum: 4 });
		const engine = loadSynthetic(img, 'sigaction');
		await engine.ensureCapstoneInitialized();
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), true, 'precondition: gate ON');

		const fn = await engine.analyzeFunction(img.entryVA, 'entry');
		// The function must reach the FINAL ret, not stop at the first ud2.
		assert.ok(fn.endAddress >= img.retVA + 1,
			`function must extend to the final ret (end=0x${fn.endAddress.toString(16)} >= 0x${(img.retVA + 1).toString(16)})`);
		// Both ud2 separators must be inside the function body.
		const ud2Count = fn.instructions.filter((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'ud2').length;
		assert.strictEqual(ud2Count, 2, 'both ud2 separators are inside the swept body');
		// The final ret must be present.
		assert.ok(fn.instructions.some((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'ret'),
			'final ret is part of the function');
	});

	test('analyzeFunction TRUNCATES at the first ud2 when the gate is OFF (byte-identical baseline)', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const img = buildImage({ installer: false });
		const engine = loadSynthetic(img, 'strlen'); // no handler installer
		await engine.ensureCapstoneInitialized();
		engine.detectTrapHandlerGate();
		assert.strictEqual(engine.isTrapHandlerGateActive(), false, 'precondition: gate OFF');

		const fn = await engine.analyzeFunction(img.entryVA, 'entry');
		// ud2 is isRet -> the function ends at/just after the first ud2; it must NOT reach the
		// final ret. This is the exact pre-v3.8.5 behaviour for genuine __builtin_trap binaries.
		assert.ok(fn.endAddress <= img.firstUd2VA + 2,
			`function truncates at the first ud2 (end=0x${fn.endAddress.toString(16)} <= 0x${(img.firstUd2VA + 2).toString(16)})`);
		const ud2Count = fn.instructions.filter((i: { mnemonic: string }) => i.mnemonic.toLowerCase() === 'ud2').length;
		assert.strictEqual(ud2Count, 1, 'only the terminating ud2 is included when the gate is off');
	});

	// --- REAL behindthescenes binary (runs only if the fixture exists) ---
	const realTest = fs.existsSync(REAL_BTS) ? test : test.skip;
	realTest('REAL behindthescenes: main grows past the ud2 separators to cover the whole body', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(120000); }
		const engine = new DisassemblerEngine() as any;
		const loaded = await engine.loadFile(REAL_BTS);
		assert.strictEqual(loaded, true, 'behindthescenes must load');
		await engine.analyzeAll();

		assert.strictEqual(engine.isTrapHandlerGateActive(), true,
			'gate ON: main installs sigaction(SIGILL=4)');

		const main = engine.getFunctions().find((f: { name: string }) => f.name === 'main');
		assert.ok(main, 'main discovered');
		// Was 135 bytes (truncated at the first ud2 @ 0x5555555552e6). Now the full body.
		assert.ok(main.size >= 460,
			`main covers the full body (size=${main.size} >= 460; pre-fix was 135)`);
		assert.ok(main.endAddress >= 0x55555555544e,
			`main extends to the real ret (end=0x${main.endAddress.toString(16)})`);

		// The hidden body's calls must now live INSIDE main: 4x strncmp (0x5555555550c0),
		// strlen (0x5555555550f0) and printf (0x555555555110).
		const callTargets = main.instructions
			.filter((i: { isCall: boolean; targetAddress?: number }) => i.isCall && i.targetAddress)
			.map((i: { targetAddress: number }) => i.targetAddress);
		const strncmpCalls = callTargets.filter((t: number) => t === 0x5555555550c0).length;
		assert.ok(strncmpCalls >= 4, `all 4 strncmp calls are inside main (found ${strncmpCalls})`);
		assert.ok(callTargets.includes(0x5555555550f0), 'strlen call inside main');
		assert.ok(callTargets.includes(0x555555555110), 'printf call inside main');

		// No interior ghost minted at the epilogue join (0x555555555439).
		assert.ok(!engine.getFunctions().some((f: { address: number }) => f.address === 0x555555555439),
			'no interior ghost function at the epilogue join target');
	});
});
