/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * IBT/CET `.plt.sec` PLT-stub naming + extent. v3.8.5.
 *
 * On modern PIE ELF (CET/IBT, the distro default) the linker emits BOTH a legacy `.plt`
 * (small stubs, keyed in _pltSymbolMap by their VA) AND an `endbr64`-guarded `.plt.sec` thunk
 * that the code actually CALLS. Function discovery lands functions at the `.plt.sec` VA, which
 * is NOT a _pltSymbolMap key, so two bugs followed:
 *
 *  (1) NAMING: `_pltSymbolMap.get(fn.address)` missed and the stub stayed `sub_<addr>` instead
 *      of `<symbol>@plt`. The fix: applyPltStubNames falls back to resolveStubSymbol(), which
 *      decodes the thunk's `bnd jmp *GOT(%rip)` and resolves it via _gotSymbolMap.
 *
 *  (2) EXTENT: a `.plt.sec` thunk is `endbr64 ; bnd jmp *GOT(%rip)` padded to a 16-byte stride.
 *      Capstone folds the BND prefix into the mnemonic ("bnd jmp"), so the wrapper reports
 *      isJump=false AND it is an indirect jump with no immediate target -- the function-end
 *      heuristic never terminates on it, so every `.plt.sec` thunk over-read into the next
 *      thunk and (under the trap-handler gate) all the way to the shared `hlt` padding at the
 *      section tail. The fix: an extent clamp (gated strictly to `.plt.sec`) ends the stub at
 *      its first `jmp`/`bnd jmp`. Legacy `.plt`/`.plt.got` and normal indirect jumps untouched.
 *
 * Reference (target): HTB "Behind the Scenes" (VeryEasy). `.plt.sec` at 0x5555555550c0..0x140,
 * 8x 16-byte thunks; pre-fix all over-read to a shared end ~0x555555555191/0x199.
 *
 * Two proofs:
 *   (1) SYNTHETIC buffers (always run) drive the engine via loadBuffer + a real Capstone decode.
 *   (2) The REAL behindthescenes binary (runs only when the fixture is present).
 */

import * as assert from 'assert';
import * as fs from 'fs';

/** Minimal vscode mock -- DisassemblerEngine imports 'vscode' for configuration. */
function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_pltsec__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_pltsec__'] = {
		id: '__vscode_mock_pltsec__',
		filename: '__vscode_mock_pltsec__',
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
 * Build a synthetic x64 image with a `.plt.sec`-style region of N 16-byte IBT thunks, each
 * `endbr64 ; bnd jmp *GOT[i](%rip)` followed by `0f 1f 44 00 00` nop padding, then a SHARED
 * `hlt` at the region tail (the over-read sink). The GOT slots map to the given symbols.
 *
 * Layout (in a single buffer; the engine's sections decide which range is `.plt.sec`):
 *   .plt.sec @ pltSecOff: N thunks (16 bytes each) + a trailing `hlt` pad.
 *   .got     @ gotOff:    N 8-byte slots.
 */
function buildPltSecImage(symbols: string[]): {
	buf: Buffer; pltSecVA: number; pltSecSize: number; gotVA: number; sharedHltVA: number;
	stubVAs: number[]; gotSymbolMap: Map<number, string>;
} {
	const n = symbols.length;
	const buf = Buffer.alloc(0x800, 0x00);
	const pltSecOff = 0x100;
	const gotOff = 0x400;
	const gotVA = BASE + gotOff;
	const stubVAs: number[] = [];
	const gotSymbolMap = new Map<number, string>();

	for (let i = 0; i < n; i++) {
		const off = pltSecOff + i * 16;
		const stubVA = BASE + off;
		stubVAs.push(stubVA);
		// endbr64
		buf[off + 0] = 0xf3; buf[off + 1] = 0x0f; buf[off + 2] = 0x1e; buf[off + 3] = 0xfa;
		// bnd jmp [rip + disp32]  (F2 prefix + FF 25 disp32)
		buf[off + 4] = 0xf2; buf[off + 5] = 0xff; buf[off + 6] = 0x25;
		// rip is past the 6-byte FF 25 disp32 instruction; insVA = stub+5, rip = insVA + 6.
		const insVA = stubVA + 5;
		const slotVA = gotVA + i * 8;
		buf.writeInt32LE(slotVA - (insVA + 6), off + 7);
		// nop padding (0f 1f 44 00 00) to fill the 16-byte stride (bytes off+11 .. off+15).
		buf[off + 11] = 0x0f; buf[off + 12] = 0x1f; buf[off + 13] = 0x44; buf[off + 14] = 0x00; buf[off + 15] = 0x00;
		gotSymbolMap.set(slotVA, symbols[i]);
	}
	// Shared `hlt` (0xf4) at the section tail -- the over-read sink the bug ran into.
	const hltOff = pltSecOff + n * 16;
	buf[hltOff] = 0xf4;
	const pltSecSize = (hltOff - pltSecOff) + 1; // thunks + the shared hlt

	return {
		buf, pltSecVA: BASE + pltSecOff, pltSecSize, gotVA,
		sharedHltVA: BASE + hltOff, stubVAs, gotSymbolMap
	};
}

/** Load a synthetic image with a `.plt.sec` section (+ a `.plt` legacy region for contrast). */
function loadSynthetic(img: ReturnType<typeof buildPltSecImage>, opts?: { legacyPltVA?: number; legacyPltSize?: number }): any {
	const engine = new DisassemblerEngine() as any;
	engine.loadBuffer(img.buf, BASE, 'x64');
	const sections: any[] = [{
		name: '.plt.sec', virtualAddress: img.pltSecVA, virtualSize: img.pltSecSize,
		rawAddress: img.pltSecVA - BASE, rawSize: img.pltSecSize, characteristics: 0,
		permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
	}];
	if (opts?.legacyPltVA !== undefined) {
		sections.push({
			name: '.plt', virtualAddress: opts.legacyPltVA, virtualSize: opts.legacyPltSize ?? 0x40,
			rawAddress: opts.legacyPltVA - BASE, rawSize: opts.legacyPltSize ?? 0x40, characteristics: 0,
			permissions: 'r-x', isCode: true, isData: false, isReadable: true, isWritable: false, isExecutable: true
		});
	}
	engine.sections = sections;
	engine._gotSymbolMap = new Map<number, string>(img.gotSymbolMap);
	engine._pltSymbolMap = new Map<number, string>();
	return engine;
}

suite('IBT/CET .plt.sec PLT-stub naming + extent (v3.8.5)', () => {

	test('isPltSecAddress is true inside .plt.sec only', () => {
		const img = buildPltSecImage(['puts']);
		const engine = loadSynthetic(img, { legacyPltVA: BASE + 0x80 });
		assert.strictEqual(engine.isPltSecAddress(img.stubVAs[0]), true, 'stub VA is in .plt.sec');
		assert.strictEqual(engine.isPltSecAddress(BASE + 0x80), false, 'legacy .plt VA is NOT .plt.sec');
		assert.strictEqual(engine.isPltSecAddress(BASE), false, 'outside any plt region');
	});

	test('EXTENT: a .plt.sec thunk clamps to its bnd jmp terminator, not the shared hlt', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const img = buildPltSecImage(['strncmp', 'puts', 'sigaction']);
		const engine = loadSynthetic(img);
		await engine.ensureCapstoneInitialized();

		for (let i = 0; i < img.stubVAs.length; i++) {
			const fn = await engine.analyzeFunction(img.stubVAs[i], undefined);
			// endbr64 (4) + bnd jmp (7) = 11 bytes; must NOT include the nop pad or run into the
			// next thunk / shared hlt.
			assert.ok(fn.size <= 16,
				`stub ${i} bounded to its 16-byte stride (size=${fn.size})`);
			assert.ok(fn.endAddress <= img.stubVAs[i] + 16,
				`stub ${i} ends within its own stride (end=0x${fn.endAddress.toString(16)})`);
			assert.ok(fn.endAddress < img.sharedHltVA,
				`stub ${i} does NOT over-read to the shared hlt at 0x${img.sharedHltVA.toString(16)}`);
			// The terminator is the bnd jmp; the shared hlt must not be inside the body.
			assert.ok(!fn.instructions.some((ins: { mnemonic: string }) => ins.mnemonic.toLowerCase() === 'hlt'),
				`stub ${i} body contains no hlt`);
		}
	});

	test('NAMING: applyPltStubNames falls back to resolveStubSymbol for .plt.sec thunks', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const symbols = ['strncmp', 'puts', 'sigaction'];
		const img = buildPltSecImage(symbols);
		const engine = loadSynthetic(img);
		await engine.ensureCapstoneInitialized();
		// _pltSymbolMap is EMPTY (the .plt.sec VA is not a key) but the legacy-.plt parse would
		// still have populated it for the real .plt; seed one entry so the ELF-gate (size>0) opens.
		engine._pltSymbolMap = new Map<number, string>([[BASE + 0xfff0, 'unrelated']]);

		// Discover the stubs as functions, then run the naming pass.
		for (const va of img.stubVAs) { await engine.analyzeFunction(va, undefined); }
		engine.applyPltStubNames();

		for (let i = 0; i < symbols.length; i++) {
			const fn = engine.getFunctions().find((f: { address: number }) => f.address === img.stubVAs[i]);
			assert.ok(fn, `stub ${i} discovered`);
			assert.strictEqual(fn.name, `${symbols[i]}@plt`,
				`stub ${i} named ${symbols[i]}@plt (was sub_*)`);
		}
	});

	test('NAMING: a user/session rename is preserved (only sub_* is replaced)', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(60000); }
		const img = buildPltSecImage(['puts']);
		const engine = loadSynthetic(img);
		await engine.ensureCapstoneInitialized();
		engine._pltSymbolMap = new Map<number, string>([[BASE + 0xfff0, 'unrelated']]);
		await engine.analyzeFunction(img.stubVAs[0], 'my_custom_name');
		engine.applyPltStubNames();
		const fn = engine.getFunctions().find((f: { address: number }) => f.address === img.stubVAs[0]);
		assert.strictEqual(fn.name, 'my_custom_name', 'a non-sub_* name is not overwritten');
	});

	// --- REAL behindthescenes binary (runs only if the fixture exists) ---
	const realTest = fs.existsSync(REAL_BTS) ? test : test.skip;
	realTest('REAL behindthescenes: .plt.sec thunks are named <symbol>@plt and do not over-read', async function () {
		// @ts-ignore mocha timeout
		if (typeof this?.timeout === 'function') { this.timeout(120000); }
		const engine = new DisassemblerEngine() as any;
		const loaded = await engine.loadFile(REAL_BTS);
		assert.strictEqual(loaded, true, 'behindthescenes must load');
		await engine.analyzeAll();

		const pltSec = engine.getSections().find((s: { name: string }) => s.name === '.plt.sec');
		assert.ok(pltSec, '.plt.sec section present (IBT/CET binary)');
		const secStart = pltSec.virtualAddress;
		const secEnd = pltSec.virtualAddress + pltSec.virtualSize;

		const funcs = engine.getFunctions();
		const stubs = funcs.filter((f: { address: number }) => f.address >= secStart && f.address < secEnd);
		assert.ok(stubs.length >= 7, `.plt.sec thunks discovered (found ${stubs.length})`);

		// Every imported stub called by main must now be `<symbol>@plt`, NOT sub_*.
		const wanted = ['sigaction', 'memset', 'sigemptyset', 'strncmp', 'strlen', 'printf', 'puts'];
		for (const w of wanted) {
			const hit = funcs.find((f: { name: string }) => f.name === `${w}@plt`);
			assert.ok(hit, `${w}@plt named (not sub_*)`);
			assert.ok(hit.address >= secStart && hit.address < secEnd, `${w}@plt is a .plt.sec thunk`);
		}

		// EXTENT: no .plt.sec thunk over-reads. Each is its own ~16-byte function; none reaches
		// the shared hlt at the section tail (pre-fix every stub ran to a shared end ~0x...191/199).
		for (const s of stubs) {
			assert.ok(s.size <= 16,
				`${s.name} bounded to its 16-byte stride (size=${s.size})`);
			assert.ok(s.endAddress <= secEnd,
				`${s.name} ends within .plt.sec (end=0x${s.endAddress.toString(16)} <= 0x${secEnd.toString(16)})`);
			assert.ok(s.endAddress <= 0x55555555516e,
				`${s.name} does NOT over-read into the shared hlt at 0x55555555516e (end=0x${s.endAddress.toString(16)})`);
		}
	});
});
