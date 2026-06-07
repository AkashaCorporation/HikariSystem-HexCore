/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * MSVC chained-unwind .pdata fragment merge (v3.8.2 FIX-027 / FIX-027b).
 *
 * Pins `reconcileFunctionsWithPdata` in disassemblerEngine.ts. A large/optimized x64
 * function is emitted by MSVC as several CONTIGUOUS RUNTIME_FUNCTION records
 * (end[i] == begin[i+1]); every continuation fragment's UNWIND_INFO carries
 * UNW_FLAG_CHAININFO (0x4) plus a trailing RUNTIME_FUNCTION chaining back to the PRIMARY.
 * The pre-FIX-027 code dropped only FULLY NESTED records, so contiguous fragments each
 * survived as a SEPARATE function. That fragmented the table AND truncated the Remill
 * lift: extension.ts injects every function end into knownFunctionEnds and the PE64 scan
 * breaks at the first one (observed on SOTTR sub_140253A70: 6 fragments -> lift stopped at
 * 0x49 of 0x2bd bytes). FIX-027 merges the chain; FIX-027b (the adversarial-review follow-up)
 * closes: #1 extend-UP a pre-discovered short primary to its merged end (else the lift still
 * truncates), #2/#3 never DROP an orphan / non-contiguous continuation, #4 duplicate-begin,
 * #5 out-of-section UNWIND_INFO.
 *
 * The real targets live outside the repo, so the cases are reproduced as synthetic PEs:
 * a flat .text section (RVA == file offset) holding NOP bodies + hand-built UNWIND_INFO
 * records, driven directly through the engine's table (matching the other engine tests).
 */

import * as assert from 'assert';
import 'mocha';
import { DisassemblerEngine } from './disassemblerEngine';

const BASE = 0x140000000;

interface Frag { begin: number; end: number; chainTo?: number; } // RVAs (chainTo = primary RVA)

/**
 * Build a synthetic x64 PE engine: a flat 64 KiB .text (RVA == file offset) of NOPs, with a
 * hand-built UNWIND_INFO per fragment (non-chained primary, or CHAININFO continuation whose
 * trailing RUNTIME_FUNCTION points at `chainTo`). Returns the engine plus the .pdata entries.
 */
function buildEngine(frags: Frag[], seed: { address: number; endAddress: number }[] = []): {
	engine: DisassemblerEngine;
	reconcile: () => Promise<void>;
} {
	const buf = Buffer.alloc(0x10000, 0x90); // NOP fill so disassembleRange always decodes
	const pdata: { beginAddress: number; endAddress: number; unwindInfoAddress: number }[] = [];

	frags.forEach((f, i) => {
		const uwRva = 0x8000 + i * 0x20; // UNWIND_INFO slot (inside .text, RVA == file offset)
		if (f.chainTo === undefined) {
			buf[uwRva] = 0x01;             // version 1, flags 0 (primary)
		} else {
			buf[uwRva] = (0x4 << 3) | 0x1; // version 1, UNW_FLAG_CHAININFO
			buf[uwRva + 1] = 0;            // SizeOfProlog
			buf[uwRva + 2] = 0;            // CountOfUnwindCodes (-> trailing RUNTIME_FUNCTION at +4)
			buf[uwRva + 3] = 0;
			buf.writeUInt32LE(f.chainTo, uwRva + 4);       // chained-to BeginAddress
			buf.writeUInt32LE(f.chainTo + 1, uwRva + 8);   // (EndAddress, unused by readChain)
			buf.writeUInt32LE(0x8000, uwRva + 12);         // (UnwindData, unused)
		}
		pdata.push({ beginAddress: f.begin, endAddress: f.end, unwindInfoAddress: uwRva });
	});

	const engine = new DisassemblerEngine() as unknown as {
		architecture: string; baseAddress: number; fileBuffer: Buffer;
		sections: { name: string; virtualAddress: number; virtualSize: number; rawAddress: number }[];
		peDataDirectories: { pdata: unknown[] };
		functions: Map<number, { address: number; name: string; size: number; endAddress: number; instructions: unknown[]; callers: number[]; callees: number[] }>;
		reconcileFunctionsWithPdata: () => Promise<void>;
	};
	engine.architecture = 'x64';
	engine.baseAddress = BASE;
	engine.fileBuffer = buf;
	engine.sections = [{ name: '.text', virtualAddress: BASE, virtualSize: 0x10000, rawAddress: 0 }];
	engine.peDataDirectories = { pdata };
	const map = new Map<number, { address: number; name: string; size: number; endAddress: number; instructions: unknown[]; callers: number[]; callees: number[] }>();
	for (const s of seed) {
		map.set(s.address, {
			address: s.address, name: `sub_${s.address.toString(16)}`, size: s.endAddress - s.address,
			endAddress: s.endAddress, instructions: [{ address: s.address, size: 1, isCall: false }], callers: [], callees: []
		});
	}
	engine.functions = map;
	return { engine: engine as unknown as DisassemblerEngine, reconcile: () => engine.reconcileFunctionsWithPdata() };
}

function funcs(engine: DisassemblerEngine): Map<number, { address: number; endAddress: number }> {
	const m = new Map<number, { address: number; endAddress: number }>();
	for (const f of engine.getFunctions()) { m.set(f.address, { address: f.address, endAddress: f.endAddress }); }
	return m;
}

suite('MSVC chained-unwind .pdata fragment merge (v3.8.2 FIX-027 / FIX-027b)', () => {

	test('merges contiguous CHAININFO fragments into ONE function spanning the merged .pdata end', async () => {
		// [1000,1010) primary + [1010,1030) chained-to-1000 -> one function [1000,1030)
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1000, end: 0x1010 },
			{ begin: 0x1010, end: 0x1030, chainTo: 0x1000 }
		]);
		await reconcile();
		const m = funcs(engine);
		assert.ok(m.has(BASE + 0x1000), 'primary kept');
		assert.strictEqual(m.get(BASE + 0x1000)!.endAddress, BASE + 0x1030, 'primary spans the merged end');
		assert.ok(!m.has(BASE + 0x1010), 'continuation fragment is NOT a separate function');
	});

	test('#1 extend-UP: a pre-discovered SHORT primary is grown to the merged .pdata end', async () => {
		// Prologue scan discovered the primary ending early at 0x1010 (interior ret); the real
		// chained-unwind function runs to 0x1030. Without extend-up, knownFunctionEnds would
		// carry 0x1010 and the PE64 lift would re-truncate.
		const { engine, reconcile } = buildEngine(
			[{ begin: 0x1000, end: 0x1010 }, { begin: 0x1010, end: 0x1030, chainTo: 0x1000 }],
			[{ address: BASE + 0x1000, endAddress: BASE + 0x1010 }] // SHORT pre-discovery
		);
		await reconcile();
		const fn = funcs(engine).get(BASE + 0x1000);
		assert.ok(fn, 'primary kept');
		assert.strictEqual(fn!.endAddress, BASE + 0x1030, 'short primary extended UP to the merged .pdata end');
	});

	test('does NOT merge two DISTINCT adjacent NON-chained primaries', async () => {
		// Two real functions that happen to be contiguous (no CHAININFO) must stay separate.
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1000, end: 0x1010 },
			{ begin: 0x1010, end: 0x1030 }
		]);
		await reconcile();
		const m = funcs(engine);
		assert.ok(m.has(BASE + 0x1000), 'first primary kept');
		assert.ok(m.has(BASE + 0x1010), 'second adjacent primary kept (NOT absorbed)');
	});

	test('#2 no-drop: an ORPHAN continuation (primary absent from the table) stays a function', async () => {
		// CHAININFO points to 0x1000 but there is no .pdata entry there; the fragment must not
		// vanish (pre-FIX-027 kept it; FIX-027b must not regress that coverage).
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1010, end: 0x1030, chainTo: 0x1000 }
		]);
		await reconcile();
		assert.ok(funcs(engine).has(BASE + 0x1010), 'orphan continuation kept (code not dropped)');
	});

	test('multi-level chain (B->A primary) merges the whole run', async () => {
		// [1000,1010) primary ; [1010,1020) chained->1000 ; [1020,1030) chained->1010 (transitive)
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1000, end: 0x1010 },
			{ begin: 0x1010, end: 0x1020, chainTo: 0x1000 },
			{ begin: 0x1020, end: 0x1030, chainTo: 0x1010 }
		]);
		await reconcile();
		const m = funcs(engine);
		assert.strictEqual(m.get(BASE + 0x1000)!.endAddress, BASE + 0x1030, 'whole transitive chain merged');
		assert.ok(!m.has(BASE + 0x1010) && !m.has(BASE + 0x1020), 'no fragment survives as its own function');
	});

	test('GATE: non-x64 architecture is a no-op (ARM64 .pdata 2nd DWORD is not an EndAddress)', async () => {
		const { engine, reconcile } = buildEngine(
			[{ begin: 0x1000, end: 0x1010 }, { begin: 0x1010, end: 0x1030, chainTo: 0x1000 }],
			[{ address: BASE + 0x1010, endAddress: BASE + 0x1030 }]
		);
		(engine as unknown as { architecture: string }).architecture = 'arm64';
		await reconcile();
		// untouched: the seeded fragment-function is still present, no merge happened
		assert.ok(funcs(engine).has(BASE + 0x1010), 'ARM64 PE left untouched by the x64-only merge');
	});
});
