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
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import 'mocha';
import type { DisassemblerEngine as DisassemblerEngineType } from './disassemblerEngine';

function installVscodeMock(): void {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (
		request: string,
		parent: unknown,
		isMain: boolean,
		options: unknown
	) {
		if (request === 'vscode') {
			return '__vscode_mock_pdata_chain__';
		}
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_pdata_chain__'] = {
		id: '__vscode_mock_pdata_chain__',
		filename: '__vscode_mock_pdata_chain__',
		loaded: true,
		exports: {
			workspace: {
				getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }),
			},
		},
	} as unknown as NodeModule;
}

installVscodeMock();
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { DisassemblerEngine } = require('./disassemblerEngine') as {
	DisassemblerEngine: typeof DisassemblerEngineType;
};
type DisassemblerEngine = DisassemblerEngineType;

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
		sections: { name: string; virtualAddress: number; virtualSize: number; rawAddress: number; rawSize: number; isCode: boolean }[];
		peDataDirectories: { pdata: unknown[] };
		functions: Map<number, { address: number; name: string; size: number; endAddress: number; instructions: unknown[]; callers: number[]; callees: number[] }>;
		ensurePdataFunctionsReconciled: () => Promise<void>;
	};
	engine.architecture = 'x64';
	engine.baseAddress = BASE;
	engine.fileBuffer = buf;
	engine.sections = [{
		name: '.text', virtualAddress: BASE, virtualSize: 0x10000,
		rawAddress: 0, rawSize: 0x10000, isCode: true
	}];
	engine.peDataDirectories = { pdata };
	const map = new Map<number, { address: number; name: string; size: number; endAddress: number; instructions: unknown[]; callers: number[]; callees: number[] }>();
	for (const s of seed) {
		map.set(s.address, {
			address: s.address, name: `sub_${s.address.toString(16)}`, size: s.endAddress - s.address,
			endAddress: s.endAddress, instructions: [{ address: s.address, size: 1, isCall: false }], callers: [], callees: []
		});
	}
	engine.functions = map;
	return { engine: engine as unknown as DisassemblerEngine, reconcile: () => engine.ensurePdataFunctionsReconciled() };
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
		await reconcile(); // hot lift and a later caller may both cross the barrier
		const m = funcs(engine);
		assert.ok(m.has(BASE + 0x1000), 'primary kept');
		assert.strictEqual(m.get(BASE + 0x1000)!.endAddress, BASE + 0x1030, 'primary spans the merged end');
		assert.ok(!m.has(BASE + 0x1010), 'continuation fragment is NOT a separate function');
		assert.deepStrictEqual(
			engine.findAuthoritativePdataRangeContaining(BASE + 0x1025),
			{ begin: BASE + 0x1000, end: BASE + 0x1030 },
			'an address inside a chained continuation resolves to the primary range'
		);
	});

	test('authoritative containment includes mid-instruction addresses and excludes the end boundary', async () => {
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1000, end: 0x1100 },
			{ begin: 0x1100, end: 0x1120 }
		]);
		await reconcile();

		assert.deepStrictEqual(
			engine.findAuthoritativePdataRangeContaining(BASE + 0x1082),
			{ begin: BASE + 0x1000, end: BASE + 0x1100 },
			'containment does not require an instruction boundary'
		);
		assert.deepStrictEqual(
			engine.findAuthoritativePdataRangeContaining(BASE + 0x1100),
			{ begin: BASE + 0x1100, end: BASE + 0x1120 },
			'the exclusive end belongs to the adjacent function when it is its begin'
		);
		assert.strictEqual(
			engine.findAuthoritativePdataRangeContaining(BASE + 0x1120),
			undefined,
			'the final end is exclusive'
		);
	});

	test('a heuristic container cannot delete an entry point outside .pdata', async () => {
		const entry = BASE + 0x1080;
		const { engine, reconcile } = buildEngine(
			[{ begin: 0x2000, end: 0x2040 }],
			[
				{ address: BASE + 0x1000, endAddress: BASE + 0x1100 },
				{ address: entry, endAddress: entry + 5 }
			]
		);
		const internals = engine as unknown as {
			fileInfo: { entryPoint: number };
			functions: Map<number, { name: string }>;
		};
		internals.fileInfo = { entryPoint: entry };
		internals.functions.get(entry)!.name = 'entry_point';

		await reconcile();
		const result = funcs(engine);
		assert.ok(!result.has(BASE + 0x1000), 'earlier false container removed');
		assert.ok(result.has(entry), 'entry point preserved as its own function');
	});

	test('parser accepts a valid Exception Directory beyond the former 250K ceiling', () => {
		const count = 250001;
		const buffer = Buffer.alloc(count * 12);
		for (let i = 0; i < count; i++) {
			const offset = i * 12;
			const begin = i * 2 + 1;
			buffer.writeUInt32LE(begin, offset);
			buffer.writeUInt32LE(begin + 1, offset + 4);
		}
		const engine = new DisassemblerEngine() as unknown as {
			fileBuffer: Buffer;
			rvaToFileOffset: (_rva: number) => number;
			parsePdataDirectory: (rva: number, size: number) => void;
			getPdataEntries: () => unknown[];
			getPdataDiagnostics: () => { declaredEntries: number; parsedEntries: number; truncated: boolean };
		};
		engine.fileBuffer = buffer;
		engine.rvaToFileOffset = () => 0;
		engine.parsePdataDirectory(1, buffer.length);

		assert.strictEqual(engine.getPdataEntries().length, count);
		assert.deepStrictEqual(engine.getPdataDiagnostics(), {
			declaredEntries: count,
			parsedEntries: count,
			truncated: false
		});
	});

	test('analyzeAll restores cached boundaries as lazy stubs even after entry discovery', async () => {
		const existing = BASE + 0x1000;
		const cached = BASE + 0x2000;
		const { engine } = buildEngine([], [{ address: existing, endAddress: existing + 5 }]);
		let persisted = 0;
		const internals = engine as unknown as {
			sessionStore: {
				getCachedFunctions: () => Array<{ address: string; name: string; size: number; end_address: number }>;
				replaceCachedFunctions: (entries: Iterable<unknown>) => void;
				getAnalysisUniverseManifest: () => undefined;
				getAnalysisSession: () => undefined;
				getMeta: (_key: string) => undefined;
			};
			scanForFunctionPrologs: () => Promise<void>;
			unmaterializedStubs: Set<number>;
		};
		internals.sessionStore = {
			getCachedFunctions: () => [{
				address: `0x${cached.toString(16)}`,
				name: 'cached_fn',
				size: 0x20,
				end_address: cached + 0x20
			}],
			replaceCachedFunctions: entries => {
				persisted = Array.from(entries).length;
			},
			getAnalysisUniverseManifest: () => undefined,
			getAnalysisSession: () => undefined,
			getMeta: () => undefined,
		};
		internals.scanForFunctionPrologs = async () => undefined;

		await engine.analyzeAll({ useCachedFunctions: true });
		const restored = engine.getFunctionAt(cached);
		assert.ok(restored, 'cached boundary restored despite an existing entry function');
		assert.strictEqual(restored!.instructions.length, 0, 'body remains lazy');
		assert.ok(internals.unmaterializedStubs.has(cached));
		assert.strictEqual(persisted, 2, 'cache replacement receives the complete table');
	});

	test('a rediscovered cached boundary materializes instead of returning a hollow function', async () => {
		const cached = BASE + 0x2000;
		const { engine } = buildEngine([]);
		const internals = engine as unknown as {
			sessionStore: {
				getCachedFunctions: () => Array<{ address: string; name: string; size: number; end_address: number }>;
				replaceCachedFunctions: (_entries: Iterable<unknown>) => void;
				getAnalysisUniverseManifest: () => undefined;
				getAnalysisSession: () => undefined;
				getMeta: (_key: string) => undefined;
			};
			scanForFunctionPrologs: () => Promise<void>;
			disassembleRange: (address: number, size: number) => Promise<Array<{
				address: number; size: number; bytes: Buffer; mnemonic: string; opStr: string; isCall: boolean;
			}>>;
		};
		internals.sessionStore = {
			getCachedFunctions: () => [{
				address: `0x${cached.toString(16)}`,
				name: 'cached_fn',
				size: 0x20,
				end_address: cached + 0x20
			}],
			replaceCachedFunctions: () => undefined,
			getAnalysisUniverseManifest: () => undefined,
			getAnalysisSession: () => undefined,
			getMeta: () => undefined,
		};
		internals.scanForFunctionPrologs = async () => {
			await engine.analyzeFunction(cached);
		};
		internals.disassembleRange = async address => [{
			address,
			size: 1,
			bytes: Buffer.from([0x90]),
			mnemonic: 'nop',
			opStr: '',
			isCall: false
		}];

		await engine.analyzeAll();
		const restored = engine.getFunctionAt(cached);
		assert.ok(restored);
		assert.strictEqual(restored!.instructions.length, 1);
		assert.strictEqual(engine.getFunctionBodyStatus(cached), 'materialized');
	});

	test('full assembly export materializes lazy bodies and reports decode completeness', async () => {
		const start = BASE + 0x1000;
		const { engine, reconcile } = buildEngine([{ begin: 0x1000, end: 0x1020 }]);
		await reconcile();
		const internals = engine as unknown as {
			disassembleRange: (address: number, size: number) => Promise<Array<{
				address: number; size: number; bytes: Buffer; mnemonic: string; opStr: string; isCall: boolean;
			}>>;
		};
		internals.disassembleRange = async address => [{
			address,
			size: 1,
			bytes: Buffer.from([0x90]),
			mnemonic: 'nop',
			opStr: '',
			isCall: false
		}];
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-asm-export-'));
		const output = path.join(dir, 'body.asm');
		try {
			const result = await engine.exportAssembly(output);
			assert.strictEqual(result.status, 'partial');
			assert.strictEqual(result.functionsWithInstructions, 1);
			assert.strictEqual(result.functionsWithoutInstructions, 0);
			assert.strictEqual(result.decodedInstructions, 1);
			assert.match(fs.readFileSync(output, 'utf8'), /nop/);
			assert.strictEqual(result.incompleteFunctions.length, 1);
			assert.strictEqual(engine.getFunctionBodyStatus(start), 'partial', 'partial decode remains explicit and retryable after streaming');
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('full assembly export reports partial when a requested body decodes empty', async () => {
		const { engine, reconcile } = buildEngine([{ begin: 0x1000, end: 0x1020 }]);
		await reconcile();
		const internals = engine as unknown as {
			disassembleRange: (_address: number, _size: number) => Promise<[]>;
		};
		internals.disassembleRange = async () => [];
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-asm-partial-'));
		try {
			const result = await engine.exportAssembly(path.join(dir, 'empty.asm'));
			assert.strictEqual(result.status, 'partial');
			assert.strictEqual(result.functionsWithInstructions, 0);
			assert.strictEqual(result.functionsWithoutInstructions, 1);
			assert.deepStrictEqual(result.emptyFunctions.map(fn => fn.reason), ['decode-empty']);
		} finally {
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});

	test('materializing a partial body never shrinks its authoritative .pdata range', async () => {
		const start = BASE + 0x1000;
		const end = BASE + 0x3000;
		const { engine, reconcile } = buildEngine([{ begin: 0x1000, end: 0x3000 }]);
		await reconcile();

		const internals = engine as unknown as {
			disassembleRange: (address: number, size: number) => Promise<Array<{ address: number; size: number; isCall: boolean }>>;
		};
		internals.disassembleRange = async address => Array.from({ length: 1000 }, (_, index) => ({
			address: address + index,
			size: 1,
			isCall: false
		}));

		const materialized = await engine.materializeFunction(start);
		assert.ok(materialized);
		assert.strictEqual(materialized!.instructions.length, 1000, 'body preview remains bounded');
		assert.strictEqual(materialized!.endAddress, end, 'authoritative end survives partial decoding');
		assert.strictEqual(materialized!.size, end - start, 'authoritative size survives partial decoding');
		assert.strictEqual(engine.getFunctionBodyStatus(start), 'partial');
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

	test('normalizes partially overlapping non-chained records at the later begin', async () => {
		const { engine, reconcile } = buildEngine([
			{ begin: 0x1000, end: 0x1040 },
			{ begin: 0x1020, end: 0x1060 }
		]);
		await reconcile();

		assert.deepStrictEqual(engine.getAuthoritativePdataRanges(), [
			{ begin: BASE + 0x1000, end: BASE + 0x1020 },
			{ begin: BASE + 0x1020, end: BASE + 0x1060 }
		]);
		assert.strictEqual(funcs(engine).get(BASE + 0x1000)!.endAddress, BASE + 0x1020);
		assert.strictEqual(funcs(engine).get(BASE + 0x1020)!.endAddress, BASE + 0x1060);
	});

	test('folds an interior export alias into its owning authoritative function', async () => {
		const owner = BASE + 0x1000;
		const alias = BASE + 0x1020;
		const { engine, reconcile } = buildEngine(
			[
				{ begin: 0x1000, end: 0x1040 },
				{ begin: 0x1020, end: 0x1040 }
			],
			[
				{ address: owner, endAddress: BASE + 0x1040 },
				{ address: alias, endAddress: BASE + 0x1040 }
			]
		);
		const internals = engine as unknown as {
			exports: Array<{ name: string; address: number; ordinal: number; isForwarder: boolean }>;
		};
		internals.exports = [{ name: 'export_alias', address: alias, ordinal: 1, isForwarder: false }];

		await reconcile();
		assert.strictEqual(engine.getFunctionAt(alias), undefined, 'interior alias is not a second overlapping function');
		assert.strictEqual(engine.getFunctionAt(owner)?.name, 'export_alias', 'alias name is retained on the owner');
	});

	test('clamps an exported leaf without .pdata at the next authoritative begin', async () => {
		const exportedLeaf = BASE + 0x1000;
		const pdataBegin = BASE + 0x1020;
		const { engine, reconcile } = buildEngine(
			[{ begin: 0x1020, end: 0x1060 }],
			[{ address: exportedLeaf, endAddress: BASE + 0x1040 }]
		);
		const internals = engine as unknown as {
			exports: Array<{ name: string; address: number; ordinal: number; isForwarder: boolean }>;
		};
		internals.exports = [{ name: 'leaf_export', address: exportedLeaf, ordinal: 1, isForwarder: false }];

		await reconcile();
		assert.strictEqual(engine.getFunctionAt(exportedLeaf)?.endAddress, pdataBegin);
		assert.strictEqual(engine.getFunctionAt(exportedLeaf)?.name, 'leaf_export');
		assert.strictEqual(engine.getFunctionAt(pdataBegin)?.endAddress, BASE + 0x1060);
	});

	test('uses the next exported leaf as an authoritative boundary', async () => {
		const first = BASE + 0x1000;
		const second = BASE + 0x1020;
		const { engine, reconcile } = buildEngine(
			[{ begin: 0x1100, end: 0x1140 }],
			[
				{ address: first, endAddress: BASE + 0x1040 },
				{ address: second, endAddress: BASE + 0x1040 }
			]
		);
		const internals = engine as unknown as {
			exports: Array<{ name: string; address: number; ordinal: number; isForwarder: boolean }>;
		};
		internals.exports = [
			{ name: 'first_leaf', address: first, ordinal: 1, isForwarder: false },
			{ name: 'second_leaf', address: second, ordinal: 2, isForwarder: false }
		];

		await reconcile();
		assert.strictEqual(engine.getFunctionAt(first)?.endAddress, second);
		assert.strictEqual(engine.getFunctionAt(second)?.endAddress, BASE + 0x1040);
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
		assert.strictEqual(
			engine.findAuthoritativePdataRangeContaining(BASE + 0x1015),
			undefined,
			'ARM64 packed unwind records are never exposed as AMD64 authoritative ranges'
		);
	});
});
