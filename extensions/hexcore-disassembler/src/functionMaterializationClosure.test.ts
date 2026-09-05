import * as assert from 'assert';
import type { Function } from './disassemblerEngine';

let DisassemblerEngine: any;

function installVscodeMock(): void {
	const Module = require('module');
	const originalResolveFilename = Module._resolveFilename;
	Module._resolveFilename = function (request: string, parent: unknown, isMain: boolean, options: unknown) {
		if (request === 'vscode') { return '__vscode_mock_materialization_closure__'; }
		return originalResolveFilename.call(this, request, parent, isMain, options);
	};
	require.cache['__vscode_mock_materialization_closure__'] = {
		id: '__vscode_mock_materialization_closure__',
		filename: '__vscode_mock_materialization_closure__',
		loaded: true,
		exports: {
			workspace: { getConfiguration: () => ({ get: (_key: string, fallback: unknown) => fallback }) },
			window: { createOutputChannel: () => ({ appendLine: () => undefined, dispose: () => undefined }) },
		},
	} as unknown as NodeModule;
}

function instruction(address: number, mnemonic: string, targetAddress?: number) {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic,
		opStr: targetAddress === undefined ? '' : `0x${targetAddress.toString(16)}`,
		size: 1,
		isCall: mnemonic === 'call',
		isJump: false,
		isRet: mnemonic === 'ret',
		isConditional: false,
		...(targetAddress === undefined ? {} : { targetAddress }),
	};
}

suite('incremental function materialization closure', () => {
	suiteSetup(() => {
		installVscodeMock();
		DisassemblerEngine = require('./disassemblerEngine').DisassemblerEngine;
	});

	test('commits a lazy body, rebuilds graph indexes, and advances both generations', async () => {
		const source: Function = {
			address: 0x401000, name: 'source', size: 2, endAddress: 0x401002,
			instructions: [], callers: [], callees: [],
		};
		const target: Function = {
			address: 0x402000, name: 'target', size: 1, endAddress: 0x402001,
			instructions: [instruction(0x402000, 'ret')], callers: [], callees: [],
		};
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[source.address, source], [target.address, target]]);
		engine.unmaterializedStubs = new Set([source.address]);
		engine.analysisGeneration = 4;
		engine.applyIatCallNames = () => { engine.iatIndexed = true; };
		engine.buildStringXrefs = () => { engine.stringXrefsIndexed = true; };
		engine.materializeFunction = async () => {
			source.instructions = [instruction(0x401000, 'call', target.address), instruction(0x401001, 'ret')];
			engine.unmaterializedStubs.delete(source.address);
			return source;
		};
		engine.sessionStore = {
			getAnalysisSession: () => ({ generation: 7 }),
			recordMaterializedFunction: () => ({ universeSha256: 'a'.repeat(64) }),
			advanceAnalysisGeneration: (_reason: string, _address: string) => ({ generation: 8 }),
		};

		const result = await engine.materializeFunctionForAnalysis(source.address);
		assert.strictEqual(result.status, 'committed');
		assert.strictEqual(result.changed, true);
		assert.strictEqual(result.instructionsAdded, 2);
		assert.strictEqual(result.engineGenerationBefore, 4);
		assert.strictEqual(result.engineGenerationAfter, 5);
		assert.strictEqual(result.sessionGenerationBefore, 7);
		assert.strictEqual(result.sessionGenerationAfter, 8);
		assert.deepStrictEqual(source.callees, [target.address]);
		assert.deepStrictEqual(target.callers, [0x401000]);
		assert.strictEqual(engine.iatIndexed, true);
		assert.strictEqual(engine.stringXrefsIndexed, true);
	});

	test('does not advance generation for an already materialized body', async () => {
		const fn: Function = {
			address: 0x403000, name: 'ready', size: 1, endAddress: 0x403001,
			instructions: [instruction(0x403000, 'ret')], callers: [], callees: [],
		};
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[fn.address, fn]]);
		engine.unmaterializedStubs = new Set();
		engine.analysisGeneration = 2;
		engine.sessionStore = { getAnalysisSession: () => ({ generation: 3 }) };

		const result = await engine.materializeFunctionForAnalysis(fn.address);
		assert.strictEqual(result.status, 'already-current');
		assert.strictEqual(result.changed, false);
		assert.strictEqual(result.engineGenerationAfter, 2);
		assert.strictEqual(result.sessionGenerationAfter, 3);
	});

	test('keeps decode-empty lazy so a transient failure can be retried', async () => {
		const fn: Function = {
			address: 0x404000, name: 'retryable', size: 1, endAddress: 0x404001,
			instructions: [], callers: [], callees: [],
		};
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[fn.address, fn]]);
		engine.unmaterializedStubs = new Set([fn.address]);
		engine.maxFunctionSize = 0x1000;
		let attempts = 0;
		engine.disassembleRange = async () => {
			attempts++;
			return attempts === 1 ? [] : [instruction(fn.address, 'ret')];
		};

		const first = await engine.materializeFunction(fn.address);
		assert.strictEqual(first?.instructions.length, 0);
		assert.strictEqual(engine.getFunctionBodyStatus(fn.address), 'decode-empty');
		const second = await engine.materializeFunction(fn.address);
		assert.strictEqual(second?.instructions.length, 1);
		assert.strictEqual(engine.getFunctionBodyStatus(fn.address), 'materialized');
		assert.strictEqual(attempts, 2);
	});

	test('keeps a partially decoded body retryable and display-only without advancing generations', async () => {
		const fn: Function = {
			address: 0x408000, name: 'partial', size: 4, endAddress: 0x408004,
			instructions: [], callers: [], callees: [],
		};
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[fn.address, fn]]);
		engine.unmaterializedStubs = new Set([fn.address]);
		engine.analysisGeneration = 9;
		engine.maxFunctionSize = 0x1000;
		engine.fileBuffer = Buffer.from([0x90, 0xc3, 0xff, 0xff]);
		engine.baseAddress = fn.address;
		engine.disassembleRange = async () => [instruction(fn.address, 'nop'), instruction(fn.address + 1, 'ret')];
		let recorded = false;
		engine.sessionStore = {
			getAnalysisSession: () => ({ generation: 12 }),
			recordMaterializedFunction: () => { recorded = true; throw new Error('partial body must not be persisted'); },
			advanceAnalysisGeneration: () => { throw new Error('partial body must not advance generation'); },
		};

		const result = await engine.materializeFunctionForAnalysis(fn.address);
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.changed, false);
		assert.strictEqual(result.engineGenerationAfter, 9);
		assert.strictEqual(result.sessionGenerationAfter, 12);
		assert.strictEqual(result.bodyCompleteness?.state, 'partial');
		assert.strictEqual(result.bodyCompleteness?.boundaryReached, false);
		assert.strictEqual(result.bodyCompleteness?.stopReason, 'decode-failure');
		assert.strictEqual(result.bodyCompleteness?.byteCoverage, 0.5);
		assert.strictEqual(engine.getFunctionBodyStatus(fn.address), 'partial');
		assert.strictEqual(engine.unmaterializedStubs.has(fn.address), true);
		assert.strictEqual(recorded, false);
	});

	test('uses the authoritative span instead of the 1000-instruction preview cap', async () => {
		const fn: Function = {
			address: 0x410000, name: 'large', size: 0x1800, endAddress: 0x411800,
			instructions: [], callers: [], callees: [],
		};
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[fn.address, fn]]);
		engine.unmaterializedStubs = new Set([fn.address]);
		engine.maxFunctionSize = 0x10000;
		let observedBudget = 0;
		engine.disassembleRange = async (_address: number, _size: number, budget: number) => {
			observedBudget = budget;
			return Array.from({ length: 1500 }, (_, index) => instruction(fn.address + index, index === 1499 ? 'ret' : 'nop'));
		};
		const materialized = await engine.materializeFunction(fn.address);
		assert.strictEqual(observedBudget, fn.size);
		assert.strictEqual(materialized?.instructions.length, 1500);
	});

	test('replays a persisted closure manifest without advancing its session generation', async () => {
		const source: Function = {
			address: 0x405000, name: 'persisted', size: 2, endAddress: 0x405002,
			instructions: [], callers: [], callees: [],
		};
		const target: Function = {
			address: 0x406000, name: 'callee', size: 1, endAddress: 0x406001,
			instructions: [instruction(0x406000, 'ret')], callers: [], callees: [],
		};
		const body = [instruction(0x405000, 'call', target.address), instruction(0x405001, 'ret')];
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[source.address, source], [target.address, target]]);
		engine.unmaterializedStubs = new Set([source.address]);
		source.instructions = body;
		const bodySha256 = engine.functionBodySha256(source);
		source.instructions = [];
		engine.materializeFunction = async () => {
			source.instructions = body;
			engine.unmaterializedStubs.delete(source.address);
			return source;
		};
		engine.applyIatCallNames = () => undefined;
		engine.sessionStore = {
			getAnalysisUniverseManifest: () => ({
				schemaVersion: 1, binarySha256: 'b'.repeat(64), universeSha256: 'c'.repeat(64), updatedAt: new Date().toISOString(),
				materializedFunctions: [{ address: '0x405000', endExclusive: '0x405002', bodySha256 }],
			}),
		};

		const restored = await engine.restorePersistedMaterializedFunctions();
		assert.strictEqual(restored.status, 'restored');
		assert.strictEqual(restored.restored, 1);
		assert.strictEqual(engine.getFunctionBodyStatus(source.address), 'materialized');
		assert.deepStrictEqual(source.callees, [target.address]);
		assert.deepStrictEqual(target.callers, [source.address]);
	});

	test('quarantines only incomplete restored bodies and preserves the complete manifest subset', async () => {
		const complete: Function = {
			address: 0x407000, name: 'complete', size: 1, endAddress: 0x407001,
			instructions: [], callers: [], callees: [],
		};
		const partial: Function = {
			address: 0x408000, name: 'partial', size: 4, endAddress: 0x408004,
			instructions: [], callers: [], callees: [],
		};
		const completeBody = [instruction(complete.address, 'ret')];
		const partialBody = [instruction(partial.address, 'ret')];
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		engine.functions = new Map([[complete.address, complete], [partial.address, partial]]);
		engine.unmaterializedStubs = new Set([complete.address, partial.address]);
		complete.instructions = completeBody;
		const completeHash = engine.functionBodySha256(complete);
		complete.instructions = [];
		partial.instructions = partialBody;
		const partialHash = engine.functionBodySha256(partial);
		partial.instructions = [];
		engine.materializeFunction = async (address: number) => {
			const fn = engine.functions.get(address);
			fn.instructions = address === complete.address ? completeBody : partialBody;
			fn.bodyCompleteness = address === complete.address
				? { state: 'complete', authoritativeStart: address, authoritativeEndExclusive: fn.endAddress, decodedEndExclusive: fn.endAddress, semanticEndExclusive: fn.endAddress, boundaryReached: true, stopReason: 'function-end', byteCoverage: 1 }
				: { state: 'partial', authoritativeStart: address, authoritativeEndExclusive: fn.endAddress, decodedEndExclusive: address + 1, semanticEndExclusive: address + 1, boundaryReached: false, stopReason: 'decode-failure', byteCoverage: 0.25 };
			if (address === complete.address) { engine.unmaterializedStubs.delete(address); }
			return fn;
		};
		engine.applyIatCallNames = () => undefined;
		let acceptedEntries: Array<{ address: string }> = [];
		engine.sessionStore = {
			getAnalysisUniverseManifest: () => ({
				schemaVersion: 1, binarySha256: 'b'.repeat(64), universeSha256: 'c'.repeat(64), updatedAt: new Date().toISOString(),
				materializedFunctions: [
					{ address: '0x407000', endExclusive: '0x407001', bodySha256: completeHash },
					{ address: '0x408000', endExclusive: '0x408004', bodySha256: partialHash },
				],
			}),
			replaceAnalysisUniverseManifest: (entries: Array<{ address: string }>) => {
				acceptedEntries = entries;
				return { universeSha256: 'd'.repeat(64) };
			},
			advanceAnalysisGeneration: () => ({ generation: 9 }),
		};

		const restored = await engine.restorePersistedMaterializedFunctions();
		assert.strictEqual(restored.status, 'partial');
		assert.strictEqual(restored.requested, 2);
		assert.strictEqual(restored.restored, 1);
		assert.strictEqual(restored.universeSha256, 'd'.repeat(64));
		assert.deepStrictEqual(acceptedEntries.map(entry => entry.address), ['0x407000']);
		assert.strictEqual(engine.getFunctionBodyStatus(complete.address), 'materialized');
		assert.strictEqual(engine.getFunctionBodyStatus(partial.address), 'partial');
	});

	test('advances a legacy generation that has no replayable universe manifest', async () => {
		const engine = Object.create(DisassemblerEngine.prototype) as any;
		const writes: Array<[string, string]> = [];
		engine.sessionStore = {
			getAnalysisUniverseManifest: () => undefined,
			getAnalysisSession: () => ({ generation: 7 }),
			getMeta: () => undefined,
			resetAnalysisUniverseManifest: () => ({ universeSha256: 'd'.repeat(64) }),
			startReanalysis: () => ({ generation: 8 }),
			setMeta: (key: string, value: string) => writes.push([key, value]),
		};

		const result = await engine.restorePersistedMaterializedFunctions();
		assert.strictEqual(result.status, 'reset');
		assert.strictEqual(result.universeSha256, 'd'.repeat(64));
		assert.match(result.failed[0], /no replayable universe manifest/);
		assert.strictEqual(writes[0][0], 'analysis_generation_universe_json');
		assert.match(writes[0][1], /"generation":8/);
	});

	test('round-trips the materialized audit universe through a target-bound snapshot', () => {
		const source = new DisassemblerEngine() as any;
		const bytes = Buffer.from([0x90, 0xc3]);
		source.fileBuffer = bytes;
		source.baseAddress = 0x401000;
		source.architecture = 'x64';
		source.fileInfo = { format: 'PE64', architecture: 'x64', entryPoint: 0x401000, imageBase: 0x400000 };
		const fn: Function = {
			address: 0x401000, name: 'entry', size: 2, endAddress: 0x401002,
			instructions: [instruction(0x401000, 'ret')], callers: [], callees: [],
		};
		source.functions = new Map([[fn.address, fn]]);
		source.instructions = new Map([[fn.address, fn.instructions[0]]]);
		source.strings = new Map([[0x402000, { address: 0x402000, string: 'path', encoding: 'ascii', references: [0x401000] }]]);
		source.comments = new Map([[0x401000, 'entry']]);
		source.xrefs = new Map([[0x402000, [{ from: 0x401000, to: 0x402000, type: 'string' }]]]);
		source.analysisComplete = true;
		source.analysisGeneration = 9;
		source.closureRestoration = { status: 'restored', requested: 1, restored: 1, failed: [], universeSha256: 'a'.repeat(64) };

		const snapshot = source.exportAnalysisSnapshot();
		const restored = new DisassemblerEngine() as any;
		restored.fileBuffer = Buffer.from(bytes);
		restored.importAnalysisSnapshot(snapshot);

		assert.strictEqual(restored.getFunctions().length, 1);
		assert.strictEqual(restored.getFunctions()[0].instructions[0].mnemonic, 'ret');
		assert.strictEqual(restored.getStrings()[0].string, 'path');
		assert.strictEqual(restored.getAnalysisGeneration(), 9);
		assert.strictEqual(restored.getAnalysisClosureRestoration().universeSha256, 'a'.repeat(64));
		assert.throws(() => {
			const wrongTarget = new DisassemblerEngine() as any;
			wrongTarget.fileBuffer = Buffer.from([0xcc]);
			wrongTarget.importAnalysisSnapshot(snapshot);
		}, /target identity/);
	});
});
