/*---------------------------------------------------------------------------------------------
 * FIX-QUALITY-001: Helix packaging helpers — unit tests
 *---------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	extractCalleeAddressesFromIr,
	resolveHelixBaseOptions,
	buildHelixFunctionStarts,
	wantsHelixFunctionStarts,
	resolveLiftByteSize,
	assessByteRangeCompletion,
	assessLiftRangeCompletion,
	isBacktrackWithinSection,
	coercePositiveInt,
	getAuthoritativeFunctionExtent,
	shouldHonorExplicitLiftWindow,
	hasHeadlessHelixIrInput,
} from './helixPackaging';

function makeEngineStub(opts: {
	functions?: Array<{ address: number }>;
	imports?: Array<{ functions: Array<{ address: number }> }>;
	exports?: Array<{ address: number }>;
}): any {
	return {
		getFunctions: () => opts.functions ?? [],
		getImports: () => opts.imports ?? [],
		getExports: () => opts.exports ?? [],
	};
}

suite('FIX-QUALITY-001 Helix packaging', () => {
	test('exact half-open range completion rejects both under-run and crossing', () => {
		assert.deepStrictEqual(assessByteRangeCompletion(2090, 2090), {
			status: 'ok', reached: true, crossed: false, coverage: 1,
		});
		const short = assessByteRangeCompletion(2068, 2090);
		assert.strictEqual(short.status, 'partial');
		assert.strictEqual(short.reached, false);
		assert.strictEqual(short.crossed, false);
		assert.match(short.reason ?? '', /not reached/);
		const crossed = assessByteRangeCompletion(2091, 2090);
		assert.strictEqual(crossed.status, 'partial');
		assert.strictEqual(crossed.reached, true);
		assert.strictEqual(crossed.crossed, true);
	});

	test('recursive-descent completion does not mistake decoded-byte union size for an endpoint', () => {
		const complete = assessLiftRangeCompletion({
			startAddress: 0x14018D720,
			endExclusive: 0x14018DF4A,
			semanticEndExclusive: 0x14018DF4A,
			pathfinderOwnershipEnd: 0x14018DF4A,
			nativeTruncated: false,
		});
		assert.deepStrictEqual(
			{ status: complete.status, reached: complete.reached, crossed: complete.crossed },
			{ status: 'ok', reached: true, crossed: false },
		);

		const truncated = assessLiftRangeCompletion({
			startAddress: 0x14018D720,
			endExclusive: 0x14018DF4A,
			semanticEndExclusive: 0x14018DF4A,
			pathfinderOwnershipEnd: 0x14018DF4A,
			nativeTruncated: true,
		});
		assert.strictEqual(truncated.status, 'partial');
		assert.match(truncated.reason ?? '', /configured limit/);
	});
	test('decompileIR treats irPath as headless input', () => {
		assert.strictEqual(hasHeadlessHelixIrInput({ irPath: 'lifted.ll' }), true);
		assert.strictEqual(hasHeadlessHelixIrInput({ irText: 'define void @f() {}' }), true);
		assert.strictEqual(hasHeadlessHelixIrInput({ file: 'lifted.ll' }), true);
		assert.strictEqual(hasHeadlessHelixIrInput({ quiet: true }), false);
		assert.strictEqual(hasHeadlessHelixIrInput(undefined), false);
	});

	test('extractCalleeAddressesFromIr finds @sub_hex and @lifted_decimal', () => {
		const ir = `
define ptr @lifted_5368865820() {
  call void @sub_14002c6e0(i64 1)
  call void @sub_14002C6D7(i64 2)
  call void @lifted_5368891104()
  ret void
}
`;
		const addrs = extractCalleeAddressesFromIr(ir);
		assert.ok(addrs.includes(0x14002c6e0), 'sub_14002c6e0');
		assert.ok(addrs.includes(0x14002c6d7), 'sub_14002C6D7');
		assert.ok(addrs.includes(5368865820), 'lifted_ entry');
		assert.ok(addrs.includes(5368891104), 'lifted_ callee');
	});

	test('extractCalleeAddressesFromIr mines CALLI i64 immediates', () => {
		// Real Remill form — no @sub_, target is the 3rd i64 arg on CALLI lines.
		const ir = `
  %v33 = call ptr @_ZN12_GLOBAL__N_14CALLI2InImEEEP6MemoryS4_R5StateT_3RnWImES2_S9_(ptr %v27, ptr %state, i64 5368891104, ptr nonnull %NEXT_PC, i64 5368865899, ptr nonnull %MEMORY)
  %v99 = call ptr @_ZN12_GLOBAL__N_14CALLI2InImEEEP6MemoryS4_R5StateT_3RnWImES2_S9_(ptr %v27, ptr %state, i64 5368880768, ptr nonnull %NEXT_PC, i64 5368865900, ptr nonnull %MEMORY)
  %other = add i64 5368891104, 1
`;
		const addrs = extractCalleeAddressesFromIr(ir);
		assert.ok(addrs.includes(5368891104), 'CALLI target');
		assert.ok(addrs.includes(5368880768), 'CALLI target 2');
		assert.ok(addrs.includes(5368865899), 'return-PC also collected');
		// Non-CALLI line must NOT contribute the same immediate (add has no CALLI).
		// (5368891104 also appears on CALLI so it is present — that's fine.)
		assert.ok(!addrs.includes(5368891105), 'non-CALLI-only immediates excluded');
	});

	test('extractCalleeAddressesFromIr ignores empty / garbage', () => {
		assert.deepStrictEqual(extractCalleeAddressesFromIr(''), []);
		assert.deepStrictEqual(extractCalleeAddressesFromIr('no callees here'), []);
	});

	test('resolveHelixBaseOptions defaults cast ON', () => {
		assert.strictEqual(resolveHelixBaseOptions({}).useCastLayer, true);
		assert.strictEqual(resolveHelixBaseOptions({ useCastLayer: true }).useCastLayer, true);
		assert.strictEqual(resolveHelixBaseOptions({ useCastLayer: false }).useCastLayer, false);
	});

	test('wantsHelixFunctionStarts defaults OFF (quality path)', () => {
		assert.strictEqual(wantsHelixFunctionStarts({}), false);
		assert.strictEqual(wantsHelixFunctionStarts({ functionStarts: false }), false);
		assert.strictEqual(wantsHelixFunctionStarts({ functionStarts: true }), true);
		assert.strictEqual(wantsHelixFunctionStarts({ honesty: true }), true);
		assert.strictEqual(wantsHelixFunctionStarts({ honestyMode: true }), true);
	});

	test('buildHelixFunctionStarts merges analyzeAll + IR callees', () => {
		const eng = makeEngineStub({
			functions: [{ address: 0x14002641c }, { address: 0x140027e88 }],
			imports: [{ functions: [{ address: 0x140031000 }] }],
			exports: [{ address: 0x140001000 }],
		});
		const ir = 'call void @sub_14002c6e0()\n  call ptr @_ZN12_GLOBAL__N_14CALLI2InImE(ptr %a, ptr %b, i64 5368890999, ptr %c)\n';
		const starts = buildHelixFunctionStarts(eng, {
			irText: ir,
			entryAddress: 0x14002641c,
			callTargets: [0x140029e80],
		});
		assert.ok(starts, 'non-empty');
		const set = new Set(starts);
		assert.ok(set.has(0x14002641c));
		assert.ok(set.has(0x14002c6e0), 'IR @sub_');
		assert.ok(set.has(5368890999), 'CALLI immediate');
		assert.ok(set.has(0x140029e80), 'callTargets');
		assert.ok(set.has(0x140031000), 'import');
		assert.ok(set.has(0x140001000), 'export');
	});

	test('buildHelixFunctionStarts returns undefined when empty', () => {
		assert.strictEqual(buildHelixFunctionStarts(makeEngineStub({})), undefined);
	});

	test('coercePositiveInt accepts number and numeric string', () => {
		assert.strictEqual(coercePositiveInt(65536), 65536);
		assert.strictEqual(coercePositiveInt('65536'), 65536);
		assert.strictEqual(coercePositiveInt('0x1000'), 0x1000);
		assert.strictEqual(coercePositiveInt(0), undefined);
		assert.strictEqual(coercePositiveInt('nope'), undefined);
	});

	test('resolveLiftByteSize clamps oversized window to known function', () => {
		const r = resolveLiftByteSize({
			size: 65536,
			count: 8192,
			knownFunctionSize: 6761,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 6761 + 64);
		assert.ok(r.reason.includes('clamped-to-fn'));
		assert.strictEqual(r.clampedFrom, 65536);
	});

	test('resolveLiftByteSize never under-lifts known function', () => {
		const r = resolveLiftByteSize({
			size: 100,
			knownFunctionSize: 6761,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 6761 + 16);
		assert.ok(r.reason.includes('raised-to-known'));
	});

	test('resolveLiftByteSize treats count as a hard scoped request', () => {
		const r = resolveLiftByteSize({
			count: 80,
			knownFunctionSize: 13_568,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 1_200);
		assert.strictEqual(r.reason, 'count*15-hard-limit');
		assert.strictEqual(r.scopeLimited, true);
		assert.strictEqual(r.countingDomain, 'instruction-count-heuristic');
	});

	test('resolveLiftByteSize uses explicit endExclusive instead of a foreign decoder count', () => {
		const r = resolveLiftByteSize({
			startAddress: 0x14018D720,
			endExclusive: '0x14018DF4A',
			count: 525,
			knownFunctionSize: 2090,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 2090);
		assert.strictEqual(r.endExclusive, 0x14018DF4A);
		assert.strictEqual(r.reason, 'explicit-endExclusive');
		assert.strictEqual(r.countingDomain, 'byte-range');
		assert.strictEqual(r.scopeLimited, undefined);
	});

	test('resolveLiftByteSize stopAtFunctionBoundary selects the exact known extent', () => {
		const r = resolveLiftByteSize({
			startAddress: 0x140190370,
			stopAtFunctionBoundary: true,
			count: 920,
			knownFunctionSize: 3904,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 3904);
		assert.strictEqual(r.endExclusive, 0x1401912B0);
		assert.strictEqual(r.reason, 'authoritative-function-boundary');
		assert.strictEqual(r.countingDomain, 'byte-range');
	});

	test('resolveLiftByteSize rejects invalid explicit boundaries', () => {
		assert.throws(() => resolveLiftByteSize({
			startAddress: 0x401000,
			endExclusive: 0x400FFF,
			knownFunctionSize: 16,
			bufferSize: 4096,
		}), /endExclusive must be greater/);
	});

	test('auto-backtrack section guard rejects previous-section padding', () => {
		const sections = [
			{ name: '.text', virtualAddress: 0x401000, virtualSize: 0x6000, rawSize: 0x6000 },
			{ name: '.oisc', virtualAddress: 0x407000, virtualSize: 0x1000, rawSize: 0x1000 },
		];
		assert.strictEqual(isBacktrackWithinSection(sections, 0x406FFA, 0x407000), false);
		assert.strictEqual(isBacktrackWithinSection(sections, 0x407000, 0x407020), true);
	});

	test('resolveLiftByteSize allowOversizedLift keeps huge window', () => {
		const r = resolveLiftByteSize({
			size: 65536,
			knownFunctionSize: 6761,
			bufferSize: 1_000_000,
			allowOversizedLift: true,
		});
		assert.strictEqual(r.size, 65536);
	});

	test('ET_REL explicit byte window survives a short fragment extent', () => {
		const options = { size: 2137 };
		assert.strictEqual(shouldHonorExplicitLiftWindow(options, true), true);
		const r = resolveLiftByteSize({
			size: options.size,
			knownFunctionSize: 997,
			bufferSize: 1_000_000,
			allowOversizedLift: shouldHonorExplicitLiftWindow(options, true),
		});
		assert.strictEqual(r.size, 2137);
		assert.strictEqual(r.reason, 'explicit-size');
	});

	test('PE and implicit ET_REL windows keep the normal clamp policy', () => {
		assert.strictEqual(shouldHonorExplicitLiftWindow({ size: 65536 }, false), false);
		assert.strictEqual(shouldHonorExplicitLiftWindow({}, true), false);
		assert.strictEqual(
			shouldHonorExplicitLiftWindow({ allowOversizedLift: true }, false), true);
	});

	test('resolveLiftByteSize uses known size when no size/count', () => {
		const r = resolveLiftByteSize({
			knownFunctionSize: 6761,
			bufferSize: 1_000_000,
		});
		assert.strictEqual(r.size, 6761 + 16);
		assert.strictEqual(r.reason, 'knownFunctionSize+pad');
	});

	test('getAuthoritativeFunctionExtent prefers pdata over short table size', () => {
		// IDE bug: prologue scan size=4800, pdata span=6761
		const eng = {
			getFunctionAt: (a: number) => a === 0x14002641c
				? { address: 0x14002641c, size: 4800, endAddress: 0x14002641c + 4800 }
				: undefined,
			getPdataEntries: () => [{
				beginAddress: 0x2641c, // RVA
				endAddress: 0x2641c + 6761,
			}],
			getBaseAddress: () => 0x140000000,
			getRecommendedLiftSize: () => 0,
		};
		const ext = getAuthoritativeFunctionExtent(eng as any, 0x14002641c);
		assert.strictEqual(ext.size, 6761);
		assert.strictEqual(ext.end, 0x14002641c + 6761);
		assert.strictEqual(ext.source, 'pdata');
	});

	test('getAuthoritativeFunctionExtent falls back to function table', () => {
		const eng = {
			getFunctionAt: () => ({ address: 0x401000, size: 100, endAddress: 0x401064 }),
			getPdataEntries: () => [],
			getBaseAddress: () => 0x400000,
			getRecommendedLiftSize: () => 0,
		};
		const ext = getAuthoritativeFunctionExtent(eng as any, 0x401000);
		assert.strictEqual(ext.size, 100);
		assert.strictEqual(ext.source, 'function-table');
	});

	test('getAuthoritativeFunctionExtent clamps stale heuristic end at a newly known adjacent function', () => {
		const eng = {
			getFunctionAt: () => ({ address: 0x1408359d0, size: 0x20, endAddress: 0x1408359f0 }),
			getFunctions: () => [{ address: 0x1408359d0 }, { address: 0x1408359e0 }],
			getPdataEntries: () => [],
			getBaseAddress: () => 0x140000000,
			getRecommendedLiftSize: () => 0,
		};
		const ext = getAuthoritativeFunctionExtent(eng as any, 0x1408359d0);
		assert.strictEqual(ext.end, 0x1408359e0);
		assert.strictEqual(ext.size, 0x10);
		assert.strictEqual(ext.source, 'function-table');
	});
});
