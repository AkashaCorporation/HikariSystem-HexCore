/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Interior-ghost drop on PE binaries WITHOUT usable .pdata (v3.8.3 Gap-A follow-on).
 *
 * Pins dropInteriorGhostFunctionsPE in disassemblerEngine.ts. The gap it closes:
 * 32-bit PE has no .pdata directory (RUNTIME_FUNCTION is x64-only) and some x64 PEs
 * ship without a usable exception directory, so reconcileFunctionsWithPdata never runs
 * and dropInteriorGhostFunctions only sweeps ZERO-caller ghosts. The prologue scan +
 * unconditional-jump-following then leave hundreds of interior "functions" that carry
 * spurious caller edges:
 *
 *   - debugme.exe (PE32, x86)  : 406 funcs, 284 interior ghosts  -> 128 funcs, 6 interior
 *   - maze.exe    (PE64, x64)  : 1647 funcs, 1124 interior ghosts -> 567 funcs, 44 interior
 *
 * Field measurement: every interior ghost entry is a REAL instruction boundary of its
 * container (no mid-instruction byte-pattern ghosts), and every caller edge into the drop
 * set is an intra-container jump or a call from another ghost. The single signal that
 * separates a real shared inner routine from an in-body jump label is:
 *
 *   KEEP iff some CALL targets the interior fn from a site OUTSIDE the container AND inside
 *   a NON-interior (top-level) function. Otherwise DROP.
 *
 * These addresses are the real ones observed on the targets. Because the binaries live
 * outside the repo, the scenarios are reproduced as synthetic function tables driven
 * directly through the engine's table (matching the other engine tests' `as any` style).
 */

import * as assert from 'assert';
import 'mocha';
import { DisassemblerEngine } from './disassemblerEngine';

interface FakeInstr {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

function ins(address: number, kind: 'call' | 'jmp' | 'other', target?: number): FakeInstr {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic: kind === 'call' ? 'call' : kind === 'jmp' ? 'jmp' : 'nop',
		opStr: target !== undefined ? `0x${target.toString(16)}` : '',
		size: 1,
		isCall: kind === 'call',
		isJump: kind === 'jmp',
		isRet: false,
		isConditional: false,
		targetAddress: target
	};
}

function fn(address: number, endAddress: number, instructions: FakeInstr[], callers: number[] = []) {
	return { address, name: `sub_${address.toString(16).toUpperCase()}`, size: endAddress - address, endAddress, instructions, callers, callees: [] as number[] };
}

/** Build an engine with a fabricated function table + fileInfo and run the PE drop pass. */
function runDrop(opts: {
	format: string; pdata?: unknown[]; relocatable?: boolean; entryPoint?: number; exports?: { address: number; isForwarder: boolean }[];
	funcs: ReturnType<typeof fn>[];
}): Map<number, ReturnType<typeof fn>> {
	const engine = new DisassemblerEngine() as any;
	const map = new Map<number, ReturnType<typeof fn>>();
	for (const f of opts.funcs) { map.set(f.address, f); }
	engine.functions = map;
	engine.fileInfo = { format: opts.format, entryPoint: opts.entryPoint ?? 0, baseAddress: 0, imageSize: 0, isRelocatable: opts.relocatable ?? false };
	engine.peDataDirectories = { pdata: opts.pdata ?? [] };
	engine.exports = opts.exports ?? [];
	engine.dropInteriorGhostFunctionsPE();
	return map;
}

suite('Interior ghost drop on PE without .pdata (v3.8.3 Gap-A follow-on)', () => {

	test('drops an interior ghost reached only by an intra-container jmp (debugme sub_401502 class)', () => {
		// container 0x40141d..0x401504 ; ghost 0x401502 is a jmp label inside it, "called"
		// (actually jumped) from sites at 0x401463/0x401489 INSIDE the container.
		const container = fn(0x40141d, 0x401504, [
			ins(0x40141d, 'other'),
			ins(0x401463, 'jmp', 0x401502),
			ins(0x401489, 'jmp', 0x401502),
			ins(0x401502, 'other')
		]);
		const ghost = fn(0x401502, 0x401504, [ins(0x401502, 'other')], [0x401463, 0x401489]);
		const map = runDrop({ format: 'PE', entryPoint: 0x4010f9, funcs: [container, ghost] });
		assert.ok(map.has(0x40141d), 'container kept');
		assert.ok(!map.has(0x401502), 'intra-container jump-label ghost dropped even though it had callers');
	});

	test('keeps an interior fn reached by a CALL from OUTSIDE the container in a top-level fn (debugme sub_40865C class)', () => {
		// shared routine 0x40865c lives inside an over-extended container 0x40859c, but is
		// CALLed from a different top-level function 0x405460.
		const overExtended = fn(0x40859c, 0x4086e0, [ins(0x40859c, 'other'), ins(0x40865c, 'other')]);
		const shared = fn(0x40865c, 0x4086e0, [ins(0x40865c, 'other')], [0x40547d]);
		const topCaller = fn(0x405460, 0x4054b0, [ins(0x405460, 'other'), ins(0x40547d, 'call', 0x40865c)]);
		const map = runDrop({ format: 'PE', entryPoint: 0x4010f9, funcs: [overExtended, shared, topCaller] });
		assert.ok(map.has(0x40865c), 'genuinely-shared inner routine kept (external CALL from top-level fn)');
		assert.ok(map.has(0x405460), 'top-level caller kept');
	});

	test('does NOT count a CALL from another interior ghost as a genuine external call', () => {
		// ghost A inside container C; the only CALL into A comes from ghost B which is ALSO
		// interior to C -> the edge vanishes with B, so A must drop.
		const container = fn(0x1000, 0x1100, [ins(0x1000, 'other'), ins(0x1040, 'other'), ins(0x1080, 'other')]);
		const ghostA = fn(0x1040, 0x1100, [ins(0x1040, 'other')], [0x1090]);
		const ghostB = fn(0x1080, 0x1100, [ins(0x1080, 'other'), ins(0x1090, 'call', 0x1040)], []);
		const map = runDrop({ format: 'PE', entryPoint: 0x1, funcs: [container, ghostA, ghostB] });
		assert.ok(!map.has(0x1040), 'ghost A dropped (only caller is another interior ghost)');
	});

	test('never drops the entry point even when it nests in a spurious container (maze EP 0x14000b680 class)', () => {
		// prologue-scan false start at 0x14000b659 swallows the real EP at 0x14000b680.
		const falseStart = fn(0x14000b659, 0x14000b756, [ins(0x14000b659, 'other'), ins(0x14000b680, 'other')]);
		const epFn = fn(0x14000b680, 0x14000b756, [ins(0x14000b680, 'other')], []);
		const map = runDrop({ format: 'PE64', entryPoint: 0x14000b680, funcs: [falseStart, epFn] });
		assert.ok(map.has(0x14000b680), 'entry point preserved as a protected root despite being interior with no callers');
	});

	test('never drops an exported function that nests in a spurious container', () => {
		const falseStart = fn(0x2000, 0x2100, [ins(0x2000, 'other'), ins(0x2040, 'other')]);
		const exp = fn(0x2040, 0x2100, [ins(0x2040, 'other')], []);
		const map = runDrop({ format: 'PE64', entryPoint: 0x1, exports: [{ address: 0x2040, isForwarder: false }], funcs: [falseStart, exp] });
		assert.ok(map.has(0x2040), 'exported function preserved as a protected root');
	});

	test('rebuilds the call graph over survivors with no dangling callee/caller edges', () => {
		const container = fn(0x3000, 0x3100, [ins(0x3000, 'other'), ins(0x3040, 'jmp', 0x3080), ins(0x3080, 'other')]);
		const ghost = fn(0x3080, 0x3100, [ins(0x3080, 'other')], [0x3040]);
		const map = runDrop({ format: 'PE', entryPoint: 0x3000, funcs: [container, ghost] });
		// container's callee edge to the now-removed ghost must not dangle
		const c = map.get(0x3000)!;
		assert.ok(!c.callees.includes(0x3080), 'callee edge to dropped ghost removed');
		for (const f of map.values()) {
			for (const callee of f.callees) { assert.ok(map.has(callee), `callee 0x${callee.toString(16)} is a real function`); }
		}
	});

	test('GATE: no-op on ELF (handled by dropInteriorGhostFunctions)', () => {
		const container = fn(0x1000, 0x1100, [ins(0x1000, 'other'), ins(0x1040, 'jmp', 0x1080), ins(0x1080, 'other')]);
		const ghost = fn(0x1080, 0x1100, [ins(0x1080, 'other')], [0x1040]);
		const map = runDrop({ format: 'ELF64', entryPoint: 0x1000, funcs: [container, ghost] });
		assert.ok(map.has(0x1080), 'ELF untouched by PE pass');
	});

	test('GATE: no-op on x64 PE WITH .pdata (handled by reconcileFunctionsWithPdata)', () => {
		const container = fn(0x1000, 0x1100, [ins(0x1000, 'other'), ins(0x1040, 'jmp', 0x1080), ins(0x1080, 'other')]);
		const ghost = fn(0x1080, 0x1100, [ins(0x1080, 'other')], [0x1040]);
		const map = runDrop({ format: 'PE64', pdata: [{ beginAddress: 0, endAddress: 1 }], entryPoint: 0x1000, funcs: [container, ghost] });
		assert.ok(map.has(0x1080), 'PE-with-.pdata untouched by this pass');
	});

	test('GATE: no-op on ET_REL (.ko)', () => {
		const container = fn(0x1000, 0x1100, [ins(0x1000, 'other'), ins(0x1040, 'jmp', 0x1080), ins(0x1080, 'other')]);
		const ghost = fn(0x1080, 0x1100, [ins(0x1080, 'other')], [0x1040]);
		const map = runDrop({ format: 'ELF64', relocatable: true, entryPoint: 0x1000, funcs: [container, ghost] });
		assert.ok(map.has(0x1080), 'ET_REL untouched');
	});
});
