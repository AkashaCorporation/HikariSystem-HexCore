/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';
import { isBacktrackContinuityValid, resolveReanchorWindow } from '../pathfinder';

suite('pathfinder D-scanrange', () => {

	// -----------------------------------------------------------------------
	// resolveReanchorWindow -- the prologue re-anchor safety guards
	// -----------------------------------------------------------------------

	suite('resolveReanchorWindow', () => {

		const start = 0x140253b21;
		const bufferLen = 0x200;

		test('(a) FIX-022c: backtrack distance > 4096 -> scanStart stays undefined', () => {
			const funcStart = start - 5000; // 5000 > 4096
			const boundaryEnd = start + 0x80;
			const w = resolveReanchorWindow(start, bufferLen, funcStart, boundaryEnd, false);
			assert.strictEqual(w.scanStart, undefined, 'over-cap backtrack must NOT re-anchor');
			assert.strictEqual(w.scanEnd, start + bufferLen, 'scanEnd falls back to the original buffer end');
		});

		test('(a) FIX-022c: backtrack distance exactly 4096 is still accepted', () => {
			const funcStart = start - 4096;
			const w = resolveReanchorWindow(start, bufferLen, funcStart, undefined, false);
			assert.strictEqual(w.scanStart, funcStart, 'distance == cap re-anchors');
		});

		test('(b) FIX-011: relocatable (.ko) buffers are never re-anchored (patches not dropped)', () => {
			const funcStart = start - 0x40; // well within the cap
			const boundaryEnd = start + 0x80;
			const w = resolveReanchorWindow(start, bufferLen, funcStart, boundaryEnd, true);
			assert.strictEqual(w.scanStart, undefined, 'relocatable file must keep the patched window');
			assert.strictEqual(w.scanEnd, start + bufferLen);
		});

		test('(c) valid PE re-anchor: scanStart is the prologue and the window contains the whole buffer', () => {
			const funcStart = start - 0x30;
			const boundaryEnd = start + 0x400; // extends past the original buffer end
			const w = resolveReanchorWindow(start, bufferLen, funcStart, boundaryEnd, false);
			assert.strictEqual(w.scanStart, funcStart, 're-anchored to the prologue');
			// every leader emitted in [scanStart, scanEnd) is < scanEnd and >= scanStart,
			// hence within the caller's re-fetched buffer.
			assert.ok(w.scanStart! <= start, 'window starts at or before the original hit');
			assert.ok(w.scanEnd >= start + bufferLen, 'window covers the original buffer end');
			assert.strictEqual(w.scanEnd, boundaryEnd, 'window grows to the function boundary end');
		});

		test('no earlier candidate (already at prologue) -> undefined', () => {
			assert.strictEqual(resolveReanchorWindow(start, bufferLen, start, start + 0x10, false).scanStart, undefined);
			assert.strictEqual(resolveReanchorWindow(start, bufferLen, undefined, undefined, false).scanStart, undefined);
		});

		test('property: when scanStart is defined the window fully contains the original buffer and honors both guards', () => {
			fc.assert(
				fc.property(
					fc.integer({ min: 0x1000, max: 0x7fffffff }),
					fc.integer({ min: 1, max: 0x4000 }),
					fc.integer({ min: 0, max: 0x6000 }),
					fc.integer({ min: 0, max: 0x2000 }),
					fc.boolean(),
					(start: number, bufferLen: number, backDist: number, endExtra: number, reloc: boolean) => {
						const funcStart = start - backDist;
						const boundaryEnd = start + bufferLen + endExtra;
						const w = resolveReanchorWindow(start, bufferLen, funcStart, boundaryEnd, reloc);
						if (w.scanStart !== undefined) {
							assert.ok(!reloc, 'never re-anchors on relocatable');
							assert.ok(start - w.scanStart > 0 && start - w.scanStart <= 4096, 'distance within (0, 4096]');
							assert.ok(w.scanStart <= start, 'scanStart <= original start');
							assert.ok(w.scanEnd >= start + bufferLen, 'scanEnd covers the original buffer');
						} else {
							assert.strictEqual(w.scanEnd, start + bufferLen, 'no re-anchor -> original window end');
						}
					}
				),
				{ numRuns: 200 }
			);
		});
	});

	suite('isBacktrackContinuityValid', () => {
		test('accepts an exact, contiguous non-terminal chain', () => {
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 1, mnemonic: 'push' },
				{ address: 0x1001, size: 3, mnemonic: 'mov' },
			], Buffer.alloc(68), 0x1000, 0x1004), true);
		});

		test('rejects an instruction that only overshoots the original address', () => {
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 4, mnemonic: 'mov' },
			], Buffer.alloc(68), 0x1000, 0x1003), false);
		});

		test('rejects a return even when it ends exactly at the original address', () => {
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 1, mnemonic: 'ret', isRet: true },
			], Buffer.alloc(65), 0x1000, 0x1001), false);
		});

		test('rejects decode gaps before the original address', () => {
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 1, mnemonic: 'push' },
				{ address: 0x1002, size: 2, mnemonic: 'mov' },
			], Buffer.alloc(68), 0x1000, 0x1004), false);
		});

		test('rejects an unconditional jump outside the validation window', () => {
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 2, mnemonic: 'jmp', targetAddress: 0x2000 },
			], Buffer.alloc(66), 0x1000, 0x1002), false);
		});

		test('rejects inter-function INT3 padding', () => {
			const bytes = Buffer.from([0xcc, 0xcc, 0x90]);
			assert.strictEqual(isBacktrackContinuityValid([
				{ address: 0x1000, size: 1, mnemonic: 'int3' },
				{ address: 0x1001, size: 1, mnemonic: 'int3' },
			], bytes, 0x1000, 0x1002), false);
		});
	});
});
