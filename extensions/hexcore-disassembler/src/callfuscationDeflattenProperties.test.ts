/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.1 - Callfuscation deflattening (call-as-jmp) pre-lift transform.
// Tests the REAL deflattenCallfuscation() from pathfinder.ts (pure, type-only deps).

import * as assert from 'assert';
import * as fc from 'fast-check';
import { deflattenCallfuscation } from './pathfinder';

/**
 * Build `count` callfuscation gadgets at a 16-byte stride.
 * Each gadget: at p, `E8 03 00 00 00` (call +3) targets a `pop` at p+8.
 * rel32 == 3 keeps displacement bytes free of 0xE8 so the only call opcodes
 * are the genuine gadgets. `popByte` is a single-byte pop (0x58..0x5F).
 */
function buildGadgets(count: number, popByte = 0x58): Buffer {
	const buf = Buffer.alloc(8 + count * 16, 0x90);
	for (let k = 0; k < count; k++) {
		const p = 8 + k * 16;
		buf[p] = 0xe8;
		buf.writeInt32LE(3, p + 1); // target = p + 5 + 3 = p + 8
		buf[p + 8] = popByte;
	}
	return buf;
}

suite('Callfuscation Deflattening - Properties (v3.8.1)', () => {

	// P1: at/above threshold, every link becomes a jmp and every pop is neutralized.
	test('P1: rewrites E8->E9 and NOPs pop discards above threshold', () => {
		fc.assert(fc.property(
			fc.integer({ min: 16, max: 400 }),
			fc.constantFrom(0x58, 0x5b, 0x5d, 0x5f),
			(count, popByte) => {
				const original = buildGadgets(count, popByte);
				const res = deflattenCallfuscation(original, 0x401000);
				assert.ok(res.applied, 'applied at/above threshold');
				assert.strictEqual(res.linkCount, count, 'all links found');
				assert.strictEqual(res.popsNeutralized, count, 'all pops neutralized (unique targets)');
				// input buffer must NOT be mutated (copy semantics)
				assert.strictEqual(original[8], 0xe8, 'original untouched');
				for (let k = 0; k < count; k++) {
					const p = 8 + k * 16;
					assert.strictEqual(res.patched[p], 0xe9, `link ${k} rewritten to jmp`);
					assert.strictEqual(res.patched.readInt32LE(p + 1), 3, `displacement preserved at ${k}`);
					assert.strictEqual(res.patched[p + 8], 0x90, `pop ${k} neutralized to nop`);
				}
			}
		), { numRuns: 120 });
	});

	// P2: below threshold, the transform is a no-op and returns the same buffer.
	test('P2: below threshold is a no-op', () => {
		fc.assert(fc.property(fc.integer({ min: 0, max: 15 }), (count) => {
			const original = buildGadgets(count);
			const res = deflattenCallfuscation(original, 0x401000);
			assert.strictEqual(res.applied, false);
			assert.strictEqual(res.linkCount, 0);
			assert.strictEqual(res.patched, original, 'returns the same buffer unchanged');
		}), { numRuns: 50 });
	});

	// P2b: minLinks is configurable.
	test('P2b: minLinks option controls the gate', () => {
		const buf = buildGadgets(4);
		assert.strictEqual(deflattenCallfuscation(buf, 0x401000, { minLinks: 4 }).applied, true);
		assert.strictEqual(deflattenCallfuscation(buf, 0x401000, { minLinks: 5 }).applied, false);
	});

	// P3: REX.B two-byte pop (41 58..5F) is neutralized to a 2-byte nop (66 90).
	test('P3: REX.B pop r8..r15 neutralized to 66 90', () => {
		const count = 20;
		const buf = Buffer.alloc(8 + count * 16, 0x90);
		for (let k = 0; k < count; k++) {
			const p = 8 + k * 16;
			buf[p] = 0xe8;
			buf.writeInt32LE(3, p + 1); // target p+8
			buf[p + 8] = 0x41; buf[p + 9] = 0x58; // pop r8
		}
		const res = deflattenCallfuscation(buf, 0x401000);
		assert.ok(res.applied);
		assert.strictEqual(res.popsNeutralized, count);
		for (let k = 0; k < count; k++) {
			const p = 8 + k * 16;
			assert.strictEqual(res.patched[p], 0xe9);
			assert.strictEqual(res.patched[p + 8], 0x66, 'REX.B pop -> 66');
			assert.strictEqual(res.patched[p + 9], 0x90, 'REX.B pop -> 90');
		}
	});

	// P4: calls whose target is NOT a pop discard are left untouched (not links).
	test('P4: ordinary calls (non-pop target) are not rewritten', () => {
		// 32 calls all targeting a NOP region (0x90) - none are callfuscation links.
		const count = 32;
		const buf = Buffer.alloc(8 + count * 16, 0x90);
		for (let k = 0; k < count; k++) {
			const p = 8 + k * 16;
			buf[p] = 0xe8;
			buf.writeInt32LE(3, p + 1); // target p+8 == 0x90 (nop, not a pop)
		}
		const res = deflattenCallfuscation(buf, 0x401000);
		assert.strictEqual(res.applied, false);
		assert.strictEqual(res.linkCount, 0);
		for (let k = 0; k < count; k++) {
			assert.strictEqual(res.patched[8 + k * 16], 0xe8, 'ordinary call left as call');
		}
	});

	test('P5: instruction-aware mode ignores E8 bytes that are not decoded call boundaries', () => {
		const buf = buildGadgets(20);
		const genuine = new Set<number>();
		for (let k = 0; k < 16; k++) {
			genuine.add(8 + k * 16);
		}
		const res = deflattenCallfuscation(buf, 0x401000, {
			instructionOffsets: genuine,
			decodedCallCount: 16,
		});
		assert.ok(res.applied);
		assert.strictEqual(res.linkCount, 16);
		for (let k = 0; k < 20; k++) {
			assert.strictEqual(res.patched[8 + k * 16], k < 16 ? 0xe9 : 0xe8);
		}
	});

	test('P6: instruction-aware ratio gate rejects sparse call-pop idioms', () => {
		const buf = buildGadgets(16);
		const offsets = new Set<number>();
		for (let k = 0; k < 16; k++) { offsets.add(8 + k * 16); }
		const res = deflattenCallfuscation(buf, 0x401000, {
			instructionOffsets: offsets,
			decodedCallCount: 64,
		});
		assert.strictEqual(res.applied, false);
	});
});
