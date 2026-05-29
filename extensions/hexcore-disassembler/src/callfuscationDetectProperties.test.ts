/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.1 — Callfuscation (call-as-jmp) detection.
// Property tests for the byte-scan gadget detector used by
// DisassemblerEngine.detectCallfuscation(). The detector finds the defining
// signature of the HTB "Callfuscated" obfuscator: a `call rel32` whose target
// begins with a `pop` that discards the just-pushed return address.

import * as assert from 'assert';
import * as fc from 'fast-check';

/**
 * Reimplements the core gadget-scan logic from DisassemblerEngine.detectCallfuscation()
 * for unit-level testing without vscode/capstone. Uses identity VA mapping (VA == offset)
 * so call targets resolve to buffer offsets directly: target = i + 5 + rel32.
 */
function scanCallfuscation(buf: Buffer): { detected: boolean; gadgetCount: number; callCount: number; ratio: number } {
	const isPopAt = (off: number): boolean => {
		if (off < 0 || off >= buf.length) { return false; }
		const b = buf[off];
		if (b >= 0x58 && b <= 0x5f) { return true; }                 // pop rax..rdi
		if (b === 0x41 && off + 1 < buf.length) {                    // REX.B pop r8..r15
			const b2 = buf[off + 1];
			return b2 >= 0x58 && b2 <= 0x5f;
		}
		return false;
	};

	let gadgetCount = 0;
	let callCount = 0;
	for (let i = 0; i + 5 <= buf.length; i++) {
		if (buf[i] !== 0xe8) { continue; }
		callCount++;
		const rel = buf.readInt32LE(i + 1);
		const target = i + 5 + rel;
		if (isPopAt(target)) { gadgetCount++; }
	}
	const ratio = callCount > 0 ? gadgetCount / callCount : 0;
	return { detected: gadgetCount >= 16 && ratio >= 0.5, gadgetCount, callCount, ratio };
}

/**
 * Build a buffer of `count` self-contained call-gadgets (16-byte stride).
 * Each gadget: `E8 03 00 00 00` (call +3) → a `pop` placed at offset p+8.
 * rel32 == 3 keeps displacement bytes free of 0xE8, so the only 0xE8 bytes are
 * the genuine call opcodes (callCount == count exactly). `popBytes` is 1 or 2
 * bytes (single-byte pop, or REX.B `41 5x`).
 */
function buildGadgetBuffer(count: number, popBytes: number[]): Buffer {
	const buf = Buffer.alloc(8 + count * 16, 0x90); // 0x90 = nop filler
	for (let k = 0; k < count; k++) {
		const p = 8 + k * 16;
		buf[p] = 0xe8;                 // call rel32
		buf.writeInt32LE(3, p + 1);    // target = (p+5) + 3 = p+8
		for (let j = 0; j < popBytes.length; j++) { buf[p + 8 + j] = popBytes[j]; }
	}
	return buf;
}

suite('Callfuscation Detection — Properties (v3.8.1)', () => {

	// P1: K call-gadgets pointing at a pop are all counted; detected when K >= 16.
	test('P1: counts every call->pop gadget and flags detection at threshold', () => {
		fc.assert(fc.property(
			fc.integer({ min: 0, max: 500 }),
			fc.constantFrom(0x58, 0x5b, 0x5f), // pop rax / pop rbx / pop rdi
			(count, popByte) => {
				const res = scanCallfuscation(buildGadgetBuffer(count, [popByte]));
				assert.strictEqual(res.gadgetCount, count, 'every gadget counted');
				assert.strictEqual(res.callCount, count, 'every call counted');
				assert.strictEqual(res.detected, count >= 16, 'detection at threshold (ratio==1)');
			}
		), { numRuns: 200 });
	});

	// P1b: REX.B two-byte pop (pop r8..r15) is recognized as a discard.
	test('P1b: recognizes REX.B pop r8..r15 (41 58..5F) as discard', () => {
		const count = 32;
		const res = scanCallfuscation(buildGadgetBuffer(count, [0x41, 0x58])); // pop r8
		assert.strictEqual(res.gadgetCount, count);
		assert.strictEqual(res.callCount, count);
		assert.ok(res.detected);
	});

	// P2: buffers with no 0xE8 never report calls or gadgets.
	test('P2: no false positives without call opcodes', () => {
		fc.assert(fc.property(
			fc.uint8Array({ minLength: 0, maxLength: 600 }).map(a => Buffer.from(a.map(b => (b === 0xe8 ? 0x90 : b)))),
			(buf) => {
				const res = scanCallfuscation(buf);
				assert.strictEqual(res.callCount, 0);
				assert.strictEqual(res.gadgetCount, 0);
				assert.strictEqual(res.detected, false);
			}
		), { numRuns: 200 });
	});

	// P3: a call whose target is NOT a pop counts as a call but not a gadget.
	test('P3: call to non-pop target is a call but not a gadget', () => {
		const buf = Buffer.alloc(64, 0x90); // 0x90 (nop) target — not a pop
		const p = 16;
		buf[p] = 0xe8;
		buf.writeInt32LE(0 - (p + 5), p + 1); // target offset 0 == 0x90 (nop)
		const res = scanCallfuscation(buf);
		assert.strictEqual(res.callCount, 1);
		assert.strictEqual(res.gadgetCount, 0);
		assert.strictEqual(res.detected, false);
	});

	// P4: a low-ratio mix (few gadgets among many plain calls) is NOT flagged.
	test('P4: ratio gate — sparse gadgets among plain calls not flagged', () => {
		// 4 gadgets (target = pop at 0) + 40 plain calls (target = nop region)
		const count = 44;
		const buf = Buffer.alloc(8 + count * 5, 0x90);
		buf[0] = 0x58; // pop rax
		for (let k = 0; k < count; k++) {
			const p = 8 + k * 5;
			buf[p] = 0xe8;
			// first 4 point to the pop; rest point to a nop (self+nop region)
			const target = k < 4 ? 0 : (p + 5 + 1);
			buf.writeInt32LE(target - (p + 5), p + 1);
		}
		const res = scanCallfuscation(buf);
		assert.strictEqual(res.gadgetCount, 4);
		assert.strictEqual(res.callCount, count);
		assert.ok(res.ratio < 0.5);
		assert.strictEqual(res.detected, false, 'low ratio must not trip detection');
	});
});
