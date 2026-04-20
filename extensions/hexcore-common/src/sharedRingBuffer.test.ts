/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Tests for SharedRingBuffer. Standalone script — no test framework dependency.
 * Run with: node out/sharedRingBuffer.test.js
 */

import * as assert from 'assert';
import {
	SharedRingBuffer,
	RING_BUFFER_HEADER_SIZE,
	RING_BUFFER_MAGIC,
	RING_BUFFER_VERSION,
} from './sharedRingBuffer';

let passed = 0;
let failed = 0;

function test(name: string, fn: () => void): void {
	try {
		fn();
		console.log(`  \x1b[32mPASS\x1b[0m ${name}`);
		passed++;
	} catch (err) {
		const msg = err instanceof Error ? err.message : String(err);
		console.log(`  \x1b[31mFAIL\x1b[0m ${name}\n        ${msg}`);
		if (err instanceof Error && err.stack) {
			console.log(err.stack.split('\n').slice(1, 4).map(l => '        ' + l.trim()).join('\n'));
		}
		failed++;
	}
}

console.log('SharedRingBuffer tests\n');

// ─── Construction & layout ────────────────────────────────────────────

test('constructor allocates header + payload', () => {
	const ring = new SharedRingBuffer({ slotSize: 32, slotCount: 4096 });
	assert.strictEqual(ring.buffer.byteLength, RING_BUFFER_HEADER_SIZE + 32 * 4096);
	assert.strictEqual(ring.slotSize, 32);
	assert.strictEqual(ring.slotCount, 4096);
});

test('constructor writes magic and version into header', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 8 });
	const view = new Int32Array(ring.buffer, 0, 16);
	assert.strictEqual(view[0], RING_BUFFER_MAGIC, 'magic at offset 0');
	assert.strictEqual(view[1], RING_BUFFER_VERSION, 'version at offset 4');
	assert.strictEqual(view[2], 16, 'slotSize at offset 8');
	assert.strictEqual(view[3], 8, 'slotCount at offset 12');
});

test('constructor initializes head/tail/dropped to zero', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 8 });
	assert.strictEqual(ring.headIndex, 0);
	assert.strictEqual(ring.tailIndex, 0);
	assert.strictEqual(ring.droppedCount(), 0);
	assert.strictEqual(ring.occupancy, 0);
});

// ─── Validation ────────────────────────────────────────────────────────

test('rejects slotSize below 16', () => {
	assert.throws(() => new SharedRingBuffer({ slotSize: 8, slotCount: 16 }), /slotSize/);
});

test('rejects slotSize not multiple of 8', () => {
	assert.throws(() => new SharedRingBuffer({ slotSize: 17, slotCount: 16 }), /slotSize/);
});

test('rejects non-power-of-two slotCount', () => {
	assert.throws(() => new SharedRingBuffer({ slotSize: 16, slotCount: 100 }), /slotCount/);
});

test('rejects zero slotCount', () => {
	assert.throws(() => new SharedRingBuffer({ slotSize: 16, slotCount: 0 }), /slotCount/);
});

// ─── tryProduce / drain roundtrip ──────────────────────────────────────

test('tryProduce + drain roundtrip preserves bytes', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 8 });
	const expectedSeq = 0xDEADBEEFCAFEBABEn;
	const expectedData = 0x12345678;

	const ok = ring.tryProduce((slot) => {
		const view = new DataView(slot.buffer, slot.byteOffset, slot.byteLength);
		view.setBigUint64(0, expectedSeq, true);
		view.setUint32(8, expectedData, true);
	});
	assert.strictEqual(ok, true);
	assert.strictEqual(ring.occupancy, 1);

	let actualSeq: bigint | null = null;
	let actualData = 0;
	const drained = ring.drain((slot, seq) => {
		actualSeq = seq;
		actualData = new DataView(slot.buffer, slot.byteOffset, slot.byteLength).getUint32(8, true);
	});

	assert.strictEqual(drained, 1);
	assert.strictEqual(actualSeq, expectedSeq);
	assert.strictEqual(actualData, expectedData);
	assert.strictEqual(ring.occupancy, 0);
});

test('drain empty ring returns 0', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 8 });
	let calls = 0;
	const drained = ring.drain(() => { calls++; });
	assert.strictEqual(drained, 0);
	assert.strictEqual(calls, 0);
});

// ─── Sequence monotonicity ─────────────────────────────────────────────

test('sequence monotonicity across 10 slots', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 16 });
	for (let i = 0; i < 10; i++) {
		ring.tryProduce((slot) => {
			new DataView(slot.buffer, slot.byteOffset, 8).setBigUint64(0, BigInt(i), true);
		});
	}
	const seqs: bigint[] = [];
	ring.drain((_slot, seq) => { seqs.push(seq); });
	assert.strictEqual(seqs.length, 10);
	for (let i = 0; i < 10; i++) {
		assert.strictEqual(seqs[i], BigInt(i), `seq[${i}]`);
	}
});

// ─── Drop counter on overflow ─────────────────────────────────────────

test('drop counter: 5000 writes into 4096-slot ring with no draining', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 4096 });
	let succeeded = 0;
	let failedCount = 0;

	for (let i = 0; i < 5000; i++) {
		const ok = ring.tryProduce((slot) => {
			new DataView(slot.buffer, slot.byteOffset, 8).setBigUint64(0, BigInt(i), true);
		});
		if (ok) succeeded++; else failedCount++;
	}

	// Ring holds slotCount - 1 = 4095 entries before declaring "full"
	// (one slot kept empty to distinguish full from empty).
	assert.strictEqual(succeeded, 4095, `expected 4095 successful writes, got ${succeeded}`);
	assert.strictEqual(failedCount, 5000 - 4095, `expected ${5000 - 4095} failed writes`);
	assert.strictEqual(ring.droppedCount(), 5000 - 4095);

	// Subsequent drain should process exactly 4095 slots.
	const drained = ring.drain(() => { /* noop */ }, 10000);
	assert.strictEqual(drained, 4095, `expected 4095 drained, got ${drained}`);
});

// ─── attach() consumer-side ────────────────────────────────────────────

test('attach() reuses an existing buffer and reads same bytes', () => {
	const producer = new SharedRingBuffer({ slotSize: 16, slotCount: 8 });
	producer.tryProduce((slot) => {
		new DataView(slot.buffer, slot.byteOffset, 8).setBigUint64(0, 42n, true);
	});

	const consumer = SharedRingBuffer.attach(producer.buffer);
	assert.strictEqual(consumer.slotSize, 16);
	assert.strictEqual(consumer.slotCount, 8);
	assert.strictEqual(consumer.occupancy, 1);

	let seenSeq: bigint | null = null;
	consumer.drain((_slot, seq) => { seenSeq = seq; });
	assert.strictEqual(seenSeq, 42n);
});

test('attach() rejects buffer with bad magic', () => {
	const buf = new SharedArrayBuffer(64 + 16 * 8);
	const view = new Int32Array(buf, 0, 16);
	view[0] = 0xBADBABE;
	assert.throws(() => SharedRingBuffer.attach(buf), /magic/);
});

test('attach() rejects buffer too small', () => {
	const buf = new SharedArrayBuffer(32);
	assert.throws(() => SharedRingBuffer.attach(buf), /too small/);
});

// ─── Wraparound ────────────────────────────────────────────────────────

test('producer + consumer interleave wraps around the ring', () => {
	const ring = new SharedRingBuffer({ slotSize: 16, slotCount: 4 });
	const seqs: bigint[] = [];
	let nextSeq = 0n;

	for (let round = 0; round < 5; round++) {
		// Push 3 (ring holds 3 = slotCount - 1)
		for (let i = 0; i < 3; i++) {
			const ok = ring.tryProduce((slot) => {
				new DataView(slot.buffer, slot.byteOffset, 8).setBigUint64(0, nextSeq, true);
			});
			assert.strictEqual(ok, true, `round ${round} push ${i}`);
			nextSeq++;
		}
		// Drain all 3
		const drained = ring.drain((_slot, seq) => { seqs.push(seq); });
		assert.strictEqual(drained, 3, `round ${round} drained`);
	}

	assert.strictEqual(seqs.length, 15);
	for (let i = 0; i < 15; i++) {
		assert.strictEqual(seqs[i], BigInt(i), `seq[${i}] after wraparound`);
	}
});

// ─── Result ────────────────────────────────────────────────────────────

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	process.exit(1);
}
