/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * SharedRingBuffer — Lock-free SPSC ring buffer over SharedArrayBuffer.
 *
 * Producer: native C++ code (e.g. hexcore-unicorn CodeHookSabCB) writes
 *           events directly to slots and advances `head` with release semantics.
 * Consumer: this TypeScript class reads slots and advances `tail` with
 *           acquire semantics.
 *
 * Sync model: single-producer single-consumer (SPSC), no mutex.
 * Drop policy: drop-newest. When `next == tail`, the producer increments
 *              `droppedCount` and returns. Consumer detects gaps via the
 *              per-slot sequence number (first 8 bytes of each slot).
 *
 * v4.0.0 — Issue #31 / docs/zero-copy-ipc-design.md
 */

// ─────────────────────────────────────────────────────────────────────────
// Constants — must stay byte-for-byte identical to the C++ RingHeader in
// extensions/hexcore-unicorn/src/unicorn_wrapper.h. Any change here MUST
// be mirrored in the C++ struct + static_assert.
// ─────────────────────────────────────────────────────────────────────────

/** "HRNG" little-endian — magic bytes at offset 0 */
export const RING_BUFFER_MAGIC = 0x48524E47;

/** Layout version — bump if the header or slot layout changes */
export const RING_BUFFER_VERSION = 1;

/** Header size in bytes (cache-line aligned) */
export const RING_BUFFER_HEADER_SIZE = 64;

/** Header field offsets in bytes */
const HEADER_OFFSET_MAGIC = 0;
const HEADER_OFFSET_VERSION = 4;
const HEADER_OFFSET_SLOT_SIZE = 8;
const HEADER_OFFSET_SLOT_COUNT = 12;
const HEADER_OFFSET_HEAD = 16;
const HEADER_OFFSET_TAIL = 24;
const HEADER_OFFSET_DROPPED = 32;

/** Int32Array indices (offset / 4) for fields that JS reads atomically */
const HEAD_INDEX_I32 = HEADER_OFFSET_HEAD / 4;
const TAIL_INDEX_I32 = HEADER_OFFSET_TAIL / 4;
const DROPPED_INDEX_I32 = HEADER_OFFSET_DROPPED / 4;

// ─────────────────────────────────────────────────────────────────────────
// Public types
// ─────────────────────────────────────────────────────────────────────────

export interface SharedRingBufferOptions {
	/** Bytes per slot. Must be >= 16 and a multiple of 8. */
	readonly slotSize: number;
	/** Number of slots. Must be a power of two. Recommended: 4096. */
	readonly slotCount: number;
}

/** Callback invoked once per drained slot. The slot is a view into the SAB — do not retain it. */
export type SlotConsumer = (slot: Uint8Array, sequenceNumber: bigint) => void;

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

function isPowerOfTwo(n: number): boolean {
	return n > 0 && (n & (n - 1)) === 0;
}

function validateOptions(options: SharedRingBufferOptions): void {
	if (!Number.isInteger(options.slotSize) || options.slotSize < 16 || (options.slotSize & 7) !== 0) {
		throw new RangeError(
			`SharedRingBuffer: slotSize must be an integer >= 16 and multiple of 8, got ${options.slotSize}`
		);
	}
	if (!Number.isInteger(options.slotCount) || !isPowerOfTwo(options.slotCount)) {
		throw new RangeError(
			`SharedRingBuffer: slotCount must be a positive power of two, got ${options.slotCount}`
		);
	}
}

// ─────────────────────────────────────────────────────────────────────────
// SharedRingBuffer
// ─────────────────────────────────────────────────────────────────────────

/**
 * Lock-free SPSC ring buffer over a SharedArrayBuffer.
 *
 * Layout:
 * ```
 * offset  field          type     atomic
 * 0x00    magic          u32      no       (0x48524E47 "HRNG")
 * 0x04    version        u32      no       (1)
 * 0x08    slotSize       u32      no
 * 0x0C    slotCount      u32      no
 * 0x10    head           u32      yes      (producer cursor)
 * 0x14    _pad0          u32      no
 * 0x18    tail           u32      yes      (consumer cursor)
 * 0x1C    _pad1          u32      no
 * 0x20    droppedCount   u32      yes      (producer increments on overflow)
 * 0x24    producerSeqHi  u32      no       (reserved)
 * 0x28    _reserved[6]   u32×6    no
 * 0x40    payload[0]     slotSize ×
 * 0x40+N  payload[1]     slotSize ×
 * ...
 * ```
 *
 * Memory ordering:
 *  - Producer writes the slot, then `head.store(next, release)`.
 *  - Consumer `tail.load(acquire)` followed by reading the slot is safe
 *    because the C++ release barrier on `head` synchronizes-with the JS
 *    Atomics.load on `head`.
 */
export class SharedRingBuffer {
	public readonly buffer: SharedArrayBuffer;
	public readonly slotSize: number;
	public readonly slotCount: number;

	private readonly _slotMask: number;
	private readonly _headerView: Int32Array;
	private readonly _payload: Uint8Array;

	/**
	 * Allocate a new ring buffer of the requested size.
	 * Total allocation = 64 byte header + slotSize × slotCount payload.
	 */
	constructor(options: SharedRingBufferOptions) {
		validateOptions(options);

		const totalSize = RING_BUFFER_HEADER_SIZE + options.slotSize * options.slotCount;
		this.buffer = new SharedArrayBuffer(totalSize);
		this.slotSize = options.slotSize;
		this.slotCount = options.slotCount;
		this._slotMask = options.slotCount - 1;

		this._headerView = new Int32Array(this.buffer, 0, RING_BUFFER_HEADER_SIZE / 4);
		this._payload = new Uint8Array(this.buffer, RING_BUFFER_HEADER_SIZE, options.slotSize * options.slotCount);

		// Initialize header (write fields directly — head/tail/dropped start at 0).
		this._headerView[HEADER_OFFSET_MAGIC / 4] = RING_BUFFER_MAGIC;
		this._headerView[HEADER_OFFSET_VERSION / 4] = RING_BUFFER_VERSION;
		this._headerView[HEADER_OFFSET_SLOT_SIZE / 4] = options.slotSize;
		this._headerView[HEADER_OFFSET_SLOT_COUNT / 4] = options.slotCount;
		Atomics.store(this._headerView, HEAD_INDEX_I32, 0);
		Atomics.store(this._headerView, TAIL_INDEX_I32, 0);
		Atomics.store(this._headerView, DROPPED_INDEX_I32, 0);
	}

	/**
	 * Attach a consumer-side view to an existing SharedArrayBuffer that was
	 * previously initialized as a ring (typically by a constructor call in
	 * another thread or extension). Validates the magic and version.
	 */
	static attach(buffer: SharedArrayBuffer): SharedRingBuffer {
		if (buffer.byteLength < RING_BUFFER_HEADER_SIZE) {
			throw new RangeError(
				`SharedRingBuffer.attach: buffer too small (${buffer.byteLength} < ${RING_BUFFER_HEADER_SIZE})`
			);
		}
		const headerView = new Int32Array(buffer, 0, RING_BUFFER_HEADER_SIZE / 4);
		const magic = headerView[HEADER_OFFSET_MAGIC / 4];
		if (magic !== RING_BUFFER_MAGIC) {
			throw new Error(
				`SharedRingBuffer.attach: bad magic 0x${(magic >>> 0).toString(16)}, expected 0x${RING_BUFFER_MAGIC.toString(16)}`
			);
		}
		const version = headerView[HEADER_OFFSET_VERSION / 4];
		if (version !== RING_BUFFER_VERSION) {
			throw new Error(
				`SharedRingBuffer.attach: version mismatch (got ${version}, expected ${RING_BUFFER_VERSION})`
			);
		}
		const slotSize = headerView[HEADER_OFFSET_SLOT_SIZE / 4];
		const slotCount = headerView[HEADER_OFFSET_SLOT_COUNT / 4];

		// Construct a wrapper without re-allocating. Use a private factory.
		return SharedRingBuffer._wrapExisting(buffer, slotSize, slotCount);
	}

	private static _wrapExisting(buffer: SharedArrayBuffer, slotSize: number, slotCount: number): SharedRingBuffer {
		validateOptions({ slotSize, slotCount });
		const expected = RING_BUFFER_HEADER_SIZE + slotSize * slotCount;
		if (buffer.byteLength < expected) {
			throw new RangeError(
				`SharedRingBuffer._wrapExisting: buffer too small (${buffer.byteLength} < ${expected})`
			);
		}
		// Bypass the constructor's allocation by using Object.create then init.
		const inst = Object.create(SharedRingBuffer.prototype) as SharedRingBuffer;
		// @ts-expect-error — assigning to readonly fields during construction
		inst.buffer = buffer;
		// @ts-expect-error
		inst.slotSize = slotSize;
		// @ts-expect-error
		inst.slotCount = slotCount;
		// @ts-expect-error
		inst._slotMask = slotCount - 1;
		// @ts-expect-error
		inst._headerView = new Int32Array(buffer, 0, RING_BUFFER_HEADER_SIZE / 4);
		// @ts-expect-error
		inst._payload = new Uint8Array(buffer, RING_BUFFER_HEADER_SIZE, slotSize * slotCount);
		return inst;
	}

	// ─── Consumer API ────────────────────────────────────────────────────

	/**
	 * Drain available slots. Calls `onSlot` for each one with a Uint8Array view
	 * over the slot bytes (do NOT retain the view — it points into the SAB and
	 * may be overwritten on the next producer write).
	 *
	 * Returns the number of slots processed. Stops at `maxPerBatch` to avoid
	 * starving the event loop on long bursts.
	 */
	drain(onSlot: SlotConsumer, maxPerBatch: number = 1024): number {
		let processed = 0;
		const head = Atomics.load(this._headerView, HEAD_INDEX_I32) >>> 0;
		let tail = Atomics.load(this._headerView, TAIL_INDEX_I32) >>> 0;

		while (tail !== head && processed < maxPerBatch) {
			const slotOffset = tail * this.slotSize;
			const slot = this._payload.subarray(slotOffset, slotOffset + this.slotSize);

			// First 8 bytes of every slot are the sequence number (producer convention).
			const seq = new DataView(slot.buffer, slot.byteOffset, 8).getBigUint64(0, true);

			onSlot(slot, seq);
			tail = (tail + 1) & this._slotMask;
			processed++;
		}

		if (processed > 0) {
			Atomics.store(this._headerView, TAIL_INDEX_I32, tail | 0);
		}
		return processed;
	}

	/** Number of slots the producer dropped due to ring overflow. */
	droppedCount(): number {
		return Atomics.load(this._headerView, DROPPED_INDEX_I32) >>> 0;
	}

	/** Current producer index (advances as the producer writes). */
	get headIndex(): number {
		return Atomics.load(this._headerView, HEAD_INDEX_I32) >>> 0;
	}

	/** Current consumer index (advances as the consumer drains). */
	get tailIndex(): number {
		return Atomics.load(this._headerView, TAIL_INDEX_I32) >>> 0;
	}

	/** Approximate number of unread slots (modulo arithmetic). */
	get occupancy(): number {
		const head = this.headIndex;
		const tail = this.tailIndex;
		return (head - tail) & this._slotMask;
	}

	// ─── Test helpers (also useful for the C++ test bridge) ──────────────

	/**
	 * Producer-side write — used ONLY by tests and by the JS-side test harness
	 * that simulates the native producer. Real production producer is C++.
	 *
	 * Returns true on success, false if the ring was full (slot dropped).
	 *
	 * NOTE: this is single-producer. Calling from multiple JS threads is unsafe.
	 */
	tryProduce(writer: (slot: Uint8Array) => void): boolean {
		const head = Atomics.load(this._headerView, HEAD_INDEX_I32) >>> 0;
		const next = (head + 1) & this._slotMask;
		const tail = Atomics.load(this._headerView, TAIL_INDEX_I32) >>> 0;
		if (next === tail) {
			// Drop newest, increment dropped counter.
			Atomics.add(this._headerView, DROPPED_INDEX_I32, 1);
			return false;
		}
		const slotOffset = head * this.slotSize;
		const slot = this._payload.subarray(slotOffset, slotOffset + this.slotSize);
		writer(slot);
		Atomics.store(this._headerView, HEAD_INDEX_I32, next | 0);
		return true;
	}
}
