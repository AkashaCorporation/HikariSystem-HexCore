/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * SharedMemoryBuffer — Generic SharedArrayBuffer wrapper for non-ring use cases.
 *
 * Provides a 64-byte header + payload layout for one-shot data exchange between
 * JS and a native module. For high-frequency producer/consumer flows (Unicorn
 * hooks), use SharedRingBuffer instead.
 *
 * v4.0.0 — Issue #31 / docs/zero-copy-ipc-design.md
 */

/** Header size in bytes (cache-line aligned) */
export const SHARED_MEMORY_HEADER_SIZE = 64;

/**
 * Standard header field offsets (mirrors hexcore-remill PoC for compatibility,
 * but this class is the production path going forward).
 */
const HEADER_OFFSETS = {
	LOCK_FLAG: 0,    // int32 — 0 unlocked, 1 locked (advisory; native can use std::atomic)
	DATA_SIZE: 4,    // uint32 — payload bytes actually used
	STATUS: 8,       // int32 — operation status
	SEQUENCE_ID: 12, // uint32 — for ordering
	TIMESTAMP_LO: 16, // uint32
	TIMESTAMP_HI: 20, // uint32
	USER_DATA_1_LO: 24,
	USER_DATA_1_HI: 28,
	USER_DATA_2_LO: 32,
	USER_DATA_2_HI: 36,
	// 24 bytes reserved padding to 64
} as const;

/** Operation status codes for the `status` field */
export const SHARED_MEMORY_STATUS = {
	IDLE: 0,
	BUSY: 1,
	COMPLETE: 2,
	ERROR: -1,
} as const;

export interface SharedMemoryBufferOptions {
	/** Payload size in bytes (excluding the 64-byte header) */
	readonly payloadSize: number;
}

/**
 * Wraps a SharedArrayBuffer with typed views for header and payload regions.
 *
 * Use this for one-shot data exchange (e.g. lifting a single function's
 * bytes into a native module without copying). For producer/consumer flows,
 * see SharedRingBuffer.
 */
export class SharedMemoryBuffer {
	public readonly buffer: SharedArrayBuffer;
	public readonly totalSize: number;
	public readonly payloadSize: number;
	public readonly headerView: Int32Array;
	public readonly payloadView: Uint8Array;

	constructor(options: SharedMemoryBufferOptions) {
		if (!Number.isInteger(options.payloadSize) || options.payloadSize < 0) {
			throw new RangeError(`SharedMemoryBuffer: payloadSize must be a non-negative integer, got ${options.payloadSize}`);
		}
		this.payloadSize = options.payloadSize;
		this.totalSize = SHARED_MEMORY_HEADER_SIZE + options.payloadSize;
		this.buffer = new SharedArrayBuffer(this.totalSize);
		this.headerView = new Int32Array(this.buffer, 0, SHARED_MEMORY_HEADER_SIZE / 4);
		this.payloadView = new Uint8Array(this.buffer, SHARED_MEMORY_HEADER_SIZE, options.payloadSize);

		// Initialize header to zero (SAB is zero on alloc, but be explicit).
		Atomics.store(this.headerView, HEADER_OFFSETS.LOCK_FLAG / 4, 0);
		Atomics.store(this.headerView, HEADER_OFFSETS.DATA_SIZE / 4, 0);
		Atomics.store(this.headerView, HEADER_OFFSETS.STATUS / 4, SHARED_MEMORY_STATUS.IDLE);
	}

	/** Get the data size (bytes actually used in the payload). */
	getDataSize(): number {
		return Atomics.load(this.headerView, HEADER_OFFSETS.DATA_SIZE / 4) >>> 0;
	}

	/** Set the data size (consumer/producer convention — call after writing the payload). */
	setDataSize(size: number): void {
		if (!Number.isInteger(size) || size < 0 || size > this.payloadSize) {
			throw new RangeError(`SharedMemoryBuffer.setDataSize: out of range (got ${size}, max ${this.payloadSize})`);
		}
		Atomics.store(this.headerView, HEADER_OFFSETS.DATA_SIZE / 4, size | 0);
	}

	/** Read the operation status code. */
	getStatus(): number {
		return Atomics.load(this.headerView, HEADER_OFFSETS.STATUS / 4);
	}

	/** Write the operation status code. */
	setStatus(status: number): void {
		Atomics.store(this.headerView, HEADER_OFFSETS.STATUS / 4, status | 0);
	}

	/**
	 * Get a Uint8Array view over the active payload region (only the bytes
	 * marked as used via setDataSize).
	 */
	getActivePayload(): Uint8Array {
		const size = this.getDataSize();
		return this.payloadView.subarray(0, size);
	}
}
