/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export function formatBytes(bytes: number): string;
export function calculateEntropy(buffer: Buffer): number;
export function readNullTerminatedString(buffer: Buffer, maxLength?: number): string;
export function isPrintableASCII(byte: number): boolean;
export function toHexDump(buffer: Buffer, bytesPerLine?: number): string;
export function escapeHtml(text: string): string;
export function formatHex(value: number, padLength?: number): string;
export function processFileInChunks(
	filePath: string,
	chunkSize: number,
	processor: (chunk: Buffer, offset: number) => void | Promise<void>,
	onProgress?: (bytesProcessed: number, totalBytes: number) => void
): Promise<void>;

export interface NativeModuleLoadOptions {
	moduleName: string;
	candidatePaths?: string[];
}

export interface NativeModuleLoadResult<T> {
	module?: T;
	error?: Error;
	attemptedPaths: string[];
	errorMessage: string;
}

export function loadNativeModule<T = unknown>(options: NativeModuleLoadOptions): NativeModuleLoadResult<T>;

export function getHexCoreBaseCSS(): string;

export function riskLevelToColor(level: 'safe' | 'warning' | 'danger'): string;
export function entropyToColor(value: number): string;

// v4.0.0 — SharedArrayBuffer zero-copy IPC primitives (Issue #31)

export const RING_BUFFER_MAGIC: number;
export const RING_BUFFER_VERSION: number;
export const RING_BUFFER_HEADER_SIZE: number;
export const SHARED_MEMORY_HEADER_SIZE: number;

export interface SharedRingBufferOptions {
	readonly slotSize: number;
	readonly slotCount: number;
}

export type SlotConsumer = (slot: Uint8Array, sequenceNumber: bigint) => void;

export class SharedRingBuffer {
	constructor(options: SharedRingBufferOptions);
	static attach(buffer: SharedArrayBuffer): SharedRingBuffer;
	readonly buffer: SharedArrayBuffer;
	readonly slotSize: number;
	readonly slotCount: number;
	drain(onSlot: SlotConsumer, maxPerBatch?: number): number;
	droppedCount(): number;
	get headIndex(): number;
	get tailIndex(): number;
	get occupancy(): number;
	tryProduce(writer: (slot: Uint8Array) => void): boolean;
}

export interface SharedMemoryBufferOptions {
	readonly payloadSize: number;
}

export const SHARED_MEMORY_STATUS: {
	readonly IDLE: 0;
	readonly BUSY: 1;
	readonly COMPLETE: 2;
	readonly ERROR: -1;
};

export class SharedMemoryBuffer {
	constructor(options: SharedMemoryBufferOptions);
	readonly buffer: SharedArrayBuffer;
	readonly totalSize: number;
	readonly payloadSize: number;
	readonly headerView: Int32Array;
	readonly payloadView: Uint8Array;
	getDataSize(): number;
	setDataSize(size: number): void;
	getStatus(): number;
	setStatus(status: number): void;
	getActivePayload(): Uint8Array;
}
