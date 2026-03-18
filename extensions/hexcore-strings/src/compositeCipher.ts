/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scoreString, extractPrintableRuns, isPrintable, formatKeyHex } from './scoringEngine';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOTAL_RESULTS = 2000;
const QUICK_CHECK_SAMPLE = 256;
const QUICK_CHECK_THRESHOLD = 0.05;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CipherOperation = 'ADD' | 'SUB' | 'ROT';

export interface CompositeCipherResult {
	value: string;
	offset: number;
	key: Buffer;
	keyHex: string;
	keySize: number;
	method: 'ADD' | 'SUB' | 'ROT';
	confidence: number;
	cipherOp: CipherOperation;
	cipherKey: number;
	rotValue?: number;
}

// ---------------------------------------------------------------------------
// Encode / Decode helpers (exported for testing)
// ---------------------------------------------------------------------------

export function addEncode(buffer: Buffer, key: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = (buffer[i] + key) & 0xFF;
	}
	return out;
}

export function addDecode(buffer: Buffer, key: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = (buffer[i] - key) & 0xFF;
	}
	return out;
}

export function subEncode(buffer: Buffer, key: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = (buffer[i] - key) & 0xFF;
	}
	return out;
}

export function subDecode(buffer: Buffer, key: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = (buffer[i] + key) & 0xFF;
	}
	return out;
}

export function rotEncode(buffer: Buffer, n: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i];
		if (byte >= 0x41 && byte <= 0x5A) {
			// Uppercase
			out[i] = ((byte - 0x41 + n) % 26) + 0x41;
		} else if (byte >= 0x61 && byte <= 0x7A) {
			// Lowercase
			out[i] = ((byte - 0x61 + n) % 26) + 0x61;
		} else {
			out[i] = byte;
		}
	}
	return out;
}

export function rotDecode(buffer: Buffer, n: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i];
		if (byte >= 0x41 && byte <= 0x5A) {
			// Uppercase: rotate back by n
			out[i] = ((byte - 0x41 - n + 26) % 26) + 0x41;
		} else if (byte >= 0x61 && byte <= 0x7A) {
			// Lowercase: rotate back by n
			out[i] = ((byte - 0x61 - n + 26) % 26) + 0x61;
		} else {
			out[i] = byte;
		}
	}
	return out;
}

// ---------------------------------------------------------------------------
// Quick-check helper
// ---------------------------------------------------------------------------

function quickCheckPrintable(decoded: Buffer): boolean {
	const sampleLen = Math.min(decoded.length, QUICK_CHECK_SAMPLE);
	if (sampleLen === 0) { return false; }
	let printableCount = 0;
	for (let i = 0; i < sampleLen; i++) {
		if (isPrintable(decoded[i])) { printableCount++; }
	}
	return (printableCount / sampleLen) >= QUICK_CHECK_THRESHOLD;
}

// ---------------------------------------------------------------------------
// Collect results from decoded buffer
// ---------------------------------------------------------------------------

function collectResults(
	decoded: Buffer,
	baseOffset: number,
	method: 'ADD' | 'SUB' | 'ROT',
	keyValue: number,
	minLength: number,
	minConfidence: number,
	results: CompositeCipherResult[],
): void {
	const runs = extractPrintableRuns(decoded, minLength);
	for (const run of runs) {
		if (results.length >= MAX_TOTAL_RESULTS) { return; }
		const confidence = scoreString(decoded, run.start, run.length);
		if (confidence < minConfidence) { continue; }

		const value = decoded.slice(run.start, run.start + run.length).toString('ascii');
		const keyBuf = Buffer.from([keyValue]);

		const result: CompositeCipherResult = {
			value,
			offset: baseOffset + run.start,
			key: keyBuf,
			keyHex: formatKeyHex(keyBuf),
			keySize: 1,
			method,
			confidence,
			cipherOp: method,
			cipherKey: keyValue,
		};

		if (method === 'ROT') {
			result.rotValue = keyValue;
		}

		results.push(result);
	}
}

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

/**
 * Scan a buffer for strings encoded with ADD, SUB, or ROT single-byte ciphers.
 *
 * ADD: decoded[i] = (buffer[i] - key) & 0xFF  (inverse of ADD encoding)
 * SUB: decoded[i] = (buffer[i] + key) & 0xFF  (inverse of SUB encoding)
 * ROT: rotate alphabetic bytes back by N (non-alphabetic pass through)
 *
 * @param buffer     Encrypted buffer to scan
 * @param baseOffset Base offset in the file
 * @param options    Scanner options
 */
export function compositeCipherScan(
	buffer: Buffer,
	baseOffset: number,
	options?: { minLength?: number; minConfidence?: number },
): CompositeCipherResult[] {
	const minLength = options?.minLength ?? 4;
	const minConfidence = options?.minConfidence ?? 0.6;
	const results: CompositeCipherResult[] = [];

	if (buffer.length === 0) {
		return results;
	}

	// --- ADD scan: keys 0x01–0xFF ---
	for (let key = 0x01; key <= 0xFF; key++) {
		if (results.length >= MAX_TOTAL_RESULTS) { break; }
		const decoded = addDecode(buffer, key);
		if (!quickCheckPrintable(decoded)) { continue; }
		collectResults(decoded, baseOffset, 'ADD', key, minLength, minConfidence, results);
	}

	// --- SUB scan: keys 0x01–0xFF ---
	for (let key = 0x01; key <= 0xFF; key++) {
		if (results.length >= MAX_TOTAL_RESULTS) { break; }
		const decoded = subDecode(buffer, key);
		if (!quickCheckPrintable(decoded)) { continue; }
		collectResults(decoded, baseOffset, 'SUB', key, minLength, minConfidence, results);
	}

	// --- ROT scan: N 1–25 ---
	for (let n = 1; n <= 25; n++) {
		if (results.length >= MAX_TOTAL_RESULTS) { break; }
		const decoded = rotDecode(buffer, n);
		if (!quickCheckPrintable(decoded)) { continue; }
		collectResults(decoded, baseOffset, 'ROT', n, minLength, minConfidence, results);
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => {
		if (b.confidence !== a.confidence) { return b.confidence - a.confidence; }
		return a.offset - b.offset;
	});

	return results;
}
