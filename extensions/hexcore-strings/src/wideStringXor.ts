/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scoreString, isPrintable, formatKeyHex } from './scoringEngine';
import { MultiByteXorResult, MultiByteXorOptions } from './multiByteXor';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Result from wide string (UTF-16LE) XOR deobfuscation scan.
 */
export interface WideStringXorResult extends MultiByteXorResult {
	/** Original byte length before UTF-16LE → UTF-8 conversion */
	originalByteLength: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOTAL_RESULTS = 2000;
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect wide strings (UTF-16LE) that have been XOR-encrypted.
 *
 * Algorithm:
 * 1. For each candidate key (single-byte 0x01–0xFF and 2-byte word-aligned):
 *    a. Decode buffer with XOR
 *    b. Check UTF-16LE pattern: alternating null bytes (byte[2i+1] == 0x00)
 *       for ASCII characters, or valid UTF-16LE byte pairs
 *    c. If pattern detected, convert UTF-16LE → UTF-8
 *    d. Score the converted string (ignoring null bytes in calculation)
 * 2. Also test word-aligned XOR: 2-byte XOR over pairs
 *
 * @param buffer     Raw binary data chunk
 * @param baseOffset File offset where this chunk starts
 * @param options    Scanner configuration
 */
export function wideStringXorScan(
	buffer: Buffer,
	baseOffset: number,
	options?: MultiByteXorOptions,
): WideStringXorResult[] {
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;

	const results: WideStringXorResult[] = [];
	const seen = new Set<string>();

	// Need at least 4 bytes for a 2-char UTF-16LE string
	if (buffer.length < 4) {
		return results;
	}

	// --- Single-byte XOR keys ---
	for (let key = 0x01; key <= 0xFF; key++) {
		scanWithSingleByteKey(buffer, baseOffset, key, minLength, minConfidence, results, seen);
		if (results.length >= MAX_TOTAL_RESULTS) {
			break;
		}
	}

	// --- 2-byte word-aligned XOR keys ---
	if (results.length < MAX_TOTAL_RESULTS) {
		scanWithWordAlignedKeys(buffer, baseOffset, minLength, minConfidence, results, seen);
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	if (results.length > MAX_TOTAL_RESULTS) {
		results.length = MAX_TOTAL_RESULTS;
	}

	return results;
}

// ---------------------------------------------------------------------------
// Single-byte XOR scan
// ---------------------------------------------------------------------------

/**
 * Decode buffer with a single-byte XOR key and look for UTF-16LE patterns.
 */
function scanWithSingleByteKey(
	buffer: Buffer,
	baseOffset: number,
	key: number,
	minLength: number,
	minConfidence: number,
	results: WideStringXorResult[],
	seen: Set<string>,
): void {
	const decoded = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		decoded[i] = buffer[i] ^ key;
	}

	extractWideStrings(decoded, baseOffset, Buffer.from([key]), 1, minLength, minConfidence, results, seen);
}

// ---------------------------------------------------------------------------
// Word-aligned 2-byte XOR scan
// ---------------------------------------------------------------------------

/**
 * Decode buffer with 2-byte XOR keys applied word-aligned over pairs.
 * Uses frequency analysis on even/odd byte positions to derive candidate keys.
 */
function scanWithWordAlignedKeys(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	minConfidence: number,
	results: WideStringXorResult[],
	seen: Set<string>,
): void {
	if (buffer.length < 4) {
		return;
	}

	// Frequency analysis on even and odd positions
	const freqEven = new Uint32Array(256);
	const freqOdd = new Uint32Array(256);
	for (let i = 0; i < buffer.length - 1; i += 2) {
		freqEven[buffer[i]]++;
		freqOdd[buffer[i + 1]]++;
	}

	let maxEven = 0, maxEvenByte = 0;
	let maxOdd = 0, maxOddByte = 0;
	for (let b = 0; b < 256; b++) {
		if (freqEven[b] > maxEven) { maxEven = freqEven[b]; maxEvenByte = b; }
		if (freqOdd[b] > maxOdd) { maxOdd = freqOdd[b]; maxOddByte = b; }
	}

	// For UTF-16LE ASCII, odd bytes should be 0x00 after decoding
	// Try assumptions: most frequent odd byte XOR'd with 0x00 = key[1]
	// Most frequent even byte XOR'd with common chars = key[0]
	const assumptions = [0x00, 0x20, 0x65];
	for (const assumed of assumptions) {
		const key0 = maxEvenByte ^ assumed;
		const key1 = maxOddByte ^ 0x00; // odd bytes should be null for ASCII UTF-16LE

		if (key0 === 0 && key1 === 0) {
			continue;
		}

		const keyBuf = Buffer.from([key0, key1]);
		const decoded = Buffer.alloc(buffer.length);
		for (let i = 0; i < buffer.length; i++) {
			decoded[i] = buffer[i] ^ keyBuf[i % 2];
		}

		extractWideStrings(decoded, baseOffset, keyBuf, 2, minLength, minConfidence, results, seen);

		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// UTF-16LE detection and extraction
// ---------------------------------------------------------------------------

/**
 * Scan a decoded buffer for UTF-16LE patterns (alternating null bytes)
 * and extract wide strings, converting them to UTF-8.
 */
function extractWideStrings(
	decoded: Buffer,
	baseOffset: number,
	key: Buffer,
	keySize: number,
	minLength: number,
	minConfidence: number,
	results: WideStringXorResult[],
	seen: Set<string>,
): void {
	// Find runs of valid UTF-16LE ASCII: byte[2i] is printable, byte[2i+1] == 0x00
	const runs = findUtf16leRuns(decoded, minLength);

	const keyHex = formatKeyHex(key);

	for (const run of runs) {
		// Convert UTF-16LE → UTF-8
		const wideSlice = decoded.subarray(run.start, run.start + run.byteLength);
		const converted = wideSlice.toString('utf16le');
		const charLength = converted.length;

		if (charLength < minLength) {
			continue;
		}

		// Score using the wide slice with ignoreNullBytes
		const confidence = scoreString(decoded, run.start, run.byteLength, { ignoreNullBytes: true });
		if (confidence < minConfidence) {
			continue;
		}

		const dedupKey = `${baseOffset + run.start}:${converted}`;
		if (seen.has(dedupKey)) {
			continue;
		}
		seen.add(dedupKey);

		results.push({
			value: converted,
			offset: baseOffset + run.start,
			key: Buffer.from(key),
			keyHex,
			keySize,
			method: 'XOR-wide',
			confidence,
			originalByteLength: run.byteLength,
		});

		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// UTF-16LE run detection
// ---------------------------------------------------------------------------

interface Utf16leRun {
	/** Byte offset in the decoded buffer where the run starts */
	start: number;
	/** Length in bytes (always even) */
	byteLength: number;
}

/**
 * Find contiguous runs of valid UTF-16LE ASCII characters.
 * A valid UTF-16LE ASCII pair is: byte[2i] is printable ASCII, byte[2i+1] == 0x00.
 */
function findUtf16leRuns(decoded: Buffer, minCharLength: number): Utf16leRun[] {
	const runs: Utf16leRun[] = [];
	let runStart = -1;
	let charCount = 0;

	// Process pairs of bytes
	const pairCount = Math.floor(decoded.length / 2);
	for (let p = 0; p < pairCount; p++) {
		const lo = decoded[p * 2];
		const hi = decoded[p * 2 + 1];

		if (hi === 0x00 && isPrintable(lo)) {
			if (runStart === -1) {
				runStart = p * 2;
				charCount = 0;
			}
			charCount++;
		} else {
			if (charCount >= minCharLength) {
				runs.push({ start: runStart, byteLength: charCount * 2 });
			}
			runStart = -1;
			charCount = 0;
		}
	}

	// Flush last run
	if (charCount >= minCharLength) {
		runs.push({ start: runStart, byteLength: charCount * 2 });
	}

	return runs;
}
