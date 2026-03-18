/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scoreString, isPrintable, extractPrintableRuns, formatKeyHex } from './scoringEngine';
import { MultiByteXorResult, MultiByteXorOptions } from './multiByteXor';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Result from rolling XOR extended deobfuscation scan.
 */
export interface RollingXorExtResult extends MultiByteXorResult {
	/** Window size (1–4 previous bytes used for XOR) */
	windowSize: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOTAL_RESULTS = 2000;
const MAX_ROLLING_WINDOW = 4;
const QUICK_CHECK_SAMPLE = 256;
const QUICK_CHECK_THRESHOLD = 0.05;
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;

// ---------------------------------------------------------------------------
// Encoding / Decoding helpers (exported for round-trip testing)
// ---------------------------------------------------------------------------

/**
 * Encode plaintext → ciphertext using rolling XOR extended.
 *
 * encoded[0] = plaintext[0] ^ seed  (for window=1; for window>1, seed is used for all missing previous bytes)
 * encoded[i] = plaintext[i] ^ XOR(encoded[i-1], ..., encoded[i-N])
 *
 * Note: encode uses the ENCODED (ciphertext) bytes for the window, not the plaintext bytes.
 * For positions where i < windowSize, missing previous encoded bytes are filled with seed.
 */
export function rollingXorExtEncode(plaintext: Buffer, seed: number, windowSize: number): Buffer {
	const len = plaintext.length;
	const encoded = Buffer.alloc(len);

	for (let i = 0; i < len; i++) {
		let xorVal = 0;
		for (let w = 1; w <= windowSize; w++) {
			if (i - w >= 0) {
				xorVal ^= encoded[i - w];
			} else {
				xorVal ^= seed;
			}
		}
		encoded[i] = plaintext[i] ^ xorVal;
	}

	return encoded;
}

/**
 * Decode ciphertext → plaintext using rolling XOR extended.
 *
 * decoded[0] = buffer[0] ^ seed  (for window=1; for window>1, seed fills missing previous bytes)
 * decoded[i] = buffer[i] ^ XOR(buffer[i-1], ..., buffer[i-N])
 *
 * Note: decode uses the CIPHERTEXT (buffer) bytes for the window.
 * For positions where i < windowSize, missing previous ciphertext bytes are filled with seed.
 */
export function rollingXorExtDecode(buffer: Buffer, seed: number, windowSize: number): Buffer {
	const len = buffer.length;
	const decoded = Buffer.alloc(len);

	for (let i = 0; i < len; i++) {
		let xorVal = 0;
		for (let w = 1; w <= windowSize; w++) {
			if (i - w >= 0) {
				xorVal ^= buffer[i - w];
			} else {
				xorVal ^= seed;
			}
		}
		decoded[i] = buffer[i] ^ xorVal;
	}

	return decoded;
}


// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a buffer for strings obfuscated with rolling XOR extended.
 *
 * Rolling XOR with window of N previous bytes:
 *   decoded[i] = buffer[i] ^ XOR(buffer[i-1], ..., buffer[i-N])
 *
 * For i < N, missing previous bytes are filled with seed (tested 0x00–0xFF).
 *
 * Window 1: decoded[i] = buffer[i] ^ buffer[i-1]
 * Window 2: decoded[i] = buffer[i] ^ (buffer[i-1] ^ buffer[i-2])
 * Window 3: decoded[i] = buffer[i] ^ (buffer[i-1] ^ buffer[i-2] ^ buffer[i-3])
 * Window 4: decoded[i] = buffer[i] ^ (buffer[i-1] ^ buffer[i-2] ^ buffer[i-3] ^ buffer[i-4])
 *
 * Quick-check with 256 bytes for each seed × windowSize combination.
 *
 * @param buffer     Raw binary data chunk (ciphertext)
 * @param baseOffset File offset where this chunk starts
 * @param options    Scanner configuration
 */
export function rollingXorExtScan(
	buffer: Buffer,
	baseOffset: number,
	options?: MultiByteXorOptions,
): RollingXorExtResult[] {
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;

	const results: RollingXorExtResult[] = [];
	const seen = new Set<string>();

	if (buffer.length < 2) {
		return results;
	}

	for (let windowSize = 1; windowSize <= MAX_ROLLING_WINDOW; windowSize++) {
		for (let seed = 0x00; seed <= 0xFF; seed++) {
			// Quick-check: decode first QUICK_CHECK_SAMPLE bytes and check printability
			const sampleSize = Math.min(QUICK_CHECK_SAMPLE, buffer.length);
			let printable = 0;

			for (let i = 0; i < sampleSize; i++) {
				let xorVal = 0;
				for (let w = 1; w <= windowSize; w++) {
					if (i - w >= 0) {
						xorVal ^= buffer[i - w];
					} else {
						xorVal ^= seed;
					}
				}
				const decoded = buffer[i] ^ xorVal;
				if (isPrintable(decoded)) {
					printable++;
				}
			}

			if ((printable / sampleSize) < QUICK_CHECK_THRESHOLD) {
				continue;
			}

			// Full decode
			const decoded = rollingXorExtDecode(buffer, seed, windowSize);

			// Extract and score printable runs
			const runs = extractPrintableRuns(decoded, minLength);
			const keyBuf = Buffer.from([seed]);
			const keyHex = formatKeyHex(keyBuf);

			for (const run of runs) {
				const confidence = scoreString(decoded, run.start, run.length);
				if (confidence < minConfidence) {
					continue;
				}

				const value = decoded.subarray(run.start, run.start + run.length).toString('ascii');
				const dedupKey = `${baseOffset + run.start}:${value}`;

				if (seen.has(dedupKey)) {
					continue;
				}
				seen.add(dedupKey);

				results.push({
					value,
					offset: baseOffset + run.start,
					key: Buffer.from(keyBuf),
					keyHex,
					keySize: 1,
					method: 'XOR-rolling-ext',
					confidence,
					windowSize,
				});

				if (results.length >= MAX_TOTAL_RESULTS) {
					return results;
				}
			}

			if (results.length >= MAX_TOTAL_RESULTS) {
				break;
			}
		}

		if (results.length >= MAX_TOTAL_RESULTS) {
			break;
		}
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	if (results.length > MAX_TOTAL_RESULTS) {
		results.length = MAX_TOTAL_RESULTS;
	}

	return results;
}
