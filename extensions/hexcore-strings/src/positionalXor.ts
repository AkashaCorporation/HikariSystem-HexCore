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
 * Result from positional XOR deobfuscation scan (counter-linear or block-rotate).
 */
export interface PositionalXorResult extends MultiByteXorResult {
	derivationParams: {
		type: 'counter-linear' | 'block-rotate';
		base?: number;
		step?: number;
		blockSize?: number;
	};
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOTAL_RESULTS = 2000;
const QUICK_CHECK_SAMPLE = 256;
const QUICK_CHECK_THRESHOLD = 0.05;
const MAX_COUNTER_STEP = 8;
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;

// ---------------------------------------------------------------------------
// Encoding / Decoding helpers (exported for round-trip testing)
// ---------------------------------------------------------------------------

/**
 * Counter-linear encode/decode (XOR is its own inverse):
 * `result[i] = buffer[i] ^ ((base + i * step) & 0xFF)`
 */
export function counterLinearApply(buffer: Buffer, base: number, step: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = buffer[i] ^ ((base + i * step) & 0xFF);
	}
	return out;
}

/**
 * Block-rotate encode/decode (XOR is its own inverse):
 * Key of N bytes is rotated (shifted) every block of M bytes.
 *
 * For key [k0, k1, ..., kN-1] and blockSize M:
 *   Block b: key is rotated by b positions, so effective key byte at
 *   position i within block b is key[(posInBlock + b) % keySize].
 */
export function blockRotateApply(buffer: Buffer, key: Buffer, blockSize: number): Buffer {
	const out = Buffer.alloc(buffer.length);
	const keySize = key.length;
	for (let i = 0; i < buffer.length; i++) {
		const blockIndex = Math.floor(i / blockSize);
		const posInBlock = i % blockSize;
		const keyByte = key[(posInBlock + blockIndex) % keySize];
		out[i] = buffer[i] ^ keyByte;
	}
	return out;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a buffer for strings obfuscated with positional XOR schemes.
 *
 * Counter-linear: decoded[i] = buffer[i] ^ ((base + i * step) & 0xFF)
 * - Tests base 0x00–0xFF, step 1–8
 * - Quick-check with 256 bytes before full decoding
 *
 * Block-rotate: key of N bytes rotated every block of M bytes
 * - Tests keySizes [2, 4, 8] with blockSizes [16, 32, 64, 128, 256]
 * - Uses frequency analysis to derive candidate keys per key size
 *
 * @param buffer     Raw binary data chunk
 * @param baseOffset File offset where this chunk starts
 * @param options    Scanner configuration
 */
export function positionalXorScan(
	buffer: Buffer,
	baseOffset: number,
	options?: MultiByteXorOptions,
): PositionalXorResult[] {
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;

	const results: PositionalXorResult[] = [];
	const seen = new Set<string>();

	// --- Counter-linear scan ---
	scanCounterLinear(buffer, baseOffset, minLength, minConfidence, results, seen);

	// --- Block-rotate scan ---
	if (results.length < MAX_TOTAL_RESULTS) {
		scanBlockRotate(buffer, baseOffset, minLength, minConfidence, results, seen);
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	if (results.length > MAX_TOTAL_RESULTS) {
		results.length = MAX_TOTAL_RESULTS;
	}

	return results;
}


// ---------------------------------------------------------------------------
// Counter-linear scan
// ---------------------------------------------------------------------------

/**
 * Scan using counter-linear XOR: decoded[i] = buffer[i] ^ ((base + i * step) & 0xFF).
 * Tests all base values 0x00–0xFF with step values 1–8.
 * Quick-check with first 256 bytes to discard unpromising combinations.
 */
function scanCounterLinear(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	minConfidence: number,
	results: PositionalXorResult[],
	seen: Set<string>,
): void {
	if (buffer.length === 0) {
		return;
	}

	for (let step = 1; step <= MAX_COUNTER_STEP; step++) {
		for (let base = 0x00; base <= 0xFF; base++) {
			// Quick-check: decode first QUICK_CHECK_SAMPLE bytes
			const sampleSize = Math.min(QUICK_CHECK_SAMPLE, buffer.length);
			let printable = 0;

			for (let i = 0; i < sampleSize; i++) {
				const decoded = buffer[i] ^ ((base + i * step) & 0xFF);
				if (isPrintable(decoded)) {
					printable++;
				}
			}

			if ((printable / sampleSize) < QUICK_CHECK_THRESHOLD) {
				continue;
			}

			// Full decode
			const decoded = counterLinearApply(buffer, base, step);

			// Extract and score printable runs
			const runs = extractPrintableRuns(decoded, minLength);
			const keyBuf = Buffer.from([base]);
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
					method: 'XOR-counter',
					confidence,
					derivationParams: {
						type: 'counter-linear',
						base,
						step,
					},
				});

				if (results.length >= MAX_TOTAL_RESULTS) {
					return;
				}
			}

			if (results.length >= MAX_TOTAL_RESULTS) {
				return;
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Block-rotate scan
// ---------------------------------------------------------------------------

/** Key sizes to test for block-rotate */
const BLOCK_ROTATE_KEY_SIZES = [2, 4, 8];

/** Block sizes to test for block-rotate */
const BLOCK_ROTATE_BLOCK_SIZES = [16, 32, 64, 128, 256];

/**
 * Scan using block-rotate XOR: key of N bytes rotated every block of M bytes.
 * Uses frequency analysis to derive candidate keys for each key size.
 */
function scanBlockRotate(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	minConfidence: number,
	results: PositionalXorResult[],
	seen: Set<string>,
): void {
	if (buffer.length === 0) {
		return;
	}

	for (const keySize of BLOCK_ROTATE_KEY_SIZES) {
		if (buffer.length < keySize) {
			continue;
		}

		for (const blockSize of BLOCK_ROTATE_BLOCK_SIZES) {
			if (buffer.length < blockSize) {
				continue;
			}

			// Derive candidate key via frequency analysis on the first block
			// Assume most frequent byte in each key position XOR'd with common assumptions
			const assumptions = [0x00, 0x20, 0x65];

			for (const assumed of assumptions) {
				const candidateKey = deriveBlockRotateKey(buffer, keySize, blockSize, assumed);

				// Skip all-zero keys
				if (candidateKey.every(b => b === 0)) {
					continue;
				}

				// Quick-check with first QUICK_CHECK_SAMPLE bytes
				const sampleSize = Math.min(QUICK_CHECK_SAMPLE, buffer.length);
				let printable = 0;
				for (let i = 0; i < sampleSize; i++) {
					const blockIndex = Math.floor(i / blockSize);
					const posInBlock = i % blockSize;
					const keyByte = candidateKey[(posInBlock + blockIndex) % keySize];
					const decoded = buffer[i] ^ keyByte;
					if (isPrintable(decoded)) {
						printable++;
					}
				}

				if ((printable / sampleSize) < QUICK_CHECK_THRESHOLD) {
					continue;
				}

				// Full decode
				const decoded = blockRotateApply(buffer, candidateKey, blockSize);

				// Extract and score printable runs
				const runs = extractPrintableRuns(decoded, minLength);
				const keyHex = formatKeyHex(candidateKey);

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
						key: Buffer.from(candidateKey),
						keyHex,
						keySize,
						method: 'XOR-block-rotate',
						confidence,
						derivationParams: {
							type: 'block-rotate',
							blockSize,
						},
					});

					if (results.length >= MAX_TOTAL_RESULTS) {
						return;
					}
				}

				if (results.length >= MAX_TOTAL_RESULTS) {
					return;
				}
			}
		}
	}
}

/**
 * Derive a candidate key for block-rotate by frequency analysis.
 * For each key byte position, find the most frequent byte across all blocks
 * at that effective position (accounting for rotation), then XOR with assumed plaintext.
 */
function deriveBlockRotateKey(
	buffer: Buffer,
	keySize: number,
	blockSize: number,
	assumedPlaintext: number,
): Buffer {
	const freq: Uint32Array[] = [];
	for (let k = 0; k < keySize; k++) {
		freq.push(new Uint32Array(256));
	}

	// Count byte frequencies per key position across all blocks
	for (let i = 0; i < buffer.length; i++) {
		const blockIndex = Math.floor(i / blockSize);
		const posInBlock = i % blockSize;
		const keyPos = (posInBlock + blockIndex) % keySize;
		freq[keyPos][buffer[i]]++;
	}

	// Find most frequent byte per key position and derive key
	const key = Buffer.alloc(keySize);
	for (let k = 0; k < keySize; k++) {
		let maxCount = 0;
		let maxByte = 0;
		for (let b = 0; b < 256; b++) {
			if (freq[k][b] > maxCount) {
				maxCount = freq[k][b];
				maxByte = b;
			}
		}
		key[k] = maxByte ^ assumedPlaintext;
	}

	return key;
}
