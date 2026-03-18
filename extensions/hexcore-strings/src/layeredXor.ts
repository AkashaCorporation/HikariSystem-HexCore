/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scoreString, extractPrintableRuns, formatKeyHex } from './scoringEngine';
import { MultiByteXorResult, MultiByteXorOptions } from './multiByteXor';
import { detectKeyLengths } from './kasiskiDetector';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAX_TOTAL_RESULTS = 2000;
const MAX_LAYERS = 3;
const HIGH_ENTROPY_THRESHOLD = 7.0;
const LOW_ENTROPY_THRESHOLD = 4.0;
const LAYER_TIME_MULTIPLIER = 2.0;
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;
const ENTROPY_BLOCK_SIZE = 256;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface LayeredXorResult extends MultiByteXorResult {
	/** Number of layers detected */
	layerCount: number;
	/** Keys for each layer in order */
	layerKeys: string[];
}

// ---------------------------------------------------------------------------
// Helpers exported for round-trip testing
// ---------------------------------------------------------------------------

/**
 * Apply XOR with each key in sequence (layer by layer).
 * For each layer, XOR the buffer with key[i % keyLen].
 *
 * Round-trip property:
 * applyXorLayers(applyXorLayers(buf, [k1, k2, k3]), [k3, k2, k1]) === buf
 */
export function applyXorLayers(buffer: Buffer, keys: Buffer[]): Buffer {
	let current = Buffer.from(buffer);
	for (const key of keys) {
		const next = Buffer.alloc(current.length);
		for (let i = 0; i < current.length; i++) {
			next[i] = current[i] ^ key[i % key.length];
		}
		current = next;
	}
	return current;
}

// ---------------------------------------------------------------------------
// Entropy calculation
// ---------------------------------------------------------------------------

/**
 * Calculate Shannon entropy for a block of bytes.
 * Returns value between 0.0 (uniform) and 8.0 (maximum entropy).
 */
function shannonEntropy(buffer: Buffer, start: number, length: number): number {
	if (length <= 0) {
		return 0;
	}

	const freq = new Uint32Array(256);
	const end = Math.min(start + length, buffer.length);
	const actualLen = end - start;
	if (actualLen <= 0) {
		return 0;
	}

	for (let i = start; i < end; i++) {
		freq[buffer[i]]++;
	}

	let entropy = 0;
	for (let b = 0; b < 256; b++) {
		if (freq[b] > 0) {
			const p = freq[b] / actualLen;
			entropy -= p * Math.log2(p);
		}
	}

	return entropy;
}

/**
 * Calculate entropy per block and detect if high-entropy regions (>7.0)
 * are adjacent to low-entropy regions (<4.0).
 */
function hasLayeredPattern(buffer: Buffer): boolean {
	if (buffer.length < ENTROPY_BLOCK_SIZE * 2) {
		return false;
	}

	const blockCount = Math.floor(buffer.length / ENTROPY_BLOCK_SIZE);
	const entropies: number[] = [];

	for (let b = 0; b < blockCount; b++) {
		entropies.push(shannonEntropy(buffer, b * ENTROPY_BLOCK_SIZE, ENTROPY_BLOCK_SIZE));
	}

	// Check for high entropy adjacent to low entropy
	for (let i = 0; i < entropies.length - 1; i++) {
		const curr = entropies[i];
		const next = entropies[i + 1];
		if ((curr > HIGH_ENTROPY_THRESHOLD && next < LOW_ENTROPY_THRESHOLD) ||
			(curr < LOW_ENTROPY_THRESHOLD && next > HIGH_ENTROPY_THRESHOLD)) {
			return true;
		}
	}

	return false;
}

// ---------------------------------------------------------------------------
// Key derivation via frequency analysis
// ---------------------------------------------------------------------------

/**
 * Derive a candidate XOR key of given length using frequency analysis.
 * Assumes the most frequent byte in each position group is XOR of the
 * most common plaintext byte (tries 0x00 and 0x20).
 */
function deriveKeyByFrequency(buffer: Buffer, keySize: number): Buffer[] {
	const frequency: Uint32Array[] = [];
	for (let g = 0; g < keySize; g++) {
		frequency.push(new Uint32Array(256));
	}

	for (let i = 0; i < buffer.length; i++) {
		frequency[i % keySize][buffer[i]]++;
	}

	const mostFrequent: number[] = [];
	for (let g = 0; g < keySize; g++) {
		let maxCount = 0;
		let maxByte = 0;
		for (let b = 0; b < 256; b++) {
			if (frequency[g][b] > maxCount) {
				maxCount = frequency[g][b];
				maxByte = b;
			}
		}
		mostFrequent.push(maxByte);
	}

	const assumptions = [0x00, 0x20, 0x65];
	const keys: Buffer[] = [];

	for (const assumed of assumptions) {
		const key = Buffer.alloc(keySize);
		for (let g = 0; g < keySize; g++) {
			key[g] = mostFrequent[g] ^ assumed;
		}
		// Skip all-zero keys
		if (key.every(b => b === 0)) {
			continue;
		}
		keys.push(key);
	}

	return keys;
}

// ---------------------------------------------------------------------------
// XOR decode helper
// ---------------------------------------------------------------------------

function xorDecode(buffer: Buffer, key: Buffer): Buffer {
	const out = Buffer.alloc(buffer.length);
	for (let i = 0; i < buffer.length; i++) {
		out[i] = buffer[i] ^ key[i % key.length];
	}
	return out;
}

// ---------------------------------------------------------------------------
// Main scan function
// ---------------------------------------------------------------------------

/**
 * Detect layered XOR encoding (up to 3 layers).
 *
 * Algorithm:
 * 1. Decode with first candidate key (via frequency or Kasiski)
 * 2. Calculate entropy of result per 256-byte blocks
 * 3. If high entropy regions (>7.0) adjacent to low entropy (<4.0):
 *    a. Apply second layer of XOR decoding
 *    b. Repeat for third layer if needed
 * 4. Time limit: 2x the time of a single layer (measured via performance.now())
 *
 * @param buffer     Encrypted buffer to scan
 * @param baseOffset Base offset in the file
 * @param options    Scanner options
 */
export function layeredXorScan(
	buffer: Buffer,
	baseOffset: number,
	options?: MultiByteXorOptions,
): LayeredXorResult[] {
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
	const results: LayeredXorResult[] = [];

	if (buffer.length === 0) {
		return results;
	}

	// Determine candidate key sizes via Kasiski + fixed sizes
	const kasiskiResult = detectKeyLengths(buffer);
	const keySizes = new Set<number>([2, 4, 8, ...kasiskiResult.candidateLengths]);

	// Measure time for first layer to enforce time limit
	const startTime = performance.now();
	let firstLayerTime = 0;

	for (const keySize of keySizes) {
		if (buffer.length < keySize) {
			continue;
		}
		if (results.length >= MAX_TOTAL_RESULTS) {
			break;
		}

		const candidateKeys = deriveKeyByFrequency(buffer, keySize);

		for (const firstKey of candidateKeys) {
			if (results.length >= MAX_TOTAL_RESULTS) {
				break;
			}

			// Layer 1: decode with first key
			const layerOneStart = performance.now();
			const layer1 = xorDecode(buffer, firstKey);
			if (firstLayerTime === 0) {
				firstLayerTime = performance.now() - layerOneStart;
				if (firstLayerTime < 1) { firstLayerTime = 1; } // minimum 1ms
			}

			const timeLimit = firstLayerTime * LAYER_TIME_MULTIPLIER;

			// Collect results from layer 1
			collectLayeredResults(
				layer1, baseOffset, [firstKey], 1,
				minLength, minConfidence, results,
			);

			// Check if layer 2 is needed (entropy pattern detection)
			if (hasLayeredPattern(layer1) && results.length < MAX_TOTAL_RESULTS) {
				// Try layer 2 with different key sizes
				const layer2KeySizes = [2, 4, 8];
				for (const ks2 of layer2KeySizes) {
					if (layer1.length < ks2) { continue; }
					if (results.length >= MAX_TOTAL_RESULTS) { break; }

					// Check time limit
					if (performance.now() - startTime > timeLimit + firstLayerTime * 10) {
						break;
					}

					const secondKeys = deriveKeyByFrequency(layer1, ks2);
					for (const secondKey of secondKeys) {
						if (results.length >= MAX_TOTAL_RESULTS) { break; }
						if (performance.now() - startTime > timeLimit + firstLayerTime * 10) {
							break;
						}

						const layer2 = xorDecode(layer1, secondKey);

						collectLayeredResults(
							layer2, baseOffset, [firstKey, secondKey], 2,
							minLength, minConfidence, results,
						);

						// Check if layer 3 is needed
						if (hasLayeredPattern(layer2) && results.length < MAX_TOTAL_RESULTS) {
							const layer3KeySizes = [2, 4];
							for (const ks3 of layer3KeySizes) {
								if (layer2.length < ks3) { continue; }
								if (results.length >= MAX_TOTAL_RESULTS) { break; }
								if (performance.now() - startTime > timeLimit + firstLayerTime * 10) {
									break;
								}

								const thirdKeys = deriveKeyByFrequency(layer2, ks3);
								for (const thirdKey of thirdKeys) {
									if (results.length >= MAX_TOTAL_RESULTS) { break; }
									if (performance.now() - startTime > timeLimit + firstLayerTime * 10) {
										break;
									}

									const layer3 = xorDecode(layer2, thirdKey);

									collectLayeredResults(
										layer3, baseOffset,
										[firstKey, secondKey, thirdKey], 3,
										minLength, minConfidence, results,
									);
								}
							}
						}
					}
				}
			}
		}
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	if (results.length > MAX_TOTAL_RESULTS) {
		results.length = MAX_TOTAL_RESULTS;
	}

	return results;
}

// ---------------------------------------------------------------------------
// Result collection
// ---------------------------------------------------------------------------

function collectLayeredResults(
	decoded: Buffer,
	baseOffset: number,
	keys: Buffer[],
	layerCount: number,
	minLength: number,
	minConfidence: number,
	results: LayeredXorResult[],
): void {
	const runs = extractPrintableRuns(decoded, minLength);

	// Use the combined key (first layer key) for the result key field
	const combinedKey = keys[0];
	const keyHex = formatKeyHex(combinedKey);
	const layerKeyHexes = keys.map(k => formatKeyHex(k));

	for (const run of runs) {
		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}

		const confidence = scoreString(decoded, run.start, run.length);
		if (confidence < minConfidence) {
			continue;
		}

		const value = decoded.subarray(run.start, run.start + run.length).toString('ascii');

		results.push({
			value,
			offset: baseOffset + run.start,
			key: Buffer.from(combinedKey),
			keyHex,
			keySize: combinedKey.length,
			method: 'XOR-layered',
			confidence,
			layerCount,
			layerKeys: layerKeyHexes,
		});
	}
}
