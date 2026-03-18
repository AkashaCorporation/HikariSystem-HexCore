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
 * Result from known-plaintext attack scan.
 * Extends MultiByteXorResult with the pattern that originated the key.
 */
export interface KnownPlaintextResult extends MultiByteXorResult {
	/** The known plaintext pattern that originated the key derivation */
	knownPattern: string;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Printability ratio below which a candidate key is discarded */
const PRINTABILITY_DISCARD = 0.30;

/** Maximum total results from this scanner */
const MAX_TOTAL_RESULTS = 2000;

/** Default minimum decoded string length */
const DEFAULT_MIN_LENGTH = 6;

/** Default minimum confidence score */
const DEFAULT_MIN_CONFIDENCE = 0.6;

/** Built-in malware plaintext patterns for known-plaintext attack */
export const MALWARE_PATTERNS: Buffer[] = [
	Buffer.from('http://'),
	Buffer.from('https://'),
	Buffer.from('MZ'),
	Buffer.from('This program'),
	Buffer.from('.exe'),
	Buffer.from('.dll'),
	Buffer.from('.sys'),
	Buffer.from('cmd.exe'),
	Buffer.from('powershell'),
	Buffer.from('HKEY_'),
	Buffer.from('SOFTWARE\\'),
	Buffer.from([0x00, 0x00]),
];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Find the most frequent byte value for each position group `i % keySize`.
 */
function findMostFrequentPerGroup(buffer: Buffer, keySize: number): number[] {
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
	return mostFrequent;
}

/**
 * Extend a partial key to the desired key size using frequency analysis.
 * The partial key covers positions [0, partialLen), and the remaining
 * positions are filled by XOR-ing the most frequent byte in each group
 * with the assumed plaintext byte 0x20 (space).
 */
function extendKeyViaFrequency(
	buffer: Buffer,
	partialKey: Buffer,
	targetKeySize: number,
): Buffer {
	if (partialKey.length >= targetKeySize) {
		return partialKey.slice(0, targetKeySize);
	}

	const fullKey = Buffer.alloc(targetKeySize);
	partialKey.copy(fullKey, 0, 0, partialKey.length);

	// Use frequency analysis for the remaining positions
	const mostFrequent = findMostFrequentPerGroup(buffer, targetKeySize);

	// Try common assumptions for extension: space (0x20) is most common
	const assumptions = [0x20, 0x00, 0x65];
	for (let g = partialKey.length; g < targetKeySize; g++) {
		// Default: assume space is the most frequent plaintext byte
		fullKey[g] = mostFrequent[g] ^ assumptions[0];
	}

	return fullKey;
}

/**
 * Calculate the printable byte ratio of a decoded buffer.
 */
function printableRatio(decoded: Buffer): number {
	if (decoded.length === 0) { return 0; }
	let count = 0;
	for (let i = 0; i < decoded.length; i++) {
		if (isPrintable(decoded[i])) {
			count++;
		}
	}
	return count / decoded.length;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Known-plaintext attack: tries to align known patterns at each position
 * in the buffer to derive XOR keys.
 *
 * Algorithm:
 * 1. For each pattern P and each position i in buffer:
 *    a. Derive partial key: key[j] = buffer[i+j] ^ P[j] for j in [0, len(P))
 *    b. If partial key length < expected keySize, extend via frequency
 *    c. Decode full buffer with extended key
 *    d. If < 30% printable, discard
 *    e. Otherwise, extract runs and score
 * 2. Optimization: stride of 1 byte, but skip if buffer[i] == P[0] ^ 0x00 (null key)
 *
 * @param buffer     Encrypted buffer
 * @param baseOffset Base offset in the file
 * @param patterns   Known plaintext patterns (defaults to MALWARE_PATTERNS)
 * @param options    Scanner options
 */
export function knownPlaintextScan(
	buffer: Buffer,
	baseOffset: number,
	patterns?: Buffer[],
	options?: MultiByteXorOptions,
): KnownPlaintextResult[] {
	const results: KnownPlaintextResult[] = [];
	const seen = new Set<string>();

	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;

	// Merge built-in patterns with custom patterns
	let allPatterns = patterns ?? MALWARE_PATTERNS;

	if (options?.customPlaintextPatterns && options.customPlaintextPatterns.length > 0) {
		const customBuffers = options.customPlaintextPatterns
			.filter(p => p.length > 0)
			.map(p => Buffer.from(p));
		allPatterns = [...allPatterns, ...customBuffers];
	}

	for (const pattern of allPatterns) {
		if (pattern.length === 0 || pattern.length > buffer.length) {
			continue;
		}

		const patternLabel = isNullPadding(pattern)
			? 'null-padding'
			: pattern.toString('ascii');

		for (let i = 0; i <= buffer.length - pattern.length; i++) {
			if (results.length >= MAX_TOTAL_RESULTS) {
				return results;
			}

			// Derive partial key from this position
			const partialKey = Buffer.alloc(pattern.length);
			let isNullKey = true;
			for (let j = 0; j < pattern.length; j++) {
				partialKey[j] = buffer[i + j] ^ pattern[j];
				if (partialKey[j] !== 0x00) {
					isNullKey = false;
				}
			}

			// Skip null keys (no-op XOR)
			if (isNullKey) {
				continue;
			}

			// Use the partial key length as the key size
			// (the pattern itself defines the key length for short patterns,
			//  extend for longer patterns if needed)
			const keySize = partialKey.length;
			const fullKey = extendKeyViaFrequency(buffer, partialKey, keySize);

			// Decode full buffer with this key
			const decoded = Buffer.alloc(buffer.length);
			for (let di = 0; di < buffer.length; di++) {
				decoded[di] = buffer[di] ^ fullKey[di % keySize];
			}

			// Discard if < 30% printable
			if (printableRatio(decoded) < PRINTABILITY_DISCARD) {
				continue;
			}

			// Extract printable runs and score
			const runs = extractPrintableRuns(decoded, minLength);
			for (const run of runs) {
				const confidence = scoreString(decoded, run.start, run.length);
				if (confidence < minConfidence) {
					continue;
				}

				const value = decoded.slice(run.start, run.start + run.length).toString('ascii');
				const dedupKey = `${run.start + baseOffset}:${value}`;
				if (seen.has(dedupKey)) {
					continue;
				}
				seen.add(dedupKey);

				results.push({
					value,
					offset: baseOffset + run.start,
					key: Buffer.from(fullKey),
					keyHex: formatKeyHex(fullKey),
					keySize,
					method: 'XOR-known-plaintext',
					confidence,
					knownPattern: patternLabel,
				});

				if (results.length >= MAX_TOTAL_RESULTS) {
					return results;
				}
			}
		}
	}

	return results;
}

/**
 * Check if a pattern buffer is the null-padding pattern [0x00, 0x00].
 */
function isNullPadding(pattern: Buffer): boolean {
	return pattern.length === 2 && pattern[0] === 0x00 && pattern[1] === 0x00;
}
