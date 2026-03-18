/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { scoreString, isPrintable, extractPrintableRuns, formatKeyHex, PrintableRun } from './scoringEngine';
import { detectKeyLengths } from './kasiskiDetector';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Result from multi-byte XOR deobfuscation scan.
 */
export interface MultiByteXorResult {
	/** The decoded printable string. */
	value: string;
	/** Absolute file offset where the encoded string starts. */
	offset: number;
	/** The XOR key used to decode this string. */
	key: Buffer;
	/** The key in hexadecimal representation. */
	keyHex: string;
	/** Size of the key in bytes. */
	keySize: number;
	/** The XOR method used: multi-byte, rolling, or increment. */
	method: 'multi-byte' | 'rolling' | 'increment'
	| 'XOR-wide' | 'XOR-layered' | 'XOR-counter'
	| 'XOR-block-rotate' | 'XOR-rolling-ext'
	| 'XOR-known-plaintext'
	| 'ADD' | 'SUB' | 'ROT';
	/** Confidence score 0–1 based on printability and bigram frequency. */
	confidence: number;
	// --- New optional fields ---
	/** PE section name where the string was found */
	section?: string;
	/** For layered XOR: sequence of keys per layer */
	layerKeys?: string[];
	/** For known-plaintext: pattern that originated the key */
	knownPattern?: string;
	/** For counter/block-rotate: derivation parameters */
	derivationParams?: { type: string; base?: number; step?: number; blockSize?: number };
	/** For rolling-ext: window size */
	windowSize?: number;
	/** For ROT: rotation value N */
	rotValue?: number;
	/** For wide strings: original byte length */
	originalByteLength?: number;
}

/**
 * Options for the multi-byte XOR scanner.
 */
export interface MultiByteXorOptions {
	/** Key sizes to test for multi-byte XOR (default: [2, 4, 8, 16]). */
	keySizes?: number[];
	/** Minimum decoded string length to include (default: 6). */
	minLength?: number;
	/** Minimum confidence score to include (default: 0.6). */
	minConfidence?: number;
	/** Enable rolling XOR mode (default: true). */
	enableRolling?: boolean;
	/** Enable XOR with increment mode (default: true). */
	enableIncrement?: boolean;
	// --- New optional fields ---
	/** Enable automatic key length detection via Kasiski/IC (default: true). */
	enableAutoKeyDetection?: boolean;
	/** Enable known-plaintext attack. */
	enableKnownPlaintext?: boolean;
	/** Enable composite cipher (ADD/SUB/ROT). */
	enableCompositeCipher?: boolean;
	/** Enable layered XOR. */
	enableLayeredXor?: boolean;
	/** Enable wide string XOR. */
	enableWideString?: boolean;
	/** Enable positional XOR. */
	enablePositionalXor?: boolean;
	/** Enable rolling XOR extended. */
	enableRollingExt?: boolean;
	/** Custom plaintext patterns for known-plaintext attack. */
	customPlaintextPatterns?: string[];
	/** Target PE sections to scan. */
	targetSections?: string[];
	/** Enable expanded frequency guesses (default: true). */
	expandedFrequencyGuesses?: boolean;
}


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_KEY_SIZES = [2, 4, 8, 16];
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;

/** Maximum total results to prevent memory issues. */
const MAX_TOTAL_RESULTS = 2000;

/** Quick-check sample size for rolling/increment modes. */
const QUICK_CHECK_SAMPLE = 256;

/** Minimum printable ratio in quick-check to proceed with full decode. */
const QUICK_CHECK_THRESHOLD = 0.05;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a buffer for strings obfuscated with multi-byte XOR, rolling XOR,
 * and XOR with increment.
 *
 * Strategy:
 * 1. Multi-byte: For each key size N, use frequency analysis to derive
 *    candidate keys, decode, and extract printable runs.
 * 2. Rolling: `decoded[i] = buffer[i] ^ buffer[i-1]` with seed byte.
 * 3. Increment: `decoded[i] = buffer[i] ^ ((baseKey + i) & 0xFF)`.
 *
 * @param buffer     Raw binary data chunk
 * @param baseOffset File offset where this chunk starts (for absolute offsets)
 * @param options    Scanner configuration
 */
export function multiByteXorScan(
	buffer: Buffer,
	baseOffset: number,
	options?: MultiByteXorOptions,
): MultiByteXorResult[] {
	const fixedKeySizes = options?.keySizes ?? DEFAULT_KEY_SIZES;
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
	const enableRolling = options?.enableRolling ?? true;
	const enableIncrement = options?.enableIncrement ?? true;
	const enableAutoKeyDetection = options?.enableAutoKeyDetection ?? true;

	const results: MultiByteXorResult[] = [];
	const seen = new Set<string>();

	// --- Determine key sizes to test ---
	let keySizes: number[];
	if (enableAutoKeyDetection) {
		const kasiskiResult = detectKeyLengths(buffer);
		const dynamicSizes = kasiskiResult.candidateLengths;
		// Merge fixed + dynamic, deduplicate
		const merged = new Set<number>([...fixedKeySizes, ...dynamicSizes]);
		keySizes = [...merged].sort((a, b) => a - b);
	} else {
		keySizes = fixedKeySizes;
	}

	// --- Multi-byte XOR via frequency analysis ---
	scanMultiByte(buffer, baseOffset, keySizes, minLength, minConfidence, results, seen, options);

	// --- Rolling XOR ---
	if (enableRolling && results.length < MAX_TOTAL_RESULTS) {
		scanRolling(buffer, baseOffset, minLength, minConfidence, results, seen);
	}

	// --- XOR with increment ---
	if (enableIncrement && results.length < MAX_TOTAL_RESULTS) {
		scanIncrement(buffer, baseOffset, minLength, minConfidence, results, seen);
	}

	// Sort by confidence descending, then offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	// Cap total results
	if (results.length > MAX_TOTAL_RESULTS) {
		results.length = MAX_TOTAL_RESULTS;
	}

	return results;
}


// ---------------------------------------------------------------------------
// Multi-byte XOR
// ---------------------------------------------------------------------------

/**
 * Scan using multi-byte XOR keys via frequency analysis.
 *
 * For each key size N:
 * 1. Group bytes by position `i % N` (N groups).
 * 2. For each group, find the most frequent byte value.
 * 3. Derive candidate key assuming most frequent byte is one of the
 *    expanded frequency guesses.
 * 4. Decode buffer with candidate key and extract printable runs.
 * 5. Discard uniform keys (all bytes same) — equivalent to single-byte XOR.
 */
function scanMultiByte(
	buffer: Buffer,
	baseOffset: number,
	keySizes: number[],
	minLength: number,
	minConfidence: number,
	results: MultiByteXorResult[],
	seen: Set<string>,
	options?: MultiByteXorOptions,
): void {
	const useExpanded = options?.expandedFrequencyGuesses ?? true;

	for (const keySize of keySizes) {
		if (buffer.length < keySize) {
			continue;
		}

		// Find most frequent byte per position group
		const mostFrequent = findMostFrequentPerGroup(buffer, keySize);

		// Expanded frequency guesses: null, space, 'e', padding, NOP, INT3
		const assumptions: number[] = useExpanded
			? [0x00, 0x20, 0x65, 0xFF, 0x90, 0xCC]
			: [0x20, 0x00];

		for (const assumed of assumptions) {
			const candidateKey = Buffer.alloc(keySize);
			for (let g = 0; g < keySize; g++) {
				candidateKey[g] = mostFrequent[g] ^ assumed;
			}

			// Skip all-zero keys (no-op)
			if (candidateKey.every(b => b === 0)) {
				continue;
			}

			// Discard uniform keys (all bytes same) — equivalent to single-byte XOR
			if (keySize > 1 && candidateKey.every(b => b === candidateKey[0])) {
				continue;
			}

			// Decode buffer with this key
			const decoded = Buffer.alloc(buffer.length);
			for (let i = 0; i < buffer.length; i++) {
				decoded[i] = buffer[i] ^ candidateKey[i % keySize];
			}

			// Extract and score printable runs
			const runs = extractPrintableRuns(decoded, minLength);
			collectResults(
				decoded, runs, baseOffset, candidateKey, keySize,
				'multi-byte', minConfidence, results, seen,
			);

			if (results.length >= MAX_TOTAL_RESULTS) {
				return;
			}
		}
	}
}


/**
 * Find the most frequent byte value for each position group `i % keySize`.
 */
function findMostFrequentPerGroup(buffer: Buffer, keySize: number): number[] {
	// frequency[group][byteValue] = count
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


// ---------------------------------------------------------------------------
// Rolling XOR
// ---------------------------------------------------------------------------

/**
 * Scan using rolling XOR: `decoded[i] = buffer[i] ^ buffer[i-1]`.
 * First byte is XOR'd with a seed byte (tested 0x00–0xFF).
 */
function scanRolling(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	minConfidence: number,
	results: MultiByteXorResult[],
	seen: Set<string>,
): void {
	if (buffer.length < 2) {
		return;
	}

	for (let seed = 0x00; seed <= 0xFF; seed++) {
		// Quick-check: decode first QUICK_CHECK_SAMPLE bytes and check printability
		const sampleSize = Math.min(QUICK_CHECK_SAMPLE, buffer.length);
		let printable = 0;
		let prev = seed;

		for (let i = 0; i < sampleSize; i++) {
			const decoded = buffer[i] ^ prev;
			if (isPrintable(decoded)) {
				printable++;
			}
			prev = buffer[i];
		}

		if ((printable / sampleSize) < QUICK_CHECK_THRESHOLD) {
			continue;
		}

		// Full decode
		const decoded = Buffer.alloc(buffer.length);
		decoded[0] = buffer[0] ^ seed;
		for (let i = 1; i < buffer.length; i++) {
			decoded[i] = buffer[i] ^ buffer[i - 1];
		}

		const runs = extractPrintableRuns(decoded, minLength);
		const keyBuf = Buffer.from([seed]);
		collectResults(
			decoded, runs, baseOffset, keyBuf, 1,
			'rolling', minConfidence, results, seen,
		);

		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}
	}
}

// ---------------------------------------------------------------------------
// XOR with Increment
// ---------------------------------------------------------------------------

/**
 * Scan using XOR with increment: `decoded[i] = buffer[i] ^ ((baseKey + i) & 0xFF)`.
 * Tests all base keys 0x00–0xFF.
 */
function scanIncrement(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	minConfidence: number,
	results: MultiByteXorResult[],
	seen: Set<string>,
): void {
	for (let baseKey = 0x00; baseKey <= 0xFF; baseKey++) {
		// Quick-check: decode first QUICK_CHECK_SAMPLE bytes and check printability
		const sampleSize = Math.min(QUICK_CHECK_SAMPLE, buffer.length);
		let printable = 0;

		for (let i = 0; i < sampleSize; i++) {
			const decoded = buffer[i] ^ ((baseKey + i) & 0xFF);
			if (isPrintable(decoded)) {
				printable++;
			}
		}

		if ((printable / sampleSize) < QUICK_CHECK_THRESHOLD) {
			continue;
		}

		// Full decode
		const decoded = Buffer.alloc(buffer.length);
		for (let i = 0; i < buffer.length; i++) {
			decoded[i] = buffer[i] ^ ((baseKey + i) & 0xFF);
		}

		const runs = extractPrintableRuns(decoded, minLength);
		const keyBuf = Buffer.from([baseKey]);
		collectResults(
			decoded, runs, baseOffset, keyBuf, 1,
			'increment', minConfidence, results, seen,
		);

		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}
	}
}


// ---------------------------------------------------------------------------
// Shared Helpers
// ---------------------------------------------------------------------------

/**
 * Collect scored results from printable runs into the results array.
 * Uses the centralized scoreString from scoringEngine.
 */
function collectResults(
	decoded: Buffer,
	runs: PrintableRun[],
	baseOffset: number,
	key: Buffer,
	keySize: number,
	method: 'multi-byte' | 'rolling' | 'increment',
	minConfidence: number,
	results: MultiByteXorResult[],
	seen: Set<string>,
): void {
	const keyHex = formatKeyHex(key);

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
			key: Buffer.from(key),
			keyHex,
			keySize,
			method,
			confidence,
		});

		if (results.length >= MAX_TOTAL_RESULTS) {
			return;
		}
	}
}
