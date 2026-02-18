/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

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
	method: 'multi-byte' | 'rolling' | 'increment';
	/** Confidence score 0–1 based on printability and bigram frequency. */
	confidence: number;
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

/**
 * Common English bigrams used for scoring decoded text quality.
 * Higher bigram hit rate = more likely to be real text.
 */
const COMMON_BIGRAMS = new Set<string>([
	'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
	'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
	'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
	'no', 'us', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne',
]);

/**
 * Common English letter frequencies for scoring.
 */
const ENGLISH_FREQ = new Set<number>([
	0x20, 0x65, 0x74, 0x61, 0x6F, 0x69, 0x6E, 0x73, 0x68, 0x72, // ' etaoinshr'
	0x64, 0x6C, 0x63, 0x75, 0x6D, 0x77, 0x66, 0x67, 0x79, 0x70, // 'dlcumwfgyp'
]);

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
	const keySizes = options?.keySizes ?? DEFAULT_KEY_SIZES;
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;
	const enableRolling = options?.enableRolling ?? true;
	const enableIncrement = options?.enableIncrement ?? true;

	const results: MultiByteXorResult[] = [];
	const seen = new Set<string>();

	// --- Multi-byte XOR via frequency analysis ---
	scanMultiByte(buffer, baseOffset, keySizes, minLength, minConfidence, results, seen);

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
// Multi-byte XOR (Task 9.1)
// ---------------------------------------------------------------------------

/**
 * Scan using multi-byte XOR keys via frequency analysis.
 *
 * For each key size N:
 * 1. Group bytes by position `i % N` (N groups).
 * 2. For each group, find the most frequent byte value.
 * 3. Derive candidate key assuming most frequent byte is space (0x20) or null (0x00).
 * 4. Decode buffer with candidate key and extract printable runs.
 */
function scanMultiByte(
	buffer: Buffer,
	baseOffset: number,
	keySizes: number[],
	minLength: number,
	minConfidence: number,
	results: MultiByteXorResult[],
	seen: Set<string>,
): void {
	for (const keySize of keySizes) {
		if (buffer.length < keySize) {
			continue;
		}

		// Find most frequent byte per position group
		const mostFrequent = findMostFrequentPerGroup(buffer, keySize);

		// Try two assumptions: most frequent byte is space (0x20) or null (0x00)
		const assumptions: number[] = [0x20, 0x00];

		for (const assumed of assumptions) {
			const candidateKey = Buffer.alloc(keySize);
			for (let g = 0; g < keySize; g++) {
				candidateKey[g] = mostFrequent[g] ^ assumed;
			}

			// Skip all-zero keys (no-op)
			if (candidateKey.every(b => b === 0)) {
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
// Rolling XOR (Task 9.2)
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
// XOR with Increment (Task 9.3)
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

interface PrintableRun {
	start: number;
	length: number;
}

/**
 * Extract contiguous runs of printable ASCII characters from a decoded buffer.
 */
function extractPrintableRuns(decoded: Buffer, minLength: number): PrintableRun[] {
	const runs: PrintableRun[] = [];
	let runStart = 0;
	let runLength = 0;

	for (let i = 0; i < decoded.length; i++) {
		if (isPrintable(decoded[i])) {
			if (runLength === 0) {
				runStart = i;
			}
			runLength++;
		} else {
			if (runLength >= minLength) {
				runs.push({ start: runStart, length: runLength });
			}
			runLength = 0;
		}
	}

	if (runLength >= minLength) {
		runs.push({ start: runStart, length: runLength });
	}

	return runs;
}

/**
 * Collect scored results from printable runs into the results array.
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
		const confidence = scoreRun(decoded, run.start, run.length);
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

/**
 * Score a printable run based on printability ratio and bigram frequency.
 *
 * Scoring factors:
 * 1. Printability ratio (0.4 weight)
 * 2. English character frequency match (0.3 weight)
 * 3. Bigram frequency bonus (up to 0.15)
 * 4. Length bonus (up to 0.15)
 * 5. Penalty for all-digits
 */
function scoreRun(decoded: Buffer, start: number, length: number): number {
	let printableCount = 0;
	let frequentCount = 0;
	let spaceCount = 0;
	let digitCount = 0;
	let bigramHits = 0;

	for (let i = start; i < start + length; i++) {
		const byte = decoded[i];
		if (isPrintable(byte)) { printableCount++; }
		if (ENGLISH_FREQ.has(byte)) { frequentCount++; }
		if (byte === 0x20) { spaceCount++; }
		if (byte >= 0x30 && byte <= 0x39) { digitCount++; }

		// Check bigrams
		if (i > start) {
			const bigram = String.fromCharCode(decoded[i - 1], decoded[i]).toLowerCase();
			if (COMMON_BIGRAMS.has(bigram)) {
				bigramHits++;
			}
		}
	}

	const printRatio = printableCount / length;
	const freqRatio = frequentCount / length;
	const bigramRatio = length > 1 ? bigramHits / (length - 1) : 0;

	// Base score from printability
	let score = printRatio * 0.4;

	// Bonus for English-like character distribution
	score += freqRatio * 0.3;

	// Bonus for bigram frequency
	score += Math.min(bigramRatio * 0.5, 0.15);

	// Bonus for having spaces (real strings often have spaces)
	if (spaceCount > 0 && spaceCount < length * 0.3) {
		score += 0.1;
	}

	// Bonus for longer strings
	if (length >= 12) { score += 0.03; }
	if (length >= 24) { score += 0.02; }

	// Penalty for all-digits
	if (digitCount > length * 0.8) {
		score *= 0.3;
	}

	return Math.min(1.0, score);
}

/**
 * Check if a byte is printable ASCII (space through tilde, plus tab/newline/CR).
 */
function isPrintable(byte: number): boolean {
	return (byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D;
}

/**
 * Format a key buffer as a hex string (e.g. "0xDEADBEEF").
 */
function formatKeyHex(key: Buffer): string {
	return '0x' + Array.from(key).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
}
