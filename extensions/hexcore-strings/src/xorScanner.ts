/*---------------------------------------------------------------------------------------------
 *  HexCore Strings Extractor v1.2.0
 *  XOR brute-force scanner — single-byte key deobfuscation
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface XorResult {
	/** The XOR key used to decode this string (0x01–0xFF). */
	key: number;
	/** The decoded printable string. */
	value: string;
	/** Absolute file offset where the encoded string starts. */
	offset: number;
	/** Length of the encoded region in bytes. */
	length: number;
	/** Confidence score 0–1 based on printability ratio and string quality. */
	confidence: number;
}

export interface XorScanOptions {
	/** Minimum string length after decoding (default: 6). */
	minLength?: number;
	/** Minimum confidence to include result (default: 0.6). */
	minConfidence?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MIN_CONFIDENCE = 0.6;

/** Minimum ratio of printable bytes in a decoded run to be considered valid. */
const PRINTABILITY_THRESHOLD = 0.85;

/**
 * Common English letter frequencies used to score string "naturalness".
 * Strings that match natural language distribution score higher.
 */
const ENGLISH_FREQ = new Set<number>([
	0x20, 0x65, 0x74, 0x61, 0x6F, 0x69, 0x6E, 0x73, 0x68, 0x72, // ' etaoinshr'
	0x64, 0x6C, 0x63, 0x75, 0x6D, 0x77, 0x66, 0x67, 0x79, 0x70, // 'dlcumwfgyp'
]);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Brute-force XOR decode a buffer with all possible single-byte keys.
 *
 * Strategy:
 * 1. For each key 0x01–0xFF, XOR every byte in the buffer.
 * 2. Extract contiguous runs of printable ASCII (length ≥ minLength).
 * 3. Score each run by printability ratio + character frequency analysis.
 * 4. Deduplicate across keys (same string at same offset = false positive).
 * 5. Return results sorted by confidence (descending).
 *
 * Performance: The inner loop is `O(255 * bufferSize)` which for a 64KB
 * chunk is ~16M iterations — fast enough for streaming chunk analysis.
 *
 * @param buffer   Raw binary data chunk
 * @param baseOffset  File offset where this chunk starts (for absolute offsets)
 * @param options  Scanner configuration
 */
export function xorBruteForce(
	buffer: Buffer,
	baseOffset: number,
	options?: XorScanOptions,
): XorResult[] {
	const minLength = options?.minLength ?? DEFAULT_MIN_LENGTH;
	const minConfidence = options?.minConfidence ?? DEFAULT_MIN_CONFIDENCE;

	// Dedup: key is "offset:decoded_value" to reject same string from multiple keys
	const seen = new Set<string>();
	const results: XorResult[] = [];

	for (let key = 0x01; key <= 0xFF; key++) {
		// Quick reject: try XOR on a sample of the buffer.
		// If less than 5% of the first 256 bytes produce printable chars, skip.
		if (!quickCheck(buffer, key)) {
			continue;
		}

		// Decode full buffer with this key
		const decoded = Buffer.alloc(buffer.length);
		for (let i = 0; i < buffer.length; i++) {
			decoded[i] = buffer[i] ^ key;
		}

		// Extract printable runs
		const runs = extractPrintableRuns(decoded, minLength);

		for (const run of runs) {
			const confidence = scoreRun(decoded, run.start, run.length);
			if (confidence < minConfidence) {
				continue;
			}

			const value = decoded.subarray(run.start, run.start + run.length).toString('ascii');
			const dedupKey = `${run.start}:${value}`;

			if (seen.has(dedupKey)) {
				continue;
			}
			seen.add(dedupKey);

			results.push({
				key,
				value,
				offset: baseOffset + run.start,
				length: run.length,
				confidence,
			});
		}
	}

	// Sort by confidence descending, then by offset ascending
	results.sort((a, b) => b.confidence - a.confidence || a.offset - b.offset);

	return results;
}

// ---------------------------------------------------------------------------
// Quick Reject
// ---------------------------------------------------------------------------

/**
 * Sample first 256 bytes with the key. If too few printable bytes result,
 * skip this key entirely — massive performance win for binary data.
 */
function quickCheck(buffer: Buffer, key: number): boolean {
	const sampleSize = Math.min(256, buffer.length);
	let printable = 0;

	for (let i = 0; i < sampleSize; i++) {
		const decoded = buffer[i] ^ key;
		if (isPrintable(decoded)) {
			printable++;
		}
	}

	return (printable / sampleSize) >= 0.05;
}

// ---------------------------------------------------------------------------
// Printable Run Extraction
// ---------------------------------------------------------------------------

interface PrintableRun {
	start: number;
	length: number;
}

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

// ---------------------------------------------------------------------------
// Confidence Scoring
// ---------------------------------------------------------------------------

/**
 * Score a printable run based on:
 * 1. Printability ratio (how many bytes in the run are printable)
 * 2. Character frequency analysis (do chars match English distribution)
 * 3. Word-like structure (spaces, mixed case, path-like separators)
 */
function scoreRun(decoded: Buffer, start: number, length: number): number {
	let printableCount = 0;
	let frequentCount = 0;
	let spaceCount = 0;
	let digitCount = 0;

	for (let i = start; i < start + length; i++) {
		const byte = decoded[i];
		if (isPrintable(byte)) { printableCount++; }
		if (ENGLISH_FREQ.has(byte)) { frequentCount++; }
		if (byte === 0x20) { spaceCount++; }
		if (byte >= 0x30 && byte <= 0x39) { digitCount++; }
	}

	const printRatio = printableCount / length;
	const freqRatio = frequentCount / length;

	// Base score from printability
	let score = printRatio * 0.4;

	// Bonus for English-like character distribution
	score += freqRatio * 0.3;

	// Bonus for having spaces (real strings often have spaces)
	if (spaceCount > 0 && spaceCount < length * 0.3) {
		score += 0.15;
	}

	// Bonus for longer strings (more likely to be real)
	if (length >= 12) { score += 0.1; }
	if (length >= 24) { score += 0.05; }

	// Penalty for all-digits (version numbers, not interesting)
	if (digitCount > length * 0.8) {
		score *= 0.3;
	}

	return Math.min(1.0, score);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function isPrintable(byte: number): boolean {
	return (byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D;
}
