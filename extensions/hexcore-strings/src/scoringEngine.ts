/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface ScoringOptions {
	/** Minimum confidence threshold (default: 0.6) */
	minConfidence?: number;
	/** If true, skip null bytes (0x00) in printability and frequency calculations (for wide strings) */
	ignoreNullBytes?: boolean;
}

export interface ScoreBreakdown {
	printability: number;
	englishFreq: number;
	bigramBonus: number;
	lengthBonus: number;
	spaceBonus: number;
	urlBonus: number;
	pathBonus: number;
	registryBonus: number;
	repetitionPenalty: number;
	digitPenalty: number;
	total: number;
}

export interface PrintableRun {
	start: number;
	length: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

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
 * Check if a byte is printable ASCII (space through tilde, plus tab/newline/CR).
 */
export function isPrintable(byte: number): boolean {
	return (byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D;
}

/**
 * Extract contiguous runs of printable ASCII characters from a decoded buffer.
 */
export function extractPrintableRuns(decoded: Buffer, minLength: number): PrintableRun[] {
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
 * Format a key buffer as a hex string "0xDEADBEEF".
 */
export function formatKeyHex(key: Buffer): string {
	return '0x' + Array.from(key).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------
// Scoring — Detailed
// ---------------------------------------------------------------------------

/**
 * Score a decoded string with full breakdown of all scoring components.
 *
 * Base weights (maintained for backward compatibility):
 * - Printability ratio: 0.4 weight
 * - English character frequency: 0.3 weight
 * - Bigram frequency: up to 0.15
 * - Length bonus: up to 0.05 (0.03 for ≥12, +0.02 for ≥24)
 * - Space bonus: 0.1 (if spaces present and < 30% of string)
 * - All-digits penalty: 0.3x multiplier
 *
 * New bonuses (additional layer):
 * - URL detected (http://, https://, ftp://): +0.15
 * - Windows path (C:\, \\, .exe, .dll): +0.10
 * - Registry key (HKEY_, SOFTWARE\): +0.10
 * - Repetition penalty (all same character): 0.5x multiplier
 *
 * @param decoded Buffer containing decoded data
 * @param start   Start offset within the buffer
 * @param length  Number of bytes to score
 * @param options Scoring options
 */
export function scoreStringDetailed(decoded: Buffer, start: number, length: number, options?: ScoringOptions): ScoreBreakdown {
	const breakdown: ScoreBreakdown = {
		printability: 0,
		englishFreq: 0,
		bigramBonus: 0,
		lengthBonus: 0,
		spaceBonus: 0,
		urlBonus: 0,
		pathBonus: 0,
		registryBonus: 0,
		repetitionPenalty: 1.0,
		digitPenalty: 1.0,
		total: 0,
	};

	if (length <= 0) {
		return breakdown;
	}

	const ignoreNull = options?.ignoreNullBytes === true;

	let printableCount = 0;
	let frequentCount = 0;
	let spaceCount = 0;
	let digitCount = 0;
	let bigramHits = 0;
	let effectiveLength = length;
	let nullCount = 0;
	let firstByte = -1;
	let allSameChar = true;

	for (let i = start; i < start + length; i++) {
		const byte = decoded[i];

		// Track null bytes for ignoreNullBytes mode
		if (ignoreNull && byte === 0x00) {
			nullCount++;
			continue;
		}

		if (firstByte === -1) {
			firstByte = byte;
		} else if (byte !== firstByte) {
			allSameChar = false;
		}

		if (isPrintable(byte)) { printableCount++; }
		if (ENGLISH_FREQ.has(byte)) { frequentCount++; }
		if (byte === 0x20) { spaceCount++; }
		if (byte >= 0x30 && byte <= 0x39) { digitCount++; }

		// Check bigrams (skip null bytes in bigram calculation)
		if (i > start) {
			const prevByte = decoded[i - 1];
			if (!(ignoreNull && prevByte === 0x00)) {
				const bigram = String.fromCharCode(prevByte, byte).toLowerCase();
				if (COMMON_BIGRAMS.has(bigram)) {
					bigramHits++;
				}
			}
		}
	}

	// Adjust effective length when ignoring null bytes
	if (ignoreNull) {
		effectiveLength = length - nullCount;
	}

	if (effectiveLength <= 0) {
		return breakdown;
	}

	const printRatio = printableCount / effectiveLength;
	const freqRatio = frequentCount / effectiveLength;
	const bigramRatio = effectiveLength > 1 ? bigramHits / (effectiveLength - 1) : 0;

	// Base score from printability
	breakdown.printability = printRatio * 0.4;

	// Bonus for English-like character distribution
	breakdown.englishFreq = freqRatio * 0.3;

	// Bonus for bigram frequency
	breakdown.bigramBonus = Math.min(bigramRatio * 0.5, 0.15);

	// Bonus for having spaces (real strings often have spaces)
	if (spaceCount > 0 && spaceCount < effectiveLength * 0.3) {
		breakdown.spaceBonus = 0.1;
	}

	// Bonus for longer strings
	if (length >= 12) { breakdown.lengthBonus += 0.03; }
	if (length >= 24) { breakdown.lengthBonus += 0.02; }

	// --- New bonuses: detect patterns in the decoded text ---
	const text = decoded.slice(start, start + length).toString('ascii');
	const textLower = text.toLowerCase();

	// URL bonus
	if (textLower.includes('http://') || textLower.includes('https://') || textLower.includes('ftp://')) {
		breakdown.urlBonus = 0.15;
	}

	// Windows path bonus
	if (text.includes('C:\\') || text.includes('\\\\') || textLower.includes('.exe') || textLower.includes('.dll')) {
		breakdown.pathBonus = 0.10;
	}

	// Registry key bonus
	if (text.includes('HKEY_') || text.includes('SOFTWARE\\')) {
		breakdown.registryBonus = 0.10;
	}

	// Repetition penalty: all same character
	if (allSameChar && effectiveLength > 1) {
		breakdown.repetitionPenalty = 0.5;
	}

	// All-digits penalty
	if (digitCount > effectiveLength * 0.8) {
		breakdown.digitPenalty = 0.3;
	}

	// Calculate total
	const base = breakdown.printability + breakdown.englishFreq + breakdown.bigramBonus
		+ breakdown.spaceBonus + breakdown.lengthBonus;
	const bonus = breakdown.urlBonus + breakdown.pathBonus + breakdown.registryBonus;
	let score = Math.min(1.0, base + bonus);
	score *= breakdown.digitPenalty;
	score *= breakdown.repetitionPenalty;

	breakdown.total = score;

	return breakdown;
}

// ---------------------------------------------------------------------------
// Scoring — Simple (returns total only)
// ---------------------------------------------------------------------------

/**
 * Score a decoded string and return the total confidence score (0.0–1.0).
 *
 * When no URL/path/registry patterns are present and no repetition penalty
 * applies, this produces IDENTICAL results to the original `scoreRun` in
 * `multiByteXor.ts` for backward compatibility.
 *
 * @param decoded Buffer containing decoded data
 * @param start   Start offset within the buffer
 * @param length  Number of bytes to score
 * @param options Scoring options
 */
export function scoreString(decoded: Buffer, start: number, length: number, options?: ScoringOptions): number {
	return scoreStringDetailed(decoded, start, length, options).total;
}
