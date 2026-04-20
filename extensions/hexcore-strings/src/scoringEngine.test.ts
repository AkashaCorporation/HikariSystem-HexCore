/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { scoreString, scoreStringDetailed, isPrintable } from './scoringEngine';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Common English bigrams — mirrors the set in scoringEngine.ts.
 * Needed for the backward-compatibility property to recompute the original formula.
 */
const COMMON_BIGRAMS = new Set<string>([
	'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
	'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar',
	'st', 'to', 'nt', 'ng', 'se', 'ha', 'as', 'ou', 'io', 'le',
	'no', 'us', 'co', 'me', 'de', 'hi', 'ri', 'ro', 'ic', 'ne',
]);

const ENGLISH_FREQ = new Set<number>([
	0x20, 0x65, 0x74, 0x61, 0x6F, 0x69, 0x6E, 0x73, 0x68, 0x72,
	0x64, 0x6C, 0x63, 0x75, 0x6D, 0x77, 0x66, 0x67, 0x79, 0x70,
]);

/**
 * Recompute the original scoring formula (before bonuses/penalties were added).
 * This is the formula from the original `scoreRun` in multiByteXor.ts.
 */
function originalFormula(decoded: Buffer, start: number, length: number): number {
	if (length <= 0) { return 0; }

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
		if (i > start) {
			const bigram = String.fromCharCode(decoded[i - 1], byte).toLowerCase();
			if (COMMON_BIGRAMS.has(bigram)) { bigramHits++; }
		}
	}

	const printRatio = printableCount / length;
	const freqRatio = frequentCount / length;
	const bigramRatio = length > 1 ? bigramHits / (length - 1) : 0;

	let score = printRatio * 0.4 + freqRatio * 0.3 + Math.min(bigramRatio * 0.5, 0.15);

	// Space bonus
	if (spaceCount > 0 && spaceCount < length * 0.3) {
		score += 0.1;
	}

	// Length bonus
	if (length >= 12) { score += 0.03; }
	if (length >= 24) { score += 0.02; }

	// All-digits penalty
	if (digitCount > length * 0.8) {
		score *= 0.3;
	}

	return Math.min(1.0, score);
}

/**
 * Check if a string (as buffer) contains any URL, Windows path, or registry key patterns.
 */
function containsBonusPatterns(buf: Buffer): boolean {
	const text = buf.toString('ascii');
	const lower = text.toLowerCase();
	if (lower.includes('http://') || lower.includes('https://') || lower.includes('ftp://')) { return true; }
	if (text.includes('C:\\') || text.includes('\\\\') || lower.includes('.exe') || lower.includes('.dll')) { return true; }
	if (text.includes('HKEY_') || text.includes('SOFTWARE\\')) { return true; }
	return false;
}

/**
 * Check if all non-null bytes in a buffer region are the same character.
 */
function isAllSameChar(buf: Buffer, start: number, length: number): boolean {
	if (length <= 1) { return true; }
	let first = -1;
	for (let i = start; i < start + length; i++) {
		if (first === -1) { first = buf[i]; }
		else if (buf[i] !== first) { return false; }
	}
	return true;
}

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Generate a printable ASCII string buffer (0x20–0x7E) that does NOT contain
 * any bonus patterns (URL, Windows path, registry key).
 */
function printableNoBonusArb(minLen: number, maxLen: number): fc.Arbitrary<Buffer> {
	// Use only lowercase letters, digits, and spaces — avoids accidentally
	// forming patterns like "http://", "C:\", "HKEY_", ".exe", ".dll", etc.
	const safeChars = 'abcdfgijklmnopqrtuvwyz 0123456789';
	return fc.stringOf(
		fc.constantFrom(...safeChars.split('')),
		{ minLength: minLen, maxLength: maxLen }
	).filter(s => {
		// Extra safety: reject if any bonus pattern sneaks in
		const lower = s.toLowerCase();
		if (lower.includes('http://') || lower.includes('https://') || lower.includes('ftp://')) { return false; }
		if (s.includes('C:\\') || s.includes('\\\\') || lower.includes('.exe') || lower.includes('.dll')) { return false; }
		if (s.includes('HKEY_') || s.includes('SOFTWARE\\')) { return false; }
		// Reject all-same-character strings (would trigger repetition penalty)
		if (s.length > 1 && new Set(s.split('')).size === 1) { return false; }
		return true;
	}).map(s => Buffer.from(s, 'ascii'));
}

// ---------------------------------------------------------------------------
// Property Tests
// ---------------------------------------------------------------------------

suite('Scoring Engine Properties', () => {

	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 11: Scoring Bonus Detection
	// **Validates: Requirements 8.1, 8.2, 8.3**
	// -----------------------------------------------------------------------

	test('P11: URL bonus adds at least 0.15 to score', () => {
		fc.assert(
			fc.property(
				printableNoBonusArb(8, 60),
				(baseBuf) => {
					// Build a combined buffer with URL pattern embedded
					const urlPrefix = Buffer.from('http://example.com ');
					const withUrl = Buffer.concat([urlPrefix, baseBuf]);

					// Get the detailed breakdown — the urlBonus field should be 0.15
					const breakdown = scoreStringDetailed(withUrl, 0, withUrl.length);
					if (breakdown.urlBonus !== 0.15) { return false; }

					// The total score should be at least 0.15 higher than the base
					// components alone (before bonus), unless capped at 1.0
					const baseOnly = breakdown.printability + breakdown.englishFreq
						+ breakdown.bigramBonus + breakdown.spaceBonus + breakdown.lengthBonus;
					const withBonus = Math.min(1.0, baseOnly + breakdown.urlBonus + breakdown.pathBonus + breakdown.registryBonus)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;
					const withoutBonus = Math.min(1.0, baseOnly)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;

					return withBonus >= withoutBonus + 0.15 - 0.001 || withBonus >= 0.99;
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P11: Windows path bonus adds at least 0.10 to score', () => {
		fc.assert(
			fc.property(
				printableNoBonusArb(8, 60),
				(baseBuf) => {
					const pathPrefix = Buffer.from('C:\\Windows\\System32 ');
					const withPath = Buffer.concat([pathPrefix, baseBuf]);

					const breakdown = scoreStringDetailed(withPath, 0, withPath.length);
					if (breakdown.pathBonus !== 0.10) { return false; }

					const baseOnly = breakdown.printability + breakdown.englishFreq
						+ breakdown.bigramBonus + breakdown.spaceBonus + breakdown.lengthBonus;
					const withBonus = Math.min(1.0, baseOnly + breakdown.urlBonus + breakdown.pathBonus + breakdown.registryBonus)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;
					const withoutBonus = Math.min(1.0, baseOnly)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;

					return withBonus >= withoutBonus + 0.10 - 0.001 || withBonus >= 0.99;
				}
			),
			{ numRuns: 100 }
		);
	});

	test('P11: Registry key bonus adds at least 0.10 to score', () => {
		fc.assert(
			fc.property(
				printableNoBonusArb(8, 60),
				(baseBuf) => {
					const regPrefix = Buffer.from('HKEY_LOCAL_MACHINE ');
					const withReg = Buffer.concat([regPrefix, baseBuf]);

					const breakdown = scoreStringDetailed(withReg, 0, withReg.length);
					if (breakdown.registryBonus !== 0.10) { return false; }

					const baseOnly = breakdown.printability + breakdown.englishFreq
						+ breakdown.bigramBonus + breakdown.spaceBonus + breakdown.lengthBonus;
					const withBonus = Math.min(1.0, baseOnly + breakdown.urlBonus + breakdown.pathBonus + breakdown.registryBonus)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;
					const withoutBonus = Math.min(1.0, baseOnly)
						* breakdown.digitPenalty * breakdown.repetitionPenalty;

					return withBonus >= withoutBonus + 0.10 - 0.001 || withBonus >= 0.99;
				}
			),
			{ numRuns: 100 }
		);
	});

	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 12: Scoring Repetition Penalty
	// **Validates: Requisito 8.4**
	// -----------------------------------------------------------------------

	test('P12: Repeated character strings score at most 50% of non-penalized score', () => {
		fc.assert(
			fc.property(
				// Generate a printable ASCII byte for the repeated character
				fc.integer({ min: 0x20, max: 0x7E }),
				// Length of the repeated string (at least 2 to trigger penalty)
				fc.integer({ min: 4, max: 200 }),
				(charCode, length) => {
					// Build a buffer of all-same character
					const buf = Buffer.alloc(length, charCode);

					// Get the detailed breakdown
					const breakdown = scoreStringDetailed(buf, 0, length);

					// The repetition penalty should be 0.5
					assert.strictEqual(breakdown.repetitionPenalty, 0.5,
						`Expected repetitionPenalty=0.5 for all-same-char buffer, got ${breakdown.repetitionPenalty}`);

					// Compute what the score would be WITHOUT the repetition penalty:
					// total_without_penalty = total / repetitionPenalty (if repetitionPenalty != 0)
					// Since repetitionPenalty is 0.5, the non-penalized score = total / 0.5 = total * 2
					// So: total <= non_penalized * 0.5
					// Which is: breakdown.total <= (breakdown.total / 0.5) * 0.5 — always true by construction.
					// More meaningfully: the actual total equals base * digitPenalty * 0.5
					const base = breakdown.printability + breakdown.englishFreq + breakdown.bigramBonus
						+ breakdown.spaceBonus + breakdown.lengthBonus
						+ breakdown.urlBonus + breakdown.pathBonus + breakdown.registryBonus;
					const nonPenalizedScore = Math.min(1.0, base) * breakdown.digitPenalty;

					// The penalized score should be at most 50% of the non-penalized score
					return breakdown.total <= nonPenalizedScore * 0.5 + 0.001;
				}
			),
			{ numRuns: 100 }
		);
	});

	// -----------------------------------------------------------------------
	// Feature: xor-massive-update, Property 14: Scoring Backward Compatibility
	// **Validates: Requisitos 8.7, 10.4**
	// -----------------------------------------------------------------------

	test('P14: Backward compatibility — no bonus/penalty strings match original formula', () => {
		fc.assert(
			fc.property(
				printableNoBonusArb(4, 120),
				(buf) => {
					// This buffer has no URL/path/registry patterns and is not all-same-char.
					// The new scoring engine should produce the same score as the original formula.
					const newScore = scoreString(buf, 0, buf.length);
					const oldScore = originalFormula(buf, 0, buf.length);

					// Verify the breakdown confirms no bonuses or penalties were applied
					const breakdown = scoreStringDetailed(buf, 0, buf.length);
					assert.strictEqual(breakdown.urlBonus, 0, 'urlBonus should be 0');
					assert.strictEqual(breakdown.pathBonus, 0, 'pathBonus should be 0');
					assert.strictEqual(breakdown.registryBonus, 0, 'registryBonus should be 0');
					assert.strictEqual(breakdown.repetitionPenalty, 1.0, 'repetitionPenalty should be 1.0');

					// Scores should be identical (within floating-point tolerance)
					return Math.abs(newScore - oldScore) < 0.0001;
				}
			),
			{ numRuns: 100 }
		);
	});
});
