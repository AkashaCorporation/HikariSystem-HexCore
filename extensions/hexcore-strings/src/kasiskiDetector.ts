/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface KasiskiResult {
	/** Candidate key lengths sorted by probability (descending) */
	candidateLengths: number[];
	/** Method that produced the result */
	detectionMethod: 'kasiski' | 'ic' | 'both';
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Default maximum key length to test */
const DEFAULT_MAX_KEY_LENGTH = 64;

/** Minimum buffer size for meaningful analysis */
const MIN_BUFFER_SIZE = 32;

/** Maximum number of candidate lengths to return */
const MAX_CANDIDATES = 10;

/** Sliding window size for Kasiski trigram search */
const TRIGRAM_SIZE = 3;

/** IC threshold — English text IC ≈ 0.0667, random ≈ 0.0039 */
const IC_THRESHOLD = 0.05;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Detect candidate key lengths using Kasiski Examination + Index of Coincidence.
 *
 * Algorithm — Kasiski Examination:
 * 1. Find all repeated sequences of 3+ bytes in the buffer
 * 2. Calculate distances between consecutive occurrences
 * 3. For each distance, find all factors (2 to maxKeyLength)
 * 4. Count factor frequencies — most common factors are likely key lengths
 * 5. Return top candidates sorted by frequency (descending)
 *
 * Algorithm — Index of Coincidence (fallback):
 * 1. For each candidate length L (2 to maxKeyLength):
 *    a. Divide buffer into L groups (bytes at position i % L)
 *    b. For each group, calculate IC = Σ(fi * (fi-1)) / (N * (N-1))
 *    c. Average IC across all L groups
 * 2. Select lengths where average IC > 0.05
 * 3. Sort by IC descending
 *
 * Combined approach:
 * 1. Run Kasiski first
 * 2. Run IC analysis
 * 3. Merge results, set detectionMethod accordingly
 *
 * @param buffer Buffer to analyze
 * @param maxKeyLength Maximum key length to test (default: 64)
 * @returns Candidate key lengths sorted by probability
 */
export function detectKeyLengths(buffer: Buffer, maxKeyLength?: number): KasiskiResult {
	const maxLen = maxKeyLength ?? DEFAULT_MAX_KEY_LENGTH;

	// Too small for meaningful analysis
	if (buffer.length < MIN_BUFFER_SIZE) {
		return { candidateLengths: [], detectionMethod: 'kasiski' };
	}

	// Run Kasiski examination
	const kasiskiCandidates = runKasiski(buffer, maxLen);

	// Run Index of Coincidence analysis
	const icCandidates = runIndexOfCoincidence(buffer, maxLen);

	// Determine detection method and merge results
	const hasKasiski = kasiskiCandidates.length > 0;
	const hasIC = icCandidates.length > 0;

	let detectionMethod: 'kasiski' | 'ic' | 'both';
	let merged: number[];

	if (hasKasiski && hasIC) {
		detectionMethod = 'both';
		merged = mergeCandidates(kasiskiCandidates, icCandidates);
	} else if (hasKasiski) {
		detectionMethod = 'kasiski';
		merged = kasiskiCandidates;
	} else if (hasIC) {
		detectionMethod = 'ic';
		merged = icCandidates;
	} else {
		detectionMethod = 'kasiski';
		merged = [];
	}

	// Deduplicate and cap
	const unique = [...new Set(merged)];
	const capped = unique.slice(0, MAX_CANDIDATES);

	return { candidateLengths: capped, detectionMethod };
}

// ---------------------------------------------------------------------------
// Kasiski Examination
// ---------------------------------------------------------------------------

/**
 * Run Kasiski examination: find repeated trigrams, compute distances,
 * factor distances, and rank factors by frequency.
 */
function runKasiski(buffer: Buffer, maxKeyLength: number): number[] {
	// Step 1: Find all repeated sequences of 3 bytes
	const trigramPositions = new Map<string, number[]>();

	for (let i = 0; i <= buffer.length - TRIGRAM_SIZE; i++) {
		const key = `${buffer[i]},${buffer[i + 1]},${buffer[i + 2]}`;
		const positions = trigramPositions.get(key);
		if (positions) {
			positions.push(i);
		} else {
			trigramPositions.set(key, [i]);
		}
	}

	// Step 2: Calculate distances between consecutive occurrences
	const factorCounts = new Map<number, number>();

	for (const positions of trigramPositions.values()) {
		if (positions.length < 2) {
			continue;
		}

		for (let i = 1; i < positions.length; i++) {
			const distance = positions[i] - positions[i - 1];

			// Step 3: Find all factors of the distance in range [2, maxKeyLength]
			for (let f = 2; f <= Math.min(distance, maxKeyLength); f++) {
				if (distance % f === 0) {
					factorCounts.set(f, (factorCounts.get(f) ?? 0) + 1);
				}
			}
		}
	}

	if (factorCounts.size === 0) {
		return [];
	}

	// Step 4: Sort factors by frequency descending
	const sorted = [...factorCounts.entries()]
		.sort((a, b) => b[1] - a[1]);

	// Return top candidate lengths
	return sorted.slice(0, MAX_CANDIDATES).map(([factor]) => factor);
}

// ---------------------------------------------------------------------------
// Index of Coincidence
// ---------------------------------------------------------------------------

/**
 * Run Index of Coincidence analysis for each candidate key length.
 *
 * For each length L:
 * 1. Divide buffer into L groups (bytes at position i % L)
 * 2. Calculate IC for each group
 * 3. Average IC across groups
 * 4. Select lengths where average IC > threshold
 */
function runIndexOfCoincidence(buffer: Buffer, maxKeyLength: number): number[] {
	const candidates: Array<{ length: number; ic: number }> = [];

	const maxL = Math.min(maxKeyLength, Math.floor(buffer.length / 2));

	for (let L = 2; L <= maxL; L++) {
		let totalIC = 0;

		for (let g = 0; g < L; g++) {
			// Count frequency of each byte value in this group
			const freq = new Uint32Array(256);
			let groupSize = 0;

			for (let i = g; i < buffer.length; i += L) {
				freq[buffer[i]]++;
				groupSize++;
			}

			if (groupSize <= 1) {
				continue;
			}

			// Calculate IC = Σ(fi * (fi-1)) / (N * (N-1))
			let sum = 0;
			for (let b = 0; b < 256; b++) {
				sum += freq[b] * (freq[b] - 1);
			}
			const ic = sum / (groupSize * (groupSize - 1));
			totalIC += ic;
		}

		const avgIC = totalIC / L;

		if (avgIC > IC_THRESHOLD) {
			candidates.push({ length: L, ic: avgIC });
		}
	}

	// Sort by IC descending
	candidates.sort((a, b) => b.ic - a.ic);

	return candidates.slice(0, MAX_CANDIDATES).map(c => c.length);
}

// ---------------------------------------------------------------------------
// Merge Candidates
// ---------------------------------------------------------------------------

/**
 * Merge Kasiski and IC candidates, prioritizing entries that appear in both.
 * Kasiski candidates come first (they are generally more reliable),
 * followed by IC-only candidates.
 */
function mergeCandidates(kasiski: number[], ic: number[]): number[] {
	const icSet = new Set(ic);
	const kasiskiSet = new Set(kasiski);

	// Entries in both lists get highest priority
	const inBoth: number[] = [];
	const kasiskiOnly: number[] = [];
	const icOnly: number[] = [];

	for (const k of kasiski) {
		if (icSet.has(k)) {
			inBoth.push(k);
		} else {
			kasiskiOnly.push(k);
		}
	}

	for (const i of ic) {
		if (!kasiskiSet.has(i)) {
			icOnly.push(i);
		}
	}

	return [...inBoth, ...kasiskiOnly, ...icOnly];
}
