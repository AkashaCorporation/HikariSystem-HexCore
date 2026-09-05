export interface ExtractedUnicodeString {
	offset: number;
	value: string;
	encoding: 'UTF-16LE';
	section?: string;
}

export interface UnicodeChunkResult {
	strings: ExtractedUnicodeString[];
	carryover: Buffer;
	carryoverOffset: number;
}

function isPrintableWidePair(low: number, high: number): boolean {
	return high === 0 && ((low >= 32 && low <= 126) || low === 9 || low === 10 || low === 13);
}

/**
 * Extract UTF-16LE ASCII runs from a stream of binary chunks.
 *
 * Wide strings may start at either byte parity. The previous scanner only
 * visited offsets 0, 2, 4... within each chunk, which missed valid strings at
 * odd file offsets and also discarded unterminated runs at chunk boundaries.
 * The returned carryover starts at the earliest unfinished candidate so both
 * alignments can be reconsidered when the next chunk arrives.
 */
export function extractUnicodeFromChunk(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	carryover: Buffer,
	carryoverOffset: number,
	finalChunk = false
): UnicodeChunkResult {
	const strings: ExtractedUnicodeString[] = [];
	const combined = carryover.length > 0 ? Buffer.concat([carryover, buffer]) : buffer;
	const combinedOffset = carryover.length > 0 ? carryoverOffset : baseOffset;
	let earliestUnfinished = combined.length;

	for (const alignment of [0, 1]) {
		let currentString = '';
		let startIndex = -1;

		const flush = (): void => {
			if (currentString.length >= minLength) {
				const trimmed = currentString.trim();
				if (trimmed.length >= minLength) {
					strings.push({
						offset: combinedOffset + startIndex,
						value: trimmed,
						encoding: 'UTF-16LE'
					});
				}
			}
			currentString = '';
			startIndex = -1;
		};

		for (let i = alignment; i + 1 < combined.length; i += 2) {
			const low = combined[i];
			const high = combined[i + 1];
			if (isPrintableWidePair(low, high)) {
				if (startIndex < 0) {
					startIndex = i;
				}
				currentString += String.fromCharCode(low);
			} else {
				flush();
			}
		}

		if (currentString.length > 0) {
			if (finalChunk) {
				flush();
			} else {
				earliestUnfinished = Math.min(earliestUnfinished, startIndex);
			}
		}
	}

	if (finalChunk) {
		return {
			strings,
			carryover: Buffer.alloc(0),
			carryoverOffset: combinedOffset + combined.length
		};
	}

	// Preserve the final byte even when no string is currently open. It may be
	// the low byte of a UTF-16LE pair split exactly at the chunk boundary.
	if (combined.length > 0) {
		earliestUnfinished = Math.min(earliestUnfinished, combined.length - 1);
	}
	const carryStart = Math.max(0, earliestUnfinished);
	return {
		strings,
		carryover: Buffer.from(combined.subarray(carryStart)),
		carryoverOffset: combinedOffset + carryStart
	};
}
