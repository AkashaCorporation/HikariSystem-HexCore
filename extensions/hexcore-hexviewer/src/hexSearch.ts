/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer — Hex Search Module
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';

/**
 * Result of a hex pattern search.
 */
export interface HexSearchResult {
	filePath: string;
	pattern: string;
	matches: Array<{ offset: number; context: string }>;
	totalMatches: number;
	generatedAt: string;
}

/**
 * Search a file for all occurrences of a hex byte pattern using streaming.
 *
 * Uses 64KB chunks with overlap equal to the pattern length to handle
 * matches that span chunk boundaries.
 *
 * @param filePath   - Absolute path to the file.
 * @param pattern    - Hex string pattern (e.g. "4D5A9000"). Spaces are stripped.
 * @param maxResults - Maximum number of matches to return (default 1000).
 * @returns A {@link HexSearchResult} with all match offsets and surrounding context.
 * @throws If the file does not exist or the pattern is invalid.
 */
export function hexSearchPattern(
	filePath: string,
	pattern: string,
	maxResults: number = 1000
): HexSearchResult {
	if (!fs.existsSync(filePath)) {
		throw new Error(`File not found: ${filePath}`);
	}

	// Normalise: strip spaces
	const cleaned = pattern.replace(/\s/g, '');

	// Validate hex characters
	if (!/^[0-9A-Fa-f]+$/.test(cleaned)) {
		throw new Error(
			`Invalid hex pattern: "${pattern}". Only hex characters (0-9, A-F) are allowed.`
		);
	}
	// Validate even length
	if (cleaned.length % 2 !== 0) {
		throw new Error(
			`Invalid hex pattern: "${pattern}". Pattern must have an even number of hex characters.`
		);
	}
	if (cleaned.length === 0) {
		throw new Error('Hex pattern must not be empty.');
	}

	const needle = Buffer.from(cleaned, 'hex');
	const CHUNK_SIZE = 64 * 1024; // 64KB
	const overlap = needle.length - 1; // overlap to catch cross-boundary matches
	const contextSize = 8; // bytes of context before and after each match

	const stats = fs.statSync(filePath);
	const fileSize = stats.size;
	const matches: Array<{ offset: number; context: string }> = [];

	const fd = fs.openSync(filePath, 'r');
	try {
		const buf = Buffer.alloc(CHUNK_SIZE + overlap);
		let fileOffset = 0;
		let carryoverLen = 0;

		while (fileOffset < fileSize && matches.length < maxResults) {
			// How many new bytes to read this iteration
			const toRead = Math.min(CHUNK_SIZE, fileSize - fileOffset);
			const readLen = fs.readSync(fd, buf, carryoverLen, toRead, fileOffset);
			const totalLen = carryoverLen + readLen;
			const chunk = buf.subarray(0, totalLen);

			// The absolute offset of chunk[0] in the file
			const chunkBaseOffset = fileOffset - carryoverLen;

			// Search for needle in chunk
			let searchStart = 0;
			while (searchStart <= totalLen - needle.length && matches.length < maxResults) {
				const idx = chunk.indexOf(needle, searchStart);
				if (idx === -1) {
					break;
				}
				const absoluteOffset = chunkBaseOffset + idx;
				const ctx = readContext(fd, fileSize, absoluteOffset, needle.length, contextSize);
				matches.push({ offset: absoluteOffset, context: ctx });
				searchStart = idx + 1;
			}

			fileOffset += readLen;

			// Keep the tail as carryover for next iteration
			if (overlap > 0 && fileOffset < fileSize) {
				const tailStart = totalLen - overlap;
				buf.copyWithin(0, tailStart, totalLen);
				carryoverLen = overlap;
			} else {
				carryoverLen = 0;
			}
		}
	} finally {
		fs.closeSync(fd);
	}

	return {
		filePath,
		pattern: cleaned.toUpperCase(),
		matches,
		totalMatches: matches.length,
		generatedAt: new Date().toISOString()
	};
}

/**
 * Read context bytes around a match for display purposes.
 * Returns a hex string: `[before] [match] [after]`.
 */
function readContext(
	fd: number,
	fileSize: number,
	matchOffset: number,
	matchLen: number,
	contextSize: number
): string {
	const ctxStart = Math.max(0, matchOffset - contextSize);
	const ctxEnd = Math.min(fileSize, matchOffset + matchLen + contextSize);
	const ctxLen = ctxEnd - ctxStart;

	const ctxBuf = Buffer.alloc(ctxLen);
	fs.readSync(fd, ctxBuf, 0, ctxLen, ctxStart);

	// Format as hex with the match portion highlighted in brackets
	const beforeLen = matchOffset - ctxStart;
	const before = ctxBuf.subarray(0, beforeLen).toString('hex').toUpperCase();
	const match = ctxBuf.subarray(beforeLen, beforeLen + matchLen).toString('hex').toUpperCase();
	const after = ctxBuf.subarray(beforeLen + matchLen).toString('hex').toUpperCase();

	const parts: string[] = [];
	if (before) { parts.push(before); }
	parts.push(`[${match}]`);
	if (after) { parts.push(after); }
	return parts.join(' ');
}
