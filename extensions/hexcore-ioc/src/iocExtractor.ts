/*---------------------------------------------------------------------------------------------
 *  HexCore IOC Extractor v1.1.0
 *  Core extraction engine — binary-aware IOC detection with noise reduction
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import type {
	IOCCategory,
	IOCMatch,
	IOCSummary,
	CoreExtractionResult,
	ProgressCallback,
	IOCStorageBackend,
	IOCStorageMode
} from './types';
import { createIOCMatchStore, type IOCMatchStore } from './iocMatchStore';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const CHUNK_SIZE = 64 * 1024;
const CARRYOVER_SIZE = 512;
const DEFAULT_MAX_MATCHES = 10_000;
const CONTEXT_RADIUS = 16;
const DEFAULT_STORAGE_MODE: IOCStorageMode = 'auto';
const DEFAULT_SQLITE_THRESHOLD_MATCHES = 20_000;
const DEFAULT_SQLITE_THRESHOLD_FILE_SIZE_BYTES = 64 * 1024 * 1024;

/**
 * Minimum number of consecutive printable bytes that must surround an IOC
 * match for it to be considered legitimate.  This is the primary defense
 * against false positives caused by random byte sequences in code/data
 * sections that happen to match an IOC regex.
 *
 * Example:  The byte sequence `E8 2E 63 6F 6D` inside a CALL instruction
 * contains `.com`, but the surrounding bytes are non-printable opcode
 * operands — the context check rejects this.
 */
const MIN_PRINTABLE_CONTEXT = 6;

// ---------------------------------------------------------------------------
// IOC Pattern Definitions
// ---------------------------------------------------------------------------

interface IOCPattern {
	category: IOCCategory;
	regex: RegExp;
	/** Optional post-match validator.  Return `null` to reject the match. */
	validate?: (match: string) => string | null;
}

/**
 * Common false-positive domains and TLDs that appear in almost every binary
 * (resource strings, compiler artifacts, version info).
 */
const DOMAIN_NOISE = new Set([
	'this.program', 'the.program', 'runtime.error',
	'floating.point', 'stack.overflow', 'not.enough',
	'out.of', 'read.only', 'write.only',
]);

/**
 * TLDs we actually care about.  Restricting the domain regex to real TLDs
 * cuts noise dramatically compared to matching `\.[a-z]{2,}`.
 */
const VALID_TLDS = new Set([
	'com', 'net', 'org', 'io', 'ru', 'cn', 'de', 'uk', 'fr', 'jp',
	'br', 'in', 'it', 'nl', 'au', 'es', 'kr', 'pl', 'se', 'ch',
	'info', 'biz', 'xyz', 'top', 'site', 'online', 'club', 'tech',
	'pro', 'dev', 'app', 'cloud', 'me', 'tv', 'cc', 'co', 'us',
	'ca', 'eu', 'asia', 'mobi', 'name', 'tel', 'gov', 'edu', 'mil',
	'onion', 'bit', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw',
]);

/** RFC1918 + loopback + link-local + APIPA blocks for private IP filtering. */
function isPrivateIPv4(ip: string): boolean {
	const parts = ip.split('.').map(Number);
	if (parts.length !== 4 || parts.some(p => p < 0 || p > 255)) {
		return false;
	}
	const [a, b] = parts;
	if (a === 10) { return true; }
	if (a === 172 && b >= 16 && b <= 31) { return true; }
	if (a === 192 && b === 168) { return true; }
	if (a === 127) { return true; }
	if (a === 169 && b === 254) { return true; }
	if (a === 0) { return true; }
	if (a === 255) { return true; }
	return false;
}

/** Validate IP octets are in 0-255 range. */
function isValidIPv4(ip: string): string | null {
	const parts = ip.split('.');
	if (parts.length !== 4) { return null; }
	for (const part of parts) {
		const num = parseInt(part, 10);
		if (Number.isNaN(num) || num < 0 || num > 255) { return null; }
		// Reject leading zeros (often version numbers like 1.02.03)
		if (part.length > 1 && part.startsWith('0')) { return null; }
	}
	return ip;
}

function validateDomain(raw: string): string | null {
	const domain = raw.toLowerCase();
	if (DOMAIN_NOISE.has(domain)) { return null; }

	const dot = domain.lastIndexOf('.');
	if (dot < 0) { return null; }

	const tld = domain.substring(dot + 1);
	if (!VALID_TLDS.has(tld)) { return null; }

	// Reject single-char labels (a.com is technically valid but almost always noise)
	const labels = domain.split('.');
	if (labels.some(l => l.length < 2)) { return null; }

	return domain;
}

function validateURL(raw: string): string | null {
	try {
		const url = new URL(raw);
		const host = url.hostname.toLowerCase();
		// Must have a real TLD or be an IP
		const dot = host.lastIndexOf('.');
		if (dot >= 0) {
			const tld = host.substring(dot + 1);
			if (!VALID_TLDS.has(tld) && !/^\d+$/.test(tld)) {
				return null;
			}
		}
		return raw;
	} catch {
		return null;
	}
}

function validateCryptoWallet(raw: string): string | null {
	// Bitcoin: 25-62 chars starting with 1, 3, or bc1
	// Ethereum: 42 chars starting with 0x
	// Monero: 95 chars starting with 4
	if (/^(1|3)[a-km-zA-HJ-NP-Z1-9]{24,33}$/.test(raw)) { return raw; }
	if (/^bc1[a-z0-9]{38,58}$/i.test(raw)) { return raw; }
	if (/^0x[0-9a-fA-F]{40}$/.test(raw)) { return raw; }
	if (/^4[0-9AB][0-9a-zA-Z]{93}$/.test(raw)) { return raw; }
	return null;
}

/**
 * Compiled IOC patterns.  Order matters — more specific patterns should come
 * first to avoid a URL being re-matched as a domain.
 */
const IOC_PATTERNS: IOCPattern[] = [
	// --- Network Indicators ---
	{
		category: 'url',
		regex: /https?:\/\/[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,256}/g,
		validate: validateURL,
	},
	{
		category: 'email',
		regex: /[a-zA-Z0-9._%+\-]{2,64}@[a-zA-Z0-9.\-]{2,253}\.[a-zA-Z]{2,24}/g,
		validate: raw => {
			const atIdx = raw.indexOf('@');
			const domain = raw.substring(atIdx + 1).toLowerCase();
			const tld = domain.substring(domain.lastIndexOf('.') + 1);
			return VALID_TLDS.has(tld) ? raw : null;
		},
	},
	{
		category: 'ipv4',
		regex: /\b(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}\b/g,
		validate: isValidIPv4,
	},
	{
		category: 'ipv6',
		regex: /\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b/g,
	},
	{
		category: 'domain',
		regex: /\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,24}\b/g,
		validate: validateDomain,
	},

	// --- Host Indicators ---
	{
		category: 'registryKey',
		regex: /\b(?:HKEY_[A-Z_]+|HKLM|HKCU|HKCR|HKU|HKCC)\\[A-Za-z0-9\\_./ \-]{4,256}/g,
	},
	{
		category: 'filePath',
		regex: /\b[A-Za-z]:\\(?:[A-Za-z0-9_.\- ]+\\){1,20}[A-Za-z0-9_.\- ]+/g,
	},
	{
		category: 'namedPipe',
		regex: /\\\\\.\\pipe\\[A-Za-z0-9_.\-]{2,128}/g,
	},
	{
		category: 'mutex',
		regex: /\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}/g,
	},

	// --- Cryptographic Hashes ---
	{
		category: 'hash',
		// MD5 (32 hex chars)
		regex: /\b[0-9a-fA-F]{32}\b/g,
		validate: raw => {
			// Reject if it looks like a GUID without braces (8-4-4-4-12 pattern)
			if (/^[0-9a-fA-F]{8}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{4}[0-9a-fA-F]{12}$/.test(raw)) {
				// Only accept if it doesn't contain all zeros or all same char
				if (/^(.)\1+$/.test(raw)) { return null; }
			}
			return raw.toLowerCase();
		},
	},
	{
		category: 'hash',
		// SHA-1 (40 hex chars)
		regex: /\b[0-9a-fA-F]{40}\b/g,
		validate: raw => /^(.)\1+$/.test(raw) ? null : raw.toLowerCase(),
	},
	{
		category: 'hash',
		// SHA-256 (64 hex chars)
		regex: /\b[0-9a-fA-F]{64}\b/g,
		validate: raw => /^(.)\1+$/.test(raw) ? null : raw.toLowerCase(),
	},

	// --- Behavioral Indicators ---
	{
		category: 'userAgent',
		regex: /(?:Mozilla\/|curl\/|wget\/|python-requests\/|Go-http-client\/)[^\r\n\x00]{10,200}/g,
	},

	// --- Financial Indicators ---
	{
		category: 'cryptoWallet',
		regex: /\b(?:(?:1|3)[a-km-zA-HJ-NP-Z1-9]{24,33}|bc1[a-z0-9]{38,58}|0x[0-9a-fA-F]{40}|4[0-9AB][0-9a-zA-Z]{93})\b/g,
		validate: validateCryptoWallet,
	},
];

// ---------------------------------------------------------------------------
// Printable Context Filter
// ---------------------------------------------------------------------------

/**
 * Check that the region surrounding the match at `[matchStart, matchEnd)` in
 * `textBlock` consists of printable characters.
 *
 * This is the **primary noise filter**.  When regex runs over decoded ASCII or
 * UTF-16 text, a coincidental byte sequence like `E8 2E 63 6F 6D` (CALL +
 * `.com`) will match the domain regex, but the bytes before and after are
 * non-printable opcodes.  By requiring MIN_PRINTABLE_CONTEXT printable bytes
 * on each side, we reject these ghost matches.
 */
function hasValidPrintableContext(
	buffer: Buffer,
	regionStart: number,
	matchOffsetInRegion: number,
	matchLength: number,
): boolean {
	const matchAbsoluteStart = regionStart + matchOffsetInRegion;
	const matchAbsoluteEnd = matchAbsoluteStart + matchLength;

	// Check bytes BEFORE the match
	let printableBefore = 0;
	const scanBefore = Math.min(matchAbsoluteStart, MIN_PRINTABLE_CONTEXT);
	for (let i = 1; i <= scanBefore; i++) {
		const pos = matchAbsoluteStart - i;
		if (pos < 0 || pos >= buffer.length) { break; }
		if (isPrintableByte(buffer[pos])) {
			printableBefore++;
		} else {
			break;
		}
	}

	// Check bytes AFTER the match
	let printableAfter = 0;
	const scanAfter = Math.min(buffer.length - matchAbsoluteEnd, MIN_PRINTABLE_CONTEXT);
	for (let i = 0; i < scanAfter; i++) {
		const pos = matchAbsoluteEnd + i;
		if (pos >= buffer.length) { break; }
		if (isPrintableByte(buffer[pos])) {
			printableAfter++;
		} else {
			break;
		}
	}

	return printableBefore >= MIN_PRINTABLE_CONTEXT || printableAfter >= MIN_PRINTABLE_CONTEXT;
}

function isPrintableByte(byte: number): boolean {
	return (byte >= 0x20 && byte <= 0x7E) || byte === 0x09 || byte === 0x0A || byte === 0x0D;
}

// ---------------------------------------------------------------------------
// UTF-16LE Decoder
// ---------------------------------------------------------------------------

/**
 * Extract printable ASCII text from a UTF-16LE encoded region of a buffer.
 *
 * Windows binaries are full of UTF-16LE strings (W.i.n.d.o.w.s.) where each
 * ASCII character is followed by a 0x00 byte.  We detect these runs by
 * looking for alternating patterns of `[printable, 0x00]` and decode them
 * into plain ASCII for IOC regex matching.
 *
 * Returns an array of `{ text, offset }` where offset is the position in the
 * original buffer where the UTF-16LE string starts.
 */
function extractUTF16LEStrings(buffer: Buffer, minLength: number): Array<{ text: string; offset: number }> {
	const results: Array<{ text: string; offset: number }> = [];
	let currentString = '';
	let startOffset = 0;

	for (let i = 0; i < buffer.length - 1; i += 2) {
		const low = buffer[i];
		const high = buffer[i + 1];

		if (high === 0x00 && isPrintableByte(low)) {
			if (currentString.length === 0) {
				startOffset = i;
			}
			currentString += String.fromCharCode(low);
		} else {
			if (currentString.length >= minLength) {
				results.push({ text: currentString, offset: startOffset });
			}
			currentString = '';
		}
	}

	if (currentString.length >= minLength) {
		results.push({ text: currentString, offset: startOffset });
	}

	return results;
}

// ---------------------------------------------------------------------------
// Context Extraction
// ---------------------------------------------------------------------------

/** Extract printable context around a match position for analyst review. */
function extractContext(buffer: Buffer, matchOffset: number, matchLength: number): string {
	const contextStart = Math.max(0, matchOffset - CONTEXT_RADIUS);
	const contextEnd = Math.min(buffer.length, matchOffset + matchLength + CONTEXT_RADIUS);
	const slice = buffer.subarray(contextStart, contextEnd);

	let context = '';
	for (let i = 0; i < slice.length; i++) {
		const byte = slice[i];
		context += isPrintableByte(byte) ? String.fromCharCode(byte) : '.';
	}

	return context;
}

function resolveStorageBackend(
	storageMode: IOCStorageMode | undefined,
	fileSize: number,
	maxMatches: number,
	sqliteThresholdMatches: number,
	sqliteThresholdFileSizeBytes: number,
): IOCStorageBackend {
	const mode = storageMode ?? DEFAULT_STORAGE_MODE;
	if (mode === 'memory' || mode === 'sqlite') {
		return mode;
	}

	if (fileSize >= sqliteThresholdFileSizeBytes || maxMatches >= sqliteThresholdMatches) {
		return 'sqlite';
	}

	return 'memory';
}

// ---------------------------------------------------------------------------
// Core Extraction Engine
// ---------------------------------------------------------------------------

export interface ExtractOptions {
	filePath: string;
	categories: readonly IOCCategory[];
	excludePrivate: boolean;
	maxMatches: number;
	storageMode?: IOCStorageMode;
	sqlitePath?: string;
	sqliteThresholdMatches?: number;
	sqliteThresholdFileSizeMB?: number;
	onProgress?: ProgressCallback;
	isCancelled?: () => boolean;
}

/**
 * Extract IOCs from a binary file using streaming chunk analysis.
 *
 * The extraction performs two passes per chunk:
 * 1. **ASCII pass** — extract printable ASCII runs, match IOC patterns with
 *    printable context validation.
 * 2. **UTF-16LE pass** — decode wide strings and match the same patterns
 *    against the decoded ASCII text.
 *
 * Deduplication can run either in-memory (`Set`) or through SQLite-backed
 * unique constraints, depending on storage mode selection.
 */
export function extractIOCs(options: ExtractOptions): CoreExtractionResult {
	const {
		filePath,
		categories,
		excludePrivate,
		maxMatches = DEFAULT_MAX_MATCHES,
		storageMode,
		sqlitePath,
		sqliteThresholdMatches = DEFAULT_SQLITE_THRESHOLD_MATCHES,
		sqliteThresholdFileSizeMB = DEFAULT_SQLITE_THRESHOLD_FILE_SIZE_BYTES / (1024 * 1024),
		onProgress,
		isCancelled,
	} = options;

	const stats = fs.statSync(filePath);
	const totalSize = stats.size;
	const sqliteThresholdFileSizeBytes = Math.max(1, Math.floor(sqliteThresholdFileSizeMB * 1024 * 1024));
	let storageBackend = resolveStorageBackend(
		storageMode,
		totalSize,
		maxMatches,
		Math.max(1, Math.floor(sqliteThresholdMatches)),
		sqliteThresholdFileSizeBytes,
	);
	let store: IOCMatchStore;
	try {
		store = createIOCMatchStore({
			backend: storageBackend,
			categories,
			sqlitePath,
		});
	} catch (error) {
		const mode = storageMode ?? DEFAULT_STORAGE_MODE;
		if (mode === 'auto' && storageBackend === 'sqlite') {
			storageBackend = 'memory';
			store = createIOCMatchStore({
				backend: storageBackend,
				categories,
			});
		} else {
			throw error;
		}
	}

	// Filter patterns to only the requested categories
	const activePatterns = IOC_PATTERNS.filter(p => categories.includes(p.category));

	let totalUniqueCount = 0;
	let truncated = false;
	let cancelled = false;
	let offset = 0;

	const fd = fs.openSync(filePath, 'r');
	try {
		while (offset < totalSize) {
			if (isCancelled?.()) {
				cancelled = true;
				break;
			}

			if (totalUniqueCount >= maxMatches) {
				truncated = true;
				break;
			}

			// Read chunk with carryover overlap to avoid splitting IOCs at
			// chunk boundaries.  We overlap the last CARRYOVER_SIZE bytes so
			// a URL/path/domain that straddles two chunks is still detected.
			const readOffset = offset === 0 ? 0 : Math.max(0, offset - CARRYOVER_SIZE);
			const bytesToRead = Math.min(CHUNK_SIZE, totalSize - readOffset);
			const buffer = Buffer.alloc(bytesToRead);
			fs.readSync(fd, buffer, 0, bytesToRead, readOffset);

			// ---------------------------------------------------------------
			// Pass 1: ASCII printable regions
			// ---------------------------------------------------------------
			const asciiText = extractASCIIPrintable(buffer);
			for (const region of asciiText) {
				if (totalUniqueCount >= maxMatches) {
					truncated = true;
					break;
				}

				const regionFileOffset = readOffset + region.offset;
				matchPatterns(
					activePatterns,
					region.text,
					regionFileOffset,
					'ASCII',
					buffer,
					region.offset,
					excludePrivate,
					store,
					() => totalUniqueCount,
					() => { totalUniqueCount++; },
					maxMatches,
				);
			}

			// ---------------------------------------------------------------
			// Pass 2: UTF-16LE decoded strings
			// ---------------------------------------------------------------
			const utf16Strings = extractUTF16LEStrings(buffer, 6);
			for (const wideStr of utf16Strings) {
				if (totalUniqueCount >= maxMatches) {
					truncated = true;
					break;
				}

				const regionFileOffset = readOffset + wideStr.offset;
				matchPatterns(
					activePatterns,
					wideStr.text,
					regionFileOffset,
					'UTF-16LE',
					buffer,
					wideStr.offset,
					excludePrivate,
					store,
					() => totalUniqueCount,
					() => { totalUniqueCount++; },
					maxMatches,
				);
			}

			offset = readOffset + bytesToRead;
			onProgress?.({
				processedBytes: Math.min(offset, totalSize),
				totalBytes: totalSize,
				percent: Math.round((Math.min(offset, totalSize) / totalSize) * 100),
				indicatorsFound: totalUniqueCount,
			});
		}

		const snapshot = store.snapshot(categories);
		const summary: IOCSummary = {
			totalIndicators: snapshot.totalUniqueCount,
			uniqueIndicators: snapshot.totalUniqueCount,
			categoryCounts: snapshot.categoryCounts,
			truncated,
		};

		return {
			fileSize: totalSize,
			storageBackend: store.backend,
			indicators: snapshot.indicators,
			summary,
			cancelled,
		};
	} finally {
		fs.closeSync(fd);
		store.dispose();
	}
}

// ---------------------------------------------------------------------------
// Pattern Matching
// ---------------------------------------------------------------------------

function matchPatterns(
	patterns: IOCPattern[],
	text: string,
	fileOffset: number,
	encoding: 'ASCII' | 'UTF-16LE',
	buffer: Buffer,
	regionBufferOffset: number,
	excludePrivate: boolean,
	store: IOCMatchStore,
	getCount: () => number,
	incrementCount: () => void,
	maxMatches: number,
): void {
	for (const pattern of patterns) {
		if (getCount() >= maxMatches) { return; }

		// Reset lastIndex for global regex reuse across calls
		pattern.regex.lastIndex = 0;

		let match: RegExpExecArray | null;
		while ((match = pattern.regex.exec(text)) !== null) {
			if (getCount() >= maxMatches) { return; }

			let value = match[0];
			// Regex indices are character-based on decoded text. For UTF-16LE
			// regions we must convert to byte offsets in the original buffer.
			const matchIndexInSource = encoding === 'UTF-16LE' ? match.index * 2 : match.index;
			const matchLengthInSource = encoding === 'UTF-16LE' ? match[0].length * 2 : match[0].length;

			// Run validator if present
			if (pattern.validate) {
				const validated = pattern.validate(value);
				if (validated === null) { continue; }
				value = validated;
			}

			// Private IP filter
			if (excludePrivate && pattern.category === 'ipv4' && isPrivateIPv4(value)) {
				continue;
			}

			// Printable context validation for ASCII matches
			if (encoding === 'ASCII') {
				const matchInBuffer = regionBufferOffset + matchIndexInSource;
				if (!hasValidPrintableContext(buffer, 0, matchInBuffer, matchLengthInSource)) {
					continue;
				}
			}

			// Extract context from buffer
			const matchBufferPos = regionBufferOffset + matchIndexInSource;
			const context = extractContext(buffer, matchBufferPos, matchLengthInSource);

			const added = store.addMatch({
				category: pattern.category,
				value,
				offset: fileOffset + matchIndexInSource,
				encoding,
				context,
			});
			if (!added) {
				continue;
			}

			incrementCount();
		}
	}
}

// ---------------------------------------------------------------------------
// ASCII Printable Region Extraction
// ---------------------------------------------------------------------------

interface PrintableRegion {
	text: string;
	offset: number;
}

/**
 * Scan a buffer and pull out contiguous runs of printable ASCII characters.
 * Only regions of 6+ characters are returned  — shorter sequences are almost
 * always random byte noise and cannot contain a meaningful IOC.
 */
function extractASCIIPrintable(buffer: Buffer): PrintableRegion[] {
	const regions: PrintableRegion[] = [];
	let currentText = '';
	let startOffset = 0;

	for (let i = 0; i < buffer.length; i++) {
		if (isPrintableByte(buffer[i])) {
			if (currentText.length === 0) {
				startOffset = i;
			}
			currentText += String.fromCharCode(buffer[i]);
		} else {
			if (currentText.length >= MIN_PRINTABLE_CONTEXT) {
				regions.push({ text: currentText, offset: startOffset });
			}
			currentText = '';
		}
	}

	if (currentText.length >= MIN_PRINTABLE_CONTEXT) {
		regions.push({ text: currentText, offset: startOffset });
	}

	return regions;
}
