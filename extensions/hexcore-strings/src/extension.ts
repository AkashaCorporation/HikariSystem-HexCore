/*---------------------------------------------------------------------------------------------
 *  HexCore Strings Extractor v1.3.0
 *  Extract ASCII and Unicode strings from binary files
 *  PE section-aware prioritization (FEAT-STRINGS-001) + streaming fallback
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { xorBruteForce, type XorResult } from './xorScanner';
import { detectStackStrings, detectStackBlobs, type StackString, type StackBlob } from './stackStringDetector';
import { multiByteXorScan, type MultiByteXorResult } from './multiByteXor';
import { knownPlaintextScan } from './knownPlaintextAttack';
import { compositeCipherScan } from './compositeCipher';
import { wideStringXorScan } from './wideStringXor';
import { positionalXorScan } from './positionalXor';
import { rollingXorExtScan } from './rollingXorExt';
import { layeredXorScan } from './layeredXor';
import { parsePESections, getSectionForOffset, type PESectionMap, type PESectionInfo } from './peSectionParser';
import { scoreString } from './scoringEngine';
import type { MultiByteXorOptions } from './multiByteXor';

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface StringsCommandOptions {
	file?: string;
	minLength?: number;
	maxStrings?: number;
	output?: CommandOutputOptions;
	quiet?: boolean;
	/** Enable XOR brute-force and stack-string deobfuscation (extractAdvanced). */
	deobfuscate?: boolean;
}

interface ExtractedString {
	offset: number;
	value: string;
	encoding: 'ASCII' | 'UTF-16LE';
	category?: string;
	/** PE section this string was found in (e.g., '.rdata', '.text'). */
	section?: string;
}

interface StringsSummary {
	asciiCount: number;
	unicodeCount: number;
	categories: Record<string, number>;
}

interface StringsExtractionResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	minLength: number;
	totalStrings: number;
	truncated: boolean;
	summary: StringsSummary;
	strings: ExtractedString[];
	/** Deobfuscated strings (XOR/Stack/etc). Populated by extractAdvanced only. */
	deobfuscated?: DeobfuscatedString[];
	/** Count of deobfuscated strings per method (quick summary for pipelines). */
	deobfuscationSummary?: Record<string, number>;
	reportMarkdown: string;
}

interface ChunkResult {
	strings: ExtractedString[];
	carryover: string;
	carryoverOffset: number;
}

interface UnicodeChunkResult {
	strings: ExtractedString[];
	carryover: Buffer;
	carryoverOffset: number;
}

interface DeobfuscatedString {
	value: string;
	offset: number;
	method: 'XOR' | 'XOR-multi' | 'XOR-rolling' | 'XOR-increment' | 'Stack'
	| 'XOR-wide' | 'XOR-layered' | 'XOR-counter'
	| 'XOR-block-rotate' | 'XOR-rolling-ext'
	| 'XOR-known-plaintext'
	| 'ADD' | 'SUB' | 'ROT';
	/** XOR key if method is XOR (single-byte). */
	xorKey?: number;
	/** Full key in hex for multi-byte XOR methods. */
	keyHex?: string;
	/** Key size in bytes for multi-byte XOR methods. */
	keySize?: number;
	confidence?: number;
	instructionCount?: number;
	// --- New optional fields ---
	section?: string;
	layerKeys?: string[];
	knownPattern?: string;
	derivationParams?: { type: string; base?: number; step?: number; blockSize?: number };
	windowSize?: number;
	rotValue?: number;
	originalByteLength?: number;
}

interface CoreExtractionResult {
	fileSize: number;
	strings: ExtractedString[];
	truncated: boolean;
	cancelled: boolean;
	deobfuscated?: DeobfuscatedString[];
}

const CHUNK_SIZE = 64 * 1024;
const DEFAULT_MIN_LENGTH = 6;
const DEFAULT_MAX_STRINGS = 50000;

// ---------------------------------------------------------------------------
// PE Section Prioritization — FEAT-STRINGS-001
// ---------------------------------------------------------------------------

/**
 * Sections are processed in priority order. Sections not in this list
 * are placed after the known ones with equal (lowest) priority.
 * Budget fractions must sum to 1.0.
 */
interface SectionBudget {
	/** Glob-style name match (case-insensitive startsWith). */
	namePrefix: string;
	/** Priority — lower number = processed first. */
	priority: number;
	/** Fraction of maxStrings allocated to this section. */
	budgetFraction: number;
}

const SECTION_BUDGETS: SectionBudget[] = [
	{ namePrefix: '.rdata',  priority: 1, budgetFraction: 0.60 },
	{ namePrefix: '.data',   priority: 2, budgetFraction: 0.20 },
	{ namePrefix: '.rsrc',   priority: 3, budgetFraction: 0.10 },
	{ namePrefix: '.text',   priority: 4, budgetFraction: 0.10 },
];

/** Fallback budget fraction for sections not in the priority list. */
const UNKNOWN_SECTION_PRIORITY = 5;

/**
 * Given actual PE sections, return them ordered by priority with per-section
 * result budgets. Sections not in SECTION_BUDGETS share leftover budget equally.
 */
function buildSectionPlan(
	sections: PESectionInfo[],
	maxStrings: number,
): Array<{ section: PESectionInfo; budget: number; priority: number }> {
	const plan: Array<{ section: PESectionInfo; budget: number; priority: number }> = [];

	// Classify each section
	const known: Array<{ section: PESectionInfo; entry: SectionBudget }> = [];
	const unknown: PESectionInfo[] = [];

	for (const sec of sections) {
		const nameLower = sec.name.toLowerCase();
		const match = SECTION_BUDGETS.find(b => nameLower.startsWith(b.namePrefix));
		if (match) {
			known.push({ section: sec, entry: match });
		} else {
			unknown.push(sec);
		}
	}

	// Assign budgets to known sections
	let totalKnownFraction = 0;
	for (const k of known) {
		totalKnownFraction += k.entry.budgetFraction;
	}

	// If there are unknown sections, redistribute: known sections get their proportional
	// share of totalKnownFraction, unknown sections share the rest equally.
	if (unknown.length > 0 && totalKnownFraction < 1.0) {
		const unknownFraction = (1.0 - totalKnownFraction) / unknown.length;
		for (const k of known) {
			plan.push({
				section: k.section,
				budget: Math.max(10, Math.floor(maxStrings * k.entry.budgetFraction)),
				priority: k.entry.priority,
			});
		}
		for (const sec of unknown) {
			plan.push({
				section: sec,
				budget: Math.max(10, Math.floor(maxStrings * unknownFraction)),
				priority: UNKNOWN_SECTION_PRIORITY,
			});
		}
	} else {
		// All sections are known (or unknown list is empty) — use budgets directly
		// If totalKnownFraction < 1.0 and no unknowns, scale up proportionally
		const scale = totalKnownFraction > 0 ? 1.0 / totalKnownFraction : 1.0;
		for (const k of known) {
			plan.push({
				section: k.section,
				budget: Math.max(10, Math.floor(maxStrings * k.entry.budgetFraction * scale)),
				priority: k.entry.priority,
			});
		}
	}

	// Sort by priority (ascending)
	plan.sort((a, b) => a.priority - b.priority);
	return plan;
}

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Strings Extractor v1.3.0 activated');

	// Original command — backward compatible
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.strings.extract', async (arg?: vscode.Uri | StringsCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return;
			}

			const minLength = await resolveMinLength(options);
			if (minLength === undefined) {
				return;
			}

			try {
				return await extractStrings(uri, minLength, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`Failed to extract strings: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);

	// Advanced command — includes XOR brute-force and stack-string detection
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.strings.extractAdvanced', async (arg?: vscode.Uri | StringsCommandOptions) => {
			const options = normalizeOptions(arg);
			options.deobfuscate = true;
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return;
			}

			const minLength = await resolveMinLength(options);
			if (minLength === undefined) {
				return;
			}

			try {
				return await extractStrings(uri, minLength, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`Failed to extract strings: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);
}

function normalizeOptions(arg?: vscode.Uri | StringsCommandOptions): StringsCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | StringsCommandOptions | undefined,
	options: StringsCommandOptions
): Promise<vscode.Uri | undefined> {
	if (arg instanceof vscode.Uri) {
		return arg;
	}

	if (typeof options.file === 'string' && options.file.length > 0) {
		return vscode.Uri.file(options.file);
	}

	const activeUri = getActiveFileUri();
	if (activeUri) {
		return activeUri;
	}

	if (options.quiet) {
		return undefined;
	}

	const files = await vscode.window.showOpenDialog({
		canSelectMany: false,
		canSelectFiles: true,
		title: 'Select file to extract strings from'
	});
	return files?.[0];
}

function getActiveFileUri(): vscode.Uri | undefined {
	const active = vscode.window.activeTextEditor?.document.uri;
	if (!active || active.scheme !== 'file') {
		return undefined;
	}
	return active;
}

async function resolveMinLength(options: StringsCommandOptions): Promise<number | undefined> {
	if (typeof options.minLength === 'number') {
		return clampMinLength(options.minLength);
	}

	if (options.quiet) {
		return DEFAULT_MIN_LENGTH;
	}

	const minLengthInput = await vscode.window.showInputBox({
		prompt: 'Minimum string length',
		value: String(DEFAULT_MIN_LENGTH),
		validateInput: value => {
			const num = parseInt(value, 10);
			if (Number.isNaN(num) || num < 1 || num > 100) {
				return 'Please enter a number between 1 and 100';
			}
			return null;
		}
	});

	if (!minLengthInput) {
		return undefined;
	}

	return clampMinLength(parseInt(minLengthInput, 10));
}

function clampMinLength(value: number): number {
	if (Number.isNaN(value)) {
		return DEFAULT_MIN_LENGTH;
	}
	return Math.max(1, Math.min(100, Math.floor(value)));
}

async function extractStrings(uri: vscode.Uri, minLength: number, options: StringsCommandOptions): Promise<StringsExtractionResult | undefined> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);
	const maxStrings = normalizeMaxStrings(options.maxStrings);

	const runExtraction = (
		onProgress?: (offset: number, totalSize: number, foundStrings: number) => void,
		isCancelled?: () => boolean
	): CoreExtractionResult => extractStringsCore(filePath, minLength, maxStrings, onProgress, isCancelled);

	const coreResult = options.quiet
		? runExtraction()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: `Extracting strings from ${fileName}...`,
				cancellable: true
			},
			async (progress, token) => runExtraction(
				(offset, totalSize, foundStrings) => {
					const pct = totalSize > 0 ? Math.round((offset / totalSize) * 100) : 100;
					progress.report({ message: `${pct}% - ${foundStrings} strings found` });
				},
				() => token.isCancellationRequested
			)
		);

	if (coreResult.cancelled) {
		if (!options.quiet) {
			vscode.window.showInformationMessage('String extraction cancelled.');
		}
		return undefined;
	}

	// Run deobfuscation if requested
	if (options.deobfuscate && !coreResult.cancelled) {
		coreResult.deobfuscated = runDeobfuscation(filePath, minLength, options);
	}

	const summary = summarizeStrings(coreResult.strings);
	let report = generateStringsReport(fileName, filePath, coreResult.fileSize, coreResult.strings, minLength, coreResult.truncated);

	// Append deobfuscation section if we found anything
	if (coreResult.deobfuscated && coreResult.deobfuscated.length > 0) {
		report += generateDeobfuscationReport(coreResult.deobfuscated);
	}

	const result: StringsExtractionResult = {
		fileName,
		filePath,
		fileSize: coreResult.fileSize,
		minLength,
		totalStrings: coreResult.strings.length,
		truncated: coreResult.truncated,
		summary,
		strings: coreResult.strings,
		reportMarkdown: report
	};

	// v3.8.0-nightly: surface deobfuscated strings in the JSON output so
	// headless pipelines (and graders/scorecards) can diff them across
	// runs without having to parse the Markdown report.
	if (coreResult.deobfuscated && coreResult.deobfuscated.length > 0) {
		result.deobfuscated = coreResult.deobfuscated;
		const summaryByMethod: Record<string, number> = {};
		for (const d of coreResult.deobfuscated) {
			summaryByMethod[d.method] = (summaryByMethod[d.method] ?? 0) + 1;
		}
		result.deobfuscationSummary = summaryByMethod;
	}

	if (options.output) {
		writeOutput(result, options.output);
	}

	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: report,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}

	return result;
}

function normalizeMaxStrings(value?: number): number {
	if (value === undefined || Number.isNaN(value)) {
		return DEFAULT_MAX_STRINGS;
	}
	return Math.max(100, Math.floor(value));
}

function extractStringsCore(
	filePath: string,
	minLength: number,
	maxStrings: number,
	onProgress?: (offset: number, totalSize: number, foundStrings: number) => void,
	isCancelled?: () => boolean
): CoreExtractionResult {
	const stats = fs.statSync(filePath);
	const totalSize = stats.size;

	// --- PE pre-scan: attempt to parse section headers ---
	let peSections: PESectionMap | null = null;
	const fd = fs.openSync(filePath, 'r');
	try {
		const preScanSize = Math.min(PE_PRESCAN_SIZE, totalSize);
		const preScanBuf = Buffer.alloc(preScanSize);
		fs.readSync(fd, preScanBuf, 0, preScanSize, 0);
		peSections = parsePESections(preScanBuf);
	} catch {
		// Not a PE or malformed — fall through to linear scan
	}

	// --- Decide extraction strategy ---
	if (peSections && peSections.isPE && peSections.sections.length > 0) {
		const result = extractStringsSectionAware(fd, totalSize, peSections, minLength, maxStrings, onProgress, isCancelled);
		fs.closeSync(fd);
		return result;
	}

	// --- Fallback: linear scan (non-PE files, ELF, raw buffers) ---
	try {
		return extractStringsLinear(fd, totalSize, null, minLength, maxStrings, onProgress, isCancelled);
	} finally {
		fs.closeSync(fd);
	}
}

/**
 * Extract strings from a single byte range within a file.
 * Handles chunked I/O, ASCII + Unicode extraction, and section annotation.
 */
function extractStringsFromRange(
	fd: number,
	rangeStart: number,
	rangeEnd: number,
	sectionName: string | undefined,
	minLength: number,
	budget: number,
	onProgress: ((offset: number, totalSize: number, foundStrings: number) => void) | undefined,
	totalSize: number,
	globalCount: number,
	isCancelled: (() => boolean) | undefined,
): { strings: ExtractedString[]; truncated: boolean; cancelled: boolean } {
	const strings: ExtractedString[] = [];
	let asciiCarryover = '';
	let asciiCarryoverOffset = rangeStart;
	let unicodeCarryover = Buffer.alloc(0);
	let unicodeCarryoverOffset = rangeStart;
	let offset = rangeStart;
	let truncated = false;
	let cancelled = false;

	while (offset < rangeEnd) {
		if (isCancelled?.()) {
			cancelled = true;
			break;
		}

		const bytesToRead = Math.min(CHUNK_SIZE, rangeEnd - offset);
		const buffer = Buffer.alloc(bytesToRead);
		fs.readSync(fd, buffer, 0, bytesToRead, offset);

		const asciiResult = extractASCIIFromChunk(buffer, offset, minLength, asciiCarryover, asciiCarryoverOffset);
		for (const s of asciiResult.strings) {
			if (sectionName) { s.section = sectionName; }
			strings.push(s);
		}
		asciiCarryover = asciiResult.carryover;
		asciiCarryoverOffset = asciiResult.carryoverOffset;

		const unicodeResult = extractUnicodeFromChunk(buffer, offset, minLength, unicodeCarryover, unicodeCarryoverOffset);
		for (const s of unicodeResult.strings) {
			if (sectionName) { s.section = sectionName; }
			strings.push(s);
		}
		unicodeCarryover = Buffer.from(unicodeResult.carryover);
		unicodeCarryoverOffset = unicodeResult.carryoverOffset;

		offset += bytesToRead;
		onProgress?.(offset, totalSize, globalCount + strings.length);

		if (strings.length >= budget) {
			truncated = true;
			break;
		}
	}

	// Flush ASCII carryover
	if (asciiCarryover.length >= minLength) {
		const trimmed = asciiCarryover.trim();
		if (trimmed.length >= minLength) {
			const entry: ExtractedString = {
				offset: asciiCarryoverOffset,
				value: trimmed,
				encoding: 'ASCII',
			};
			if (sectionName) { entry.section = sectionName; }
			strings.push(entry);
		}
	}

	return { strings, truncated, cancelled };
}

/**
 * Section-aware extraction for PE files (FEAT-STRINGS-001).
 * Processes sections in priority order (.rdata > .data > .rsrc > .text)
 * with per-section result budgets to prevent .text noise from drowning
 * out high-value strings in .rdata.
 */
function extractStringsSectionAware(
	fd: number,
	totalSize: number,
	peSections: PESectionMap,
	minLength: number,
	maxStrings: number,
	onProgress: ((offset: number, totalSize: number, foundStrings: number) => void) | undefined,
	isCancelled: (() => boolean) | undefined,
): CoreExtractionResult {
	const plan = buildSectionPlan(peSections.sections, maxStrings);
	const allStrings: ExtractedString[] = [];
	let truncated = false;
	let cancelled = false;

	for (const entry of plan) {
		if (cancelled) { break; }
		if (allStrings.length >= maxStrings) {
			truncated = true;
			break;
		}

		const sec = entry.section;
		// Skip zero-size sections
		if (sec.size <= 0) { continue; }

		const rangeStart = sec.offset;
		const rangeEnd = Math.min(sec.offset + sec.size, totalSize);
		if (rangeStart >= totalSize || rangeStart >= rangeEnd) { continue; }

		// Remaining global budget may be less than this section's allocation
		const remainingGlobal = maxStrings - allStrings.length;
		const sectionBudget = Math.min(entry.budget, remainingGlobal);

		const result = extractStringsFromRange(
			fd, rangeStart, rangeEnd, sec.name,
			minLength, sectionBudget,
			onProgress, totalSize, allStrings.length,
			isCancelled,
		);

		allStrings.push(...result.strings);
		if (result.cancelled) { cancelled = true; }
		if (result.truncated) {
			// Section-level truncation is expected — continue to next section
		}
	}

	if (allStrings.length >= maxStrings) {
		truncated = true;
	}

	categorizeStrings(allStrings);
	allStrings.sort((a, b) => a.offset - b.offset);
	const uniqueStrings = deduplicateStrings(allStrings);

	return {
		fileSize: totalSize,
		strings: uniqueStrings,
		truncated,
		cancelled,
	};
}

/**
 * Linear (non-section-aware) extraction — used for non-PE files.
 * This is the original sequential scan logic, preserved for ELF / raw buffers.
 */
function extractStringsLinear(
	fd: number,
	totalSize: number,
	_peSections: PESectionMap | null,
	minLength: number,
	maxStrings: number,
	onProgress: ((offset: number, totalSize: number, foundStrings: number) => void) | undefined,
	isCancelled: (() => boolean) | undefined,
): CoreExtractionResult {
	const allStrings: ExtractedString[] = [];
	let asciiCarryover = '';
	let asciiCarryoverOffset = 0;
	let unicodeCarryover = Buffer.alloc(0);
	let unicodeCarryoverOffset = 0;
	let offset = 0;
	let truncated = false;
	let cancelled = false;

	while (offset < totalSize) {
		if (isCancelled?.()) {
			cancelled = true;
			break;
		}

		const bytesToRead = Math.min(CHUNK_SIZE, totalSize - offset);
		const buffer = Buffer.alloc(bytesToRead);
		fs.readSync(fd, buffer, 0, bytesToRead, offset);

		const asciiResult = extractASCIIFromChunk(buffer, offset, minLength, asciiCarryover, asciiCarryoverOffset);
		allStrings.push(...asciiResult.strings);
		asciiCarryover = asciiResult.carryover;
		asciiCarryoverOffset = asciiResult.carryoverOffset;

		const unicodeResult = extractUnicodeFromChunk(buffer, offset, minLength, unicodeCarryover, unicodeCarryoverOffset);
		allStrings.push(...unicodeResult.strings);
		unicodeCarryover = Buffer.from(unicodeResult.carryover);
		unicodeCarryoverOffset = unicodeResult.carryoverOffset;

		offset += bytesToRead;
		onProgress?.(offset, totalSize, allStrings.length);

		if (allStrings.length > maxStrings) {
			truncated = true;
			break;
		}
	}

	if (asciiCarryover.length >= minLength) {
		allStrings.push({
			offset: asciiCarryoverOffset,
			value: asciiCarryover.trim(),
			encoding: 'ASCII'
		});
	}

	categorizeStrings(allStrings);
	allStrings.sort((a, b) => a.offset - b.offset);
	const uniqueStrings = deduplicateStrings(allStrings);

	return {
		fileSize: totalSize,
		strings: uniqueStrings,
		truncated,
		cancelled
	};
}

function writeOutput(result: StringsExtractionResult, output: CommandOutputOptions): void {
	const outputFormat = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (outputFormat === 'md') {
		fs.writeFileSync(output.path, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				fileName: result.fileName,
				filePath: result.filePath,
				fileSize: result.fileSize,
				minLength: result.minLength,
				totalStrings: result.totalStrings,
				truncated: result.truncated,
				summary: result.summary,
				strings: result.strings,
				// v3.8.0-nightly: include deobfuscation results (XOR-multi,
				// Stack, etc.) in the JSON so headless pipelines can diff
				// decoded strings across runs. Fields are only present when
				// extractAdvanced produced at least one deob hit.
				deobfuscated: result.deobfuscated,
				deobfuscationSummary: result.deobfuscationSummary,
				generatedAt: new Date().toISOString()
			},
			null,
			2
		),
		'utf8'
	);
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

function extractASCIIFromChunk(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	carryover: string,
	carryoverOffset: number
): ChunkResult {
	const strings: ExtractedString[] = [];
	let currentString = carryover;
	let startOffset = carryover.length > 0 ? carryoverOffset : baseOffset;

	for (let i = 0; i < buffer.length; i++) {
		const byte = buffer[i];

		if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
			if (currentString.length === 0) {
				startOffset = baseOffset + i;
			}
			currentString += String.fromCharCode(byte);
		} else {
			if (currentString.length >= minLength) {
				const trimmed = currentString.trim();
				if (trimmed.length >= minLength) {
					strings.push({
						offset: startOffset,
						value: trimmed,
						encoding: 'ASCII'
					});
				}
			}
			currentString = '';
		}
	}

	return {
		strings,
		carryover: currentString,
		carryoverOffset: startOffset
	};
}

function extractUnicodeFromChunk(
	buffer: Buffer,
	baseOffset: number,
	minLength: number,
	carryover: Buffer,
	carryoverOffset: number
): UnicodeChunkResult {
	const strings: ExtractedString[] = [];

	const combined = carryover.length > 0 ? Buffer.concat([carryover, buffer]) : buffer;
	const combinedOffset = carryover.length > 0 ? carryoverOffset : baseOffset;

	let currentString = '';
	let startOffset = combinedOffset;

	for (let i = 0; i < combined.length - 1; i += 2) {
		const low = combined[i];
		const high = combined[i + 1];

		if (high === 0 && ((low >= 32 && low <= 126) || low === 9 || low === 10 || low === 13)) {
			if (currentString.length === 0) {
				startOffset = combinedOffset + i;
			}
			currentString += String.fromCharCode(low);
		} else {
			if (currentString.length >= minLength) {
				const trimmed = currentString.trim();
				if (trimmed.length >= minLength) {
					strings.push({
						offset: startOffset,
						value: trimmed,
						encoding: 'UTF-16LE'
					});
				}
			}
			currentString = '';
		}
	}

	const newCarryover = combined.length % 2 === 1 ? Buffer.from(combined.subarray(-1)) : Buffer.alloc(0);

	return {
		strings,
		carryover: newCarryover,
		carryoverOffset: baseOffset + buffer.length - 1
	};
}

function deduplicateStrings(strings: ExtractedString[]): ExtractedString[] {
	const seen = new Set<string>();
	return strings.filter(stringValue => {
		const key = `${stringValue.offset}-${stringValue.value.substring(0, 50)}`;
		if (seen.has(key)) {
			return false;
		}
		seen.add(key);
		return true;
	});
}

function categorizeStrings(strings: ExtractedString[]): void {
	const patterns: Array<{ category: string; regex: RegExp }> = [
		{ category: 'URL', regex: /^https?:\/\//i },
		{ category: 'IP Address', regex: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/ },
		{ category: 'Email', regex: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/ },
		{ category: 'File Path', regex: /^[a-zA-Z]:\\|^\\\\|^\/[a-zA-Z]/i },
		{ category: 'Registry Key', regex: /^HKEY_|^HKLM\\|^HKCU\\/i },
		{ category: 'DLL', regex: /\.dll$/i },
		{ category: 'Executable', regex: /\.(exe|com|bat|cmd|ps1|vbs|js)$/i },
		{ category: 'Sensitive', regex: /password|passwd|secret|token|api[_-]?key|credential/i },
		{ category: 'Function', regex: /^(Get|Set|Create|Delete|Read|Write|Open|Close|Load|Unload)[A-Z]/i },
		{ category: 'WinAPI', regex: /^(Nt|Zw|Rtl|Ldr|Crypt|Virtual|Heap|Process|Thread|Reg|File)/i },
	];

	for (const extracted of strings) {
		for (const pattern of patterns) {
			if (pattern.regex.test(extracted.value)) {
				extracted.category = pattern.category;
				break;
			}
		}
	}
}

function summarizeStrings(strings: ExtractedString[]): StringsSummary {
	const categories: Record<string, number> = {};
	let asciiCount = 0;
	let unicodeCount = 0;

	for (const extracted of strings) {
		if (extracted.encoding === 'ASCII') {
			asciiCount++;
		} else {
			unicodeCount++;
		}

		const category = extracted.category ?? 'General';
		categories[category] = (categories[category] ?? 0) + 1;
	}

	return {
		asciiCount,
		unicodeCount,
		categories
	};
}

function generateStringsReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	strings: ExtractedString[],
	minLength: number,
	truncated: boolean
): string {
	const asciiCount = strings.filter(stringValue => stringValue.encoding === 'ASCII').length;
	const unicodeCount = strings.filter(stringValue => stringValue.encoding === 'UTF-16LE').length;
	const hasSections = strings.some(s => s.section !== undefined && s.section !== '');

	const categorized = new Map<string, ExtractedString[]>();
	for (const stringValue of strings) {
		const category = stringValue.category || 'General';
		if (!categorized.has(category)) {
			categorized.set(category, []);
		}
		categorized.get(category)!.push(stringValue);
	}

	// Build section breakdown if section data is available
	let sectionBreakdown = '';
	if (hasSections) {
		const sectionCounts = new Map<string, number>();
		for (const s of strings) {
			const sec = s.section ?? '(unknown)';
			sectionCounts.set(sec, (sectionCounts.get(sec) ?? 0) + 1);
		}
		sectionBreakdown = '\n### Strings by PE Section\n\n| Section | Count |\n|---------|-------|\n';
		// Sort sections by count descending
		const sorted = [...sectionCounts.entries()].sort((a, b) => b[1] - a[1]);
		for (const [sec, count] of sorted) {
			sectionBreakdown += `| **${sec}** | ${count} |\n`;
		}
		sectionBreakdown += '\n';
	}

	let report = `# HexCore Strings Extractor Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${fileName} |
| **File Path** | ${filePath} |
| **File Size** | ${formatBytes(fileSize)} |
| **Min Length** | ${minLength} characters |
| **Processing** | ${hasSections ? 'Section-aware (PE prioritized)' : 'Streaming (memory efficient)'} |
| **Truncated** | ${truncated ? 'Yes (max strings limit reached)' : 'No'} |

---

## Summary

| Type | Count |
|------|-------|
| **ASCII Strings** | ${asciiCount} |
| **Unicode Strings** | ${unicodeCount} |
| **Total** | ${strings.length} |
${sectionBreakdown}
---

## Interesting Strings by Category

`;

	const priorityCategories = ['URL', 'IP Address', 'Email', 'Registry Key', 'Sensitive', 'File Path', 'DLL', 'Executable', 'WinAPI', 'Function'];

	for (const category of priorityCategories) {
		const items = categorized.get(category);
		if (items && items.length > 0) {
			report += `### ${category} (${items.length})\n\n`;
			if (hasSections) {
				report += '| Offset | Encoding | Section | Value |\n';
				report += '|--------|----------|---------|-------|\n';
			} else {
				report += '| Offset | Encoding | Value |\n';
				report += '|--------|----------|-------|\n';
			}
			for (const item of items.slice(0, 50)) {
				const escapedValue = item.value.replace(/\|/g, '\\|').replace(/\n/g, ' ').substring(0, 80);
				const offsetHex = `0x${item.offset.toString(16).toUpperCase().padStart(8, '0')}`;
				if (hasSections) {
					report += `| ${offsetHex} | ${item.encoding} | ${item.section ?? '—'} | \`${escapedValue}\` |\n`;
				} else {
					report += `| ${offsetHex} | ${item.encoding} | \`${escapedValue}\` |\n`;
				}
			}
			if (items.length > 50) {
				report += hasSections
					? `| ... | ... | ... | *${items.length - 50} more* |\n`
					: `| ... | ... | *${items.length - 50} more* |\n`;
			}
			report += '\n';
		}
	}

	const generalStrings = categorized.get('General') || [];
	if (generalStrings.length > 0) {
		report += `### General Strings (showing first 100 of ${generalStrings.length})\n\n`;
		if (hasSections) {
			report += '| Offset | Encoding | Section | Value |\n';
			report += '|--------|----------|---------|-------|\n';
		} else {
			report += '| Offset | Encoding | Value |\n';
			report += '|--------|----------|-------|\n';
		}
		for (const item of generalStrings.slice(0, 100)) {
			const escapedValue = item.value.replace(/\|/g, '\\|').replace(/\n/g, ' ').substring(0, 80);
			const truncatedValue = item.value.length > 80 ? '...' : '';
			const offsetHex = `0x${item.offset.toString(16).toUpperCase().padStart(8, '0')}`;
			if (hasSections) {
				report += `| ${offsetHex} | ${item.encoding} | ${item.section ?? '—'} | \`${escapedValue}${truncatedValue}\` |\n`;
			} else {
				report += `| ${offsetHex} | ${item.encoding} | \`${escapedValue}${truncatedValue}\` |\n`;
			}
		}
		report += '\n';
	}

	report += `---
*Generated by HexCore Strings Extractor v1.3.0 (${hasSections ? 'Section-Aware' : 'Streaming'})*
`;

	return report;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) {
		return '0 B';
	}
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

export function deactivate() { }

// ---------------------------------------------------------------------------
// Deobfuscation Engine (Advanced Strings v1.2.0)
// ---------------------------------------------------------------------------

const DEOB_CHUNK_SIZE = 64 * 1024;

/** Maps multiByteXor method names to DeobfuscatedString method names. */
const MULTI_XOR_METHOD_MAP: Record<string, DeobfuscatedString['method']> = {
	'multi-byte': 'XOR-multi',
	'rolling': 'XOR-rolling',
	'increment': 'XOR-increment',
	'XOR-wide': 'XOR-wide',
	'XOR-layered': 'XOR-layered',
	'XOR-counter': 'XOR-counter',
	'XOR-block-rotate': 'XOR-block-rotate',
	'XOR-rolling-ext': 'XOR-rolling-ext',
	'XOR-known-plaintext': 'XOR-known-plaintext',
	'ADD': 'ADD',
	'SUB': 'SUB',
	'ROT': 'ROT',
};

/** Maximum deobfuscated results from the orchestrator. */
const MAX_DEOB_RESULTS = 5000;

/** Size of the PE header pre-scan buffer. */
const PE_PRESCAN_SIZE = 2048;

/**
 * Convert a MultiByteXorResult (or subtype) to a DeobfuscatedString,
 * optionally annotating with PE section info.
 */
/**
 * Extract printable-ASCII byte runs of length [minLen..maxLen] from the
 * buffer and return them as candidate XOR keys. These are used for a
 * known-key trial against obfuscated blobs too short for frequency
 * analysis to succeed.
 *
 * Restricted to the length window since single-byte keys are already
 * covered by `xorBruteForce` and keys longer than 16 bytes are rare.
 */
function extractPrintableRunsAsKeys(buffer: Buffer, minLen: number, maxLen: number): Buffer[] {
	const candidates = new Map<string, Buffer>();
	let runStart = -1;
	for (let i = 0; i < buffer.length; i++) {
		const b = buffer[i];
		const printable = (b >= 0x20 && b <= 0x7E) || b === 0x09;
		if (printable) {
			if (runStart === -1) { runStart = i; }
		} else {
			if (runStart !== -1) {
				addRunCandidates(buffer, runStart, i, minLen, maxLen, candidates);
				runStart = -1;
			}
		}
	}
	if (runStart !== -1) {
		addRunCandidates(buffer, runStart, buffer.length, minLen, maxLen, candidates);
	}
	return [...candidates.values()];
}

function addRunCandidates(
	buffer: Buffer,
	start: number,
	end: number,
	minLen: number,
	maxLen: number,
	out: Map<string, Buffer>
): void {
	const runLen = end - start;
	if (runLen < minLen) { return; }
	// Slide a window of each length [minLen..maxLen] across the run so we
	// catch sub-words like "Ashaka" inside "AshakaShadow". Cap total window
	// positions to keep the trial set bounded.
	const maxWindows = 256;
	let windows = 0;
	for (let len = minLen; len <= maxLen && len <= runLen; len++) {
		for (let s = start; s + len <= end; s++) {
			if (windows++ >= maxWindows) { return; }
			const slice = buffer.subarray(s, s + len);
			const key = slice.toString('binary');
			if (!out.has(key)) { out.set(key, Buffer.from(slice)); }
		}
	}
}

interface KnownKeyHit {
	value: string;
	keyHex: string;
	keySize: number;
	confidence: number;
}

/**
 * Try each candidate key against the blob. A good decode must:
 *   1. produce ≥ 0.85 printable ASCII bytes
 *   2. score ≥ 0.5 on the bigram language model (rules out printable-but-random
 *      gibberish like `GIse 3+NFt{uqwORb,._dNOt`)
 *   3. not be a subset/shift of a higher-scoring hit (dedup on decoded value)
 *
 * Returns top 3 hits sorted by combined (printable × bigram) score.
 */
function tryKnownKeys(blob: Buffer, candidates: Buffer[]): KnownKeyHit[] {
	const hits: KnownKeyHit[] = [];
	const seen = new Set<string>();
	for (const key of candidates) {
		if (key.length === 0) { continue; }
		const decoded = Buffer.alloc(blob.length);
		let printableCount = 0;
		for (let i = 0; i < blob.length; i++) {
			const x = blob[i] ^ key[i % key.length];
			decoded[i] = x;
			if ((x >= 0x20 && x <= 0x7E) || x === 0x09) { printableCount++; }
		}
		const ratio = printableCount / blob.length;
		if (ratio < 0.85) { continue; }
		// Trim trailing NUL padding so "https://…\0\0" reports cleanly.
		let endIdx = decoded.length;
		while (endIdx > 0 && decoded[endIdx - 1] === 0) { endIdx--; }
		if (endIdx < 4) { continue; }

		// Reject printable-but-random gibberish via the existing bigram
		// scorer — real plaintext scores ≥ 0.75, noise ≤ 0.7. On a 22KB
		// binary, the 0.5 threshold let ~15K false positives through that
		// tied on ratio; 0.75 keeps the correct URL at the top and drops
		// the next-best noise by a large margin.
		const bigramScore = scoreString(decoded, 0, endIdx);
		if (bigramScore < 0.75) { continue; }

		const value = decoded.subarray(0, endIdx).toString('utf8');
		if (seen.has(value)) { continue; }
		seen.add(value);
		const keyHex = '0x' + key.toString('hex').toUpperCase();
		// Combined confidence: both signals must be strong. A decode that
		// hits 100% printable but only scrapes bigram 0.5 is weaker than
		// one that's 95% printable but bigram 0.9.
		const confidence = Math.min(1, (ratio + bigramScore) / 2);
		hits.push({ value, keyHex, keySize: key.length, confidence });
	}
	hits.sort((a, b) => b.confidence - a.confidence);
	return hits.slice(0, 3);
}

function toDeobfuscatedString(
	mr: MultiByteXorResult,
	peSections: PESectionMap | null,
): DeobfuscatedString {
	const mapped = MULTI_XOR_METHOD_MAP[mr.method];
	const result: DeobfuscatedString = {
		value: mr.value,
		offset: mr.offset,
		method: mapped ?? (mr.method as DeobfuscatedString['method']),
		keyHex: mr.keyHex,
		keySize: mr.keySize,
		confidence: mr.confidence,
	};

	// Copy optional fields if present
	if (mr.layerKeys) { result.layerKeys = mr.layerKeys; }
	if (mr.knownPattern) { result.knownPattern = mr.knownPattern; }
	if (mr.derivationParams) { result.derivationParams = mr.derivationParams; }
	if (mr.windowSize !== undefined) { result.windowSize = mr.windowSize; }
	if (mr.rotValue !== undefined) { result.rotValue = mr.rotValue; }
	if (mr.originalByteLength !== undefined) { result.originalByteLength = mr.originalByteLength; }

	// Annotate with PE section if available
	if (peSections && peSections.isPE && peSections.sections.length > 0) {
		const section = getSectionForOffset(peSections.sections, mr.offset);
		if (section) {
			result.section = section;
		}
	}

	return result;
}

/**
 * Run XOR brute-force, multi-byte, new scanners, and stack-string detection on the binary.
 * Uses chunked streaming to handle large files.
 *
 * Scanner pipeline order:
 * 1. xorBruteForce        — single-byte XOR
 * 2. multiByteXorScan     — multi-byte + rolling + increment
 * 3. knownPlaintextScan   — known-plaintext attack
 * 4. compositeCipherScan  — ADD/SUB/ROT
 * 5. wideStringXorScan    — UTF-16LE
 * 6. positionalXorScan    — counter + block-rotate
 * 7. rollingXorExtScan    — rolling N-bytes
 * 8. layeredXorScan       — XOR in layers (most expensive, last)
 * 9. detectStackStrings   — stack strings
 */
function runDeobfuscation(
	filePath: string,
	minLength: number,
	_options: StringsCommandOptions,
): DeobfuscatedString[] {
	const stats = fs.statSync(filePath);
	const totalSize = stats.size;
	const results: DeobfuscatedString[] = [];
	const seen = new Set<string>();

	// --- Build scanner options from command options ---
	const cmdOpts = (_options as Record<string, unknown>) ?? {};
	const enableKnownPlaintext = cmdOpts.enableKnownPlaintext !== false;
	const enableCompositeCipher = cmdOpts.enableCompositeCipher !== false;
	const enableWideString = cmdOpts.enableWideString !== false;
	const enablePositionalXor = cmdOpts.enablePositionalXor !== false;
	const enableRollingExt = cmdOpts.enableRollingExt !== false;
	const enableLayeredXor = cmdOpts.enableLayeredXor !== false;
	const targetSections = cmdOpts.targetSections as string[] | undefined;
	const customPlaintextPatterns = cmdOpts.customPlaintextPatterns as string[] | undefined;

	const scannerOpts: MultiByteXorOptions = {
		minLength,
		customPlaintextPatterns,
		targetSections,
	};

	// --- PE pre-scan: read first 2KB for section parsing ---
	let peSections: PESectionMap | null = null;
	const fd = fs.openSync(filePath, 'r');
	try {
		const preScanSize = Math.min(PE_PRESCAN_SIZE, totalSize);
		const preScanBuf = Buffer.alloc(preScanSize);
		fs.readSync(fd, preScanBuf, 0, preScanSize, 0);
		peSections = parsePESections(preScanBuf);

		let offset = 0;

		while (offset < totalSize) {
			const bytesToRead = Math.min(DEOB_CHUNK_SIZE, totalSize - offset);
			const buffer = Buffer.alloc(bytesToRead);
			fs.readSync(fd, buffer, 0, bytesToRead, offset);

			// If targetSections specified and PE is valid, skip chunks outside target sections
			if (targetSections && targetSections.length > 0 && peSections && peSections.isPE) {
				const chunkEnd = offset + bytesToRead;
				const inTarget = peSections.sections.some(s =>
					targetSections.includes(s.name) &&
					offset < s.offset + s.size &&
					chunkEnd > s.offset
				);
				if (!inTarget) {
					offset += bytesToRead;
					continue;
				}
			}

			// --- 0. Stack-resident XOR blob detection (RUNS FIRST) ---
			// v3.8.0-nightly: must run before xorBruteForce, which routinely
			// fills the MAX_DEOB_RESULTS=5000 cap on binaries with many single-
			// byte XOR hits. The stack-blob path is extremely targeted
			// (typically <5 blobs per binary) and the recovered C2-URL-class
			// strings are the highest-signal output of the whole deob stack.
			{
				const stackBlobs = detectStackBlobs(buffer, offset);
				const candidateKeys = stackBlobs.length > 0 ? extractPrintableRunsAsKeys(buffer, 3, 16) : [];
				for (const blob of stackBlobs) {
					if (blob.bytes.length < 8) { continue; }
					const knownKeyHits = tryKnownKeys(blob.bytes, candidateKeys);
					for (const kh of knownKeyHits) {
						const dedupKey = `stack-xor:${kh.value}`;
						if (seen.has(dedupKey)) { continue; }
						seen.add(dedupKey);
						const entry: DeobfuscatedString = {
							value: kh.value,
							offset: blob.offset,
							method: 'XOR-multi',
							keyHex: kh.keyHex,
							keySize: kh.keySize,
							confidence: kh.confidence,
							instructionCount: blob.instructionCount,
						};
						if (peSections && peSections.isPE) {
							const section = getSectionForOffset(peSections.sections, blob.offset);
							if (section) { entry.section = section; }
						}
						results.push(entry);
					}
					// Also run frequency analysis for blobs where the known-key
					// trial found nothing.
					if (knownKeyHits.length === 0) {
						const decoded = multiByteXorScan(blob.bytes, 0, scannerOpts);
						for (const dr of decoded.slice(0, 5)) {
							const dedupKey = `stack-xor:${dr.value}`;
							if (seen.has(dedupKey)) { continue; }
							seen.add(dedupKey);
							const entry: DeobfuscatedString = {
								value: dr.value,
								offset: blob.offset,
								method: 'XOR-multi',
								keyHex: dr.keyHex,
								keySize: dr.keySize,
								confidence: dr.confidence,
								instructionCount: blob.instructionCount,
							};
							if (peSections && peSections.isPE) {
								const section = getSectionForOffset(peSections.sections, blob.offset);
								if (section) { entry.section = section; }
							}
							results.push(entry);
						}
					}
				}
			}

			// --- 1. XOR brute-force ---
			const xorResults = xorBruteForce(buffer, offset, { minLength });
			for (const xr of xorResults) {
				if (results.length >= MAX_DEOB_RESULTS) { break; }
				const key = `xor:${xr.value}`;
				if (seen.has(key)) { continue; }
				seen.add(key);
				const entry: DeobfuscatedString = {
					value: xr.value,
					offset: xr.offset,
					method: 'XOR',
					xorKey: xr.key,
					confidence: xr.confidence,
				};
				if (peSections && peSections.isPE) {
					const section = getSectionForOffset(peSections.sections, xr.offset);
					if (section) { entry.section = section; }
				}
				results.push(entry);
			}

			// --- 2. Multi-byte XOR scan ---
			if (results.length < MAX_DEOB_RESULTS) {
				const multiResults = multiByteXorScan(buffer, offset, scannerOpts);
				for (const mr of multiResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `${MULTI_XOR_METHOD_MAP[mr.method]}:${mr.value}`;
					if (seen.has(dedupKey) || seen.has(`xor:${mr.value}`)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(mr, peSections));
				}
			}

			// --- 3. Known-plaintext scan ---
			if (enableKnownPlaintext && results.length < MAX_DEOB_RESULTS) {
				const kpResults = knownPlaintextScan(buffer, offset, undefined, scannerOpts);
				for (const kr of kpResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `XOR-known-plaintext:${kr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(kr, peSections));
				}
			}

			// --- 4. Composite cipher scan (ADD/SUB/ROT) ---
			if (enableCompositeCipher && results.length < MAX_DEOB_RESULTS) {
				const ccResults = compositeCipherScan(buffer, offset, scannerOpts);
				for (const cr of ccResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `${cr.method}:${cr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					const entry = toDeobfuscatedString(cr as unknown as MultiByteXorResult, peSections);
					if (cr.rotValue !== undefined) { entry.rotValue = cr.rotValue; }
					results.push(entry);
				}
			}

			// --- 5. Wide string XOR scan ---
			if (enableWideString && results.length < MAX_DEOB_RESULTS) {
				const wsResults = wideStringXorScan(buffer, offset, scannerOpts);
				for (const wr of wsResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `XOR-wide:${wr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(wr, peSections));
				}
			}

			// --- 6. Positional XOR scan ---
			if (enablePositionalXor && results.length < MAX_DEOB_RESULTS) {
				const pxResults = positionalXorScan(buffer, offset, scannerOpts);
				for (const pr of pxResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `${pr.method}:${pr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(pr, peSections));
				}
			}

			// --- 7. Rolling XOR extended scan ---
			if (enableRollingExt && results.length < MAX_DEOB_RESULTS) {
				const rxResults = rollingXorExtScan(buffer, offset, scannerOpts);
				for (const rr of rxResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `XOR-rolling-ext:${rr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(rr, peSections));
				}
			}

			// --- 8. Layered XOR scan (most expensive, last) ---
			if (enableLayeredXor && results.length < MAX_DEOB_RESULTS) {
				const lxResults = layeredXorScan(buffer, offset, scannerOpts);
				for (const lr of lxResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const dedupKey = `XOR-layered:${lr.value}`;
					if (seen.has(dedupKey)) { continue; }
					seen.add(dedupKey);
					results.push(toDeobfuscatedString(lr, peSections));
				}
			}

			// --- 9. Stack string detection ---
			if (results.length < MAX_DEOB_RESULTS) {
				const stackResults = detectStackStrings(buffer, offset);
				for (const ss of stackResults) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					const key = `stack:${ss.value}`;
					if (seen.has(key)) { continue; }
					seen.add(key);
					const entry: DeobfuscatedString = {
						value: ss.value,
						offset: ss.offset,
						method: 'Stack',
						instructionCount: ss.instructionCount,
					};
					if (peSections && peSections.isPE) {
						const section = getSectionForOffset(peSections.sections, ss.offset);
						if (section) { entry.section = section; }
					}
					results.push(entry);
				}
			}

			// --- 10. Stack-resident XOR blob detection ---
			// v3.8.0-nightly: malware (Ashaka family) inlines XOR-obfuscated
			// payloads as `mov byte [rbp+N], 0xYY` or `mov dword [rbp+N], imm32`
			// sequences instead of a contiguous .rdata blob. Collect raw blobs
			// (no ASCII filter), then try TWO recovery strategies:
			//   (1) multiByteXorScan frequency analysis — works when blob is big
			//   (2) known-key trial: any printable-ASCII run (length 3..16) that
			//       exists elsewhere in the binary is a plausible XOR key. Try
			//       each against every blob. This covers short blobs (e.g. a
			//       36-byte C2 URL) where frequency analysis fails.
			if (results.length < MAX_DEOB_RESULTS) {
				const stackBlobs = detectStackBlobs(buffer, offset);
				// Collect candidate keys once per chunk: printable ASCII runs
				// of length 3..16. These are cheap to derive and rarely yield
				// false positives on 8+-byte blobs thanks to isPrintable gate.
				const candidateKeys = extractPrintableRunsAsKeys(buffer, 3, 16);
				for (const blob of stackBlobs) {
					if (results.length >= MAX_DEOB_RESULTS) { break; }
					if (blob.bytes.length < 8) { continue; }

					// Strategy 2: known-key trial against binary-resident
					// printable runs. Do this FIRST — a successful trial with
					// the literal key wins over noisy frequency guesses.
					const knownKeyHits = tryKnownKeys(blob.bytes, candidateKeys);
					for (const kh of knownKeyHits) {
						if (results.length >= MAX_DEOB_RESULTS) { break; }
						const dedupKey = `stack-xor:${kh.value}`;
						if (seen.has(dedupKey) || seen.has(`xor:${kh.value}`) || seen.has(`XOR-multi:${kh.value}`)) { continue; }
						seen.add(dedupKey);
						const entry: DeobfuscatedString = {
							value: kh.value,
							offset: blob.offset,
							method: 'XOR-multi',
							keyHex: kh.keyHex,
							keySize: kh.keySize,
							confidence: kh.confidence,
							instructionCount: blob.instructionCount,
						};
						if (peSections && peSections.isPE) {
							const section = getSectionForOffset(peSections.sections, blob.offset);
							if (section) { entry.section = section; }
						}
						results.push(entry);
					}

					// Strategy 1: fall back to frequency analysis.
					const decoded = multiByteXorScan(blob.bytes, 0, scannerOpts);
					for (const dr of decoded) {
						if (results.length >= MAX_DEOB_RESULTS) { break; }
						const dedupKey = `stack-xor:${dr.value}`;
						if (seen.has(dedupKey) || seen.has(`xor:${dr.value}`) || seen.has(`XOR-multi:${dr.value}`)) { continue; }
						seen.add(dedupKey);
						const entry: DeobfuscatedString = {
							value: dr.value,
							offset: blob.offset, // point back to the instruction sequence in .text
							method: 'XOR-multi',
							keyHex: dr.keyHex,
							keySize: dr.keySize,
							confidence: dr.confidence,
							instructionCount: blob.instructionCount,
						};
						if (peSections && peSections.isPE) {
							const section = getSectionForOffset(peSections.sections, blob.offset);
							if (section) { entry.section = section; }
						}
						results.push(entry);
					}
				}
			}

			offset += bytesToRead;

			// Cap total deobfuscated results
			if (results.length >= MAX_DEOB_RESULTS) {
				break;
			}
		}
	} finally {
		fs.closeSync(fd);
	}

	return results;
}

/**
 * Generate Markdown section for deobfuscated strings to append to the main report.
 */
function generateDeobfuscationReport(deobfuscated: DeobfuscatedString[]): string {
	// --- Partition results by method ---
	const singleByteXor = deobfuscated.filter(d => d.method === 'XOR');
	const multiByteXor = deobfuscated.filter(d => d.method === 'XOR-multi');
	const rollingXor = deobfuscated.filter(d => d.method === 'XOR-rolling');
	const incrementXor = deobfuscated.filter(d => d.method === 'XOR-increment');
	const stackStrings = deobfuscated.filter(d => d.method === 'Stack');
	const wideXor = deobfuscated.filter(d => d.method === 'XOR-wide');
	const layeredXor = deobfuscated.filter(d => d.method === 'XOR-layered');
	const counterXor = deobfuscated.filter(d => d.method === 'XOR-counter');
	const blockRotateXor = deobfuscated.filter(d => d.method === 'XOR-block-rotate');
	const rollingExtXor = deobfuscated.filter(d => d.method === 'XOR-rolling-ext');
	const knownPlaintext = deobfuscated.filter(d => d.method === 'XOR-known-plaintext');
	const addCipher = deobfuscated.filter(d => d.method === 'ADD');
	const subCipher = deobfuscated.filter(d => d.method === 'SUB');
	const rotCipher = deobfuscated.filter(d => d.method === 'ROT');

	// Determine if any result has a PE section field
	const hasSections = deobfuscated.some(d => d.section !== undefined && d.section !== '');

	let report = '\n---\n\n## 🔓 Deobfuscated Strings\n\n';

	// --- Statistical summary ---
	report += deobReportStatsSummary([
		{ label: 'XOR Single-Byte', items: singleByteXor },
		{ label: 'XOR Multi-Byte', items: multiByteXor },
		{ label: 'XOR Rolling', items: rollingXor },
		{ label: 'XOR Increment', items: incrementXor },
		{ label: 'XOR Wide', items: wideXor },
		{ label: 'XOR Layered', items: layeredXor },
		{ label: 'XOR Counter', items: counterXor },
		{ label: 'XOR Block-Rotate', items: blockRotateXor },
		{ label: 'XOR Rolling-Ext', items: rollingExtXor },
		{ label: 'XOR Known-Plaintext', items: knownPlaintext },
		{ label: 'ADD', items: addCipher },
		{ label: 'SUB', items: subCipher },
		{ label: 'ROT', items: rotCipher },
		{ label: 'Stack', items: stackStrings },
	]);

	// --- Standard table sections (same column layout) ---
	report += deobReportStandardSection('XOR Single-Byte', singleByteXor, hasSections);
	report += deobReportStandardSection('XOR Multi-Byte', multiByteXor, hasSections);
	report += deobReportStandardSection('XOR Rolling', rollingXor, hasSections);
	report += deobReportStandardSection('XOR Increment', incrementXor, hasSections);
	report += deobReportStandardSection('XOR Wide', wideXor, hasSections);
	report += deobReportStandardSection('XOR Counter', counterXor, hasSections);
	report += deobReportStandardSection('XOR Block-Rotate', blockRotateXor, hasSections);
	report += deobReportStandardSection('XOR Rolling-Ext', rollingExtXor, hasSections);
	report += deobReportStandardSection('ADD', addCipher, hasSections);
	report += deobReportStandardSection('SUB', subCipher, hasSections);
	report += deobReportStandardSection('ROT', rotCipher, hasSections);

	// --- Special sections with extra columns ---
	report += deobReportLayeredSection(layeredXor, hasSections);
	report += deobReportKnownPlaintextSection(knownPlaintext, hasSections);

	// --- Stack strings (different layout) ---
	if (stackStrings.length > 0) {
		report += `### Stack Strings (${stackStrings.length})\n\n`;
		report += '| # | Offset | Instructions | Value |\n';
		report += '|---|--------|-------------|-------|\n';

		const display = stackStrings.slice(0, 100);
		for (let i = 0; i < display.length; i++) {
			const d = display[i];
			const escaped = deobEscape(d.value);
			report += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.instructionCount ?? '—'} | \`${escaped}\` |\n`;
		}
		if (stackStrings.length > 100) {
			report += `| ... | ... | ... | *${stackStrings.length - 100} more* |\n`;
		}
		report += '\n';
	}

	return report;
}

// ---------------------------------------------------------------------------
// Deobfuscation report helpers
// ---------------------------------------------------------------------------

function deobOffset(offset: number): string {
	return `0x${offset.toString(16).toUpperCase().padStart(8, '0')}`;
}

function deobEscape(text: string): string {
	return text.replace(/\|/g, '\\|').replace(/\n/g, ' ').substring(0, 60);
}

function deobConfidence(d: DeobfuscatedString): string {
	return d.confidence !== undefined ? `${Math.round(d.confidence * 100)}%` : '—';
}

function deobKey(d: DeobfuscatedString): string {
	if (d.xorKey !== undefined) {
		return `0x${d.xorKey.toString(16).toUpperCase().padStart(2, '0')}`;
	}
	return d.keyHex ?? '—';
}

function deobKeySize(d: DeobfuscatedString): string {
	if (d.xorKey !== undefined) {
		return '1';
	}
	return d.keySize !== undefined ? String(d.keySize) : '—';
}

/**
 * Build the statistical summary table at the top of the deobfuscation section.
 */
function deobReportStatsSummary(
	groups: Array<{ label: string; items: DeobfuscatedString[] }>,
): string {
	const nonEmpty = groups.filter(g => g.items.length > 0);
	if (nonEmpty.length === 0) {
		return '';
	}

	let out = '### 📊 Summary by Method\n\n';
	out += '| Method | Count | Avg Confidence |\n';
	out += '|--------|-------|----------------|\n';

	for (const g of nonEmpty) {
		const count = g.items.length;
		const withConf = g.items.filter(d => d.confidence !== undefined);
		let avgConf = '—';
		if (withConf.length > 0) {
			const sum = withConf.reduce((acc, d) => acc + (d.confidence ?? 0), 0);
			avgConf = `${Math.round((sum / withConf.length) * 100)}%`;
		}
		out += `| ${g.label} | ${count} | ${avgConf} |\n`;
	}
	out += '\n';
	return out;
}

/**
 * Render a standard deobfuscation table section.
 * Columns: #, Offset, Method, Key, Key Size, Confidence, Value (+ optional Section).
 */
function deobReportStandardSection(
	title: string,
	items: DeobfuscatedString[],
	hasSections: boolean,
): string {
	if (items.length === 0) {
		return '';
	}

	let out = `### ${title} (${items.length})\n\n`;

	if (hasSections) {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Section | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|---------|-------|\n';
	} else {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|-------|\n';
	}

	const display = items.slice(0, 100);
	for (let i = 0; i < display.length; i++) {
		const d = display[i];
		const escaped = deobEscape(d.value);
		const extra = deobExtraInfo(d);
		const keyStr = extra || deobKey(d);
		const sizeStr = deobKeySize(d);
		if (hasSections) {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${keyStr} | ${sizeStr} | ${deobConfidence(d)} | ${d.section ?? '—'} | \`${escaped}\` |\n`;
		} else {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${keyStr} | ${sizeStr} | ${deobConfidence(d)} | \`${escaped}\` |\n`;
		}
	}

	if (items.length > 100) {
		if (hasSections) {
			out += `| ... | ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		} else {
			out += `| ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		}
	}
	out += '\n';
	return out;
}

/**
 * Build extra key info for methods that have special metadata.
 * Returns a richer key string or empty string to fall back to default.
 */
function deobExtraInfo(d: DeobfuscatedString): string {
	// Counter-linear: show base+step
	if (d.method === 'XOR-counter' && d.derivationParams) {
		const p = d.derivationParams;
		return `base=0x${(p.base ?? 0).toString(16).toUpperCase()}, step=${p.step ?? 1}`;
	}
	// Block-rotate: show key + block size
	if (d.method === 'XOR-block-rotate' && d.derivationParams) {
		const p = d.derivationParams;
		const keyPart = d.keyHex ?? '—';
		return `${keyPart} (block=${p.blockSize ?? '—'})`;
	}
	// Rolling-ext: show window size
	if (d.method === 'XOR-rolling-ext' && d.windowSize !== undefined) {
		const seedPart = d.keyHex ?? (d.xorKey !== undefined ? `0x${d.xorKey.toString(16).toUpperCase().padStart(2, '0')}` : '—');
		return `${seedPart} (win=${d.windowSize})`;
	}
	// ROT: show rotation value
	if (d.method === 'ROT' && d.rotValue !== undefined) {
		return `ROT-${d.rotValue}`;
	}
	// ADD/SUB: show key value
	if ((d.method === 'ADD' || d.method === 'SUB') && d.xorKey !== undefined) {
		return `0x${d.xorKey.toString(16).toUpperCase().padStart(2, '0')}`;
	}
	// XOR-wide: show original byte length if available
	if (d.method === 'XOR-wide' && d.originalByteLength !== undefined) {
		const keyPart = deobKey(d);
		return `${keyPart} (${d.originalByteLength}B)`;
	}
	return '';
}

/**
 * Render XOR-layered section with extra Layers column showing key sequence.
 */
function deobReportLayeredSection(
	items: DeobfuscatedString[],
	hasSections: boolean,
): string {
	if (items.length === 0) {
		return '';
	}

	let out = `### XOR Layered (${items.length})\n\n`;

	if (hasSections) {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Layers | Section | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|--------|---------|-------|\n';
	} else {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Layers | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|--------|-------|\n';
	}

	const display = items.slice(0, 100);
	for (let i = 0; i < display.length; i++) {
		const d = display[i];
		const escaped = deobEscape(d.value);
		const layers = d.layerKeys && d.layerKeys.length > 0
			? d.layerKeys.map((k, idx) => `L${idx + 1}:${k}`).join(' → ')
			: '—';
		if (hasSections) {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${deobKey(d)} | ${deobKeySize(d)} | ${deobConfidence(d)} | ${layers} | ${d.section ?? '—'} | \`${escaped}\` |\n`;
		} else {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${deobKey(d)} | ${deobKeySize(d)} | ${deobConfidence(d)} | ${layers} | \`${escaped}\` |\n`;
		}
	}

	if (items.length > 100) {
		if (hasSections) {
			out += `| ... | ... | ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		} else {
			out += `| ... | ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		}
	}
	out += '\n';
	return out;
}

/**
 * Render XOR-known-plaintext section with extra Pattern column.
 */
function deobReportKnownPlaintextSection(
	items: DeobfuscatedString[],
	hasSections: boolean,
): string {
	if (items.length === 0) {
		return '';
	}

	let out = `### XOR Known-Plaintext (${items.length})\n\n`;

	if (hasSections) {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Pattern | Section | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|---------|---------|-------|\n';
	} else {
		out += '| # | Offset | Method | Key | Key Size | Confidence | Pattern | Value |\n';
		out += '|---|--------|--------|-----|----------|------------|---------|-------|\n';
	}

	const display = items.slice(0, 100);
	for (let i = 0; i < display.length; i++) {
		const d = display[i];
		const escaped = deobEscape(d.value);
		const pattern = d.knownPattern ?? '—';
		if (hasSections) {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${deobKey(d)} | ${deobKeySize(d)} | ${deobConfidence(d)} | ${pattern} | ${d.section ?? '—'} | \`${escaped}\` |\n`;
		} else {
			out += `| ${i + 1} | ${deobOffset(d.offset)} | ${d.method} | ${deobKey(d)} | ${deobKeySize(d)} | ${deobConfidence(d)} | ${pattern} | \`${escaped}\` |\n`;
		}
	}

	if (items.length > 100) {
		if (hasSections) {
			out += `| ... | ... | ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		} else {
			out += `| ... | ... | ... | ... | ... | ... | ... | *${items.length - 100} more* |\n`;
		}
	}
	out += '\n';
	return out;
}

