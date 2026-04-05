/*---------------------------------------------------------------------------------------------
 *  HexCore Base64 Decoder v2.0.0
 *  Detect and decode Base64 encoded strings with confidence scoring
 *  Features: entropy analysis, context filtering, false-positive reduction
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ConfidenceCategory = 'high_confidence' | 'medium_confidence' | 'possible';

export interface Base64Match {
	offset: number;
	encoded: string;
	decoded: string;
	decodedHex: string;
	isPrintable: boolean;
	/** v2.0: Confidence score 0-100 */
	confidence: number;
	/** v2.0: Confidence category */
	category: ConfidenceCategory;
	/** v2.0: Human-readable reasons for the confidence score */
	reasons: string[];
	/** v2.0: Shannon entropy of the encoded string (bits/byte) */
	entropy: number;
}

// ---------------------------------------------------------------------------
// Confidence scoring engine
// ---------------------------------------------------------------------------

/** Shannon entropy in bits per byte (0 = uniform, ~6.0 = good base64) */
function shannonEntropy(data: string): number {
	if (data.length === 0) { return 0; }
	const freq = new Map<string, number>();
	for (const ch of data) {
		freq.set(ch, (freq.get(ch) || 0) + 1);
	}
	let entropy = 0;
	for (const count of freq.values()) {
		const p = count / data.length;
		if (p > 0) {
			entropy -= p * Math.log2(p);
		}
	}
	return entropy;
}

/** Character distribution uniformity score (0 = skewed, 1 = uniform) */
function charDistributionScore(data: string): number {
	if (data.length < 4) { return 0; }
	const stripped = data.replace(/=+$/, '');
	const freq = new Map<string, number>();
	for (const ch of stripped) {
		freq.set(ch, (freq.get(ch) || 0) + 1);
	}

	// Base64 alphabet has 64 characters. Perfect uniformity = each appears data.length/64 times
	const expected = stripped.length / 64;
	if (expected < 0.1) { return 0.5; } // too short to measure

	let chiSq = 0;
	for (const count of freq.values()) {
		const diff = count - expected;
		chiSq += (diff * diff) / expected;
	}

	// Normalize: lower chiSq = more uniform = higher score
	// chiSq of 0 = perfect, chiSq > 200 = very skewed
	const normalized = Math.max(0, 1 - chiSq / (stripped.length * 2));
	return normalized;
}

// ---------------------------------------------------------------------------
// Context-aware false positive filters
// ---------------------------------------------------------------------------

/** Common Windows API name patterns (CamelCase) that match base64 alphabet */
const WINDOWS_API_PATTERNS = [
	/^[A-Z][a-z]+([A-Z][a-z]+){2,}(Ex)?[AW]?$/, // CamelCase: CreateFileA, VirtualAllocEx
	/^(Get|Set|Create|Open|Close|Read|Write|Find|Delete|Query|Register|Unregister|Initialize|Enable|Disable)/,
	/^(Nt|Zw|Rtl|Ldr)[A-Z]/,                      // NT native API prefixes
];

/** Pure alphabet / sequential patterns that produce false positives */
const ALPHABET_PATTERNS = [
	/^[a-z]+$/,                                     // all lowercase
	/^[A-Z]+$/,                                     // all uppercase
	/^[a-zA-Z]+$/,                                  // only letters, no digits/+/
	/^0123456789/,                                   // numeric sequences
	/^abcdefgh/i,                                    // alphabet sequences
	/^ABCDEFGH/,                                     // uppercase alphabet sequences
];

/** Common code identifiers and format strings */
const CODE_IDENTIFIER_PATTERNS = [
	/^(std|boost|__[a-z])/i,                         // C++ namespace patterns
	/^[a-z_][a-zA-Z0-9_]*$/,                         // snake_case / camelCase identifiers
	/^\w+\.\w+\.\w+/,                                // dotted identifiers (com.example.Class)
	/^https?:\/\//,                                   // URLs
	/^[A-Fa-f0-9]{32,}$/,                            // pure hex strings (SHA256, MD5)
	/^\{?[A-Fa-f0-9]{8}(-[A-Fa-f0-9]{4}){3}-[A-Fa-f0-9]{12}\}?$/, // GUIDs
];

/**
 * Check if a string looks like a Windows API name or common programming identifier.
 * Returns a reason string if it's a false positive, or null if it looks legitimate.
 */
function detectFalsePositive(encoded: string): string | null {
	// Alphabet sequences
	for (const pattern of ALPHABET_PATTERNS) {
		if (pattern.test(encoded)) {
			return 'Alphabet sequence or pure-letter string';
		}
	}

	// Windows API names
	for (const pattern of WINDOWS_API_PATTERNS) {
		if (pattern.test(encoded)) {
			return 'Matches Windows API naming pattern';
		}
	}

	// Code identifiers
	for (const pattern of CODE_IDENTIFIER_PATTERNS) {
		if (pattern.test(encoded)) {
			return 'Matches code identifier or format pattern';
		}
	}

	// Repeated character sequences (e.g., AAAAAAAAAAAA)
	if (encoded.length >= 20) {
		const uniqueChars = new Set(encoded).size;
		if (uniqueChars <= 3) {
			return 'Very low character diversity (repeated pattern)';
		}
	}

	// Check for high ratio of a single character class
	const uppercaseCount = (encoded.match(/[A-Z]/g) || []).length;
	const lowercaseCount = (encoded.match(/[a-z]/g) || []).length;
	const digitCount = (encoded.match(/[0-9]/g) || []).length;
	const specialCount = (encoded.match(/[+/]/g) || []).length;
	const total = encoded.replace(/=+$/, '').length;

	// Real base64 has mixed case + digits + sometimes +/
	// PE import names are predominantly letters with almost no digits/special
	if (total >= 20 && specialCount === 0 && digitCount === 0) {
		// No digits or +/ at all in 20+ chars — very likely a name, not base64
		const ratio = (uppercaseCount + lowercaseCount) / total;
		if (ratio > 0.98) {
			return 'All alphabetic characters (no digits or +/)';
		}
	}

	return null;
}

// ---------------------------------------------------------------------------
// Core scoring
// ---------------------------------------------------------------------------

interface ScoringResult {
	score: number;
	reasons: string[];
	entropy: number;
}

function calculateConfidence(encoded: string, decoded: Buffer): ScoringResult {
	const reasons: string[] = [];
	let score = 50; // Start at neutral

	const strippedLen = encoded.replace(/=+$/, '').length;

	// --- 1. Length scoring ---
	if (strippedLen >= 100) {
		score += 15;
		reasons.push('+15 long string (≥100 chars)');
	} else if (strippedLen >= 60) {
		score += 10;
		reasons.push('+10 medium-long string (≥60 chars)');
	} else if (strippedLen >= 40) {
		score += 5;
		reasons.push('+5 moderate string (≥40 chars)');
	} else if (strippedLen < 24) {
		score -= 10;
		reasons.push('-10 short string (<24 chars)');
	}

	// --- 2. Entropy scoring ---
	const entropy = shannonEntropy(encoded.replace(/=+$/, ''));

	if (entropy >= 5.5) {
		score += 15;
		reasons.push(`+15 high entropy (${entropy.toFixed(2)} bits/byte)`);
	} else if (entropy >= 4.5) {
		score += 8;
		reasons.push(`+8 moderate entropy (${entropy.toFixed(2)} bits/byte)`);
	} else if (entropy >= 3.5) {
		score += 0;
		reasons.push(`+0 low-moderate entropy (${entropy.toFixed(2)} bits/byte)`);
	} else {
		score -= 15;
		reasons.push(`-15 very low entropy (${entropy.toFixed(2)} bits/byte)`);
	}

	// --- 3. Padding scoring ---
	const hasPadding = encoded.endsWith('=');
	const paddingCount = (encoded.match(/=+$/)?.[0] || '').length;

	if (hasPadding && paddingCount <= 2) {
		score += 8;
		reasons.push('+8 valid padding present');
	} else if (encoded.length % 4 === 0 && !hasPadding) {
		score += 3;
		reasons.push('+3 length divisible by 4 (no padding needed)');
	} else if (paddingCount > 2) {
		score -= 10;
		reasons.push('-10 invalid padding (>2 equals signs)');
	}

	// --- 4. Character distribution ---
	const distScore = charDistributionScore(encoded);
	if (distScore > 0.6) {
		score += 8;
		reasons.push(`+8 good character distribution (${(distScore * 100).toFixed(0)}%)`);
	} else if (distScore < 0.2) {
		score -= 10;
		reasons.push(`-10 skewed character distribution (${(distScore * 100).toFixed(0)}%)`);
	}

	// --- 5. Decoded content quality ---
	let printableCount = 0;
	for (const byte of decoded) {
		if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
			printableCount++;
		}
	}
	const printableRatio = decoded.length > 0 ? printableCount / decoded.length : 0;

	if (printableRatio > 0.9) {
		score += 12;
		reasons.push(`+12 decoded is highly printable (${(printableRatio * 100).toFixed(0)}%)`);
	} else if (printableRatio > 0.7) {
		score += 5;
		reasons.push(`+5 decoded is mostly printable (${(printableRatio * 100).toFixed(0)}%)`);
	} else if (printableRatio < 0.1) {
		// Binary data — could be legit (encrypted payload, compressed data)
		// Don't penalize much, just don't reward
		score -= 3;
		reasons.push(`-3 decoded is binary data (${(printableRatio * 100).toFixed(0)}% printable)`);
	}

	// --- 6. Decoded content patterns ---
	if (printableRatio > 0.7) {
		const decodedStr = decoded.toString('utf8');

		// Check for structured content (JSON, XML, URLs, paths)
		if (/^\s*[{[]/.test(decodedStr)) {
			score += 5;
			reasons.push('+5 decoded looks like JSON/structured data');
		} else if (/<\w+[\s>]/.test(decodedStr)) {
			score += 5;
			reasons.push('+5 decoded looks like XML/HTML');
		} else if (/https?:\/\//.test(decodedStr)) {
			score += 5;
			reasons.push('+5 decoded contains URL');
		} else if (/^(\/|[A-Z]:\\)/.test(decodedStr)) {
			score += 3;
			reasons.push('+3 decoded looks like file path');
		}

		// Check for meaningful English words
		const words = decodedStr.match(/[a-z]{4,}/gi) || [];
		if (words.length >= 3) {
			score += 3;
			reasons.push('+3 decoded contains English-like words');
		}
	}

	// --- 7. Null byte ratio penalty ---
	const nullCount = decoded.filter(b => b === 0).length;
	const nullRatio = decoded.length > 0 ? nullCount / decoded.length : 0;
	if (nullRatio > 0.3) {
		score -= 8;
		reasons.push(`-8 high null byte ratio (${(nullRatio * 100).toFixed(0)}%)`);
	}

	// --- 8. Context filter penalties ---
	const falsePositiveReason = detectFalsePositive(encoded);
	if (falsePositiveReason) {
		score -= 25;
		reasons.push(`-25 context filter: ${falsePositiveReason}`);
	}

	// Clamp score to 0-100
	score = Math.max(0, Math.min(100, score));

	return { score, reasons, entropy };
}

function scoreToCategory(score: number): ConfidenceCategory {
	if (score >= 75) { return 'high_confidence'; }
	if (score >= 50) { return 'medium_confidence'; }
	return 'possible';
}

// ---------------------------------------------------------------------------
// Core detection & decoding
// ---------------------------------------------------------------------------

function findBase64Strings(content: string): Array<{ offset: number; match: string }> {
	const results: Array<{ offset: number; match: string }> = [];

	// Base64 pattern: 20-4096 chars, valid base64 alphabet
	// Upper bound prevents ReDoS on adversarial input
	const base64Regex = /[A-Za-z0-9+/]{20,4096}={0,2}/g;

	let match;
	while ((match = base64Regex.exec(content)) !== null) {
		const str = match[0];
		if (isLikelyBase64(str)) {
			results.push({
				offset: match.index,
				match: str
			});
		}
	}

	return results;
}

function isLikelyBase64(str: string): boolean {
	if (str.length < 20) { return false; }

	const withoutPadding = str.replace(/=+$/, '');
	const validChars = withoutPadding.replace(/[A-Za-z0-9+/]/g, '');
	if (validChars.length > 0) { return false; }

	try {
		const decoded = Buffer.from(str, 'base64');
		if (decoded.length < 8) { return false; }

		const nullCount = decoded.filter(b => b === 0).length;
		if (nullCount > decoded.length * 0.5) { return false; }

		return true;
	} catch {
		return false;
	}
}

function decodeMatches(matches: Array<{ offset: number; match: string }>, minConfidence: number): Base64Match[] {
	const results: Base64Match[] = [];

	for (const { offset, match } of matches) {
		try {
			const decoded = Buffer.from(match, 'base64');
			const decodedHex = decoded.toString('hex').toUpperCase();

			// Calculate confidence score
			const { score, reasons, entropy } = calculateConfidence(match, decoded);

			// Filter by minimum confidence
			if (score < minConfidence) { continue; }

			const category = scoreToCategory(score);

			// Determine printability
			let printableCount = 0;
			for (const byte of decoded) {
				if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
					printableCount++;
				}
			}
			const isPrintable = printableCount > decoded.length * 0.7;
			const decodedStr = decoded.toString('utf8');

			results.push({
				offset,
				encoded: match,
				decoded: isPrintable ? decodedStr : '[Binary Data]',
				decodedHex: decodedHex.substring(0, 64) + (decodedHex.length > 64 ? '...' : ''),
				isPrintable,
				confidence: score,
				category,
				reasons,
				entropy
			});
		} catch {
			// Skip invalid base64
		}
	}

	// Sort by confidence descending
	results.sort((a, b) => b.confidence - a.confidence);

	return results;
}

// ---------------------------------------------------------------------------
// File scanning
// ---------------------------------------------------------------------------

function scanFileForBase64(filePath: string, minConfidence: number = 30): Base64Match[] {
	const stats = fs.statSync(filePath);
	const MAX_FILE_SIZE = 512 * 1024 * 1024;

	if (stats.size > MAX_FILE_SIZE) {
		throw new Error(`File is ${(stats.size / (1024 * 1024)).toFixed(0)}MB — exceeds limit of 512MB.`);
	}

	const CHUNK_SIZE = 1024 * 1024;
	const OVERLAP = 4096;
	let allMatches: Array<{ offset: number; match: string }> = [];
	let bytesRead = 0;
	let carryover = '';

	const fd = fs.openSync(filePath, 'r');
	try {
		const buf = Buffer.alloc(CHUNK_SIZE);
		let readLen: number;

		while ((readLen = fs.readSync(fd, buf, 0, CHUNK_SIZE, bytesRead)) > 0) {
			const chunk = buf.subarray(0, readLen).toString('binary');
			const combined = carryover + chunk;
			const baseOffset = bytesRead - carryover.length;

			const chunkMatches = findBase64Strings(combined);
			for (const m of chunkMatches) {
				allMatches.push({ offset: baseOffset + m.offset, match: m.match });
			}

			bytesRead += readLen;
			carryover = readLen >= OVERLAP ? combined.slice(-OVERLAP) : '';
		}
	} finally {
		fs.closeSync(fd);
	}

	// Deduplicate matches from overlap regions
	const seen = new Set<string>();
	allMatches = allMatches.filter(m => {
		const key = `${m.offset}:${m.match.slice(0, 64)}`;
		if (seen.has(key)) { return false; }
		seen.add(key);
		return true;
	});

	return decodeMatches(allMatches, minConfidence);
}

// ---------------------------------------------------------------------------
// Extension activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Base64 Decoder v2.0.0 activated (confidence scoring engine)');

	// Interactive command
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.base64.decode', async (uri?: vscode.Uri) => {
			if (!uri) {
				const files = await vscode.window.showOpenDialog({
					canSelectMany: false,
					canSelectFiles: true,
					title: 'Select file to scan for Base64'
				});
				if (files && files.length > 0) {
					uri = files[0];
				} else {
					return;
				}
			}

			await decodeBase64InFile(uri);
		})
	);

	// Headless command for pipeline/agent use
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.base64.decodeHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			if (!filePath) {
				throw new Error('decodeHeadless requires a "file" argument.');
			}

			if (!fs.existsSync(filePath)) {
				throw new Error(`File not found: ${filePath}`);
			}

			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			// v2.0: Configurable minimum confidence (default: 30 = filters out noise)
			const minConfidence = typeof arg?.minConfidence === 'number'
				? Math.max(0, Math.min(100, arg.minConfidence))
				: 30;

			// v2.0: Filter by category
			const categoryFilter = typeof arg?.category === 'string'
				? arg.category as ConfidenceCategory
				: undefined;

			let matches = scanFileForBase64(filePath, minConfidence);

			// Apply category filter if specified
			if (categoryFilter) {
				matches = matches.filter(m => m.category === categoryFilter);
			}

			// v2.0: Category breakdown
			const highConfidence = matches.filter(m => m.category === 'high_confidence');
			const mediumConfidence = matches.filter(m => m.category === 'medium_confidence');
			const possible = matches.filter(m => m.category === 'possible');

			const result = {
				filePath,
				matches,
				totalMatches: matches.length,
				breakdown: {
					high_confidence: highConfidence.length,
					medium_confidence: mediumConfidence.length,
					possible: possible.length,
				},
				averageConfidence: matches.length > 0
					? Math.round(matches.reduce((sum, m) => sum + m.confidence, 0) / matches.length)
					: 0,
				minConfidenceUsed: minConfidence,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`HexCore Base64: ${matches.length} match(es) — ${highConfidence.length} high, ${mediumConfidence.length} medium, ${possible.length} possible`
				);
			}

			return result;
		})
	);
}

// ---------------------------------------------------------------------------
// Interactive file scan with UI
// ---------------------------------------------------------------------------

async function decodeBase64InFile(uri: vscode.Uri): Promise<void> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);

	await vscode.window.withProgress({
		location: vscode.ProgressLocation.Notification,
		title: `Scanning ${fileName} for Base64...`,
		cancellable: false
	}, async (progress) => {
		try {
			progress.report({ increment: 10, message: 'Scanning file...' });

			const decodedMatches = scanFileForBase64(filePath, 30);

			progress.report({ increment: 70, message: 'Generating report...' });

			const stats = fs.statSync(filePath);
			const report = generateReport(fileName, filePath, stats.size, decodedMatches);

			const doc = await vscode.workspace.openTextDocument({
				content: report,
				language: 'markdown'
			});

			await vscode.window.showTextDocument(doc, { preview: false });

			progress.report({ increment: 20, message: 'Done' });
		} catch (error: any) {
			vscode.window.showErrorMessage(`Base64 scan failed: ${error.message}`);
		}
	});
}

// ---------------------------------------------------------------------------
// Report generation
// ---------------------------------------------------------------------------

function generateReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	matches: Base64Match[]
): string {
	const highConfidence = matches.filter(m => m.category === 'high_confidence');
	const mediumConfidence = matches.filter(m => m.category === 'medium_confidence');
	const possible = matches.filter(m => m.category === 'possible');

	const printableMatches = matches.filter(m => m.isPrintable);
	const binaryMatches = matches.filter(m => !m.isPrintable);

	let report = `# HexCore Base64 Decoder Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${fileName} |
| **File Path** | ${filePath} |
| **File Size** | ${formatBytes(fileSize)} |

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Matches** | ${matches.length} |
| **High Confidence** | ${highConfidence.length} |
| **Medium Confidence** | ${mediumConfidence.length} |
| **Possible** | ${possible.length} |
| **Printable (Text)** | ${printableMatches.length} |
| **Binary Data** | ${binaryMatches.length} |

---

`;

	// High confidence section
	if (highConfidence.length > 0) {
		report += `## High Confidence Matches\n\n`;
		for (const match of highConfidence.slice(0, 30)) {
			report += formatMatchEntry(match);
		}
		if (highConfidence.length > 30) {
			report += `*... and ${highConfidence.length - 30} more high-confidence matches*\n\n`;
		}
	}

	// Medium confidence section
	if (mediumConfidence.length > 0) {
		report += `## Medium Confidence Matches\n\n`;
		for (const match of mediumConfidence.slice(0, 20)) {
			report += formatMatchEntry(match);
		}
		if (mediumConfidence.length > 20) {
			report += `*... and ${mediumConfidence.length - 20} more medium-confidence matches*\n\n`;
		}
	}

	// Possible section (collapsed)
	if (possible.length > 0) {
		report += `## Possible Matches (Low Confidence)\n\n`;
		report += '| Offset | Length | Confidence | Entropy | Type |\n';
		report += '|--------|--------|------------|---------|------|\n';
		for (const match of possible.slice(0, 15)) {
			const typeLabel = match.isPrintable ? 'Text' : 'Binary';
			report += `| 0x${match.offset.toString(16).toUpperCase().padStart(8, '0')} | ${match.encoded.length} | ${match.confidence}% | ${match.entropy.toFixed(2)} | ${typeLabel} |\n`;
		}
		if (possible.length > 15) {
			report += `| ... | ... | ... | ... | *${possible.length - 15} more* |\n`;
		}
		report += '\n';
	}

	if (matches.length === 0) {
		report += '*No Base64 strings found.*\n';
	}

	report += `
---
*Generated by HexCore Base64 Decoder v2.0.0 — Confidence Scoring Engine*
`;

	return report;
}

function formatMatchEntry(match: Base64Match): string {
	const truncatedEncoded = match.encoded.length > 60
		? match.encoded.substring(0, 60) + '...'
		: match.encoded;
	const escapedDecoded = match.decoded
		.replace(/\|/g, '\\|')
		.replace(/\n/g, '\\n')
		.replace(/\r/g, '');

	let entry = `### Offset 0x${match.offset.toString(16).toUpperCase().padStart(8, '0')} — **${match.confidence}%** (${match.category.replace(/_/g, ' ')})

| Metric | Value |
|--------|-------|
| Confidence | **${match.confidence}%** |
| Category | ${match.category.replace(/_/g, ' ')} |
| Entropy | ${match.entropy.toFixed(2)} bits/byte |
| Type | ${match.isPrintable ? 'Printable Text' : 'Binary Data'} |
| Length | ${match.encoded.length} chars |

**Encoded:**
\`\`\`
${truncatedEncoded}
\`\`\`

`;

	if (match.isPrintable) {
		entry += `**Decoded:**
\`\`\`
${escapedDecoded.substring(0, 500)}${escapedDecoded.length > 500 ? '...' : ''}
\`\`\`

`;
	} else {
		entry += `**Decoded (hex):** \`${match.decodedHex}\`

`;
	}

	// Show scoring reasons
	entry += `<details><summary>Scoring breakdown</summary>\n\n`;
	for (const reason of match.reasons) {
		entry += `- ${reason}\n`;
	}
	entry += `\n</details>\n\n---\n\n`;

	return entry;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) { return '0 B'; }
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function deactivate() { }
