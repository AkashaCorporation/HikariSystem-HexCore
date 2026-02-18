/*---------------------------------------------------------------------------------------------
 *  HexCore Base64 Decoder v1.0.0
 *  Detect and decode Base64 encoded strings
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

interface Base64Match {
	offset: number;
	encoded: string;
	decoded: string;
	decodedHex: string;
	isPrintable: boolean;
}

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Base64 Decoder extension activated');

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

			const matches = scanFileForBase64(filePath);

			const result = {
				filePath,
				matches,
				totalMatches: matches.length,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`HexCore Base64: Found ${matches.length} Base64 string(s) in ${path.basename(filePath)}`
				);
			}

			return result;
		})
	);
}

/**
 * Scan a file for Base64 strings using streaming with 1MB chunks and 4KB overlap.
 * Reusable core logic extracted from decodeBase64InFile.
 */
function scanFileForBase64(filePath: string): Base64Match[] {
	const stats = fs.statSync(filePath);
	const MAX_FILE_SIZE = 512 * 1024 * 1024; // 512MB safety limit

	if (stats.size > MAX_FILE_SIZE) {
		throw new Error(`File is ${(stats.size / (1024 * 1024)).toFixed(0)}MB — exceeds limit of 512MB.`);
	}

	const CHUNK_SIZE = 1024 * 1024; // 1MB chunks
	const OVERLAP = 4096; // overlap to catch base64 spanning chunk boundaries
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

			// Keep tail as carryover for next chunk
			carryover = readLen >= OVERLAP ? combined.slice(-OVERLAP) : '';
		}
	} finally {
		fs.closeSync(fd);
	}

	// Deduplicate matches that may appear in overlap regions
	const seen = new Set<string>();
	allMatches = allMatches.filter(m => {
		const key = `${m.offset}:${m.match.slice(0, 64)}`;
		if (seen.has(key)) { return false; }
		seen.add(key);
		return true;
	});

	return decodeMatches(allMatches);
}

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

			const decodedMatches = scanFileForBase64(filePath);

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

function findBase64Strings(content: string): Array<{ offset: number; match: string }> {
	const results: Array<{ offset: number; match: string }> = [];

	// Base64 pattern: 20-4096 chars, valid base64 alphabet
	// Upper bound prevents ReDoS on adversarial input
	const base64Regex = /[A-Za-z0-9+/]{20,4096}={0,2}/g;

	let match;
	while ((match = base64Regex.exec(content)) !== null) {
		// Validate it's actually Base64 (length must be divisible by 4 or close)
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
	// Must be at least 20 chars
	if (str.length < 20) return false;

	// Check for proper Base64 structure
	const withoutPadding = str.replace(/=+$/, '');

	// Should have mostly valid base64 chars
	const validChars = withoutPadding.replace(/[A-Za-z0-9+/]/g, '');
	if (validChars.length > 0) return false;

	// Try to decode and check if result makes sense
	try {
		const decoded = Buffer.from(str, 'base64');

		// Check if decoded length is reasonable
		if (decoded.length < 10) return false;

		// Reject if too many null bytes (likely not real base64)
		const nullCount = decoded.filter(b => b === 0).length;
		if (nullCount > decoded.length * 0.5) return false;

		return true;
	} catch {
		return false;
	}
}

function decodeMatches(matches: Array<{ offset: number; match: string }>): Base64Match[] {
	const results: Base64Match[] = [];

	for (const { offset, match } of matches) {
		try {
			const decoded = Buffer.from(match, 'base64');
			const decodedStr = decoded.toString('utf8');
			const decodedHex = decoded.toString('hex').toUpperCase();

			// Check if decoded is printable
			let printableCount = 0;
			for (const byte of decoded) {
				if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10 || byte === 13) {
					printableCount++;
				}
			}
			const isPrintable = printableCount > decoded.length * 0.7;

			results.push({
				offset,
				encoded: match,
				decoded: isPrintable ? decodedStr : '[Binary Data]',
				decodedHex: decodedHex.substring(0, 64) + (decodedHex.length > 64 ? '...' : ''),
				isPrintable
			});
		} catch {
			// Skip invalid base64
		}
	}

	return results;
}

function generateReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	matches: Base64Match[]
): string {
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

| Type | Count |
|------|-------|
| **Total Base64 Strings** | ${matches.length} |
| **Printable (Text)** | ${printableMatches.length} |
| **Binary Data** | ${binaryMatches.length} |

---

## Decoded Strings (Printable)

`;

	if (printableMatches.length > 0) {
		for (const match of printableMatches.slice(0, 50)) {
			const truncatedEncoded = match.encoded.length > 60
				? match.encoded.substring(0, 60) + '...'
				: match.encoded;
			const escapedDecoded = match.decoded
				.replace(/\|/g, '\\|')
				.replace(/\n/g, '\\n')
				.replace(/\r/g, '');

			report += `### Offset 0x${match.offset.toString(16).toUpperCase().padStart(8, '0')}

**Encoded:**
\`\`\`
${truncatedEncoded}
\`\`\`

**Decoded:**
\`\`\`
${escapedDecoded.substring(0, 500)}${escapedDecoded.length > 500 ? '...' : ''}
\`\`\`

---

`;
		}
		if (printableMatches.length > 50) {
			report += `*... and ${printableMatches.length - 50} more printable strings*\n\n`;
		}
	} else {
		report += '*No printable Base64 strings found.*\n\n';
	}

	report += `## Binary Data (First 10)

`;

	if (binaryMatches.length > 0) {
		report += '| Offset | Length | First Bytes (Hex) |\n';
		report += '|--------|--------|------------------|\n';
		for (const match of binaryMatches.slice(0, 10)) {
			report += `| 0x${match.offset.toString(16).toUpperCase().padStart(8, '0')} | ${match.encoded.length} | \`${match.decodedHex}\` |\n`;
		}
		if (binaryMatches.length > 10) {
			report += `| ... | ... | *${binaryMatches.length - 10} more* |\n`;
		}
	} else {
		report += '*No binary Base64 data found.*\n';
	}

	report += `

---
*Generated by HexCore Base64 Decoder v1.0.0*
`;

	return report;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) return '0 B';
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

export function deactivate() { }
