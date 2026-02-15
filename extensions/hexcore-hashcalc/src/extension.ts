/*---------------------------------------------------------------------------------------------
 *  HexCore Hash Calculator v1.1.0
 *  Calculate MD5, SHA1, SHA256, SHA512 hashes with algorithm selection
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha512';
type OutputFormat = 'json' | 'md';

interface HashResults {
	[key: string]: string;
}

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface HashCommandOptions {
	file?: string;
	algorithms?: HashAlgorithm[] | 'all' | 'quick';
	output?: CommandOutputOptions;
	quiet?: boolean;
}

interface HashCalculationResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	timestamp: string;
	algorithms: HashAlgorithm[];
	hashes: HashResults;
	reportMarkdown: string;
}

const ALL_ALGORITHMS: HashAlgorithm[] = ['md5', 'sha1', 'sha256', 'sha512'];
const QUICK_ALGORITHMS: HashAlgorithm[] = ['sha256'];

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Hash Calculator v1.1.0 activated');

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hashcalc.calculate', async (arg?: vscode.Uri | HashCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options, 'Select file to hash');
			if (!uri) {
				return;
			}

			const selectedAlgorithms = await resolveAlgorithmsForCalculate(options);
			if (!selectedAlgorithms) {
				return;
			}

			try {
				return await calculateHashes(uri, selectedAlgorithms, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`Failed to calculate hashes: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hashcalc.quick', async (arg?: vscode.Uri | HashCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options, 'Select file for quick hash (SHA-256)');
			if (!uri) {
				return;
			}

			try {
				const result = await calculateHashes(uri, QUICK_ALGORITHMS, options);
				if (!options.quiet) {
					const hash = result.hashes.sha256;
					if (hash) {
						await vscode.env.clipboard.writeText(hash);
						vscode.window.showInformationMessage(`SHA-256: ${hash} (copied to clipboard)`);
					}
				}
				return result;
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`Failed to calculate hash: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hashcalc.verify', async () => {
			const expectedHash = await vscode.window.showInputBox({
				prompt: 'Enter the expected hash to verify',
				placeHolder: 'e.g., d41d8cd98f00b204e9800998ecf8427e'
			});

			if (!expectedHash) {
				return;
			}

			const files = await vscode.window.showOpenDialog({
				canSelectMany: false,
				canSelectFiles: true,
				title: 'Select file to verify'
			});

			if (!files || files.length === 0) {
				return;
			}

			await verifyHash(files[0], expectedHash.trim().toLowerCase());
		})
	);

	// Backward-compatible aliases used by automation/skills.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hash.file', async (arg?: vscode.Uri | HashCommandOptions) => {
			return vscode.commands.executeCommand('hexcore.hashcalc.calculate', arg);
		}),
		vscode.commands.registerCommand('hexcore.hash.calculate', async (arg?: vscode.Uri | HashCommandOptions) => {
			return vscode.commands.executeCommand('hexcore.hashcalc.calculate', arg);
		})
	);
}

function normalizeOptions(arg?: vscode.Uri | HashCommandOptions): HashCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | HashCommandOptions | undefined,
	options: HashCommandOptions,
	dialogTitle: string
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
		canSelectFolders: false,
		title: dialogTitle
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

async function resolveAlgorithmsForCalculate(options: HashCommandOptions): Promise<HashAlgorithm[] | undefined> {
	if (options.algorithms) {
		return normalizeAlgorithms(options.algorithms);
	}

	if (options.quiet) {
		return ALL_ALGORITHMS;
	}

	const algorithmChoice = await vscode.window.showQuickPick(
		[
			{ label: 'All (MD5, SHA-1, SHA-256, SHA-512)', value: 'all', picked: true },
			{ label: 'MD5', value: 'md5' },
			{ label: 'SHA-1', value: 'sha1' },
			{ label: 'SHA-256', value: 'sha256' },
			{ label: 'SHA-512', value: 'sha512' },
			{ label: 'Quick (MD5 + SHA-256)', value: 'quick' },
		],
		{
			placeHolder: 'Select hash algorithm(s)',
			title: 'HexCore Hash Calculator'
		}
	);

	if (!algorithmChoice) {
		return undefined;
	}

	return normalizeAlgorithms(algorithmChoice.value as HashCommandOptions['algorithms']);
}

function normalizeAlgorithms(value: HashCommandOptions['algorithms']): HashAlgorithm[] {
	if (value === 'all') {
		return [...ALL_ALGORITHMS];
	}
	if (value === 'quick') {
		return ['md5', 'sha256'];
	}
	if (Array.isArray(value)) {
		const filtered = value.filter(isHashAlgorithm);
		return filtered.length > 0 ? filtered : [...ALL_ALGORITHMS];
	}
	if (isHashAlgorithm(value)) {
		return [value];
	}
	return [...ALL_ALGORITHMS];
}

function isHashAlgorithm(value: unknown): value is HashAlgorithm {
	return value === 'md5' || value === 'sha1' || value === 'sha256' || value === 'sha512';
}

async function calculateHashes(
	uri: vscode.Uri,
	algorithms: HashAlgorithm[],
	options: HashCommandOptions
): Promise<HashCalculationResult> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);

	const runCalculation = async (onProgress?: (percent: number) => void): Promise<HashCalculationResult> => {
		const stats = fs.statSync(filePath);
		const hashes = await calculateHashesStreaming(filePath, algorithms, onProgress);
		const timestamp = new Date().toISOString();
		const report = generateHashReport(fileName, filePath, stats.size, hashes, algorithms, timestamp);

		return {
			fileName,
			filePath,
			fileSize: stats.size,
			timestamp,
			algorithms,
			hashes,
			reportMarkdown: report
		};
	};

	const result = options.quiet
		? await runCalculation()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: `Calculating hashes for ${fileName}...`,
				cancellable: false
			},
			async progress => runCalculation(percent => {
				progress.report({ message: `Processing... ${Math.round(percent)}%` });
			})
		);

	if (options.output) {
		writeOutput(result, options.output);
	}

	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: result.reportMarkdown,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}

	return result;
}

async function calculateSingleHash(filePath: string, algorithm: HashAlgorithm): Promise<string> {
	return new Promise((resolve, reject) => {
		const hash = crypto.createHash(algorithm);
		const stream = fs.createReadStream(filePath);

		stream.on('data', (chunk: Buffer) => hash.update(chunk));
		stream.on('end', () => resolve(hash.digest('hex')));
		stream.on('error', reject);
	});
}

async function calculateHashesStreaming(
	filePath: string,
	algorithms: HashAlgorithm[],
	onProgress?: (percent: number) => void
): Promise<HashResults> {
	return new Promise((resolve, reject) => {
		const hashers: Map<HashAlgorithm, crypto.Hash> = new Map();

		for (const algorithm of algorithms) {
			hashers.set(algorithm, crypto.createHash(algorithm));
		}

		const stats = fs.statSync(filePath);
		const totalSize = stats.size;
		let bytesRead = 0;

		const stream = fs.createReadStream(filePath);

		stream.on('data', (chunk: Buffer) => {
			for (const hasher of hashers.values()) {
				hasher.update(chunk);
			}

			bytesRead += chunk.length;
			if (onProgress && totalSize > 0) {
				onProgress((bytesRead / totalSize) * 100);
			}
		});

		stream.on('end', () => {
			const results: HashResults = {};
			for (const [algorithm, hasher] of hashers) {
				results[algorithm] = hasher.digest('hex');
			}
			resolve(results);
		});

		stream.on('error', reject);
	});
}

function writeOutput(result: HashCalculationResult, output: CommandOutputOptions): void {
	const outputFormat = normalizeOutputFormat(output.path, output.format);

	// Validate output path is within workspace or user home to prevent arbitrary writes
	const resolvedPath = path.resolve(output.path);
	const workspaceFolders = vscode.workspace.workspaceFolders;
	const homeDir = require('os').homedir();
	const isInWorkspace = workspaceFolders?.some(f => resolvedPath.startsWith(f.uri.fsPath));
	const isInHome = resolvedPath.startsWith(homeDir);
	if (!isInWorkspace && !isInHome) {
		throw new Error(`Output path must be within workspace or user home directory: ${resolvedPath}`);
	}

	fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

	if (outputFormat === 'md') {
		fs.writeFileSync(resolvedPath, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				fileName: result.fileName,
				filePath: result.filePath,
				fileSize: result.fileSize,
				timestamp: result.timestamp,
				algorithms: result.algorithms,
				hashes: result.hashes
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

function generateHashReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	hashes: HashResults,
	algorithms: HashAlgorithm[],
	timestamp: string
): string {
	const sizeFormatted = formatBytes(fileSize);

	let report = `# HexCore Hash Calculator Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${fileName} |
| **File Path** | ${filePath} |
| **File Size** | ${sizeFormatted} (${fileSize.toLocaleString()} bytes) |
| **Calculated** | ${timestamp} |
| **Algorithms** | ${algorithms.map(algorithm => algorithm.toUpperCase()).join(', ')} |

---

## Hash Values

`;

	const algoNames: Record<HashAlgorithm, string> = {
		md5: 'MD5',
		sha1: 'SHA-1',
		sha256: 'SHA-256',
		sha512: 'SHA-512'
	};

	for (const algorithm of algorithms) {
		if (hashes[algorithm]) {
			report += `### ${algoNames[algorithm]}
\`\`\`
${hashes[algorithm]}
\`\`\`

`;
		}
	}

	report += `---

## Quick Copy

| Algorithm | Hash |
|-----------|------|
`;

	for (const algorithm of algorithms) {
		if (hashes[algorithm]) {
			report += `| ${algoNames[algorithm]} | \`${hashes[algorithm]}\` |\n`;
		}
	}

	report += `
---

## VirusTotal Links

`;

	if (hashes.md5) {
		report += `- [Search MD5 on VirusTotal](https://www.virustotal.com/gui/search/${hashes.md5})\n`;
	}
	if (hashes.sha256) {
		report += `- [Search SHA-256 on VirusTotal](https://www.virustotal.com/gui/search/${hashes.sha256})\n`;
	}

	report += `
---
*Generated by HexCore Hash Calculator v1.1.0*
`;

	return report;
}

async function verifyHash(uri: vscode.Uri, expectedHash: string): Promise<void> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);

	await vscode.window.withProgress({
		location: vscode.ProgressLocation.Notification,
		title: `Verifying hash for ${fileName}...`,
		cancellable: false
	}, async () => {
		try {
			let hashType: HashAlgorithm;
			let hashTypeName: string;

			switch (expectedHash.length) {
				case 32:
					hashType = 'md5';
					hashTypeName = 'MD5';
					break;
				case 40:
					hashType = 'sha1';
					hashTypeName = 'SHA-1';
					break;
				case 64:
					hashType = 'sha256';
					hashTypeName = 'SHA-256';
					break;
				case 128:
					hashType = 'sha512';
					hashTypeName = 'SHA-512';
					break;
				default:
					vscode.window.showErrorMessage(
						`Unknown hash format (${expectedHash.length} characters). Expected MD5 (32), SHA-1 (40), SHA-256 (64), or SHA-512 (128).`
					);
					return;
			}

			const calculatedHash = await calculateSingleHash(filePath, hashType);

			if (calculatedHash === expectedHash) {
				vscode.window.showInformationMessage(`MATCH: ${hashTypeName} hash verified successfully for ${fileName}`);
			} else {
				vscode.window.showWarningMessage(
					`MISMATCH: ${hashTypeName} hash does NOT match!\n\nExpected: ${expectedHash}\nCalculated: ${calculatedHash}`
				);
			}
		} catch (error: unknown) {
			vscode.window.showErrorMessage(`Failed to verify hash: ${toErrorMessage(error)}`);
		}
	});
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
