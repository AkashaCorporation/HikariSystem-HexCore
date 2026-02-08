/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer v1.0.0
 *  Visual entropy analysis with ASCII graph
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface EntropyCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	blockSize?: number;
}

interface EntropyBlock {
	offset: number;
	size: number;
	entropy: number;
}

interface EntropySummary {
	averageEntropy: number;
	maxEntropy: number;
	minEntropy: number;
	highEntropyBlocks: EntropyBlock[];
	lowEntropyBlocks: EntropyBlock[];
	assessment: string;
	assessmentDetails: string;
}

interface EntropyAnalysisResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	blockSize: number;
	totalBlocks: number;
	blocks: EntropyBlock[];
	summary: EntropySummary;
	graph: string;
	reportMarkdown: string;
}

const DEFAULT_BLOCK_SIZE = 256;

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Entropy Analyzer extension activated');

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.entropy.analyze', async (arg?: vscode.Uri | EntropyCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return;
			}

			try {
				return await analyzeEntropy(uri, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`Entropy analysis failed: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);
}

function normalizeOptions(arg?: vscode.Uri | EntropyCommandOptions): EntropyCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | EntropyCommandOptions | undefined,
	options: EntropyCommandOptions
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
		title: 'Select file for entropy analysis'
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

async function analyzeEntropy(uri: vscode.Uri, options: EntropyCommandOptions): Promise<EntropyAnalysisResult> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);
	const blockSize = normalizeBlockSize(options.blockSize);

	const runAnalysis = async (): Promise<EntropyAnalysisResult> => {
		const stats = fs.statSync(filePath);
		const buffer = fs.readFileSync(filePath);

		const blocks: EntropyBlock[] = [];
		for (let offset = 0; offset < buffer.length; offset += blockSize) {
			const end = Math.min(offset + blockSize, buffer.length);
			const chunk = buffer.subarray(offset, end);
			blocks.push({
				offset,
				size: end - offset,
				entropy: calculateEntropy(chunk)
			});
		}

		const summary = summarizeEntropy(blocks);
		const graph = generateAsciiGraph(blocks, 60, 20);
		const report = generateEntropyReport(fileName, filePath, stats.size, blockSize, blocks, summary, graph);

		return {
			fileName,
			filePath,
			fileSize: stats.size,
			blockSize,
			totalBlocks: blocks.length,
			blocks,
			summary,
			graph,
			reportMarkdown: report
		};
	};

	const result = options.quiet
		? await runAnalysis()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: `Analyzing entropy of ${fileName}...`,
				cancellable: false
			},
			async progress => {
				progress.report({ increment: 30, message: 'Calculating entropy blocks...' });
				const analysis = await runAnalysis();
				progress.report({ increment: 70, message: 'Generating report...' });
				return analysis;
			}
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

function normalizeBlockSize(blockSize?: number): number {
	if (!blockSize || Number.isNaN(blockSize)) {
		return DEFAULT_BLOCK_SIZE;
	}
	return Math.min(65536, Math.max(16, Math.floor(blockSize)));
}

function summarizeEntropy(blocks: EntropyBlock[]): EntropySummary {
	if (blocks.length === 0) {
		return {
			averageEntropy: 0,
			maxEntropy: 0,
			minEntropy: 0,
			highEntropyBlocks: [],
			lowEntropyBlocks: [],
			assessment: 'Empty File',
			assessmentDetails: 'The selected file has no data blocks to analyze.'
		};
	}

	const entropies = blocks.map(block => block.entropy);
	const averageEntropy = entropies.reduce((acc, value) => acc + value, 0) / entropies.length;
	const maxEntropy = Math.max(...entropies);
	const minEntropy = Math.min(...entropies);
	const highEntropyBlocks = blocks.filter(block => block.entropy > 7.0);
	const lowEntropyBlocks = blocks.filter(block => block.entropy < 1.0);

	let assessment = 'Normal';
	let assessmentDetails = 'File appears to be uncompressed and unencrypted.';

	if (averageEntropy > 7.5) {
		assessment = 'Highly Encrypted/Compressed';
		assessmentDetails = 'Very high entropy suggests encryption or strong compression.';
	} else if (averageEntropy > 6.5) {
		assessment = 'Possibly Packed';
		assessmentDetails = 'Elevated entropy may indicate packing or compression.';
	} else if (highEntropyBlocks.length > blocks.length * 0.5) {
		assessment = 'Mixed Content';
		assessmentDetails = 'Significant portions have high entropy - possible encrypted sections.';
	}

	return {
		averageEntropy,
		maxEntropy,
		minEntropy,
		highEntropyBlocks,
		lowEntropyBlocks,
		assessment,
		assessmentDetails
	};
}

function writeOutput(result: EntropyAnalysisResult, output: CommandOutputOptions): void {
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
				blockSize: result.blockSize,
				totalBlocks: result.totalBlocks,
				summary: result.summary,
				blocks: result.blocks,
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

function calculateEntropy(buffer: Buffer): number {
	if (buffer.length === 0) {
		return 0;
	}

	const freq = new Array(256).fill(0);
	for (let i = 0; i < buffer.length; i++) {
		freq[buffer[i]]++;
	}

	let entropy = 0;
	for (let i = 0; i < 256; i++) {
		if (freq[i] > 0) {
			const p = freq[i] / buffer.length;
			entropy -= p * Math.log2(p);
		}
	}

	return entropy;
}

function generateEntropyReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	blockSize: number,
	blocks: EntropyBlock[],
	summary: EntropySummary,
	graph: string
): string {
	const highEntropyPercentage = blocks.length > 0
		? ((summary.highEntropyBlocks.length / blocks.length) * 100).toFixed(1)
		: '0.0';
	const lowEntropyPercentage = blocks.length > 0
		? ((summary.lowEntropyBlocks.length / blocks.length) * 100).toFixed(1)
		: '0.0';

	let report = `# HexCore Entropy Analysis Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${fileName} |
| **File Path** | ${filePath} |
| **File Size** | ${formatBytes(fileSize)} |
| **Block Size** | ${blockSize} bytes |
| **Total Blocks** | ${blocks.length} |

---

## Entropy Statistics

| Metric | Value |
|--------|-------|
| **Average Entropy** | ${summary.averageEntropy.toFixed(4)} / 8.00 |
| **Maximum Entropy** | ${summary.maxEntropy.toFixed(4)} |
| **Minimum Entropy** | ${summary.minEntropy.toFixed(4)} |
| **High Entropy Blocks (>7.0)** | ${summary.highEntropyBlocks.length} (${highEntropyPercentage}%) |
| **Low Entropy Blocks (<1.0)** | ${summary.lowEntropyBlocks.length} (${lowEntropyPercentage}%) |

---

## Assessment

**${summary.assessment}**

${summary.assessmentDetails}

---

## Entropy Graph

\`\`\`
${graph}
\`\`\`

**Legend:** Each column represents a block. Height shows entropy (0-8).
- Low entropy (0-3): Likely plaintext, null bytes, or repetitive data
- Medium entropy (3-6): Code, structured data
- High entropy (6-8): Encrypted, compressed, or random data

---

## High Entropy Regions (>7.0)

`;

	if (summary.highEntropyBlocks.length > 0) {
		report += '| Offset | Entropy |\n';
		report += '|--------|--------|\n';
		for (const block of summary.highEntropyBlocks.slice(0, 20)) {
			report += `| 0x${block.offset.toString(16).toUpperCase().padStart(8, '0')} | ${block.entropy.toFixed(4)} |\n`;
		}
		if (summary.highEntropyBlocks.length > 20) {
			report += `| ... | *${summary.highEntropyBlocks.length - 20} more regions* |\n`;
		}
	} else {
		report += '*No high entropy regions detected.*\n';
	}

	report += `
---

## Entropy Scale Reference

| Range | Typical Content |
|-------|-----------------|
| 0.0 - 1.0 | Null bytes, single repeated byte |
| 1.0 - 3.0 | Simple text, repetitive patterns |
| 3.0 - 5.0 | English text, source code |
| 5.0 - 6.5 | Compiled code, mixed content |
| 6.5 - 7.5 | Compressed data (ZIP, PNG) |
| 7.5 - 8.0 | Encrypted or random data |

---
*Generated by HexCore Entropy Analyzer v1.0.0*
`;

	return report;
}

function generateAsciiGraph(blocks: EntropyBlock[], width: number, height: number): string {
	const lines: string[] = [];

	const step = Math.max(1, Math.floor(blocks.length / width));
	const sampledBlocks: number[] = [];

	for (let i = 0; i < width && i * step < blocks.length; i++) {
		const startIdx = i * step;
		const endIdx = Math.min(startIdx + step, blocks.length);
		let maxEntropy = 0;
		for (let j = startIdx; j < endIdx; j++) {
			if (blocks[j].entropy > maxEntropy) {
				maxEntropy = blocks[j].entropy;
			}
		}
		sampledBlocks.push(maxEntropy);
	}

	for (let row = height - 1; row >= 0; row--) {
		const threshold = (row / height) * 8;
		let line = '';

		if (row === height - 1) {
			line = '8.0|';
		} else if (row === Math.floor(height / 2)) {
			line = '4.0|';
		} else if (row === 0) {
			line = '0.0|';
		} else {
			line = '   |';
		}

		for (const entropy of sampledBlocks) {
			if (entropy >= threshold) {
				if (entropy > 7.0) {
					line += '#';
				} else if (entropy > 5.0) {
					line += '=';
				} else if (entropy > 3.0) {
					line += '-';
				} else {
					line += '.';
				}
			} else {
				line += ' ';
			}
		}
		lines.push(line);
	}

	lines.push('   +' + '-'.repeat(sampledBlocks.length));
	lines.push('    0' + ' '.repeat(Math.floor(sampledBlocks.length / 2) - 3) + 'Offset' + ' '.repeat(Math.floor(sampledBlocks.length / 2) - 6) + 'EOF');

	return lines.join('\n');
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
