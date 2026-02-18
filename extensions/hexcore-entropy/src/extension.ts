/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer v1.1.0
 *  Visual entropy analysis with graph for detecting packed or encrypted regions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { analyzeEntropyFile } from './entropyAnalyzer';
import { generateAsciiGraph } from './graphGenerator';
import { generateEntropyReport } from './reportGenerator';
import { EntropyWebviewProvider } from './entropyWebviewProvider';
import {
	CommandOutputOptions,
	EntropyAnalysisResult,
	EntropyCommandOptions,
	OutputFormat
} from './types';

export function activate(context: vscode.ExtensionContext): void {
	console.log('HexCore Entropy Analyzer extension activated');

	const entropyViewProvider = new EntropyWebviewProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			EntropyWebviewProvider.viewType,
			entropyViewProvider
		)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.entropy.analyze', async (arg?: vscode.Uri | EntropyCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return undefined;
			}

			try {
				const result = await analyzeEntropy(uri, options);
				entropyViewProvider.showAnalysis(result);
				return result;
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

	const runAnalysis = async (
		progress?: vscode.Progress<{ message?: string; increment?: number }>
	): Promise<EntropyAnalysisResult> => {
		let lastProgress = 0;
		const core = await analyzeEntropyFile(filePath, {
			blockSize: options.blockSize,
			sampleRatio: options.sampleRatio,
			onProgress: event => {
				if (!progress) {
					return;
				}
				const increment = Math.max(0, event.percent - lastProgress);
				lastProgress = event.percent;
				progress.report({
					increment,
					message: `Processed ${formatBytes(event.processedBytes)} / ${formatBytes(event.totalBytes)}`
				});
			}
		});

		const graph = generateAsciiGraph(core.blocks, 60, 20);
		const result: EntropyAnalysisResult = {
			...core,
			fileName,
			graph,
			reportMarkdown: ''
		};
		result.reportMarkdown = generateEntropyReport(result);
		return result;
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
				progress.report({ message: 'Reading file in chunks...' });
				const analysis = await runAnalysis(progress);
				progress.report({ increment: 100, message: 'Generating report...' });
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
				cryptoSignals: result.cryptoSignals,
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

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes < 0) {
		return '0 B';
	}
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

export function deactivate(): void { }
