/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { analyzeELFFile, ELFAnalysis } from './elfParser';
import { buildMarkdownReport } from './elfReport';

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface ELFAnalyzeCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore ELF Analyzer extension activated');

	// Command: Analyze ELF file from explorer context menu or headless
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.elfanalyzer.analyze', async (arg?: vscode.Uri | ELFAnalyzeCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return undefined;
			}

			try {
				return await analyze(uri, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(vscode.l10n.t('Failed to analyze ELF file: {0}', toErrorMessage(error)));
				}
				throw error;
			}
		})
	);

	// Command: Analyze current active file as ELF
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.elfanalyzer.analyzeActive', async () => {
			const editor = vscode.window.activeTextEditor;
			if (editor) {
				return vscode.commands.executeCommand('hexcore.elfanalyzer.analyze', editor.document.uri);
			} else {
				vscode.window.showWarningMessage(vscode.l10n.t('No active file to analyze'));
				return undefined;
			}
		})
	);

	// Public API
	const api = {
		analyzeELFFile: analyzeELFFile
	};

	return api;
}

function normalizeOptions(arg?: vscode.Uri | ELFAnalyzeCommandOptions): ELFAnalyzeCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | ELFAnalyzeCommandOptions | undefined,
	options: ELFAnalyzeCommandOptions
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
		title: vscode.l10n.t('Select ELF file to analyze'),
		filters: {
			'ELF Files': ['elf', 'so', 'o', 'out'],
			'All Files': ['*']
		}
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

async function analyze(
	uri: vscode.Uri,
	options: ELFAnalyzeCommandOptions
): Promise<ELFAnalysis> {
	const runAnalysis = (): ELFAnalysis => analyzeELFFile(uri.fsPath);
	const analysis = options.quiet
		? runAnalysis()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: vscode.l10n.t('Analyzing ELF file...'),
				cancellable: false
			},
			async () => runAnalysis()
		);

	if (options.output) {
		writeOutput(analysis, options.output);
	}

	if (!options.quiet) {
		const markdown = buildMarkdownReport(analysis);
		const doc = await vscode.workspace.openTextDocument({
			content: markdown,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}

	return analysis;
}

function writeOutput(analysis: ELFAnalysis, output: CommandOutputOptions): void {
	const outputFormat = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (outputFormat === 'md') {
		fs.writeFileSync(output.path, buildMarkdownReport(analysis), 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(analysis, null, '\t'),
		'utf8'
	);
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

export function deactivate() { }
