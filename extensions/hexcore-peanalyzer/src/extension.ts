/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { PEAnalyzerViewProvider } from './peAnalyzerView';
import { analyzePEFile, PEAnalysis } from './peParser';

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface PEAnalyzeCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore PE Analyzer extension activated');

	// Register the webview provider for the sidebar
	const provider = new PEAnalyzerViewProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider('hexcore.peanalyzer.view', provider)
	);

	// Command: Analyze PE file from explorer context menu
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.peanalyzer.analyze', async (arg?: vscode.Uri | PEAnalyzeCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return undefined;
			}

			try {
				return await analyze(uri, options, provider);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(vscode.l10n.t('Failed to analyze PE file: {0}', toErrorMessage(error)));
				}
				throw error;
			}
		})
	);

	// Command: Analyze current active file
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.peanalyzer.analyzeActive', async () => {
			const editor = vscode.window.activeTextEditor;
			if (editor) {
				return vscode.commands.executeCommand('hexcore.peanalyzer.analyze', editor.document.uri);
			} else {
				vscode.window.showWarningMessage(vscode.l10n.t('No active file to analyze'));
				return undefined;
			}
		})
	);

	// Backward-compatible alias used by automation docs/skills.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.pe.analyze', async (arg?: vscode.Uri | PEAnalyzeCommandOptions) => {
			return vscode.commands.executeCommand('hexcore.peanalyzer.analyze', arg);
		})
	);
	// Public API
	const api = {
		analyzePEFile: analyzePEFile
	};

	return api;
}

function normalizeOptions(arg?: vscode.Uri | PEAnalyzeCommandOptions): PEAnalyzeCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | PEAnalyzeCommandOptions | undefined,
	options: PEAnalyzeCommandOptions
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
		title: vscode.l10n.t('Select PE file to analyze'),
		filters: {
			'Executable Files': ['exe', 'dll', 'sys', 'ocx'],
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
	options: PEAnalyzeCommandOptions,
	provider: PEAnalyzerViewProvider
): Promise<PEAnalysis> {
	const runAnalysis = async (): Promise<PEAnalysis> => analyzePEFile(uri.fsPath);
	const analysis = options.quiet
		? await runAnalysis()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: vscode.l10n.t('Analyzing PE file...'),
				cancellable: false
			},
			async () => runAnalysis()
		);

	if (options.output) {
		writeOutput(analysis, options.output);
	}

	if (!options.quiet) {
		provider.showAnalysis(analysis);
	}

	return analysis;
}

function writeOutput(analysis: PEAnalysis, output: CommandOutputOptions): void {
	const outputFormat = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (outputFormat === 'md') {
		fs.writeFileSync(output.path, buildMarkdownReport(analysis), 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				...serializeForJson(analysis),
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

function serializeForJson(analysis: PEAnalysis): Record<string, unknown> {
	const parsed = JSON.parse(JSON.stringify(analysis, (_key, value) => {
		if (typeof value === 'bigint') {
			return value.toString();
		}

		if (isBufferJsonValue(value)) {
			return `[Buffer ${value.data.length} bytes]`;
		}

		return value;
	}));
	return isRecord(parsed) ? parsed : {};
}

function isBufferJsonValue(value: unknown): value is { type: 'Buffer'; data: number[] } {
	if (!value || typeof value !== 'object') {
		return false;
	}
	const candidate = value as { type?: unknown; data?: unknown };
	return candidate.type === 'Buffer' && Array.isArray(candidate.data);
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === 'object';
}

function buildMarkdownReport(analysis: PEAnalysis): string {
	const lines: string[] = [];
	lines.push('# PE Analysis Report');
	lines.push('');
	lines.push(`- File: \`${analysis.fileName}\``);
	lines.push(`- Path: \`${analysis.filePath}\``);
	lines.push(`- Size: ${analysis.fileSize} bytes`);
	lines.push(`- Is PE: ${analysis.isPE ? 'Yes' : 'No'}`);

	if (analysis.error) {
		lines.push(`- Error: ${analysis.error}`);
	}

	lines.push('');

	if (!analysis.isPE) {
		return lines.join('\n');
	}

	lines.push('## Summary');
	lines.push('');
	lines.push(`- Sections: ${analysis.sections.length}`);
	lines.push(`- Import DLLs: ${analysis.imports.length}`);
	lines.push(`- Exported Symbols: ${analysis.exports.length}`);
	lines.push(`- Entropy: ${analysis.entropy.toFixed(2)}`);
	lines.push(`- Packer Signatures: ${analysis.packerSignatures.length}`);
	lines.push(`- Suspicious Strings: ${analysis.suspiciousStrings.length}`);
	lines.push('');

	lines.push('## Sections');
	lines.push('');
	lines.push('| Name | VA | Raw Size | Entropy | Characteristics |');
	lines.push('|---|---:|---:|---:|---|');
	for (const section of analysis.sections) {
		lines.push(
			`| ${section.name} | 0x${section.virtualAddress.toString(16).toUpperCase()} | ${section.sizeOfRawData} | ${section.entropy.toFixed(2)} | ${section.characteristics.join(', ')} |`
		);
	}
	lines.push('');

	lines.push('## Imports');
	lines.push('');
	if (analysis.imports.length === 0) {
		lines.push('- None');
	} else {
		for (const imp of analysis.imports) {
			lines.push(`- ${imp.dllName} (${imp.functions.length})`);
		}
	}
	lines.push('');

	lines.push('## Security');
	lines.push('');
	if (analysis.mitigations.length === 0) {
		lines.push('- No mitigation data');
	} else {
		for (const mitigation of analysis.mitigations) {
			lines.push(`- ${mitigation.name}: ${mitigation.enabled ? 'Enabled' : 'Disabled'}`);
		}
	}
	lines.push('');

	if (analysis.packerSignatures.length > 0) {
		lines.push('## Packer Signatures');
		lines.push('');
		for (const signature of analysis.packerSignatures) {
			lines.push(`- ${signature}`);
		}
		lines.push('');
	}

	if (analysis.suspiciousStrings.length > 0) {
		lines.push('## Suspicious Strings (Top 100)');
		lines.push('');
		for (const value of analysis.suspiciousStrings.slice(0, 100)) {
			lines.push(`- \`${value}\``);
		}
		lines.push('');
	}

	return lines.join('\n');
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

export function deactivate() { }

