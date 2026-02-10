/*---------------------------------------------------------------------------------------------
 *  HexCore Minidump Parser v1.0.0
 *  Windows Minidump (MDMP) analysis for memory forensics
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { parseMinidump } from './mdmpParser';
import { generateMinidumpReport } from './reportGenerator';
import type {
	MinidumpAnalysisResult,
	MinidumpCommandOptions,
	CommandOutputOptions,
	OutputFormat,
} from './types';

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
	console.log('HexCore Minidump Parser v1.0.0 activated');

	// hexcore.minidump.parse — Full analysis
	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.minidump.parse',
			(arg?: vscode.Uri | MinidumpCommandOptions) => handleCommand(arg, 'full'),
		),
	);

	// hexcore.minidump.threads — Thread listing
	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.minidump.threads',
			(arg?: vscode.Uri | MinidumpCommandOptions) => handleCommand(arg, 'threads'),
		),
	);

	// hexcore.minidump.modules — Module listing
	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.minidump.modules',
			(arg?: vscode.Uri | MinidumpCommandOptions) => handleCommand(arg, 'modules'),
		),
	);

	// hexcore.minidump.memory — Memory regions
	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.minidump.memory',
			(arg?: vscode.Uri | MinidumpCommandOptions) => handleCommand(arg, 'memory'),
		),
	);
}

// ---------------------------------------------------------------------------
// Command Handler
// ---------------------------------------------------------------------------

type CommandMode = 'full' | 'threads' | 'modules' | 'memory';

async function handleCommand(
	arg: vscode.Uri | MinidumpCommandOptions | undefined,
	mode: CommandMode,
): Promise<MinidumpAnalysisResult | undefined> {
	const options = normalizeOptions(arg);
	const uri = await resolveTargetUri(arg, options);

	if (!uri) {
		return undefined;
	}

	try {
		return await runAnalysis(uri, options, mode);
	} catch (error: unknown) {
		const msg = toErrorMessage(error);
		if (!options.quiet) {
			vscode.window.showErrorMessage(`Minidump analysis failed: ${msg}`);
		}
		throw error;
	}
}

async function runAnalysis(
	uri: vscode.Uri,
	options: MinidumpCommandOptions,
	mode: CommandMode,
): Promise<MinidumpAnalysisResult> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);

	const doAnalysis = async (
		progress?: vscode.Progress<{ message?: string; increment?: number }>,
	): Promise<MinidumpAnalysisResult> => {
		progress?.report({ message: 'Parsing MDMP header...' });

		const core = parseMinidump(filePath);

		progress?.report({ increment: 50, message: 'Generating report...' });

		const result: MinidumpAnalysisResult = {
			...core,
			fileName,
			reportMarkdown: '',
		};
		result.reportMarkdown = generateMinidumpReport(result);

		progress?.report({ increment: 50, message: 'Done.' });
		return result;
	};

	const result = options.quiet
		? await doAnalysis()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: `Analyzing Minidump: ${fileName}`,
				cancellable: false,
			},
			async (progress) => doAnalysis(progress),
		);

	// Write output file (headless pipeline)
	if (options.output) {
		writeOutput(result, options.output, mode);
	}

	// Show report (interactive mode)
	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: result.reportMarkdown,
			language: 'markdown',
		});
		await vscode.window.showTextDocument(doc, { preview: false });

		// Summary notification
		const threatCount = result.threats.rwxRegions.length +
			result.threats.suspiciousStartAddresses.length;
		if (threatCount > 0) {
			vscode.window.showWarningMessage(
				`⚠️ ${threatCount} threat indicator(s) found in ${fileName}`
			);
		} else {
			vscode.window.showInformationMessage(
				`Minidump analysis complete: ${result.threads.length} threads, ` +
				`${result.modules.length} modules, ${result.memoryRegions.length} memory regions.`
			);
		}
	}

	return result;
}

// ---------------------------------------------------------------------------
// Output Serialization
// ---------------------------------------------------------------------------

function writeOutput(
	result: MinidumpAnalysisResult,
	output: CommandOutputOptions,
	mode: CommandMode,
): void {
	const format = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(output.path, result.reportMarkdown, 'utf8');
		return;
	}

	// JSON — filter by mode for smaller output
	const data = buildJsonOutput(result, mode);
	fs.writeFileSync(output.path, JSON.stringify(data, bigIntReplacer, 2), 'utf8');
}

function buildJsonOutput(result: MinidumpAnalysisResult, mode: CommandMode): unknown {
	const base = {
		fileName: result.fileName,
		filePath: result.filePath,
		fileSize: result.fileSize,
		dumpTimestamp: result.header.timestamp,
		systemInfo: result.systemInfo,
		generatedAt: new Date().toISOString(),
	};

	switch (mode) {
		case 'threads':
			return { ...base, threads: result.threads, threadExInfo: result.threadExInfo };
		case 'modules':
			return { ...base, modules: result.modules };
		case 'memory':
			return { ...base, memoryRegions: result.memoryRegions, threats: { rwxRegions: result.threats.rwxRegions } };
		default:
			return {
				...base,
				threads: result.threads,
				threadExInfo: result.threadExInfo,
				modules: result.modules,
				memoryRegions: result.memoryRegions,
				threats: result.threats,
			};
	}
}

/** JSON.stringify replacer that converts BigInt to hex strings. */
function bigIntReplacer(_key: string, value: unknown): unknown {
	if (typeof value === 'bigint') {
		return `0x${value.toString(16).toUpperCase()}`;
	}
	return value;
}

// ---------------------------------------------------------------------------
// Option Resolution
// ---------------------------------------------------------------------------

function normalizeOptions(arg?: vscode.Uri | MinidumpCommandOptions): MinidumpCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | MinidumpCommandOptions | undefined,
	options: MinidumpCommandOptions,
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
		title: 'Select Minidump (.dmp) file',
		filters: { 'Minidump Files': ['dmp', 'mdmp'], 'All Files': ['*'] },
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

export function deactivate(): void { }
