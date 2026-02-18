/*---------------------------------------------------------------------------------------------
 *  HexCore IOC Extractor v1.1.0
 *  Automatic extraction of Indicators of Compromise from binary files
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { extractIOCs } from './iocExtractor';
import { generateIOCReport } from './reportGenerator';
import type {
	IOCCategory,
	IOCCommandOptions,
	IOCExtractionResult,
	CommandOutputOptions,
	OutputFormat,
	ALL_IOC_CATEGORIES,
} from './types';
import { ALL_IOC_CATEGORIES as ALL_CATEGORIES } from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_MAX_MATCHES = 10_000;

/** Quick pick labels for IOC categories. */
const CATEGORY_PICK_LABELS: Record<IOCCategory, string> = {
	ipv4: 'IPv4 Addresses',
	ipv6: 'IPv6 Addresses',
	url: 'URLs',
	domain: 'Domains',
	email: 'Email Addresses',
	hash: 'Hashes (MD5 / SHA-1 / SHA-256)',
	filePath: 'File Paths',
	registryKey: 'Registry Keys',
	namedPipe: 'Named Pipes',
	mutex: 'Mutexes / GUIDs',
	userAgent: 'User Agents',
	cryptoWallet: 'Crypto Wallets',
};

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

export function activate(context: vscode.ExtensionContext): void {
	console.log('HexCore IOC Extractor v1.1.0 activated');

	context.subscriptions.push(
		vscode.commands.registerCommand(
			'hexcore.ioc.extract',
			async (arg?: vscode.Uri | IOCCommandOptions) => {
				const options = normalizeOptions(arg);
				const uri = await resolveTargetUri(arg, options);
				if (!uri) {
					return undefined;
				}

				// Interactive category selection via quick pick (Req 12.3)
				if (!options.quiet && !options.categories) {
					const picked = await pickCategories();
					if (!picked) {
						return undefined; // user cancelled
					}
					options.categories = picked;
				}

				try {
					return await runExtraction(uri, options);
				} catch (error: unknown) {
					if (!options.quiet) {
						vscode.window.showErrorMessage(
							`IOC extraction failed: ${toErrorMessage(error)}`
						);
					}
					throw error;
				}
			}
		),

		vscode.commands.registerCommand(
			'hexcore.ioc.extractActive',
			async () => {
				const uri = getActiveFileUri();
				if (!uri) {
					vscode.window.showWarningMessage('No active file to extract IOCs from.');
					return undefined;
				}

				try {
					return await runExtraction(uri, {});
				} catch (error: unknown) {
					vscode.window.showErrorMessage(
						`IOC extraction failed: ${toErrorMessage(error)}`
					);
					throw error;
				}
			}
		),
	);
}

// ---------------------------------------------------------------------------
// Option Resolution
// ---------------------------------------------------------------------------

function normalizeOptions(arg?: vscode.Uri | IOCCommandOptions): IOCCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | IOCCommandOptions | undefined,
	options: IOCCommandOptions,
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
		title: 'Select file for IOC extraction',
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

function resolveCategories(options: IOCCommandOptions): IOCCategory[] {
	if (Array.isArray(options.categories) && options.categories.length > 0) {
		return options.categories.filter(c => ALL_CATEGORIES.includes(c));
	}
	return [...ALL_CATEGORIES];
}

/**
 * Show a multi-select quick pick for IOC category selection.
 * Returns the selected categories, or undefined if the user cancelled.
 */
async function pickCategories(): Promise<IOCCategory[] | undefined> {
	const items: (vscode.QuickPickItem & { category: IOCCategory })[] =
		ALL_CATEGORIES.map(cat => ({
			label: CATEGORY_PICK_LABELS[cat],
			category: cat,
			picked: true,
		}));

	const selected = await vscode.window.showQuickPick(items, {
		canPickMany: true,
		title: 'Select IOC Categories',
		placeHolder: 'Choose which IOC categories to extract (all selected by default)',
	});

	if (!selected || selected.length === 0) {
		return undefined;
	}

	return selected.map(item => item.category);
}

// ---------------------------------------------------------------------------
// Extraction Orchestration
// ---------------------------------------------------------------------------

async function runExtraction(
	uri: vscode.Uri,
	options: IOCCommandOptions,
): Promise<IOCExtractionResult | undefined> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);
	const categories = resolveCategories(options);
	const excludePrivate = options.excludePrivate ?? false;
	const maxMatches = normalizeMaxMatches(options.maxMatches);

	const doExtraction = async (
		progress?: vscode.Progress<{ message?: string; increment?: number }>,
		token?: vscode.CancellationToken,
	): Promise<IOCExtractionResult> => {
		let lastPercent = 0;

		const core = extractIOCs({
			filePath,
			categories,
			excludePrivate,
			maxMatches,
			storageMode: options.storageMode,
			sqlitePath: options.sqlitePath,
			sqliteThresholdMatches: options.sqliteThresholdMatches,
			sqliteThresholdFileSizeMB: options.sqliteThresholdFileSizeMB,
			onProgress: event => {
				if (!progress) { return; }
				const increment = Math.max(0, event.percent - lastPercent);
				lastPercent = event.percent;
				progress.report({
					increment,
					message: `${event.percent}% — ${event.indicatorsFound} IOCs found`,
				});
			},
			isCancelled: () => token?.isCancellationRequested ?? false,
		});

		if (core.cancelled) {
			return buildCancelledResult(fileName, filePath, core.fileSize, categories);
		}

		const result: IOCExtractionResult = {
			fileName,
			filePath,
			fileSize: core.fileSize,
			storageBackend: core.storageBackend,
			summary: core.summary,
			indicators: core.indicators,
			reportMarkdown: '',
		};
		result.reportMarkdown = generateIOCReport(result);
		return result;
	};

	const result = options.quiet
		? await doExtraction()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: `Extracting IOCs from ${fileName}...`,
				cancellable: true,
			},
			async (progress, token) => {
				progress.report({ message: 'Scanning binary...' });
				return doExtraction(progress, token);
			}
		);

	// Cancelled — bail out
	if (result.summary.uniqueIndicators === 0 && !options.quiet) {
		vscode.window.showInformationMessage(`No IOCs found in ${fileName}.`);
		return result;
	}

	// Write output file if requested (headless pipeline)
	if (options.output) {
		writeOutput(result, options.output);
	}

	// Show report in editor (interactive mode)
	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: result.reportMarkdown,
			language: 'markdown',
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}

	return result;
}

// ---------------------------------------------------------------------------
// Output Serialization
// ---------------------------------------------------------------------------

function writeOutput(result: IOCExtractionResult, output: CommandOutputOptions): void {
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
				storageBackend: result.storageBackend,
				summary: result.summary,
				indicators: result.indicators,
				generatedAt: new Date().toISOString(),
			},
			null,
			2,
		),
		'utf8',
	);
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function normalizeMaxMatches(value?: number): number {
	if (value === undefined || !Number.isFinite(value)) {
		return DEFAULT_MAX_MATCHES;
	}
	return Math.max(10, Math.floor(value));
}

function buildCancelledResult(
	fileName: string,
	filePath: string,
	fileSize: number,
	categories: IOCCategory[],
): IOCExtractionResult {
	const indicators = Object.create(null) as Record<IOCCategory, never[]>;
	const categoryCounts = Object.create(null) as Record<IOCCategory, number>;
	for (const cat of categories) {
		indicators[cat] = [];
		categoryCounts[cat] = 0;
	}

	return {
		fileName,
		filePath,
		fileSize,
		storageBackend: 'memory',
		summary: {
			totalIndicators: 0,
			uniqueIndicators: 0,
			categoryCounts,
			truncated: false,
		},
		indicators,
		reportMarkdown: `# IOC Extraction Cancelled\n\nExtraction was cancelled by the user.\n`,
	};
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

export function deactivate(): void { }
