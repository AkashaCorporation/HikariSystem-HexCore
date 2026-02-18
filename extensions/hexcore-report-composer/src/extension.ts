/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { ReportAggregator, ComposedReport } from './reportAggregator';

/**
 * Options for the composeReport command.
 */
interface ComposeReportArgs {
	/** Workspace root path (optional, uses current workspace). */
	file?: string;
	/** Explicit reports directory path (overrides default hexcore-reports/). */
	reportsDir?: string;
	/** Path to analyst notes file. */
	notes?: string;
	/** Output destination. */
	output?: { path: string };
	/** Suppress UI messages. */
	quiet?: boolean;
}

/**
 * Activates the HexCore Report Composer extension.
 */
export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore Report Composer extension activated');

	const aggregator = new ReportAggregator();

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.pipeline.composeReport', async (args?: ComposeReportArgs) => {
			const options = args ?? {};

			try {
				return await composeReport(aggregator, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(
						vscode.l10n.t('Failed to compose report: {0}', toErrorMessage(error))
					);
				}
				throw error;
			}
		})
	);

	// Public API
	const api = {
		ReportAggregator
	};

	return api;
}


/**
 * Resolves the workspace root directory.
 */
function resolveWorkspaceRoot(file?: string): string {
	if (typeof file === 'string' && file.length > 0) {
		return path.dirname(file);
	}

	const folders = vscode.workspace.workspaceFolders;
	if (folders && folders.length > 0) {
		return folders[0].uri.fsPath;
	}

	throw new Error('No workspace folder open. Provide a workspace root via the "file" option.');
}

/**
 * Reads analyst notes from a file path.
 */
function readAnalystNotes(notesPath: string): string {
	if (!fs.existsSync(notesPath)) {
		throw new Error(`Analyst notes file not found: ${notesPath}`);
	}
	return fs.readFileSync(notesPath, 'utf8');
}

/**
 * Core logic for the composeReport command.
 */
async function composeReport(
	aggregator: ReportAggregator,
	options: ComposeReportArgs
): Promise<ComposedReport> {
	const workspaceRoot = resolveWorkspaceRoot(options.file);

	// Resolve reports directory in priority order:
	// 1. Explicit reportsDir argument (from pipeline or user)
	// 2. outDir inferred from output.path parent directory
	// 3. Default: {workspace}/hexcore-reports/
	let reportsDir: string;
	if (typeof options.reportsDir === 'string' && options.reportsDir.length > 0) {
		reportsDir = path.isAbsolute(options.reportsDir)
			? options.reportsDir
			: path.resolve(workspaceRoot, options.reportsDir);
	} else if (options.output && typeof options.output.path === 'string') {
		// When called from pipeline, output.path is inside outDir — use its parent
		reportsDir = path.dirname(options.output.path);
	} else {
		reportsDir = path.join(workspaceRoot, 'hexcore-reports');
	}

	// Validate reports directory exists
	if (!fs.existsSync(reportsDir)) {
		throw new Error(`No reports found. Directory does not exist: ${reportsDir}`);
	}

	// Scan for report files
	const sources = aggregator.scanReportsDirectory(reportsDir);
	if (sources.length === 0) {
		throw new Error('No reports found in hexcore-reports/. Directory is empty or contains no .md/.json files.');
	}

	// Read analyst notes if provided
	let notes: string | undefined;
	if (typeof options.notes === 'string' && options.notes.length > 0) {
		notes = readAnalystNotes(options.notes);
	}

	// Compose the report
	const runCompose = () => {
		const report = aggregator.compose(sources, notes);
		return report;
	};

	const report = options.quiet
		? runCompose()
		: await vscode.window.withProgress(
			{
				location: vscode.ProgressLocation.Notification,
				title: vscode.l10n.t('Composing analysis report...'),
				cancellable: false
			},
			async () => runCompose()
		);

	// Generate Markdown
	const markdown = aggregator.toMarkdown(report);

	// Save to output path if provided
	if (options.output) {
		fs.mkdirSync(path.dirname(options.output.path), { recursive: true });
		fs.writeFileSync(options.output.path, markdown, 'utf8');
	}

	// Open in new tab if not quiet
	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: markdown,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}

	return report;
}

/**
 * Extracts a human-readable error message.
 */
function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

/**
 * Deactivates the HexCore Report Composer extension.
 */
export function deactivate() { }
