/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Scanner Extension v2.1
 *  YARA rule-based malware detection with DefenderYara integration
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { YaraEngine, RuleMatch, ScanResult } from './yaraEngine';
import { ResultsTreeProvider } from './resultsTree';
import { RulesTreeProvider } from './rulesTree';

let outputChannel: vscode.OutputChannel;

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface YaraScanCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

export function activate(context: vscode.ExtensionContext): void {
	const engine = new YaraEngine();
	const resultsProvider = new ResultsTreeProvider();
	const rulesProvider = new RulesTreeProvider();
	outputChannel = vscode.window.createOutputChannel('HexCore YARA');
	let defenderIndexTask: Promise<number> | undefined;
	const logActivationError = (scope: string, error: unknown): void => {
		outputChannel.appendLine(`[YARA] ${scope} failed: ${formatError(error)}`);
	};
	const ensureDefenderCatalogIndexed = async (basePath: string, forceReindex: boolean): Promise<number> => {
		if (defenderIndexTask) {
			outputChannel.appendLine('[YARA] DefenderYara indexing already running, waiting for completion...');
			return defenderIndexTask;
		}

		defenderIndexTask = (async () => {
			const count = engine.indexDefenderYara(basePath, forceReindex);
			rulesProvider.updateFromEngine(engine);
			return count;
		})();

		try {
			return await defenderIndexTask;
		} finally {
			defenderIndexTask = undefined;
		}
	};

	// Wire progress to output channel
	engine.setProgressCallback((msg: string) => {
		outputChannel.appendLine(`[YARA] ${msg}`);
	});

	try {
		context.subscriptions.push(
			vscode.window.registerTreeDataProvider('hexcore.yara.results', resultsProvider),
			vscode.window.registerTreeDataProvider('hexcore.yara.rules', rulesProvider)
		);
	} catch (error) {
		logActivationError('Tree provider registration', error);
	}

	// ── Load built-in rules ──────────────────────────────────────────────
	const rulesDir = path.join(context.extensionPath, 'rules');
	try {
		if (fs.existsSync(rulesDir)) {
			engine.loadRulesFromDirectory(rulesDir);
		}
	} catch (error) {
		logActivationError('Built-in rules load', error);
	}

	// ── Auto-detect DefenderYara ─────────────────────────────────────────
	const config = vscode.workspace.getConfiguration('hexcore.yara');
	const defenderPath = config.get<string>('defenderYaraPath', '');

	const autoDetectDefenderYara = async (): Promise<void> => {
		if (defenderPath && fs.existsSync(defenderPath)) {
			const count = await ensureDefenderCatalogIndexed(defenderPath, false);
			outputChannel.appendLine(`[YARA] DefenderYara indexed: ${count} rules`);
		} else {
			// Try common locations
			const commonPaths = [
				path.join(process.env.USERPROFILE || '', 'Desktop', 'DefenderYara-main'),
				path.join(process.env.USERPROFILE || '', 'Downloads', 'DefenderYara-main'),
				'C:\\DefenderYara-main',
			];
			for (const p of commonPaths) {
				if (fs.existsSync(p)) {
					outputChannel.appendLine(`[YARA] Auto-detected DefenderYara at: ${p}`);
					const count = await ensureDefenderCatalogIndexed(p, false);
					outputChannel.appendLine(`[YARA] DefenderYara indexed: ${count} rules`);
					break;
				}
			}
		}
	};
	void autoDetectDefenderYara().catch(error => {
		logActivationError('DefenderYara indexing', error);
	});

	// ── Command: Scan File ───────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.scan', async (arg?: vscode.Uri | YaraScanCommandOptions) => {
			const options = normalizeScanOptions(arg);
			const uri = await resolveScanTargetUri(arg, options);
			if (!uri) {
				return undefined;
			}

			const executeScan = async (): Promise<ScanResult> => {
				const result = await engine.scanFileWithResult(uri.fsPath);
				resultsProvider.setScanResult(result);
				if (options.output) {
					writeScanOutput(result, options.output);
				}
				return result;
			};

			if (options.quiet) {
				return executeScan();
			}

			outputChannel.show(true);

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'YARA Scanning...',
				cancellable: false
			}, async progress => {
				progress.report({ message: path.basename(uri.fsPath) });
				const result = await executeScan();

				if (result.matches.length > 0) {
					const severity = result.threatScore >= 75 ? '🔴' :
						result.threatScore >= 50 ? '🟠' :
							result.threatScore >= 25 ? '🟡' : '🟢';

					vscode.window.showWarningMessage(
						`${severity} YARA: ${result.matches.length} matches | Threat Score: ${result.threatScore}/100 | Time: ${result.scanTime}ms`,
						'Show Details'
					).then(action => {
						if (action === 'Show Details') {
							outputChannel.show(true);
							showThreatReport(result.file, result);
						}
					});
				} else {
					vscode.window.showInformationMessage(
						`🟢 YARA: Clean — no matches (${result.scanTime}ms)`
					);
				}
			});

			return undefined;
		})
	);

	// ── Command: Scan Workspace ──────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.scanWorkspace', async () => {
			const folders = vscode.workspace.workspaceFolders;
			if (!folders) {
				vscode.window.showErrorMessage('No workspace open');
				return;
			}

			outputChannel.show(true);

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'YARA Scanning Workspace...',
				cancellable: false
			}, async () => {
				const results = await engine.scanDirectory(folders[0].uri.fsPath);
				const allMatches: RuleMatch[] = [];
				for (const r of results) {
					allMatches.push(...r.matches);
				}
				resultsProvider.setResults(folders[0].uri.fsPath, allMatches);

				vscode.window.showInformationMessage(
					`YARA: Scanned workspace — ${results.length} files with matches, ${allMatches.length} total matches`
				);
			});
		})
	);

	// ── Command: Load DefenderYara ───────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.loadDefender', async () => {
			const input = await vscode.window.showOpenDialog({
				canSelectMany: false,
				canSelectFolders: true,
				canSelectFiles: false,
				openLabel: 'Select DefenderYara Folder'
			});

			if (!input || input.length === 0) { return; }

			const selectedPath = input[0].fsPath;
			outputChannel.show(true);

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'Indexing DefenderYara...',
				cancellable: false
			}, async () => {
				const count = await ensureDefenderCatalogIndexed(selectedPath, false);

				vscode.window.showInformationMessage(
					`DefenderYara: Indexed ${count} rules. Use "Load Category" to load specific rule sets.`
				);

				// Save path for next time
				await config.update('defenderYaraPath', selectedPath, vscode.ConfigurationTarget.Global);
			});
		})
	);

	// ── Command: Load Category ───────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.loadCategory', async () => {
			if (defenderIndexTask) {
				vscode.window.showInformationMessage('DefenderYara indexing is in progress. Please wait and try again.');
				await defenderIndexTask;
			}

			const stats = engine.getCatalogStats();

			if (stats.total === 0) {
				vscode.window.showWarningMessage('No DefenderYara rules indexed. Run "Load DefenderYara" first.');
				return;
			}

			const categories = Object.entries(stats.categories)
				.sort((a, b) => b[1] - a[1])
				.map(([cat, count]) => ({
					label: cat,
					description: `${count} rules`,
					detail: `Load all ${cat} detection rules`
				}));

			const selected = await vscode.window.showQuickPick(categories, {
				placeHolder: 'Select category to load',
				canPickMany: true
			});

			if (!selected || selected.length === 0) { return; }

			outputChannel.show(true);
			let totalLoaded = 0;

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'Loading YARA rules...',
				cancellable: false
			}, async (progress) => {
				for (const item of selected) {
					progress.report({ message: item.label });
					const count = engine.loadDefenderCategory(item.label);
					totalLoaded += count;
				}

				rulesProvider.updateFromEngine(engine);

				vscode.window.showInformationMessage(
					`Loaded ${totalLoaded} rules from ${selected.map(s => s.label).join(', ')}`
				);
			});
		})
	);

	// ── Command: Quick Scan (Essentials) ─────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.quickScan', async (uri?: vscode.Uri) => {
			if (!uri) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					openLabel: 'Quick Scan (Threat Essentials)'
				});
				if (uris && uris.length > 0) { uri = uris[0]; }
			}
			if (!uri) { return; }

			outputChannel.show(true);

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'Quick Threat Scan...',
				cancellable: false
			}, async (progress) => {
				// Load essential categories if not already loaded
				const stats = engine.getCatalogStats();
				if (stats.loaded === 0 && stats.total > 0) {
					progress.report({ message: 'Loading essential rules...' });
					engine.loadDefenderEssentials();
					rulesProvider.updateFromEngine(engine);
				}

				progress.report({ message: `Scanning ${path.basename(uri!.fsPath)}...` });
				const result = await engine.scanFileWithResult(uri!.fsPath);
				resultsProvider.setScanResult(result);

				showThreatReport(uri!.fsPath, result);

				const severity = result.threatScore >= 75 ? '🔴 CRITICAL' :
					result.threatScore >= 50 ? '🟠 HIGH' :
						result.threatScore >= 25 ? '🟡 MEDIUM' : '🟢 CLEAN';

				vscode.window.showWarningMessage(
					`${severity} | Score: ${result.threatScore}/100 | ${result.matches.length} matches | ${result.scanTime}ms`
				);
			});
		})
	);

	// ── Command: Update Rules ────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.updateRules', async () => {
			await engine.updateRules();
			rulesProvider.updateFromEngine(engine);
			vscode.window.showInformationMessage('YARA rules reloaded');
		})
	);

	// ── Command: Create Rule ─────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.createRule', async () => {
			const editor = vscode.window.activeTextEditor;
			if (!editor) { return; }

			const selection = editor.document.getText(editor.selection);
			if (!selection) {
				vscode.window.showWarningMessage('Select text to create rule from');
				return;
			}

			const ruleName = await vscode.window.showInputBox({
				prompt: 'Rule name',
				value: 'custom_rule'
			});

			if (ruleName) {
				const rule = engine.createRuleFromString(ruleName, selection);
				const doc = await vscode.workspace.openTextDocument({
					content: rule,
					language: 'yara'
				});
				await vscode.window.showTextDocument(doc);
			}
		})
	);

	// ── Command: Show Threat Report ──────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.threatReport', async () => {
			const lastResult = resultsProvider.getLastScanResult();
			if (!lastResult) {
				vscode.window.showInformationMessage('No scan results. Run a scan first.');
				return;
			}
			showThreatReport(lastResult.file, lastResult);
		})
	);

	// ── Auto-update on startup ───────────────────────────────────────────
	if (config.get<boolean>('autoUpdate', true)) {
		engine.updateRules().catch(error => logActivationError('Auto-update rules', error));
	}

	outputChannel.appendLine('[YARA] HexCore YARA v2.1 activated');
	outputChannel.appendLine(`[YARA] Built-in rules: ${engine.getAllRules().length}`);
	outputChannel.appendLine(`[YARA] DefenderYara catalog: ${engine.getCatalogStats().total} rules indexed`);
}

function normalizeScanOptions(arg?: vscode.Uri | YaraScanCommandOptions): YaraScanCommandOptions {
	if (!arg || arg instanceof vscode.Uri) {
		return {};
	}
	return arg;
}

async function resolveScanTargetUri(
	arg: vscode.Uri | YaraScanCommandOptions | undefined,
	options: YaraScanCommandOptions
): Promise<vscode.Uri | undefined> {
	if (arg instanceof vscode.Uri) {
		return arg;
	}

	if (typeof options.file === 'string' && options.file.length > 0) {
		return vscode.Uri.file(options.file);
	}

	const activeUri = vscode.window.activeTextEditor?.document.uri;
	if (activeUri && activeUri.scheme === 'file') {
		return activeUri;
	}

	if (options.quiet) {
		return undefined;
	}

	const uris = await vscode.window.showOpenDialog({
		canSelectMany: false,
		openLabel: 'Scan with YARA'
	});
	if (!uris || uris.length === 0) {
		return undefined;
	}
	return uris[0];
}

function writeScanOutput(result: ScanResult, output: CommandOutputOptions): void {
	const format = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(output.path, buildScanMarkdown(result), 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				file: result.file,
				threatScore: result.threatScore,
				scanTime: result.scanTime,
				fileSize: result.fileSize,
				categories: result.categories,
				matchCount: result.matches.length,
				matches: result.matches,
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

function buildScanMarkdown(result: ScanResult): string {
	const lines: string[] = [];
	lines.push('# YARA Scan Report');
	lines.push('');
	lines.push(`- File: \`${path.basename(result.file)}\``);
	lines.push(`- Path: \`${result.file}\``);
	lines.push(`- Size: ${formatBytes(result.fileSize)}`);
	lines.push(`- Scan Time: ${result.scanTime} ms`);
	lines.push(`- Threat Score: ${result.threatScore}/100`);
	lines.push(`- Match Count: ${result.matches.length}`);
	lines.push('');

	if (Object.keys(result.categories).length > 0) {
		lines.push('## Categories');
		lines.push('');
		for (const [category, count] of Object.entries(result.categories).sort((a, b) => b[1] - a[1])) {
			lines.push(`- ${category}: ${count}`);
		}
		lines.push('');
	}

	lines.push('## Matches');
	lines.push('');
	if (result.matches.length === 0) {
		lines.push('- No matches');
		lines.push('');
		return lines.join('\n');
	}

	for (const match of result.matches) {
		lines.push(`### ${match.ruleName}`);
		lines.push(`- Namespace: ${match.namespace}`);
		lines.push(`- Severity: ${match.severity}`);
		lines.push(`- Score: ${match.score}`);
		lines.push(`- Family: ${match.meta.family ?? 'unknown'}`);
		lines.push(`- Platform: ${match.meta.platform ?? 'unknown'}`);
		if (match.strings.length > 0) {
			lines.push('- Strings:');
			for (const str of match.strings.slice(0, 20)) {
				lines.push(`  - ${str.identifier} @ 0x${str.offset.toString(16).toUpperCase()}: ${str.data}`);
			}
			if (match.strings.length > 20) {
				lines.push(`  - ... and ${match.strings.length - 20} more`);
			}
		}
		lines.push('');
	}

	return lines.join('\n');
}

function formatBytes(bytes: number): string {
	if (!Number.isFinite(bytes) || bytes < 0) {
		return '0 B';
	}
	if (bytes < 1024) {
		return `${bytes} B`;
	}
	const units = ['KB', 'MB', 'GB', 'TB'];
	let value = bytes / 1024;
	let index = 0;
	while (value >= 1024 && index < units.length - 1) {
		value /= 1024;
		index++;
	}
	return `${value.toFixed(2)} ${units[index]}`;
}

// ── Threat Report ────────────────────────────────────────────────────────

function showThreatReport(filePath: string, result: { matches: RuleMatch[]; threatScore: number; scanTime: number; fileSize: number; categories: Record<string, number> }): void {
	const md = buildThreatReportMarkdown(filePath, result);
	vscode.workspace.openTextDocument({ content: md, language: 'markdown' }).then(doc => {
		vscode.window.showTextDocument(doc, { preview: true });
	});
}

function buildThreatReportMarkdown(filePath: string, result: { matches: RuleMatch[]; threatScore: number; scanTime: number; fileSize: number; categories: Record<string, number> }): string {
	const lines: string[] = [];
	const scoreLabel = result.threatScore > 70 ? '🔴 CRITICAL' :
		result.threatScore >= 30 ? '🟡 MEDIUM' : '🟢 CLEAN';

	lines.push('# HexCore Threat Report');
	lines.push('');
	lines.push('## Summary');
	lines.push('');
	lines.push(`| Field | Value |`);
	lines.push(`|-------|-------|`);
	lines.push(`| File | \`${path.basename(filePath)}\` |`);
	lines.push(`| Path | \`${filePath}\` |`);
	lines.push(`| Size | ${formatBytes(result.fileSize)} |`);
	lines.push(`| Scan Time | ${result.scanTime} ms |`);
	lines.push(`| Threat Score | **${result.threatScore}/100** (${scoreLabel}) |`);
	lines.push(`| Total Matches | ${result.matches.length} |`);
	lines.push('');

	// Threat score bar
	const barLen = 30;
	const filled = Math.round((result.threatScore / 100) * barLen);
	const bar = '█'.repeat(filled) + '░'.repeat(barLen - filled);
	lines.push(`\`[${bar}]\` ${result.threatScore}/100`);
	lines.push('');

	// Categories summary
	if (Object.keys(result.categories).length > 0) {
		lines.push('## Categories');
		lines.push('');
		lines.push('| Category | Detections |');
		lines.push('|----------|-----------|');
		for (const [category, count] of Object.entries(result.categories).sort((a, b) => b[1] - a[1])) {
			lines.push(`| ${category} | ${count} |`);
		}
		lines.push('');
	}

	// Matches detail
	lines.push('## Detections');
	lines.push('');

	if (result.matches.length === 0) {
		lines.push('✅ No threats detected.');
		lines.push('');
	} else {
		// Group by category
		const byCategory: Record<string, RuleMatch[]> = {};
		for (const m of result.matches) {
			const cat = m.namespace || 'Unknown';
			if (!byCategory[cat]) { byCategory[cat] = []; }
			byCategory[cat].push(m);
		}

		for (const [category, matches] of Object.entries(byCategory)) {
			lines.push(`### ${category} — ${matches.length} detection(s)`);
			lines.push('');

			for (const m of matches) {
				const icon = m.severity === 'critical' ? '🔴' :
					m.severity === 'high' ? '🟠' :
						m.severity === 'medium' ? '🟡' : '🟢';
				lines.push(`#### ${icon} ${m.ruleName}`);
				lines.push('');
				lines.push(`- **Family:** ${m.meta.family || 'unknown'}`);
				lines.push(`- **Severity:** ${m.severity}`);
				lines.push(`- **Score:** ${m.score}`);
				lines.push(`- **Platform:** ${m.meta.platform || 'unknown'}`);

				if (m.strings.length > 0) {
					lines.push('');
					lines.push('**String Matches:**');
					lines.push('');
					lines.push('| Identifier | Offset | Data |');
					lines.push('|-----------|--------|------|');
					for (const s of m.strings.slice(0, 20)) {
						const escaped = s.data.replace(/\|/g, '\\|').replace(/\n/g, '\\n');
						lines.push(`| ${s.identifier} | \`0x${s.offset.toString(16).toUpperCase()}\` | ${escaped} |`);
					}
					if (m.strings.length > 20) {
						lines.push(`| ... | | ${m.strings.length - 20} more |`);
					}
				}
				lines.push('');
			}
		}
	}

	// Recommendations
	lines.push('## Recommendations');
	lines.push('');
	if (result.threatScore > 70) {
		lines.push('⚠️ **High threat level detected.** Recommended actions:');
		lines.push('');
		lines.push('1. Isolate the file in a sandbox environment');
		lines.push('2. Run dynamic analysis with the HexCore Debugger');
		lines.push('3. Extract IOCs using the IOC Extractor');
		lines.push('4. Check strings for C2 indicators');
		lines.push('5. Submit to VirusTotal for cross-reference');
	} else if (result.threatScore >= 30) {
		lines.push('⚡ **Moderate threat indicators found.** Recommended actions:');
		lines.push('');
		lines.push('1. Review matched rules for false positives');
		lines.push('2. Analyze suspicious strings and API calls');
		lines.push('3. Check entropy for packed sections');
	} else {
		lines.push('✅ **Low or no threat detected.** The file appears clean based on loaded rules.');
		lines.push('');
		lines.push('Consider loading additional YARA rule categories for deeper analysis.');
	}
	lines.push('');

	lines.push('---');
	lines.push(`*Report generated at ${new Date().toLocaleString()} by HexCore YARA Scanner*`);

	return lines.join('\n');
}

export function deactivate(): void {
	// Cleanup
}

function formatError(error: unknown): string {
	if (error instanceof Error) {
		return error.stack || error.message;
	}
	return String(error);
}
