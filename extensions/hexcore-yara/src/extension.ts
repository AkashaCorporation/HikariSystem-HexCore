/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Scanner Extension v2.0
 *  YARA rule-based malware detection with DefenderYara integration
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { YaraEngine, RuleMatch } from './yaraEngine';
import { ResultsTreeProvider } from './resultsTree';
import { RulesTreeProvider } from './rulesTree';

let outputChannel: vscode.OutputChannel;

export function activate(context: vscode.ExtensionContext): void {
	const engine = new YaraEngine();
	const resultsProvider = new ResultsTreeProvider();
	const rulesProvider = new RulesTreeProvider();
	outputChannel = vscode.window.createOutputChannel('HexCore YARA');

	// Wire progress to output channel
	engine.setProgressCallback((msg: string) => {
		outputChannel.appendLine(`[YARA] ${msg}`);
	});

	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('hexcore.yara.results', resultsProvider),
		vscode.window.registerTreeDataProvider('hexcore.yara.rules', rulesProvider)
	);

	// ── Load built-in rules ──────────────────────────────────────────────
	const rulesDir = path.join(context.extensionPath, 'rules');
	if (fs.existsSync(rulesDir)) {
		engine.loadRulesFromDirectory(rulesDir);
	}

	// ── Auto-detect DefenderYara ─────────────────────────────────────────
	const config = vscode.workspace.getConfiguration('hexcore.yara');
	const defenderPath = config.get<string>('defenderYaraPath', '');

	if (defenderPath && fs.existsSync(defenderPath)) {
		const count = engine.indexDefenderYara(defenderPath);
		outputChannel.appendLine(`[YARA] DefenderYara indexed: ${count} rules`);
		rulesProvider.updateFromEngine(engine);
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
				const count = engine.indexDefenderYara(p);
				outputChannel.appendLine(`[YARA] DefenderYara indexed: ${count} rules`);
				rulesProvider.updateFromEngine(engine);
				break;
			}
		}
	}

	// ── Command: Scan File ───────────────────────────────────────────────
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.scan', async (uri?: vscode.Uri) => {
			if (!uri) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					openLabel: 'Scan with YARA'
				});
				if (uris && uris.length > 0) {
					uri = uris[0];
				}
			}
			if (!uri) { return; }

			outputChannel.show(true);

			await vscode.window.withProgress({
				location: vscode.ProgressLocation.Notification,
				title: 'YARA Scanning...',
				cancellable: false
			}, async (progress) => {
				progress.report({ message: path.basename(uri!.fsPath) });

				const result = await engine.scanFileWithResult(uri!.fsPath);
				resultsProvider.setScanResult(result);

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
				const count = engine.indexDefenderYara(selectedPath);
				rulesProvider.updateFromEngine(engine);

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
		engine.updateRules();
	}

	outputChannel.appendLine('[YARA] HexCore YARA v2.0 activated');
	outputChannel.appendLine(`[YARA] Built-in rules: ${engine.getAllRules().length}`);
	outputChannel.appendLine(`[YARA] DefenderYara catalog: ${engine.getCatalogStats().total} rules indexed`);
}

// ── Threat Report ────────────────────────────────────────────────────────

function showThreatReport(filePath: string, result: { matches: RuleMatch[]; threatScore: number; scanTime: number; fileSize: number; categories: Record<string, number> }): void {
	outputChannel.appendLine('');
	outputChannel.appendLine('═'.repeat(60));
	outputChannel.appendLine('  HEXCORE THREAT REPORT');
	outputChannel.appendLine('═'.repeat(60));
	outputChannel.appendLine(`  File:         ${path.basename(filePath)}`);
	outputChannel.appendLine(`  Path:         ${filePath}`);
	outputChannel.appendLine(`  Size:         ${(result.fileSize / 1024).toFixed(1)} KB`);
	outputChannel.appendLine(`  Scan Time:    ${result.scanTime}ms`);
	outputChannel.appendLine(`  Rules Tested: ${result.matches.length > 0 ? 'Multiple' : '0'}`);
	outputChannel.appendLine('─'.repeat(60));

	// Threat score bar
	const barLen = 40;
	const filled = Math.round((result.threatScore / 100) * barLen);
	const bar = '█'.repeat(filled) + '░'.repeat(barLen - filled);
	const scoreLabel = result.threatScore >= 75 ? 'CRITICAL' :
		result.threatScore >= 50 ? 'HIGH' :
		result.threatScore >= 25 ? 'MEDIUM' : 'CLEAN';
	outputChannel.appendLine(`  Threat Score: [${bar}] ${result.threatScore}/100 (${scoreLabel})`);
	outputChannel.appendLine('─'.repeat(60));

	if (result.matches.length === 0) {
		outputChannel.appendLine('  ✓ No threats detected');
	} else {
		// Group by category
		const byCategory: Record<string, RuleMatch[]> = {};
		for (const m of result.matches) {
			const cat = m.namespace || 'Unknown';
			if (!byCategory[cat]) { byCategory[cat] = []; }
			byCategory[cat].push(m);
		}

		for (const [category, matches] of Object.entries(byCategory)) {
			outputChannel.appendLine(`  [${category}] — ${matches.length} detection(s)`);
			for (const m of matches.slice(0, 10)) {
				const icon = m.severity === 'critical' ? '🔴' :
					m.severity === 'high' ? '🟠' :
					m.severity === 'medium' ? '🟡' : '🟢';
				outputChannel.appendLine(`    ${icon} ${m.ruleName} (${m.meta.family || 'unknown'}) — score: ${m.score}`);

				// Show first 3 string matches
				for (const s of m.strings.slice(0, 3)) {
					outputChannel.appendLine(`       ├─ ${s.identifier} @ 0x${s.offset.toString(16).toUpperCase()}: ${s.data}`);
				}
				if (m.strings.length > 3) {
					outputChannel.appendLine(`       └─ ... and ${m.strings.length - 3} more`);
				}
			}
			if (matches.length > 10) {
				outputChannel.appendLine(`    ... and ${matches.length - 10} more in this category`);
			}
		}
	}

	outputChannel.appendLine('═'.repeat(60));
	outputChannel.appendLine(`  Scan completed at ${new Date().toLocaleString()}`);
	outputChannel.appendLine('═'.repeat(60));
	outputChannel.appendLine('');
}

export function deactivate(): void {
	// Cleanup
}
