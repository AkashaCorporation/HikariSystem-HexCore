/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Scanner Extension
 *  YARA rule-based malware detection
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { YaraEngine, RuleMatch } from './yaraEngine';
import { ResultsTreeProvider, RuleMatchItem } from './resultsTree';
import { RulesTreeProvider } from './rulesTree';

export function activate(context: vscode.ExtensionContext): void {
	const engine = new YaraEngine();
	const resultsProvider = new ResultsTreeProvider();
	const rulesProvider = new RulesTreeProvider();

	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('hexcore.yara.results', resultsProvider),
		vscode.window.registerTreeDataProvider('hexcore.yara.rules', rulesProvider)
	);

	// Load built-in rules
	const rulesDir = path.join(context.extensionPath, 'rules');
	if (fs.existsSync(rulesDir)) {
		engine.loadRulesFromDirectory(rulesDir);
	}

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
			if (uri) {
				const results = await engine.scanFile(uri.fsPath);
				resultsProvider.setResults(uri.fsPath, results);
				
				if (results.length > 0) {
					vscode.window.showWarningMessage(`YARA: ${results.length} matches found!`);
				} else {
					vscode.window.showInformationMessage('YARA: No matches found');
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.scanWorkspace', async () => {
			const folders = vscode.workspace.workspaceFolders;
			if (!folders) {
				vscode.window.showErrorMessage('No workspace open');
				return;
			}
			
			// Scan all files in workspace
			const results = await engine.scanDirectory(folders[0].uri.fsPath);
			// Flatten all matches
			const allMatches: RuleMatch[] = [];
			for (const r of results) {
				allMatches.push(...r.matches);
			}
			resultsProvider.setResults(folders[0].uri.fsPath, allMatches);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.updateRules', async () => {
			await engine.updateRules();
			vscode.window.showInformationMessage('YARA rules updated');
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.yara.createRule', async () => {
			const editor = vscode.window.activeTextEditor;
			if (!editor) return;
			
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

	// Auto-update on startup
	const config = vscode.workspace.getConfiguration('hexcore.yara');
	if (config.get<boolean>('autoUpdate', true)) {
		engine.updateRules();
	}

	console.log('HexCore YARA extension activated');
}

export function deactivate(): void {
	// Cleanup
}
