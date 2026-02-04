/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { PEAnalyzerViewProvider } from './peAnalyzerView';
import { analyzePEFile } from './peParser';

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore PE Analyzer extension activated');

	// Register the webview provider for the sidebar
	const provider = new PEAnalyzerViewProvider(context.extensionUri);
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider('hexcore.peanalyzer.view', provider)
	);

	// Command: Analyze PE file from explorer context menu
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.peanalyzer.analyze', async (uri: vscode.Uri) => {
			if (!uri) {
				const files = await vscode.window.showOpenDialog({
					canSelectMany: false,
					filters: {
						'Executable Files': ['exe', 'dll', 'sys', 'ocx'],
						'All Files': ['*']
					}
				});
				if (files && files.length > 0) {
					uri = files[0];
				} else {
					return;
				}
			}

			try {
				vscode.window.withProgress({
					location: vscode.ProgressLocation.Notification,
					title: vscode.l10n.t("Analyzing PE file..."),
					cancellable: false
				}, async () => {
					const analysis = await analyzePEFile(uri.fsPath);
					provider.showAnalysis(analysis);
				});
			} catch (error: any) {
				vscode.window.showErrorMessage(`Failed to analyze PE file: ${error.message}`);
			}
		})
	);

	// Command: Analyze current active file
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.peanalyzer.analyzeActive', async () => {
			const editor = vscode.window.activeTextEditor;
			if (editor) {
				vscode.commands.executeCommand('hexcore.peanalyzer.analyze', editor.document.uri);
			} else {
				vscode.window.showWarningMessage('No active file to analyze');
			}
		})
	);
	// Public API
	const api = {
		analyzePEFile: analyzePEFile
	};

	return api;
}

export function deactivate() { }

