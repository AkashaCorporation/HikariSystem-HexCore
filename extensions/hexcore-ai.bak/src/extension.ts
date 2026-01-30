/*---------------------------------------------------------------------------------------------
 *  HexCore AI Assistant Extension
 *  AI-powered reverse engineering assistant
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { AIChatProvider } from './aiChatProvider';
import { AIAnalysisEngine } from './aiEngine';
import { InsightsTreeProvider } from './insightsTree';

export function activate(context: vscode.ExtensionContext): void {
	const engine = new AIAnalysisEngine(context);
	const chatProvider = new AIChatProvider(context.extensionUri, engine);
	const insightsProvider = new InsightsTreeProvider(engine);

	// Register Webview Provider
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			'hexcore.ai.chat',
			chatProvider,
			{ webviewOptions: { retainContextWhenHidden: true } }
		)
	);

	// Register Tree Provider
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('hexcore.ai.insights', insightsProvider)
	);

	// Register Commands
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.ask', async () => {
			const question = await vscode.window.showInputBox({
				prompt: 'Ask Kimi Assistant',
				placeHolder: 'e.g., What does this function do?'
			});
			if (question) {
				chatProvider.show();
				await chatProvider.askQuestion(question);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.analyzeFunction', async () => {
			chatProvider.show();
			const result = await engine.analyzeCurrentFunction();
			chatProvider.addMessage('assistant', result);
			insightsProvider.refresh();
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.explainCode', async () => {
			chatProvider.show();
			const result = await engine.explainCurrentCode();
			chatProvider.addMessage('assistant', result);
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.findVulns', async () => {
			chatProvider.show();
			chatProvider.addMessage('user', '🔍 Find vulnerabilities in this binary');
			const result = await engine.findVulnerabilities();
			chatProvider.addMessage('assistant', result);
			insightsProvider.refresh();
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.generateExploit', async () => {
			const vulnType = await vscode.window.showQuickPick([
				{ label: 'Buffer Overflow', value: 'buffer_overflow' },
				{ label: 'Format String', value: 'format_string' },				{ label: 'Use-After-Free', value: 'uaf' },
				{ label: 'Integer Overflow', value: 'integer_overflow' },
				{ label: 'Command Injection', value: 'command_injection' }
			], { placeHolder: 'Select vulnerability type' });

			if (vulnType) {
				chatProvider.show();
				chatProvider.addMessage('user', `🎯 Generate ${vulnType.label} exploit template`);
				const result = await engine.generateExploit(vulnType.value);
				chatProvider.addMessage('assistant', result);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.ctfHint', async () => {
			const challenge = await vscode.window.showInputBox({
				prompt: 'Describe the CTF challenge',
				placeHolder: 'e.g., Binary exploitation, stack overflow, no canary...'
			});
			if (challenge) {
				chatProvider.show();
				chatProvider.addMessage('user', `🏁 CTF Help: ${challenge}`);
				const result = await engine.getCTFHint(challenge);
				chatProvider.addMessage('assistant', result);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.scanBinary', async () => {
			const uri = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Scan with AI',
				filters: { 'Binaries': ['exe', 'dll', 'elf', 'so', 'bin'] }
			});
			if (uri && uri[0]) {
				chatProvider.show();
				chatProvider.addMessage('user', `📊 Full analysis of ${uri[0].fsPath}`);
				const result = await engine.fullBinaryAnalysis(uri[0].fsPath);
				chatProvider.addMessage('assistant', result);
				insightsProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.clearChat', () => {
			chatProvider.clearChat();
		})
	);

	// Event listeners for auto-analysis
	let autoAnalyze = vscode.workspace.getConfiguration('hexcore.ai').get<boolean>('autoAnalyze', false);
	
	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration(e => {
			if (e.affectsConfiguration('hexcore.ai.autoAnalyze')) {
				autoAnalyze = vscode.workspace.getConfiguration('hexcore.ai').get<boolean>('autoAnalyze', false);
			}
		})
	);

	// Listen for disassembler navigation
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.ai.onNavigate', async (address: number) => {
			if (autoAnalyze) {
				const result = await engine.quickAnalyze(address);
				insightsProvider.addInsight('function', `Function at 0x${address.toString(16)}`, result.summary);
			}
		})
	);

	console.log('HexCore AI Assistant extension activated');
}

export function deactivate(): void {
	// Cleanup
}
