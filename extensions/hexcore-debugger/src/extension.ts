/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger Extension
 *  Dynamic analysis with debugger integration
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DebuggerViewProvider } from './debuggerView';
import { RegisterTreeProvider } from './registerTree';
import { MemoryTreeProvider } from './memoryTree';
import { DebugEngine } from './debugEngine';

export function activate(context: vscode.ExtensionContext): void {
	const engine = new DebugEngine();
	const debuggerView = new DebuggerViewProvider(context.extensionUri, engine);
	const registerProvider = new RegisterTreeProvider(engine);
	const memoryProvider = new MemoryTreeProvider(engine);

	// Register providers
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider('hexcore.debugger.view', debuggerView),
		vscode.window.registerTreeDataProvider('hexcore.debugger.registers', registerProvider),
		vscode.window.registerTreeDataProvider('hexcore.debugger.memory', memoryProvider)
	);

	// Commands
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.start', async () => {
			const uri = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Debug'
			});
			if (uri && uri[0]) {
				await engine.startDebugging(uri[0].fsPath);
				debuggerView.show();
				registerProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.attach', async () => {
			const pid = await vscode.window.showInputBox({
				prompt: 'Enter Process ID to attach'
			});
			if (pid) {
				await engine.attach(parseInt(pid));
				debuggerView.show();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.breakpoint', async () => {
			const addr = await vscode.window.showInputBox({
				prompt: 'Breakpoint address (hex)',
				placeHolder: '0x401000'
			});
			if (addr) {
				await engine.setBreakpoint(parseInt(addr.replace(/^0x/, ''), 16));
				vscode.window.showInformationMessage(`Breakpoint set at ${addr}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.stepInto', () => engine.stepInto()),
		vscode.commands.registerCommand('hexcore.debug.stepOver', () => engine.stepOver()),
		vscode.commands.registerCommand('hexcore.debug.continue', () => engine.continue())
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.traceAPI', async () => {
			await engine.enableAPITracing();
			vscode.window.showInformationMessage('API Tracing enabled');
		})
	);

	console.log('HexCore Debugger extension activated');
}

export function deactivate(): void {
	// Cleanup
}
