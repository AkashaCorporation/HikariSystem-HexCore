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

	// ============================================================================
	// Emulation Mode Commands (Unicorn Engine)
	// ============================================================================

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulate', async () => {
			const uri = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Emulate',
				filters: {
					'Executables': ['exe', 'dll', 'so', 'bin', 'elf'],
					'All Files': ['*']
				}
			});
			if (uri && uri[0]) {
				try {
					await engine.startEmulation(uri[0].fsPath);
					debuggerView.show();
					registerProvider.refresh();
					vscode.window.showInformationMessage('Emulation started');
				} catch (error: any) {
					vscode.window.showErrorMessage(`Emulation failed: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulateWithArch', async () => {
			const uri = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Emulate',
				filters: {
					'Executables': ['exe', 'dll', 'so', 'bin', 'elf'],
					'All Files': ['*']
				}
			});
			if (uri && uri[0]) {
				const arch = await vscode.window.showQuickPick(
					['x64', 'x86', 'arm64', 'arm', 'mips', 'riscv'],
					{ placeHolder: 'Select architecture' }
				);
				if (arch) {
					try {
						await engine.startEmulation(uri[0].fsPath, arch as any);
						debuggerView.show();
						registerProvider.refresh();
						vscode.window.showInformationMessage(`Emulation started (${arch})`);
					} catch (error: any) {
						vscode.window.showErrorMessage(`Emulation failed: ${error.message}`);
					}
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationStep', async () => {
			try {
				await engine.emulationStep();
				registerProvider.refresh();
			} catch (error: any) {
				vscode.window.showErrorMessage(`Step failed: ${error.message}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationContinue', async () => {
			try {
				await engine.emulationContinue();
				registerProvider.refresh();
			} catch (error: any) {
				vscode.window.showErrorMessage(`Continue failed: ${error.message}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationBreakpoint', async () => {
			const addr = await vscode.window.showInputBox({
				prompt: 'Breakpoint address (hex)',
				placeHolder: '0x401000'
			});
			if (addr) {
				try {
					const address = BigInt(addr.startsWith('0x') ? addr : '0x' + addr);
					engine.emulationSetBreakpoint(address);
					vscode.window.showInformationMessage(`Breakpoint set at ${addr}`);
				} catch (error: any) {
					vscode.window.showErrorMessage(`Failed to set breakpoint: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationReadMemory', async () => {
			const addr = await vscode.window.showInputBox({
				prompt: 'Memory address (hex)',
				placeHolder: '0x400000'
			});
			if (addr) {
				const size = await vscode.window.showInputBox({
					prompt: 'Size in bytes',
					value: '256'
				});
				if (size) {
					try {
						const address = BigInt(addr.startsWith('0x') ? addr : '0x' + addr);
						const data = engine.emulationReadMemory(address, parseInt(size));
						const hexView = formatHexDump(data, address);
						const doc = await vscode.workspace.openTextDocument({
							content: hexView,
							language: 'hexdump'
						});
						await vscode.window.showTextDocument(doc);
					} catch (error: any) {
						vscode.window.showErrorMessage(`Failed to read memory: ${error.message}`);
					}
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.saveSnapshot', () => {
			try {
				engine.saveSnapshot();
				vscode.window.showInformationMessage('Snapshot saved');
			} catch (error: any) {
				vscode.window.showErrorMessage(`Failed to save snapshot: ${error.message}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.restoreSnapshot', () => {
			try {
				engine.restoreSnapshot();
				registerProvider.refresh();
				vscode.window.showInformationMessage('Snapshot restored');
			} catch (error: any) {
				vscode.window.showErrorMessage(`Failed to restore snapshot: ${error.message}`);
			}
		})
	);

	console.log('HexCore Debugger extension activated');
}

/**
 * Format buffer as hex dump
 */
function formatHexDump(data: Buffer, baseAddress: bigint): string {
	const lines: string[] = [];
	const bytesPerLine = 16;

	for (let i = 0; i < data.length; i += bytesPerLine) {
		const addr = (baseAddress + BigInt(i)).toString(16).padStart(16, '0').toUpperCase();
		const bytes: string[] = [];
		let ascii = '';

		for (let j = 0; j < bytesPerLine; j++) {
			if (i + j < data.length) {
				const byte = data[i + j];
				bytes.push(byte.toString(16).padStart(2, '0').toUpperCase());
				ascii += (byte >= 0x20 && byte <= 0x7E) ? String.fromCharCode(byte) : '.';
			} else {
				bytes.push('  ');
				ascii += ' ';
			}
		}

		const hex = bytes.slice(0, 8).join(' ') + '  ' + bytes.slice(8).join(' ');
		lines.push(`${addr}  ${hex}  |${ascii}|`);
	}

	return lines.join('\n');
}

export function deactivate(): void {
	// Cleanup
}
