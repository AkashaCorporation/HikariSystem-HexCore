/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger Extension
 *  Emulation-based binary analysis using Unicorn engine
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { DebuggerViewProvider } from './debuggerView';
import { RegisterTreeProvider } from './registerTree';
import { MemoryTreeProvider } from './memoryTree';
import { DebugEngine } from './debugEngine';
import type { ArchitectureType } from './unicornWrapper';

export function activate(context: vscode.ExtensionContext): void {
	const engine = new DebugEngine();
	const debuggerView = new DebuggerViewProvider(context.extensionUri, engine);
	const registerProvider = new RegisterTreeProvider(engine);
	const memoryProvider = new MemoryTreeProvider(engine);

	const ensureEmulationAvailable = async (arch: ArchitectureType): Promise<boolean> => {
		const availability = await engine.getEmulationAvailability(arch);
		if (availability.available) {
			return true;
		}

		const detail = availability.error ? ` ${availability.error}` : '';
		vscode.window.showErrorMessage(
			vscode.l10n.t('Unicorn engine is not available.{0}', detail)
		);
		return false;
	};

	// Register providers
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider('hexcore.debugger.view', debuggerView),
		vscode.window.registerTreeDataProvider('hexcore.debugger.registers', registerProvider),
		vscode.window.registerTreeDataProvider('hexcore.debugger.memory', memoryProvider)
	);

	// Unicorn engine status
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.unicornStatus', async () => {
			const availability = await engine.getEmulationAvailability('x64');
			if (availability.available) {
				vscode.window.showInformationMessage(
					vscode.l10n.t('Unicorn engine is available for this session.')
				);
			} else {
				const detail = availability.error ?? vscode.l10n.t('Unavailable');
				vscode.window.showWarningMessage(
					vscode.l10n.t('Unicorn engine status: {0}', detail)
				);
			}
		})
	);

	// Emulate - auto-detect architecture
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
				if (!(await ensureEmulationAvailable('x64'))) {
					return;
				}
				try {
					await engine.startEmulation(uri[0].fsPath);
					debuggerView.show();
					registerProvider.refresh();
					memoryProvider.refresh();
					vscode.window.showInformationMessage('Emulation started');
				} catch (error: any) {
					vscode.window.showErrorMessage(`Emulation failed: ${error.message}`);
				}
			}
		})
	);

	// Emulate - choose architecture manually
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
				const architectureItems: Array<vscode.QuickPickItem & { arch: ArchitectureType }> = [
					{ label: 'x64', arch: 'x64' },
					{ label: 'x86', arch: 'x86' },
					{ label: 'arm64', arch: 'arm64' },
					{ label: 'arm', arch: 'arm' },
					{ label: 'mips', arch: 'mips' },
					{ label: 'riscv', arch: 'riscv' }
				];
				const selection = await vscode.window.showQuickPick(
					architectureItems,
					{ placeHolder: vscode.l10n.t("Select architecture") }
				);
				if (selection) {
					const arch = selection.arch;
					if (!(await ensureEmulationAvailable(arch))) {
						return;
					}
					try {
						await engine.startEmulation(uri[0].fsPath, arch);
						debuggerView.show();
						registerProvider.refresh();
						memoryProvider.refresh();
						vscode.window.showInformationMessage(`Emulation started (${arch})`);
					} catch (error: any) {
						vscode.window.showErrorMessage(`Emulation failed: ${error.message}`);
					}
				}
			}
		})
	);

	// Step instruction
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationStep', async () => {
			try {
				await engine.emulationStep();
				registerProvider.refresh();
				memoryProvider.refresh();
			} catch (error: any) {
				vscode.window.showErrorMessage(`Step failed: ${error.message}`);
			}
		})
	);

	// Continue execution
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulationContinue', async () => {
			try {
				await engine.emulationContinue();
				registerProvider.refresh();
				memoryProvider.refresh();
			} catch (error: any) {
				vscode.window.showErrorMessage(`Continue failed: ${error.message}`);
			}
		})
	);

	// Set breakpoint
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

	// Read memory
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

	// Set stdin buffer for ELF emulation
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.setStdin', async () => {
			const state = engine.getEmulationState();
			if (!state) {
				vscode.window.showWarningMessage('Start emulation before setting stdin buffer');
				return;
			}

			const input = await vscode.window.showInputBox({
				prompt: 'STDIN buffer for emulation (use \\n for new lines)',
				placeHolder: 'e.g. 123\\nhello\\n',
				value: ''
			});

			if (input === undefined) {
				return;
			}

			const decoded = decodeEscapedInput(input);
			engine.setStdinBuffer(decoded);
			vscode.window.showInformationMessage(`STDIN buffer set (${decoded.length} bytes)`);
		})
	);

	// Save snapshot
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

	// Restore snapshot
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.restoreSnapshot', () => {
			try {
				engine.restoreSnapshot();
				registerProvider.refresh();
				memoryProvider.refresh();
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

function decodeEscapedInput(value: string): string {
	return value
		.replace(/\\r/g, '\r')
		.replace(/\\n/g, '\n')
		.replace(/\\t/g, '\t')
		.replace(/\\\\/g, '\\');
}
