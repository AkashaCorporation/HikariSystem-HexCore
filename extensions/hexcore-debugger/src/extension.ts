/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger Extension
 *  Emulation-based binary analysis using Unicorn engine
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';
import { DebuggerViewProvider } from './debuggerView';
import { RegisterTreeProvider } from './registerTree';
import { MemoryTreeProvider } from './memoryTree';
import { DebugEngine } from './debugEngine';
import { TraceTreeProvider } from './traceView';
import type { ArchitectureType } from './unicornWrapper';

export function activate(context: vscode.ExtensionContext): void {
	const engine = new DebugEngine();
	const debuggerView = new DebuggerViewProvider(context.extensionUri, engine);
	const registerProvider = new RegisterTreeProvider(engine);
	const memoryProvider = new MemoryTreeProvider(engine);
	const traceProvider = new TraceTreeProvider(engine.getTraceManager());

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
		vscode.window.registerTreeDataProvider('hexcore.debugger.memory', memoryProvider),
		vscode.window.registerTreeDataProvider('hexcore.debugger.trace', traceProvider)
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
						const data = await engine.emulationReadMemory(address, parseInt(size));
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

	// ============================================================================
	// Headless Commands (Pipeline-safe, no UI prompts)
	// ============================================================================

	// Emulate Headless — start emulation from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulateHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			if (!filePath) {
				throw new Error('emulateHeadless requires a "file" argument.');
			}

			const arch = typeof arg?.arch === 'string' ? arg.arch as ArchitectureType : undefined;
			const stdin = typeof arg?.stdin === 'string' ? arg.stdin : undefined;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			await engine.startEmulation(filePath, arch);

			if (stdin) {
				engine.setStdinBuffer(stdin);
			}

			const state = engine.getEmulationState();
			const regions = await engine.getMemoryRegions();

			const exportData = {
				file: filePath,
				architecture: engine.getArchitecture(),
				fileType: engine.getFileType(),
				entryPoint: state ? '0x' + state.currentAddress.toString(16) : '0x0',
				memoryRegions: regions.map(r => ({
					address: '0x' + r.address.toString(16),
					size: r.size,
					permissions: r.permissions,
					name: r.name
				})),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Emulation started: ${engine.getArchitecture()} ${engine.getFileType()}`);
			}

			return exportData;
		})
	);

	// Continue Headless — run until breakpoint, exit, or error
	// Wraps emulationContinue in a crash-safe handler that captures state on failure.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.continueHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;
			const maxSteps = typeof arg?.maxSteps === 'number' ? arg.maxSteps : 0;

			const stateBefore = engine.getEmulationState();
			if (!stateBefore) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			const instrBefore = stateBefore.instructionsExecuted;
			let crashed = false;
			let crashError = '';

			if (maxSteps > 0) {
				// Counted mode: single emuStart call with count=N (avoids hook add/delete churn)
				try {
					await engine.emulationRunCounted(maxSteps);
				} catch (error: any) {
					crashed = true;
					crashError = error.message || String(error);
				}
			} else {
				// Full continue (uses continueElfSafely internally)
				try {
					await engine.emulationContinue();
				} catch (error: any) {
					crashed = true;
					crashError = error.message || String(error);
				}
			}

			const stateAfter = engine.getEmulationState();
			const registers = engine.getFullRegisters();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();

			const exportData = {
				crashed,
				crashError: crashError || undefined,
				state: stateAfter ? {
					isRunning: stateAfter.isRunning,
					isPaused: stateAfter.isPaused,
					currentAddress: '0x' + stateAfter.currentAddress.toString(16),
					instructionsExecuted: stateAfter.instructionsExecuted,
					lastError: stateAfter.lastError
				} : null,
				instructionsRan: (stateAfter?.instructionsExecuted ?? 0) - instrBefore,
				registers,
				apiCalls: apiCalls.map(c => ({
					dll: c.dll,
					name: c.name,
					returnValue: '0x' + (c.returnValue ?? 0n).toString(16)
				})),
				stdout,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				const status = crashed ? `CRASHED: ${crashError}` : 'OK';
				vscode.window.showInformationMessage(
					`Emulation ${status}: ${exportData.instructionsRan} instructions, ${apiCalls.length} API calls`
				);
			}

			return exportData;
		})
	);

	// Step Headless — execute N instructions
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.stepHeadless', async (arg?: Record<string, unknown>) => {
			const count = typeof arg?.count === 'number' ? arg.count : 1;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			const steps: Array<{ address: string; registers: Record<string, string> }> = [];

			for (let i = 0; i < count; i++) {
				await engine.emulationStep();
				const regs = engine.getFullRegisters();
				const s = engine.getEmulationState();
				steps.push({
					address: s ? '0x' + s.currentAddress.toString(16) : '0x0',
					registers: regs
				});

				// Stop if emulation ended
				if (s && !s.isRunning) {
					break;
				}
			}

			const finalState = engine.getEmulationState();
			const exportData = {
				stepsRequested: count,
				stepsExecuted: steps.length,
				steps,
				finalState: finalState ? {
					currentAddress: '0x' + finalState.currentAddress.toString(16),
					instructionsExecuted: finalState.instructionsExecuted,
					isRunning: finalState.isRunning,
					isPaused: finalState.isPaused
				} : null,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Stepped ${steps.length} instruction(s)`);
			}

			return exportData;
		})
	);

	// Read Memory Headless
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.readMemoryHeadless', async (arg?: Record<string, unknown>) => {
			const addrStr = typeof arg?.address === 'string' ? arg.address : undefined;
			const size = typeof arg?.size === 'number' ? arg.size : 256;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			if (!addrStr) {
				throw new Error('readMemoryHeadless requires an "address" argument (hex string).');
			}

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			const address = BigInt(addrStr.startsWith('0x') ? addrStr : '0x' + addrStr);
			const data = await engine.emulationReadMemory(address, size);

			// Build hex dump
			const hexLines: string[] = [];
			const bytesPerLine = 16;
			for (let i = 0; i < data.length; i += bytesPerLine) {
				const addr = (address + BigInt(i)).toString(16).padStart(16, '0');
				const bytes: string[] = [];
				let ascii = '';
				for (let j = 0; j < bytesPerLine; j++) {
					if (i + j < data.length) {
						const byte = data[i + j];
						bytes.push(byte.toString(16).padStart(2, '0'));
						ascii += (byte >= 0x20 && byte <= 0x7E) ? String.fromCharCode(byte) : '.';
					}
				}
				hexLines.push(`${addr}  ${bytes.join(' ')}  |${ascii}|`);
			}

			const exportData = {
				address: '0x' + address.toString(16),
				size,
				hexDump: hexLines.join('\n'),
				ascii: data.toString('utf8').replace(/[^\x20-\x7E]/g, '.'),
				raw: data.toString('base64'),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Read ${size} bytes from 0x${address.toString(16)}`);
			}

			return exportData;
		})
	);

	// Get Registers Headless
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.getRegistersHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			const registers = engine.getFullRegisters();

			const exportData = {
				architecture: engine.getArchitecture(),
				registers,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Registers: ${engine.getArchitecture()}`);
			}

			return exportData;
		})
	);

	// Set Breakpoint Headless
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.setBreakpointHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			// Accept single address or array
			const rawAddr = arg?.address;
			const addresses: string[] = [];
			if (typeof rawAddr === 'string') {
				addresses.push(rawAddr);
			} else if (Array.isArray(rawAddr)) {
				for (const a of rawAddr) {
					if (typeof a === 'string') {
						addresses.push(a);
					}
				}
			}

			if (addresses.length === 0) {
				throw new Error('setBreakpointHeadless requires an "address" argument (string or string[]).');
			}

			const set: string[] = [];
			for (const addrStr of addresses) {
				const address = BigInt(addrStr.startsWith('0x') ? addrStr : '0x' + addrStr);
				engine.emulationSetBreakpoint(address);
				set.push('0x' + address.toString(16));
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Breakpoints set: ${set.join(', ')}`);
			}

			return { breakpoints: set, generatedAt: new Date().toISOString() };
		})
	);

	// Get State Headless — full emulation state dump
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.getStateHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			const registers = engine.getFullRegisters();
			const regions = await engine.getMemoryRegions();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();

			const exportData = {
				state: state ? {
					isRunning: state.isRunning,
					isPaused: state.isPaused,
					isReady: state.isReady,
					currentAddress: '0x' + state.currentAddress.toString(16),
					instructionsExecuted: state.instructionsExecuted,
					lastError: state.lastError
				} : null,
				architecture: engine.getArchitecture(),
				fileType: engine.getFileType(),
				registers,
				memoryRegions: regions.map(r => ({
					address: '0x' + r.address.toString(16),
					size: r.size,
					permissions: r.permissions,
					name: r.name
				})),
				apiCallLog: apiCalls.map(c => ({
					dll: c.dll,
					name: c.name,
					returnValue: '0x' + (c.returnValue ?? 0n).toString(16)
				})),
				stdout,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Emulation state: ${state?.instructionsExecuted ?? 0} instructions`);
			}

			return exportData;
		})
	);

	// Snapshot Headless — save emulation snapshot from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.snapshotHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			engine.saveSnapshot();

			const exportData = {
				success: true,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage('Emulation snapshot saved');
			}

			return exportData;
		})
	);

	// Restore Snapshot Headless — restore emulation snapshot from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.restoreSnapshotHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			try {
				engine.restoreSnapshot();
			} catch {
				throw new Error('No snapshot available. Call snapshotHeadless first.');
			}

			const registers = engine.getFullRegisters();
			const updatedState = engine.getEmulationState();

			const exportData = {
				success: true,
				registers,
				state: {
					currentAddress: updatedState ? '0x' + updatedState.currentAddress.toString(16) : '0x0',
					instructionsExecuted: updatedState?.instructionsExecuted ?? 0,
					isRunning: updatedState?.isRunning ?? false
				},
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage('Emulation snapshot restored');
			}

			return exportData;
		})
	);

	// Export Trace Headless — export API/libc call trace as JSON
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.exportTraceHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const traceManager = engine.getTraceManager();
			const traceExport = traceManager.exportJSON();

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(traceExport, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Trace exported: ${traceExport.totalEntries} entries`);
			}

			return traceExport;
		})
	);

	// Emulate Full Headless — unified single-shot emulation (load → configure → run → collect → dispose)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.emulateFullHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			if (!filePath) {
				throw new Error('emulateFullHeadless requires a "file" argument.');
			}

			const arch = typeof arg?.arch === 'string' ? arg.arch as ArchitectureType : undefined;
			const stdin = typeof arg?.stdin === 'string' ? arg.stdin : undefined;
			const maxInstructions = typeof arg?.maxInstructions === 'number' ? arg.maxInstructions : 1_000_000;
			const breakpoints = Array.isArray(arg?.breakpoints) ? arg.breakpoints as string[] : undefined;
			const keepAlive = arg?.keepAlive === true;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			console.log('[emulateFullHeadless] starting emulation...');
			await engine.startEmulation(filePath, arch);

			if (stdin) {
				engine.setStdinBuffer(decodeEscapedInput(stdin));
			}

			if (breakpoints) {
				for (const addr of breakpoints) {
					engine.emulationSetBreakpoint(BigInt(addr));
				}
			}

			let crashed = false;
			let crashError = '';

			try {
				await engine.emulationRunCounted(maxInstructions);
			} catch (error: any) {
				crashed = true;
				crashError = error.message || String(error);
			}

			const stateAfter = engine.getEmulationState();
			const registers = engine.getFullRegisters();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();
			const regions = await engine.getMemoryRegions();

			if (!keepAlive) {
				engine.disposeEmulation();
			}

			const exportData = {
				file: filePath,
				architecture: engine.getArchitecture(),
				fileType: engine.getFileType(),
				crashed,
				crashError: crashError || undefined,
				state: stateAfter ? {
					isRunning: stateAfter.isRunning,
					isPaused: stateAfter.isPaused,
					currentAddress: '0x' + stateAfter.currentAddress.toString(16),
					instructionsExecuted: stateAfter.instructionsExecuted,
					lastError: stateAfter.lastError
				} : null,
				registers,
				apiCalls: apiCalls.map(c => ({
					dll: c.dll,
					name: c.name,
					returnValue: '0x' + (c.returnValue ?? 0n).toString(16)
				})),
				stdout,
				memoryRegions: regions.map(r => ({
					address: '0x' + r.address.toString(16),
					size: r.size,
					permissions: r.permissions,
					name: r.name
				})),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				const status = crashed ? `CRASHED: ${crashError}` : 'OK';
				vscode.window.showInformationMessage(
					`Full emulation ${status}: ${filePath} (${engine.getArchitecture()})`
				);
			}

			return exportData;
		})
	);

	// Write Memory Headless — write data to emulation memory from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.writeMemoryHeadless', async (arg?: Record<string, unknown>) => {
			const addrStr = typeof arg?.address === 'string' ? arg.address : undefined;
			const dataStr = typeof arg?.data === 'string' ? arg.data : undefined;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			if (!addrStr) {
				throw new Error('writeMemoryHeadless requires an "address" argument (hex string).');
			}
			if (!dataStr) {
				throw new Error('writeMemoryHeadless requires a "data" argument (base64 or 0x-prefixed hex).');
			}

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session.');
			}

			const address = BigInt(addrStr.startsWith('0x') ? addrStr : '0x' + addrStr);
			const buffer = decodeDataParam(dataStr);
			await engine.emulationWriteMemory(address, buffer);

			const exportData = {
				address: '0x' + address.toString(16),
				bytesWritten: buffer.length,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Wrote ${buffer.length} bytes to 0x${address.toString(16)}`);
			}

			return exportData;
		})
	);

	// Set Register Headless — set CPU register value from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.setRegisterHeadless', async (arg?: Record<string, unknown>) => {
			const name = typeof arg?.name === 'string' ? arg.name : undefined;
			const rawValue = arg?.value;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			if (!name) {
				throw new Error('setRegisterHeadless requires a "name" argument (register name).');
			}
			if (rawValue === undefined || rawValue === null) {
				throw new Error('setRegisterHeadless requires a "value" argument (hex string or decimal number).');
			}

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session.');
			}

			// Parse value: hex string (0x-prefixed) or decimal number
			let parsedValue: bigint;
			if (typeof rawValue === 'string' && rawValue.startsWith('0x')) {
				parsedValue = BigInt(rawValue);
			} else {
				parsedValue = BigInt(Number(rawValue));
			}

			await engine.emulationSetRegister(name, parsedValue);

			const exportData = {
				register: name,
				value: '0x' + parsedValue.toString(16),
				architecture: engine.getArchitecture(),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Set ${name} = 0x${parsedValue.toString(16)}`);
			}

			return exportData;
		})
	);

	// Set Stdin Headless — set STDIN buffer for emulation from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.setStdinHeadless', async (arg?: Record<string, unknown>) => {
			const input = typeof arg?.input === 'string' ? arg.input : undefined;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session.');
			}

			const decodedInput = decodeEscapedInput(input ?? '');
			engine.setStdinBuffer(decodedInput);

			const exportData = {
				bytesSet: Buffer.byteLength(decodedInput),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`STDIN buffer set: ${exportData.bytesSet} bytes`);
			}

			return exportData;
		})
	);

	// Dispose Headless — release emulation session resources from pipeline
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.disposeHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			engine.disposeEmulation();

			const exportData = {
				disposed: true as const,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage('Emulation session disposed.');
			}

			return exportData;
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

export function decodeDataParam(data: string): Buffer {
	if (data.startsWith('0x') || data.startsWith('0X')) {
		const hex = data.slice(2);
		if (hex.length === 0 || !/^[0-9a-fA-F]+$/.test(hex) || hex.length % 2 !== 0) {
			throw new Error('Invalid data format. Use base64 or 0x-prefixed hex.');
		}
		return Buffer.from(hex, 'hex');
	}
	const buf = Buffer.from(data, 'base64');
	if (buf.length === 0 && data.length > 0) {
		throw new Error('Invalid data format. Use base64 or 0x-prefixed hex.');
	}
	return buf;
}
