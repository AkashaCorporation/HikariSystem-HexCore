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
	const emulator = vscode.workspace.getConfiguration('hexcore').get<string>('emulator', 'azoth');
	if (emulator !== 'debugger') {
		console.log(`[hexcore-debugger] activation skipped — hexcore.emulator="${emulator}" (Azoth is the default emulator in v3.8.0; set hexcore.emulator="debugger" to enable the legacy TypeScript debugger for regression comparison)`);
		context.subscriptions.push(
			vscode.workspace.onDidChangeConfiguration((e) => {
				if (e.affectsConfiguration('hexcore.emulator')) {
					vscode.window.showInformationMessage(
						vscode.l10n.t('HexCore emulator setting changed. Reload the window to apply.'),
						vscode.l10n.t('Reload Window')
					).then((choice) => {
						if (choice) {
							vscode.commands.executeCommand('workbench.action.reloadWindow');
						}
					});
				}
			})
		);
		return;
	}

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
		vscode.commands.registerCommand('hexcore.debug.saveSnapshot', async () => {
			try {
				await engine.saveSnapshot();
				vscode.window.showInformationMessage('Snapshot saved');
			} catch (error: any) {
				vscode.window.showErrorMessage(`Failed to save snapshot: ${error.message}`);
			}
		})
	);

	// Restore snapshot
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.restoreSnapshot', async () => {
			try {
				await engine.restoreSnapshot();
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
			const permissiveMemoryMapping = arg?.permissiveMemoryMapping === true;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			await engine.startEmulation(filePath, arch, { permissiveMemoryMapping });

			if (stdin) {
				engine.setStdinBuffer(stdin);
			}

			const state = engine.getEmulationState();
			const regions = await engine.getMemoryRegions();

			const exportData = {
				file: filePath,
				architecture: engine.getArchitecture(),
				executionBackend: engine.getExecutionBackend(),
				fileType: engine.getFileType(),
				permissiveMemoryMapping,
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
			const registers = await engine.getFullRegistersAsync();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();
			const terminatedWithError = Boolean(stateAfter?.lastError);
			const effectiveError = crashError || stateAfter?.lastError || undefined;
			const faultInfo = engine.getLastFaultInfo();

			const exportData = {
				crashed,
				crashError: crashError || undefined,
				terminatedWithError,
				error: effectiveError,
				faultInfo,
				executionBackend: engine.getExecutionBackend(),
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
				const status = crashed
					? `CRASHED: ${crashError}`
					: terminatedWithError
						? `ERROR: ${effectiveError}`
						: 'OK';
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
				const regs = await engine.getFullRegistersAsync();
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

	// Get Registers Headless
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.getRegistersHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			const registers = await engine.getFullRegistersAsync();

			const exportData = {
				architecture: engine.getArchitecture(),
				executionBackend: engine.getExecutionBackend(),
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
			const outputOptions = arg?.output as { path?: string } | undefined;

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

			const exportData = { breakpoints: set, generatedAt: new Date().toISOString() };
			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			return exportData;
		})
	);

	// Get State Headless — full emulation state dump
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.getStateHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			const registers = await engine.getFullRegistersAsync();
			const regions = await engine.getMemoryRegions();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();
			const faultInfo = engine.getLastFaultInfo();

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
				executionBackend: engine.getExecutionBackend(),
				fileType: engine.getFileType(),
				registers,
				faultInfo,
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

			await engine.saveSnapshot();

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
				await engine.restoreSnapshot();
			} catch {
				throw new Error('No snapshot available. Call snapshotHeadless first.');
			}

			const registers = await engine.getFullRegistersAsync();
			const updatedState = engine.getEmulationState();

			const exportData = {
				success: true,
				executionBackend: engine.getExecutionBackend(),
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

	// Session counter to prevent stale emulateFullHeadless calls from disposing newer sessions
	let emulateSessionId = 0;

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
			const keepAlive = arg?.keepAlive === true;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			// v3.7 options
			const permissiveMemoryMapping = arg?.permissiveMemoryMapping === true;
			const prngMode = typeof arg?.prngMode === 'string' ? arg.prngMode as 'glibc' | 'msvcrt' | 'stub' : undefined;
			const collectSideChannels = arg?.collectSideChannels === true;
			const memoryDumps = Array.isArray(arg?.memoryDumps) ? arg.memoryDumps as Array<{ address: string; size: number; trigger: 'breakpoint' | 'end' }> : undefined;

			// Parse breakpoints — support both simple string[] and rich config objects
			let simpleBreakpoints: string[] | undefined;
			let breakpointConfigs: Array<{ address: string; autoSnapshot?: boolean; dumpRanges?: Array<{ address: string; size: number }> }> | undefined;

			if (Array.isArray(arg?.breakpoints)) {
				const bpArr = arg.breakpoints;
				if (bpArr.length > 0 && typeof bpArr[0] === 'string') {
					simpleBreakpoints = bpArr as string[];
				} else if (bpArr.length > 0 && typeof bpArr[0] === 'object') {
					breakpointConfigs = bpArr as typeof breakpointConfigs;
				}
			}

			console.log('[emulateFullHeadless] starting emulation...');
			const mySession = ++emulateSessionId;
			await engine.startEmulation(filePath, arch, {
				permissiveMemoryMapping,
				prngMode,
				collectSideChannels,
				memoryDumps,
				breakpointConfigs
			});

			if (stdin) {
				engine.setStdinBuffer(decodeEscapedInput(stdin));
			}

			// Set breakpoints (simple string addresses)
			if (simpleBreakpoints) {
				for (const addr of simpleBreakpoints) {
					engine.emulationSetBreakpoint(BigInt(addr));
				}
			}
			// Set breakpoints from rich config objects
			if (breakpointConfigs) {
				for (const bp of breakpointConfigs) {
					engine.emulationSetBreakpoint(BigInt(bp.address));
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

			// Collect end-of-emulation memory dumps
			await engine.collectMemoryDumps('end');

			const stateAfter = engine.getEmulationState();
			const registers = await engine.getFullRegistersAsync();
			const apiCalls = engine.getApiCallLog();
			const stdout = engine.getStdoutBuffer();
			const regions = await engine.getMemoryRegions();
			const terminatedWithError = Boolean(stateAfter?.lastError);
			const effectiveError = crashError || stateAfter?.lastError || undefined;
			const faultInfo = engine.getLastFaultInfo();

			// Collect v3.7 data
			const breakpointSnapshotsData = engine.getBreakpointSnapshots();
			const memoryDumpsData = engine.getCollectedMemoryDumps();
			const sideChannelDataResult = collectSideChannels ? engine.getSideChannelData() : undefined;

			// v3.7.1: dumpAndDisassemble — disassemble collected memory dumps (Reqs 8.1, 8.4)
			const dumpDisassemblyResults: Array<{
				dump: { address: string; size: number; data: string };
				instructions: Array<{ address: string; mnemonic: string; opStr: string; size: number; bytes: string }>;
			}> = [];
			if (memoryDumpsData.length > 0) {
				for (const dump of memoryDumpsData) {
					try {
						const result = await engine.dumpAndDisassemble(dump.address, dump.size);
						dumpDisassemblyResults.push({
							dump: result.dump,
							instructions: result.instructions.map(i => ({
								address: '0x' + i.address.toString(16),
								mnemonic: i.mnemonic,
								opStr: i.opStr,
								size: i.size,
								bytes: Buffer.isBuffer(i.bytes)
									? i.bytes.toString('hex')
									: Array.from(i.bytes as ArrayLike<number>).map((b: number) => b.toString(16).padStart(2, '0')).join('')
							}))
						});
					} catch (err: any) {
						console.warn(`[emulateFullHeadless] dumpAndDisassemble failed for ${dump.address}: ${err.message}`);
					}
				}
			}

			if (!keepAlive && mySession === emulateSessionId) {
				engine.disposeEmulation();
			}

			const exportData: Record<string, any> = {
				file: filePath,
				architecture: engine.getArchitecture(),
				executionBackend: engine.getExecutionBackend(),
				fileType: engine.getFileType(),
				crashed,
				crashError: crashError || undefined,
				terminatedWithError,
				error: effectiveError,
				faultInfo,
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

			// Include v3.7 data if present
			if (breakpointSnapshotsData.length > 0) {
				exportData.breakpointSnapshots = breakpointSnapshotsData;
			}
			if (memoryDumpsData.length > 0) {
				exportData.memoryDumps = memoryDumpsData;
			}
			if (dumpDisassemblyResults.length > 0) {
				exportData.dumpDisassembly = dumpDisassemblyResults;
			}
			if (sideChannelDataResult) {
				exportData.sideChannelData = sideChannelDataResult;
			}

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

	// Read Memory Headless — read arbitrary memory range from active emulation (v3.7)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.readMemoryHeadless', async (arg?: Record<string, unknown>) => {
			const addrStr = typeof arg?.address === 'string' ? arg.address : undefined;
			const size = typeof arg?.size === 'number' ? arg.size : undefined;
			const format = typeof arg?.format === 'string' ? arg.format : 'base64'; // 'base64' | 'hex'
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			if (!addrStr) {
				throw new Error('readMemoryHeadless requires an "address" argument (hex string).');
			}
			if (!size || size <= 0) {
				throw new Error('readMemoryHeadless requires a positive "size" argument.');
			}

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session.');
			}

			const address = BigInt(addrStr.startsWith('0x') ? addrStr : '0x' + addrStr);
			const data = await engine.emulationReadMemory(address, size);

			const exportData = {
				address: '0x' + address.toString(16),
				size: data.length,
				data: format === 'hex' ? data.toString('hex') : data.toString('base64'),
				format,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`Read ${data.length} bytes from 0x${address.toString(16)}`);
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

	// Search Memory Headless — pattern search across emulated RAM (Issue #18)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.debug.searchMemoryHeadless', async (arg?: Record<string, unknown>) => {
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as { path?: string } | undefined;

			const state = engine.getEmulationState();
			if (!state) {
				throw new Error('No active emulation session. Call emulateHeadless first.');
			}

			// Parse pattern — supports hex string ("48 8B ?? 00"), ASCII, or UTF-16
			const patternStr = typeof arg?.pattern === 'string' ? arg.pattern : undefined;
			const encoding = typeof arg?.encoding === 'string' ? arg.encoding : 'hex'; // 'hex' | 'ascii' | 'utf16'
			const regionsFilter = typeof arg?.regions === 'string' ? arg.regions : 'all'; // 'all' | 'heap' | 'stack' | or "0x1000-0x2000"
			const maxResults = typeof arg?.maxResults === 'number' ? arg.maxResults : 100;

			if (!patternStr) {
				throw new Error('searchMemoryHeadless requires a "pattern" argument.');
			}

			// Build search bytes and wildcard mask from pattern
			let searchBytes: number[];
			let wildcardMask: boolean[];

			if (encoding === 'ascii') {
				const buf = Buffer.from(patternStr, 'ascii');
				searchBytes = Array.from(buf);
				wildcardMask = searchBytes.map(() => false);
			} else if (encoding === 'utf16') {
				const buf = Buffer.from(patternStr, 'utf16le');
				searchBytes = Array.from(buf);
				wildcardMask = searchBytes.map(() => false);
			} else {
				// Hex pattern with ?? wildcards: "48 8B ?? 00" or "488B??00"
				const tokens: string[] = [];
				const normalized = patternStr.trim();
				if (normalized.includes(' ')) {
					tokens.push(...normalized.split(/\s+/));
				} else {
					for (let i = 0; i < normalized.length; i += 2) {
						tokens.push(normalized.substring(i, i + 2));
					}
				}
				searchBytes = [];
				wildcardMask = [];
				for (const token of tokens) {
					if (token === '??' || token === '?') {
						searchBytes.push(0);
						wildcardMask.push(true);
					} else {
						const byte = parseInt(token, 16);
						if (isNaN(byte)) {
							throw new Error(`Invalid hex byte in pattern: "${token}"`);
						}
						searchBytes.push(byte);
						wildcardMask.push(false);
					}
				}
			}

			if (searchBytes.length === 0) {
				throw new Error('Pattern is empty after parsing.');
			}

			// Get memory regions to search
			const allRegions = await engine.getMemoryRegions();
			let regionsToSearch = allRegions;

			if (regionsFilter === 'heap') {
				regionsToSearch = allRegions.filter(r => r.name?.toLowerCase().includes('heap'));
			} else if (regionsFilter === 'stack') {
				regionsToSearch = allRegions.filter(r => r.name?.toLowerCase().includes('stack'));
			} else if (regionsFilter !== 'all') {
				// Try to parse as "0xSTART-0xEND"
				const rangeMatch = regionsFilter.match(/^(0x[0-9a-fA-F]+)\s*-\s*(0x[0-9a-fA-F]+)$/);
				if (rangeMatch) {
					const rangeStart = BigInt(rangeMatch[1]);
					const rangeEnd = BigInt(rangeMatch[2]);
					regionsToSearch = allRegions.filter(r => {
						const rEnd = BigInt(r.address) + BigInt(r.size);
						return BigInt(r.address) < rangeEnd && rEnd > rangeStart;
					});
				}
			}

			// Search each region
			const matches: Array<{ address: string; region: string; size: number }> = [];
			const patternLen = searchBytes.length;

			for (const region of regionsToSearch) {
				if (matches.length >= maxResults) break;

				const regionAddr = BigInt(region.address);
				const regionSize = region.size;

				// Read region in chunks (max 4MB at a time to avoid memory issues)
				const chunkSize = Math.min(regionSize, 4 * 1024 * 1024);
				let offset = 0;

				while (offset < regionSize && matches.length < maxResults) {
					const readSize = Math.min(chunkSize, regionSize - offset);
					let data: Buffer;
					try {
						data = await engine.emulationReadMemory(regionAddr + BigInt(offset), readSize);
					} catch {
						// Skip unreadable regions (MMIO, guard pages)
						break;
					}

					// Linear scan with wildcard support
					for (let i = 0; i <= data.length - patternLen; i++) {
						let found = true;
						for (let j = 0; j < patternLen; j++) {
							if (!wildcardMask[j] && data[i + j] !== searchBytes[j]) {
								found = false;
								break;
							}
						}
						if (found) {
							const matchAddr = regionAddr + BigInt(offset + i);
							matches.push({
								address: '0x' + matchAddr.toString(16),
								region: region.name || `region@0x${regionAddr.toString(16)}`,
								size: patternLen
							});
							if (matches.length >= maxResults) break;
							// Skip past this match to avoid overlapping results
							i += patternLen - 1;
						}
					}

					offset += readSize;
					// If we read less than chunkSize, we're done with this region
					if (readSize < chunkSize) break;
				}
			}

			const exportData = {
				success: true,
				pattern: patternStr,
				encoding,
				regionsSearched: regionsToSearch.length,
				totalMatches: matches.length,
				matches,
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`Found ${matches.length} match(es) for pattern "${patternStr}" across ${regionsToSearch.length} memory region(s).`
				);
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
