/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { DisassemblyEditorProvider } from './disassemblyEditor';
import { FunctionTreeProvider } from './functionTree';
import { StringRefProvider } from './stringRefTree';
import { SectionTreeProvider } from './sectionTree';
import { ImportTreeProvider } from './importTree';
import { ExportTreeProvider } from './exportTree';
import { DisassemblerEngine } from './disassemblerEngine';
import { DisassemblerFactory } from './disassemblerFactory';
import { GraphViewProvider } from './graphViewProvider';
import { AutomationPipelineRunner, PipelineRunStatus, listCapabilities } from './automationPipelineRunner';

type OutputFormat = 'json' | 'md';

interface AnalyzeAllOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface AnalyzeAllCommandOptions {
	file?: string;
	output?: AnalyzeAllOutputOptions;
	quiet?: boolean;
	maxFunctions?: number;
	maxFunctionSize?: number;
	forceReload?: boolean;
}

interface AnalyzeAllFunctionSummary {
	address: string;
	name: string;
	size: number;
	instructionCount: number;
	callers: number;
	callees: number;
}

interface AnalyzeAllResult {
	filePath: string;
	fileName: string;
	newFunctions: number;
	totalFunctions: number;
	totalStrings: number;
	architecture: string;
	baseAddress: string;
	sections: number;
	imports: number;
	exports: number;
	functions: AnalyzeAllFunctionSummary[];
	reportMarkdown: string;
}

interface RunJobCommandOptions {
	jobFile?: string;
	quiet?: boolean;
}

export function activate(context: vscode.ExtensionContext): void {
	// Use Factory to get the initial global engine (or specific if we knew context)
	const factory = DisassemblerFactory.getInstance();
	const engine = factory.getEngine(); // Default global engine for now

	// Event emitter for synchronization between views
	const onDidChangeActiveEditor = new vscode.EventEmitter<string | undefined>();

	const disasmEditorProvider = new DisassemblyEditorProvider(context, engine, onDidChangeActiveEditor);
	const functionProvider = new FunctionTreeProvider(engine);
	const stringRefProvider = new StringRefProvider(engine);
	const sectionProvider = new SectionTreeProvider(engine);
	const importProvider = new ImportTreeProvider(engine);
	const exportProvider = new ExportTreeProvider(engine);
	const graphViewProvider = new GraphViewProvider(context.extensionUri, engine);

	const ensureAssemblerAvailable = async (): Promise<boolean> => {
		const availability = await engine.getAssemblerAvailability();
		if (availability.available) {
			return true;
		}

		const detail = availability.error ? ` ${availability.error}` : '';
		vscode.window.showErrorMessage(
			vscode.l10n.t('LLVM MC engine is not available.{0}', detail)
		);
		return false;
	};

	const showNativeStatus = async (): Promise<void> => {
		const disassembler = await engine.getDisassemblerAvailability();
		const assembler = await engine.getAssemblerAvailability();
		if (disassembler.available && assembler.available) {
			vscode.window.showInformationMessage(
				vscode.l10n.t('Native engines are available for this session.')
			);
			return;
		}

		const parts: string[] = [];
		if (!disassembler.available) {
			parts.push(
				vscode.l10n.t('Capstone: {0}', disassembler.error ?? vscode.l10n.t('Unavailable'))
			);
		}
		if (!assembler.available) {
			parts.push(
				vscode.l10n.t('LLVM MC: {0}', assembler.error ?? vscode.l10n.t('Unavailable'))
			);
		}

		vscode.window.showWarningMessage(
			vscode.l10n.t('Native engine status: {0}', parts.join(' | '))
		);
	};

	const pipelineRunner = new AutomationPipelineRunner();
	const pendingJobRuns = new Map<string, NodeJS.Timeout>();

	const runPipelineJob = async (arg?: vscode.Uri | string | RunJobCommandOptions): Promise<PipelineRunStatus | undefined> => {
		const options = normalizeRunJobCommandOptions(arg);
		const quiet = options.quiet ?? false;
		const jobFilePath = resolveJobFilePath(arg, options.jobFile);
		if (!jobFilePath) {
			if (!quiet) {
				vscode.window.showWarningMessage('No .hexcore_job.json file was found.');
			}
			return undefined;
		}

		try {
			const status = await pipelineRunner.runJobFile(jobFilePath, true);
			if (!quiet) {
				if (status.status === 'ok') {
					vscode.window.showInformationMessage(`Pipeline completed successfully. Status file: ${path.join(status.outDir, 'hexcore-pipeline.status.json')}`);
				} else {
					vscode.window.showWarningMessage(`Pipeline finished with errors. Check: ${path.join(status.outDir, 'hexcore-pipeline.log')}`);
				}
			}
			return status;
		} catch (error: unknown) {
			if (!quiet) {
				vscode.window.showErrorMessage(`Pipeline execution failed: ${toErrorMessage(error)}`);
			}
			throw error;
		}
	};

	const scheduleJobRun = (jobFilePath: string): void => {
		const normalizedPath = path.resolve(jobFilePath);
		const existing = pendingJobRuns.get(normalizedPath);
		if (existing) {
			clearTimeout(existing);
		}

		const timeoutHandle = setTimeout(() => {
			pendingJobRuns.delete(normalizedPath);
			runPipelineJob({ jobFile: normalizedPath, quiet: true }).catch(error => {
				console.error('HexCore pipeline auto-run failed:', error);
			});
		}, 350);
		pendingJobRuns.set(normalizedPath, timeoutHandle);
	};

	const autoRunExistingJobs = (): void => {
		const folders = vscode.workspace.workspaceFolders ?? [];
		for (const folder of folders) {
			const jobFilePath = path.join(folder.uri.fsPath, '.hexcore_job.json');
			if (fs.existsSync(jobFilePath)) {
				scheduleJobRun(jobFilePath);
			}
		}
	};

	// Sync tree views when editor changes
	onDidChangeActiveEditor.event(() => {
		functionProvider.refresh();
		stringRefProvider.refresh();
		sectionProvider.refresh();
		importProvider.refresh();
		exportProvider.refresh();
	});

	// Register Custom Editor (Main disassembly view)
	context.subscriptions.push(
		vscode.window.registerCustomEditorProvider(
			DisassemblyEditorProvider.viewType,
			disasmEditorProvider,
			{
				webviewOptions: { retainContextWhenHidden: true },
				supportsMultipleEditorsPerDocument: false
			}
		)
	);

	// Register Webview Providers (Sidebar)
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			'hexcore.disassembler.graphView',
			graphViewProvider,
			{ webviewOptions: { retainContextWhenHidden: true } }
		)
	);

	// Register Tree Providers
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('hexcore.disassembler.functions', functionProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.strings', stringRefProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.sections', sectionProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.imports', importProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.exports', exportProvider)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.pipeline.runJob', async (arg?: vscode.Uri | string | RunJobCommandOptions) => {
			return runPipelineJob(arg);
		}),
		vscode.commands.registerCommand('hexcore.pipeline.listCapabilities', async (options?: { output?: string | { path?: string }; quiet?: boolean }) => {
			const capabilities = listCapabilities();
			const outputPath = typeof options?.output === 'string'
				? path.resolve(options.output)
				: (typeof options?.output?.path === 'string' ? path.resolve(options.output.path) : undefined);

			if (outputPath) {
				fs.writeFileSync(outputPath, JSON.stringify(capabilities, null, 2), 'utf8');
				if (!options?.quiet) {
					vscode.window.showInformationMessage(`Pipeline capabilities written to ${outputPath}`);
				}
				return capabilities;
			}
			// Show in output channel if no file output
			const outputChannel = vscode.window.createOutputChannel('HexCore Pipeline');
			outputChannel.clear();
			outputChannel.appendLine('HexCore Pipeline - Command Capabilities');
			outputChannel.appendLine('='.repeat(50));
			outputChannel.appendLine('');
			for (const cap of capabilities) {
				const status = cap.headless ? 'HEADLESS' : 'INTERACTIVE';
				outputChannel.appendLine(`[${status}] ${cap.command}`);
				if (cap.aliases.length > 0) {
					outputChannel.appendLine(`  Aliases:    ${cap.aliases.join(', ')}`);
				}
				outputChannel.appendLine(`  Timeout:    ${cap.defaultTimeoutMs}ms`);
				outputChannel.appendLine(`  Validates:  ${cap.validateOutput}`);
				outputChannel.appendLine(`  Extension:  ${cap.requiredExtension.join(', ')}`);
				if (cap.reason) {
					outputChannel.appendLine(`  Note:       ${cap.reason}`);
				}
				outputChannel.appendLine('');
			}
			outputChannel.show();
			return capabilities;
		})
	);

	const jobWatcher = vscode.workspace.createFileSystemWatcher('**/.hexcore_job.json');
	context.subscriptions.push(jobWatcher);
	context.subscriptions.push(
		jobWatcher.onDidCreate(uri => scheduleJobRun(uri.fsPath)),
		jobWatcher.onDidChange(uri => scheduleJobRun(uri.fsPath))
	);
	context.subscriptions.push({
		dispose: () => {
			for (const timeoutHandle of pendingJobRuns.values()) {
				clearTimeout(timeoutHandle);
			}
			pendingJobRuns.clear();
		}
	});

	autoRunExistingJobs();

	// Register Commands
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.openFile', async () => {
			const uris = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Open Binary',
				filters: {
					'Windows Executables': ['exe', 'dll', 'sys', 'ocx', 'scr', 'cpl'],
					'Linux Executables': ['elf', 'so', 'a', 'o'],
					'Raw Binary': ['bin', 'raw', 'dmp'],
					'All Files': ['*']
				}
			});
			if (uris && uris.length > 0) {
				// Open in Custom Editor
				await vscode.commands.executeCommand('vscode.openWith', uris[0], DisassemblyEditorProvider.viewType);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.open', async (uri?: vscode.Uri) => {
			if (uri) {
				await vscode.commands.executeCommand('vscode.openWith', uri, DisassemblyEditorProvider.viewType);
				return;
			}

			await vscode.commands.executeCommand('hexcore.disasm.openFile');
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzeFile', async (uri?: vscode.Uri) => {
			if (!uri) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					openLabel: 'Disassemble',
					filters: {
						'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
						'All Files': ['*']
					}
				});
				if (uris && uris.length > 0) {
					uri = uris[0];
				}
			}
			if (uri) {
				try {
					// Open in custom editor (main disassembly view)
					await vscode.commands.executeCommand('vscode.openWith', uri, DisassemblyEditorProvider.viewType);
				} catch (error: any) {
					vscode.window.showErrorMessage(`Failed to disassemble file: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.goToAddress', async (argAddress?: number) => {
			let addr: number | undefined = argAddress;

			if (addr === undefined) {
				const input = await vscode.window.showInputBox({
					prompt: 'Enter address (hex)',
					placeHolder: '0x401000',
					validateInput: (value) => {
						const val = parseInt(value.replace(/^0x/, ''), 16);
						return isNaN(val) ? 'Invalid hex address' : null;
					}
				});
				if (input) {
					addr = parseInt(input.replace(/^0x/, ''), 16);
				}
			}

			if (addr !== undefined) {
				const targetAddress = addr;
				disasmEditorProvider.navigateToAddress(targetAddress);

				// Sync Graph View if function exists - auto-focus graph
				let func = engine.getFunctionAt(targetAddress);
				if (!func) {
					// Try to find containing function
					const funcs = engine.getFunctions();
					func = funcs.find(f => targetAddress >= f.address && targetAddress < f.endAddress);
				}

				if (func && func.instructions.length > 0) {
					// Auto-focus the graph view and show CFG
					try {
						await vscode.commands.executeCommand('hexcore.disassembler.graphView.focus');
					} catch {
						// View may not be visible yet, that's ok
					}
					graphViewProvider.showFunction(func);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.findXrefs', async () => {
			const input = await vscode.window.showInputBox({
				prompt: 'Find references to address',
				placeHolder: '0x401000'
			});
			if (input) {
				const addr = parseInt(input.replace(/^0x/, ''), 16);
				const xrefs = await engine.findCrossReferences(addr);
				disasmEditorProvider.showXrefs(xrefs);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.addComment', async () => {
			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No address selected');
				return;
			}
			const comment = await vscode.window.showInputBox({
				prompt: `Add comment at 0x${addr.toString(16)}`,
				placeHolder: 'Enter comment...'
			});
			if (comment) {
				engine.addComment(addr, comment);
				disasmEditorProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.renameFunction', async (item?: any) => {
			const addr = item?.address || disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const currentName = engine.getFunctionName(addr) || `sub_${addr.toString(16).toUpperCase()}`;
			const newName = await vscode.window.showInputBox({
				prompt: 'Rename function',
				value: currentName
			});
			if (newName) {
				engine.renameFunction(addr, newName);
				functionProvider.refresh();
				disasmEditorProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.showCFG', async () => {
			const addr = disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}

			const func = engine.getFunctionAt(addr);
			if (func) {
				// Focus the graph view
				await vscode.commands.executeCommand('hexcore.disassembler.graphView.focus');
				// Render the graph
				graphViewProvider.showFunction(func);
			} else {
				vscode.window.showErrorMessage('Function data not found');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.searchString', async () => {
			const query = await vscode.window.showInputBox({
				prompt: 'Search string references',
				placeHolder: 'Enter string to search...'
			});
			if (query) {
				const results = await engine.searchStringReferences(query);
				stringRefProvider.setResults(results);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.exportASM', async () => {
			const uri = await vscode.window.showSaveDialog({
				filters: { 'Assembly': ['asm', 's'], 'Text': ['txt'] }
			});
			if (uri) {
				await engine.exportAssembly(uri.fsPath);
				vscode.window.showInformationMessage(`Assembly exported to ${uri.fsPath}`);
			}
		})
	);

	// ============================================================================
	// Assembly & Patching Commands (LLVM MC)
	// ============================================================================

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.patchInstruction', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No instruction selected');
				return;
			}

			const newCode = await vscode.window.showInputBox({
				prompt: `Patch instruction at 0x${addr.toString(16)}`,
				placeHolder: 'mov rax, rbx'
			});

			if (newCode) {
				try {
					const result = await engine.patchInstruction(addr, newCode);
					if (result.success) {
						engine.applyPatch(addr, result.bytes);
						disasmEditorProvider.refresh();
						const msg = result.nopPadding > 0
							? `Patched with ${result.nopPadding} NOP padding`
							: 'Instruction patched successfully';
						vscode.window.showInformationMessage(msg);
					} else {
						vscode.window.showErrorMessage(`Patch failed: ${result.error}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Patch error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.nopInstruction', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No instruction selected');
				return;
			}

			const confirm = await vscode.window.showQuickPick(['Yes', 'No'], {
				placeHolder: `NOP instruction at 0x${addr.toString(16)}?`
			});

			if (confirm === 'Yes') {
				try {
					const success = await engine.nopInstruction(addr);
					if (success) {
						disasmEditorProvider.refresh();
						vscode.window.showInformationMessage('Instruction replaced with NOPs');
					} else {
						vscode.window.showErrorMessage('Failed to NOP instruction');
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`NOP error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.assemble', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const code = await vscode.window.showInputBox({
				prompt: 'Assemble instruction',
				placeHolder: 'mov rax, 0x1234'
			});

			if (code) {
				try {
					const result = await engine.assemble(code);
					if (result.success) {
						const hex = result.bytes.toString('hex').toUpperCase().match(/.{2}/g)?.join(' ');
						vscode.window.showInformationMessage(`${result.size} bytes: ${hex}`);
					} else {
						vscode.window.showErrorMessage(`Assembly error: ${result.error}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Assembly error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.assembleMultiple', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const input = await vscode.window.showInputBox({
				prompt: 'Assemble multiple instructions (separate with ;)',
				placeHolder: 'push rbp; mov rbp, rsp; sub rsp, 0x20'
			});

			if (input) {
				const instructions = input.split(';').map(s => s.trim()).filter(s => s.length > 0);
				try {
					const results = await engine.assembleMultiple(instructions);
					const allBytes: Buffer[] = [];
					let hasError = false;

					for (const r of results) {
						if (r.success) {
							allBytes.push(r.bytes);
						} else {
							vscode.window.showErrorMessage(`Error in "${r.statement}": ${r.error}`);
							hasError = true;
							break;
						}
					}

					if (!hasError) {
						const combined = Buffer.concat(allBytes);
						const hex = combined.toString('hex').toUpperCase().match(/.{2}/g)?.join(' ');
						vscode.window.showInformationMessage(`${combined.length} bytes: ${hex}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Assembly error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.savePatchedFile', async () => {
			const uri = await vscode.window.showSaveDialog({
				filters: {
					'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
					'All Files': ['*']
				},
				saveLabel: 'Save Patched File'
			});

			if (uri) {
				try {
					engine.savePatched(uri.fsPath);
					vscode.window.showInformationMessage(`Patched file saved to ${uri.fsPath}`);
				} catch (error: any) {
					vscode.window.showErrorMessage(`Save error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.setSyntax', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const syntax = await vscode.window.showQuickPick(['Intel', 'AT&T'], {
				placeHolder: 'Select assembly syntax'
			});

			if (syntax) {
				engine.setAssemblySyntax(syntax === 'Intel' ? 'intel' : 'att');
				vscode.window.showInformationMessage(`Syntax set to ${syntax}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.showLlvmVersion', () => {
			engine.getAssemblerAvailability().then((availability) => {
				if (!availability.available) {
					const detail = availability.error ? ` ${availability.error}` : '';
					vscode.window.showErrorMessage(
						vscode.l10n.t('LLVM MC engine is not available.{0}', detail)
					);
					return;
				}
				const version = engine.getLlvmVersion();
				vscode.window.showInformationMessage(`LLVM MC Version: ${version}`);
			});
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.nativeStatus', async () => {
			await showNativeStatus();
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzeAll', async (arg?: vscode.Uri | AnalyzeAllCommandOptions) => {
			const options = normalizeAnalyzeAllCommandOptions(arg);
			const targetFilePath = await resolveAnalyzeAllTargetFilePath(arg, options, engine);
			if (!targetFilePath) {
				const errorMessage = 'No binary file is selected for analysis.';
				if (options.quiet) {
					throw new Error(errorMessage);
				}
				vscode.window.showWarningMessage(errorMessage);
				return undefined;
			}

			const runAnalysis = async (progress?: vscode.Progress<{ message?: string }>): Promise<number> => {
				engine.reloadConfig();
				const currentFile = engine.getFilePath();
				const forceReload = shouldForceReloadAnalyzeAll(options);
				if (forceReload || currentFile !== targetFilePath) {
					progress?.report({ message: `Loading ${path.basename(targetFilePath)}...` });
					const loaded = await engine.loadFile(targetFilePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${targetFilePath}`);
					}
				}

				const defaultLimits = engine.getAnalysisLimits();
				const requestedLimits = resolveAnalyzeAllLimits(options);
				const overrideMaxFunctions = requestedLimits.maxFunctions ?? defaultLimits.maxFunctions;
				const overrideMaxFunctionSize = requestedLimits.maxFunctionSize ?? defaultLimits.maxFunctionSize;
				const hasOverride = overrideMaxFunctions !== defaultLimits.maxFunctions
					|| overrideMaxFunctionSize !== defaultLimits.maxFunctionSize;

				if (hasOverride) {
					engine.setAnalysisLimits(overrideMaxFunctions, overrideMaxFunctionSize);
					progress?.report({
						message: `Applying limits (maxFunctions=${overrideMaxFunctions}, maxFunctionSize=${overrideMaxFunctionSize})...`
					});
				}

				try {
					progress?.report({ message: 'Scanning for function prologs and references...' });
					return engine.analyzeAll();
				} finally {
					if (hasOverride) {
						engine.setAnalysisLimits(defaultLimits.maxFunctions, defaultLimits.maxFunctionSize);
					}
				}
			};

			const newFunctions = options.quiet
				? await runAnalysis()
				: await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: 'Analyzing binary...',
						cancellable: false
					},
					async progress => runAnalysis(progress)
				);

			functionProvider.refresh();
			stringRefProvider.refresh();
			sectionProvider.refresh();
			importProvider.refresh();
			exportProvider.refresh();

			const result = createAnalyzeAllResult(engine, targetFilePath, newFunctions);
			if (options.output) {
				writeAnalyzeAllOutput(result, options.output);
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					`Analysis complete: ${result.newFunctions} new functions found (${result.totalFunctions} total)`
				);
			}

			return result;
		})
	);

	console.log('HexCore Disassembler extension activated');
}

export function deactivate(): void {
	DisassemblerFactory.getInstance().disposeAll();
}

function normalizeAnalyzeAllCommandOptions(arg?: vscode.Uri | AnalyzeAllCommandOptions): AnalyzeAllCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}

	const raw = arg as AnalyzeAllCommandOptions;
	const normalized: AnalyzeAllCommandOptions = {};

	if (typeof raw.file === 'string') {
		normalized.file = raw.file;
	}
	if (raw.output) {
		normalized.output = raw.output;
	}
	if (typeof raw.quiet === 'boolean') {
		normalized.quiet = raw.quiet;
	}
	if (raw.maxFunctions !== undefined) {
		normalized.maxFunctions = parsePositiveIntegerOption(raw.maxFunctions, 'maxFunctions');
	}
	if (raw.maxFunctionSize !== undefined) {
		normalized.maxFunctionSize = parsePositiveIntegerOption(raw.maxFunctionSize, 'maxFunctionSize');
	}
	if (raw.forceReload !== undefined) {
		if (typeof raw.forceReload !== 'boolean') {
			throw new Error('Invalid "forceReload" option: expected boolean.');
		}
		normalized.forceReload = raw.forceReload;
	}

	return normalized;
}

async function resolveAnalyzeAllTargetFilePath(
	arg: vscode.Uri | AnalyzeAllCommandOptions | undefined,
	options: AnalyzeAllCommandOptions,
	engine: DisassemblerEngine
): Promise<string | undefined> {
	if (arg instanceof vscode.Uri && arg.scheme === 'file') {
		return arg.fsPath;
	}

	if (typeof options.file === 'string' && options.file.length > 0) {
		return path.resolve(options.file);
	}

	const activeFilePath = getActiveFilePath();
	if (activeFilePath) {
		return activeFilePath;
	}

	const loadedFilePath = engine.getFilePath();
	if (loadedFilePath) {
		return loadedFilePath;
	}

	if (options.quiet) {
		return undefined;
	}

	const uris = await vscode.window.showOpenDialog({
		canSelectMany: false,
		openLabel: 'Analyze',
		filters: {
			'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
			'All Files': ['*']
		}
	});
	return uris?.[0]?.fsPath;
}

function getActiveFilePath(): string | undefined {
	const uri = vscode.window.activeTextEditor?.document.uri;
	if (!uri || uri.scheme !== 'file') {
		return undefined;
	}
	return uri.fsPath;
}

function shouldForceReloadAnalyzeAll(options: AnalyzeAllCommandOptions): boolean {
	if (typeof options.forceReload === 'boolean') {
		return options.forceReload;
	}
	return options.quiet === true;
}

function resolveAnalyzeAllLimits(options: AnalyzeAllCommandOptions): { maxFunctions?: number; maxFunctionSize?: number } {
	return {
		maxFunctions: options.maxFunctions,
		maxFunctionSize: options.maxFunctionSize
	};
}

function parsePositiveIntegerOption(value: number, optionName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new Error(`Invalid "${optionName}" option: expected finite number.`);
	}
	const normalized = Math.floor(value);
	if (normalized < 1) {
		throw new Error(`Invalid "${optionName}" option: expected value >= 1.`);
	}
	return normalized;
}

function normalizeRunJobCommandOptions(arg?: vscode.Uri | string | RunJobCommandOptions): RunJobCommandOptions {
	if (arg === undefined) {
		return {};
	}
	if (arg instanceof vscode.Uri) {
		return { jobFile: arg.fsPath };
	}
	if (typeof arg === 'string') {
		return { jobFile: arg };
	}
	return arg;
}

function resolveJobFilePath(arg: vscode.Uri | string | RunJobCommandOptions | undefined, explicitPath?: string): string | undefined {
	if (typeof explicitPath === 'string' && explicitPath.length > 0) {
		return path.resolve(explicitPath);
	}

	if (arg instanceof vscode.Uri) {
		return arg.fsPath;
	}

	if (typeof arg === 'string' && arg.length > 0) {
		return path.resolve(arg);
	}

	const folders = vscode.workspace.workspaceFolders ?? [];
	for (const folder of folders) {
		const candidate = path.join(folder.uri.fsPath, '.hexcore_job.json');
		if (fs.existsSync(candidate)) {
			return candidate;
		}
	}

	return undefined;
}

function createAnalyzeAllResult(engine: DisassemblerEngine, targetFilePath: string, newFunctions: number): AnalyzeAllResult {
	const functions = engine.getFunctions();
	const functionSummaries: AnalyzeAllFunctionSummary[] = functions.map(func => ({
		address: toHexAddress(func.address),
		name: func.name,
		size: func.size,
		instructionCount: func.instructions.length,
		callers: func.callers.length,
		callees: func.callees.length
	}));

	const result: AnalyzeAllResult = {
		filePath: targetFilePath,
		fileName: path.basename(targetFilePath),
		newFunctions,
		totalFunctions: functions.length,
		totalStrings: engine.getStrings().length,
		architecture: engine.getArchitecture(),
		baseAddress: toHexAddress(engine.getBaseAddress()),
		sections: engine.getSections().length,
		imports: engine.getImports().length,
		exports: engine.getExports().length,
		functions: functionSummaries,
		reportMarkdown: ''
	};

	result.reportMarkdown = generateAnalyzeAllReport(result);
	return result;
}

function generateAnalyzeAllReport(result: AnalyzeAllResult): string {
	let report = `# HexCore Disassembly Analysis Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${result.fileName} |
| **File Path** | ${result.filePath} |
| **Architecture** | ${result.architecture} |
| **Base Address** | ${result.baseAddress} |

---

## Analysis Summary

| Metric | Value |
|--------|-------|
| **New Functions** | ${result.newFunctions} |
| **Total Functions** | ${result.totalFunctions} |
| **Total Strings** | ${result.totalStrings} |
| **Sections** | ${result.sections} |
| **Imports** | ${result.imports} |
| **Exports** | ${result.exports} |

---

## Functions (Top 100)

| Address | Name | Size | Instructions | Callers | Callees |
|---------|------|------|--------------|---------|---------|
`;

	for (const func of result.functions.slice(0, 100)) {
		report += `| ${func.address} | ${func.name} | ${func.size} | ${func.instructionCount} | ${func.callers} | ${func.callees} |\n`;
	}

	if (result.functions.length > 100) {
		report += `| ... | ... | ... | ... | ... | ... |\n`;
	}

	report += `
---
*Generated by HexCore Disassembler*
`;

	return report;
}

function writeAnalyzeAllOutput(result: AnalyzeAllResult, output: AnalyzeAllOutputOptions): void {
	const format = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(output.path, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				filePath: result.filePath,
				fileName: result.fileName,
				newFunctions: result.newFunctions,
				totalFunctions: result.totalFunctions,
				totalStrings: result.totalStrings,
				architecture: result.architecture,
				baseAddress: result.baseAddress,
				sections: result.sections,
				imports: result.imports,
				exports: result.exports,
				functions: result.functions,
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

function toHexAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

