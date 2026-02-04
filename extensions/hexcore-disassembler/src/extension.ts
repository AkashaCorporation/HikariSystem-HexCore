/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as path from 'path';
import { DisassemblerViewProvider } from './disassemblerView';
import { DisassemblyEditorProvider } from './disassemblyEditor';
import { FunctionTreeProvider } from './functionTree';
import { StringRefProvider } from './stringRefTree';
import { SectionTreeProvider } from './sectionTree';
import { ImportTreeProvider } from './importTree';
import { ExportTreeProvider } from './exportTree';
import { DisassemblerEngine } from './disassemblerEngine';
import { DisassemblerFactory } from './disassemblerFactory';
import { GraphViewProvider } from './graphViewProvider';

export function activate(context: vscode.ExtensionContext): void {
	// Use Factory to get the initial global engine (or specific if we knew context)
	const factory = DisassemblerFactory.getInstance();
	const engine = factory.getEngine(); // Default global engine for now

	// Event emitter for synchronization between views
	const onDidChangeActiveEditor = new vscode.EventEmitter<string | undefined>();

	const disasmProvider = new DisassemblerViewProvider(context.extensionUri, engine);
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
			'hexcore.disassembler.view',
			disasmProvider,
			{ webviewOptions: { retainContextWhenHidden: true } }
		)
	);

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
					await disasmProvider.loadFile(uri.fsPath);
					functionProvider.refresh();
					stringRefProvider.refresh();
					sectionProvider.refresh();
					importProvider.refresh();
					exportProvider.refresh();
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
				disasmProvider.navigateToAddress(targetAddress);

				// Sync Graph View if function exists
				let func = engine.getFunctionAt(targetAddress);
				if (!func) {
					// Try to find containing function
					const funcs = engine.getFunctions();
					func = funcs.find(f => targetAddress >= f.address && targetAddress < f.endAddress);
				}

				if (func) {
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
				disasmProvider.showXrefs(xrefs);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.addComment', async () => {
			const addr = disasmProvider.getCurrentAddress();
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
				disasmProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.renameFunction', async (item?: any) => {
			const addr = item?.address || disasmProvider.getCurrentAddress();
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
				disasmProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.showCFG', async () => {
			const addr = disasmProvider.getCurrentFunctionAddress();
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

			const addr = disasmProvider.getCurrentAddress();
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
						disasmProvider.refresh();
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

			const addr = disasmProvider.getCurrentAddress();
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
						disasmProvider.refresh();
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

	console.log('HexCore Disassembler extension activated');
}

export function deactivate(): void {
	DisassemblerFactory.getInstance().disposeAll();
}

