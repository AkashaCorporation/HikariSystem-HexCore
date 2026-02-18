/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as path from 'path';
import { DisassemblerEngine, Instruction, Function, XRef, Section, FileInfo } from './disassemblerEngine';
import { getHexCoreBaseCSS } from 'hexcore-common';
import { addressToOffset } from './addressConversion';
import { AnnotationStore, AnnotationEntry } from './annotationStore';

export class DisassemblerViewProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private currentAddress: number = 0;
	private currentFunction?: number;
	private selectedAddress?: number;
	private engine: DisassemblerEngine;
	private remillAvailable: boolean = false;
	private currentSyntax: 'intel' | 'att' = 'intel';
	private syncEnabled: boolean = false;
	private annotationStore?: AnnotationStore;
	private firstAnnotationSaved: boolean = false;

	constructor(
		private readonly extensionUri: vscode.Uri,
		engine: DisassemblerEngine
	) {
		this.engine = engine;
		try {
			const remillExt = vscode.extensions.getExtension('hikarisystem.hexcore-remill');
			this.remillAvailable = !!remillExt;
		} catch {
			this.remillAvailable = false;
		}
	}

	resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this.view = webviewView;
		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this.extensionUri]
		};

		webviewView.webview.html = this.getInitialHtml();

		webviewView.webview.onDidReceiveMessage(async (message) => {
			switch (message.command) {
				case 'jumpTo':
					this.navigateToAddress(message.address);
					break;
				case 'selectInstruction':
					this.selectedAddress = message.address;
					// Sync with Hex Viewer when sync is enabled
					if (this.syncEnabled && typeof message.address === 'number') {
						const fileInfo = this.engine.getFileInfo();
						const baseAddress = fileInfo?.baseAddress ?? 0;
						const offset = addressToOffset(message.address, baseAddress);
						try {
							vscode.commands.executeCommand('hexcore.hexview.goToOffset', offset);
						} catch {
							// Hex Viewer extension may not be active
						}
					}
					break;
				case 'contextMenu':
					this.showContextMenu(message.address, message.x, message.y);
					break;
				case 'addComment':
					await this.addCommentAt(message.address);
					break;
				case 'editComment':
					await this.editCommentAt(message.address);
					break;
				case 'deleteComment':
					await this.deleteCommentAt(message.address);
					break;
				case 'loadAnnotations':
					this.sendAnnotationsToWebview();
					break;
				case 'patchInstruction':
					await vscode.commands.executeCommand('hexcore.disasm.patchInstruction');
					break;
				case 'nopInstruction':
					await vscode.commands.executeCommand('hexcore.disasm.nopInstruction');
					break;
				case 'findXrefs': {
					const xrefs = await this.engine.findCrossReferences(message.address);
					this.showXrefs(xrefs);
					break;
				}
				case 'searchStringRefs':
					try {
						const refs = await vscode.commands.executeCommand('hexcore.disasm.searchStringRefs');
						if (refs && this.view) {
							this.view.webview.postMessage({ command: 'showStringRefs', data: refs });
						}
					} catch (err: any) {
						vscode.window.showErrorMessage(`Search String Refs failed: ${err?.message || err}`);
					}
					break;
				case 'exportAsm':
					try {
						const result = await vscode.commands.executeCommand('hexcore.disasm.exportAssembly');
						if (result) {
							const doc = await vscode.workspace.openTextDocument({ content: String(result), language: 'asm' });
							await vscode.window.showTextDocument(doc, { preview: true });
						}
					} catch (err: any) {
						vscode.window.showErrorMessage(`Export ASM failed: ${err?.message || err}`);
					}
					break;
				case 'goToAddress': {
					const addr = parseInt(message.address, 16);
					if (!isNaN(addr)) {
						this.navigateToAddress(addr);
					}
					break;
				}
				case 'deepAnalysis':
					await vscode.commands.executeCommand('hexcore.disasm.deepAnalysis');
					break;
				case 'showCFG':
					this.showControlFlowGraph(this.selectedAddress || this.currentAddress);
					break;
				case 'buildFormula':
					await vscode.commands.executeCommand('hexcore.disasm.buildFormula');
					break;
				case 'liftToIR':
					await vscode.commands.executeCommand('hexcore.disasm.liftToIR');
					break;
				case 'checkConstants':
					try {
						const findings = await vscode.commands.executeCommand('hexcore.disasm.checkConstants');
						if (findings && this.view) {
							this.view.webview.postMessage({ command: 'showConstantCheck', data: findings });
						}
					} catch (err: any) {
						vscode.window.showErrorMessage(`Check Constants failed: ${err?.message || err}`);
					}
					break;
				case 'toggleSyntax':
					this.currentSyntax = this.currentSyntax === 'intel' ? 'att' : 'intel';
					await vscode.commands.executeCommand('hexcore.disasm.setSyntax', this.currentSyntax);
					this.refresh();
					break;
				case 'toggleSync':
					this.syncEnabled = !this.syncEnabled;
					if (this.view) {
						this.view.webview.postMessage({ command: 'syncState', enabled: this.syncEnabled });
					}
					break;
				case 'syncToHex':
					// Explicit sync request from webview — convert address to offset and navigate Hex Viewer
					if (typeof message.address === 'number') {
						const fileInfo = this.engine.getFileInfo();
						const baseAddress = fileInfo?.baseAddress ?? 0;
						const offset = addressToOffset(message.address, baseAddress);
						try {
							vscode.commands.executeCommand('hexcore.hexview.goToOffset', offset);
						} catch {
							// Hex Viewer extension may not be active
						}
					}
					break;
				case 'changeArch':
					await vscode.commands.executeCommand('hexcore.disasm.setSyntax', message.arch);
					break;
			}
		});
	}

	async loadFile(filePath: string): Promise<void> {
		await this.engine.loadFile(filePath);
		const funcs = this.engine.getFunctions();
		if (funcs.length > 0) {
			this.currentFunction = funcs[0].address;
		}
		// Initialize annotation store and load existing annotations
		this.annotationStore = new AnnotationStore(filePath);
		try {
			this.annotationStore.load();
		} catch {
			vscode.window.showWarningMessage('Failed to load annotations — file may be corrupted. A backup was created.');
		}
		this.firstAnnotationSaved = false;
		await this.refresh();
		this.sendAnnotationsToWebview();
		if (this.view) {
			this.view.show?.(true);
		}
	}

	async refresh(): Promise<void> {
		if (!this.view) {
			return;
		}

		const fileInfo = this.engine.getFileInfo();
		const sections = this.engine.getSections();
		const funcs = this.engine.getFunctions();
		const func = this.currentFunction ? this.engine.getFunctionAt(this.currentFunction) : undefined;

		this.view.webview.postMessage({
			command: 'updateView',
			data: {
				fileInfo: fileInfo ? {
					...fileInfo,
					fileName: this.engine.getFileName(),
					timestamp: fileInfo.timestamp?.toISOString()
				} : null,
				sections: sections,
				functions: funcs.map(f => ({
					address: f.address,
					name: f.name,
					size: f.size
				})),
				currentFunction: func ? {
					...func,
					instructions: func.instructions.map(inst => ({
						...inst,
						bytes: Array.from(inst.bytes)
					}))
				} : null,
				selectedAddress: this.selectedAddress,
				syntax: this.currentSyntax,
				syncEnabled: this.syncEnabled,
				remillAvailable: this.remillAvailable
			}
		});
	}

	navigateToAddress(address: number): void {
		this.currentAddress = address;
		this.selectedAddress = address;

		const funcs = this.engine.getFunctions();
		for (const func of funcs) {
			if (address >= func.address && address < func.endAddress) {
				this.currentFunction = func.address;
				break;
			}
		}
		this.refresh();
	}

	getCurrentAddress(): number | undefined {
		return this.selectedAddress || this.currentAddress;
	}

	getCurrentFunctionAddress(): number | undefined {
		return this.currentFunction;
	}

	private async addCommentAt(address: number): Promise<void> {
		const addrHex = '0x' + address.toString(16).toUpperCase();
		const existing = this.annotationStore?.getAll()[addrHex];
		const comment = await vscode.window.showInputBox({
			prompt: `Add comment at ${addrHex}`,
			placeHolder: 'Enter comment...',
			value: existing?.comment
		});
		if (comment !== undefined && comment.length > 0) {
			this.engine.addComment(address, comment);
			if (this.annotationStore) {
				if (!this.firstAnnotationSaved) {
					this.annotationStore.ensureGitignore();
					this.firstAnnotationSaved = true;
				}
				this.annotationStore.setComment(addrHex, comment);
			}
			this.sendAnnotationsToWebview();
			this.refresh();
		}
	}

	private async editCommentAt(address: number): Promise<void> {
		const addrHex = '0x' + address.toString(16).toUpperCase();
		const existing = this.annotationStore?.getAll()[addrHex];
		if (!existing) {
			return this.addCommentAt(address);
		}
		const comment = await vscode.window.showInputBox({
			prompt: `Edit comment at ${addrHex}`,
			placeHolder: 'Enter comment...',
			value: existing.comment
		});
		if (comment !== undefined && comment.length > 0) {
			this.engine.addComment(address, comment);
			if (this.annotationStore) {
				this.annotationStore.setComment(addrHex, comment);
			}
			this.sendAnnotationsToWebview();
			this.refresh();
		}
	}

	private async deleteCommentAt(address: number): Promise<void> {
		const addrHex = '0x' + address.toString(16).toUpperCase();
		if (this.annotationStore) {
			this.annotationStore.deleteComment(addrHex);
		}
		this.sendAnnotationsToWebview();
		this.refresh();
	}

	private sendAnnotationsToWebview(): void {
		if (!this.view || !this.annotationStore) {
			return;
		}
		const annotations = this.annotationStore.getAll();
		this.view.webview.postMessage({
			command: 'updateAnnotations',
			annotations
		});
	}

	private async showContextMenu(address: number, x: number, y: number): Promise<void> {
		// Context menu handled via webview
	}

	showXrefs(xrefs: XRef[]): void {
		if (!this.view || xrefs.length === 0) {
			vscode.window.showInformationMessage('No cross-references found');
			return;
		}

		type XrefPickItem = vscode.QuickPickItem & { address: number };
		const items: XrefPickItem[] = xrefs.map(x => ({
			label: `0x${x.from.toString(16).toUpperCase()}`,
			description: x.type,
			address: x.from
		}));

		vscode.window.showQuickPick<XrefPickItem>(items, {
			placeHolder: `${xrefs.length} cross-references found`
		}).then(selected => {
			if (selected) {
				this.navigateToAddress(selected.address);
			}
		});
	}

	showControlFlowGraph(address: number): void {
		// Handled by graphViewProvider
	}

	private getInitialHtml(): string {
		const baseCSS = getHexCoreBaseCSS();
		const remillAvailable = this.remillAvailable;
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>HexCore Disassembler</title>
	<style>
		${baseCSS}

		:root {
			--bg-primary: #1e1e1e;
			--bg-secondary: #252526;
			--bg-tertiary: #2d2d30;
			--bg-hover: #3c3c3c;
			--bg-selected: #094771;
			--text-primary: #d4d4d4;
			--text-secondary: #808080;
			--text-muted: #5a5a5a;
			--border-color: #3c3c3c;
			--accent-blue: #569cd6;
			--accent-green: #4ec9b0;
			--accent-yellow: #dcdcaa;
			--accent-orange: #ce9178;
			--accent-purple: #c586c0;
			--accent-red: #f44747;
			--address-color: #858585;
			--bytes-color: #6a9955;
			--mnemonic-color: #569cd6;
			--register-color: #9cdcfe;
			--number-color: #b5cea8;
			--string-color: #ce9178;
			--comment-color: #6a9955;
			--label-color: #4ec9b0;
		}

		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: var(--hexcore-mono, 'Consolas', 'Monaco', 'Courier New', monospace);
			font-size: 12px;
			line-height: 1.5;
			background: var(--bg-primary);
			color: var(--text-primary);
			overflow: hidden;
			height: 100vh;
			display: flex;
			flex-direction: column;
		}

		#app {
			display: flex;
			flex-direction: column;
			flex: 1;
			min-height: 0;
			overflow: hidden;
		}

		/* Header */
		.header {
			background: var(--bg-secondary);
			border-bottom: 1px solid var(--border-color);
			padding: 8px 12px;
		}

		.header-title {
			font-size: 13px;
			font-weight: 600;
			color: var(--text-primary);
			margin-bottom: 4px;
		}

		.header-info {
			display: flex;
			flex-wrap: wrap;
			gap: 16px;
			font-size: 11px;
			color: var(--text-secondary);
		}

		.header-item {
			display: flex;
			align-items: center;
			gap: 4px;
		}

		.header-item .label {
			color: var(--text-muted);
		}

		.header-item .value {
			color: var(--accent-blue);
		}

		.header-item .value.clickable {
			cursor: pointer;
			text-decoration: underline;
		}

		.header-item .value.clickable:hover {
			color: var(--accent-green);
		}

		/* Toolbar */
		.toolbar {
			background: var(--bg-tertiary);
			border-bottom: 1px solid var(--border-color);
			padding: 4px 8px;
			display: flex;
			gap: 4px;
			align-items: center;
			flex-wrap: wrap;
		}

		.toolbar-btn {
			background: transparent;
			border: 1px solid transparent;
			color: var(--text-secondary);
			padding: 4px 8px;
			cursor: pointer;
			font-size: 11px;
			border-radius: 3px;
			display: flex;
			align-items: center;
			gap: 4px;
			white-space: nowrap;
		}

		.toolbar-btn:hover {
			background: var(--bg-hover);
			color: var(--text-primary);
		}

		.toolbar-btn.active {
			background: var(--bg-selected);
			color: var(--text-primary);
		}

		.toolbar-separator {
			width: 1px;
			height: 20px;
			background: var(--border-color);
			margin: 0 4px;
		}

		.toolbar-right {
			margin-left: auto;
			display: flex;
			gap: 4px;
			align-items: center;
		}

		.toolbar-input {
			background: var(--bg-primary);
			border: 1px solid var(--border-color);
			color: var(--text-primary);
			padding: 3px 6px;
			font-size: 11px;
			font-family: inherit;
			border-radius: 3px;
			width: 100px;
		}

		.toolbar-input:focus {
			border-color: var(--accent-blue);
			outline: none;
		}

		.toolbar-input::placeholder {
			color: var(--text-muted);
		}

		.syntax-toggle {
			font-weight: 600;
			min-width: 50px;
			text-align: center;
		}

		/* Main Content */
		.main-content {
			display: flex;
			flex: 1;
			min-height: 0;
			overflow: hidden;
		}

		/* Function List Sidebar */
		.sidebar {
			width: 200px;
			background: var(--bg-secondary);
			border-right: 1px solid var(--border-color);
			display: flex;
			flex-direction: column;
		}

		.sidebar-header {
			padding: 8px;
			font-size: 11px;
			font-weight: 600;
			color: var(--text-secondary);
			border-bottom: 1px solid var(--border-color);
			text-transform: uppercase;
		}

		.sidebar-content {
			flex: 1;
			overflow-y: auto;
		}

		.function-item {
			padding: 4px 8px;
			cursor: pointer;
			display: flex;
			align-items: center;
			gap: 6px;
			border-left: 2px solid transparent;
		}

		.function-item:hover {
			background: var(--bg-hover);
		}

		.function-item.active {
			background: var(--bg-selected);
			border-left-color: var(--accent-blue);
		}

		.function-item .icon {
			color: var(--accent-yellow);
			font-size: 10px;
		}

		.function-item .name {
			flex: 1;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
			color: var(--label-color);
		}

		.function-item .addr {
			font-size: 10px;
			color: var(--text-muted);
		}

		/* Disassembly View */
		.disasm-container {
			flex: 1;
			display: flex;
			flex-direction: column;
			overflow: hidden;
		}

		.disasm-header {
			background: var(--bg-tertiary);
			padding: 6px 12px;
			border-bottom: 1px solid var(--border-color);
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.disasm-header .func-name {
			color: var(--label-color);
			font-weight: 600;
		}

		.disasm-header .func-info {
			color: var(--text-muted);
			font-size: 11px;
		}

		.disasm-content {
			flex: 1;
			overflow-y: auto;
			padding: 4px 0;
		}

		/* Instruction Row */
		.instruction {
			display: flex;
			padding: 1px 12px;
			cursor: pointer;
			border-left: 2px solid transparent;
		}

		.instruction:hover {
			background: var(--bg-hover);
		}

		.instruction.selected {
			background: var(--bg-selected);
			border-left-color: var(--accent-blue);
		}

		.instruction.breakpoint {
			border-left-color: var(--accent-red);
		}

		.instruction.call-target {
			background: rgba(78, 201, 176, 0.1);
		}

		.inst-address {
			min-width: 100px;
			color: var(--address-color);
			user-select: none;
		}

		.inst-bytes {
			min-width: 140px;
			color: var(--bytes-color);
			font-size: 10px;
			opacity: 0.7;
			user-select: none;
		}

		.inst-mnemonic {
			min-width: 70px;
			color: var(--mnemonic-color);
			font-weight: 500;
		}

		.inst-mnemonic.call { color: var(--accent-green); }
		.inst-mnemonic.jump { color: var(--accent-purple); }
		.inst-mnemonic.ret { color: var(--accent-red); }

		.inst-operands {
			flex: 1;
			color: var(--text-primary);
		}

		.inst-operands .register { color: var(--register-color); }
		.inst-operands .number { color: var(--number-color); }
		.inst-operands .address { color: var(--accent-green); cursor: pointer; text-decoration: underline; }
		.inst-operands .string { color: var(--string-color); }

		.inst-comment {
			color: var(--comment-color);
			margin-left: 20px;
			font-style: italic;
		}

		.inst-comment::before {
			content: '; ';
		}

		.inst-annotation {
			color: var(--vscode-editorLineNumber-foreground, #858585);
			margin-left: 20px;
			font-style: italic;
			cursor: pointer;
		}

		.inst-annotation::before {
			content: '; ';
		}

		.inst-annotation:hover {
			color: var(--accent-blue);
			text-decoration: underline;
		}

		/* Section Labels */
		.section-label {
			padding: 8px 12px 4px;
			color: var(--label-color);
			font-weight: 600;
			border-top: 1px solid var(--border-color);
			margin-top: 8px;
		}

		.section-label::before {
			content: '';
			display: inline-block;
			width: 8px;
			height: 8px;
			background: var(--accent-green);
			margin-right: 8px;
			border-radius: 2px;
		}

		/* Xref indicator */
		.xref-badge {
			background: var(--bg-tertiary);
			color: var(--accent-blue);
			font-size: 9px;
			padding: 1px 4px;
			border-radius: 2px;
			margin-left: 8px;
		}

		/* Results Panel (right side) */
		.results-panel {
			width: 280px;
			background: var(--bg-secondary);
			border-left: 1px solid var(--border-color);
			display: none;
			flex-direction: column;
			overflow: hidden;
		}

		.results-panel.visible {
			display: flex;
		}

		.results-panel-header {
			padding: 8px 12px;
			font-size: 11px;
			font-weight: 600;
			color: var(--text-secondary);
			border-bottom: 1px solid var(--border-color);
			display: flex;
			justify-content: space-between;
			align-items: center;
			text-transform: uppercase;
		}

		.results-panel-close {
			background: transparent;
			border: none;
			color: var(--text-secondary);
			cursor: pointer;
			font-size: 14px;
			padding: 0 4px;
		}

		.results-panel-close:hover {
			color: var(--text-primary);
		}

		.results-panel-content {
			flex: 1;
			overflow-y: auto;
			padding: 4px 0;
		}

		.result-item {
			padding: 4px 12px;
			cursor: pointer;
			display: flex;
			align-items: center;
			gap: 8px;
			font-size: 11px;
		}

		.result-item:hover {
			background: var(--bg-hover);
		}

		.result-item .result-addr {
			color: var(--address-color);
			font-family: var(--hexcore-mono, monospace);
			min-width: 80px;
		}

		.result-item .result-text {
			flex: 1;
			overflow: hidden;
			text-overflow: ellipsis;
			white-space: nowrap;
			color: var(--text-primary);
		}

		.result-item .result-text.suspicious {
			color: var(--hexcore-danger, var(--accent-red));
		}

		.result-item .result-text.safe {
			color: var(--hexcore-safe, var(--accent-green));
		}

		.result-section-header {
			padding: 6px 12px;
			font-size: 10px;
			font-weight: 600;
			color: var(--text-muted);
			text-transform: uppercase;
			border-top: 1px solid var(--border-color);
			margin-top: 4px;
		}

		/* Welcome Screen */
		.welcome {
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			height: 100%;
			color: var(--text-secondary);
			text-align: center;
			padding: 40px;
		}

		.welcome-icon {
			font-size: 48px;
			margin-bottom: 16px;
			opacity: 0.5;
		}

		.welcome-title {
			font-size: 16px;
			font-weight: 600;
			margin-bottom: 8px;
			color: var(--text-primary);
		}

		.welcome-text {
			font-size: 12px;
			line-height: 1.6;
			max-width: 300px;
		}

		.welcome-shortcut {
			margin-top: 16px;
			padding: 8px 16px;
			background: var(--bg-tertiary);
			border-radius: 4px;
			font-size: 11px;
		}

		.welcome-shortcut kbd {
			background: var(--bg-hover);
			padding: 2px 6px;
			border-radius: 3px;
			margin: 0 2px;
		}

		/* Context Menu */
		.context-menu {
			position: fixed;
			background: var(--bg-secondary);
			border: 1px solid var(--border-color);
			border-radius: 4px;
			padding: 4px 0;
			min-width: 180px;
			box-shadow: 0 4px 12px rgba(0,0,0,0.3);
			z-index: 1000;
			display: none;
		}

		.context-menu.visible {
			display: block;
		}

		.context-menu-item {
			padding: 6px 12px;
			cursor: pointer;
			display: flex;
			align-items: center;
			gap: 8px;
		}

		.context-menu-item:hover {
			background: var(--bg-hover);
		}

		.context-menu-item .shortcut {
			margin-left: auto;
			color: var(--text-muted);
			font-size: 10px;
		}

		.context-menu-separator {
			height: 1px;
			background: var(--border-color);
			margin: 4px 0;
		}

		/* Scrollbar */
		::-webkit-scrollbar {
			width: 10px;
			height: 10px;
		}

		::-webkit-scrollbar-track {
			background: var(--bg-primary);
		}

		::-webkit-scrollbar-thumb {
			background: var(--bg-hover);
			border-radius: 5px;
		}

		::-webkit-scrollbar-thumb:hover {
			background: var(--text-muted);
		}
	</style>
</head>
<body>
	<div id="app">
		<div class="welcome">
			<div class="welcome-icon">&#128269;</div>
			<div class="welcome-title">HexCore Disassembler</div>
			<div class="welcome-text">
				Open a binary file to start reverse engineering.<br>
				Supports PE, ELF, and raw binary formats.
			</div>
			<div class="welcome-shortcut">
				<kbd>Ctrl</kbd>+<kbd>Shift</kbd>+<kbd>P</kbd> → "Disassemble Binary"
			</div>
		</div>
	</div>

	<div class="context-menu" id="contextMenu">
		<div class="context-menu-item" data-action="goto">Go to Address <span class="shortcut">G</span></div>
		<div class="context-menu-item" data-action="xrefs">Find References <span class="shortcut">X</span></div>
		<div class="context-menu-separator"></div>
		<div class="context-menu-item" data-action="comment">Add Comment <span class="shortcut">;</span></div>
		<div class="context-menu-item" data-action="editComment">Edit Comment</div>
		<div class="context-menu-item" data-action="deleteComment">Delete Comment</div>
		<div class="context-menu-item" data-action="rename">Rename <span class="shortcut">N</span></div>
		<div class="context-menu-separator"></div>
		<div class="context-menu-item" data-action="patch">Patch Instruction <span class="shortcut">P</span></div>
		<div class="context-menu-item" data-action="nop">NOP Instruction</div>
		<div class="context-menu-separator"></div>
		<div class="context-menu-item" data-action="copy">Copy Address</div>
		<div class="context-menu-item" data-action="copyBytes">Copy Bytes</div>
	</div>

	<script>
		const vscode = acquireVsCodeApi();
		let currentData = null;
		let selectedAddress = null;
		let currentSyntax = 'intel';
		let syncEnabled = false;
		let remillAvailable = ${remillAvailable};
		let annotations = {};

		// Listen for messages from extension
		window.addEventListener('message', event => {
			const message = event.data;
			switch (message.command) {
				case 'updateView':
					currentData = message.data;
					if (message.data.syntax) currentSyntax = message.data.syntax;
					if (message.data.syncEnabled !== undefined) syncEnabled = message.data.syncEnabled;
					if (message.data.remillAvailable !== undefined) remillAvailable = message.data.remillAvailable;
					renderView();
					break;
				case 'showStringRefs':
					showResultsPanel('String References', message.data, 'strings');
					break;
				case 'showConstantCheck':
					showResultsPanel('Constant Check', message.data, 'constants');
					break;
				case 'syncState':
					syncEnabled = message.enabled;
					updateSyncButton();
					break;
				case 'updateAnnotations':
					annotations = message.annotations || {};
					renderView();
					break;
			}
		});

		function renderView() {
			if (!currentData || !currentData.fileInfo) {
				return;
			}

			const { fileInfo, sections, functions, currentFunction, selectedAddress: selAddr } = currentData;
			selectedAddress = selAddr;

			const app = document.getElementById('app');
			app.innerHTML = \`
				<div class="header">
					<div class="header-title">\${fileInfo.fileName || 'Unknown'}</div>
					<div class="header-info">
						<div class="header-item">
							<span class="label">Format:</span>
							<span class="value">\${fileInfo.format}</span>
						</div>
						<div class="header-item">
							<span class="label">Arch:</span>
							<span class="value clickable" onclick="changeArchitecture()" title="Click to change architecture">\${fileInfo.architecture}</span>
						</div>
						<div class="header-item">
							<span class="label">Entry:</span>
							<span class="value">0x\${fileInfo.entryPoint.toString(16).toUpperCase()}</span>
						</div>
						<div class="header-item">
							<span class="label">Base:</span>
							<span class="value">0x\${fileInfo.baseAddress.toString(16).toUpperCase()}</span>
						</div>
						\${fileInfo.subsystem ? \`
						<div class="header-item">
							<span class="label">Subsystem:</span>
							<span class="value">\${fileInfo.subsystem}</span>
						</div>\` : ''}
						<div class="header-item">
							<span class="label">Syntax:</span>
							<span class="value">\${currentSyntax.toUpperCase()}</span>
						</div>
					</div>
				</div>
				<div class="toolbar">
					<button class="toolbar-btn" onclick="sendCommand('searchStringRefs')" title="Search String References">&#128270; Strings</button>
					<button class="toolbar-btn" onclick="sendCommand('exportAsm')" title="Export Assembly">&#128190; Export ASM</button>
					<div class="toolbar-separator"></div>
					<input class="toolbar-input" id="goToAddrInput" type="text" placeholder="0x..." title="Go to Address" onkeydown="handleGoToAddress(event)" />
					<button class="toolbar-btn" onclick="goToAddressFromInput()" title="Go to Address">&#8594; Go</button>
					<div class="toolbar-separator"></div>
					<button class="toolbar-btn" onclick="sendCommand('deepAnalysis')" title="Deep Analysis (Prolog Scan + Xrefs)">&#128300; Deep Analysis</button>
					<button class="toolbar-btn" onclick="sendCommand('showCFG')" title="Show Control Flow Graph">&#9670; CFG</button>
					<button class="toolbar-btn" onclick="sendCommand('buildFormula')" title="Build Formula from Instructions">&#402; Formula</button>
					<button class="toolbar-btn" onclick="sendCommand('checkConstants')" title="Check Constant Annotation Sanity">&#10003; Constants</button>
					\${remillAvailable ? \`<button class="toolbar-btn" onclick="sendCommand('liftToIR')" title="Lift to LLVM IR (Remill)">&#9881; Lift to IR</button>\` : ''}
					<div class="toolbar-separator"></div>
					<button class="toolbar-btn syntax-toggle" onclick="sendCommand('toggleSyntax')" title="Toggle Intel/AT&T syntax">\${currentSyntax === 'intel' ? 'Intel' : 'AT&T'}</button>
					<button class="toolbar-btn \${syncEnabled ? 'active' : ''}" id="syncBtn" onclick="sendCommand('toggleSync')" title="Sync with Hex View">\${syncEnabled ? '&#128279; Sync ON' : '&#128279; Sync'}</button>
				</div>
				<div class="main-content">
					<div class="sidebar">
						<div class="sidebar-header">Functions (\${functions.length})</div>
						<div class="sidebar-content">
							\${functions.map(f => \`
								<div class="function-item \${currentFunction && f.address === currentFunction.address ? 'active' : ''}"
									onclick="jumpToFunction(\${f.address})">
									<span class="icon">&#402;</span>
									<span class="name">\${escapeHtml(f.name)}</span>
									<span class="addr">\${f.size}b</span>
								</div>
							\`).join('')}
						</div>
					</div>
					<div class="disasm-container">
						\${currentFunction ? \`
							<div class="disasm-header">
								<span class="func-name">\${escapeHtml(currentFunction.name)}</span>
								<span class="func-info">
									0x\${currentFunction.address.toString(16).toUpperCase()} -
									0x\${currentFunction.endAddress.toString(16).toUpperCase()}
									(\${currentFunction.size} bytes, \${currentFunction.instructions.length} instructions)
								</span>
							</div>
							<div class="disasm-content">
								\${renderInstructions(currentFunction.instructions)}
							</div>
						\` : \`
							<div class="welcome">
								<div class="welcome-text">Select a function from the sidebar</div>
							</div>
						\`}
					</div>
					<div class="results-panel" id="resultsPanel">
						<div class="results-panel-header">
							<span id="resultsPanelTitle">Results</span>
							<button class="results-panel-close" onclick="closeResultsPanel()" title="Close">&times;</button>
						</div>
						<div class="results-panel-content" id="resultsPanelContent"></div>
					</div>
				</div>
			\`;
		}

		function sendCommand(command, data) {
			vscode.postMessage({ command, ...data });
		}

		function handleGoToAddress(event) {
			if (event.key === 'Enter') {
				goToAddressFromInput();
			}
		}

		function goToAddressFromInput() {
			const input = document.getElementById('goToAddrInput');
			if (input && input.value) {
				vscode.postMessage({ command: 'goToAddress', address: input.value.replace(/^0x/i, '') });
				input.value = '';
			}
		}

		function changeArchitecture() {
			vscode.postMessage({ command: 'changeArch' });
		}

		function updateSyncButton() {
			const btn = document.getElementById('syncBtn');
			if (btn) {
				btn.className = 'toolbar-btn' + (syncEnabled ? ' active' : '');
				btn.innerHTML = syncEnabled ? '&#128279; Sync ON' : '&#128279; Sync';
			}
		}

		function showResultsPanel(title, data, type) {
			const panel = document.getElementById('resultsPanel');
			const titleEl = document.getElementById('resultsPanelTitle');
			const content = document.getElementById('resultsPanelContent');
			if (!panel || !titleEl || !content) return;

			titleEl.textContent = title;
			panel.classList.add('visible');

			if (type === 'strings') {
				renderStringResults(content, data);
			} else if (type === 'constants') {
				renderConstantResults(content, data);
			}
		}

		function renderStringResults(container, data) {
			if (!data || !Array.isArray(data) || data.length === 0) {
				container.innerHTML = '<div class="result-item"><span class="result-text">No string references found</span></div>';
				return;
			}
			container.innerHTML = data.map(item => \`
				<div class="result-item" onclick="jumpToAddress(\${item.address || 0})">
					<span class="result-addr">0x\${(item.address || 0).toString(16).toUpperCase().padStart(8, '0')}</span>
					<span class="result-text">\${escapeHtml(item.value || item.string || '')}</span>
				</div>
			\`).join('');
		}

		function renderConstantResults(container, data) {
			if (!data || !Array.isArray(data) || data.length === 0) {
				container.innerHTML = '<div class="result-item"><span class="result-text">No findings</span></div>';
				return;
			}
			container.innerHTML = data.map(item => {
				const isSuspicious = item.suspicious || item.severity === 'danger';
				return \`
					<div class="result-item" onclick="jumpToAddress(\${item.address || 0})">
						<span class="result-addr">0x\${(item.address || 0).toString(16).toUpperCase().padStart(8, '0')}</span>
						<span class="result-text \${isSuspicious ? 'suspicious' : 'safe'}">\${escapeHtml(item.message || item.description || '')}</span>
					</div>
				\`;
			}).join('');
		}

		function closeResultsPanel() {
			const panel = document.getElementById('resultsPanel');
			if (panel) panel.classList.remove('visible');
		}

		function renderInstructions(instructions) {
			return instructions.map(inst => {
				const isSelected = selectedAddress === inst.address;
				const mnemonicClass = getMnemonicClass(inst.mnemonic);
				const operands = highlightOperands(inst.opStr, inst.targetAddress);
				const bytes = inst.bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
				const addrHex = '0x' + inst.address.toString(16).toUpperCase();
				const annotation = annotations[addrHex];

				return \`
					<div class="instruction \${isSelected ? 'selected' : ''} \${inst.isCall ? 'call-target' : ''}"
						data-address="\${inst.address}"
						onclick="selectInstruction(\${inst.address})"
						ondblclick="handleInstructionDblClick(event, \${inst.address})"
						oncontextmenu="showContextMenu(event, \${inst.address})">
						<span class="inst-address">0x\${inst.address.toString(16).toUpperCase().padStart(8, '0')}</span>
						<span class="inst-bytes">\${bytes}</span>
						<span class="inst-mnemonic \${mnemonicClass}">\${inst.mnemonic}</span>
						<span class="inst-operands">\${operands}</span>
						\${inst.comment ? \`<span class="inst-comment">\${escapeHtml(inst.comment)}</span>\` : ''}
						\${annotation ? \`<span class="inst-annotation" ondblclick="editAnnotation(event, \${inst.address})" title="Double-click to edit">\${escapeHtml(annotation.comment)}</span>\` : ''}
					</div>
				\`;
			}).join('');
		}

		function getMnemonicClass(mnemonic) {
			const m = mnemonic.toLowerCase();
			if (m === 'call') return 'call';
			if (m.startsWith('j') || m === 'loop' || m === 'loope' || m === 'loopne') return 'jump';
			if (m === 'ret' || m === 'retn' || m === 'retf') return 'ret';
			return '';
		}

		function highlightOperands(opStr, targetAddress) {
			if (!opStr) return '';

			let result = escapeHtml(opStr);

			// Highlight registers
			result = result.replace(/\\b(r[a-z]x|e[a-z]x|[a-z]x|r[0-9]+|[re]?[sb]p|[re]?[sd]i|[re]?ip|[cdefgs]s|xmm[0-9]+|ymm[0-9]+)\\b/gi,
				'<span class="register">$1</span>');

			// Highlight hex numbers
			result = result.replace(/\\b(0x[0-9a-fA-F]+|[0-9a-fA-F]+h)\\b/g,
				'<span class="number">$1</span>');

			// Highlight decimal numbers
			result = result.replace(/\\b([0-9]+)\\b/g,
				'<span class="number">$1</span>');

			// Make target addresses clickable
			if (targetAddress && targetAddress > 0) {
				const addrHex = '0x' + targetAddress.toString(16).toUpperCase();
				result = result.replace(new RegExp(addrHex, 'gi'),
					\`<span class="address" onclick="jumpToAddress(\${targetAddress})">\${addrHex}</span>\`);
			}

			return result;
		}

		function escapeHtml(text) {
			if (!text) return '';
			return text.replace(/&/g, '&amp;')
					.replace(/</g, '&lt;')
					.replace(/>/g, '&gt;')
					.replace(/"/g, '&quot;');
		}

		function selectInstruction(address) {
			selectedAddress = address;
			document.querySelectorAll('.instruction').forEach(el => {
				el.classList.remove('selected');
				if (parseInt(el.dataset.address) === address) {
					el.classList.add('selected');
				}
			});
			vscode.postMessage({ command: 'selectInstruction', address });
		}

		function jumpToFunction(address) {
			vscode.postMessage({ command: 'jumpTo', address });
		}

		function jumpToAddress(address) {
			if (address && address > 0) {
				vscode.postMessage({ command: 'jumpTo', address });
			}
		}

		function jumpToTarget(address) {
			if (address && address > 0) {
				jumpToAddress(address);
			}
		}

		function handleInstructionDblClick(event, address) {
			const addrHex = '0x' + address.toString(16).toUpperCase();
			if (annotations[addrHex]) {
				// Double-click on annotated instruction → edit comment
				event.stopPropagation();
				vscode.postMessage({ command: 'editComment', address });
			} else {
				// Default: jump to target
				const inst = currentData && currentData.currentFunction
					? currentData.currentFunction.instructions.find(i => i.address === address)
					: null;
				if (inst && inst.targetAddress && inst.targetAddress > 0) {
					jumpToAddress(inst.targetAddress);
				}
			}
		}

		function editAnnotation(event, address) {
			event.stopPropagation();
			event.preventDefault();
			vscode.postMessage({ command: 'editComment', address });
		}

		function showContextMenu(event, address) {
			event.preventDefault();
			selectInstruction(address);

			const menu = document.getElementById('contextMenu');
			menu.style.left = event.clientX + 'px';
			menu.style.top = event.clientY + 'px';
			menu.classList.add('visible');
			menu.dataset.address = address;
		}

		// Hide context menu on click outside
		document.addEventListener('click', () => {
			document.getElementById('contextMenu').classList.remove('visible');
		});

		// Context menu actions
		document.getElementById('contextMenu').addEventListener('click', (e) => {
			const item = e.target.closest('.context-menu-item');
			if (!item) return;

			const action = item.dataset.action;
			const address = parseInt(document.getElementById('contextMenu').dataset.address);

			switch (action) {
				case 'goto':
					vscode.postMessage({ command: 'jumpTo', address });
					break;
				case 'xrefs':
					vscode.postMessage({ command: 'findXrefs', address });
					break;
				case 'comment':
					vscode.postMessage({ command: 'addComment', address });
					break;
				case 'editComment':
					vscode.postMessage({ command: 'editComment', address });
					break;
				case 'deleteComment':
					vscode.postMessage({ command: 'deleteComment', address });
					break;
				case 'patch':
					vscode.postMessage({ command: 'patchInstruction', address });
					break;
				case 'nop':
					vscode.postMessage({ command: 'nopInstruction', address });
					break;
				case 'copy':
					navigator.clipboard.writeText('0x' + address.toString(16).toUpperCase());
					break;
			}

			document.getElementById('contextMenu').classList.remove('visible');
		});

		// Keyboard shortcuts
		document.addEventListener('keydown', (e) => {
			if (!selectedAddress) return;

			switch (e.key.toLowerCase()) {
				case 'g':
					vscode.postMessage({ command: 'jumpTo', address: selectedAddress });
					break;
				case 'x':
					vscode.postMessage({ command: 'findXrefs', address: selectedAddress });
					break;
				case ';':
					vscode.postMessage({ command: 'addComment', address: selectedAddress });
					break;
				case 'p':
					vscode.postMessage({ command: 'patchInstruction', address: selectedAddress });
					break;
			}
		});
	</script>
</body>
</html>`;
	}
}
