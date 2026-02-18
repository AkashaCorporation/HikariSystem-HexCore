/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as path from 'path';
import { DisassemblerEngine } from './disassemblerEngine';

export class DisassemblyEditorProvider implements vscode.CustomReadonlyEditorProvider {
	public static readonly viewType = 'hexcore.disassembler.editor';

	private activeWebview?: vscode.Webview;
	private currentAddress?: number;
	private currentFunctionAddress?: number;
	private syncEnabled: boolean = false;

	constructor(
		private readonly context: vscode.ExtensionContext,
		private readonly engine: DisassemblerEngine,
		private readonly onDidChangeActiveEditor: vscode.EventEmitter<string | undefined>
	) { }

	/** Get the currently selected instruction address */
	getCurrentAddress(): number | undefined {
		return this.currentAddress;
	}

	/** Get the currently displayed function address */
	getCurrentFunctionAddress(): number | undefined {
		return this.currentFunctionAddress;
	}

	/** Navigate to an address and refresh the view */
	navigateToAddress(address: number): void {
		if (!this.activeWebview) {
			return;
		}
		const funcs = this.engine.getFunctions();
		const containing = funcs.find(f => address >= f.address && address < f.endAddress);
		if (containing) {
			this.currentFunctionAddress = containing.address;
		}
		this.currentAddress = address;
		this.updateWebview(this.activeWebview, containing ? containing.address : address);
	}

	/** Refresh the current view */
	refresh(): void {
		if (this.activeWebview) {
			this.updateWebview(this.activeWebview, this.currentFunctionAddress);
		}
	}

	/** Show xrefs in a quick pick */
	async showXrefs(xrefs: import('./disassemblerEngine').XRef[]): Promise<void> {
		if (xrefs.length === 0) {
			vscode.window.showInformationMessage('No cross-references found');
			return;
		}

		type XrefPickItem = vscode.QuickPickItem & { address: number };
		const items: XrefPickItem[] = xrefs.map(x => ({
			label: `0x${x.from.toString(16).toUpperCase()}`,
			description: x.type,
			address: x.from
		}));

		const selected = await vscode.window.showQuickPick<XrefPickItem>(items, {
			placeHolder: `${xrefs.length} references found`
		});

		if (selected) {
			this.navigateToAddress(selected.address);
		}
	}

	async openCustomDocument(
		uri: vscode.Uri,
		openContext: vscode.CustomDocumentOpenContext,
		token: vscode.CancellationToken
	): Promise<vscode.CustomDocument> {
		return { uri, dispose: () => { } };
	}

	async resolveCustomEditor(
		document: vscode.CustomDocument,
		webviewPanel: vscode.WebviewPanel,
		token: vscode.CancellationToken
	): Promise<void> {
		webviewPanel.webview.options = {
			enableScripts: true,
			localResourceRoots: [this.context.extensionUri]
		};

		// Track visibility to toggle context
		webviewPanel.onDidChangeViewState(e => {
			vscode.commands.executeCommand('setContext', 'hexcore:disassemblerActive', e.webviewPanel.active);
			if (e.webviewPanel.active) {
				this.activeWebview = e.webviewPanel.webview;
			}
		});

		// Initial set
		this.activeWebview = webviewPanel.webview;
		vscode.commands.executeCommand('setContext', 'hexcore:disassemblerActive', webviewPanel.active);

		// Load and analyze file
		try {
			await this.engine.loadFile(document.uri.fsPath);

			// Notify other views
			this.onDidChangeActiveEditor.fire(document.uri.fsPath);

			// Render disassembly
			webviewPanel.webview.html = this.getHtmlContent(webviewPanel.webview);

			// Handle messages from webview
			webviewPanel.webview.onDidReceiveMessage(async (message) => {
				await this.handleMessage(message, webviewPanel.webview);
			});

			// Initial data send
			this.updateWebview(webviewPanel.webview);

		} catch (error: any) {
			vscode.window.showErrorMessage(`Failed to open binary: ${error.message}`);
			webviewPanel.webview.html = this.getErrorHtml(error.message);
		}
	}

	private async handleMessage(message: any, webview: vscode.Webview): Promise<void> {
		switch (message.command) {
			case 'ready':
				this.updateWebview(webview);
				break;

			case 'jumpToAddress':
				// Navigation handled here
				{
					const target = message.address as number;
					const funcs = this.engine.getFunctions();
					const containing = funcs.find(f => target >= f.address && target < f.endAddress);
					this.updateWebview(webview, containing ? containing.address : target);
				}
				break;

			case 'selectFunction': {
				const func = this.engine.getFunctionAt(message.address);
				if (func) {
					this.currentFunctionAddress = func.address;
					this.currentAddress = func.address;
					this.updateWebview(webview, func.address);
					// Auto-update graph view when switching functions
					vscode.commands.executeCommand('hexcore.disasm.showCFG');
				}
				break;
			}

			case 'addComment': {
				const comment = await vscode.window.showInputBox({
					prompt: `Comment at 0x${message.address.toString(16)}`,
					placeHolder: 'Enter comment...'
				});
				if (comment) {
					this.engine.addComment(message.address, comment);
					this.updateWebview(webview);
				}
				break;
			}

			case 'patchInstruction': {
				const newCode = await vscode.window.showInputBox({
					prompt: `Patch instruction at 0x${message.address.toString(16)}`,
					placeHolder: 'mov rax, rbx'
				});
				if (newCode) {
					try {
						const result = await this.engine.patchInstruction(message.address, newCode);
						if (result.success) {
							this.engine.applyPatch(message.address, result.bytes);
							this.updateWebview(webview);
							const msg = result.nopPadding > 0
								? `Patched with ${result.nopPadding} NOP padding`
								: 'Patched successfully';
							vscode.window.showInformationMessage(msg);
						} else {
							vscode.window.showErrorMessage(`Patch failed: ${result.error}`);
						}
					} catch (error: any) {
						vscode.window.showErrorMessage(`Patch error: ${error.message}`);
					}
				}
				break;
			}

			case 'findXrefs': {
				const xrefs = await this.engine.findCrossReferences(message.address);
				if (xrefs.length === 0) {
					vscode.window.showInformationMessage('No cross-references found');
					return;
				}

				type XrefPickItem = vscode.QuickPickItem & { address: number };
				const items: XrefPickItem[] = xrefs.map(x => ({
					label: `0x${x.from.toString(16).toUpperCase()}`,
					description: x.type,
					address: x.from
				}));

				const selected = await vscode.window.showQuickPick<XrefPickItem>(items, {
					placeHolder: `${xrefs.length} references found`
				});

				if (selected) {
					this.updateWebview(webview, selected.address);
				}
				break;
			}

			case 'searchStringRefs':
				vscode.commands.executeCommand('hexcore.disasm.searchString');
				break;

			case 'exportAsm':
				vscode.commands.executeCommand('hexcore.disasm.exportASM');
				break;

			case 'deepAnalysis':
				vscode.commands.executeCommand('hexcore.disasm.analyzeFile');
				break;

			case 'showCFG':
				vscode.commands.executeCommand('hexcore.disasm.showCFG');
				break;

			case 'buildFormula':
				vscode.commands.executeCommand('hexcore.disasm.buildFormula');
				break;

			case 'checkConstants':
				vscode.commands.executeCommand('hexcore.disasm.checkConstants');
				break;

			case 'liftToIR':
				vscode.commands.executeCommand('hexcore.disasm.liftToIR');
				break;

			case 'toggleSyntax':
				vscode.commands.executeCommand('hexcore.disasm.setSyntax');
				break;

			case 'toggleSync': {
				// Toggle sync state and notify webview
				const newState = !this.syncEnabled;
				this.syncEnabled = newState;
				webview.postMessage({ command: 'syncState', enabled: newState });
				break;
			}

			case 'checkRemill': {
				try {
					const remillExt = vscode.extensions.getExtension('hikarisystem.hexcore-remill');
					webview.postMessage({ command: 'remillStatus', available: !!remillExt });
				} catch {
					webview.postMessage({ command: 'remillStatus', available: false });
				}
				break;
			}
		}
	}

	private updateWebview(webview: vscode.Webview, address?: number): void {
		const fileInfo = this.engine.getFileInfo();
		const sections = this.engine.getSections();
		const functions = this.engine.getFunctions();

		// If no address specified, use first function
		if (!address && functions.length > 0) {
			const entryPoint = fileInfo?.entryPoint;
			const entryFunc = entryPoint ? functions.find(f => f.address === entryPoint) : undefined;
			const firstWithSize = functions.find(f => f.size > 0);
			address = entryFunc?.address ?? firstWithSize?.address ?? functions[0].address;
		}

		const currentFunction = address ? this.engine.getFunctionAt(address) : undefined;

		webview.postMessage({
			command: 'updateDisassembly',
			data: {
				fileInfo: fileInfo ? {
					...fileInfo,
					fileName: this.engine.getFileName(),
					timestamp: fileInfo.timestamp?.toISOString()
				} : null,
				sections,
				functions: functions.map(f => ({
					address: f.address,
					name: f.name,
					size: f.size,
					endAddress: f.endAddress
				})),
				currentFunction: currentFunction ? {
					...currentFunction,
					instructions: currentFunction.instructions.map(inst => ({
						...inst,
						bytes: Array.from(inst.bytes)
					}))
				} : null,
				currentAddress: address
			}
		});
	}

	private getHtmlContent(webview: vscode.Webview): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${webview.cspSource} 'unsafe-inline'; script-src ${webview.cspSource} 'unsafe-inline';">
	<title>Disassembly</title>
	<style>
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
			--address-color: #858585;
			--bytes-color: #6a9955;
			--mnemonic-color: #569cd6;
			--register-color: #9cdcfe;
			--number-color: #b5cea8;
			--comment-color: #6a9955;
			--label-color: #4ec9b0;
			--call-color: #4ec9b0;
			--jump-color: #c586c0;
			--ret-color: #f44747;
		}

		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
			font-size: 13px;
			line-height: 1.6;
			background: var(--bg-primary);
			color: var(--text-primary);
			overflow: hidden;
			height: 100vh;
		}

		.header {
			background: var(--bg-secondary);
			border-bottom: 1px solid var(--border-color);
			padding: 12px 16px;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}

		.header-left {
			display: flex;
			flex-direction: column;
			gap: 4px;
		}

		.file-name {
			font-size: 14px;
			font-weight: 600;
			color: var(--text-primary);
		}

		.file-info {
			font-size: 11px;
			color: var(--text-secondary);
		}

		.header-right {
			display: flex;
			gap: 12px;
			align-items: center;
			font-size: 11px;
			color: var(--text-muted);
		}

		.function-selector {
			background: var(--bg-tertiary);
			border-bottom: 1px solid var(--border-color);
			padding: 8px 16px;
			display: flex;
			align-items: center;
			gap: 12px;
		}

		.function-label {
			font-size: 11px;
			color: var(--text-muted);
			text-transform: uppercase;
		}

		.function-name {
			font-size: 13px;
			font-weight: 600;
			color: var(--label-color);
		}

		.function-select {
			background: var(--bg-secondary);
			color: var(--text-primary);
			border: 1px solid var(--border-color);
			border-radius: 4px;
			padding: 4px 8px;
			font-size: 12px;
			min-width: 240px;
		}

		.function-select:focus {
			outline: none;
			border-color: var(--mnemonic-color);
		}

		.function-stats {
			font-size: 11px;
			color: var(--text-secondary);
			margin-left: auto;
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
			border-color: var(--mnemonic-color);
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

		.disasm-container {
			height: calc(100vh - 126px);
			overflow-y: auto;
			padding: 8px 0;
		}

		.instruction {
			display: flex;
			padding: 2px 16px;
			cursor: pointer;
			border-left: 3px solid transparent;
			transition: background-color 0.1s;
		}

		.instruction:hover {
			background: var(--bg-hover);
		}

		.instruction.selected {
			background: var(--bg-selected);
			border-left-color: var(--mnemonic-color);
		}

		.instruction.call-target {
			background: rgba(78, 201, 176, 0.05);
		}

		.inst-address {
			min-width: 110px;
			color: var(--address-color);
			user-select: none;
			font-weight: 500;
		}

		.inst-bytes {
			min-width: 180px;
			color: var(--bytes-color);
			font-size: 11px;
			opacity: 0.8;
			font-family: monospace;
		}

		.inst-mnemonic {
			min-width: 90px;
			color: var(--mnemonic-color);
			font-weight: 600;
		}

		.inst-mnemonic.call { color: var(--call-color); }
		.inst-mnemonic.jump { color: var(--jump-color); }
		.inst-mnemonic.ret { color: var(--ret-color); }

		.inst-operands {
			flex: 1;
			color: var(--text-primary);
		}

		.inst-operands .register { color: var(--register-color); font-weight: 500; }
		.inst-operands .number { color: var(--number-color); }
		.inst-operands .address {
			color: var(--label-color);
			cursor: pointer;
			text-decoration: underline;
			text-decoration-color: rgba(78, 201, 176, 0.3);
		}
		.inst-operands .address:hover {
			text-decoration-color: var(--label-color);
		}

		.inst-comment {
			color: var(--comment-color);
			margin-left: 24px;
			font-style: italic;
		}

		.inst-comment::before {
			content: '; ';
		}

		.function-header {
			padding: 12px 16px 4px;
			color: var(--label-color);
			font-weight: 600;
			font-size: 14px;
			border-top: 2px solid var(--border-color);
			margin-top: 8px;
			background: rgba(78, 201, 176, 0.05);
		}

		.function-header::before {
			content: '>> ';
			margin-right: 4px;
		}

		.loading {
			display: flex;
			align-items: center;
			justify-content: center;
			height: 100vh;
			color: var(--text-secondary);
			font-size: 14px;
		}

		::-webkit-scrollbar {
			width: 12px;
			height: 12px;
		}

		::-webkit-scrollbar-track {
			background: var(--bg-primary);
		}

		::-webkit-scrollbar-thumb {
			background: var(--bg-hover);
			border-radius: 6px;
		}

		::-webkit-scrollbar-thumb:hover {
			background: var(--text-muted);
		}

		.context-menu {
			position: fixed;
			background: var(--bg-secondary);
			border: 1px solid var(--border-color);
			border-radius: 4px;
			padding: 4px 0;
			min-width: 200px;
			box-shadow: 0 4px 16px rgba(0,0,0,0.5);
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
			font-size: 12px;
		}

		.context-menu-item:hover {
			background: var(--bg-hover);
		}

		.context-menu-separator {
			height: 1px;
			background: var(--border-color);
			margin: 4px 0;
		}

		/* Constant Decoder Tooltip */
		.hexcore-tooltip {
			position: fixed;
			background: #1a1a2e;
			border: 1px solid #4a4a6a;
			border-radius: 6px;
			padding: 0;
			min-width: 280px;
			max-width: 380px;
			box-shadow: 0 8px 32px rgba(0,0,0,0.7);
			z-index: 2000;
			pointer-events: auto;
			opacity: 0;
			transform: translateY(4px);
			transition: opacity 0.15s ease, transform 0.15s ease;
			font-size: 12px;
		}

		.hexcore-tooltip.visible {
			opacity: 1;
			transform: translateY(0);
		}

		.hexcore-tooltip-header {
			padding: 8px 12px;
			background: #16213e;
			border-bottom: 1px solid #4a4a6a;
			border-radius: 6px 6px 0 0;
			font-weight: 600;
			color: var(--number-color);
			font-size: 13px;
			display: flex;
			align-items: center;
			gap: 8px;
		}

		.hexcore-tooltip-header::before {
			content: '#';
			color: var(--text-muted);
			font-size: 11px;
		}

		.hexcore-tooltip-body {
			padding: 6px 0;
		}

		.hexcore-tooltip-row {
			display: flex;
			align-items: center;
			padding: 3px 12px;
			gap: 8px;
			transition: background 0.1s;
		}

		.hexcore-tooltip-row:hover {
			background: rgba(255,255,255,0.04);
		}

		.hexcore-tooltip-label {
			min-width: 68px;
			color: var(--text-muted);
			font-size: 11px;
			text-transform: uppercase;
			flex-shrink: 0;
		}

		.hexcore-tooltip-value {
			flex: 1;
			color: var(--text-primary);
			font-family: 'Consolas', 'Monaco', monospace;
			word-break: break-all;
			user-select: all;
		}

		.hexcore-tooltip-copy {
			width: 20px;
			height: 20px;
			display: flex;
			align-items: center;
			justify-content: center;
			cursor: pointer;
			color: var(--text-muted);
			border-radius: 3px;
			flex-shrink: 0;
			font-size: 11px;
			transition: color 0.15s, background 0.15s;
		}

		.hexcore-tooltip-copy:hover {
			color: var(--text-primary);
			background: rgba(255,255,255,0.1);
		}

		.hexcore-tooltip-copy.copied {
			color: #4ec9b0;
		}

		.hexcore-tooltip-separator {
			height: 1px;
			background: #4a4a6a;
			margin: 4px 12px;
			opacity: 0.5;
		}

		.inst-operands .number[data-value] {
			cursor: default;
			border-bottom: 1px dotted rgba(181, 206, 168, 0.3);
		}

		.inst-operands .number[data-value]:hover {
			border-bottom-color: var(--number-color);
		}
	</style>
</head>
<body>
	<div id="app">
		<div class="loading">Loading disassembly...</div>
	</div>

	<div class="context-menu" id="contextMenu">
		<div class="context-menu-item" data-action="goto">Go to Address</div>
		<div class="context-menu-item" data-action="xrefs">Find References</div>
		<div class="context-menu-separator"></div>
		<div class="context-menu-item" data-action="comment">Add Comment</div>
		<div class="context-menu-item" data-action="patch">Patch Instruction</div>
		<div class="context-menu-separator"></div>
		<div class="context-menu-item" data-action="copy">Copy Address</div>
		<div class="context-menu-item" data-action="copyBytes">Copy Bytes</div>
	</div>

	<script>
		const vscode = acquireVsCodeApi();
		let currentData = null;
		let selectedAddress = null;
		let remillAvailable = false;
		let currentSyntax = 'Intel';
		let syncEnabled = false;

		// Check remill availability
		try {
			vscode.postMessage({ command: 'checkRemill' });
		} catch(e) {}

		// Notify ready
		vscode.postMessage({ command: 'ready' });

		// Listen for updates
		window.addEventListener('message', event => {
			const message = event.data;
			if (message.command === 'updateDisassembly') {
				currentData = message.data;
				selectedAddress = message.data.currentAddress;
				render();
			} else if (message.command === 'remillStatus') {
				remillAvailable = message.available;
			} else if (message.command === 'syntaxChanged') {
				currentSyntax = message.syntax;
				const btn = document.querySelector('.syntax-toggle');
				if (btn) btn.textContent = currentSyntax;
			} else if (message.command === 'syncState') {
				syncEnabled = message.enabled;
				const btn = document.getElementById('syncBtn');
				if (btn) {
					btn.className = 'toolbar-btn' + (syncEnabled ? ' active' : '');
					btn.innerHTML = syncEnabled ? '&#128279; Sync ON' : '&#128279; Sync';
				}
			}
		});

		function render() {
			if (!currentData || !currentData.fileInfo) {
				return;
			}

			const { fileInfo, functions, currentFunction } = currentData;

			const app = document.getElementById('app');
			app.innerHTML = \`
				<div class="header">
					<div class="header-left">
						<div class="file-name">\${escapeHtml(fileInfo.fileName || 'Unknown')}</div>
						<div class="file-info">
							\${fileInfo.format} | \${fileInfo.architecture} |
							Entry: 0x\${fileInfo.entryPoint.toString(16).toUpperCase()} |
							Base: 0x\${fileInfo.baseAddress.toString(16).toUpperCase()}
						</div>
					</div>
					<div class="header-right">
						<span>\${functions.length} function(s)</span>
					</div>
				</div>
				\${currentFunction ? \`
					<div class="function-selector">
						<span class="function-label">Function:</span>
						<select id="functionSelect" class="function-select">
							\${functions.map(f => {
								const label = \`\${f.name} (0x\${f.address.toString(16).toUpperCase()})\`;
								const selected = currentFunction && f.address === currentFunction.address ? 'selected' : '';
								return \`<option value="\${f.address}" \${selected}>\${escapeHtml(label)}</option>\`;
							}).join('')}
						</select>
						<span class="function-stats">
							0x\${currentFunction.address.toString(16).toUpperCase()} -
							0x\${currentFunction.endAddress.toString(16).toUpperCase()} |
							\${currentFunction.size} bytes |
							\${currentFunction.instructions.length} instruction(s)
						</span>
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
						\${remillAvailable ? '<button class="toolbar-btn" onclick="sendCommand(\\'liftToIR\\')" title="Lift to LLVM IR (Remill)">&#9881; Lift to IR</button>' : ''}
						<div class="toolbar-separator"></div>
						<button class="toolbar-btn syntax-toggle" onclick="sendCommand('toggleSyntax')" title="Toggle Intel/AT&T syntax">\${currentSyntax}</button>
						<button class="toolbar-btn \${syncEnabled ? 'active' : ''}" id="syncBtn" onclick="sendCommand('toggleSync')" title="Sync with Hex View">\${syncEnabled ? '&#128279; Sync ON' : '&#128279; Sync'}</button>
					</div>
					<div class="disasm-container">
						\${renderInstructions(currentFunction.instructions)}
					</div>
				\` : \`
					<div class="loading">No function selected</div>
				\`}
			\`;

			const functionSelect = document.getElementById('functionSelect');
			if (functionSelect) {
				functionSelect.addEventListener('change', () => {
					const value = parseInt(functionSelect.value, 10);
					if (!isNaN(value)) {
						vscode.postMessage({ command: 'selectFunction', address: value });
					}
				});
			}
		}

		function renderInstructions(instructions) {
			return instructions.map(inst => {
				const isSelected = selectedAddress === inst.address;
				const mnemonicClass = getMnemonicClass(inst.mnemonic);
				const operands = highlightOperands(inst.opStr, inst.targetAddress);
				const bytes = inst.bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');

				return \`
					<div class="instruction \${isSelected ? 'selected' : ''} \${inst.isCall ? 'call-target' : ''}"
						data-address="\${inst.address}"
						onclick="selectInstruction(\${inst.address})"
						ondblclick="jumpToTarget(\${inst.targetAddress || 0})"
						oncontextmenu="showContextMenu(event, \${inst.address})">
						<span class="inst-address">0x\${inst.address.toString(16).toUpperCase().padStart(8, '0')}</span>
						<span class="inst-bytes">\${bytes.padEnd(30)}</span>
						<span class="inst-mnemonic \${mnemonicClass}">\${inst.mnemonic.padEnd(8)}</span>
						<span class="inst-operands">\${operands}</span>
						\${inst.comment ? \`<span class="inst-comment">\${escapeHtml(inst.comment)}</span>\` : ''}
					</div>
				\`;
			}).join('');
		}

		function getMnemonicClass(mnemonic) {
			const m = mnemonic.toLowerCase();
			if (m === 'call') return 'call';
			if (m.startsWith('j') || m === 'loop') return 'jump';
			if (m === 'ret' || m === 'retn') return 'ret';
			return '';
		}

		function highlightOperands(opStr, targetAddress) {
			if (!opStr) return '';
			let result = escapeHtml(opStr);

			// 1. Target addresses FIRST (replace with placeholder to protect from other regexes)
			if (targetAddress && targetAddress > 0) {
				const addrHex = '0x' + targetAddress.toString(16).toUpperCase();
				result = result.replace(new RegExp(addrHex, 'gi'),
					'\\x02ADDR:' + targetAddress + ':' + addrHex + '\\x02');
			}

			// 2. Registers
			result = result.replace(/\\b(r[a-z]x|e[a-z]x|[a-z]x|r[0-9]+|[re]?[sb]p|[re]?[sd]i|[re]?ip|xmm[0-9]+|ymm[0-9]+)\\b/gi,
				'<span class="register">$1</span>');

			// 3. Hex numbers (placeholder)
			result = result.replace(/\\b(0x[0-9a-fA-F]+|[0-9a-fA-F]+h)\\b/g,
				(match) => '\\x01NUM:' + match + '\\x01');

			// 4. Decimal numbers - skip anything already in a placeholder or tag
			result = result.replace(/(?<![x"=>a-fA-F\\x01\\x02:])\\b([0-9]+)\\b(?![0-9a-fA-F]*[">;\\x01\\x02])/g,
				(match) => '\\x01NUM:' + match + '\\x01');

			// 5. Replace number placeholders with spans
			result = result.replace(/\\x01NUM:([^\\x01]+)\\x01/g,
				(_, val) => '<span class="number" data-value="' + val + '">' + val + '</span>');

			// 6. Replace address placeholders with clickable spans
			result = result.replace(/\\x02ADDR:([^:]+):([^\\x02]+)\\x02/g,
				(_, addr, hex) => '<span class="address" onclick="jumpToAddress(' + addr + ')">' + hex + '</span>');

			return result;
		}

		function sendCommand(command, data) {
			vscode.postMessage({ command: command, ...(data || {}) });
		}

		function handleGoToAddress(event) {
			if (event.key === 'Enter') {
				goToAddressFromInput();
			}
		}

		function goToAddressFromInput() {
			const input = document.getElementById('goToAddrInput');
			if (input && input.value) {
				const addrStr = input.value.trim().replace(/^0x/i, '');
				const addr = parseInt(addrStr, 16);
				if (!isNaN(addr)) {
					vscode.postMessage({ command: 'jumpToAddress', address: addr });
				}
				input.value = '';
			}
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
					el.scrollIntoView({ block: 'center', behavior: 'smooth' });
				}
			});
		}

		function jumpToAddress(address) {
			if (address && address > 0) {
				vscode.postMessage({ command: 'jumpToAddress', address });
			}
		}

		function jumpToTarget(address) {
			if (address && address > 0) {
				jumpToAddress(address);
			}
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

		document.addEventListener('click', () => {
			document.getElementById('contextMenu').classList.remove('visible');
		});

		document.getElementById('contextMenu').addEventListener('click', (e) => {
			const item = e.target.closest('.context-menu-item');
			if (!item) return;

			const action = item.dataset.action;
			const address = parseInt(document.getElementById('contextMenu').dataset.address);

			switch (action) {
				case 'goto':
					vscode.postMessage({ command: 'jumpToAddress', address });
					break;
				case 'xrefs':
					vscode.postMessage({ command: 'findXrefs', address });
					break;
				case 'comment':
					vscode.postMessage({ command: 'addComment', address });
					break;
				case 'patch':
					vscode.postMessage({ command: 'patchInstruction', address });
					break;
				case 'copy':
					navigator.clipboard.writeText('0x' + address.toString(16).toUpperCase());
					break;
				case 'copyBytes':
					const insn = currentData.currentFunction.instructions.find(i => i.address === address);
					if (insn) {
						const bytes = insn.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
						navigator.clipboard.writeText(bytes);
					}
					break;
			}
		});

		// === Constant Decoder Tooltip ===
		let tooltipEl = null;
		let tooltipHideTimer = null;

		function parseImmediate(str) {
			if (!str) return null;
			str = str.trim();
			try {
				if (str.toLowerCase().endsWith('h')) {
					// NASM-style hex: 0FFh
					return BigInt('0x' + str.slice(0, -1));
				} else if (str.toLowerCase().startsWith('0x')) {
					return BigInt(str);
				} else {
					const n = BigInt(str);
					return n;
				}
			} catch (e) {
				return null;
			}
		}

		function computeRepresentations(value) {
			const reps = [];
			const absVal = value < 0n ? -value : value;

			// Hex
			const hexStr = '0x' + (value < 0n
				? (0xFFFFFFFFFFFFFFFFn + value + 1n).toString(16).toUpperCase()
				: value.toString(16).toUpperCase());
			reps.push({ label: 'Hex', value: hexStr });

			// Unsigned decimal
			const unsigned = value < 0n ? (0xFFFFFFFFFFFFFFFFn + value + 1n) : value;
			reps.push({ label: 'Unsigned', value: unsigned.toString() });

			// Signed 32-bit (if value fits in 32 bits)
			if (unsigned <= 0xFFFFFFFFn) {
				const u32 = Number(unsigned & 0xFFFFFFFFn);
				const s32 = u32 > 0x7FFFFFFF ? u32 - 0x100000000 : u32;
				reps.push({ label: 'Signed32', value: s32.toString() });
			}

			// Signed 64-bit (if value is larger than 32 bits)
			if (unsigned > 0xFFFFFFFFn) {
				const s64 = unsigned > 0x7FFFFFFFFFFFFFFFn
					? -(0xFFFFFFFFFFFFFFFFn - unsigned + 1n)
					: unsigned;
				reps.push({ label: 'Signed64', value: s64.toString() });
			}

			// Binary (grouped by 8 bits)
			let binStr = unsigned.toString(2);
			// Pad to nearest 8 bits
			const padLen = Math.ceil(binStr.length / 8) * 8;
			binStr = binStr.padStart(padLen, '0');
			const binGrouped = binStr.match(/.{1,8}/g).join(' ');
			reps.push({ label: 'Binary', value: binGrouped });

			// ASCII (decode bytes, show printable chars)
			if (unsigned <= 0xFFFFFFFFFFFFFFFFn) {
				let hexForAscii = unsigned.toString(16);
				if (hexForAscii.length % 2 !== 0) hexForAscii = '0' + hexForAscii;
				const bytes = [];
				for (let i = 0; i < hexForAscii.length; i += 2) {
					bytes.push(parseInt(hexForAscii.substr(i, 2), 16));
				}
				// Show as little-endian (most common in x86)
				const asciiLE = bytes.reverse().map(b =>
					(b >= 0x20 && b <= 0x7E) ? String.fromCharCode(b) : '.'
				).join('');
				if (asciiLE.length > 0 && asciiLE.length <= 8) {
					reps.push({ label: 'ASCII', value: '"' + asciiLE + '"' });
				}
			}

			// Float32 (IEEE 754, only for 32-bit values)
			if (unsigned <= 0xFFFFFFFFn) {
				const buf = new ArrayBuffer(4);
				new DataView(buf).setUint32(0, Number(unsigned), false);
				const f32 = new DataView(buf).getFloat32(0, false);
				if (isFinite(f32) && f32 !== 0 && Math.abs(f32) > 1e-30 && Math.abs(f32) < 1e30) {
					reps.push({ label: 'Float32', value: f32.toPrecision(6) });
				}
			}

			return reps;
		}

		function createTooltipElement() {
			const el = document.createElement('div');
			el.className = 'hexcore-tooltip';
			el.addEventListener('mouseenter', () => {
				if (tooltipHideTimer) {
					clearTimeout(tooltipHideTimer);
					tooltipHideTimer = null;
				}
			});
			el.addEventListener('mouseleave', () => {
				hideConstantTooltip();
			});
			document.body.appendChild(el);
			return el;
		}

		function showConstantTooltip(targetEl, x, y) {
			const rawValue = targetEl.getAttribute('data-value');
			const parsed = parseImmediate(rawValue);
			if (parsed === null) return;

			if (tooltipHideTimer) {
				clearTimeout(tooltipHideTimer);
				tooltipHideTimer = null;
			}

			if (!tooltipEl) {
				tooltipEl = createTooltipElement();
			}

			const reps = computeRepresentations(parsed);

			tooltipEl.innerHTML = '<div class="hexcore-tooltip-header">' + escapeHtml(rawValue) + '</div>'
				+ '<div class="hexcore-tooltip-body">'
				+ reps.map(r =>
					'<div class="hexcore-tooltip-row">'
					+ '<span class="hexcore-tooltip-label">' + r.label + '</span>'
					+ '<span class="hexcore-tooltip-value">' + escapeHtml(r.value) + '</span>'
					+ '<span class="hexcore-tooltip-copy" data-copy="' + escapeHtml(r.value) + '" title="Copy">\\u2398</span>'
					+ '</div>'
				).join('')
				+ '</div>';

			// Position tooltip
			const vw = window.innerWidth;
			const vh = window.innerHeight;
			let posX = x + 12;
			let posY = y + 16;

			// Measure tooltip size
			tooltipEl.style.left = '-9999px';
			tooltipEl.style.top = '-9999px';
			tooltipEl.classList.add('visible');
			const tw = tooltipEl.offsetWidth;
			const th = tooltipEl.offsetHeight;

			// Adjust if would go off-screen
			if (posX + tw > vw - 8) posX = x - tw - 12;
			if (posY + th > vh - 8) posY = y - th - 8;
			if (posX < 8) posX = 8;
			if (posY < 8) posY = 8;

			tooltipEl.style.left = posX + 'px';
			tooltipEl.style.top = posY + 'px';

			// Copy button handlers
			tooltipEl.querySelectorAll('.hexcore-tooltip-copy').forEach(btn => {
				btn.onclick = (e) => {
					e.stopPropagation();
					const val = btn.getAttribute('data-copy');
					navigator.clipboard.writeText(val).then(() => {
						btn.classList.add('copied');
						btn.textContent = '\\u2713';
						setTimeout(() => {
							btn.classList.remove('copied');
							btn.textContent = '\\u2398';
						}, 1200);
					});
				};
			});
		}

		function hideConstantTooltip() {
			if (tooltipHideTimer) clearTimeout(tooltipHideTimer);
			tooltipHideTimer = setTimeout(() => {
				if (tooltipEl) {
					tooltipEl.classList.remove('visible');
				}
				tooltipHideTimer = null;
			}, 250);
		}

		// Hover events for constant decoder (event delegation)
		document.addEventListener('mouseover', (e) => {
			const numberEl = e.target.closest('.number[data-value]');
			if (numberEl) {
				showConstantTooltip(numberEl, e.clientX, e.clientY);
			}
		});

		document.addEventListener('mouseout', (e) => {
			const numberEl = e.target.closest('.number[data-value]');
			if (numberEl) {
				hideConstantTooltip();
			}
		});

		// Keyboard shortcuts
		document.addEventListener('keydown', (e) => {
			if (!selectedAddress) return;

			switch (e.key.toLowerCase()) {
				case 'g':
					vscode.postMessage({ command: 'jumpToAddress', address: selectedAddress });
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

	private getErrorHtml(error: string): string {
		return `<!DOCTYPE html>
<html>
<head>
	<style>
		body {
			font-family: sans-serif;
			padding: 40px;
			color: #f44747;
			background: #1e1e1e;
		}
		h1 { font-size: 18px; margin-bottom: 16px; }
		pre {
			background: #252526;
			padding: 16px;
			border-radius: 4px;
			overflow: auto;
		}
	</style>
</head>
<body>
	<h1>Failed to open binary</h1>
	<pre>${error}</pre>
</body>
</html>`;
	}
}

