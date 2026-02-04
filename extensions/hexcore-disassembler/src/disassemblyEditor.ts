/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as path from 'path';
import { DisassemblerEngine } from './disassemblerEngine';

export class DisassemblyEditorProvider implements vscode.CustomReadonlyEditorProvider {
	public static readonly viewType = 'hexcore.disassembler.editor';

	constructor(
		private readonly context: vscode.ExtensionContext,
		private readonly engine: DisassemblerEngine,
		private readonly onDidChangeActiveEditor: vscode.EventEmitter<string | undefined>
	) { }

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
		});

		// Initial set
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
					this.updateWebview(webview, func.address);
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

		.disasm-container {
			height: calc(100vh - 90px);
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

		// Notify ready
		vscode.postMessage({ command: 'ready' });

		// Listen for updates
		window.addEventListener('message', event => {
			const message = event.data;
			if (message.command === 'updateDisassembly') {
				currentData = message.data;
				selectedAddress = message.data.currentAddress;
				render();
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

			// Registers
			result = result.replace(/\\b(r[a-z]x|e[a-z]x|[a-z]x|r[0-9]+|[re]?[sb]p|[re]?[sd]i|[re]?ip|xmm[0-9]+|ymm[0-9]+)\\b/gi,
				'<span class="register">$1</span>');

			// Hex numbers
			result = result.replace(/\\b(0x[0-9a-fA-F]+|[0-9a-fA-F]+h)\\b/g,
				'<span class="number">$1</span>');

			// Decimal numbers
			result = result.replace(/\\b([0-9]+)\\b/g,
				'<span class="number">$1</span>');

			// Target addresses
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

