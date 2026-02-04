/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import * as path from 'path';
import { DisassemblerEngine, Instruction, Function, XRef, Section, FileInfo } from './disassemblerEngine';

export class DisassemblerViewProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private currentAddress: number = 0;
	private currentFunction?: number;
	private selectedAddress?: number;
	private engine: DisassemblerEngine;

	constructor(
		private readonly extensionUri: vscode.Uri,
		engine: DisassemblerEngine
	) {
		this.engine = engine;
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
					break;
				case 'contextMenu':
					this.showContextMenu(message.address, message.x, message.y);
					break;
				case 'addComment':
					await this.addCommentAt(message.address);
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
			}
		});
	}

	async loadFile(filePath: string): Promise<void> {
		await this.engine.loadFile(filePath);
		const funcs = this.engine.getFunctions();
		if (funcs.length > 0) {
			this.currentFunction = funcs[0].address;
		}
		await this.refresh();
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
				selectedAddress: this.selectedAddress
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
		const comment = await vscode.window.showInputBox({
			prompt: `Add comment at 0x${address.toString(16).toUpperCase()}`,
			placeHolder: 'Enter comment...'
		});
		if (comment) {
			this.engine.addComment(address, comment);
			this.refresh();
		}
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
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>HexCore Disassembler</title>
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
			font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
			font-size: 12px;
			line-height: 1.5;
			background: var(--bg-primary);
			color: var(--text-primary);
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

		/* Toolbar */
		.toolbar {
			background: var(--bg-tertiary);
			border-bottom: 1px solid var(--border-color);
			padding: 4px 8px;
			display: flex;
			gap: 4px;
			align-items: center;
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

		/* Main Content */
		.main-content {
			display: flex;
			height: calc(100vh - 80px);
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

		// Listen for messages from extension
		window.addEventListener('message', event => {
			const message = event.data;
			if (message.command === 'updateView') {
				currentData = message.data;
				renderView();
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
							<span class="value">\${fileInfo.architecture}</span>
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
					</div>
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
				</div>
			\`;
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
						<span class="inst-bytes">\${bytes}</span>
						<span class="inst-mnemonic \${mnemonicClass}">\${inst.mnemonic}</span>
						<span class="inst-operands">\${operands}</span>
						\${inst.comment ? \`<span class="inst-comment">\${escapeHtml(inst.comment)}</span>\` : ''}
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

