/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler View Provider - Simplified
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine } from './disassemblerEngine';

export class DisassemblerViewProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private currentAddress: number = 0;
	private currentFunction?: number;
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
			enableScripts: true
		};

		webviewView.webview.html = this.getSimpleHtml();

		webviewView.webview.onDidReceiveMessage(async (message) => {
			if (message.command === 'jumpTo') {
				this.navigateToAddress(message.address);
			}
		});
	}

	async loadFile(filePath: string): Promise<void> {
		await this.engine.loadFile(filePath);
		const funcs = this.engine.getFunctions();
		if (funcs.length > 0) {
			this.currentFunction = funcs[0].address;
			await this.refresh();
		}
		if (this.view) {
			this.view.show?.(true);
		}
	}

	async refresh(): Promise<void> {
		if (!this.view || !this.currentFunction) return;

		const func = this.engine.getFunctionAt(this.currentFunction);
		if (!func) return;

		// Build simple HTML content
		let content = `<div style="font-family: Consolas, monospace; font-size: 12px;">`;
		content += `<div style="background: var(--vscode-titleBar-activeBackground); padding: 8px; margin-bottom: 8px; border-radius: 4px; font-weight: bold;">`;
		content += `${func.name} @ 0x${func.address.toString(16).toUpperCase()}`;
		content += `</div>`;
		
		if (func.instructions.length === 0) {
			content += `<div style="padding: 20px; text-align: center; color: var(--vscode-descriptionForeground);">`;
			content += `No instructions decoded.<br>Bytes at entry point may not be valid code.`;
			content += `</div>`;
		} else {
			content += `<div style="max-height: calc(100vh - 100px); overflow-y: auto;">`;
			for (const inst of func.instructions) {
				const addrStr = `0x${inst.address.toString(16).toUpperCase().padStart(8, '0')}`;
				const bytesStr = Array.from(inst.bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
				
				content += `<div style="display: flex; padding: 2px 8px; font-family: Consolas, monospace;">`;
				content += `<span style="color: var(--vscode-symbolIcon-fieldForeground); min-width: 100px; opacity: 0.7;">${addrStr}</span>`;
				if (bytesStr) {
					content += `<span style="color: var(--vscode-descriptionForeground); min-width: 150px; opacity: 0.6; font-size: 10px;">${bytesStr}</span>`;
				}
				content += `<span style="color: var(--vscode-keyword-default); min-width: 60px; font-weight: bold;">${inst.mnemonic}</span>`;
				content += `<span style="color: var(--vscode-foreground); flex: 1;">${inst.opStr || ''}</span>`;
				content += `</div>`;
			}
			content += `</div>`;
		}
		content += `</div>`;

		this.view.webview.postMessage({
			command: 'updateContent',
			content: content
		});
	}

	navigateToAddress(address: number): void {
		this.currentAddress = address;
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
		return this.currentAddress;
	}

	getCurrentFunctionAddress(): number | undefined {
		return this.currentFunction;
	}

	showXrefs(xrefs: any[]): void {
		if (!this.view || xrefs.length === 0) return;
		let content = `Xrefs (${xrefs.length}): `;
		content += xrefs.map(x => `0x${x.from.toString(16)}`).join(', ');
		vscode.window.showInformationMessage(content);
	}

	showControlFlowGraph(address: number): void {
		vscode.window.showInformationMessage('CFG visualization coming in v2.1');
	}

	private getSimpleHtml(): string {
		return `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body {
			font-family: Consolas, Monaco, monospace;
			font-size: 12px;
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
			padding: 8px;
			margin: 0;
		}
	</style>
</head>
<body>
	<div id="content">
		<div style="text-align: center; padding: 40px; color: var(--vscode-descriptionForeground);">
			<p>Open a binary file to start disassembly</p>
			<p>Use "HexCore: Disassemble Binary" from command palette</p>
		</div>
	</div>
	<script>
		const vscode = acquireVsCodeApi();
		window.addEventListener('message', event => {
			const msg = event.data;
			if (msg.command === 'updateContent') {
				document.getElementById('content').innerHTML = msg.content;
			}
		});
	</script>
</body>
</html>`;
	}
}
