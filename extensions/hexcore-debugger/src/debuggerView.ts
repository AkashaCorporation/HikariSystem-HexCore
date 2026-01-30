/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger View Provider - Simplified
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DebugEngine } from './debugEngine';

export class DebuggerViewProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private engine: DebugEngine;

	constructor(extensionUri: vscode.Uri, engine: DebugEngine) {
		this.engine = engine;

		engine.onEvent((event, data) => {
			if (this.view) {
				this.view.webview.postMessage({ command: event, data });
			}
		});
	}

	resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this.view = webviewView;
		webviewView.webview.options = { enableScripts: true };
		webviewView.webview.html = this.getHtml();

		webviewView.webview.onDidReceiveMessage((message) => {
			switch (message.command) {
				case 'stepInto':
					vscode.commands.executeCommand('hexcore.debug.stepInto');
					break;
				case 'stepOver':
					vscode.commands.executeCommand('hexcore.debug.stepOver');
					break;
				case 'continue':
					vscode.commands.executeCommand('hexcore.debug.continue');
					break;
				case 'breakpoint':
					vscode.commands.executeCommand('hexcore.debug.breakpoint');
					break;
			}
		});
	}

	show(): void {
		this.view?.show?.(true);
	}

	private getHtml(): string {
		return `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline';">
	<style>
		body {
			font-family: var(--vscode-font-family);
			padding: 10px;
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
		}
		.toolbar {
			display: flex;
			gap: 8px;
			margin-bottom: 15px;
		}
		button {
			padding: 6px 12px;
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			border-radius: 3px;
			cursor: pointer;
		}
		button:hover {
			background: var(--vscode-button-hoverBackground);
		}
		.output {
			font-family: Consolas, monospace;
			font-size: 12px;
			background: var(--vscode-terminal-background);
			padding: 10px;
			border-radius: 4px;
			min-height: 200px;
		}
		.status {
			margin-top: 10px;
			padding: 8px;
			background: var(--vscode-statusBar-background);
			border-radius: 3px;
		}
	</style>
</head>
<body>
	<div class="toolbar">
		<button onclick="sendCmd('stepInto')">[Step In]</button>
		<button onclick="sendCmd('stepOver')">[Step Over]</button>
		<button onclick="sendCmd('continue')">[Continue]</button>
		<button onclick="sendCmd('breakpoint')">[+ Break]</button>
	</div>
	<div class="output" id="output">Debugger ready. Start a session to see output.</div>
	<div class="status" id="status">Status: Idle</div>

	<script>
		const vscode = acquireVsCodeApi();

		function sendCmd(cmd) {
			vscode.postMessage({ command: cmd });
		}

		window.addEventListener('message', event => {
			const msg = event.data;
			if (msg.command === 'stopped') {
				document.getElementById('status').textContent = 'Status: Stopped';
			}
			if (msg.command === 'breakpoint-hit') {
				document.getElementById('output').textContent += '\n[Breakpoint hit]';
			}
		});
	</script>
</body>
</html>`;
	}
}
