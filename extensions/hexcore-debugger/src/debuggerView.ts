/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger View Provider
 *  Webview with emulation controls and API call log
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
		_context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this.view = webviewView;
		webviewView.webview.options = { enableScripts: true };
		webviewView.webview.html = this.getHtml();

		webviewView.webview.onDidReceiveMessage((message) => {
			switch (message.command) {
				case 'step':
					vscode.commands.executeCommand('hexcore.debug.emulationStep');
					break;
				case 'continue':
					vscode.commands.executeCommand('hexcore.debug.emulationContinue');
					break;
				case 'breakpoint':
					vscode.commands.executeCommand('hexcore.debug.emulationBreakpoint');
					break;
				case 'readMemory':
					vscode.commands.executeCommand('hexcore.debug.emulationReadMemory');
					break;
				case 'snapshot':
					vscode.commands.executeCommand('hexcore.debug.saveSnapshot');
					break;
				case 'restore':
					vscode.commands.executeCommand('hexcore.debug.restoreSnapshot');
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
			gap: 6px;
			margin-bottom: 12px;
			flex-wrap: wrap;
		}
		button {
			padding: 5px 10px;
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			border-radius: 3px;
			cursor: pointer;
			font-size: 11px;
		}
		button:hover {
			background: var(--vscode-button-hoverBackground);
		}
		.section-title {
			font-weight: bold;
			margin: 10px 0 5px 0;
			font-size: 11px;
			text-transform: uppercase;
			color: var(--vscode-descriptionForeground);
		}
		.api-log {
			font-family: Consolas, monospace;
			font-size: 11px;
			background: var(--vscode-terminal-background);
			padding: 8px;
			border-radius: 4px;
			max-height: 300px;
			overflow-y: auto;
		}
		.api-entry {
			padding: 2px 0;
			border-bottom: 1px solid var(--vscode-panel-border);
		}
		.api-name {
			color: var(--vscode-symbolIcon-functionForeground, #DCDCAA);
		}
		.api-dll {
			color: var(--vscode-descriptionForeground);
		}
		.api-ret {
			color: var(--vscode-symbolIcon-numberForeground, #B5CEA8);
		}
		.status {
			margin-top: 10px;
			padding: 6px;
			background: var(--vscode-statusBar-background);
			border-radius: 3px;
			font-size: 11px;
		}
	</style>
</head>
<body>
	<div class="toolbar">
		<button onclick="sendCmd('step')" title="Step one instruction">Step</button>
		<button onclick="sendCmd('continue')" title="Continue execution">Continue</button>
		<button onclick="sendCmd('breakpoint')" title="Set breakpoint">+ Break</button>
		<button onclick="sendCmd('readMemory')" title="Read memory">Memory</button>
		<button onclick="sendCmd('snapshot')" title="Save snapshot">Save</button>
		<button onclick="sendCmd('restore')" title="Restore snapshot">Restore</button>
	</div>
	<div class="section-title">API Call Log</div>
	<div class="api-log" id="apiLog">Waiting for emulation to start...</div>
	<div class="status" id="status">Status: Idle</div>

	<script>
		const vscode = acquireVsCodeApi();
		const apiLog = document.getElementById('apiLog');
		const status = document.getElementById('status');

		function sendCmd(cmd) {
			vscode.postMessage({ command: cmd });
		}

		window.addEventListener('message', event => {
			const msg = event.data;
			switch (msg.command) {
				case 'emulation-started':
					apiLog.textContent = '';
					status.textContent = 'Status: Running (' + (msg.data?.fileType || 'unknown') + ')';
					break;
				case 'api-call':
					if (msg.data) {
						const entry = document.createElement('div');
						entry.className = 'api-entry';
						const ret = '0x' + (msg.data.returnValue || 0n).toString(16);
						entry.innerHTML =
							'<span class="api-dll">' + (msg.data.dll || '') + '!</span>' +
							'<span class="api-name">' + (msg.data.name || '') + '</span>' +
							' = <span class="api-ret">' + ret + '</span>';
						apiLog.appendChild(entry);
						apiLog.scrollTop = apiLog.scrollHeight;
					}
					break;
				case 'step':
					status.textContent = 'Status: Paused (stepped)';
					break;
				case 'stopped':
					status.textContent = 'Status: Stopped';
					break;
				case 'breakpoint-hit':
					status.textContent = 'Status: Breakpoint hit';
					break;
				case 'snapshot-saved':
					status.textContent = 'Status: Snapshot saved';
					break;
				case 'snapshot-restored':
					status.textContent = 'Status: Snapshot restored';
					break;
			}
		});
	</script>
</body>
</html>`;
	}
}
