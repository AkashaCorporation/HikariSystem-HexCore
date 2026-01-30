/*---------------------------------------------------------------------------------------------
 *  HexCore AI Chat Provider - Simplified
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { AIAnalysisEngine } from './aiEngine';

export class AIChatProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private messages: Array<{ role: 'user' | 'assistant'; content: string }> = [];
	private engine: AIAnalysisEngine;

	constructor(
		private readonly extensionUri: vscode.Uri,
		engine: AIAnalysisEngine
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

		webviewView.webview.html = this.getHtml();

		webviewView.webview.onDidReceiveMessage(async (message) => {
			if (message.command === 'sendMessage') {
				await this.askQuestion(message.text);
			}
		});

		// Initial welcome
		if (this.messages.length === 0) {
			this.addMessage('assistant', 'Welcome to HexCore AI Assistant! Ask me anything about reverse engineering or malware analysis.');
		}
	}

	async askQuestion(text: string): Promise<void> {
		this.addMessage('user', text);
		const response = await this.engine.askQuestion(text);
		this.addMessage('assistant', response);
	}

	addMessage(role: 'user' | 'assistant', content: string): void {
		this.messages.push({ role, content });
		if (this.view) {
			this.view.webview.postMessage({
				command: 'addMessage',
				role,
				content
			});
		}
	}

	show(): void {
		this.view?.show?.(true);
	}

	clearChat(): void {
		this.messages = [];
		this.engine.clearHistory();
		if (this.view) {
			this.view.webview.postMessage({ command: 'clearChat' });
		}
		this.addMessage('assistant', 'Chat cleared. How can I help?');
	}

	private getHtml(): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<style>
		* { margin: 0; padding: 0; box-sizing: border-box; }
		body {
			font-family: var(--vscode-font-family);
			font-size: 13px;
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
			display: flex;
			flex-direction: column;
			height: 100vh;
		}
		.messages {
			flex: 1;
			overflow-y: auto;
			padding: 12px;
		}
		.message {
			margin-bottom: 12px;
			padding: 10px 12px;
			border-radius: 8px;
			line-height: 1.5;
		}
		.message.user {
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			margin-left: 20px;
		}
		.message.assistant {
			background: var(--vscode-textBlockQuote-background);
			border-left: 3px solid var(--vscode-textBlockQuote-border);
			margin-right: 20px;
		}
		.input-area {
			padding: 12px;
			border-top: 1px solid var(--vscode-panel-border);
		}
		.input-row {
			display: flex;
			gap: 8px;
		}
		input {
			flex: 1;
			padding: 8px 12px;
			border: 1px solid var(--vscode-input-border);
			background: var(--vscode-input-background);
			color: var(--vscode-input-foreground);
			border-radius: 4px;
		}
		button {
			padding: 8px 16px;
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			border-radius: 4px;
			cursor: pointer;
		}
	</style>
</head>
<body>
	<div class="messages" id="messages"></div>
	<div class="input-area">
		<div class="input-row">
			<input type="text" id="input" placeholder="Ask Kimi...">
			<button onclick="send()">Send</button>
		</div>
	</div>

	<script>
		const vscode = acquireVsCodeApi();
		const messagesDiv = document.getElementById('messages');
		const input = document.getElementById('input');

		input.addEventListener('keypress', e => {
			if (e.key === 'Enter') send();
		});

		function send() {
			const text = input.value.trim();
			if (text) {
				vscode.postMessage({ command: 'sendMessage', text });
				input.value = '';
			}
		}

		window.addEventListener('message', event => {
			const msg = event.data;
			if (msg.command === 'addMessage') {
				const div = document.createElement('div');
				div.className = 'message ' + msg.role;
				div.textContent = msg.content;
				messagesDiv.appendChild(div);
				messagesDiv.scrollTop = messagesDiv.scrollHeight;
			}
			if (msg.command === 'clearChat') {
				messagesDiv.innerHTML = '';
			}
		});
	</script>
</body>
</html>`;
	}
}
