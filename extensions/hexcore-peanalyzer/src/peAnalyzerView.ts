/*---------------------------------------------------------------------------------------------
 *  HexCore PE Analyzer View Provider
 *  Webview UI for displaying PE analysis results
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { PEAnalysis } from './peParser';

export class PEAnalyzerViewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'hexcore.peanalyzer.view';
	private _view?: vscode.WebviewView;
	private _currentAnalysis?: PEAnalysis;

	constructor(private readonly _extensionUri: vscode.Uri) { }

	resolveWebviewView(
		webviewView: vscode.WebviewView,
		context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this._view = webviewView;

		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this._extensionUri]
		};

		webviewView.webview.html = this._getHtmlContent();

		webviewView.webview.onDidReceiveMessage(async message => {
			switch (message.command) {
				case 'openFile':
					await vscode.commands.executeCommand('hexcore.peanalyzer.analyze');
					break;
				case 'copyToClipboard':
					vscode.env.clipboard.writeText(message.text);
					vscode.window.showInformationMessage('Copied to clipboard');
					break;
			}
		});
	}

	showAnalysis(analysis: PEAnalysis): void {
		this._currentAnalysis = analysis;
		if (this._view) {
			this._view.webview.postMessage({
				command: 'showAnalysis',
				analysis: this._serializeAnalysis(analysis)
			});
			this._view.show?.(true);
		}
	}

	private _serializeAnalysis(analysis: PEAnalysis): any {
		// Convert BigInt to string for JSON serialization
		const serialized = JSON.parse(JSON.stringify(analysis, (key, value) =>
			typeof value === 'bigint' ? value.toString() : value
		));
		return serialized;
	}

	private _getHtmlContent(): string {
		const nonce = this._getNonce();
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-\${nonce}';">
	<title>PE Analyzer</title>
	<style>
		:root {
			--bg-primary: var(--vscode-editor-background);
			--bg-secondary: var(--vscode-sideBar-background);
			--bg-tertiary: var(--vscode-input-background);
			--text-primary: var(--vscode-editor-foreground);
			--text-secondary: var(--vscode-descriptionForeground);
			--text-muted: var(--vscode-disabledForeground);
			--border-color: var(--vscode-panel-border);
			--accent: var(--vscode-textLink-foreground);
			--success: var(--vscode-testing-iconPassed);
			--warning: var(--vscode-editorWarning-foreground);
			--error: var(--vscode-editorError-foreground);
			--info: var(--vscode-editorInfo-foreground);
		}

		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: var(--vscode-font-family);
			font-size: 12px;
			background: var(--bg-primary);
			color: var(--text-primary);
			padding: 0;
			line-height: 1.5;
		}

		.container {
			padding: 12px;
		}

		.empty-state {
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			padding: 40px 20px;
			text-align: center;
		}

		.empty-state .icon {
			font-size: 48px;
			margin-bottom: 16px;
			opacity: 0.5;
		}

		.empty-state h3 {
			margin-bottom: 8px;
			color: var(--text-primary);
		}

		.empty-state p {
			color: var(--text-secondary);
			margin-bottom: 16px;
		}

		.btn {
			display: inline-flex;
			align-items: center;
			gap: 6px;
			padding: 8px 16px;
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			border-radius: 4px;
			cursor: pointer;
			font-size: 12px;
			font-family: inherit;
		}

		.btn:hover {
			background: var(--vscode-button-hoverBackground);
		}

		.header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			padding: 8px 12px;
			background: var(--bg-secondary);
			border-bottom: 1px solid var(--border-color);
			margin: -12px -12px 12px -12px;
		}

		.header h2 {
			font-size: 13px;
			font-weight: 600;
			display: flex;
			align-items: center;
			gap: 8px;
		}

		.file-info {
			background: var(--bg-tertiary);
			border-radius: 6px;
			padding: 12px;
			margin-bottom: 12px;
		}

		.file-info .filename {
			font-weight: 600;
			font-size: 14px;
			margin-bottom: 4px;
			word-break: break-all;
		}

		.file-info .meta {
			display: flex;
			flex-wrap: wrap;
			gap: 12px;
			color: var(--text-secondary);
			font-size: 11px;
		}

		.section {
			margin-bottom: 16px;
		}

		.section-header {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 8px 0;
			cursor: pointer;
			user-select: none;
			border-bottom: 1px solid var(--border-color);
		}

		.section-header:hover {
			color: var(--accent);
		}

		.section-header .icon {
			width: 16px;
			text-align: center;
		}

		.section-header .title {
			font-weight: 600;
			flex: 1;
		}

		.section-header .count {
			background: var(--bg-tertiary);
			padding: 2px 8px;
			border-radius: 10px;
			font-size: 10px;
		}

		.section-content {
			padding: 8px 0;
		}

		.section-content.collapsed {
			display: none;
		}

		table {
			width: 100%;
			border-collapse: collapse;
		}

		th, td {
			text-align: left;
			padding: 6px 8px;
			border-bottom: 1px solid var(--border-color);
		}

		th {
			font-weight: 600;
			color: var(--text-secondary);
			font-size: 10px;
			text-transform: uppercase;
		}

		td {
			font-family: Consolas, Monaco, monospace;
			font-size: 11px;
		}

		.badge {
			display: inline-block;
			padding: 2px 6px;
			border-radius: 3px;
			font-size: 10px;
			font-weight: 500;
		}

		.badge.success { background: rgba(35, 134, 54, 0.2); color: var(--success); }
		.badge.warning { background: rgba(187, 128, 9, 0.2); color: var(--warning); }
		.badge.error { background: rgba(215, 58, 73, 0.2); color: var(--error); }
		.badge.info { background: rgba(3, 102, 214, 0.2); color: var(--info); }

		.tag-list {
			display: flex;
			flex-wrap: wrap;
			gap: 4px;
		}

		.tag {
			display: inline-block;
			padding: 2px 6px;
			background: var(--bg-tertiary);
			border-radius: 3px;
			font-size: 10px;
			font-family: Consolas, Monaco, monospace;
		}

		.progress-bar {
			height: 4px;
			background: var(--bg-tertiary);
			border-radius: 2px;
			overflow: hidden;
		}

		.progress-bar .fill {
			height: 100%;
			border-radius: 2px;
			transition: width 0.3s ease;
		}

		.entropy-low { background: var(--success); }
		.entropy-medium { background: var(--warning); }
		.entropy-high { background: var(--error); }

		.import-dll {
			margin-bottom: 8px;
		}

		.import-dll .dll-name {
			font-weight: 600;
			padding: 6px 8px;
			background: var(--bg-tertiary);
			border-radius: 4px 4px 0 0;
			display: flex;
			align-items: center;
			gap: 8px;
			cursor: pointer;
		}

		.import-dll .functions {
			padding: 8px;
			background: var(--bg-secondary);
			border-radius: 0 0 4px 4px;
			font-family: Consolas, Monaco, monospace;
			font-size: 11px;
			max-height: 200px;
			overflow-y: auto;
		}

		.import-dll .functions.collapsed {
			display: none;
		}

		.func-item {
			padding: 2px 0;
			color: var(--text-secondary);
		}

		.suspicious-item {
			padding: 4px 8px;
			margin-bottom: 4px;
			background: rgba(215, 58, 73, 0.1);
			border-left: 3px solid var(--error);
			border-radius: 0 4px 4px 0;
			font-family: Consolas, Monaco, monospace;
			font-size: 11px;
			word-break: break-all;
		}

		.packer-warning {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 8px 12px;
			background: rgba(187, 128, 9, 0.15);
			border: 1px solid var(--warning);
			border-radius: 4px;
			margin-bottom: 12px;
		}

		.packer-warning .icon {
			font-size: 16px;
		}

		.error-state {
			padding: 20px;
			text-align: center;
			color: var(--error);
		}
	</style>
</head>
<body>
	<div class="container" id="content">
		<div class="empty-state">
			<div class="icon">[PE]</div>
			<h3>PE Analyzer</h3>
			<p>Analyze portable executable files to view headers, sections, imports, and more.</p>
			<button class="btn" onclick="openFile()">[+] Analyze File</button>
		</div>
	</div>

	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();

		function openFile() {
			vscode.postMessage({ command: 'openFile' });
		}

		function copyText(text) {
			vscode.postMessage({ command: 'copyToClipboard', text: text });
		}

		function toggleSection(id) {
			const content = document.getElementById(id);
			if (content) {
				content.classList.toggle('collapsed');
			}
		}

		function formatBytes(bytes) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const sizes = ['B', 'KB', 'MB', 'GB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
		}

		function getEntropyClass(entropy) {
			if (entropy < 5) return 'entropy-low';
			if (entropy < 7) return 'entropy-medium';
			return 'entropy-high';
		}

		function getEntropyLabel(entropy) {
			if (entropy < 5) return 'Normal';
			if (entropy < 7) return 'Suspicious';
			return 'Packed/Encrypted';
		}

		function renderAnalysis(analysis) {
			if (!analysis.isPE) {
				return '<div class="error-state"><p>[X] ' + (analysis.error || 'Not a valid PE file') + '</p></div>';
			}

			let html = '';

			// Header
			html += '<div class="header"><h2>[PE] ' + escapeHtml(analysis.fileName) + '</h2></div>';

			// File Info
			html += '<div class="file-info">';
			html += '<div class="filename">' + escapeHtml(analysis.fileName) + '</div>';
			html += '<div class="meta">';
			html += '<span>[Size] ' + formatBytes(analysis.fileSize) + '</span>';
			if (analysis.optionalHeader) {
				html += '<span>[Type] ' + analysis.optionalHeader.magic + '</span>';
			}
			if (analysis.peHeader) {
				html += '<span>[Arch] ' + analysis.peHeader.machine + '</span>';
			}
			if (analysis.optionalHeader) {
				html += '<span>[Subsystem] ' + analysis.optionalHeader.subsystem + '</span>';
			}
			html += '</div></div>';

			// Packer Warning
			if (analysis.packerSignatures && analysis.packerSignatures.length > 0) {
				html += '<div class="packer-warning">';
				html += '<span class="icon">[!]</span>';
				html += '<span><strong>Packer Detected:</strong> ' + analysis.packerSignatures.join(', ') + '</span>';
				html += '</div>';
			}

			// Entropy
			html += '<div class="section">';
			html += '<div class="section-header" onclick="toggleSection(\\'entropy-content\\')">';
			html += '<span class="icon">[#]</span>';
			html += '<span class="title">Entropy Analysis</span>';
			html += '<span class="badge ' + (analysis.entropy > 7 ? 'error' : analysis.entropy > 5 ? 'warning' : 'success') + '">' + analysis.entropy.toFixed(2) + '</span>';
			html += '</div>';
			html += '<div class="section-content" id="entropy-content">';
			html += '<div style="margin-bottom:8px"><strong>Overall: </strong>' + getEntropyLabel(analysis.entropy) + '</div>';
			html += '<div class="progress-bar"><div class="fill ' + getEntropyClass(analysis.entropy) + '" style="width:' + (analysis.entropy / 8 * 100) + '%"></div></div>';
			html += '</div></div>';

			// Headers Section
			if (analysis.peHeader) {
				html += '<div class="section">';
				html += '<div class="section-header" onclick="toggleSection(\\'headers-content\\')">';
				html += '<span class="icon">[H]</span>';
				html += '<span class="title">PE Headers</span>';
				html += '</div>';
				html += '<div class="section-content" id="headers-content">';
				html += '<table>';
				html += '<tr><th>Field</th><th>Value</th></tr>';
				html += '<tr><td>Machine</td><td>' + analysis.peHeader.machine + '</td></tr>';
				html += '<tr><td>Timestamp</td><td>' + analysis.peHeader.timeDateStampHuman + '</td></tr>';
				html += '<tr><td>Sections</td><td>' + analysis.peHeader.numberOfSections + '</td></tr>';
				if (analysis.optionalHeader) {
					html += '<tr><td>Entry Point</td><td>0x' + analysis.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase() + '</td></tr>';
					html += '<tr><td>Image Base</td><td>0x' + analysis.optionalHeader.imageBase.toString(16).toUpperCase() + '</td></tr>';
					html += '<tr><td>Checksum</td><td>0x' + analysis.optionalHeader.checksum.toString(16).toUpperCase() + '</td></tr>';
				}
				html += '</table>';

				// Characteristics
				if (analysis.peHeader.characteristics && analysis.peHeader.characteristics.length > 0) {
					html += '<div style="margin-top:8px"><strong>Characteristics:</strong></div>';
					html += '<div class="tag-list" style="margin-top:4px">';
					analysis.peHeader.characteristics.forEach(c => {
						html += '<span class="tag">' + c + '</span>';
					});
					html += '</div>';
				}

				// DLL Characteristics (Security)
				if (analysis.optionalHeader && analysis.optionalHeader.dllCharacteristics) {
					html += '<div style="margin-top:12px"><strong>Security Features:</strong></div>';
					html += '<div class="tag-list" style="margin-top:4px">';
					analysis.optionalHeader.dllCharacteristics.forEach(c => {
						const isGood = c.includes('ASLR') || c.includes('DEP') || c.includes('GUARD_CF') || c.includes('HIGH_ENTROPY');
						html += '<span class="badge ' + (isGood ? 'success' : 'info') + '">' + c + '</span>';
					});
					html += '</div>';
				}

				html += '</div></div>';
			}

			// Sections
			if (analysis.sections && analysis.sections.length > 0) {
				html += '<div class="section">';
				html += '<div class="section-header" onclick="toggleSection(\\'sections-content\\')">';
				html += '<span class="icon">[S]</span>';
				html += '<span class="title">Sections</span>';
				html += '<span class="count">' + analysis.sections.length + '</span>';
				html += '</div>';
				html += '<div class="section-content" id="sections-content">';
				html += '<table>';
				html += '<tr><th>Name</th><th>VirtAddr</th><th>Size</th><th>Entropy</th><th>Flags</th></tr>';
				analysis.sections.forEach(sec => {
					html += '<tr>';
					html += '<td>' + escapeHtml(sec.name || '(empty)') + '</td>';
					html += '<td>0x' + sec.virtualAddress.toString(16).toUpperCase() + '</td>';
					html += '<td>' + formatBytes(sec.sizeOfRawData) + '</td>';
					html += '<td><span class="badge ' + (sec.entropy > 7 ? 'error' : sec.entropy > 5 ? 'warning' : 'success') + '">' + sec.entropy.toFixed(2) + '</span></td>';
					html += '<td class="tag-list">';
					(sec.characteristics || []).slice(0, 4).forEach(c => {
						html += '<span class="tag">' + c + '</span>';
					});
					html += '</td>';
					html += '</tr>';
				});
				html += '</table>';
				html += '</div></div>';
			}

			// Imports
			if (analysis.imports && analysis.imports.length > 0) {
				html += '<div class="section">';
				html += '<div class="section-header" onclick="toggleSection(\\'imports-content\\')">';
				html += '<span class="icon">[I]</span>';
				html += '<span class="title">Imports</span>';
				html += '<span class="count">' + analysis.imports.length + ' DLLs</span>';
				html += '</div>';
				html += '<div class="section-content" id="imports-content">';
				analysis.imports.forEach((imp, idx) => {
					html += '<div class="import-dll">';
					html += '<div class="dll-name" onclick="toggleSection(\\'import-' + idx + '\\')">';
					html += '<span>[+]</span>';
					html += '<span>' + escapeHtml(imp.dllName) + '</span>';
					html += '<span class="count">' + imp.functions.length + '</span>';
					html += '</div>';
					html += '<div class="functions collapsed" id="import-' + idx + '">';
					imp.functions.forEach(fn => {
						html += '<div class="func-item">' + escapeHtml(fn) + '</div>';
					});
					html += '</div></div>';
				});
				html += '</div></div>';
			}

			// Suspicious Strings
			if (analysis.suspiciousStrings && analysis.suspiciousStrings.length > 0) {
				html += '<div class="section">';
				html += '<div class="section-header" onclick="toggleSection(\\'strings-content\\')">';
				html += '<span class="icon">[!]</span>';
				html += '<span class="title">Suspicious Strings</span>';
				html += '<span class="count badge warning">' + analysis.suspiciousStrings.length + '</span>';
				html += '</div>';
				html += '<div class="section-content" id="strings-content">';
				const maxStrings = 20;
				analysis.suspiciousStrings.slice(0, maxStrings).forEach(str => {
					html += '<div class="suspicious-item">' + escapeHtml(str) + '</div>';
				});
				if (analysis.suspiciousStrings.length > maxStrings) {
					html += '<div style="padding:4px 8px;opacity:0.7;font-style:italic;">Showing ' + maxStrings + ' of ' + analysis.suspiciousStrings.length + ' strings</div>';
				}
				html += '</div></div>';
			}

			return html;
		}

		function escapeHtml(text) {
			if (!text) return '';
			const div = document.createElement('div');
			div.textContent = text;
			return div.innerHTML;
		}

		window.addEventListener('message', event => {
			const message = event.data;
			if (message.command === 'showAnalysis') {
				document.getElementById('content').innerHTML = renderAnalysis(message.analysis);
			}
		});
	</script>
</body>
</html>`;
	}

	private _getNonce(): string {
		const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		let nonce = '';
		for (let i = 0; i < 32; i++) {
			nonce += possible.charAt(Math.floor(Math.random() * possible.length));
		}
		return nonce;
	}
}
