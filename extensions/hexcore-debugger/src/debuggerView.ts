/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger View Provider
 *  Webview with emulation controls, API call log, and headless command access
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DebugEngine } from './debugEngine';
import { ArchitectureType } from './unicornWrapper';
import { getHexCoreBaseCSS } from 'hexcore-common';

/**
 * Represents a single API call entry in the log.
 */
export interface ApiCallEntry {
	dll: string;
	name: string;
	returnValue: string;
}

/**
 * Decode escape sequences in a stdin input string.
 * Supports: \\n → newline, \\t → tab, \\\\ → backslash.
 * Characters that are not part of a recognized escape sequence are kept as-is.
 */
export function decodeEscapedInput(input: string): string {
	let result = '';
	let i = 0;
	while (i < input.length) {
		if (input[i] === '\\' && i + 1 < input.length) {
			const next = input[i + 1];
			if (next === 'n') {
				result += '\n';
				i += 2;
			} else if (next === 't') {
				result += '\t';
				i += 2;
			} else if (next === '\\') {
				result += '\\';
				i += 2;
			} else {
				result += input[i];
				i++;
			}
		} else {
			result += input[i];
			i++;
		}
	}
	return result;
}

/**
 * Filter API calls by DLL or function name (case-insensitive).
 * If filter is empty, returns all calls.
 */
export function filterApiCalls(calls: ApiCallEntry[], filter: string): ApiCallEntry[] {
	if (!filter || filter.trim().length === 0) {
		return calls;
	}
	const lowerFilter = filter.toLowerCase();
	return calls.filter(c =>
		c.dll.toLowerCase().includes(lowerFilter) ||
		c.name.toLowerCase().includes(lowerFilter)
	);
}

const STATUS_COLORS: Record<string, string> = {
	'running': '#4ec9b0',
	'paused': '#dcdcaa',
	'stopped': '#808080',
	'breakpoint-hit': '#f44747',
	'crashed': '#f44747',
};

const ARCHITECTURES: ArchitectureType[] = ['x86', 'x64', 'arm', 'arm64', 'mips', 'riscv'];

export class DebuggerViewProvider implements vscode.WebviewViewProvider {
	private view?: vscode.WebviewView;
	private engine: DebugEngine;

	/**
	 * Recursively convert BigInt values to hex strings for JSON serialization.
	 * JSON.stringify cannot handle BigInt, and webview.postMessage uses JSON internally.
	 */
	static serializeForWebview(obj: any): any {
		if (obj === null || obj === undefined) {
			return obj;
		}
		if (typeof obj === 'bigint') {
			return '0x' + obj.toString(16).toUpperCase();
		}
		if (Array.isArray(obj)) {
			return obj.map(item => DebuggerViewProvider.serializeForWebview(item));
		}
		if (typeof obj === 'object' && !(obj instanceof Buffer)) {
			const result: Record<string, any> = {};
			for (const key of Object.keys(obj)) {
				result[key] = DebuggerViewProvider.serializeForWebview(obj[key]);
			}
			return result;
		}
		return obj;
	}

	constructor(extensionUri: vscode.Uri, engine: DebugEngine) {
		this.engine = engine;

		engine.onEvent((event, data) => {
			if (this.view) {
				const safeData = DebuggerViewProvider.serializeForWebview(data);
				this.view.webview.postMessage({ command: event, data: safeData });
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

		webviewView.webview.onDidReceiveMessage(async (message) => {
			switch (message.command) {
				case 'openFile': {
					const uris = await vscode.window.showOpenDialog({
						canSelectMany: false,
						openLabel: 'Select Binary',
						filters: { 'Binary Files': ['exe', 'dll', 'elf', 'so', 'o', 'bin', '*'] }
					});
					if (uris && uris.length > 0) {
						webviewView.webview.postMessage({
							command: 'fileSelected',
							data: { path: uris[0].fsPath }
						});
					}
					break;
				}
				case 'selectArch': {
					const arch = message.data?.arch as ArchitectureType | undefined;
					if (arch) {
						webviewView.webview.postMessage({
							command: 'archSelected',
							data: { arch }
						});
					}
					break;
				}
				case 'startEmulation': {
					const filePath = message.data?.filePath as string | undefined;
					const arch = message.data?.arch as ArchitectureType | undefined;
					if (filePath && arch) {
						try {
							await vscode.commands.executeCommand('hexcore.debug.emulateWithArch', { file: filePath, arch });
						} catch (err: unknown) {
							const errMsg = err instanceof Error ? err.message : String(err);
							webviewView.webview.postMessage({
								command: 'error',
								data: { message: errMsg }
							});
						}
					}
					break;
				}
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
				case 'setStdin': {
					const raw = message.data?.value as string ?? '';
					const decoded = decodeEscapedInput(raw);
					vscode.commands.executeCommand('hexcore.debug.setStdin', { value: decoded });
					break;
				}
				case 'filterApiLog': {
					// Filtering is handled client-side in the webview
					break;
				}
				case 'exportTrace': {
					try {
						const result = await vscode.commands.executeCommand('hexcore.debug.exportTraceHeadless');
						if (result) {
							const doc = await vscode.workspace.openTextDocument({
								content: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
								language: typeof result === 'string' && result.startsWith('#') ? 'markdown' : 'json'
							});
							await vscode.window.showTextDocument(doc, { preview: true });
						}
					} catch (err: unknown) {
						const errMsg = err instanceof Error ? err.message : String(err);
						vscode.window.showErrorMessage(`Export Trace failed: ${errMsg}`);
					}
					break;
				}
				case 'getState': {
					try {
						const result = await vscode.commands.executeCommand('hexcore.debug.getStateHeadless');
						if (result) {
							const content = typeof result === 'string' ? result : JSON.stringify(result, null, 2);
							const doc = await vscode.workspace.openTextDocument({
								content,
								language: 'json'
							});
							await vscode.window.showTextDocument(doc, { preview: true });
						}
					} catch (err: unknown) {
						const errMsg = err instanceof Error ? err.message : String(err);
						vscode.window.showErrorMessage(`Get State failed: ${errMsg}`);
					}
					break;
				}
			}
		});
	}

	show(): void {
		this.view?.show?.(true);
	}

	private getHtml(): string {
		const baseCSS = getHexCoreBaseCSS();
		return `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; font-src data:;">
	<style>
${baseCSS}

		body {
			font-family: var(--vscode-font-family);
			padding: 0;
			margin: 0;
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
		}
		.content {
			padding: 8px;
		}
		/* Welcome screen */
		.welcome {
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			padding: 32px 16px;
			text-align: center;
			gap: 16px;
		}
		.welcome-icon {
			font-size: 48px;
			opacity: 0.5;
		}
		.welcome h2 {
			margin: 0;
			font-size: 14px;
			font-weight: 600;
		}
		.welcome p {
			margin: 0;
			font-size: 12px;
			color: var(--vscode-descriptionForeground);
			max-width: 280px;
			line-height: 1.5;
		}
		.welcome-btn {
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			padding: 8px 20px;
			border-radius: 3px;
			cursor: pointer;
			font-size: 13px;
			font-weight: 600;
			display: flex;
			align-items: center;
			gap: 6px;
		}
		.welcome-btn:hover {
			background: var(--vscode-button-hoverBackground);
		}
		/* Architecture selector */
		.arch-selector {
			display: flex;
			gap: 2px;
			align-items: center;
		}
		.arch-selector select {
			background: var(--vscode-dropdown-background);
			color: var(--vscode-dropdown-foreground);
			border: 1px solid var(--vscode-dropdown-border);
			padding: 3px 6px;
			font-size: 11px;
			border-radius: 3px;
			cursor: pointer;
		}
		/* Status indicator */
		.status-bar {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 6px 8px;
			background: var(--vscode-statusBar-background);
			border-radius: 3px;
			font-size: 11px;
			margin-bottom: 8px;
		}
		.status-dot {
			width: 8px;
			height: 8px;
			border-radius: 50%;
			flex-shrink: 0;
		}
		.status-info {
			display: flex;
			gap: 12px;
			align-items: center;
			font-family: var(--hexcore-mono);
			font-size: 11px;
			color: var(--vscode-descriptionForeground);
		}
		.error-banner {
			background: #f4474722;
			color: #f44747;
			padding: 6px 8px;
			border-radius: 3px;
			font-size: 11px;
			margin-bottom: 8px;
			display: none;
		}
		/* Section titles */
		.section-title {
			font-weight: bold;
			margin: 10px 0 5px 0;
			font-size: 11px;
			text-transform: uppercase;
			color: var(--vscode-descriptionForeground);
		}
		/* API log */
		.api-log-container {
			margin-bottom: 8px;
		}
		.api-filter {
			display: flex;
			gap: 4px;
			margin-bottom: 4px;
		}
		.api-filter input {
			flex: 1;
			background: var(--vscode-input-background);
			color: var(--vscode-input-foreground);
			border: 1px solid var(--vscode-input-border, transparent);
			padding: 3px 6px;
			font-size: 11px;
			border-radius: 3px;
			font-family: var(--hexcore-mono);
		}
		.api-log {
			font-family: var(--hexcore-mono);
			font-size: 11px;
			background: var(--vscode-terminal-background);
			padding: 0;
			border-radius: 4px;
			max-height: 250px;
			overflow-y: auto;
		}
		.api-table {
			width: 100%;
			border-collapse: collapse;
			font-size: 11px;
		}
		.api-table th {
			text-align: left;
			padding: 4px 6px;
			border-bottom: 1px solid var(--vscode-panel-border);
			color: var(--vscode-descriptionForeground);
			font-weight: 600;
			position: sticky;
			top: 0;
			background: var(--vscode-terminal-background);
		}
		.api-table td {
			padding: 2px 6px;
			border-bottom: 1px solid var(--vscode-panel-border);
		}
		.api-dll { color: var(--vscode-descriptionForeground); }
		.api-name { color: var(--vscode-symbolIcon-functionForeground, #DCDCAA); }
		.api-ret { color: var(--vscode-symbolIcon-numberForeground, #B5CEA8); }
		/* Stdout section */
		.stdout-section {
			font-family: var(--hexcore-mono);
			font-size: 11px;
			background: var(--vscode-terminal-background);
			padding: 8px;
			border-radius: 4px;
			max-height: 150px;
			overflow-y: auto;
			white-space: pre-wrap;
			word-break: break-all;
			min-height: 24px;
			color: var(--vscode-terminal-foreground, var(--vscode-editor-foreground));
		}
		/* Stdin inline field */
		.stdin-row {
			display: flex;
			gap: 4px;
			align-items: center;
			margin-bottom: 8px;
		}
		.stdin-row input {
			flex: 1;
			background: var(--vscode-input-background);
			color: var(--vscode-input-foreground);
			border: 1px solid var(--vscode-input-border, transparent);
			padding: 3px 6px;
			font-size: 11px;
			border-radius: 3px;
			font-family: var(--hexcore-mono);
		}
		.stdin-row button {
			padding: 3px 8px;
			font-size: 11px;
		}
		.hidden { display: none !important; }
	</style>
</head>
<body>
	<!-- Welcome screen (shown when idle) -->
	<div id="welcomeScreen" class="welcome">
		<div class="welcome-icon">&#x1F41B;</div>
		<h2>HexCore Debugger</h2>
		<p>Select a binary file and architecture to start emulation. Supports PE and ELF formats with API call tracing.</p>
		<div class="arch-selector">
			<label style="font-size:11px;color:var(--vscode-descriptionForeground)">Arch:</label>
			<select id="welcomeArch">
				<option value="x86">x86</option>
				<option value="x64" selected>x64</option>
				<option value="arm">ARM</option>
				<option value="arm64">ARM64</option>
				<option value="mips">MIPS</option>
				<option value="riscv">RISC-V</option>
			</select>
		</div>
		<button class="welcome-btn" onclick="openFile()">
			<span class="codicon codicon-folder-opened"></span>
			Open File
		</button>
	</div>

	<!-- Main session view (shown when emulation active) -->
	<div id="sessionView" class="hidden">
		<!-- Toolbar -->
		<div class="hexcore-toolbar">
			<div class="hexcore-toolbar-left">
				<button class="hexcore-btn" onclick="openFile()" title="Open File">
					<span class="codicon codicon-folder-opened"></span>
				</button>
				<div class="arch-selector">
					<select id="archSelect" onchange="selectArch(this.value)">
						<option value="x86">x86</option>
						<option value="x64" selected>x64</option>
						<option value="arm">ARM</option>
						<option value="arm64">ARM64</option>
						<option value="mips">MIPS</option>
						<option value="riscv">RISC-V</option>
					</select>
				</div>
				<span style="border-left:1px solid var(--vscode-panel-border);height:16px;margin:0 2px"></span>
				<button class="hexcore-btn" onclick="sendCmd('step')" title="Step one instruction">
					<span class="codicon codicon-debug-step-over"></span> Step
				</button>
				<button class="hexcore-btn" onclick="sendCmd('continue')" title="Continue execution">
					<span class="codicon codicon-play"></span> Continue
				</button>
				<button class="hexcore-btn" onclick="sendCmd('breakpoint')" title="Set breakpoint">
					<span class="codicon codicon-debug-breakpoint"></span> +Break
				</button>
				<button class="hexcore-btn" onclick="sendCmd('readMemory')" title="Read memory">
					<span class="codicon codicon-file-binary"></span> Memory
				</button>
				<button class="hexcore-btn" onclick="sendCmd('snapshot')" title="Save snapshot">
					<span class="codicon codicon-save"></span> Save
				</button>
				<button class="hexcore-btn" onclick="sendCmd('restore')" title="Restore snapshot">
					<span class="codicon codicon-history"></span> Restore
				</button>
				<button class="hexcore-btn" onclick="toggleStdin()" title="Set STDIN buffer">
					<span class="codicon codicon-edit"></span> STDIN
				</button>
				<span style="border-left:1px solid var(--vscode-panel-border);height:16px;margin:0 2px"></span>
				<button class="hexcore-btn" onclick="sendCmd('exportTrace')" title="Export execution trace">
					<span class="codicon codicon-export"></span> Export Trace
				</button>
				<button class="hexcore-btn" onclick="sendCmd('getState')" title="Get emulation state">
					<span class="codicon codicon-json"></span> Get State
				</button>
			</div>
			<div class="hexcore-toolbar-right">
				<span id="archInfo"></span>
				<span id="fileTypeInfo"></span>
				<span id="instrCount">Instructions: 0</span>
			</div>
		</div>

		<div class="content">
			<!-- Status bar -->
			<div class="status-bar">
				<div class="status-dot" id="statusDot" style="background:#808080"></div>
				<span id="statusText">Idle</span>
			</div>

			<!-- Error banner -->
			<div class="error-banner" id="errorBanner"></div>

			<!-- Stdin inline field -->
			<div class="stdin-row hidden" id="stdinRow">
				<label style="font-size:11px;color:var(--vscode-descriptionForeground);white-space:nowrap">STDIN:</label>
				<input type="text" id="stdinInput" placeholder="Enter stdin (supports \\n \\t \\\\)" />
				<button class="hexcore-btn" onclick="sendStdin()">Send</button>
			</div>

			<!-- API Call Log -->
			<div class="api-log-container">
				<div class="section-title">API Call Log</div>
				<div class="api-filter">
					<input type="text" id="apiFilter" placeholder="Filter by DLL or function..." oninput="applyFilter()" />
				</div>
				<div class="api-log" id="apiLog">
					<table class="api-table">
						<thead>
							<tr><th>DLL</th><th>Function</th><th>Return</th></tr>
						</thead>
						<tbody id="apiLogBody"></tbody>
					</table>
				</div>
			</div>

			<!-- Stdout -->
			<div class="section-title">Captured Stdout</div>
			<div class="stdout-section" id="stdoutSection">No output captured yet.</div>
		</div>
	</div>

	<script>
		const vscode = acquireVsCodeApi();
		let currentStatus = 'idle';
		let selectedFilePath = null;
		let selectedArch = 'x64';
		let apiCalls = [];
		let stdoutBuffer = '';
		let stdinVisible = false;

		function sendCmd(cmd, data) {
			vscode.postMessage({ command: cmd, data: data });
		}

		function openFile() {
			selectedArch = document.getElementById(currentStatus === 'idle' ? 'welcomeArch' : 'archSelect').value;
			sendCmd('openFile');
		}

		function selectArch(arch) {
			selectedArch = arch;
			sendCmd('selectArch', { arch: arch });
		}

		function toggleStdin() {
			stdinVisible = !stdinVisible;
			document.getElementById('stdinRow').classList.toggle('hidden', !stdinVisible);
			if (stdinVisible) {
				document.getElementById('stdinInput').focus();
			}
		}

		function sendStdin() {
			const input = document.getElementById('stdinInput');
			sendCmd('setStdin', { value: input.value });
			input.value = '';
		}

		function applyFilter() {
			const filter = document.getElementById('apiFilter').value.toLowerCase();
			const rows = document.getElementById('apiLogBody').querySelectorAll('tr');
			rows.forEach(row => {
				const dll = row.cells[0]?.textContent?.toLowerCase() || '';
				const fn = row.cells[1]?.textContent?.toLowerCase() || '';
				row.style.display = (!filter || dll.includes(filter) || fn.includes(filter)) ? '' : 'none';
			});
		}

		function updateStatus(status, extra) {
			currentStatus = status;
			const dot = document.getElementById('statusDot');
			const text = document.getElementById('statusText');
			const colors = {
				'running': '#4ec9b0',
				'paused': '#dcdcaa',
				'stopped': '#808080',
				'breakpoint-hit': '#f44747',
				'crashed': '#f44747'
			};
			dot.style.background = colors[status] || '#808080';
			const labels = {
				'idle': 'Idle',
				'running': 'Running',
				'paused': 'Paused',
				'stopped': 'Stopped',
				'breakpoint-hit': 'Breakpoint Hit',
				'crashed': 'Crashed'
			};
			text.textContent = labels[status] || status;
			if (extra) { text.textContent += ' — ' + extra; }

			// Toggle welcome vs session view
			document.getElementById('welcomeScreen').classList.toggle('hidden', status !== 'idle');
			document.getElementById('sessionView').classList.toggle('hidden', status === 'idle');
		}

		function addApiCall(data) {
			if (!data) { return; }
			apiCalls.push(data);
			const tbody = document.getElementById('apiLogBody');
			const row = document.createElement('tr');
			row.innerHTML =
				'<td class="api-dll">' + escapeHtml(data.dll || '') + '</td>' +
				'<td class="api-name">' + escapeHtml(data.name || '') + '</td>' +
				'<td class="api-ret">' + escapeHtml(String(data.returnValue ?? '0x0')) + '</td>';
			tbody.appendChild(row);
			// Auto-scroll to most recent entry
			const log = document.getElementById('apiLog');
			log.scrollTop = log.scrollHeight;
			// Apply current filter
			applyFilter();
		}

		function escapeHtml(str) {
			return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
		}

		function updateStdout(text) {
			stdoutBuffer += text;
			const el = document.getElementById('stdoutSection');
			el.textContent = stdoutBuffer || 'No output captured yet.';
			el.scrollTop = el.scrollHeight;
		}

		function showError(msg) {
			const banner = document.getElementById('errorBanner');
			banner.textContent = msg;
			banner.style.display = 'block';
			setTimeout(() => { banner.style.display = 'none'; }, 10000);
		}

		window.addEventListener('message', event => {
			const msg = event.data;
			switch (msg.command) {
				case 'fileSelected':
					selectedFilePath = msg.data?.path;
					// Auto-start emulation when file + arch are ready
					if (selectedFilePath && selectedArch) {
						sendCmd('startEmulation', { filePath: selectedFilePath, arch: selectedArch });
					}
					break;
				case 'archSelected':
					selectedArch = msg.data?.arch;
					break;
				case 'emulation-started':
					apiCalls = [];
					stdoutBuffer = '';
					document.getElementById('apiLogBody').innerHTML = '';
					document.getElementById('stdoutSection').textContent = 'No output captured yet.';
					document.getElementById('errorBanner').style.display = 'none';
					updateStatus('running');
					if (msg.data?.architecture) {
						document.getElementById('archInfo').textContent = 'Arch: ' + msg.data.architecture.toUpperCase();
						const sel = document.getElementById('archSelect');
						if (sel) { sel.value = msg.data.architecture; }
					}
					if (msg.data?.fileType) {
						document.getElementById('fileTypeInfo').textContent = msg.data.fileType.toUpperCase();
					}
					break;
				case 'updateState':
					if (msg.data?.status) { updateStatus(msg.data.status); }
					if (msg.data?.instructionCount !== undefined) {
						document.getElementById('instrCount').textContent = 'Instructions: ' + msg.data.instructionCount;
					}
					if (msg.data?.architecture) {
						document.getElementById('archInfo').textContent = 'Arch: ' + msg.data.architecture.toUpperCase();
					}
					if (msg.data?.fileType) {
						document.getElementById('fileTypeInfo').textContent = msg.data.fileType.toUpperCase();
					}
					break;
				case 'api-call':
					addApiCall(msg.data);
					break;
				case 'stdout-update':
					if (msg.data?.text) { updateStdout(msg.data.text); }
					break;
				case 'step':
					updateStatus('paused', 'stepped');
					if (msg.data?.instructionCount !== undefined) {
						document.getElementById('instrCount').textContent = 'Instructions: ' + msg.data.instructionCount;
					}
					break;
				case 'stopped':
					updateStatus('stopped');
					break;
				case 'breakpoint-hit':
					updateStatus('breakpoint-hit');
					break;
				case 'crashed':
					updateStatus('crashed', msg.data?.reason);
					break;
				case 'snapshot-saved':
					// Brief visual feedback
					break;
				case 'snapshot-restored':
					// Brief visual feedback
					break;
				case 'error':
					if (msg.data?.message) {
						showError(msg.data.message);
						updateStatus('idle');
					}
					break;
			}
		});

		// Initialize in idle state
		updateStatus('idle');
	</script>
</body>
</html>`;
	}
}
