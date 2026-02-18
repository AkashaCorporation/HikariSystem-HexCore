/*---------------------------------------------------------------------------------------------
 *  HexCore PE Analyzer View Provider
 *  Webview UI for displaying PE analysis results with tabbed interface
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { PEAnalysis } from './peParser';
import { getHexCoreBaseCSS, riskLevelToColor, entropyToColor } from 'hexcore-common';

// ============================================================================
// Exported Interfaces
// ============================================================================

export interface PEViewTab {
	id: 'overview' | 'headers' | 'sections' | 'imports' | 'exports' | 'resources' | 'security';
	label: string;
	icon: string;
}

export interface RiskIndicator {
	level: 'safe' | 'warning' | 'danger';
	label: string;
	detail: string;
}

// ============================================================================
// Exported Functions
// ============================================================================

const SUSPICIOUS_APIS: string[] = [
	'CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory',
	'NtUnmapViewOfSection', 'NtWriteVirtualMemory', 'RtlCreateUserThread',
	'QueueUserAPC', 'SetWindowsHookEx', 'CreateProcess', 'WinExec',
	'ShellExecute', 'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest',
	'RegSetValueEx', 'CryptEncrypt', 'CryptDecrypt', 'IsDebuggerPresent',
	'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess',
	'GetProcAddress', 'LoadLibrary', 'GetModuleHandle'
];

/**
 * Checks whether a given API function name is considered suspicious.
 * Comparison is case-insensitive and also matches names ending with 'A' or 'W' suffixes.
 */
export function isSuspiciousApi(name: string): boolean {
	const lower = name.toLowerCase();
	for (const api of SUSPICIOUS_APIS) {
		const apiLower = api.toLowerCase();
		if (lower === apiLower || lower === apiLower + 'a' || lower === apiLower + 'w') {
			return true;
		}
	}
	return false;
}

/**
 * Classifies risk indicators for a PE analysis result.
 * Returns an array of RiskIndicator objects based on packer detection,
 * entropy anomalies, suspicious API usage, anti-debug techniques, etc.
 */
export function classifyRisk(analysis: PEAnalysis): RiskIndicator[] {
	const risks: RiskIndicator[] = [];

	// Packer detection
	if (analysis.packerSignatures && analysis.packerSignatures.length > 0) {
		for (const packer of analysis.packerSignatures) {
			risks.push({
				level: 'danger',
				label: `Packer: ${packer}`,
				detail: `Packer signature detected: ${packer}`
			});
		}
	}

	// High entropy
	if (analysis.entropy > 7.0) {
		risks.push({
			level: 'danger',
			label: 'High Entropy',
			detail: `Overall entropy ${analysis.entropy.toFixed(2)} suggests packed or encrypted content`
		});
	} else if (analysis.entropy > 5.0) {
		risks.push({
			level: 'warning',
			label: 'Moderate Entropy',
			detail: `Overall entropy ${analysis.entropy.toFixed(2)} is above normal`
		});
	}

	// Suspicious sections
	if (analysis.sections) {
		for (const sec of analysis.sections) {
			if (sec.entropy > 7.0) {
				risks.push({
					level: 'warning',
					label: `High Entropy: ${sec.name}`,
					detail: `Section ${sec.name} has entropy ${sec.entropy.toFixed(2)}`
				});
			}
		}
		const knownNames = ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.idata', '.edata', '.pdata', '.tls', '.debug'];
		for (const sec of analysis.sections) {
			const normalized = sec.name.toLowerCase().trim();
			if (normalized.length > 0 && !knownNames.includes(normalized)) {
				risks.push({
					level: 'warning',
					label: `Unusual Section: ${sec.name}`,
					detail: `Section name "${sec.name}" is not a standard PE section`
				});
			}
		}
	}

	// Anti-debug techniques
	if (analysis.antiDebug && analysis.antiDebug.length > 0) {
		risks.push({
			level: 'danger',
			label: 'Anti-Debug',
			detail: `${analysis.antiDebug.length} anti-debug technique(s) detected`
		});
	}

	// Suspicious API imports
	if (analysis.imports) {
		let suspiciousCount = 0;
		for (const imp of analysis.imports) {
			for (const fn of imp.functions) {
				if (isSuspiciousApi(fn.name)) {
					suspiciousCount++;
				}
			}
		}
		if (suspiciousCount > 5) {
			risks.push({
				level: 'danger',
				label: 'Suspicious APIs',
				detail: `${suspiciousCount} suspicious API imports detected`
			});
		} else if (suspiciousCount > 0) {
			risks.push({
				level: 'warning',
				label: 'Suspicious APIs',
				detail: `${suspiciousCount} suspicious API import(s) detected`
			});
		}
	}

	// No risks found
	if (risks.length === 0) {
		risks.push({
			level: 'safe',
			label: 'Clean',
			detail: 'No suspicious indicators detected'
		});
	}

	return risks;
}

/**
 * Validates a PE checksum by comparing the calculated value with the header value.
 */
export function validateChecksum(calculated: number, header: number): { value: number; valid: boolean } {
	return {
		value: calculated,
		valid: calculated === header
	};
}

// ============================================================================
// Tab Definitions
// ============================================================================

const PE_TABS: PEViewTab[] = [
	{ id: 'overview', label: 'Overview', icon: 'dashboard' },
	{ id: 'headers', label: 'Headers', icon: 'symbol-structure' },
	{ id: 'sections', label: 'Sections', icon: 'layers' },
	{ id: 'imports', label: 'Imports', icon: 'references' },
	{ id: 'exports', label: 'Exports', icon: 'export' },
	{ id: 'resources', label: 'Resources', icon: 'file-media' },
	{ id: 'security', label: 'Security', icon: 'shield' }
];

// ============================================================================
// View Provider
// ============================================================================

export class PEAnalyzerViewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'hexcore.peanalyzer.view';
	private _view?: vscode.WebviewView;
	private _currentAnalysis?: PEAnalysis;

	constructor(private readonly _extensionUri: vscode.Uri) { }

	resolveWebviewView(
		webviewView: vscode.WebviewView,
		_context: vscode.WebviewViewResolveContext,
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
				case 'openInDisassembler':
					if (this._currentAnalysis) {
						await vscode.commands.executeCommand('hexcore.disasm.openFile', this._currentAnalysis.filePath);
					}
					break;
				case 'openInHexViewer':
					if (this._currentAnalysis) {
						const uri = vscode.Uri.file(this._currentAnalysis.filePath);
						await vscode.commands.executeCommand('vscode.openWith', uri, 'hexcore.hexEditor');
					}
					break;
				case 'switchTab':
					// Tab switching is handled client-side; no extension action needed
					break;
			}
		});
	}

	showAnalysis(analysis: PEAnalysis): void {
		this._currentAnalysis = analysis;
		if (this._view) {
			const risks = classifyRisk(analysis);
			this._view.webview.postMessage({
				command: 'showAnalysis',
				analysis: this._serializeAnalysis(analysis),
				risks: risks
			});
			this._view.show?.(true);
		}
	}

	private _serializeAnalysis(analysis: PEAnalysis): any {
		const serialized = JSON.parse(JSON.stringify(analysis, (_key, value) =>
			typeof value === 'bigint' ? value.toString() : value
		));
		return serialized;
	}

	private _getHtmlContent(): string {
		const nonce = this._getNonce();
		const baseCSS = getHexCoreBaseCSS();
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
	<title>PE Analyzer</title>
	<style>
		${baseCSS}
		:root {
			--bg-primary: var(--vscode-editor-background);
			--bg-secondary: var(--vscode-sideBar-background);
			--bg-tertiary: var(--vscode-input-background);
			--text-primary: var(--vscode-editor-foreground);
			--text-secondary: var(--vscode-descriptionForeground);
			--text-muted: var(--vscode-disabledForeground);
			--border-color: var(--vscode-panel-border);
			--accent: var(--vscode-textLink-foreground);
		}
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: var(--vscode-font-family);
			font-size: 12px;
			background: var(--bg-primary);
			color: var(--text-primary);
			padding: 0;
			line-height: 1.5;
		}
		.container { padding: 0; }
		.empty-state {
			display: flex;
			flex-direction: column;
			align-items: center;
			justify-content: center;
			padding: 40px 20px;
			text-align: center;
		}
		.empty-state .icon { font-size: 48px; margin-bottom: 16px; opacity: 0.5; }
		.empty-state h3 { margin-bottom: 8px; color: var(--text-primary); }
		.empty-state p { color: var(--text-secondary); margin-bottom: 16px; }
		.btn {
			display: inline-flex; align-items: center; gap: 6px;
			padding: 8px 16px; background: var(--vscode-button-background);
			color: var(--vscode-button-foreground); border: none;
			border-radius: 4px; cursor: pointer; font-size: 12px; font-family: inherit;
		}
		.btn:hover { background: var(--vscode-button-hoverBackground); }
		.header {
			display: flex; align-items: center; justify-content: space-between;
			padding: 8px 12px; background: var(--bg-secondary);
			border-bottom: 1px solid var(--border-color);
		}
		.header h2 {
			font-size: 13px; font-weight: 600;
			display: flex; align-items: center; gap: 8px;
		}
		.header-actions { display: flex; gap: 4px; }
		/* Tab bar */
		.tab-bar {
			display: flex; gap: 0; background: var(--bg-secondary);
			border-bottom: 1px solid var(--border-color);
			overflow-x: auto; flex-shrink: 0;
		}
		.tab-item {
			padding: 8px 14px; cursor: pointer; font-size: 11px;
			color: var(--text-secondary); border-bottom: 2px solid transparent;
			white-space: nowrap; display: flex; align-items: center; gap: 4px;
			background: transparent; border-top: none; border-left: none; border-right: none;
			font-family: inherit;
		}
		.tab-item:hover { color: var(--text-primary); background: var(--vscode-toolbar-hoverBackground); }
		.tab-item.active {
			color: var(--accent); border-bottom-color: var(--accent);
		}
		.tab-content { padding: 12px; display: none; }
		.tab-content.active { display: block; }
		/* File info */
		.file-info {
			background: var(--bg-tertiary); border-radius: 6px;
			padding: 12px; margin-bottom: 12px;
		}
		.file-info .filename {
			font-weight: 600; font-size: 14px; margin-bottom: 4px; word-break: break-all;
		}
		.file-info .meta {
			display: flex; flex-wrap: wrap; gap: 12px;
			color: var(--text-secondary); font-size: 11px;
		}
		/* Risk indicators */
		.risk-indicators { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }
		/* Section styles */
		.section { margin-bottom: 16px; }
		.section-header {
			display: flex; align-items: center; gap: 8px; padding: 8px 0;
			cursor: pointer; user-select: none; border-bottom: 1px solid var(--border-color);
		}
		.section-header:hover { color: var(--accent); }
		.section-header .icon { width: 16px; text-align: center; }
		.section-header .title { font-weight: 600; flex: 1; }
		.section-header .count {
			background: var(--bg-tertiary); padding: 2px 8px;
			border-radius: 10px; font-size: 10px;
		}
		.section-content { padding: 8px 0; }
		.section-content.collapsed { display: none; }
		/* Tables */
		table { width: 100%; border-collapse: collapse; }
		th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--border-color); }
		th { font-weight: 600; color: var(--text-secondary); font-size: 10px; text-transform: uppercase; }
		td { font-family: var(--hexcore-mono); font-size: 11px; }
		.tag-list { display: flex; flex-wrap: wrap; gap: 4px; }
		.tag {
			display: inline-block; padding: 2px 6px; background: var(--bg-tertiary);
			border-radius: 3px; font-size: 10px; font-family: var(--hexcore-mono);
		}
		/* Entropy bars */
		.entropy-bar-container {
			display: flex; align-items: center; gap: 6px; min-width: 120px;
		}
		.entropy-bar {
			height: 8px; border-radius: 4px; flex: 1;
			background: var(--bg-tertiary); overflow: hidden;
		}
		.entropy-bar .fill {
			height: 100%; border-radius: 4px; transition: width 0.3s ease;
		}
		.entropy-value { font-size: 10px; min-width: 30px; text-align: right; }
		/* Import DLL groups */
		.import-dll { margin-bottom: 8px; }
		.import-dll .dll-name {
			font-weight: 600; padding: 6px 8px; background: var(--bg-tertiary);
			border-radius: 4px 4px 0 0; display: flex; align-items: center;
			gap: 8px; cursor: pointer;
		}
		.import-dll .functions {
			padding: 8px; background: var(--bg-secondary);
			border-radius: 0 0 4px 4px; font-family: var(--hexcore-mono);
			font-size: 11px; max-height: 200px; overflow-y: auto;
		}
		.import-dll .functions.collapsed { display: none; }
		.func-item { padding: 2px 0; color: var(--text-secondary); }
		.func-item.suspicious {
			color: var(--hexcore-danger); font-weight: 600;
			padding: 2px 4px; background: #f4474712; border-radius: 2px;
		}
		/* Security / certificate */
		.cert-table td:first-child { color: var(--text-secondary); font-weight: 600; width: 120px; }
		.checksum-valid { color: var(--hexcore-safe); }
		.checksum-invalid { color: var(--hexcore-danger); }
		/* Navigation buttons */
		.nav-buttons { display: flex; gap: 4px; margin-top: 8px; }
		.error-state { padding: 20px; text-align: center; color: var(--hexcore-danger); }
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
	<script>
		const vscode = acquireVsCodeApi();
		let currentTab = 'overview';

		function openFile() { vscode.postMessage({ command: 'openFile' }); }
		function copyText(text) { vscode.postMessage({ command: 'copyToClipboard', text: text }); }
		function openInDisassembler() { vscode.postMessage({ command: 'openInDisassembler' }); }
		function openInHexViewer() { vscode.postMessage({ command: 'openInHexViewer' }); }

		function switchTab(tabId) {
			currentTab = tabId;
			document.querySelectorAll('.tab-item').forEach(t => t.classList.toggle('active', t.dataset.tab === tabId));
			document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'tab-' + tabId));
			vscode.postMessage({ command: 'switchTab', tab: tabId });
		}

		function toggleSection(id) {
			const el = document.getElementById(id);
			if (el) { el.classList.toggle('collapsed'); }
		}

		function formatBytes(bytes) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const sizes = ['B', 'KB', 'MB', 'GB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
		}

		function escapeHtml(text) {
			if (!text) return '';
			const div = document.createElement('div');
			div.textContent = String(text);
			return div.innerHTML;
		}

		function entropyColor(val) {
			if (val < 5.0) return '#4ec9b0';
			if (val <= 7.0) return '#dcdcaa';
			return '#f44747';
		}

		function riskBadge(r) {
			return '<span class="hexcore-badge hexcore-badge-' + r.level + '" title="' + escapeHtml(r.detail) + '">' + escapeHtml(r.label) + '</span>';
		}
		const SUSPICIOUS_API_LIST = [
			'createremotethread','virtualallocex','writeprocessmemory',
			'ntunmapviewofsection','ntwritevirtualmemory','rtlcreateuserthread',
			'queueuserapc','setwindowshookex','createprocess','winexec',
			'shellexecute','urldownloadtofile','internetopen','httpsendrequest',
			'regsetvalueex','cryptencrypt','cryptdecrypt','isdebuggerpresent',
			'checkremotedebuggerpresent','ntqueryinformationprocess',
			'getprocaddress','loadlibrary','getmodulehandle'
		];

		function isSuspiciousApiClient(name) {
			const lower = (name || '').toLowerCase();
			for (const api of SUSPICIOUS_API_LIST) {
				if (lower === api || lower === api + 'a' || lower === api + 'w') return true;
			}
			return false;
		}

		function renderAnalysis(analysis, risks) {
			if (!analysis.isPE) {
				return '<div class="error-state"><p>[X] ' + escapeHtml(analysis.error || 'Not a valid PE file') + '</p></div>';
			}
			let html = '';
			// Header bar
			html += '<div class="header"><h2>[PE] ' + escapeHtml(analysis.fileName) + '</h2>';
			html += '<div class="header-actions">';
			html += '<button class="hexcore-btn" onclick="openInDisassembler()" title="Open in Disassembler">Disasm</button>';
			html += '<button class="hexcore-btn" onclick="openInHexViewer()" title="Open in Hex Viewer">Hex</button>';
			html += '</div></div>';
			// Tab bar
			html += '<div class="tab-bar">';
			const tabs = ${JSON.stringify(PE_TABS)};
			tabs.forEach(function(tab) {
				const active = tab.id === 'overview' ? ' active' : '';
				html += '<button class="tab-item' + active + '" data-tab="' + tab.id + '" onclick="switchTab(\\'' + tab.id + '\\')">' + tab.label + '</button>';
			});
			html += '</div>';
			// === Overview Tab ===
			html += '<div class="tab-content active" id="tab-overview">';
			// Risk indicators
			if (risks && risks.length > 0) {
				html += '<div class="risk-indicators">';
				risks.forEach(function(r) { html += riskBadge(r); });
				html += '</div>';
			}
			// File info
			html += '<div class="file-info">';
			html += '<div class="filename">' + escapeHtml(analysis.fileName) + '</div>';
			html += '<div class="meta">';
			html += '<span>[Size] ' + formatBytes(analysis.fileSize) + '</span>';
			if (analysis.optionalHeader) html += '<span>[Type] ' + escapeHtml(analysis.optionalHeader.magic) + '</span>';
			if (analysis.peHeader) html += '<span>[Arch] ' + escapeHtml(analysis.peHeader.machine) + '</span>';
			if (analysis.optionalHeader) html += '<span>[Subsystem] ' + escapeHtml(analysis.optionalHeader.subsystem) + '</span>';
			html += '</div></div>';
			// Compilation timestamp
			if (analysis.timestamps) {
				html += '<div class="file-info"><strong>Compilation:</strong> ' + escapeHtml(analysis.timestamps.compile) + '</div>';
			}
			// Entropy overview
			html += '<div class="section"><div class="section-header"><span class="icon">[#]</span><span class="title">Entropy</span>';
			html += '<span class="hexcore-badge" style="background:' + entropyColor(analysis.entropy) + '22;color:' + entropyColor(analysis.entropy) + '">' + analysis.entropy.toFixed(2) + '</span>';
			html += '</div></div>';
			// Suspicious strings summary
			if (analysis.suspiciousStrings && analysis.suspiciousStrings.length > 0) {
				html += '<div class="section"><div class="section-header"><span class="icon">[!]</span>';
				html += '<span class="title">Suspicious Strings</span>';
				html += '<span class="hexcore-badge hexcore-badge-warning">' + analysis.suspiciousStrings.length + '</span>';
				html += '</div></div>';
			}
			// Navigation buttons
			html += '<div class="nav-buttons">';
			html += '<button class="hexcore-btn" onclick="openInDisassembler()">Open in Disassembler</button>';
			html += '<button class="hexcore-btn" onclick="openInHexViewer()">Open in Hex Viewer</button>';
			html += '</div>';
			html += '</div>';
			// === Headers Tab ===
			html += '<div class="tab-content" id="tab-headers">';
			if (analysis.peHeader) {
				html += '<div class="section"><div class="section-header"><span class="title">PE Header</span></div>';
				html += '<div class="section-content"><table>';
				html += '<tr><th>Field</th><th>Value</th></tr>';
				html += '<tr><td>Machine</td><td>' + escapeHtml(analysis.peHeader.machine) + '</td></tr>';
				html += '<tr><td>Timestamp</td><td>' + escapeHtml(analysis.peHeader.timeDateStampHuman) + '</td></tr>';
				html += '<tr><td>Sections</td><td>' + analysis.peHeader.numberOfSections + '</td></tr>';
				if (analysis.optionalHeader) {
					html += '<tr><td>Entry Point</td><td>0x' + analysis.optionalHeader.addressOfEntryPoint.toString(16).toUpperCase() + '</td></tr>';
					html += '<tr><td>Image Base</td><td>0x' + (analysis.optionalHeader.imageBase || 0).toString(16).toUpperCase() + '</td></tr>';
					html += '<tr><td>Checksum</td><td>0x' + analysis.optionalHeader.checksum.toString(16).toUpperCase() + '</td></tr>';
					html += '<tr><td>Linker</td><td>' + analysis.optionalHeader.majorLinkerVersion + '.' + analysis.optionalHeader.minorLinkerVersion + '</td></tr>';
				}
				html += '</table></div></div>';
				// Characteristics
				if (analysis.peHeader.characteristics && analysis.peHeader.characteristics.length > 0) {
					html += '<div class="section"><div class="section-header"><span class="title">Characteristics</span></div>';
					html += '<div class="section-content"><div class="tag-list">';
					analysis.peHeader.characteristics.forEach(function(c) { html += '<span class="tag">' + escapeHtml(c) + '</span>'; });
					html += '</div></div></div>';
				}
				// DLL Characteristics
				if (analysis.optionalHeader && analysis.optionalHeader.dllCharacteristics) {
					html += '<div class="section"><div class="section-header"><span class="title">Security Features</span></div>';
					html += '<div class="section-content"><div class="tag-list">';
					analysis.optionalHeader.dllCharacteristics.forEach(function(c) {
						const isGood = c.includes('ASLR') || c.includes('DEP') || c.includes('GUARD_CF') || c.includes('HIGH_ENTROPY');
						html += '<span class="hexcore-badge hexcore-badge-' + (isGood ? 'safe' : 'warning') + '">' + escapeHtml(c) + '</span>';
					});
					html += '</div></div></div>';
				}
			} else {
				html += '<p style="color:var(--text-secondary);padding:12px;">No header data available.</p>';
			}
			html += '</div>';
			// === Sections Tab (with entropy bars) ===
			html += '<div class="tab-content" id="tab-sections">';
			if (analysis.sections && analysis.sections.length > 0) {
				html += '<table>';
				html += '<tr><th>Name</th><th>VirtAddr</th><th>Size</th><th>Entropy</th><th>Flags</th></tr>';
				analysis.sections.forEach(function(sec) {
					const eColor = entropyColor(sec.entropy);
					const pct = (sec.entropy / 8 * 100).toFixed(1);
					html += '<tr>';
					html += '<td>' + escapeHtml(sec.name || '(empty)') + '</td>';
					html += '<td>0x' + sec.virtualAddress.toString(16).toUpperCase() + '</td>';
					html += '<td>' + formatBytes(sec.sizeOfRawData) + '</td>';
					html += '<td><div class="entropy-bar-container">';
					html += '<div class="entropy-bar"><div class="fill" style="width:' + pct + '%;background:' + eColor + '"></div></div>';
					html += '<span class="entropy-value" style="color:' + eColor + '">' + sec.entropy.toFixed(2) + '</span>';
					html += '</div></td>';
					html += '<td><div class="tag-list">';
					(sec.characteristics || []).slice(0, 4).forEach(function(c) { html += '<span class="tag">' + escapeHtml(c) + '</span>'; });
					html += '</div></td>';
					html += '</tr>';
				});
				html += '</table>';
				html += '<div class="nav-buttons">';
				html += '<button class="hexcore-btn" onclick="openInDisassembler()">Open in Disassembler</button>';
				html += '<button class="hexcore-btn" onclick="openInHexViewer()">Open in Hex Viewer</button>';
				html += '</div>';
			} else {
				html += '<p style="color:var(--text-secondary);padding:12px;">No sections found.</p>';
			}
			html += '</div>';
			// === Imports Tab (grouped by DLL, suspicious highlighted) ===
			html += '<div class="tab-content" id="tab-imports">';
			if (analysis.imports && analysis.imports.length > 0) {
				html += '<div style="margin-bottom:8px;color:var(--text-secondary);font-size:11px;">' + analysis.imports.length + ' DLLs imported</div>';
				analysis.imports.forEach(function(imp, idx) {
					const suspCount = imp.functions.filter(function(fn) {
						const name = typeof fn === 'string' ? fn : fn.name;
						return isSuspiciousApiClient(name);
					}).length;
					html += '<div class="import-dll">';
					html += '<div class="dll-name" onclick="toggleSection(\\'imp-' + idx + '\\')">';
					html += '<span>[+]</span>';
					html += '<span>' + escapeHtml(imp.dllName) + '</span>';
					html += '<span class="count">' + imp.functions.length + '</span>';
					if (suspCount > 0) {
						html += '<span class="hexcore-badge hexcore-badge-danger">' + suspCount + ' suspicious</span>';
					}
					html += '</div>';
					html += '<div class="functions collapsed" id="imp-' + idx + '">';
					imp.functions.forEach(function(fn) {
						const name = typeof fn === 'string' ? fn : fn.name;
						const susp = isSuspiciousApiClient(name);
						html += '<div class="func-item' + (susp ? ' suspicious' : '') + '">' + escapeHtml(name) + '</div>';
					});
					html += '</div></div>';
				});
			} else {
				html += '<p style="color:var(--text-secondary);padding:12px;">No imports found.</p>';
			}
			html += '</div>';
			// === Exports Tab ===
			html += '<div class="tab-content" id="tab-exports">';
			if (analysis.exports && analysis.exports.length > 0) {
				html += '<table>';
				html += '<tr><th>Ordinal</th><th>Name</th><th>Address</th></tr>';
				analysis.exports.forEach(function(exp) {
					html += '<tr>';
					html += '<td>' + exp.ordinal + '</td>';
					html += '<td>' + escapeHtml(exp.name) + '</td>';
					html += '<td>0x' + exp.address.toString(16).toUpperCase() + '</td>';
					html += '</tr>';
				});
				html += '</table>';
			} else {
				html += '<p style="color:var(--text-secondary);padding:12px;">No exports found.</p>';
			}
			html += '</div>';

			// === Resources Tab ===
			html += '<div class="tab-content" id="tab-resources">';
			if (analysis.resources && analysis.resources.length > 0) {
				html += '<table>';
				html += '<tr><th>Type</th><th>Name</th><th>Size</th><th>Language</th></tr>';
				analysis.resources.forEach(function(res) {
					html += '<tr>';
					html += '<td>' + escapeHtml(res.type) + '</td>';
					html += '<td>' + escapeHtml(String(res.name)) + '</td>';
					html += '<td>' + formatBytes(res.size) + '</td>';
					html += '<td>' + (res.langId || 'N/A') + '</td>';
					html += '</tr>';
				});
				html += '</table>';
			} else {
				html += '<p style="color:var(--text-secondary);padding:12px;">No resources found.</p>';
			}
			html += '</div>';
			// === Security Tab ===
			html += '<div class="tab-content" id="tab-security">';
			// Compilation timestamp
			if (analysis.timestamps) {
				html += '<div class="section"><div class="section-header"><span class="title">Compilation Timestamp</span></div>';
				html += '<div class="section-content"><table class="cert-table">';
				html += '<tr><td>Date</td><td>' + escapeHtml(analysis.timestamps.compile) + '</td></tr>';
				html += '<tr><td>Unix</td><td>' + analysis.timestamps.compileUnix + '</td></tr>';
				html += '</table></div></div>';
			}
			// Checksum
			if (analysis.optionalHeader) {
				const chk = analysis.optionalHeader.checksum;
				html += '<div class="section"><div class="section-header"><span class="title">Checksum</span></div>';
				html += '<div class="section-content"><table class="cert-table">';
				html += '<tr><td>Header Value</td><td>0x' + chk.toString(16).toUpperCase() + '</td></tr>';
				if (chk === 0) {
					html += '<tr><td>Status</td><td class="checksum-invalid">Not set (0x0)</td></tr>';
				} else {
					html += '<tr><td>Status</td><td class="checksum-valid">Present</td></tr>';
				}
				html += '</table></div></div>';
			}
			// Digital certificate (if security data directory exists)
			if (analysis.optionalHeader && analysis.optionalHeader.dataDirectories) {
				const secDir = analysis.optionalHeader.dataDirectories.find(function(d) { return d.name === 'Security' || d.name === 'Certificate Table'; });
				if (secDir && secDir.size > 0) {
					html += '<div class="section"><div class="section-header"><span class="title">Digital Certificate</span>';
					html += '<span class="hexcore-badge hexcore-badge-safe">Signed</span></div>';
					html += '<div class="section-content"><table class="cert-table">';
					html += '<tr><td>Directory Size</td><td>' + formatBytes(secDir.size) + '</td></tr>';
					html += '<tr><td>Directory RVA</td><td>0x' + secDir.virtualAddress.toString(16).toUpperCase() + '</td></tr>';
					html += '</table></div></div>';
				} else {
					html += '<div class="section"><div class="section-header"><span class="title">Digital Certificate</span>';
					html += '<span class="hexcore-badge hexcore-badge-warning">Not Signed</span></div></div>';
				}
			}
			// Security mitigations
			if (analysis.mitigations && analysis.mitigations.length > 0) {
				html += '<div class="section"><div class="section-header"><span class="title">Security Mitigations</span></div>';
				html += '<div class="section-content"><table>';
				html += '<tr><th>Feature</th><th>Status</th><th>Description</th></tr>';
				analysis.mitigations.forEach(function(m) {
					html += '<tr>';
					html += '<td>' + escapeHtml(m.name) + '</td>';
					html += '<td><span class="hexcore-badge hexcore-badge-' + (m.enabled ? 'safe' : 'danger') + '">' + (m.enabled ? 'Enabled' : 'Disabled') + '</span></td>';
					html += '<td style="font-family:var(--vscode-font-family);font-size:11px;">' + escapeHtml(m.description) + '</td>';
					html += '</tr>';
				});
				html += '</table></div></div>';
			}
			// Anti-debug
			if (analysis.antiDebug && analysis.antiDebug.length > 0) {
				html += '<div class="section"><div class="section-header"><span class="title">Anti-Debug Techniques</span>';
				html += '<span class="hexcore-badge hexcore-badge-danger">' + analysis.antiDebug.length + '</span></div>';
				html += '<div class="section-content"><table>';
				html += '<tr><th>Technique</th><th>Severity</th><th>Description</th></tr>';
				analysis.antiDebug.forEach(function(ad) {
					const lvl = ad.severity === 'high' ? 'danger' : ad.severity === 'medium' ? 'warning' : 'safe';
					html += '<tr>';
					html += '<td>' + escapeHtml(ad.name) + '</td>';
					html += '<td><span class="hexcore-badge hexcore-badge-' + lvl + '">' + escapeHtml(ad.severity) + '</span></td>';
					html += '<td style="font-family:var(--vscode-font-family);font-size:11px;">' + escapeHtml(ad.description) + '</td>';
					html += '</tr>';
				});
				html += '</table></div></div>';
			}
			html += '</div>';

			return html;
		}

		window.addEventListener('message', function(event) {
			const message = event.data;
			if (message.command === 'showAnalysis') {
				document.getElementById('content').innerHTML = renderAnalysis(message.analysis, message.risks);
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
