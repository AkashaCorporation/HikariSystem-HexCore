/*---------------------------------------------------------------------------------------------
 *  HexCore PE Analyzer - Webview Provider
 *  Provides the analysis UI in the sidebar
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { PEAnalysis } from './peParser';

export class PEAnalyzerViewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'hexcore.peanalyzer.view';
	private _view?: vscode.WebviewView;
	private _currentAnalysis?: PEAnalysis;

	constructor(private readonly _extensionUri: vscode.Uri) { }

	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		_context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	) {
		this._view = webviewView;

		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this._extensionUri],
		};

		webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

		// Handle messages from webview
		webviewView.webview.onDidReceiveMessage((message) => {
			switch (message.type) {
				case 'copyToClipboard':
					vscode.env.clipboard.writeText(message.text);
					vscode.window.showInformationMessage('Copied to clipboard');
					break;
				case 'openFile':
					if (this._currentAnalysis) {
						vscode.commands.executeCommand('vscode.open', vscode.Uri.file(this._currentAnalysis.filePath));
					}
					break;
				case 'exportToJson':
					this.exportToJson();
					break;
			}
		});
	}

	public showAnalysis(analysis: PEAnalysis) {
		this._currentAnalysis = analysis;
		if (this._view) {
			// Convert BigInt to string for JSON serialization
			const serializable = JSON.parse(JSON.stringify(analysis, (key, value) =>
				typeof value === 'bigint' ? value.toString() : value
			));
			this._view.webview.postMessage({ type: 'analysis', data: serializable });
			this._view.show(true);
		}
	}

	private async exportToJson() {
		if (!this._currentAnalysis) return;

		const json = JSON.stringify(this._currentAnalysis, (key, value) =>
			typeof value === 'bigint' ? value.toString() : value
			, 2);

		const uri = await vscode.window.showSaveDialog({
			defaultUri: vscode.Uri.file(this._currentAnalysis.fileName + '.analysis.json'),
			filters: { 'JSON': ['json'] }
		});

		if (uri) {
			await vscode.workspace.fs.writeFile(uri, Buffer.from(json, 'utf8'));
			vscode.window.showInformationMessage('Analysis exported to ' + uri.fsPath);
		}
	}

	private _getHtmlForWebview(_webview: vscode.Webview): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>PE Analyzer</title>
	<style>
		:root {
			--font-mono: 'Consolas', 'Courier New', monospace;
		}

		* { margin: 0; padding: 0; box-sizing: border-box; }

		body {
			font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, sans-serif);
			background-color: var(--vscode-sideBar-background);
			color: var(--vscode-foreground);
			font-size: 12px;
			padding: 8px;
			overflow-x: hidden;
		}

		.welcome {
			text-align: center;
			padding: 40px 20px;
			color: var(--vscode-descriptionForeground);
		}

		.welcome h2 {
			margin-bottom: 12px;
			color: var(--vscode-foreground);
		}

		.welcome p {
			margin-bottom: 8px;
		}

		.welcome .icon {
			font-size: 48px;
			margin-bottom: 16px;
		}

		/* Analysis Container */
		.analysis {
			display: none;
		}

		.analysis.visible {
			display: block;
		}

		/* Header */
		.header {
			background: var(--vscode-editor-background);
			border: 1px solid var(--vscode-panel-border);
			border-radius: 4px;
			padding: 12px;
			margin-bottom: 12px;
		}

		.filename {
			font-size: 14px;
			font-weight: bold;
			color: var(--vscode-textLink-foreground);
			word-break: break-all;
			margin-bottom: 4px;
		}

		.file-info {
			color: var(--vscode-descriptionForeground);
			font-size: 11px;
		}

		/* Badges */
		.badges {
			display: flex;
			flex-wrap: wrap;
			gap: 4px;
			margin-top: 8px;
		}

		.badge {
			padding: 2px 8px;
			border-radius: 10px;
			font-size: 10px;
			font-weight: bold;
		}

		.badge.pe32 { background: #3b82f6; color: white; }
		.badge.pe64 { background: #8b5cf6; color: white; }
		.badge.dll { background: #f59e0b; color: black; }
		.badge.exe { background: #10b981; color: white; }
		.badge.gui { background: #06b6d4; color: white; }
		.badge.console { background: #6b7280; color: white; }
		.badge.packer { background: #ef4444; color: white; }
		.badge.high-entropy { background: #dc2626; color: white; }
		.badge.aslr { background: #22c55e; color: white; }
		.badge.dep { background: #22c55e; color: white; }

		/* Sections */
		.section {
			margin-bottom: 12px;
		}

		.section-header {
			display: flex;
			align-items: center;
			justify-content: space-between;
			background: var(--vscode-editor-background);
			border: 1px solid var(--vscode-panel-border);
			border-radius: 4px 4px 0 0;
			padding: 8px 12px;
			cursor: pointer;
			user-select: none;
		}

		.section-header:hover {
			background: var(--vscode-list-hoverBackground);
		}

		.section-title {
			font-weight: bold;
			font-size: 11px;
			text-transform: uppercase;
			color: var(--vscode-sideBarTitle-foreground);
		}

		.section-toggle {
			font-size: 10px;
			color: var(--vscode-descriptionForeground);
		}

		.section-content {
			background: var(--vscode-editor-background);
			border: 1px solid var(--vscode-panel-border);
			border-top: none;
			border-radius: 0 0 4px 4px;
			padding: 8px 12px;
			display: none;
		}

		.section-content.open {
			display: block;
		}

		/* Data Grid */
		.data-grid {
			display: grid;
			grid-template-columns: 120px 1fr;
			gap: 4px 8px;
		}

		.data-label {
			color: var(--vscode-descriptionForeground);
			font-size: 11px;
		}

		.data-value {
			font-family: var(--font-mono);
			font-size: 11px;
			word-break: break-all;
			color: var(--vscode-editor-foreground);
		}

		.data-value.highlight {
			color: var(--vscode-textLink-foreground);
		}

		.data-value.warning {
			color: #f59e0b;
		}

		.data-value.danger {
			color: #ef4444;
		}

		/* Table */
		.table {
			width: 100%;
			border-collapse: collapse;
			font-size: 11px;
		}

		.table th, .table td {
			padding: 4px 8px;
			text-align: left;
			border-bottom: 1px solid var(--vscode-panel-border);
		}

		.table th {
			background: var(--vscode-sideBar-background);
			font-weight: bold;
			color: var(--vscode-sideBarTitle-foreground);
		}

		.table td {
			font-family: var(--font-mono);
		}

		.table tr:hover td {
			background: var(--vscode-list-hoverBackground);
		}

		/* Entropy bar */
		.entropy-bar {
			display: flex;
			align-items: center;
			gap: 8px;
		}

		.entropy-bar-track {
			flex: 1;
			height: 8px;
			background: var(--vscode-input-background);
			border-radius: 4px;
			overflow: hidden;
		}

		.entropy-bar-fill {
			height: 100%;
			border-radius: 4px;
			transition: width 0.3s;
		}

		.entropy-bar-fill.low { background: #22c55e; }
		.entropy-bar-fill.medium { background: #f59e0b; }
		.entropy-bar-fill.high { background: #ef4444; }

		/* Tags */
		.tags {
			display: flex;
			flex-wrap: wrap;
			gap: 4px;
		}

		.tag {
			padding: 2px 6px;
			background: var(--vscode-badge-background);
			color: var(--vscode-badge-foreground);
			border-radius: 3px;
			font-size: 10px;
		}

		/* String list */
		.string-list {
			max-height: 200px;
			overflow-y: auto;
		}

		.string-item {
			padding: 4px 8px;
			font-family: var(--font-mono);
			font-size: 10px;
			border-bottom: 1px solid var(--vscode-panel-border);
			word-break: break-all;
		}

		.string-item:hover {
			background: var(--vscode-list-hoverBackground);
			cursor: pointer;
		}

		/* Import/Export list */
		.import-list {
			max-height: 300px;
			overflow-y: auto;
		}

		.import-dll {
			padding: 6px 8px;
			background: var(--vscode-sideBar-background);
			font-weight: bold;
			border-bottom: 1px solid var(--vscode-panel-border);
			color: var(--vscode-textLink-foreground);
		}

		/* Error */
		.error {
			background: #7f1d1d;
			color: #fecaca;
			padding: 12px;
			border-radius: 4px;
			margin-bottom: 12px;
		}
	</style>
</head>
<body>
	<div class="welcome" id="welcome">
		<div class="icon" style="font-size: 24px; font-weight: bold;">PE</div>
		<h2>PE Analyzer</h2>
		<p>Right-click an EXE or DLL file</p>
		<p>and select <strong>"HexCore: Analyze PE File"</strong></p>
	</div>

	<div class="analysis" id="analysis">
		<!-- Header -->
		<div class="header">
			<div class="filename" id="filename">-</div>
			<div class="file-info" id="fileInfo">-</div>
			<div class="badges" id="badges"></div>
		<div style="margin-top: 8px; display: flex; gap: 4px;">
				<button class="badge" style="cursor: pointer; border: none;" onclick="exportToJson()">Export JSON</button>
				<button class="badge" style="cursor: pointer; border: none; background: var(--vscode-button-secondaryBackground); color: var(--vscode-button-secondaryForeground);" onclick="vscode.postMessage({type:'openFile'})">Open in Hex</button>
			</div>
		</div>

		<!-- Error -->
		<div class="error" id="error" style="display: none;"></div>

		<!-- DOS Header -->
		<div class="section" id="sectionDOS">
			<div class="section-header" onclick="toggleSection('DOS')">
				<span class="section-title">DOS Header</span>
				<span class="section-toggle" id="toggleDOS">▼</span>
			</div>
			<div class="section-content open" id="contentDOS">
				<div class="data-grid" id="dosHeaderGrid"></div>
			</div>
		</div>

		<!-- PE Header -->
		<div class="section" id="sectionPE">
			<div class="section-header" onclick="toggleSection('PE')">
				<span class="section-title">PE Header (COFF)</span>
				<span class="section-toggle" id="togglePE">▼</span>
			</div>
			<div class="section-content open" id="contentPE">
				<div class="data-grid" id="peHeaderGrid"></div>
			</div>
		</div>

		<!-- Optional Header -->
		<div class="section" id="sectionOptional">
			<div class="section-header" onclick="toggleSection('Optional')">
				<span class="section-title">Optional Header</span>
				<span class="section-toggle" id="toggleOptional">▼</span>
			</div>
			<div class="section-content open" id="contentOptional">
				<div class="data-grid" id="optionalHeaderGrid"></div>
			</div>
		</div>

		<!-- Sections -->
		<div class="section" id="sectionSections">
			<div class="section-header" onclick="toggleSection('Sections')">
				<span class="section-title">Sections</span>
				<span class="section-toggle" id="toggleSections">▼</span>
			</div>
			<div class="section-content" id="contentSections">
				<table class="table" id="sectionsTable">
					<thead>
						<tr>
							<th>Name</th>
							<th>VSize</th>
							<th>RawSize</th>
							<th>Entropy</th>
							<th>Flags</th>
						</tr>
					</thead>
					<tbody id="sectionsBody"></tbody>
				</table>
			</div>
		</div>

		<!-- Imports -->
		<div class="section" id="sectionImports">
			<div class="section-header" onclick="toggleSection('Imports')">
				<span class="section-title">Imports</span>
				<span class="section-toggle" id="toggleImports">▼</span>
			</div>
			<div class="section-content" id="contentImports">
				<div class="import-list" id="importsList"></div>
			</div>
		</div>

		<!-- Entropy -->
		<div class="section" id="sectionEntropy">
			<div class="section-header" onclick="toggleSection('Entropy')">
				<span class="section-title">Entropy Analysis</span>
				<span class="section-toggle" id="toggleEntropy">▼</span>
			</div>
			<div class="section-content" id="contentEntropy">
				<div class="data-grid">
					<div class="data-label">Overall Entropy:</div>
					<div class="entropy-bar">
						<div class="entropy-bar-track">
							<div class="entropy-bar-fill" id="entropyBar"></div>
						</div>
						<span id="entropyValue">0.00</span>
					</div>
				</div>
				<p style="margin-top: 8px; font-size: 10px; color: var(--vscode-descriptionForeground);">
					<strong>0-5:</strong> Low (likely uncompressed) |
					<strong>5-7:</strong> Medium (possibly packed) |
					<strong>7-8:</strong> High (encrypted/compressed)
				</p>
			</div>
		</div>

		<!-- Packer Detection -->
		<div class="section" id="sectionPackers">
			<div class="section-header" onclick="toggleSection('Packers')">
				<span class="section-title">Packer Detection</span>
				<span class="section-toggle" id="togglePackers">▼</span>
			</div>
			<div class="section-content" id="contentPackers">
				<div class="tags" id="packerTags"></div>
			</div>
		</div>

		<!-- Suspicious Strings -->
		<div class="section" id="sectionStrings">
			<div class="section-header" onclick="toggleSection('Strings')">
				<span class="section-title">Suspicious Strings</span>
				<span class="section-toggle" id="toggleStrings">▼</span>
			</div>
			<div class="section-content" id="contentStrings">
				<div class="string-list" id="stringsList"></div>
			</div>
		</div>
	</div>

	<script>
		const vscode = acquireVsCodeApi();

		function toggleSection(name) {
			const content = document.getElementById('content' + name);
			const toggle = document.getElementById('toggle' + name);
			if (content.classList.contains('open')) {
				content.classList.remove('open');
				toggle.textContent = '▶';
			} else {
				content.classList.add('open');
				toggle.textContent = '▼';
			}
		}

		function formatSize(bytes) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const sizes = ['B', 'KB', 'MB', 'GB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
		}

		function formatHex(value, pad = 8) {
			return '0x' + value.toString(16).toUpperCase().padStart(pad, '0');
		}

		function createDataRow(label, value, cls = '') {
			return '<div class="data-label">' + label + ':</div>' +
				   '<div class="data-value ' + cls + '">' + value + '</div>';
		}

		function renderAnalysis(data) {
			document.getElementById('welcome').style.display = 'none';
			document.getElementById('analysis').classList.add('visible');

			// Header
			document.getElementById('filename').textContent = data.fileName;
			document.getElementById('fileInfo').textContent = formatSize(data.fileSize) + ' | ' + data.filePath;

			// Badges
			const badges = [];
			if (data.optionalHeader) {
				badges.push('<span class="badge ' + (data.optionalHeader.is64Bit ? 'pe64' : 'pe32') + '">' +
					(data.optionalHeader.is64Bit ? 'PE32+' : 'PE32') + '</span>');

				if (data.peHeader?.characteristics?.includes('DLL')) {
					badges.push('<span class="badge dll">DLL</span>');
				} else {
					badges.push('<span class="badge exe">EXE</span>');
				}

				if (data.optionalHeader.subsystem.includes('GUI')) {
					badges.push('<span class="badge gui">GUI</span>');
				} else if (data.optionalHeader.subsystem.includes('Console')) {
					badges.push('<span class="badge console">Console</span>');
				}

				if (data.optionalHeader.dllCharacteristics.some(c => c.includes('ASLR'))) {
					badges.push('<span class="badge aslr">ASLR</span>');
				}
				if (data.optionalHeader.dllCharacteristics.some(c => c.includes('DEP'))) {
					badges.push('<span class="badge dep">DEP</span>');
				}
			}

			if (data.packerSignatures.length > 0) {
				for (const p of data.packerSignatures) {
					badges.push('<span class="badge packer">' + p + '</span>');
				}
			}

			if (data.entropy > 7) {
				badges.push('<span class="badge high-entropy">High Entropy</span>');
			}

			document.getElementById('badges').innerHTML = badges.join('');

			// Error
			if (data.error) {
				document.getElementById('error').style.display = 'block';
				document.getElementById('error').textContent = 'Error: ' + data.error;
			} else {
				document.getElementById('error').style.display = 'none';
			}

			// DOS Header
			if (data.dosHeader) {
				document.getElementById('dosHeaderGrid').innerHTML =
					createDataRow('Magic', data.dosHeader.magic) +
					createDataRow('PE Offset', formatHex(data.dosHeader.peHeaderOffset));
			}

			// PE Header
			if (data.peHeader) {
				document.getElementById('peHeaderGrid').innerHTML =
					createDataRow('Machine', data.peHeader.machine) +
					createDataRow('Sections', data.peHeader.numberOfSections) +
					createDataRow('Timestamp', data.peHeader.timeDateStampHuman, 'highlight') +
					createDataRow('Characteristics', data.peHeader.characteristics.join(', '));
			}

			// Optional Header
			if (data.optionalHeader) {
				const oh = data.optionalHeader;
				document.getElementById('optionalHeaderGrid').innerHTML =
					createDataRow('Magic', oh.magic) +
					createDataRow('Entry Point', formatHex(oh.addressOfEntryPoint), 'highlight') +
					createDataRow('Image Base', formatHex(Number(oh.imageBase))) +
					createDataRow('Subsystem', oh.subsystem) +
					createDataRow('Size of Image', formatSize(oh.sizeOfImage)) +
					createDataRow('Size of Headers', formatSize(oh.sizeOfHeaders)) +
					createDataRow('Checksum', formatHex(oh.checksum)) +
					createDataRow('DLL Chars', oh.dllCharacteristics.join(', '));
			}

			// Sections
			const tbody = document.getElementById('sectionsBody');
			tbody.innerHTML = '';
			for (const sec of data.sections) {
				const entropyClass = sec.entropy > 7 ? 'danger' : (sec.entropy > 5 ? 'warning' : '');
				const flags = sec.characteristics.filter(c => ['CODE', 'EXECUTE', 'READ', 'WRITE'].includes(c)).join(', ');
				tbody.innerHTML += '<tr>' +
					'<td>' + sec.name + '</td>' +
					'<td>' + formatHex(sec.virtualSize, 6) + '</td>' +
					'<td>' + formatHex(sec.sizeOfRawData, 6) + '</td>' +
					'<td class="' + entropyClass + '">' + sec.entropy.toFixed(2) + '</td>' +
					'<td>' + flags + '</td>' +
					'</tr>';
			}

			// Imports
			const importsList = document.getElementById('importsList');
			if (data.imports.length > 0) {
				let importsHtml = '';
				for (const imp of data.imports) {
					importsHtml += '<div class="import-dll" onclick="toggleDllFuncs(this)">' + imp.dllName +
						' <span style="color: var(--vscode-descriptionForeground); font-weight: normal;">(' + imp.functions.length + ')</span></div>';
					if (imp.functions.length > 0) {
						importsHtml += '<div class="dll-funcs" style="display:none; max-height: 150px; overflow-y: auto; font-size: 10px; padding-left: 12px; background: var(--vscode-editor-background);">';
						for (const fn of imp.functions.slice(0, 50)) {
							importsHtml += '<div style="padding: 2px 4px; border-bottom: 1px solid var(--vscode-panel-border);">' + escapeHtml(fn) + '</div>';
						}
						if (imp.functions.length > 50) {
							importsHtml += '<div style="padding: 4px; color: var(--vscode-descriptionForeground);">...and ' + (imp.functions.length - 50) + ' more</div>';
						}
						importsHtml += '</div>';
					}
				}
				importsList.innerHTML = importsHtml;
			} else {
				importsList.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No imports found or unable to parse</div>';
			}

			// Entropy
			const entropyPct = (data.entropy / 8) * 100;
			const entropyBar = document.getElementById('entropyBar');
			entropyBar.style.width = entropyPct + '%';
			entropyBar.className = 'entropy-bar-fill ' + (data.entropy > 7 ? 'high' : (data.entropy > 5 ? 'medium' : 'low'));
			document.getElementById('entropyValue').textContent = data.entropy.toFixed(2) + ' / 8.00';

			// Packers
			const packerTags = document.getElementById('packerTags');
			if (data.packerSignatures.length > 0) {
				packerTags.innerHTML = data.packerSignatures.map(p =>
					'<span class="tag" style="background: #ef4444; color: white;">' + p + '</span>'
				).join('');
			} else {
				packerTags.innerHTML = '<span style="color: var(--vscode-descriptionForeground);">No known packers detected</span>';
			}

			// Rich Header
			const richContent = document.getElementById('richHeaderContent');
			if (data.richHeader && data.richHeader.valid) {
				let richHtml = '<div class="data-grid">';
				richHtml += '<div class="data-label">XOR Key:</div><div class="data-value">0x' + data.richHeader.xorKey.toString(16).toUpperCase() + '</div>';
				richHtml += '</div><div style="margin-top: 8px; font-size: 11px;">';
				richHtml += '<strong>CompID Entries:</strong></div><div style="max-height: 150px; overflow-y: auto;">';
				richHtml += '<table class="table"><thead><tr><th>Product</th><th>Build</th><th>Count</th></tr></thead><tbody>';
				for (const entry of data.richHeader.entries) {
					richHtml += '<tr><td>' + (entry.productName || 'Unknown') + '</td><td>' + (entry.compId >> 16) + '</td><td>' + entry.count + '</td></tr>';
				}
				richHtml += '</tbody></table></div>';
				richContent.innerHTML = richHtml;
			} else {
				richContent.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No Rich Header found</div>';
			}

			// Resources
			const resourcesContent = document.getElementById('resourcesContent');
			if (data.resources && data.resources.length > 0) {
				resourcesContent.innerHTML = '<table class="table"><thead><tr><th>Type</th><th>Name</th><th>Size</th></tr></thead><tbody>' +
					data.resources.map(r => '<tr><td>' + r.type + '</td><td>' + r.name + '</td><td>' + formatSize(r.size) + '</td></tr>').join('') +
					'</tbody></table>';
			} else {
				resourcesContent.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No resources found</div>';
			}

			// TLS Callbacks
			const tlsContent = document.getElementById('tlsContent');
			if (data.tlsCallbacks && data.tlsCallbacks.length > 0) {
				tlsContent.innerHTML = '<div style="color: var(--vscode-errorForeground); font-weight: bold; margin-bottom: 8px;">⚠️ TLS Callbacks Detected!</div>' +
					'<div style="font-size: 11px; color: var(--vscode-descriptionForeground); margin-bottom: 8px;">' +
					'TLS callbacks execute before the entry point and can be used to hide malicious code.</div>' +
					'<div class="tags">' + data.tlsCallbacks.map(addr => 
						'<span class="tag" style="background: var(--vscode-errorForeground); color: white;">0x' + addr.toString(16).toUpperCase() + '</span>'
					).join('') + '</div>';
			} else {
				tlsContent.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No TLS callbacks found</div>';
			}

			// Anti-Debug
			const antiDebugContent = document.getElementById('antiDebugContent');
			if (data.antiDebug && data.antiDebug.length > 0) {
				antiDebugContent.innerHTML = '<table class="table"><thead><tr><th>Technique</th><th>Severity</th></tr></thead><tbody>' +
					data.antiDebug.map(a => '<tr><td>' + a.name + '<br><span style="font-size: 9px; color: var(--vscode-descriptionForeground);">' + a.description + '</span></td><td class="' + a.severity + '">' + a.severity.toUpperCase() + '</td></tr>').join('') +
					'</tbody></table>';
			} else {
				antiDebugContent.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No anti-debug techniques detected</div>';
			}

			// Mitigations
			const mitigationsContent = document.getElementById('mitigationsContent');
			if (data.mitigations && data.mitigations.length > 0) {
				mitigationsContent.innerHTML = '<div class="data-grid">' +
					data.mitigations.map(m => '<div class="data-label">' + m.name + '</div><div class="data-value ' + (m.enabled ? 'highlight' : '') + '">' + (m.enabled ? '✅ Enabled' : '❌ Disabled') + '</div>').join('') +
					'</div>';
			} else {
				mitigationsContent.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">Unable to determine mitigations</div>';
			}

			// Suspicious Strings
			const stringsList = document.getElementById('stringsList');
			if (data.suspiciousStrings.length > 0) {
				stringsList.innerHTML = data.suspiciousStrings.map(s =>
					'<div class="string-item" onclick="copyString(this)">' + escapeHtml(s) + '</div>'
				).join('');
			} else {
				stringsList.innerHTML = '<div style="padding: 8px; color: var(--vscode-descriptionForeground);">No suspicious strings found</div>';
			}
		}

		function escapeHtml(text) {
			const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
			return text.replace(/[&<>"']/g, m => map[m]);
		}

		function copyString(el) {
			vscode.postMessage({ type: 'copyToClipboard', text: el.textContent });
		}

		function toggleDllFuncs(el) {
			const funcs = el.nextElementSibling;
			if (funcs && funcs.classList.contains('dll-funcs')) {
				funcs.style.display = funcs.style.display === 'none' ? 'block' : 'none';
			}
		}

		function exportToJson() {
			vscode.postMessage({ type: 'exportToJson' });
		}

		// Listen for messages from extension
		window.addEventListener('message', event => {
			const message = event.data;
			if (message.type === 'analysis') {
				renderAnalysis(message.data);
			}
		});
	</script>
</body>
</html>`;
	}
}
