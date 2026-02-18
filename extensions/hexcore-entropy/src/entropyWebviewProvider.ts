/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer — Interactive Webview
 *  SVG-based entropy chart with clickable blocks and Hex Viewer navigation
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { EntropyAnalysisResult, EntropyBlock } from './types';
import { generateEntropyReport, SectionInfo } from './reportGenerator';

// ============================================================================
// Exported Interfaces
// ============================================================================

export interface EntropyBlockData {
	offset: number;
	size: number;
	entropy: number;
	sectionName?: string;
}

export interface EntropyWebviewData {
	blocks: EntropyBlockData[];
	fileSize: number;
	fileName: string;
	overallEntropy: number;
	highEntropyThreshold: number;
}

/**
 * Maps an entropy value to the standard HexCore color palette.
 * - green  #4ec9b0  for values < 5.0
 * - yellow #dcdcaa  for values >= 5.0 and <= 7.0
 * - red    #f44747  for values > 7.0
 */
export function entropyBlockColor(entropy: number): string {
	if (entropy < 5.0) {
		return '#4ec9b0';
	}
	if (entropy <= 7.0) {
		return '#dcdcaa';
	}
	return '#f44747';
}

/**
 * Builds the tooltip text for an entropy block.
 * Includes offset, size, entropy, and optionally the section name.
 */
export function buildBlockTooltip(block: EntropyBlockData): string {
	const offsetHex = `0x${block.offset.toString(16).toUpperCase().padStart(8, '0')}`;
	let tip = `Offset: ${offsetHex}\nSize: ${block.size} bytes\nEntropy: ${block.entropy.toFixed(4)}`;
	if (block.sectionName) {
		tip += `\nSection: ${block.sectionName}`;
	}
	return tip;
}


// ============================================================================
// View Provider
// ============================================================================

export class EntropyWebviewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'hexcore.entropy.view';
	private _view?: vscode.WebviewView;
	private _currentResult?: EntropyAnalysisResult;
	private _sections?: SectionInfo[];

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

		// Re-send cached analysis when the webview is recreated (sidebar reopened)
		if (this._currentResult) {
			const data = this._buildWebviewData(this._currentResult, this._sections);
			// Small delay to let the webview initialize its message listener
			setTimeout(() => {
				webviewView.webview.postMessage({ command: 'showAnalysis', data });
			}, 100);
		}

		webviewView.webview.onDidReceiveMessage(async message => {
			switch (message.command) {
				case 'goToOffset':
					if (typeof message.offset === 'number') {
						await vscode.commands.executeCommand('hexcore.hexview.goToOffset', message.offset);
					}
					break;
				case 'exportMarkdown':
					await this._exportMarkdown();
					break;
				case 'openFile': {
					const files = await vscode.window.showOpenDialog({
						canSelectMany: false,
						canSelectFiles: true,
						title: 'Select file for entropy analysis'
					});
					if (files?.[0]) {
						await vscode.commands.executeCommand('hexcore.entropy.analyze', files[0]);
					}
					break;
				}
			}
		});
	}

	/**
	 * Sends analysis data to the webview for rendering.
	 */
	showAnalysis(result: EntropyAnalysisResult, sections?: SectionInfo[]): void {
		this._currentResult = result;
		this._sections = sections;
		if (this._view) {
			const data = this._buildWebviewData(result, sections);
			this._view.webview.postMessage({
				command: 'showAnalysis',
				data
			});
			this._view.show?.(true);
		}
	}

	private _buildWebviewData(result: EntropyAnalysisResult, sections?: SectionInfo[]): EntropyWebviewData {
		const blocks: EntropyBlockData[] = result.blocks.map(b => {
			let sectionName: string | undefined;
			if (sections && sections.length > 0) {
				for (const sec of sections) {
					if (b.offset >= sec.offset && b.offset < sec.offset + sec.size) {
						sectionName = sec.name;
						break;
					}
				}
			}
			return {
				offset: b.offset,
				size: b.size,
				entropy: b.entropy,
				sectionName
			};
		});

		return {
			blocks,
			fileSize: result.fileSize,
			fileName: result.fileName,
			overallEntropy: result.summary.averageEntropy,
			highEntropyThreshold: 7.0
		};
	}

	private async _exportMarkdown(): Promise<void> {
		if (!this._currentResult) {
			vscode.window.showWarningMessage('No entropy analysis available to export.');
			return;
		}
		const markdown = generateEntropyReport(this._currentResult, this._sections);
		const doc = await vscode.workspace.openTextDocument({
			content: markdown,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });
	}


	private _getHtmlContent(): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
:root {
	--hexcore-safe: #4ec9b0;
	--hexcore-warning: #dcdcaa;
	--hexcore-danger: #f44747;
	--hexcore-mono: Consolas, Monaco, 'Courier New', monospace;
}
body {
	margin: 0;
	padding: 0;
	color: var(--vscode-foreground);
	background: var(--vscode-editor-background);
	font-family: var(--vscode-font-family, sans-serif);
	font-size: var(--vscode-font-size, 13px);
}
.hexcore-toolbar {
	background: var(--vscode-editor-background);
	border-bottom: 1px solid var(--vscode-panel-border);
	padding: 4px 8px;
	display: flex;
	gap: 4px;
	align-items: center;
}
.hexcore-toolbar-left {
	display: flex;
	gap: 4px;
	align-items: center;
}
.hexcore-toolbar-right {
	margin-left: auto;
	display: flex;
	gap: 8px;
	align-items: center;
	color: var(--vscode-descriptionForeground);
	font-size: 11px;
}
.hexcore-btn {
	background: transparent;
	border: 1px solid transparent;
	color: var(--vscode-foreground);
	padding: 4px 8px;
	cursor: pointer;
	font-size: 11px;
	border-radius: 3px;
	display: flex;
	align-items: center;
	gap: 4px;
}
.hexcore-btn:hover {
	background: var(--vscode-toolbar-hoverBackground);
}
.hexcore-badge {
	padding: 2px 6px;
	border-radius: 3px;
	font-size: 10px;
	font-weight: 600;
}
.hexcore-badge-safe { background: #4ec9b022; color: #4ec9b0; }
.hexcore-badge-warning { background: #dcdcaa22; color: #dcdcaa; }
.hexcore-badge-danger { background: #f4474722; color: #f44747; }

#welcome {
	display: flex;
	flex-direction: column;
	align-items: center;
	justify-content: center;
	height: 80vh;
	color: var(--vscode-descriptionForeground);
	text-align: center;
	padding: 16px;
}
#welcome h2 { margin-bottom: 8px; }
#welcome p { margin: 4px 0; font-size: 12px; }

#chart-container {
	display: none;
	padding: 8px;
	overflow-x: auto;
}
#chart-container svg { display: block; }

.entropy-bar { cursor: pointer; }
.entropy-bar:hover { opacity: 0.8; stroke: var(--vscode-focusBorder); stroke-width: 1; }

#tooltip {
	display: none;
	position: fixed;
	background: var(--vscode-editorHoverWidget-background, #252526);
	border: 1px solid var(--vscode-editorHoverWidget-border, #454545);
	color: var(--vscode-editorHoverWidget-foreground, #cccccc);
	padding: 6px 10px;
	border-radius: 3px;
	font-family: var(--hexcore-mono);
	font-size: 11px;
	white-space: pre;
	pointer-events: none;
	z-index: 100;
}

.legend {
	display: flex;
	gap: 16px;
	padding: 8px;
	font-size: 11px;
	color: var(--vscode-descriptionForeground);
}
.legend-item {
	display: flex;
	align-items: center;
	gap: 4px;
}
.legend-swatch {
	width: 12px;
	height: 12px;
	border-radius: 2px;
}

.stats-bar {
	padding: 4px 8px;
	font-size: 11px;
	font-family: var(--hexcore-mono);
	color: var(--vscode-descriptionForeground);
	border-bottom: 1px solid var(--vscode-panel-border);
	display: none;
}
</style>
</head>
<body>

<div class="hexcore-toolbar">
	<div class="hexcore-toolbar-left">
		<span style="font-weight:600;">Entropy Chart</span>
	</div>
	<div class="hexcore-toolbar-right">
		<button class="hexcore-btn" id="btn-open" title="Analyze a different file">
			Open File
		</button>
		<button class="hexcore-btn" id="btn-export" title="Export as Markdown report">
			Export Markdown
		</button>
		<span id="file-info"></span>
	</div>
</div>

<div class="stats-bar" id="stats-bar"></div>

<div id="welcome">
	<h2>Entropy Analyzer</h2>
	<p>Run <strong>HexCore: Entropy Graph</strong> to visualize entropy distribution.</p>
	<p>Click on bars to navigate in the Hex Viewer.</p>
</div>

<div id="chart-container"></div>

<div class="legend" id="legend" style="display:none;">
	<div class="legend-item"><div class="legend-swatch" style="background:#4ec9b0;"></div> Low (&lt; 5.0)</div>
	<div class="legend-item"><div class="legend-swatch" style="background:#dcdcaa;"></div> Medium (5.0–7.0)</div>
	<div class="legend-item"><div class="legend-swatch" style="background:#f44747;"></div> High (&gt; 7.0)</div>
</div>

<div id="tooltip"></div>

<script>
(function() {
	const vscode = acquireVsCodeApi();
	const chartContainer = document.getElementById('chart-container');
	const welcome = document.getElementById('welcome');
	const tooltip = document.getElementById('tooltip');
	const legend = document.getElementById('legend');
	const statsBar = document.getElementById('stats-bar');
	const fileInfo = document.getElementById('file-info');

	document.getElementById('btn-export').addEventListener('click', () => {
		vscode.postMessage({ command: 'exportMarkdown' });
	});

	document.getElementById('btn-open').addEventListener('click', () => {
		vscode.postMessage({ command: 'openFile' });
	});

	window.addEventListener('message', event => {
		const msg = event.data;
		if (msg.command === 'showAnalysis') {
			renderChart(msg.data);
		}
	});

	function entropyColor(val) {
		if (val < 5.0) return '#4ec9b0';
		if (val <= 7.0) return '#dcdcaa';
		return '#f44747';
	}

	function renderChart(data) {
		welcome.style.display = 'none';
		chartContainer.style.display = 'block';
		legend.style.display = 'flex';
		statsBar.style.display = 'block';

		fileInfo.textContent = data.fileName;
		statsBar.textContent = 'Blocks: ' + data.blocks.length +
			' | Avg: ' + data.overallEntropy.toFixed(4) +
			' | File: ' + formatBytes(data.fileSize);

		const blocks = data.blocks;
		if (blocks.length === 0) {
			chartContainer.innerHTML = '<p style="padding:16px;color:var(--vscode-descriptionForeground);">No blocks to display.</p>';
			return;
		}

		const svgWidth = Math.max(300, Math.min(blocks.length * 4, 2000));
		const svgHeight = 200;
		const barWidth = Math.max(1, svgWidth / blocks.length);
		const maxEntropy = 8.0;

		let svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' + svgWidth + '" height="' + svgHeight + '" viewBox="0 0 ' + svgWidth + ' ' + svgHeight + '">';

		for (let i = 0; i < blocks.length; i++) {
			const b = blocks[i];
			const barHeight = (b.entropy / maxEntropy) * svgHeight;
			const x = i * barWidth;
			const y = svgHeight - barHeight;
			const color = entropyColor(b.entropy);
			const offsetHex = '0x' + b.offset.toString(16).toUpperCase().padStart(8, '0');
			svg += '<rect class="entropy-bar" x="' + x.toFixed(2) + '" y="' + y.toFixed(2) + '" width="' + barWidth.toFixed(2) + '" height="' + barHeight.toFixed(2) + '" fill="' + color + '"'
				+ ' data-offset="' + b.offset + '"'
				+ ' data-size="' + b.size + '"'
				+ ' data-entropy="' + b.entropy.toFixed(4) + '"'
				+ ' data-section="' + (b.sectionName || '') + '"'
				+ ' data-offsethex="' + offsetHex + '"'
				+ '/>';
		}

		svg += '</svg>';
		chartContainer.innerHTML = svg;

		chartContainer.querySelectorAll('.entropy-bar').forEach(bar => {
			bar.addEventListener('click', () => {
				const offset = parseInt(bar.getAttribute('data-offset'), 10);
				vscode.postMessage({ command: 'goToOffset', offset: offset });
			});
			bar.addEventListener('mouseenter', (e) => {
				const offsetHex = bar.getAttribute('data-offsethex');
				const size = bar.getAttribute('data-size');
				const entropy = bar.getAttribute('data-entropy');
				const section = bar.getAttribute('data-section');
				let text = 'Offset: ' + offsetHex + '\\nSize: ' + size + ' bytes\\nEntropy: ' + entropy;
				if (section) {
					text += '\\nSection: ' + section;
				}
				tooltip.textContent = text;
				tooltip.style.display = 'block';
				positionTooltip(e);
			});
			bar.addEventListener('mousemove', positionTooltip);
			bar.addEventListener('mouseleave', () => {
				tooltip.style.display = 'none';
			});
		});
	}

	function positionTooltip(e) {
		tooltip.style.left = (e.clientX + 12) + 'px';
		tooltip.style.top = (e.clientY + 12) + 'px';
	}

	function formatBytes(bytes) {
		if (bytes === 0) return '0 B';
		const k = 1024;
		const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
		const i = Math.floor(Math.log(bytes) / Math.log(k));
		return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
	}
})();
</script>
</body>
</html>`;
	}

}
