/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Graph View Provider
 *  CustomEditorProvider that renders CFG as interactive SVG
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine, Function as DisasmFunction } from './disassemblerEngine';
import { BasicBlockAnalyzer, CFG } from './basicBlockAnalyzer';
import { GraphLayoutEngine, GraphLayout, NodeLayout, EdgeLayout, LAYOUT_CONSTANTS } from './graphLayoutEngine';

export class GraphViewProvider implements vscode.WebviewViewProvider {
	public static readonly viewType = 'hexcore.graphView';

	private _view?: vscode.WebviewView;
	private engine: DisassemblerEngine;
	private blockAnalyzer: BasicBlockAnalyzer;
	private layoutEngine: GraphLayoutEngine;
	private currentCFG?: CFG;
	private currentLayout?: GraphLayout;

	constructor(
		private readonly _extensionUri: vscode.Uri,
		engine: DisassemblerEngine
	) {
		this.engine = engine;
		this.blockAnalyzer = new BasicBlockAnalyzer();
		this.layoutEngine = new GraphLayoutEngine();
	}

	public resolveWebviewView(
		webviewView: vscode.WebviewView,
		_context: vscode.WebviewViewResolveContext,
		_token: vscode.CancellationToken
	): void {
		this._view = webviewView;

		webviewView.webview.options = {
			enableScripts: true,
			localResourceRoots: [this._extensionUri]
		};

		webviewView.webview.html = this._getHtmlForWebview(webviewView.webview);

		// Handle messages from webview
		webviewView.webview.onDidReceiveMessage(async message => {
			switch (message.type) {
				case 'blockClick':
					this.handleBlockClick(message.blockId, message.address);
					break;
				case 'goToAddress':
					vscode.commands.executeCommand('hexcore.disassembler.goToAddress', message.address);
					break;
			}
		});
	}

	/**
	 * Update the graph view with a new function
	 */
	public async showFunction(func: DisasmFunction): Promise<void> {
		if (!this._view) return;

		// Build CFG from function instructions
		this.currentCFG = this.blockAnalyzer.buildCFG(
			func.instructions,
			func.name,
			func.address
		);

		// Calculate layout
		this.currentLayout = this.layoutEngine.calculateLayout(this.currentCFG);

		// Send to webview
		this._view.webview.postMessage({
			type: 'updateGraph',
			cfg: this.serializeCFG(this.currentCFG),
			layout: this.serializeLayout(this.currentLayout)
		});
	}

	/**
	 * Clear the graph view
	 */
	public clear(): void {
		if (!this._view) return;
		this._view.webview.postMessage({ type: 'clear' });
	}

	private handleBlockClick(blockId: number, address: number): void {
		// Navigate in sidebar disassembly
		vscode.commands.executeCommand('hexcore.disassembler.goToAddress', address);
	}

	private serializeCFG(cfg: CFG): any {
		const blocks: any[] = [];
		for (const [id, block] of cfg.blocks) {
			blocks.push({
				id,
				startAddress: block.startAddress,
				endAddress: block.endAddress,
				instructions: block.instructions.map(inst => ({
					address: inst.address,
					mnemonic: inst.mnemonic,
					opStr: inst.opStr,
					bytes: Array.from(inst.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ')
				})),
				type: block.type,
				successors: block.successors,
				predecessors: block.predecessors
			});
		}

		return {
			blocks,
			edges: cfg.edges,
			entryBlockId: cfg.entryBlockId,
			functionName: cfg.functionName,
			functionAddress: cfg.functionAddress
		};
	}

	private serializeLayout(layout: GraphLayout): any {
		const nodes: any[] = [];
		for (const [id, node] of layout.nodes) {
			nodes.push({ ...node });
		}

		return {
			nodes,
			edges: layout.edges,
			width: layout.width,
			height: layout.height
		};
	}

	private _getHtmlForWebview(webview: vscode.Webview): string {
		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>CFG View</title>
	<style>
		* {
			margin: 0;
			padding: 0;
			box-sizing: border-box;
		}

		body {
			background: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
			font-family: var(--vscode-font-family);
			font-size: 12px;
			overflow: hidden;
		}

		.toolbar {
			position: fixed;
			top: 0;
			left: 0;
			right: 0;
			height: 32px;
			background: var(--vscode-titleBar-activeBackground);
			border-bottom: 1px solid var(--vscode-widget-border);
			display: flex;
			align-items: center;
			padding: 0 8px;
			gap: 8px;
			z-index: 100;
		}

		.toolbar-title {
			font-weight: bold;
			color: var(--vscode-titleBar-activeForeground);
			flex: 1;
		}

		.toolbar-btn {
			background: var(--vscode-button-secondaryBackground);
			color: var(--vscode-button-secondaryForeground);
			border: none;
			padding: 4px 8px;
			cursor: pointer;
			border-radius: 2px;
		}

		.toolbar-btn:hover {
			background: var(--vscode-button-secondaryHoverBackground);
		}

		.container {
			position: fixed;
			top: 32px;
			left: 0;
			right: 0;
			bottom: 0;
			overflow: auto;
			cursor: grab;
		}

		.container.dragging {
			cursor: grabbing;
		}

		.graph-canvas {
			min-width: 100%;
			min-height: 100%;
		}

		/* Block styling */
		.block {
			cursor: pointer;
		}

		.block-rect {
			fill: var(--vscode-editor-background);
			stroke: var(--vscode-widget-border);
			stroke-width: 1;
			rx: 4;
		}

		.block.selected .block-rect {
			stroke: var(--vscode-focusBorder);
			stroke-width: 2;
		}

		.block:hover .block-rect {
			fill: var(--vscode-list-hoverBackground);
		}

		.block-header {
			fill: var(--vscode-badge-background);
		}

		.block-header-text {
			fill: var(--vscode-badge-foreground);
			font-size: 11px;
			font-weight: bold;
		}

		.block-entry .block-header {
			fill: var(--vscode-testing-iconPassed);
		}

		.block-exit .block-header {
			fill: var(--vscode-testing-iconFailed);
		}

		.instruction {
			font-family: var(--vscode-editor-font-family), monospace;
			font-size: 11px;
		}

		.inst-address {
			fill: var(--vscode-editorLineNumber-foreground);
		}

		.inst-mnemonic {
			fill: var(--vscode-symbolIcon-functionForeground, #dcdcaa);
		}

		.inst-mnemonic.call {
			fill: var(--vscode-symbolIcon-methodForeground, #569cd6);
		}

		.inst-mnemonic.jump {
			fill: var(--vscode-symbolIcon-eventForeground, #c586c0);
		}

		.inst-mnemonic.ret {
			fill: var(--vscode-symbolIcon-keywordForeground, #f14c4c);
		}

		.inst-operand {
			fill: var(--vscode-editor-foreground);
		}

		/* Edge styling */
		.edge {
			fill: none;
			stroke-width: 1.5;
		}

		.edge.unconditional {
			stroke: var(--vscode-charts-blue);
		}

		.edge.true {
			stroke: var(--vscode-testing-iconPassed);
		}

		.edge.false {
			stroke: var(--vscode-testing-iconFailed);
		}

		.edge.fallthrough {
			stroke: var(--vscode-widget-border);
			stroke-dasharray: 4 2;
		}

		.edge.call {
			stroke: var(--vscode-charts-purple);
			stroke-dasharray: 4 2;
		}

		.edge-arrow {
			fill: var(--vscode-charts-blue);
		}

		.edge.true .edge-arrow {
			fill: var(--vscode-testing-iconPassed);
		}

		.edge.false .edge-arrow {
			fill: var(--vscode-testing-iconFailed);
		}

		.edge-label {
			font-size: 10px;
			fill: var(--vscode-descriptionForeground);
		}

		.empty-state {
			position: absolute;
			top: 50%;
			left: 50%;
			transform: translate(-50%, -50%);
			text-align: center;
			color: var(--vscode-descriptionForeground);
		}

		.empty-state h2 {
			margin-bottom: 8px;
		}

		.zoom-info {
			position: fixed;
			bottom: 8px;
			right: 8px;
			background: var(--vscode-badge-background);
			color: var(--vscode-badge-foreground);
			padding: 2px 6px;
			border-radius: 4px;
			font-size: 11px;
		}
	</style>
</head>
<body>
	<div class="toolbar">
		<span class="toolbar-title" id="title">Control Flow Graph</span>
		<button class="toolbar-btn" id="zoomIn">[+]</button>
		<button class="toolbar-btn" id="zoomOut">[-]</button>
		<button class="toolbar-btn" id="fitView">[Fit]</button>
	</div>

	<div class="container" id="container">
		<svg class="graph-canvas" id="canvas">
			<defs>
				<marker id="arrowhead" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
					<polygon class="edge-arrow" points="0 0, 10 3.5, 0 7" />
				</marker>
				<marker id="arrowhead-green" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
					<polygon fill="var(--vscode-testing-iconPassed)" points="0 0, 10 3.5, 0 7" />
				</marker>
				<marker id="arrowhead-red" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">
					<polygon fill="var(--vscode-testing-iconFailed)" points="0 0, 10 3.5, 0 7" />
				</marker>
			</defs>
			<g id="graphGroup" transform="translate(0,0) scale(1)">
				<g id="edgesGroup"></g>
				<g id="blocksGroup"></g>
			</g>
		</svg>
		<div class="empty-state" id="emptyState">
			<h2>No Graph</h2>
			<p>Select a function to view its control flow graph</p>
		</div>
	</div>

	<div class="zoom-info" id="zoomInfo">100%</div>

	<script>
		const vscode = acquireVsCodeApi();
		const container = document.getElementById('container');
		const canvas = document.getElementById('canvas');
		const graphGroup = document.getElementById('graphGroup');
		const edgesGroup = document.getElementById('edgesGroup');
		const blocksGroup = document.getElementById('blocksGroup');
		const emptyState = document.getElementById('emptyState');
		const titleEl = document.getElementById('title');
		const zoomInfo = document.getElementById('zoomInfo');

		let zoom = 1;
		let panX = 0;
		let panY = 0;
		let isDragging = false;
		let dragStartX = 0;
		let dragStartY = 0;
		let selectedBlockId = null;

		let currentCFG = null;
		let currentLayout = null;

		const INST_HEIGHT = ${LAYOUT_CONSTANTS.INSTRUCTION_HEIGHT};
		const HEADER_HEIGHT = ${LAYOUT_CONSTANTS.HEADER_HEIGHT};

		// Zoom controls
		document.getElementById('zoomIn').addEventListener('click', () => setZoom(zoom * 1.2));
		document.getElementById('zoomOut').addEventListener('click', () => setZoom(zoom / 1.2));
		document.getElementById('fitView').addEventListener('click', fitToView);

		// Mouse wheel zoom
		container.addEventListener('wheel', (e) => {
			e.preventDefault();
			const delta = e.deltaY > 0 ? 0.9 : 1.1;
			setZoom(zoom * delta);
		});

		// Pan controls
		container.addEventListener('mousedown', (e) => {
			if (e.target === canvas || e.target === container) {
				isDragging = true;
				dragStartX = e.clientX - panX;
				dragStartY = e.clientY - panY;
				container.classList.add('dragging');
			}
		});

		document.addEventListener('mousemove', (e) => {
			if (isDragging) {
				panX = e.clientX - dragStartX;
				panY = e.clientY - dragStartY;
				updateTransform();
			}
		});

		document.addEventListener('mouseup', () => {
			isDragging = false;
			container.classList.remove('dragging');
		});

		function setZoom(newZoom) {
			zoom = Math.max(0.1, Math.min(3, newZoom));
			zoomInfo.textContent = Math.round(zoom * 100) + '%';
			updateTransform();
		}

		function updateTransform() {
			graphGroup.setAttribute('transform', 'translate(' + panX + ',' + panY + ') scale(' + zoom + ')');
		}

		function fitToView() {
			if (!currentLayout) return;
			const containerRect = container.getBoundingClientRect();
			const scaleX = (containerRect.width - 40) / currentLayout.width;
			const scaleY = (containerRect.height - 40) / currentLayout.height;
			zoom = Math.min(scaleX, scaleY, 1);
			panX = (containerRect.width - currentLayout.width * zoom) / 2;
			panY = 20;
			zoomInfo.textContent = Math.round(zoom * 100) + '%';
			updateTransform();
		}

		function selectBlock(blockId) {
			// Deselect previous
			if (selectedBlockId !== null) {
				const prev = document.getElementById('block-' + selectedBlockId);
				if (prev) prev.classList.remove('selected');
			}
			// Select new
			selectedBlockId = blockId;
			const block = document.getElementById('block-' + blockId);
			if (block) block.classList.add('selected');
		}

		// Handle messages from extension
		window.addEventListener('message', event => {
			const message = event.data;
			switch (message.type) {
				case 'updateGraph':
					currentCFG = message.cfg;
					currentLayout = message.layout;
					renderGraph();
					break;
				case 'clear':
					clearGraph();
					break;
			}
		});

		function clearGraph() {
			edgesGroup.innerHTML = '';
			blocksGroup.innerHTML = '';
			emptyState.style.display = 'block';
			titleEl.textContent = 'Control Flow Graph';
			currentCFG = null;
			currentLayout = null;
		}

		function renderGraph() {
			if (!currentCFG || !currentLayout) {
				emptyState.style.display = 'block';
				return;
			}

			emptyState.style.display = 'none';
			titleEl.textContent = currentCFG.functionName + ' @ 0x' + currentCFG.functionAddress.toString(16);

			// Update canvas size
			canvas.setAttribute('width', currentLayout.width + 100);
			canvas.setAttribute('height', currentLayout.height + 100);

			// Clear previous
			edgesGroup.innerHTML = '';
			blocksGroup.innerHTML = '';

			// Render edges first (so they're behind blocks)
			for (const edge of currentLayout.edges) {
				renderEdge(edge);
			}

			// Render blocks
			const blockMap = new Map();
			for (const block of currentCFG.blocks) {
				blockMap.set(block.id, block);
			}

			for (const node of currentLayout.nodes) {
				const block = blockMap.get(node.id);
				if (block) {
					renderBlock(block, node);
				}
			}

			// Fit to view
			fitToView();
		}

		function renderEdge(edge) {
			const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
			g.classList.add('edge', edge.type);

			// Create path
			const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
			let d = 'M ' + edge.points[0].x + ' ' + edge.points[0].y;

			if (edge.points.length === 4) {
				// Bezier curve
				d += ' C ' + edge.points[1].x + ' ' + edge.points[1].y;
				d += ', ' + edge.points[2].x + ' ' + edge.points[2].y;
				d += ', ' + edge.points[3].x + ' ' + edge.points[3].y;
			} else {
				// Polyline
				for (let i = 1; i < edge.points.length; i++) {
					d += ' L ' + edge.points[i].x + ' ' + edge.points[i].y;
				}
			}

			path.setAttribute('d', d);

			// Set arrowhead based on edge type
			let marker = 'url(#arrowhead)';
			if (edge.type === 'true') marker = 'url(#arrowhead-green)';
			else if (edge.type === 'false') marker = 'url(#arrowhead-red)';
			path.setAttribute('marker-end', marker);

			g.appendChild(path);

			// Add label if present
			if (edge.label) {
				const midPoint = edge.points[Math.floor(edge.points.length / 2)];
				const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
				text.classList.add('edge-label');
				text.setAttribute('x', midPoint.x + 5);
				text.setAttribute('y', midPoint.y - 5);
				text.textContent = edge.label;
				g.appendChild(text);
			}

			edgesGroup.appendChild(g);
		}

		function renderBlock(block, node) {
			const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
			g.classList.add('block');
			g.classList.add('block-' + block.type);
			g.id = 'block-' + block.id;
			g.setAttribute('transform', 'translate(' + node.x + ',' + node.y + ')');

			// Block rectangle
			const rect = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
			rect.classList.add('block-rect');
			rect.setAttribute('width', node.width);
			rect.setAttribute('height', node.height);
			g.appendChild(rect);

			// Header background
			const header = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
			header.classList.add('block-header');
			header.setAttribute('width', node.width);
			header.setAttribute('height', HEADER_HEIGHT);
			header.setAttribute('rx', 4);
			g.appendChild(header);

			// Header text (address)
			const headerText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
			headerText.classList.add('block-header-text');
			headerText.setAttribute('x', 8);
			headerText.setAttribute('y', 18);
			headerText.textContent = '0x' + block.startAddress.toString(16).toUpperCase();
			g.appendChild(headerText);

			// Instructions
			let y = HEADER_HEIGHT + 14;
			for (const inst of block.instructions) {
				const instG = document.createElementNS('http://www.w3.org/2000/svg', 'g');
				instG.classList.add('instruction');
				instG.setAttribute('transform', 'translate(8,' + y + ')');

				// Mnemonic
				const mnemonic = document.createElementNS('http://www.w3.org/2000/svg', 'text');
				mnemonic.classList.add('inst-mnemonic');
				if (inst.mnemonic.startsWith('call')) mnemonic.classList.add('call');
				else if (inst.mnemonic.startsWith('j')) mnemonic.classList.add('jump');
				else if (inst.mnemonic === 'ret' || inst.mnemonic === 'retn') mnemonic.classList.add('ret');
				mnemonic.setAttribute('x', 0);
				mnemonic.textContent = inst.mnemonic;
				instG.appendChild(mnemonic);

				// Operand
				const operand = document.createElementNS('http://www.w3.org/2000/svg', 'text');
				operand.classList.add('inst-operand');
				operand.setAttribute('x', 60);
				operand.textContent = inst.opStr;
				instG.appendChild(operand);

				g.appendChild(instG);
				y += INST_HEIGHT;
			}

			// Click handler
			g.addEventListener('click', () => {
				selectBlock(block.id);
				vscode.postMessage({ type: 'blockClick', blockId: block.id, address: block.startAddress });
			});

			g.addEventListener('dblclick', () => {
				vscode.postMessage({ type: 'goToAddress', address: block.startAddress });
			});

			blocksGroup.appendChild(g);
		}
	</script>
</body>
</html>`;
	}
}
