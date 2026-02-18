/*---------------------------------------------------------------------------------------------
 *  HexCore Hex Viewer v2.0 - Custom Editor Provider with Editing & Templates
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import { StructureTemplate, STRUCTURE_TEMPLATES } from './structureTemplates';
import { BookmarkManager, Bookmark } from './bookmarkManager';
import { getHexCoreBaseCSS } from 'hexcore-common';

export class HexEditorProvider implements vscode.CustomReadonlyEditorProvider<HexDocument> {
	public static readonly viewType = 'hexcore.hexEditor';
	private bookmarkManager: BookmarkManager;
	private static activeWebview?: vscode.Webview;

	constructor(private readonly context: vscode.ExtensionContext) {
		this.bookmarkManager = new BookmarkManager(context);
	}

	/**
	 * Get the currently active webview (if any hex editor is open)
	 */
	public static getActiveWebview(): vscode.Webview | undefined {
		return HexEditorProvider.activeWebview;
	}

	/**
	 * Send a message to the active webview
	 */
	public static postToActiveWebview(message: any): boolean {
		if (HexEditorProvider.activeWebview) {
			HexEditorProvider.activeWebview.postMessage(message);
			return true;
		}
		return false;
	}

	public static register(context: vscode.ExtensionContext): vscode.Disposable {
		const provider = new HexEditorProvider(context);
		return vscode.window.registerCustomEditorProvider(
			HexEditorProvider.viewType,
			provider,
			{
				webviewOptions: {
					retainContextWhenHidden: true
				},
				supportsMultipleEditorsPerDocument: false
			}
		);
	}

	async openCustomDocument(
		uri: vscode.Uri,
		_openContext: vscode.CustomDocumentOpenContext,
		_token: vscode.CancellationToken
	): Promise<HexDocument> {
		const stat = await vscode.workspace.fs.stat(uri);
		return new HexDocument(uri, Number(stat.size));
	}

	async resolveCustomEditor(
		document: HexDocument,
		webviewPanel: vscode.WebviewPanel,
		_token: vscode.CancellationToken
	): Promise<void> {
		webviewPanel.webview.options = {
			enableScripts: true
		};

		// Track active webview
		HexEditorProvider.activeWebview = webviewPanel.webview;
		webviewPanel.onDidDispose(() => {
			if (HexEditorProvider.activeWebview === webviewPanel.webview) {
				HexEditorProvider.activeWebview = undefined;
			}
		});

		const bookmarks = this.bookmarkManager.getBookmarks(document.uri.fsPath);
		webviewPanel.webview.html = this.getHtmlForWebview(webviewPanel.webview, document, bookmarks);

		// Track edit state
		let editedBytes = new Map<number, number>();
		let isModified = false;

		webviewPanel.webview.onDidReceiveMessage(async message => {
			switch (message.type) {
				case 'ready':
					webviewPanel.webview.postMessage({
						type: 'init',
						fileSize: document.fileSize,
						fileName: document.uri.fsPath,
						canEdit: true
					});
					break;

				case 'requestData':
					try {
						const { offset, length } = message;
						const data = await this.readChunk(document.uri, offset, length);
						// Apply any pending edits
						const editedData = new Uint8Array(data);
						for (let i = 0; i < editedData.length; i++) {
							const globalOffset = offset + i;
							if (editedBytes.has(globalOffset)) {
								editedData[i] = editedBytes.get(globalOffset)!;
							}
						}
						webviewPanel.webview.postMessage({
							type: 'chunkData',
							offset: offset,
							data: Array.from(editedData),
							editedRanges: Array.from(editedBytes.keys())
								.filter(k => k >= offset && k < offset + length)
								.map(k => k - offset)
						});
					} catch (e) {
						vscode.window.showErrorMessage('Failed to read file chunk: ' + e);
					}
					break;

				case 'editByte':
					// Track the edit
					editedBytes.set(message.offset, message.value);
					isModified = true;
					webviewPanel.webview.postMessage({
						type: 'editConfirmed',
						offset: message.offset,
						value: message.value
					});
					break;

				case 'save':
					try {
						await this.saveDocument(document, editedBytes);
						editedBytes.clear();
						isModified = false;
						webviewPanel.webview.postMessage({ type: 'saved' });
						vscode.window.showInformationMessage('File saved successfully');
					} catch (e) {
						vscode.window.showErrorMessage('Failed to save: ' + e);
					}
					break;

				case 'copyToClipboard':
					vscode.env.clipboard.writeText(message.text);
					vscode.window.showInformationMessage('Copied to clipboard');
					break;

				case 'search':
					try {
						const results = await this.searchHex(document.uri, document.fileSize, message.pattern);
						webviewPanel.webview.postMessage({
							type: 'searchResults',
							results: results
						});
					} catch (e) {
						vscode.window.showErrorMessage('Search failed: ' + e);
					}
					break;

				case 'goToOffset':
					webviewPanel.webview.postMessage({
						type: 'jumpToOffset',
						offset: message.offset
					});
					break;

				case 'addBookmark':
					const bookmark = this.bookmarkManager.addBookmark(
						document.uri.fsPath,
						message.offset,
						message.name,
						message.color
					);
					webviewPanel.webview.postMessage({
						type: 'bookmarkAdded',
						bookmark: bookmark
					});
					break;

				case 'removeBookmark':
					this.bookmarkManager.removeBookmark(document.uri.fsPath, message.offset);
					break;

				case 'applyTemplate':
					const template = STRUCTURE_TEMPLATES.find(t => t.name === message.templateName);
					if (template) {
						const data = await this.readChunk(document.uri, message.offset, template.size);
						const parsed = this.parseTemplate(template, data);
						webviewPanel.webview.postMessage({
							type: 'templateApplied',
							parsed: parsed,
							template: template
						});
					}
					break;

				case 'getTemplates':
					webviewPanel.webview.postMessage({
						type: 'templatesList',
						templates: STRUCTURE_TEMPLATES.map(t => ({
							name: t.name,
							size: t.size,
							description: t.description
						}))
					});
					break;

				case 'syncToDisasm':
					// Cross-extension sync: navigate Disassembler to the address corresponding to this offset
					// The Disassembler's goToAddress command accepts a virtual address.
					// We pass the offset directly — the disassembler will interpret it as an address.
					// For proper conversion, the disassembler should add its base address.
					if (typeof message.offset === 'number') {
						try {
							await vscode.commands.executeCommand('hexcore.disasm.goToAddress', message.offset);
						} catch {
							// Disassembler extension may not be active — fail silently
						}
					}
					break;

				case 'toggleSyncDisasm':
					// Sync toggle state is managed in the webview; nothing to persist on the host side
					break;
			}
		});
	}

	private async readChunk(uri: vscode.Uri, offset: number, length: number): Promise<Uint8Array> {
		if (uri.scheme === 'file') {
			return new Promise((resolve, reject) => {
				fs.open(uri.fsPath, 'r', (err: NodeJS.ErrnoException | null, fd: number) => {
					if (err) return reject(err);
					const buffer = Buffer.alloc(length);
					fs.read(fd, buffer, 0, length, offset, (readErr: NodeJS.ErrnoException | null, bytesRead: number) => {
						fs.close(fd, () => { });
						if (readErr) return reject(readErr);
						resolve(buffer.slice(0, bytesRead));
					});
				});
			});
		} else {
			const allData = await vscode.workspace.fs.readFile(uri);
			return allData.slice(offset, offset + length);
		}
	}

	private async saveDocument(document: HexDocument, edits: Map<number, number>): Promise<void> {
		if (edits.size === 0) return;

		const buffer = await vscode.workspace.fs.readFile(document.uri);
		const newBuffer = Buffer.from(buffer);

		for (const [offset, value] of edits) {
			if (offset < newBuffer.length) {
				newBuffer[offset] = value;
			}
		}

		await vscode.workspace.fs.writeFile(document.uri, newBuffer);
	}

	private async searchHex(uri: vscode.Uri, fileSize: number, pattern: string): Promise<number[]> {
		const results: number[] = [];
		const hexPattern = pattern.replace(/\s+/g, '').toUpperCase();

		if (hexPattern.length === 0 || hexPattern.length % 2 !== 0) {
			return results;
		}

		const searchBytes: number[] = [];
		for (let i = 0; i < hexPattern.length; i += 2) {
			const byte = parseInt(hexPattern.substr(i, 2), 16);
			if (isNaN(byte)) return results;
			searchBytes.push(byte);
		}

		const chunkSize = 65536;
		const overlap = searchBytes.length - 1;

		for (let offset = 0; offset < fileSize && results.length < 1000; offset += chunkSize - overlap) {
			const length = Math.min(chunkSize, fileSize - offset);
			const data = await this.readChunk(uri, offset, length);

			for (let i = 0; i <= data.length - searchBytes.length; i++) {
				let match = true;
				for (let j = 0; j < searchBytes.length; j++) {
					if (data[i + j] !== searchBytes[j]) {
						match = false;
						break;
					}
				}
				if (match) {
					const absoluteOffset = offset + i;
					if (results.length === 0 || results[results.length - 1] !== absoluteOffset) {
						results.push(absoluteOffset);
					}
				}
			}
		}

		return results;
	}

	private parseTemplate(template: StructureTemplate, data: Uint8Array): any {
		const result: any = {};
		let offset = 0;
		const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

		for (const field of template.fields) {
			if (offset >= data.length) break;

			switch (field.type) {
				case 'uint8':
					result[field.name] = view.getUint8(offset);
					offset += 1;
					break;
				case 'uint16':
					result[field.name] = view.getUint16(offset, true);
					offset += 2;
					break;
				case 'uint32':
					result[field.name] = view.getUint32(offset, true);
					offset += 4;
					break;
				case 'uint64':
					result[field.name] = view.getBigUint64(offset, true).toString();
					offset += 8;
					break;
				case 'ascii':
					const strLen = field.length || 1;
					result[field.name] = Buffer.from(data.slice(offset, offset + strLen))
						.toString('ascii').replace(/\x00/g, '');
					offset += strLen;
					break;
			}
		}

		return result;
	}

	private getHtmlForWebview(webview: vscode.Webview, document: HexDocument, bookmarks: Bookmark[]): string {
		const config = vscode.workspace.getConfiguration('hexcore.hexViewer');
		const bytesPerRow = config.get<number>('bytesPerRow', 16);
		const showAscii = config.get<boolean>('showAscii', true);
		const uppercase = config.get<boolean>('uppercase', true);

		// Generate nonce for CSP to prevent XSS via inline script injection
		const nonce = this.getNonce();
		const baseCSS = getHexCoreBaseCSS();

		return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Hex Editor</title>
	<style>
		${baseCSS}

		:root {
			--font-mono: 'Consolas', 'Monaco', 'Courier New', monospace;
			--row-height: 22px;
		}

		* { margin: 0; padding: 0; box-sizing: border-box; }

		body {
			font-family: var(--font-mono);
			background-color: var(--vscode-editor-background);
			color: var(--vscode-editor-foreground);
			font-size: 13px;
			overflow: hidden;
			user-select: none;
		}

		/* Toolbar */
		.toolbar {
			display: flex;
			align-items: center;
			gap: 8px;
			padding: 4px 8px;
			background: var(--vscode-editor-background);
			border-bottom: 1px solid var(--vscode-panel-border);
			min-height: 36px;
			flex-wrap: wrap;
		}

		.toolbar-group { display: flex; align-items: center; gap: 4px; }
		.toolbar-item { display: flex; align-items: center; gap: 6px; font-size: 11px; }
		.label { color: var(--vscode-descriptionForeground); }
		.value { color: var(--vscode-textLink-foreground); font-weight: bold; }
		.divider { width: 1px; height: 16px; background: var(--vscode-panel-border); }

		.toolbar-btn {
			background: var(--vscode-button-secondaryBackground);
			color: var(--vscode-button-secondaryForeground);
			border: none;
			padding: 4px 10px;
			font-size: 11px;
			cursor: pointer;
			border-radius: 3px;
			display: flex;
			align-items: center;
			gap: 4px;
		}
		.toolbar-btn:hover { background: var(--vscode-button-secondaryHoverBackground); }
		.toolbar-btn.primary { background: var(--vscode-button-background); }
		.toolbar-btn.primary:hover { background: var(--vscode-button-hoverBackground); }
		.toolbar-btn:disabled { opacity: 0.5; cursor: not-allowed; }
		.toolbar-btn.modified { background: var(--vscode-inputValidation-warningBackground); }
		.toolbar-btn.active { background: var(--hexcore-safe); color: #000; }

		.toolbar-input { display: flex; align-items: center; gap: 4px; }
		.toolbar-input input {
			background: var(--vscode-input-background);
			border: 1px solid var(--vscode-input-border);
			color: var(--vscode-input-foreground);
			padding: 3px 6px;
			font-size: 11px;
			font-family: var(--font-mono);
			width: 100px;
			border-radius: 3px;
		}
		.toolbar-input input:focus { outline: 1px solid var(--vscode-focusBorder); }

		.toolbar-right {
			margin-left: auto;
			display: flex;
			gap: 8px;
			align-items: center;
			color: var(--vscode-descriptionForeground);
			font-size: 11px;
		}

		/* Main Layout */
		.container { display: flex; height: calc(100vh - 36px); }

		/* Hex View */
		.hex-view-container {
			flex: 1;
			position: relative;
			overflow-y: auto;
			overflow-x: hidden;
			outline: none;
		}

		.phantom-spacer { position: absolute; top: 0; left: 0; width: 1px; visibility: hidden; }
		.content-layer { position: absolute; top: 0; left: 0; width: 100%; will-change: transform; }

		.hex-row {
			height: var(--row-height);
			display: flex;
			align-items: center;
			padding: 0 10px;
		}
		.hex-row:hover { background-color: var(--vscode-list-hoverBackground); }
		.hex-row.edited { background-color: var(--vscode-gitDecoration-modifiedResourceForeground); opacity: 0.2; }

		.offset-col {
			color: var(--vscode-editorLineNumber-foreground);
			width: 80px;
			flex-shrink: 0;
			font-size: 11px;
		}
		.offset-col.bookmarked::before {
			content: "[B]";
			margin-right: 4px;
			color: var(--vscode-textLink-foreground);
		}

		.bytes-col {
			display: flex;
			gap: 3px;
			margin-left: 16px;
			font-family: var(--font-mono);
		}

		.byte {
			display: inline-block;
			width: 2ch;
			text-align: center;
			font-size: 12px;
			cursor: pointer;
			border-radius: 2px;
			outline: none;
		}
		.byte:hover { background-color: var(--vscode-editor-selectionBackground); }
		.byte.selected { background-color: var(--vscode-editor-selectionBackground); color: var(--vscode-editor-selectionForeground); }
		.byte.edited { color: var(--vscode-gitDecoration-modifiedResourceForeground); font-weight: bold; }
		.byte.search-match { background-color: var(--vscode-editor-findMatchBackground); color: var(--vscode-editor-findMatchForeground); }
		.byte.editing { background: var(--vscode-input-background); border: 1px solid var(--vscode-focusBorder); }

		.ascii-col {
			margin-left: 24px;
			border-left: 1px solid var(--vscode-panel-border);
			padding-left: 10px;
			display: flex;
			font-size: 11px;
		}
		.char {
			width: 1ch;
			text-align: center;
			cursor: pointer;
		}
		.char:hover { background-color: var(--vscode-editor-selectionBackground); }
		.char.selected { background-color: var(--vscode-editor-selectionBackground); color: var(--vscode-editor-selectionForeground); }
		.char.non-print { color: var(--vscode-descriptionForeground); opacity: 0.4; }

		/* Sidebar */
		.sidebar {
			width: 300px;
			background-color: var(--vscode-sideBar-background);
			border-left: 1px solid var(--vscode-panel-border);
			padding: 12px;
			overflow-y: auto;
			display: flex;
			flex-direction: column;
			gap: 16px;
		}

		.section-header {
			text-transform: uppercase;
			font-size: 10px;
			font-weight: bold;
			color: var(--vscode-sideBarTitle-foreground);
			border-bottom: 1px solid var(--vscode-panel-border);
			padding-bottom: 4px;
			margin-bottom: 6px;
			display: flex;
			justify-content: space-between;
			align-items: center;
		}
		.section-header button {
			font-size: 9px;
			padding: 2px 6px;
		}

		.data-grid {
			display: grid;
			grid-template-columns: 80px 1fr;
			gap: 4px;
			font-size: 11px;
		}
		.data-label { color: var(--vscode-descriptionForeground); text-align: right; padding-right: 6px; }
		.data-value {
			font-family: var(--font-mono);
			color: var(--vscode-editor-foreground);
			user-select: text;
			white-space: nowrap;
			overflow: hidden;
			text-overflow: ellipsis;
			font-size: 11px;
		}

		/* Templates */
		.template-select {
			width: 100%;
			padding: 4px;
			font-size: 11px;
			background: var(--vscode-dropdown-background);
			color: var(--vscode-dropdown-foreground);
			border: 1px solid var(--vscode-dropdown-border);
			margin-bottom: 8px;
		}

		.template-fields {
			font-size: 10px;
			max-height: 150px;
			overflow-y: auto;
		}
		.template-field {
			display: flex;
			justify-content: space-between;
			padding: 2px 0;
			border-bottom: 1px solid var(--vscode-panel-border);
		}
		.template-field-name { color: var(--vscode-descriptionForeground); }
		.template-field-value { font-family: var(--font-mono); }

		/* Bookmarks */
		.bookmark-list {
			max-height: 150px;
			overflow-y: auto;
			font-size: 10px;
		}
		.bookmark-item {
			display: flex;
			justify-content: space-between;
			align-items: center;
			padding: 3px 6px;
			margin-bottom: 2px;
			background: var(--vscode-list-hoverBackground);
			border-radius: 3px;
			cursor: pointer;
		}
		.bookmark-item:hover { background: var(--vscode-list-activeSelectionBackground); }
		.bookmark-color { width: 8px; height: 8px; border-radius: 50%; margin-right: 4px; display: inline-block; }
		.bookmark-name { flex: 1; overflow: hidden; text-overflow: ellipsis; }
		.bookmark-offset { color: var(--vscode-descriptionForeground); font-family: var(--font-mono); }
		.bookmark-delete { color: var(--vscode-errorForeground); cursor: pointer; padding: 0 4px; }

		/* Copy buttons */
		.copy-section { display: flex; flex-direction: column; gap: 4px; }
		.copy-btn {
			padding: 4px 8px;
			font-size: 10px;
			background: var(--vscode-button-secondaryBackground);
			color: var(--vscode-button-secondaryForeground);
			border: 1px solid var(--vscode-panel-border);
			cursor: pointer;
			border-radius: 3px;
			text-align: left;
		}
		.copy-btn:hover { background: var(--vscode-button-secondaryHoverBackground); }
		.copy-btn:disabled { opacity: 0.5; cursor: not-allowed; }

		/* Search Results */
		.search-results { max-height: 120px; overflow-y: auto; font-size: 10px; }
		.search-result-item {
			padding: 3px 6px;
			cursor: pointer;
			border-radius: 2px;
		}
		.search-result-item:hover { background: var(--vscode-list-hoverBackground); }
		.search-info { font-size: 10px; color: var(--vscode-descriptionForeground); margin-bottom: 4px; }

		/* Edit Mode Indicator */
		.edit-mode-indicator {
			background: var(--vscode-inputValidation-warningBackground);
			color: var(--vscode-inputValidation-warningForeground);
			padding: 2px 8px;
			border-radius: 3px;
			font-size: 10px;
			font-weight: bold;
		}
	</style>
</head>
<body>
	<div class="toolbar">
		<div class="toolbar-group">
			<div class="toolbar-input">
				<input type="text" id="gotoInput" placeholder="Go to offset..." />
				<button class="toolbar-btn" id="gotoBtn" title="Go to Offset">Go</button>
			</div>
			<div class="toolbar-input">
				<input type="text" id="searchInput" placeholder="Search hex..." />
				<button class="toolbar-btn" id="searchBtn" title="Search Hex">Find</button>
			</div>
		</div>
		<div class="divider"></div>
		<div class="toolbar-group">
			<button class="toolbar-btn" id="addBookmarkBtn" title="Add Bookmark">+ Bookmark</button>
			<button class="toolbar-btn" id="applyTemplateBtn" title="Apply Template">Template</button>
			<button class="toolbar-btn" id="editModeBtn" title="Toggle Edit Mode">Edit Mode</button>
		</div>
		<div class="divider"></div>
		<div class="toolbar-group">
			<button class="toolbar-btn" id="copyHexBtn" title="Copy as Hex" disabled>Copy Hex</button>
			<button class="toolbar-btn" id="copyCArrayBtn" title="Copy as C Array" disabled>Copy C</button>
			<button class="toolbar-btn" id="copyPythonBtn" title="Copy as Python Bytes" disabled>Copy Py</button>
		</div>
		<div class="divider"></div>
		<button class="toolbar-btn" id="syncDisasmBtn" title="Sync with Disassembler">Sync Disasm</button>
		<div class="toolbar-right">
			<span class="label">FILE:</span>
			<span class="value" id="fileName">-</span>
			<span class="divider"></span>
			<span class="label">SIZE:</span>
			<span class="value" id="fileSize">-</span>
			<span class="divider"></span>
			<span class="label">OFFSET:</span>
			<span class="value" id="cursorOffset">0x00000000</span>
			<button class="toolbar-btn primary" id="saveBtn" disabled>Save</button>
		</div>
	</div>

	<div class="container">
		<div class="hex-view-container" id="scrollContainer" tabindex="0">
			<div class="phantom-spacer" id="phantomSpacer"></div>
			<div class="content-layer" id="contentLayer"></div>
		</div>

		<div class="sidebar">
			<div>
				<div class="section-header">Data Inspector</div>
				<div class="data-grid" id="dataInspector">
					<div class="data-label">UInt8</div><div class="data-value" id="valUInt8">-</div>
					<div class="data-label">Int8</div><div class="data-value" id="valInt8">-</div>
					<div class="data-label">UInt16 LE</div><div class="data-value" id="valUInt16LE">-</div>
					<div class="data-label">UInt16 BE</div><div class="data-value" id="valUInt16BE">-</div>
					<div class="data-label">Int16 LE</div><div class="data-value" id="valInt16LE">-</div>
					<div class="data-label">Int16 BE</div><div class="data-value" id="valInt16BE">-</div>
					<div class="data-label">UInt32 LE</div><div class="data-value" id="valUInt32LE">-</div>
					<div class="data-label">UInt32 BE</div><div class="data-value" id="valUInt32BE">-</div>
					<div class="data-label">Int32 LE</div><div class="data-value" id="valInt32LE">-</div>
					<div class="data-label">Int32 BE</div><div class="data-value" id="valInt32BE">-</div>
					<div class="data-label">UInt64 LE</div><div class="data-value" id="valUInt64LE">-</div>
					<div class="data-label">Float32 LE</div><div class="data-value" id="valFloat32LE">-</div>
					<div class="data-label">Float32 BE</div><div class="data-value" id="valFloat32BE">-</div>
					<div class="data-label">Float64 LE</div><div class="data-value" id="valFloat64LE">-</div>
					<div class="data-label">Float64 BE</div><div class="data-value" id="valFloat64BE">-</div>
					<div class="data-label">ASCII</div><div class="data-value" id="valAscii">-</div>
					<div class="data-label">UTF-16 LE</div><div class="data-value" id="valUtf16le">-</div>
				</div>
			</div>

			<div>
				<div class="section-header">Selection</div>
				<div class="data-grid">
					<div class="data-label">Start</div><div class="data-value" id="selStart">-</div>
					<div class="data-label">End</div><div class="data-value" id="selEnd">-</div>
					<div class="data-label">Length</div><div class="data-value" id="selLen">-</div>
				</div>
			</div>

			<div>
				<div class="section-header">Copy</div>
				<div class="copy-section">
					<button class="copy-btn" id="copyHex" disabled>Copy as Hex</button>
					<button class="copy-btn" id="copyCArray" disabled>Copy as C Array</button>
					<button class="copy-btn" id="copyPython" disabled>Copy as Python Bytes</button>
				</div>
			</div>

			<div>
				<div class="section-header">Structure Template</div>
				<select class="template-select" id="templateSelect">
					<option value="">Select template...</option>
				</select>
				<div class="template-fields" id="templateFields"></div>
			</div>

			<div>
				<div class="section-header">
					<span>Bookmarks</span>
				</div>
				<div class="bookmark-list" id="bookmarkList"></div>
			</div>

			<div id="searchResultsSection" style="display: none;">
				<div class="section-header">Search Results</div>
				<div class="search-info" id="searchInfo">-</div>
				<div class="search-results" id="searchResults"></div>
			</div>
		</div>
	</div>

	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();

		// Configuration
		const BYTES_PER_ROW = ${bytesPerRow};
		const ROW_HEIGHT = 22;
		const UPPERCASE = ${uppercase};
		const SHOW_ASCII = ${showAscii};
		const CHUNK_SIZE = 8192;

		// State
		let totalFileSize = 0;
		let totalRows = 0;
		let cachedChunks = new Map();
		let pendingRequests = new Set();
		let selection = { start: -1, end: -1 };
		let isSelecting = false;
		let searchMatches = [];
		let editedBytes = new Set();
		let bookmarks = ${JSON.stringify(bookmarks)};
		let isEditMode = false;
		let currentEditOffset = -1;
		let isModified = false;

		const scrollContainer = document.getElementById('scrollContainer');
		const phantomSpacer = document.getElementById('phantomSpacer');
		const contentLayer = document.getElementById('contentLayer');

		// Initialize
		vscode.postMessage({ type: 'ready' });
		vscode.postMessage({ type: 'getTemplates' });

		// Toolbar handlers
		document.getElementById('saveBtn').addEventListener('click', () => {
			vscode.postMessage({ type: 'save' });
		});

		document.getElementById('editModeBtn').addEventListener('click', () => {
			isEditMode = !isEditMode;
			document.getElementById('editModeBtn').textContent = isEditMode ? 'Lock' : 'Edit Mode';
			document.getElementById('editModeBtn').classList.toggle('modified', isEditMode);
			renderVisibleRows();
		});

		document.getElementById('searchBtn').addEventListener('click', doSearch);
		document.getElementById('searchInput').addEventListener('keydown', e => {
			if (e.key === 'Enter') doSearch();
		});

		document.getElementById('gotoBtn').addEventListener('click', doGoto);
		document.getElementById('gotoInput').addEventListener('keydown', e => {
			if (e.key === 'Enter') doGoto();
		});

		document.getElementById('addBookmarkBtn').addEventListener('click', () => {
			if (selection.start === -1) {
				alert('Select a position first');
				return;
			}
			const name = prompt('Bookmark name:', 'Bookmark');
			if (name) {
				const colors = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4', '#ffeaa7', '#dfe6e9'];
				const color = colors[bookmarks.length % colors.length];
				vscode.postMessage({ type: 'addBookmark', offset: selection.start, name, color });
			}
		});

		document.getElementById('applyTemplateBtn').addEventListener('click', () => {
			const select = document.getElementById('templateSelect');
			if (select.value && selection.start !== -1) {
				vscode.postMessage({ type: 'applyTemplate', templateName: select.value, offset: selection.start });
			}
		});

		document.getElementById('templateSelect').addEventListener('change', (e) => {
			if (e.target.value && selection.start !== -1) {
				vscode.postMessage({ type: 'applyTemplate', templateName: e.target.value, offset: selection.start });
			}
		});

		// Sync with Disassembler toggle (placeholder for Task 17)
		let syncDisasmEnabled = false;
		document.getElementById('syncDisasmBtn').addEventListener('click', () => {
			syncDisasmEnabled = !syncDisasmEnabled;
			document.getElementById('syncDisasmBtn').classList.toggle('active', syncDisasmEnabled);
			document.getElementById('syncDisasmBtn').textContent = syncDisasmEnabled ? '🔗 Sync Disasm' : 'Sync Disasm';
			vscode.postMessage({ type: 'toggleSyncDisasm', enabled: syncDisasmEnabled });
		});

		function doSearch() {
			const pattern = document.getElementById('searchInput').value.trim();
			if (pattern) {
				document.getElementById('searchInfo').textContent = 'Searching...';
				document.getElementById('searchResultsSection').style.display = 'block';
				vscode.postMessage({ type: 'search', pattern: pattern });
			}
		}

		function doGoto() {
			const input = document.getElementById('gotoInput').value.trim();
			let offset = input.toLowerCase().startsWith('0x') ? parseInt(input, 16) : parseInt(input, 10);
			if (!isNaN(offset) && offset >= 0 && offset < totalFileSize) {
				jumpToOffset(offset);
			}
		}

		function jumpToOffset(offset) {
			const row = Math.floor(offset / BYTES_PER_ROW);
			scrollContainer.scrollTop = row * ROW_HEIGHT;
			selection.start = offset;
			selection.end = offset;
			renderVisibleRows();
			updateInspector();
		}

		function addBookmarkToUI(bookmark) {
			bookmarks.push(bookmark);
			renderBookmarks();
			renderVisibleRows();
		}

		function renderBookmarks() {
			const list = document.getElementById('bookmarkList');
			list.innerHTML = bookmarks.map(b => \`
				<div class="bookmark-item" data-offset="\${b.offset}">
					<span class="bookmark-color" style="background: \${b.color}"></span>
					<span class="bookmark-name">\${b.name}</span>
					<span class="bookmark-offset">0x\${b.offset.toString(16).toUpperCase()}</span>
					<span class="bookmark-delete" data-offset="\${b.offset}">×</span>
				</div>
			\`).join('');

			list.querySelectorAll('.bookmark-item').forEach(el => {
				el.addEventListener('click', (e) => {
					if (!e.target.classList.contains('bookmark-delete')) {
						jumpToOffset(parseInt(el.dataset.offset));
					}
				});
			});

			list.querySelectorAll('.bookmark-delete').forEach(el => {
				el.addEventListener('click', (e) => {
					e.stopPropagation();
					const offset = parseInt(el.dataset.offset);
					bookmarks = bookmarks.filter(b => b.offset !== offset);
					renderBookmarks();
					vscode.postMessage({ type: 'removeBookmark', offset });
				});
			});
		}

		// Copy buttons — sidebar
		document.getElementById('copyHex').addEventListener('click', () => copySelection('hex'));
		document.getElementById('copyCArray').addEventListener('click', () => copySelection('c-array'));
		document.getElementById('copyPython').addEventListener('click', () => copySelection('python-bytes'));

		// Copy buttons — toolbar
		document.getElementById('copyHexBtn').addEventListener('click', () => copySelection('hex'));
		document.getElementById('copyCArrayBtn').addEventListener('click', () => copySelection('c-array'));
		document.getElementById('copyPythonBtn').addEventListener('click', () => copySelection('python-bytes'));

		/**
		 * formatSelection — matches the exported function in hexCopyFormats.ts
		 */
		function formatSelectionFn(bytes, format) {
			switch (format) {
				case 'hex':
					return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(' ');
				case 'c-array':
					return '{ ' + Array.from(bytes).map(b => '0x' + b.toString(16).padStart(2, '0').toUpperCase()).join(', ') + ' }';
				case 'python-bytes':
					return "b'" + Array.from(bytes).map(b => '\\\\x' + b.toString(16).padStart(2, '0')).join('') + "'";
				default:
					return '';
			}
		}

		function copySelection(format) {
			if (selection.start === -1) return;
			const start = Math.min(selection.start, selection.end);
			const end = Math.max(selection.start, selection.end);
			const bytes = getBytesRange(start, end - start + 1);
			if (bytes.length === 0) return;

			const text = formatSelectionFn(new Uint8Array(bytes), format);
			vscode.postMessage({ type: 'copyToClipboard', text: text });
		}

		function getBytesRange(start, count) {
			const result = [];
			for (let i = 0; i < count && (start + i) < totalFileSize; i++) {
				const chunkStart = Math.floor((start + i) / CHUNK_SIZE) * CHUNK_SIZE;
				const chunk = cachedChunks.get(chunkStart);
				if (chunk) {
					const relOffset = (start + i) - chunkStart;
					if (relOffset < chunk.length) {
						result.push(chunk[relOffset]);
					}
				}
			}
			return result;
		}

		// Message handler
		window.addEventListener('message', e => {
			const msg = e.data;
			switch (msg.type) {
				case 'init':
					totalFileSize = msg.fileSize;
					totalRows = Math.ceil(totalFileSize / BYTES_PER_ROW);
					document.getElementById('fileName').textContent = msg.fileName.split(/[\\\\/]/).pop();
					document.getElementById('fileSize').textContent = formatBytes(totalFileSize);
					phantomSpacer.style.height = (totalRows * ROW_HEIGHT) + 'px';
					renderBookmarks();
					onScroll();
					break;

				case 'chunkData':
					cachedChunks.set(msg.offset, new Uint8Array(msg.data));
					pendingRequests.delete(msg.offset);
					if (msg.editedRanges) {
						msg.editedRanges.forEach(r => editedBytes.add(msg.offset + r));
					}
					renderVisibleRows();
					break;

				case 'editConfirmed':
					editedBytes.add(msg.offset);
					isModified = true;
					document.getElementById('saveBtn').disabled = false;
					document.getElementById('saveBtn').classList.add('modified');
					renderVisibleRows();
					break;

				case 'saved':
					isModified = false;
					editedBytes.clear();
					document.getElementById('saveBtn').disabled = true;
					document.getElementById('saveBtn').classList.remove('modified');
					break;

				case 'searchResults':
					searchMatches = msg.results;
					document.getElementById('searchInfo').textContent = msg.results.length + ' matches';
					const resultsDiv = document.getElementById('searchResults');
					const maxDisplay = 50;
					resultsDiv.innerHTML = msg.results.slice(0, maxDisplay).map(offset =>
					\`<div class="search-result-item" data-offset="\${offset}">0x\${offset.toString(16).toUpperCase().padStart(8, '0')}</div>\`
					).join('') + (msg.results.length > maxDisplay ? \`<div style="padding:4px 8px;opacity:0.7;font-style:italic;">Showing \${maxDisplay} of \${msg.results.length} results</div>\` : '');
					resultsDiv.querySelectorAll('.search-result-item').forEach(el => {
						el.addEventListener('click', () => jumpToOffset(parseInt(el.dataset.offset)));
					});
					renderVisibleRows();
					break;

				case 'templatesList':
					const select = document.getElementById('templateSelect');
					select.innerHTML = '<option value="">Select template...</option>' +
						msg.templates.map(t => \`<option value="\${t.name}">\${t.name} (\${t.size} bytes)</option>\`).join('');
					break;

				case 'templateApplied':
					const fieldsDiv = document.getElementById('templateFields');
					fieldsDiv.innerHTML = Object.entries(msg.parsed).map(([k, v]) =>
					\`<div class="template-field"><span class="template-field-name">\${k}:</span><span class="template-field-value">\${v}</span></div>\`
					).join('');
					break;

				case 'bookmarkAdded':
					addBookmarkToUI(msg.bookmark);
					break;

				case 'jumpToOffset':
					jumpToOffset(msg.offset);
					break;
			}
		});

		// Virtual Scroll
		scrollContainer.addEventListener('scroll', onScroll);
		let scrollRAF = null;
		function onScroll() {
			if (scrollRAF) return;
			scrollRAF = requestAnimationFrame(() => {
				scrollRAF = null;
				renderVisibleRows();
			});
		}

		function renderVisibleRows() {
			const scrollTop = scrollContainer.scrollTop;
			const viewportHeight = scrollContainer.clientHeight;
			const startRow = Math.floor(scrollTop / ROW_HEIGHT);
			const visibleRowCount = Math.ceil(viewportHeight / ROW_HEIGHT);
			const buffer = 5;
			const renderStartRow = Math.max(0, startRow - buffer);
			const renderEndRow = Math.min(totalRows, startRow + visibleRowCount + buffer);

			contentLayer.style.transform = 'translateY(' + (renderStartRow * ROW_HEIGHT) + 'px)';

			let html = '';
			const missingChunks = new Set();

			for (let row = renderStartRow; row < renderEndRow; row++) {
				const rowOffset = row * BYTES_PER_ROW;
				const rowData = getRowData(rowOffset);

				if (!rowData) {
					const chunkStart = Math.floor(rowOffset / CHUNK_SIZE) * CHUNK_SIZE;
					if (!cachedChunks.has(chunkStart) && !pendingRequests.has(chunkStart)) {
						missingChunks.add(chunkStart);
					}
				}

				html += generateRowHtml(row, rowOffset, rowData);
			}

			contentLayer.innerHTML = html;

			missingChunks.forEach(chunkOffset => {
				pendingRequests.add(chunkOffset);
				vscode.postMessage({ type: 'requestData', offset: chunkOffset, length: CHUNK_SIZE });
			});
		}

		function getRowData(offset) {
			const chunkStart = Math.floor(offset / CHUNK_SIZE) * CHUNK_SIZE;
			const chunk = cachedChunks.get(chunkStart);
			if (chunk) {
				const relOffset = offset - chunkStart;
				const endOffset = Math.min(relOffset + BYTES_PER_ROW, chunk.length);
				if (relOffset < chunk.length) {
					return chunk.subarray(relOffset, endOffset);
				}
			}
			return null;
		}

		function generateRowHtml(row, offset, data) {
			const offsetStr = UPPERCASE
				? offset.toString(16).toUpperCase().padStart(8, '0')
				: offset.toString(16).padStart(8, '0');

			const hasBookmark = bookmarks.some(b => b.offset >= offset && b.offset < offset + BYTES_PER_ROW);

			let hexHtml = '';
			let asciiHtml = '';

			for (let i = 0; i < BYTES_PER_ROW; i++) {
				const currentOffset = offset + i;
				if (currentOffset >= totalFileSize) break;

				let byteVal = null;
				if (data && i < data.length) byteVal = data[i];

				const isSelected = selection.start !== -1 &&
					currentOffset >= Math.min(selection.start, selection.end) &&
					currentOffset <= Math.max(selection.start, selection.end);

				const isSearchMatch = searchMatches.includes(currentOffset);
				const isEdited = editedBytes.has(currentOffset);

				let classes = 'byte';
				if (byteVal === 0) classes += ' null';
				if (isSelected) classes += ' selected';
				if (isSearchMatch) classes += ' search-match';
				if (isEdited) classes += ' edited';

				if (byteVal !== null) {
					const hex = UPPERCASE
						? byteVal.toString(16).toUpperCase().padStart(2, '0')
						: byteVal.toString(16).padStart(2, '0');
					hexHtml += \`<span class="\${classes}" data-o="\${currentOffset}">\${hex}</span>\`;
				} else {
					hexHtml += '<span class="byte null">..</span>';
				}

				if (SHOW_ASCII) {
					if (byteVal !== null) {
						const isPrint = byteVal >= 32 && byteVal <= 126;
						const char = isPrint ? String.fromCharCode(byteVal) : '.';
						const charClasses = 'char' + (isSelected ? ' selected' : '') + (!isPrint ? ' non-print' : '');
						asciiHtml += \`<span class="\${charClasses}" data-o="\${currentOffset}">\${escapeHtml(char)}</span>\`;
					} else {
						asciiHtml += '<span class="char non-print">.</span>';
					}
				}
			}

			const bookmarkClass = hasBookmark ? ' bookmarked' : '';
			return \`<div class="hex-row">
				<span class="offset-col\${bookmarkClass}">0x\${offsetStr}</span>
				<div class="bytes-col">\${hexHtml}</div>
				\${SHOW_ASCII ? '<div class="ascii-col">' + asciiHtml + '</div>' : ''}
			</div>\`;
		}

		// Selection handling
		scrollContainer.addEventListener('mousedown', e => {
			const target = e.target;
			if (target.dataset && target.dataset.o) {
				const offset = parseInt(target.dataset.o, 10);
				if (e.shiftKey && selection.start !== -1) {
					selection.end = offset;
				} else {
					selection.start = offset;
					selection.end = offset;
				}
				isSelecting = true;
				renderVisibleRows();
				updateInspector();
			}
		});

		scrollContainer.addEventListener('mousemove', e => {
			if (!isSelecting) return;
			const target = e.target;
			if (target.dataset && target.dataset.o) {
				selection.end = parseInt(target.dataset.o, 10);
				renderVisibleRows();
				updateInspector();
			}
		});

		window.addEventListener('mouseup', () => {
			isSelecting = false;
		});

		// Edit mode
		scrollContainer.addEventListener('dblclick', e => {
			if (!isEditMode) return;
			const target = e.target;
			if (target.classList.contains('byte') && target.dataset.o) {
				const offset = parseInt(target.dataset.o, 10);
				startEditing(offset, target);
			}
		});

		function startEditing(offset, element) {
			if (currentEditOffset !== -1) {
				finishEditing();
			}

			currentEditOffset = offset;
			element.classList.add('editing');
			element.contentEditable = 'true';
			element.focus();

			const originalValue = element.textContent;
			element.textContent = '';

			const onKeyDown = (e) => {
				if (e.key === 'Enter') {
					e.preventDefault();
					finishEditing();
				} else if (e.key === 'Escape') {
					e.preventDefault();
					element.textContent = originalValue;
					finishEditing();
				}
			};

			const onBlur = () => {
				const newValue = element.textContent.trim();
				if (/^[0-9A-Fa-f]{2}$/.test(newValue)) {
					const byteValue = parseInt(newValue, 16);
					vscode.postMessage({ type: 'editByte', offset: currentEditOffset, value: byteValue });
				} else {
					element.textContent = originalValue;
				}
				finishEditing();
			};

			element.addEventListener('keydown', onKeyDown);
			element.addEventListener('blur', onBlur, { once: true });
		}

		function finishEditing() {
			if (currentEditOffset === -1) return;
			const element = document.querySelector(\`.byte[data-o="\${currentEditOffset}"]\`);
			if (element) {
				element.classList.remove('editing');
				element.contentEditable = 'false';
			}
			currentEditOffset = -1;
		}

		function updateInspector() {
			if (selection.start === -1) return;

			const start = Math.min(selection.start, selection.end);
			const end = Math.max(selection.start, selection.end);
			const len = end - start + 1;

			document.getElementById('selStart').textContent = '0x' + start.toString(16).toUpperCase().padStart(8, '0');
			document.getElementById('selEnd').textContent = '0x' + end.toString(16).toUpperCase().padStart(8, '0');
			document.getElementById('selLen').textContent = len + ' bytes';
			document.getElementById('cursorOffset').textContent = '0x' + start.toString(16).toUpperCase().padStart(8, '0');

			// Enable copy buttons
			document.getElementById('copyHex').disabled = false;
			document.getElementById('copyCArray').disabled = false;
			document.getElementById('copyPython').disabled = false;
			document.getElementById('copyHexBtn').disabled = false;
			document.getElementById('copyCArrayBtn').disabled = false;
			document.getElementById('copyPythonBtn').disabled = false;

			const bytes = getBytesRange(start, 8);
			if (bytes.length === 0) return;

			const buffer = new ArrayBuffer(8);
			const uint8View = new Uint8Array(buffer);
			for (let i = 0; i < Math.min(bytes.length, 8); i++) {
				uint8View[i] = bytes[i];
			}
			const view = new DataView(buffer);
			const bLen = bytes.length;

			// Data Inspector — all formats with LE/BE and N/A for insufficient bytes
			document.getElementById('valUInt8').textContent = bLen >= 1 ? view.getUint8(0) : 'N/A';
			document.getElementById('valInt8').textContent = bLen >= 1 ? view.getInt8(0) : 'N/A';
			document.getElementById('valUInt16LE').textContent = bLen >= 2 ? view.getUint16(0, true) : 'N/A';
			document.getElementById('valUInt16BE').textContent = bLen >= 2 ? view.getUint16(0, false) : 'N/A';
			document.getElementById('valInt16LE').textContent = bLen >= 2 ? view.getInt16(0, true) : 'N/A';
			document.getElementById('valInt16BE').textContent = bLen >= 2 ? view.getInt16(0, false) : 'N/A';
			document.getElementById('valUInt32LE').textContent = bLen >= 4 ? view.getUint32(0, true) : 'N/A';
			document.getElementById('valUInt32BE').textContent = bLen >= 4 ? view.getUint32(0, false) : 'N/A';
			document.getElementById('valInt32LE').textContent = bLen >= 4 ? view.getInt32(0, true) : 'N/A';
			document.getElementById('valInt32BE').textContent = bLen >= 4 ? view.getInt32(0, false) : 'N/A';
			document.getElementById('valUInt64LE').textContent = bLen >= 8 ? view.getBigUint64(0, true).toString() : 'N/A';
			document.getElementById('valFloat32LE').textContent = bLen >= 4 ? view.getFloat32(0, true).toPrecision(6) : 'N/A';
			document.getElementById('valFloat32BE').textContent = bLen >= 4 ? view.getFloat32(0, false).toPrecision(6) : 'N/A';
			document.getElementById('valFloat64LE').textContent = bLen >= 8 ? view.getFloat64(0, true).toPrecision(10) : 'N/A';
			document.getElementById('valFloat64BE').textContent = bLen >= 8 ? view.getFloat64(0, false).toPrecision(10) : 'N/A';

			// ASCII: show printable chars, '.' for non-printable
			let asciiStr = '';
			for (let i = 0; i < Math.min(bLen, 8); i++) {
				const b = bytes[i];
				asciiStr += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
			}
			document.getElementById('valAscii').textContent = bLen >= 1 ? asciiStr : 'N/A';

			// UTF-16 LE
			let utf16str = '';
			for (let i = 0; i + 1 < Math.min(bLen, 8); i += 2) {
				const code = bytes[i] | (bytes[i + 1] << 8);
				utf16str += String.fromCharCode(code);
			}
			document.getElementById('valUtf16le').textContent = bLen >= 2 ? utf16str : 'N/A';

			// Sync with Disassembler if enabled
			if (syncDisasmEnabled) {
				vscode.postMessage({ type: 'syncToDisasm', offset: start });
			}
		}

		function formatBytes(bytes) {
			if (bytes === 0) return '0 B';
			const k = 1024;
			const sizes = ['B', 'KB', 'MB', 'GB'];
			const i = Math.floor(Math.log(bytes) / Math.log(k));
			return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
		}

		function escapeHtml(text) {
			const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
			return text.replace(/[&<>"']/g, m => map[m]);
		}
	</script>
</body>
</html>`;
	}

	private getNonce(): string {
		const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		let nonce = '';
		for (let i = 0; i < 32; i++) {
			nonce += possible.charAt(Math.floor(Math.random() * possible.length));
		}
		return nonce;
	}
}

class HexDocument implements vscode.CustomDocument {
	constructor(
		public readonly uri: vscode.Uri,
		public readonly fileSize: number
	) { }

	dispose(): void { }
}
