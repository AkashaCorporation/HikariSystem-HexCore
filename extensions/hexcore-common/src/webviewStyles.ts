/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Returns the base CSS string for HexCore webviews.
 * Includes CSS custom properties for risk colors, monospace font,
 * toolbar layout, button styles, and risk badge classes.
 */
export function getHexCoreBaseCSS(): string {
	return `
:root {
	--hexcore-safe: #4ec9b0;
	--hexcore-warning: #dcdcaa;
	--hexcore-danger: #f44747;
	--hexcore-mono: Consolas, Monaco, 'Courier New', monospace;
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
`;
}
