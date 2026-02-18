/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Trace View
 *  TreeDataProvider for API/libc call trace display
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { TraceManager, TraceEntry } from './traceManager';

/**
 * Tree item representing a single API/libc call trace entry.
 * Displays function name as label with library, arguments, return value and PC as details.
 */
export class TraceItem extends vscode.TreeItem {
	constructor(entry: TraceEntry, index: number) {
		super(`${entry.functionName}`, vscode.TreeItemCollapsibleState.None);

		const argsStr = entry.arguments.length > 0
			? entry.arguments.join(', ')
			: '(none)';

		this.description = `[${entry.library}] → ${entry.returnValue}`;
		this.tooltip = new vscode.MarkdownString(
			`**#${index + 1} ${entry.functionName}**\n\n`
			+ `| Field | Value |\n`
			+ `|-------|-------|\n`
			+ `| Library | ${entry.library} |\n`
			+ `| Arguments | ${argsStr} |\n`
			+ `| Return | ${entry.returnValue} |\n`
			+ `| PC | ${entry.pcAddress} |\n`
			+ `| Time | ${new Date(entry.timestamp).toISOString()} |`
		);
		this.iconPath = new vscode.ThemeIcon('symbol-event');
	}
}

/**
 * Provides trace entries as a flat tree for the Trace Panel sidebar view.
 * Subscribes to TraceManager.onEntry() for real-time updates.
 */
export class TraceTreeProvider implements vscode.TreeDataProvider<TraceItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<TraceItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

	private traceManager: TraceManager;

	constructor(traceManager: TraceManager) {
		this.traceManager = traceManager;

		// Subscribe to real-time trace updates
		this.traceManager.onEntry(() => {
			this.refresh();
		});
	}

	/**
	 * Force a refresh of the tree view.
	 */
	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: TraceItem): vscode.TreeItem {
		return element;
	}

	getChildren(): Thenable<TraceItem[]> {
		const entries = this.traceManager.getEntries();
		const items = entries.map((entry, index) => new TraceItem(entry, index));
		return Promise.resolve(items);
	}
}
