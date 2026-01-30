/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - String References Tree Provider
 *  Tree view showing discovered strings
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine, StringReference } from './disassemblerEngine';

export class StringTreeItem extends vscode.TreeItem {
	constructor(
		public readonly stringRef: StringReference,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(stringRef.string.substring(0, 50), collapsibleState);
		this.tooltip = `Address: 0x${stringRef.address.toString(16).toUpperCase()}\nEncoding: ${stringRef.encoding}\nLength: ${stringRef.string.length}`;
		this.description = `0x${stringRef.address.toString(16).toUpperCase()} [${stringRef.encoding}]`;
		this.contextValue = 'string';
		this.iconPath = new vscode.ThemeIcon('symbol-string');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to String',
			arguments: [stringRef.address]
		};
	}
}

export class StringRefProvider implements vscode.TreeDataProvider<StringTreeItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<StringTreeItem | undefined | null | void> = new vscode.EventEmitter<StringTreeItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<StringTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;
	private results: StringReference[] = [];

	constructor(private engine: DisassemblerEngine) {}

	refresh(): void {
		this.results = this.engine.getStrings();
		this._onDidChangeTreeData.fire();
	}

	setResults(results: StringReference[]): void {
		this.results = results;
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: StringTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: StringTreeItem): Thenable<StringTreeItem[]> {
		if (element) {
			return Promise.resolve([]);
		}

		const strings = this.results.length > 0 ? this.results : this.engine.getStrings();
		// Limit to first 100 strings for performance
		return Promise.resolve(
			strings.slice(0, 100).map(str => new StringTreeItem(
				str,
				vscode.TreeItemCollapsibleState.None
			))
		);
	}
}
