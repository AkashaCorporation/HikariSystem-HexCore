/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Function Tree Provider
 *  Tree view showing discovered functions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine, Function } from './disassemblerEngine';

export class FunctionTreeItem extends vscode.TreeItem {
	constructor(
		public readonly func: Function,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(func.name, collapsibleState);
		this.tooltip = `Address: 0x${func.address.toString(16).toUpperCase()}\nSize: ${func.size} bytes`;
		this.description = `0x${func.address.toString(16).toUpperCase()} (${func.size} bytes)`;
		this.contextValue = 'function';
		this.iconPath = new vscode.ThemeIcon('symbol-method');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Function',
			arguments: [func.address]
		};
	}
}

export class FunctionTreeProvider implements vscode.TreeDataProvider<FunctionTreeItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<FunctionTreeItem | undefined | null | void> = new vscode.EventEmitter<FunctionTreeItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<FunctionTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

	constructor(private engine: DisassemblerEngine) {}

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: FunctionTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: FunctionTreeItem): Thenable<FunctionTreeItem[]> {
		if (element) {
			// Function details - could show callers/callees
			return Promise.resolve([]);
		}

		const functions = this.engine.getFunctions();
		return Promise.resolve(
			functions.map(func => new FunctionTreeItem(
				func,
				vscode.TreeItemCollapsibleState.None
			))
		);
	}
}
