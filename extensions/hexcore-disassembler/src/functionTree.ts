/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Function Tree Provider
 *  Tree view showing discovered functions with callers/callees
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine, Function } from './disassemblerEngine';

type FunctionTreeElement = FunctionTreeItem | FunctionRefGroupItem | FunctionRefItem;

export class FunctionTreeItem extends vscode.TreeItem {
	constructor(
		public readonly func: Function,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(func.name, collapsibleState);
		const callerCount = func.callers.length;
		const calleeCount = func.callees.length;
		this.tooltip = `Address: 0x${func.address.toString(16).toUpperCase()}\nSize: ${func.size} bytes\nCallers: ${callerCount}\nCallees: ${calleeCount}`;
		this.description = `0x${func.address.toString(16).toUpperCase()} (${func.size}b)`;
		this.contextValue = 'function';
		this.iconPath = new vscode.ThemeIcon('symbol-method');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Function',
			arguments: [func.address]
		};
	}
}

export class FunctionRefGroupItem extends vscode.TreeItem {
	constructor(
		public readonly groupType: 'callers' | 'callees',
		public readonly addresses: number[],
		public readonly engine: DisassemblerEngine
	) {
		super(
			groupType === 'callers' ? `Callers (${addresses.length})` : `Callees (${addresses.length})`,
			addresses.length > 0 ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None
		);
		this.iconPath = new vscode.ThemeIcon(
			groupType === 'callers' ? 'call-incoming' : 'call-outgoing'
		);
		this.contextValue = groupType;
	}
}

export class FunctionRefItem extends vscode.TreeItem {
	constructor(
		public readonly address: number,
		public readonly engine: DisassemblerEngine
	) {
		const func = engine.getFunctionAt(address);
		const name = func ? func.name : `sub_${address.toString(16).toUpperCase()}`;
		super(name, vscode.TreeItemCollapsibleState.None);
		this.description = `0x${address.toString(16).toUpperCase()}`;
		this.contextValue = 'functionRef';
		this.iconPath = new vscode.ThemeIcon('symbol-method');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Function',
			arguments: [address]
		};
	}
}

export class FunctionTreeProvider implements vscode.TreeDataProvider<FunctionTreeElement> {
	private _onDidChangeTreeData: vscode.EventEmitter<FunctionTreeElement | undefined | null | void> = new vscode.EventEmitter<FunctionTreeElement | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<FunctionTreeElement | undefined | null | void> = this._onDidChangeTreeData.event;

	constructor(private engine: DisassemblerEngine) {}

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: FunctionTreeElement): vscode.TreeItem {
		return element;
	}

	getChildren(element?: FunctionTreeElement): Thenable<FunctionTreeElement[]> {
		if (!element) {
			// Root level - show functions
			const functions = this.engine.getFunctions();
			return Promise.resolve(
				functions.map(func => {
					const hasChildren = func.callers.length > 0 || func.callees.length > 0;
					return new FunctionTreeItem(
						func,
						hasChildren ? vscode.TreeItemCollapsibleState.Collapsed : vscode.TreeItemCollapsibleState.None
					);
				})
			);
		}

		if (element instanceof FunctionTreeItem) {
			// Show callers and callees groups
			const groups: FunctionTreeElement[] = [];
			if (element.func.callers.length > 0) {
				groups.push(new FunctionRefGroupItem('callers', element.func.callers, this.engine));
			}
			if (element.func.callees.length > 0) {
				groups.push(new FunctionRefGroupItem('callees', element.func.callees, this.engine));
			}
			return Promise.resolve(groups);
		}

		if (element instanceof FunctionRefGroupItem) {
			// Show individual references
			return Promise.resolve(
				element.addresses.map(addr => new FunctionRefItem(addr, element.engine))
			);
		}

		return Promise.resolve([]);
	}
}
