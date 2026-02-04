/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { DisassemblerEngine, ExportFunction } from './disassemblerEngine';

export class ExportTreeItem extends vscode.TreeItem {
	constructor(
		public readonly exportFunc: ExportFunction,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(exportFunc.name || `Ordinal_${exportFunc.ordinal}`, collapsibleState);

		const addrHex = exportFunc.address.toString(16).toUpperCase();

		const tooltipLines = [
			`Function: ${exportFunc.name || '(unnamed)'}`,
			`Ordinal: ${exportFunc.ordinal}`,
			`Address: 0x${addrHex}`
		];

		if (exportFunc.isForwarder && exportFunc.forwarderName) {
			tooltipLines.push(`Forwards to: ${exportFunc.forwarderName}`);
		}

		this.tooltip = tooltipLines.join('\n');
		this.description = exportFunc.isForwarder
			? `-> ${exportFunc.forwarderName}`
			: `0x${addrHex} [#${exportFunc.ordinal}]`;
		this.contextValue = exportFunc.isForwarder ? 'exportForwarder' : 'exportFunction';

		// Different icon for forwarders
		if (exportFunc.isForwarder) {
			this.iconPath = new vscode.ThemeIcon('arrow-right', new vscode.ThemeColor('charts.orange'));
		} else {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.green'));
		}

		if (!exportFunc.isForwarder) {
			this.command = {
				command: 'hexcore.disasm.goToAddress',
				title: 'Go to Export',
				arguments: [exportFunc.address]
			};
		}
	}
}

export class ExportTreeProvider implements vscode.TreeDataProvider<ExportTreeItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<ExportTreeItem | undefined | null | void> = new vscode.EventEmitter<ExportTreeItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<ExportTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

	constructor(private engine: DisassemblerEngine) { }

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: ExportTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: ExportTreeItem): Thenable<ExportTreeItem[]> {
		if (element) {
			// Export functions have no children
			return Promise.resolve([]);
		}

		const exports = this.engine.getExports();
		return Promise.resolve(
			exports
				.sort((a, b) => a.ordinal - b.ordinal)
				.map(exp => new ExportTreeItem(
					exp,
					vscode.TreeItemCollapsibleState.None
				))
		);
	}
}

