/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { DisassemblerEngine, ImportLibrary, ImportFunction } from './disassemblerEngine';

type ImportTreeElement = ImportLibraryItem | ImportFunctionItem;

export class ImportLibraryItem extends vscode.TreeItem {
	constructor(
		public readonly library: ImportLibrary,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(library.name, collapsibleState);

		this.tooltip = `${library.name}\n${library.functions.length} imported function(s)`;
		this.description = `(${library.functions.length})`;
		this.contextValue = 'importLibrary';
		this.iconPath = new vscode.ThemeIcon('library', new vscode.ThemeColor('charts.purple'));
	}
}

export class ImportFunctionItem extends vscode.TreeItem {
	constructor(
		public readonly func: ImportFunction,
		public readonly libraryName: string,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(func.name, collapsibleState);

		const addrHex = func.address.toString(16).toUpperCase();
		const ordinalStr = func.ordinal !== undefined ? ` (Ordinal: ${func.ordinal})` : '';
		const hintStr = func.hint !== undefined ? ` [Hint: ${func.hint}]` : '';

		this.tooltip = [
			`Function: ${func.name}`,
			`Library: ${libraryName}`,
			`IAT Address: 0x${addrHex}`,
			ordinalStr,
			hintStr
		].filter(s => s.length > 0).join('\n');

		this.description = `0x${addrHex}`;
		this.contextValue = 'importFunction';
		this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.blue'));

		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Import',
			arguments: [func.address]
		};
	}
}

export class ImportTreeProvider implements vscode.TreeDataProvider<ImportTreeElement> {
	private _onDidChangeTreeData: vscode.EventEmitter<ImportTreeElement | undefined | null | void> = new vscode.EventEmitter<ImportTreeElement | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<ImportTreeElement | undefined | null | void> = this._onDidChangeTreeData.event;

	constructor(private engine: DisassemblerEngine) { }

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: ImportTreeElement): vscode.TreeItem {
		return element;
	}

	getChildren(element?: ImportTreeElement): Thenable<ImportTreeElement[]> {
		if (!element) {
			// Root level - show libraries
			const imports = this.engine.getImports();
			return Promise.resolve(
				imports.map(lib => new ImportLibraryItem(
					lib,
					lib.functions.length > 0
						? vscode.TreeItemCollapsibleState.Collapsed
						: vscode.TreeItemCollapsibleState.None
				))
			);
		}

		if (element instanceof ImportLibraryItem) {
			// Show functions under library
			return Promise.resolve(
				element.library.functions.map(func => new ImportFunctionItem(
					func,
					element.library.name,
					vscode.TreeItemCollapsibleState.None
				))
			);
		}

		return Promise.resolve([]);
	}

	getParent(element: ImportTreeElement): vscode.ProviderResult<ImportTreeElement> {
		if (element instanceof ImportFunctionItem) {
			const imports = this.engine.getImports();
			const lib = imports.find(l => l.name === element.libraryName);
			if (lib) {
				return new ImportLibraryItem(lib, vscode.TreeItemCollapsibleState.Expanded);
			}
		}
		return undefined;
	}
}

