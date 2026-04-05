/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { DisassemblerEngine, ImportLibrary, ImportFunction } from './disassemblerEngine';
import { lookupApi, formatApiSignature, CATEGORY_LABELS } from './peApiDatabase';

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
		const ordinalStr = func.ordinal !== undefined ? `Ordinal: ${func.ordinal}` : '';
		const hintStr = func.hint !== undefined ? `Hint: ${func.hint}` : '';

		// v3.7.5: Resolve API signature from database
		const apiSig = lookupApi(func.name);

		const tooltipLines = [
			`Function: ${func.name}`,
			`Library: ${libraryName}`,
			`IAT Address: 0x${addrHex}`,
		];
		if (ordinalStr) { tooltipLines.push(ordinalStr); }
		if (hintStr) { tooltipLines.push(hintStr); }

		if (apiSig) {
			tooltipLines.push('');
			tooltipLines.push(formatApiSignature(apiSig));
			tooltipLines.push('');
			tooltipLines.push(`Category: ${CATEGORY_LABELS[apiSig.category] || apiSig.category}`);
			if (apiSig.tags.length > 0) {
				tooltipLines.push(`Tags: ${apiSig.tags.join(', ')}`);
			}
		}

		this.tooltip = tooltipLines.join('\n');

		// v3.7.5: Show category in description alongside address
		if (apiSig) {
			this.description = `0x${addrHex}  [${apiSig.category}]`;
		} else {
			this.description = `0x${addrHex}`;
		}

		this.contextValue = 'importFunction';

		// v3.7.5: Color-code icons by security relevance
		if (apiSig && (apiSig.category === 'injection' || apiSig.tags.includes('shellcode'))) {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.red'));
		} else if (apiSig && (apiSig.category === 'network' || apiSig.category === 'crypto')) {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.orange'));
		} else if (apiSig && (apiSig.category === 'hook' || apiSig.tags.includes('keylogger'))) {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.red'));
		} else if (apiSig && (apiSig.tags.includes('anti_debug') || apiSig.tags.includes('evasion'))) {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.yellow'));
		} else {
			this.iconPath = new vscode.ThemeIcon('symbol-function', new vscode.ThemeColor('charts.blue'));
		}

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

