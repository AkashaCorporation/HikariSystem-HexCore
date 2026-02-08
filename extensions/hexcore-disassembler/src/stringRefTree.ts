/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - String References Tree Provider
 *  Tree view showing discovered strings with cross-references
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DisassemblerEngine, StringReference } from './disassemblerEngine';

type StringTreeElement = StringTreeItem | StringXrefItem;

export class StringTreeItem extends vscode.TreeItem {
	constructor(
		public readonly stringRef: StringReference,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(stringRef.string.substring(0, 80), collapsibleState);

		const refCount = stringRef.references.length;
		const refStr = refCount > 0 ? ` (${refCount} ref${refCount > 1 ? 's' : ''})` : '';

		this.tooltip = [
			`Address: 0x${stringRef.address.toString(16).toUpperCase()}`,
			`Encoding: ${stringRef.encoding}`,
			`Length: ${stringRef.string.length}`,
			`References: ${refCount}`
		].join('\n');

		this.description = `0x${stringRef.address.toString(16).toUpperCase()} [${stringRef.encoding}]${refStr}`;
		this.contextValue = 'string';
		this.iconPath = new vscode.ThemeIcon('symbol-string');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to String',
			arguments: [stringRef.address]
		};
	}
}

export class StringXrefItem extends vscode.TreeItem {
	constructor(
		public readonly refAddress: number,
		private readonly engine: DisassemblerEngine
	) {
		const func = engine.getFunctions().find(
			f => refAddress >= f.address && refAddress < f.endAddress
		);
		const label = func
			? `${func.name}+0x${(refAddress - func.address).toString(16)}`
			: `0x${refAddress.toString(16).toUpperCase()}`;

		super(label, vscode.TreeItemCollapsibleState.None);
		this.description = `0x${refAddress.toString(16).toUpperCase()}`;
		this.contextValue = 'stringXref';
		this.iconPath = new vscode.ThemeIcon('references');
		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Reference',
			arguments: [refAddress]
		};
	}
}

export class StringRefProvider implements vscode.TreeDataProvider<StringTreeElement> {
	private _onDidChangeTreeData: vscode.EventEmitter<StringTreeElement | undefined | null | void> = new vscode.EventEmitter<StringTreeElement | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<StringTreeElement | undefined | null | void> = this._onDidChangeTreeData.event;
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

	getTreeItem(element: StringTreeElement): vscode.TreeItem {
		return element;
	}

	getChildren(element?: StringTreeElement): Thenable<StringTreeElement[]> {
		if (!element) {
			const strings = this.results.length > 0 ? this.results : this.engine.getStrings();
			// Show up to 10000 strings
			return Promise.resolve(
				strings.slice(0, 10000).map(str => new StringTreeItem(
					str,
					str.references.length > 0
						? vscode.TreeItemCollapsibleState.Collapsed
						: vscode.TreeItemCollapsibleState.None
				))
			);
		}

		if (element instanceof StringTreeItem) {
			return Promise.resolve(
				element.stringRef.references.map(addr => new StringXrefItem(addr, this.engine))
			);
		}

		return Promise.resolve([]);
	}
}
