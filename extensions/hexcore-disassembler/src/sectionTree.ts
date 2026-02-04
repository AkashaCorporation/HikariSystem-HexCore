/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as vscode from 'vscode';
import { DisassemblerEngine, Section } from './disassemblerEngine';

export class SectionTreeItem extends vscode.TreeItem {
	constructor(
		public readonly section: Section,
		public readonly collapsibleState: vscode.TreeItemCollapsibleState
	) {
		super(section.name, collapsibleState);

		const permissions = section.permissions;
		const sizeKB = (section.virtualSize / 1024).toFixed(2);

		this.tooltip = [
			`Name: ${section.name}`,
			`Virtual Address: 0x${section.virtualAddress.toString(16).toUpperCase()}`,
			`Virtual Size: ${section.virtualSize} bytes (${sizeKB} KB)`,
			`Raw Address: 0x${section.rawAddress.toString(16).toUpperCase()}`,
			`Raw Size: ${section.rawSize} bytes`,
			`Permissions: ${permissions}`,
			`Code: ${section.isCode ? 'Yes' : 'No'}`,
			`Data: ${section.isData ? 'Yes' : 'No'}`
		].join('\n');

		this.description = `${permissions} | 0x${section.virtualAddress.toString(16).toUpperCase()} (${sizeKB} KB)`;
		this.contextValue = 'section';

		// Icon based on section type
		if (section.isCode) {
			this.iconPath = new vscode.ThemeIcon('code', new vscode.ThemeColor('charts.blue'));
		} else if (section.isData && section.isWritable) {
			this.iconPath = new vscode.ThemeIcon('file-binary', new vscode.ThemeColor('charts.yellow'));
		} else if (section.isData) {
			this.iconPath = new vscode.ThemeIcon('file-binary', new vscode.ThemeColor('charts.green'));
		} else {
			this.iconPath = new vscode.ThemeIcon('symbol-misc');
		}

		this.command = {
			command: 'hexcore.disasm.goToAddress',
			title: 'Go to Section',
			arguments: [section.virtualAddress]
		};
	}
}

export class SectionTreeProvider implements vscode.TreeDataProvider<SectionTreeItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<SectionTreeItem | undefined | null | void> = new vscode.EventEmitter<SectionTreeItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<SectionTreeItem | undefined | null | void> = this._onDidChangeTreeData.event;

	constructor(private engine: DisassemblerEngine) { }

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: SectionTreeItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: SectionTreeItem): Thenable<SectionTreeItem[]> {
		if (element) {
			// Section details could be expanded here
			return Promise.resolve([]);
		}

		const sections = this.engine.getSections();
		return Promise.resolve(
			sections.map(section => new SectionTreeItem(
				section,
				vscode.TreeItemCollapsibleState.None
			))
		);
	}
}

