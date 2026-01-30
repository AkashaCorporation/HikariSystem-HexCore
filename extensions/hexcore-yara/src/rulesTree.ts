/*---------------------------------------------------------------------------------------------
 *  HexCore YARA - Rules Tree Provider
 *  Shows available YARA rules
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';

export class RuleCategoryItem extends vscode.TreeItem {
	constructor(name: string, count: number) {
		super(name, vscode.TreeItemCollapsibleState.Collapsed);
		this.description = `${count} rules`;
		this.iconPath = new vscode.ThemeIcon('folder');
	}
}

export class RuleItem extends vscode.TreeItem {
	constructor(name: string, description: string) {
		super(name, vscode.TreeItemCollapsibleState.None);
		this.description = description;
		this.iconPath = new vscode.ThemeIcon('shield');
	}
}

export class RulesTreeProvider implements vscode.TreeDataProvider<RuleCategoryItem | RuleItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<RuleCategoryItem | RuleItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

	private categories = [
		{ name: 'Packers', rules: ['UPX', 'VMProtect', 'Themida', 'ASPack'] },
		{ name: 'Malware', rules: ['Trojan', 'Ransomware', 'Spyware'] },
		{ name: 'Behavior', rules: ['Reverse Shell', 'Keylogger', 'Downloader'] },
		{ name: 'Indicators', rules: ['Suspicious API', 'Base64 Executable', 'Shellcode'] }
	];

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: RuleCategoryItem | RuleItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: RuleCategoryItem): Thenable<(RuleCategoryItem | RuleItem)[]> {
		if (!element) {
			return Promise.resolve(
				this.categories.map(c => new RuleCategoryItem(c.name, c.rules.length))
			);
		}

		const category = this.categories.find(c => c.name === element.label);
		if (category) {
			return Promise.resolve(
				category.rules.map(r => new RuleItem(r, 'Built-in rule'))
			);
		}

		return Promise.resolve([]);
	}
}
