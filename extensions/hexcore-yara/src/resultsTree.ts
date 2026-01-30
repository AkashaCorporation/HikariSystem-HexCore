/*---------------------------------------------------------------------------------------------
 *  HexCore YARA - Results Tree Provider
 *  Shows scan results
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { RuleMatch } from './yaraEngine';

export class FileMatchItem extends vscode.TreeItem {
	constructor(public readonly filePath: string, public readonly matches: RuleMatch[]) {
		super(vscode.Uri.file(filePath).fsPath.split(/[\\/]/).pop() || 'Unknown', 
			vscode.TreeItemCollapsibleState.Expanded);
		this.tooltip = filePath;
		this.description = `${matches.length} match(es)`;
		this.iconPath = new vscode.ThemeIcon('warning');
	}
}

export class RuleMatchItem extends vscode.TreeItem {
	constructor(public readonly match: RuleMatch) {
		super(match.ruleName, vscode.TreeItemCollapsibleState.Collapsed);
		this.tooltip = match.meta.description || match.ruleName;
		this.description = match.namespace;
		
		const severity = match.meta.severity || 'medium';
		if (severity === 'critical' || severity === 'high') {
			this.iconPath = new vscode.ThemeIcon('error');
		} else {
			this.iconPath = new vscode.ThemeIcon('warning');
		}
	}
}

export class StringMatchItem extends vscode.TreeItem {
	constructor(
		public readonly filePath: string,
		public readonly stringMatch: { identifier: string; offset: number; data: string }
	) {
		super(`${stringMatch.identifier} @ 0x${stringMatch.offset.toString(16)}`, 
			vscode.TreeItemCollapsibleState.None);
		this.tooltip = stringMatch.data;
		this.description = stringMatch.data.substring(0, 30);
		this.iconPath = new vscode.ThemeIcon('symbol-string');
		this.command = {
			command: 'hexcore.openHexViewAtOffset',
			title: 'Open in Hex Viewer',
			arguments: [vscode.Uri.file(filePath), stringMatch.offset]
		};
	}
}

export class ResultsTreeProvider implements vscode.TreeDataProvider<FileMatchItem | RuleMatchItem | StringMatchItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<FileMatchItem | RuleMatchItem | StringMatchItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
	private results: Array<{ file: string; matches: RuleMatch[] }> = [];

	setResults(file: string, matches: RuleMatch[]): void {
		// Check if file already exists in results
		const existing = this.results.find(r => r.file === file);
		if (existing) {
			existing.matches = matches;
		} else {
			this.results.push({ file, matches });
		}
		this._onDidChangeTreeData.fire(undefined);
	}

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: FileMatchItem | RuleMatchItem | StringMatchItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: FileMatchItem | RuleMatchItem): Thenable<(FileMatchItem | RuleMatchItem | StringMatchItem)[]> {
		if (!element) {
			// Root level - return files
			return Promise.resolve(
				this.results.map(r => new FileMatchItem(r.file, r.matches))
			);
		}

		if (element instanceof FileMatchItem) {
			// File level - return rule matches
			return Promise.resolve(
				element.matches.map(m => new RuleMatchItem(m))
			);
		}

		if (element instanceof RuleMatchItem) {
			// Rule level - return string matches
			// Find the file path for this rule match
			const fileResult = this.results.find(r => r.matches.includes(element.match));
			const filePath = fileResult?.file || '';
			return Promise.resolve(
				element.match.strings.map(s => new StringMatchItem(filePath, s))
			);
		}

		return Promise.resolve([]);
	}
}
