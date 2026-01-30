/*---------------------------------------------------------------------------------------------
 *  HexCore AI - Insights Tree Provider
 *  Shows AI-generated insights and findings
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { AIAnalysisEngine } from './aiEngine';

export class InsightItem extends vscode.TreeItem {
	constructor(
		public readonly type: string,
		public readonly label: string,
		public readonly description: string
	) {
		super(label, vscode.TreeItemCollapsibleState.None);
		this.tooltip = description;
		this.contextValue = type;
		
		const icons: Record<string, string> = {
			vulnerability: 'warning',
			function: 'symbol-method',
			string: 'symbol-string',
			insight: 'lightbulb'
		};
		this.iconPath = new vscode.ThemeIcon(icons[type] || 'info');
	}
}

export class InsightsTreeProvider implements vscode.TreeDataProvider<InsightItem> {
	private _onDidChangeTreeData: vscode.EventEmitter<InsightItem | undefined | null | void> = new vscode.EventEmitter<InsightItem | undefined | null | void>();
	readonly onDidChangeTreeData: vscode.Event<InsightItem | undefined | null | void> = this._onDidChangeTreeData.event;
	private customInsights: InsightItem[] = [];

	constructor(private engine: AIAnalysisEngine) {}

	refresh(): void {
		this._onDidChangeTreeData.fire();
	}

	addInsight(type: string, title: string, content: string): void {
		this.customInsights.push(new InsightItem(type, title, content));
		this._onDidChangeTreeData.fire();
	}

	clearInsights(): void {
		this.customInsights = [];
		this._onDidChangeTreeData.fire();
	}

	getTreeItem(element: InsightItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: InsightItem): Thenable<InsightItem[]> {
		if (element) {
			return Promise.resolve([]);
		}

		const engineInsights = this.engine.getInsights().map(i => 
			new InsightItem(i.type, i.title, i.content)
		);
		
		return Promise.resolve([...this.customInsights, ...engineInsights]);
	}
}
