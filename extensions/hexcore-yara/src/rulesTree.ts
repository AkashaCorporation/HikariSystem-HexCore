/*---------------------------------------------------------------------------------------------
 *  HexCore YARA - Rules Tree Provider v3.5.3
 *  Dynamic categories from DefenderYara + built-in rules
 *  Shows count per category and loading status
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { YaraEngine } from './yaraEngine';

export class RuleCategoryItem extends vscode.TreeItem {
	public readonly categoryName: string;
	public readonly ruleCount: number;
	public readonly isLoaded: boolean;

	constructor(name: string, count: number, loaded: boolean = false, isDefender: boolean = false) {
		super(name, vscode.TreeItemCollapsibleState.Collapsed);
		this.categoryName = name;
		this.ruleCount = count;
		this.isLoaded = loaded;
		this.description = loaded ? `${count} rules (loaded)` : `${count} rules`;
		this.tooltip = loaded
			? `${name}: ${count} rules loaded and ready for scanning`
			: `${name}: ${count} rules available — click to load`;
		this.iconPath = new vscode.ThemeIcon(
			isDefender ? 'shield' : 'folder',
			loaded ? new vscode.ThemeColor('charts.green') : undefined
		);

		if (!loaded && isDefender) {
			this.contextValue = 'defenderCategory';
		}
	}
}

export class RuleItem extends vscode.TreeItem {
	constructor(name: string, description: string, severity?: string) {
		super(name, vscode.TreeItemCollapsibleState.None);
		this.description = description;

		const icon = severity === 'critical' ? 'error' :
			severity === 'high' ? 'warning' :
				severity === 'medium' ? 'info' : 'shield';
		this.iconPath = new vscode.ThemeIcon(icon);
	}
}

export class RuleStatsItem extends vscode.TreeItem {
	constructor(label: string, detail: string, isLoading: boolean = false) {
		super(label, vscode.TreeItemCollapsibleState.None);
		this.description = detail;
		this.iconPath = new vscode.ThemeIcon(isLoading ? 'sync~spin' : 'graph');
	}
}

export class RulesTreeProvider implements vscode.TreeDataProvider<RuleCategoryItem | RuleItem | RuleStatsItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<RuleCategoryItem | RuleItem | RuleStatsItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

	private builtinCategories = [
		{ name: 'Packers', rules: ['UPX_Packed', 'VMProtect', 'Themida'], severity: 'medium' },
		{ name: 'Behavior', rules: ['Suspicious_API', 'Base64_Executable', 'Shellcode_Pattern', 'PE_Reverse_Shell'], severity: 'high' },
	];

	private defenderCategories: Array<{ name: string; count: number; loaded: boolean }> = [];
	private totalCatalog: number = 0;
	private totalLoaded: number = 0;
	private isLoading: boolean = false;

	setLoading(loading: boolean): void {
		this.isLoading = loading;
		this._onDidChangeTreeData.fire(undefined);
	}

	updateFromEngine(engine: YaraEngine): void {
		const stats = engine.getCatalogStats();
		this.totalCatalog = stats.total;
		this.totalLoaded = stats.loaded;

		this.defenderCategories = Object.entries(stats.categories)
			.sort((a, b) => b[1] - a[1])
			.map(([name, count]) => {
				const loadedEntries = engine.getCatalog().filter(e => e.category === name && e.loaded);
				return { name, count, loaded: loadedEntries.length > 0 };
			});

		this._onDidChangeTreeData.fire(undefined);
	}

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: RuleCategoryItem | RuleItem | RuleStatsItem): vscode.TreeItem {
		return element;
	}

	getChildren(element?: RuleCategoryItem): Thenable<(RuleCategoryItem | RuleItem | RuleStatsItem)[]> {
		if (!element) {
			const items: (RuleCategoryItem | RuleItem | RuleStatsItem)[] = [];

			// Stats header with loading status
			if (this.totalCatalog > 0 || this.isLoading) {
				const statusText = this.isLoading ? 'Loading...' :
					`${this.totalCatalog.toLocaleString()} indexed | ${this.totalLoaded.toLocaleString()} loaded`;
				items.push(new RuleStatsItem('DefenderYara', statusText, this.isLoading));
			}

			// Built-in categories
			for (const cat of this.builtinCategories) {
				items.push(new RuleCategoryItem(cat.name, cat.rules.length, true, false));
			}

			// DefenderYara categories
			for (const cat of this.defenderCategories) {
				items.push(new RuleCategoryItem(cat.name, cat.count, cat.loaded, true));
			}

			return Promise.resolve(items);
		}

		if (element instanceof RuleCategoryItem) {
			// Built-in category children
			const builtin = this.builtinCategories.find(c => c.name === element.categoryName);
			if (builtin) {
				return Promise.resolve(
					builtin.rules.map(r => new RuleItem(r, 'Built-in rule', builtin.severity))
				);
			}

			// DefenderYara category — show summary
			const defCat = this.defenderCategories.find(c => c.name === element.categoryName);
			if (defCat) {
				if (defCat.loaded) {
					return Promise.resolve([
						new RuleItem(`${defCat.count} rules loaded`, 'Ready for scanning', 'medium')
					]);
				} else {
					return Promise.resolve([
						new RuleItem('Not loaded', 'Use "YARA: Load Category" to activate', 'info')
					]);
				}
			}
		}

		return Promise.resolve([]);
	}
}
