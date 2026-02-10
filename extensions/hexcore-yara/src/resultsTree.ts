/*---------------------------------------------------------------------------------------------
 *  HexCore YARA - Results Tree Provider v2.1
 *  Scan results with threat scoring and severity icons
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as path from 'path';
import { RuleMatch, ScanResult } from './yaraEngine';

// ── Tree Items ──────────────────────────────────────────────────────────────

export class ThreatScoreItem extends vscode.TreeItem {
	constructor(result: ScanResult) {
		const scoreLabel = result.threatScore >= 75 ? '🔴 CRITICAL' :
			result.threatScore >= 50 ? '🟠 HIGH' :
			result.threatScore >= 25 ? '🟡 MEDIUM' : '🟢 CLEAN';

		super(`Threat Score: ${result.threatScore}/100 — ${scoreLabel}`, vscode.TreeItemCollapsibleState.None);

		this.description = `${result.matches.length} matches | ${result.scanTime}ms`;
		this.tooltip = `File: ${result.file}\nSize: ${(result.fileSize / 1024).toFixed(1)} KB\nScore: ${result.threatScore}/100\nMatches: ${result.matches.length}\nScan Time: ${result.scanTime}ms`;

		const iconId = result.threatScore >= 75 ? 'error' :
			result.threatScore >= 50 ? 'warning' :
			result.threatScore >= 25 ? 'info' : 'pass';
		this.iconPath = new vscode.ThemeIcon(iconId);

		this.command = {
			command: 'hexcore.yara.threatReport',
			title: 'Show Threat Report'
		};
	}
}

export class FileMatchItem extends vscode.TreeItem {
	constructor(public readonly filePath: string, public readonly matches: RuleMatch[]) {
		super(path.basename(filePath), vscode.TreeItemCollapsibleState.Expanded);
		this.tooltip = filePath;
		this.description = `${matches.length} match(es)`;
		this.resourceUri = vscode.Uri.file(filePath);

		// Color by highest severity
		const hasCritical = matches.some(m => m.severity === 'critical');
		const hasHigh = matches.some(m => m.severity === 'high');
		this.iconPath = new vscode.ThemeIcon(
			hasCritical ? 'error' : hasHigh ? 'warning' : 'info'
		);
	}
}

export class CategoryMatchItem extends vscode.TreeItem {
	public readonly categoryMatches: RuleMatch[];

	constructor(category: string, matches: RuleMatch[]) {
		super(category, vscode.TreeItemCollapsibleState.Collapsed);
		this.categoryMatches = matches;
		this.description = `${matches.length} detection(s)`;

		const hasCritical = matches.some(m => m.severity === 'critical');
		const hasHigh = matches.some(m => m.severity === 'high');
		this.iconPath = new vscode.ThemeIcon(
			hasCritical ? 'error' : hasHigh ? 'warning' : 'shield',
			hasCritical ? new vscode.ThemeColor('errorForeground') :
			hasHigh ? new vscode.ThemeColor('editorWarning.foreground') : undefined
		);
	}
}

export class RuleMatchItem extends vscode.TreeItem {
	constructor(public readonly match: RuleMatch) {
		super(match.ruleName, vscode.TreeItemCollapsibleState.Collapsed);

		const family = match.meta.family || 'unknown';
		this.tooltip = `${match.ruleName}\nFamily: ${family}\nSeverity: ${match.severity}\nScore: ${match.score}`;
		this.description = `${family} | ${match.severity} | score:${match.score}`;

		const icon = match.severity === 'critical' ? 'error' :
			match.severity === 'high' ? 'warning' :
			match.severity === 'medium' ? 'info' : 'shield';
		this.iconPath = new vscode.ThemeIcon(icon);
	}
}

export class StringMatchItem extends vscode.TreeItem {
	constructor(
		public readonly filePath: string,
		public readonly stringMatch: { identifier: string; offset: number; data: string }
	) {
		super(`${stringMatch.identifier} @ 0x${stringMatch.offset.toString(16).toUpperCase()}`,
			vscode.TreeItemCollapsibleState.None);
		this.tooltip = stringMatch.data;
		this.description = stringMatch.data.substring(0, 40);
		this.iconPath = new vscode.ThemeIcon('symbol-string');
		this.command = {
			command: 'hexcore.openHexViewAtOffset',
			title: 'Open in Hex Viewer',
			arguments: [vscode.Uri.file(filePath), stringMatch.offset]
		};
	}
}

// ── Tree Provider ───────────────────────────────────────────────────────────

type TreeElement = ThreatScoreItem | FileMatchItem | CategoryMatchItem | RuleMatchItem | StringMatchItem;

export class ResultsTreeProvider implements vscode.TreeDataProvider<TreeElement> {
	private _onDidChangeTreeData = new vscode.EventEmitter<TreeElement | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

	private results: Array<{ file: string; matches: RuleMatch[] }> = [];
	private lastScanResult: ScanResult | null = null;

	setResults(file: string, matches: RuleMatch[]): void {
		const existing = this.results.find(r => r.file === file);
		if (existing) {
			existing.matches = matches;
		} else {
			this.results.push({ file, matches });
		}
		this._onDidChangeTreeData.fire(undefined);
	}

	setScanResult(result: ScanResult): void {
		this.lastScanResult = result;
		this.setResults(result.file, result.matches);
	}

	getLastScanResult(): ScanResult | null {
		return this.lastScanResult;
	}

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: TreeElement): vscode.TreeItem {
		return element;
	}

	getChildren(element?: TreeElement): Thenable<TreeElement[]> {
		if (!element) {
			const items: TreeElement[] = [];

			// Threat score header
			if (this.lastScanResult) {
				items.push(new ThreatScoreItem(this.lastScanResult));
			}

			// File results
			for (const r of this.results) {
				items.push(new FileMatchItem(r.file, r.matches));
			}

			return Promise.resolve(items);
		}

		if (element instanceof FileMatchItem) {
			// Group matches by category
			const byCategory: Record<string, RuleMatch[]> = {};
			for (const m of element.matches) {
				const cat = m.namespace || 'Unknown';
				if (!byCategory[cat]) { byCategory[cat] = []; }
				byCategory[cat].push(m);
			}

			// If only one category, show rule matches directly
			const categories = Object.keys(byCategory);
			if (categories.length === 1) {
				return Promise.resolve(
					element.matches.map(m => new RuleMatchItem(m))
				);
			}

			return Promise.resolve(
				categories.map(cat => new CategoryMatchItem(cat, byCategory[cat]))
			);
		}

		if (element instanceof CategoryMatchItem) {
			return Promise.resolve(
				element.categoryMatches.map(m => new RuleMatchItem(m))
			);
		}

		if (element instanceof RuleMatchItem) {
			const fileResult = this.results.find(r => r.matches.includes(element.match));
			const filePath = fileResult?.file || '';
			return Promise.resolve(
				element.match.strings.slice(0, 20).map(s => new StringMatchItem(filePath, s))
			);
		}

		return Promise.resolve([]);
	}
}
