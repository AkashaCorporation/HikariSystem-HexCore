/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Memory Tree Provider
 *  Shows memory regions
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DebugEngine } from './debugEngine';

export class MemoryItem extends vscode.TreeItem {
	constructor(address: bigint, size: number, perms: string, name?: string) {
		super(name || `Region 0x${address.toString(16)}`, vscode.TreeItemCollapsibleState.None);
		this.description = `${(size / 1024).toFixed(1)} KB [${perms}]`;
		this.tooltip = `Address: 0x${address.toString(16)}\nSize: ${size} bytes\nPermissions: ${perms}`;
	}
}

export class MemoryTreeProvider implements vscode.TreeDataProvider<MemoryItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<MemoryItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
	private engine: DebugEngine;

	constructor(engine: DebugEngine) {
		this.engine = engine;
	}

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: MemoryItem): vscode.TreeItem {
		return element;
	}

	async getChildren(): Promise<MemoryItem[]> {
		const regions = await this.engine.getMemoryRegions();
		return regions.map(r => new MemoryItem(r.address, r.size, r.permissions, r.name));
	}
}
