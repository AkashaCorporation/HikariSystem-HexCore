/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Register Tree Provider
 *  Shows CPU register state
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import { DebugEngine } from './debugEngine';

export class RegisterItem extends vscode.TreeItem {
	constructor(name: string, value: bigint) {
		super(name, vscode.TreeItemCollapsibleState.None);
		this.description = `0x${value.toString(16).toUpperCase().padStart(16, '0')}`;
		this.tooltip = `${name}: ${value.toString()} (decimal)`;
	}
}

export class RegisterTreeProvider implements vscode.TreeDataProvider<RegisterItem> {
	private _onDidChangeTreeData = new vscode.EventEmitter<RegisterItem | undefined>();
	readonly onDidChangeTreeData = this._onDidChangeTreeData.event;
	private engine: DebugEngine;

	constructor(engine: DebugEngine) {
		this.engine = engine;
		engine.onEvent(() => this.refresh());
	}

	refresh(): void {
		this._onDidChangeTreeData.fire(undefined);
	}

	getTreeItem(element: RegisterItem): vscode.TreeItem {
		return element;
	}

	getChildren(): Thenable<RegisterItem[]> {
		const regs = this.engine.getRegisters();
		const items: RegisterItem[] = [];
		
		if (regs.rax) items.push(new RegisterItem('RAX', regs.rax));
		if (regs.rbx) items.push(new RegisterItem('RBX', regs.rbx));
		if (regs.rcx) items.push(new RegisterItem('RCX', regs.rcx));
		if (regs.rdx) items.push(new RegisterItem('RDX', regs.rdx));
		if (regs.rsi) items.push(new RegisterItem('RSI', regs.rsi));
		if (regs.rdi) items.push(new RegisterItem('RDI', regs.rdi));
		if (regs.rbp) items.push(new RegisterItem('RBP', regs.rbp));
		if (regs.rsp) items.push(new RegisterItem('RSP', regs.rsp));
		if (regs.rip) items.push(new RegisterItem('RIP', regs.rip));
		if (regs.r8) items.push(new RegisterItem('R8', regs.r8));
		if (regs.r9) items.push(new RegisterItem('R9', regs.r9));
		if (regs.r10) items.push(new RegisterItem('R10', regs.r10));
		if (regs.r11) items.push(new RegisterItem('R11', regs.r11));
		if (regs.r12) items.push(new RegisterItem('R12', regs.r12));
		if (regs.r13) items.push(new RegisterItem('R13', regs.r13));
		if (regs.r14) items.push(new RegisterItem('R14', regs.r14));
		if (regs.r15) items.push(new RegisterItem('R15', regs.r15));
		if (regs.rflags) items.push(new RegisterItem('RFLAGS', regs.rflags));

		return Promise.resolve(items);
	}
}
