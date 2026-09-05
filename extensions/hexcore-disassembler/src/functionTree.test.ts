/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';

suite('function tree lazy visibility', () => {
	let tree: typeof import('./functionTree');
	suiteSetup(() => {
		const Module = require('module');
		const original = Module._load;
		Module._load = function (this: unknown, id: string, ...args: unknown[]) {
			if (id === 'vscode') return {
				TreeItem: class { constructor(public label: string, public collapsibleState: number) {} },
				ThemeIcon: class { constructor(public id: string) {} },
				TreeItemCollapsibleState: { None: 0, Collapsed: 1 },
				EventEmitter: class { event = () => {}; fire() {} },
			};
			return original.call(this, id, ...args);
		};
		try { tree = require('./functionTree'); } finally { Module._load = original; }
	});
	test('lists lazy, partial and complete functions without decoding any body', async () => {
		const functions = [1, 2, 3].map(address => ({ address, name: `f${address}`, size: 16, callers: [], callees: [], instructions: [] }));
		const statuses = new Map([[1, 'lazy'], [2, 'partial'], [3, 'materialized']]);
		const engine = {
			getFunctions: () => functions,
			getFunctionBodyStatus: (address: number) => statuses.get(address),
			materializeFunction: () => { throw new Error('tree must not force eager decoding'); },
		} as unknown as import('./disassemblerEngine').DisassemblerEngine;
		const provider = new tree.FunctionTreeProvider(engine);
		const items = await provider.getChildren();
		assert.strictEqual(items.length, 3);
		assert.ok(String(items[0].description).includes('[lazy]'));
		assert.ok(String(items[1].description).includes('[partial]'));
		assert.ok(String(items[2].description).includes('[materialized]'));
		assert.ok(String(items[0].tooltip).includes('Known callers: 0'));
		assert.ok(String(items[0].tooltip).includes('Reference completeness: not established'));
		assert.strictEqual(items[0].command?.command, 'hexcore.disasm.goToAddress');
		assert.deepStrictEqual(items[0].command?.arguments, [1]);
	});
	test('empty decode is not labeled as complete', () => {
		const func = { address: 1, name: 'empty', size: 1, callers: [], callees: [] } as unknown as import('./disassemblerEngine').Function;
		const item = new tree.FunctionTreeItem(func, 0, 'decode-empty');
		assert.ok(String(item.description).includes('[decode-empty]'));
		assert.strictEqual((item.iconPath as { id: string }).id, 'warning');
	});
});
