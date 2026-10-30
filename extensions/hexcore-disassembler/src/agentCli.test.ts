/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as path from 'path';
import { main, packagedBootstrapArguments } from './agentCli';

suite('Agent Bridge CLI', () => {
	test('prints standalone help without requiring a running bridge', async () => {
		const stdout: string[] = [];
		const stderr: string[] = [];
		const code = await main(['help'], { stdout: value => stdout.push(value), stderr: value => stderr.push(value) });
		assert.strictEqual(code, 0);
		assert.strictEqual(stderr.length, 0);
		assert.ok(stdout[0].includes('HexCore Agent Bridge CLI v1'));
		assert.ok(stdout[0].includes('submit'));
		assert.ok(stdout[0].includes('validate'));
		assert.ok(stdout[0].includes('schema'));
		assert.ok(stdout[0].includes('--summary'));
	});

	test('builds a bounded packaged bootstrap request for the authenticated workspace', () => {
		const args = packagedBootstrapArguments('C:\\cases\\sample', 'C:\\profiles\\isolated');
		assert.deepStrictEqual(args, [
			'--user-data-dir', path.resolve('C:\\profiles\\isolated'),
			'--reuse-window', path.resolve('C:\\cases\\sample'),
			'--open-url', 'vscode://command/hexcore.agentBridge.activate',
		]);
	});
});
