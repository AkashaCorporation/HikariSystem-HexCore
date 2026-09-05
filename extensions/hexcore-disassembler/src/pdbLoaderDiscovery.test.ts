/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { findPdbutil } from './pdbLoader';

suite('portable PDB tool discovery', () => {
	const childProcess = require('child_process');
	let originalSpawn: typeof childProcess.spawnSync;
	let originalOverride: string | undefined;
	setup(() => { originalSpawn = childProcess.spawnSync; originalOverride = process.env.HEXCORE_PDBUTIL; });
	teardown(() => {
		childProcess.spawnSync = originalSpawn;
		if (originalOverride === undefined) delete process.env.HEXCORE_PDBUTIL;
		else process.env.HEXCORE_PDBUTIL = originalOverride;
	});
	test('prefers an explicit tool override without opening a console', () => {
		process.env.HEXCORE_PDBUTIL = 'C:/Tools/fixture-pdbutil.exe';
		childProcess.spawnSync = (candidate: string, args: string[], options: { windowsHide: boolean }) => {
			assert.strictEqual(candidate, process.env.HEXCORE_PDBUTIL);
			assert.deepStrictEqual(args, ['--version']);
			assert.strictEqual(options.windowsHide, true);
			return { status: 0 };
		};
		assert.strictEqual(findPdbutil(), process.env.HEXCORE_PDBUTIL);
	});
	test('uses generic installation locations and never a developer home', () => {
		delete process.env.HEXCORE_PDBUTIL;
		const attempts: string[] = [];
		childProcess.spawnSync = (candidate: string) => { attempts.push(candidate); return { status: null }; };
		assert.strictEqual(findPdbutil(), null);
		assert.strictEqual(attempts[0], process.platform === 'win32' ? 'llvm-pdbutil.exe' : 'llvm-pdbutil');
		assert.ok(attempts.every(candidate => !/[/\\](Users|home)[/\\]/i.test(candidate)));
	});
});
