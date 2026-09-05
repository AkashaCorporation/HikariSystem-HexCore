/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

function verifyRuntimes({ appRoot, manifest, execute = spawnSync }) {
	const root = path.resolve(appRoot);
	if (manifest.platform !== process.platform || manifest.arch !== process.arch) throw new Error('Runtime smoke must run on the packaged platform/architecture');
	return manifest.engines.filter(engine => engine.active).map(engine => {
		const extensionRoot = path.join(root, 'extensions', engine.id);
		let executable = process.execPath;
		let args;
		if (engine.id === 'hexcore-revenant') {
			executable = path.resolve(root, engine.primaryRuntime);
			args = ['--version'];
		} else {
			const entry = path.join(extensionRoot, 'index.js');
			args = ['-e', 'require(process.argv[1]); console.log("HEXCORE_RUNTIME_LOADED");', entry];
		}
		const child = execute(executable, args, { cwd: extensionRoot, encoding: 'utf8', timeout: 30000, maxBuffer: 1024 * 1024, windowsHide: true });
		const loaded = engine.id === 'hexcore-revenant' ? /^revenant-engine:\s*\S+/m.test(String(child.stdout)) : String(child.stdout).includes('HEXCORE_RUNTIME_LOADED');
		return {
			id: engine.id, packageVersion: engine.version, primaryRuntime: engine.primaryRuntime,
			ok: child.status === 0 && !child.error && loaded,
			exitCode: child.status, timedOut: child.error?.code === 'ETIMEDOUT',
			...(child.error ? { error: child.error.message } : {}),
			stderrTail: String(child.stderr ?? '').slice(-3000),
		};
	});
}

if (require.main === module) {
	try {
		const args = process.argv.slice(2);
		const readArg = key => args[args.indexOf(key) + 1];
		if (!args.includes('--app-root') || !args.includes('--manifest') || !args.includes('--output')) throw new Error('Required: --app-root --manifest --output');
		const manifest = JSON.parse(fs.readFileSync(readArg('--manifest'), 'utf8'));
		const results = verifyRuntimes({ appRoot: readArg('--app-root'), manifest });
		const report = { scope: 'native-load-and-bundled-cli-version', passed: results.every(result => result.ok), results };
		fs.writeFileSync(readArg('--output'), `${JSON.stringify(report, null, 2)}\n`);
		console.log(JSON.stringify(report));
		if (!report.passed) process.exitCode = 1;
	} catch (error) { console.error(error.message); process.exitCode = 1; }
}
module.exports = { verifyRuntimes };
