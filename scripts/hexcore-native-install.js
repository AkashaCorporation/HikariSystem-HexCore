/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const cwd = process.cwd();
const pkgPath = path.join(cwd, 'package.json');

if (!fs.existsSync(pkgPath)) {
	console.error('[hexcore-native-install] package.json not found in', cwd);
	process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const moduleName = pkg.name || 'unknown';

function run(command, args) {
	const result = spawnSync(command, args, {
		cwd,
		stdio: 'inherit',
		shell: true,
		env: process.env
	});

	if (result.error) {
		return { ok: false, error: result.error.message };
	}

	if (result.status !== 0) {
		return { ok: false, error: `Exit code ${result.status}` };
	}

	return { ok: true };
}

function resolveBin(name) {
	const binName = process.platform === 'win32' ? `${name}.cmd` : name;
	const localBin = path.join(cwd, 'node_modules', '.bin', binName);
	return fs.existsSync(localBin) ? localBin : name;
}

function findBinaryDir() {
	const dirCandidates = [
		path.join(cwd, 'prebuilds', `${process.platform}-${process.arch}`),
		path.join(cwd, 'build', 'Release'),
		path.join(cwd, 'build', 'Debug'),
		path.join(cwd, 'lib', 'binding', `${process.platform}-${process.arch}`)
	];

	for (const dir of dirCandidates) {
		if (!fs.existsSync(dir)) {
			continue;
		}
		const entries = fs.readdirSync(dir);
		if (entries.some(entry => entry.endsWith('.node'))) {
			return dir;
		}
	}

	return undefined;
}

function copyIfExists(src, destDir) {
	if (!fs.existsSync(src)) {
		return;
	}

	const dest = path.join(destDir, path.basename(src));
	if (!fs.existsSync(dest)) {
		fs.copyFileSync(src, dest);
	}
}

function copyUnicornRuntimeDeps(binaryDir) {
	const depsDir = path.join(cwd, 'deps', 'unicorn');
	if (!fs.existsSync(depsDir)) {
		return;
	}

	if (process.platform === 'win32') {
		copyIfExists(path.join(depsDir, 'unicorn.dll'), binaryDir);
		return;
	}

	if (process.platform === 'linux') {
		copyIfExists(path.join(depsDir, 'libunicorn.so'), binaryDir);
		copyIfExists(path.join(depsDir, 'libunicorn.so.2'), binaryDir);
		return;
	}

	if (process.platform === 'darwin') {
		copyIfExists(path.join(depsDir, 'libunicorn.dylib'), binaryDir);
		copyIfExists(path.join(depsDir, 'libunicorn.2.dylib'), binaryDir);
	}
}

console.log(`[hexcore-native-install] Installing native module: ${moduleName}`);

const useNapiRuntime = Boolean(pkg.binary && Array.isArray(pkg.binary.napi_versions) && pkg.binary.napi_versions.length > 0);
const prebuildArgs = useNapiRuntime ? ['--verbose', '--runtime', 'napi'] : ['--verbose'];
const prebuildCmd = resolveBin('prebuild-install');
const prebuildResult = run(prebuildCmd, prebuildArgs);
if (!prebuildResult.ok) {
	console.warn(`[hexcore-native-install] prebuild-install failed: ${prebuildResult.error}`);
	const nodeGypCmd = resolveBin('node-gyp');
	const buildResult = run(nodeGypCmd, ['rebuild']);
	if (!buildResult.ok) {
		console.error(`[hexcore-native-install] node-gyp rebuild failed: ${buildResult.error}`);
		process.exit(1);
	}
}

const binaryDir = findBinaryDir();
if (binaryDir && moduleName === 'hexcore-unicorn') {
	copyUnicornRuntimeDeps(binaryDir);
}
