/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const moduleRoot = path.resolve(__dirname, '..');
const platformArch = `${process.platform}-${process.arch}`;
const outputDir = path.join(moduleRoot, 'prebuilds', platformArch);

function resolveNpmCommand() {
	return process.platform === 'win32' ? 'npm.cmd' : 'npm';
}

function run(command, args) {
	const result = spawnSync(command, args, {
		cwd: moduleRoot,
		stdio: 'inherit',
		shell: true,
		env: process.env
	});

	if (result.error) {
		throw result.error;
	}

	if (result.status !== 0) {
		throw new Error(`${command} ${args.join(' ')} failed with exit code ${result.status}`);
	}
}

function ensureDir(dir) {
	fs.mkdirSync(dir, { recursive: true });
}

function tryResolveBetterSqlite3Root() {
	const packageJsonPath = require.resolve('better-sqlite3/package.json', {
		paths: [moduleRoot]
	});
	return path.dirname(packageJsonPath);
}

function findNativeBinaryPaths(packageRoot) {
	const binaries = [];

	const releaseBinary = path.join(packageRoot, 'build', 'Release', 'better_sqlite3.node');
	if (fs.existsSync(releaseBinary)) {
		binaries.push(releaseBinary);
	}

	const debugBinary = path.join(packageRoot, 'build', 'Debug', 'better_sqlite3.node');
	if (fs.existsSync(debugBinary)) {
		binaries.push(debugBinary);
	}

	const prebuildDir = path.join(packageRoot, 'prebuilds', platformArch);
	if (fs.existsSync(prebuildDir)) {
		for (const entry of fs.readdirSync(prebuildDir)) {
			const fullPath = path.join(prebuildDir, entry);
			if (entry.endsWith('.node') && fs.statSync(fullPath).isFile()) {
				binaries.push(fullPath);
			}
		}
	}

	return binaries;
}

function copyBinary(src, destFileName) {
	ensureDir(outputDir);
	const target = path.join(outputDir, destFileName);
	fs.copyFileSync(src, target);
	return target;
}

function writeMetadata(binaryPaths) {
	const metadata = {
		module: 'hexcore-better-sqlite3',
		sourceModule: 'better-sqlite3',
		platform: process.platform,
		arch: process.arch,
		node: process.version,
		generatedAt: new Date().toISOString(),
		binaries: binaryPaths.map(filePath => path.basename(filePath))
	};

	const metadataPath = path.join(outputDir, 'metadata.json');
	fs.writeFileSync(metadataPath, JSON.stringify(metadata, null, 2), 'utf8');
}

function main() {
	console.log(`[hexcore-better-sqlite3] Starting prebuild for ${platformArch}`);

	const npm = resolveNpmCommand();
	run(npm, ['rebuild', 'better-sqlite3', '--build-from-source']);

	const packageRoot = tryResolveBetterSqlite3Root();
	const binaries = findNativeBinaryPaths(packageRoot);

	if (binaries.length === 0) {
		throw new Error('No better-sqlite3 native binary was found after rebuild.');
	}

	const copied = new Set();
	for (const binaryPath of binaries) {
		const baseName = path.basename(binaryPath);
		const copiedPath = copyBinary(binaryPath, baseName);
		copied.add(copiedPath);
	}

	// A stable filename simplifies downstream scripts.
	const first = [...copied][0];
	copyBinary(first, 'node.napi.node');

	writeMetadata([...copied, path.join(outputDir, 'node.napi.node')]);
	console.log(`[hexcore-better-sqlite3] Prebuild complete: ${outputDir}`);
}

main();
