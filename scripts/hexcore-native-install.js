/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync, execSync } = require('child_process');

const cwd = process.cwd();
const pkgPath = path.join(cwd, 'package.json');

if (!fs.existsSync(pkgPath)) {
	console.error('[hexcore-native-install] package.json not found in', cwd);
	process.exit(1);
}

const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
const moduleName = pkg.name || 'unknown';

console.log(`[hexcore-native-install] Installing native module: ${moduleName}`);

// ---------------------------------------------------------------------------
// Detect NAPI-RS modules (have "napi" field in package.json)
// ---------------------------------------------------------------------------
const isNapiRs = Boolean(pkg.napi && pkg.napi.binaryName);

if (isNapiRs) {
	installNapiRs();
} else {
	installPrebuildify();
}

// ---------------------------------------------------------------------------
// NAPI-RS install path — downloads .node from GitHub Release
// ---------------------------------------------------------------------------
function installNapiRs() {
	const binaryName = pkg.napi.binaryName;
	const version = pkg.version;
	const nodeFileName = resolveNapiRsFileName(binaryName);

	if (!nodeFileName) {
		console.error(`[hexcore-native-install] Unsupported platform for NAPI-RS: ${process.platform}-${process.arch}`);
		process.exit(1);
	}

	// Check if .node already exists locally
	const localPath = path.join(cwd, nodeFileName);
	if (fs.existsSync(localPath)) {
		console.log(`[hexcore-native-install] NAPI-RS binary already exists: ${nodeFileName}`);
		return;
	}

	// Resolve GitHub repo URL from package.json repository field
	const repoUrl = (pkg.repository && (typeof pkg.repository === 'string' ? pkg.repository : pkg.repository.url)) || '';
	const repoMatch = repoUrl.match(/github\.com[/:]([^/]+\/[^/.]+)/);
	if (!repoMatch) {
		console.error(`[hexcore-native-install] Cannot resolve GitHub repo from package.json repository: ${repoUrl}`);
		process.exit(1);
	}
	const repo = repoMatch[1];
	const tag = `v${version}`;

	// Asset name: {binaryName}-v{version}-napi-{platform}-{arch}.node
	// e.g. hexcore-helix-v0.2.0-napi-win32-x64.node
	const assetName = `${binaryName}-v${version}-napi-${process.platform}-${process.arch}.node`;
	const downloadUrl = `https://github.com/${repo}/releases/download/${tag}/${assetName}`;

	console.log(`[hexcore-native-install] Downloading NAPI-RS binary from: ${downloadUrl}`);

	// Try gh CLI first (works in CI with GITHUB_TOKEN), then curl/Invoke-WebRequest
	let downloaded = false;

	// Method 1: gh CLI (handles auth automatically in CI)
	const ghResult = run('gh', ['release', 'download', tag, '--repo', repo, '--pattern', assetName, '--dir', cwd]);
	if (ghResult.ok && fs.existsSync(path.join(cwd, assetName))) {
		// Rename from asset name to the NAPI-RS expected name
		fs.renameSync(path.join(cwd, assetName), localPath);
		downloaded = true;
	}

	// Method 2: curl (Linux/macOS) or Invoke-WebRequest (Windows)
	if (!downloaded) {
		if (process.platform === 'win32') {
			const pwshResult = run('powershell', [
				'-Command',
				`Invoke-WebRequest -Uri '${downloadUrl}' -OutFile '${localPath}' -MaximumRedirection 10`
			]);
			downloaded = pwshResult.ok && fs.existsSync(localPath);
		} else {
			const curlResult = run('curl', ['-fsSL', '-o', localPath, '-L', downloadUrl]);
			downloaded = curlResult.ok && fs.existsSync(localPath);
		}
	}

	if (downloaded && fs.existsSync(localPath)) {
		console.log(`[hexcore-native-install] NAPI-RS binary installed: ${nodeFileName}`);
	} else {
		console.warn(`[hexcore-native-install] Failed to download NAPI-RS binary: ${assetName}`);
		console.warn(`[hexcore-native-install] The module will degrade gracefully at runtime.`);
		// Don't exit(1) — Helix is optional, continue-on-error in CI
	}
}

/**
 * Resolve the NAPI-RS .node filename for the current platform.
 * Matches the naming convention from the NAPI-RS index.js loader.
 */
function resolveNapiRsFileName(binaryName) {
	const p = process.platform;
	const a = process.arch;

	if (p === 'win32' && a === 'x64') { return `${binaryName}.win32-x64-msvc.node`; }
	if (p === 'linux' && a === 'x64') {
		return isMusl()
			? `${binaryName}.linux-x64-musl.node`
			: `${binaryName}.linux-x64-gnu.node`;
	}
	if (p === 'darwin' && a === 'x64') { return `${binaryName}.darwin-x64.node`; }
	if (p === 'darwin' && a === 'arm64') { return `${binaryName}.darwin-arm64.node`; }

	return undefined;
}

function isMusl() {
	if (!process.report || typeof process.report.getReport !== 'function') {
		try {
			const lddPath = execSync('which ldd').toString().trim();
			return fs.readFileSync(lddPath, 'utf8').includes('musl');
		} catch {
			return true;
		}
	}
	const report = process.report.getReport();
	const rpt = typeof report === 'string' ? JSON.parse(report) : report;
	return !rpt.header.glibcVersionRuntime;
}

// ---------------------------------------------------------------------------
// Prebuildify install path (Capstone, Unicorn, LLVM-MC, Remill, Rellic, etc.)
// ---------------------------------------------------------------------------
function installPrebuildify() {
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
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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
