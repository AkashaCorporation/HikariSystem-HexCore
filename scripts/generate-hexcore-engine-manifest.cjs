/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const ENGINE_SPECS = [
	{ id: 'hexcore-capstone', active: true },
	{ id: 'hexcore-unicorn', active: true },
	{ id: 'hexcore-llvm-mc', active: true },
	{ id: 'hexcore-better-sqlite3', active: true },
	{ id: 'hexcore-remill', active: true },
	{ id: 'hexcore-souper', active: true },
	{ id: 'hexcore-helix', active: true },
	{ id: 'hexcore-elixir', active: true },
	{ id: 'hexcore-revenant', active: true },
	{ id: 'hexcore-rellic', active: false, required: false }
];

const NATIVE_EXTENSIONS = new Set(['.node', '.dll', '.exe', '.bc']);
const ADDON_NAMES = {
	'hexcore-capstone': 'hexcore_capstone', 'hexcore-unicorn': 'hexcore_unicorn',
	'hexcore-llvm-mc': 'hexcore_llvm_mc', 'hexcore-better-sqlite3': 'hexcore_sqlite3',
	'hexcore-remill': 'hexcore_remill', 'hexcore-souper': 'hexcore_souper'
};

function runtimeCandidates(id, platform, arch) {
	if (id === 'hexcore-revenant') {
		const os = platform === 'win32' ? 'win' : platform === 'darwin' ? 'osx' : 'linux';
		const executable = platform === 'win32' ? 'revenant-engine.exe' : 'revenant-engine';
		return [`bin/${os}-${arch}/${executable}`, `bin/${executable}`];
	}
	if (id === 'hexcore-helix' || id === 'hexcore-elixir') {
		const suffixes = platform === 'win32' ? [`win32-${arch}-msvc`]
			: platform === 'linux' ? [`linux-${arch}-gnu`, `linux-${arch}-musl`] : [`darwin-${arch}`];
		return suffixes.map(suffix => `${id}.${suffix}.node`);
	}
	const name = ADDON_NAMES[id];
	if (!name) return [];
	return [
		`prebuilds/${platform}-${arch}/node.napi.node`,
		`prebuilds/${platform}-${arch}/${id}.node`,
		`prebuilds/${platform}-${arch}/${name}.node`,
		`build/Release/${name}.node`
	];
}

function requireRuntimeFile(extensionRoot, candidates, label) {
	for (const relative of candidates) {
		const fullPath = path.join(extensionRoot, relative);
		try { if (fs.statSync(fullPath).isFile() && fs.statSync(fullPath).size > 0) return fullPath; } catch { /* try next supported location */ }
	}
	throw new Error(`${label} missing or empty; expected one of: ${candidates.join(', ')}`);
}

function parseArguments(argv) {
	const values = new Map();
	for (let index = 0; index < argv.length; index += 2) {
		const key = argv[index];
		const value = argv[index + 1];
		if (!key?.startsWith('--') || !value) {
			throw new Error(`Invalid argument sequence near: ${key || '<end>'}`);
		}
		values.set(key.slice(2), value);
	}
	return values;
}

function readJson(filePath) {
	return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function normalizeRepository(repository) {
	if (typeof repository === 'string') {
		return repository;
	}
	return repository?.url || null;
}

function listNativeArtifacts(directory) {
	const artifacts = [];
	const pending = [directory];

	while (pending.length > 0) {
		const current = pending.pop();
		for (const entry of fs.readdirSync(current, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
			const fullPath = path.join(current, entry.name);
			if (entry.isDirectory()) {
				if (!['node_modules', '.git', 'test', 'tests', 'target'].includes(entry.name)) pending.push(fullPath);
			} else if (entry.isFile() && NATIVE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
				artifacts.push(fullPath);
			}
		}
	}

	return artifacts.sort((a, b) => a.localeCompare(b));
}

function hashFile(filePath) {
	const hash = crypto.createHash('sha256');
	const buffer = Buffer.allocUnsafe(1024 * 1024);
	const fd = fs.openSync(filePath, 'r');
	try {
		let read;
		while ((read = fs.readSync(fd, buffer, 0, buffer.length, null)) > 0) hash.update(buffer.subarray(0, read));
	} finally { fs.closeSync(fd); }
	return hash.digest('hex');
}

function generateManifest({ appRoot, outputPath, platform = process.platform, arch = process.arch }) {
	const resolvedRoot = path.resolve(appRoot);
	const productPath = path.join(resolvedRoot, 'product.json');
	if (!fs.existsSync(productPath)) {
		throw new Error(`Packaged product.json not found: ${productPath}`);
	}

	const product = readJson(productPath);
	if (!product.hexcoreVersion) {
		throw new Error(`Packaged product metadata has no hexcoreVersion: ${productPath}`);
	}
	const engines = ENGINE_SPECS.map(spec => {
		const extensionRoot = path.join(resolvedRoot, 'extensions', spec.id);
		const packagePath = path.join(extensionRoot, 'package.json');
		if (!fs.existsSync(packagePath)) {
			if (spec.required === false) return { id: spec.id, active: false, version: null, repository: null, releaseTag: null, artifacts: [] };
			throw new Error(`Required engine package is missing: ${packagePath}`);
		}

		const packageJson = readJson(packagePath);
		const artifactPaths = listNativeArtifacts(extensionRoot);
		let primaryRuntime;
		if (spec.required !== false) {
			primaryRuntime = requireRuntimeFile(extensionRoot, runtimeCandidates(spec.id, platform, arch), `Engine ${spec.id} primary runtime`);
			if (!artifactPaths.includes(primaryRuntime)) artifactPaths.push(primaryRuntime);
			if (platform === 'win32' && spec.id === 'hexcore-unicorn') {
				requireRuntimeFile(extensionRoot, ['deps/unicorn/unicorn.dll', 'build/Release/unicorn.dll', `prebuilds/${platform}-${arch}/unicorn.dll`, 'unicorn.dll'], 'Unicorn runtime DLL');
			}
			if (platform === 'win32' && spec.id === 'hexcore-elixir') {
				requireRuntimeFile(extensionRoot, ['unicorn.dll'], 'Elixir adjacent Unicorn runtime DLL');
			}
			if (spec.id === 'hexcore-remill' && !artifactPaths.some(file => path.extname(file).toLowerCase() === '.bc')) {
				throw new Error('Remill semantics bitcode missing from package');
			}
		}

		return {
			id: spec.id,
			active: spec.active,
			version: packageJson.version,
			repository: normalizeRepository(packageJson.repository),
			releaseTag: `v${packageJson.version}`,
			...(primaryRuntime ? { primaryRuntime: path.relative(resolvedRoot, primaryRuntime).split(path.sep).join('/'), runtimeValidation: 'presence-only' } : {}),
			artifacts: artifactPaths.map(artifactPath => {
				const stat = fs.statSync(artifactPath);
				return {
					path: path.relative(resolvedRoot, artifactPath).split(path.sep).join('/'),
					bytes: stat.size,
					sha256: hashFile(artifactPath)
				};
			})
		};
	});

	const manifest = {
		schemaVersion: 1,
		product: {
			name: product.nameLong || product.nameShort,
			version: product.hexcoreVersion,
			commit: product.commit || process.env.GITHUB_SHA || null,
			distribution: 'portable',
			updatePolicy: 'manual'
		},
		platform,
		arch,
		engines
	};

	const resolvedOutput = path.resolve(outputPath);
	fs.mkdirSync(path.dirname(resolvedOutput), { recursive: true });
	fs.writeFileSync(resolvedOutput, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
	return manifest;
}

if (require.main === module) {
	try {
		const args = parseArguments(process.argv.slice(2));
		const appRoot = args.get('app-root');
		const outputPath = args.get('output');
		if (!appRoot || !outputPath) {
			throw new Error('Usage: generate-hexcore-engine-manifest.cjs --app-root <resources/app> --output <manifest.json>');
		}
		const manifest = generateManifest({ appRoot, outputPath });
		const artifactCount = manifest.engines.reduce((total, engine) => total + engine.artifacts.length, 0);
		console.log(`HexCore engine manifest: ${manifest.engines.length} engines, ${artifactCount} artifacts -> ${path.resolve(outputPath)}`);
	} catch (error) {
		console.error(`HexCore engine manifest failed: ${error?.stack || error}`);
		process.exit(1);
	}
}

module.exports = { ENGINE_SPECS, runtimeCandidates, generateManifest };
