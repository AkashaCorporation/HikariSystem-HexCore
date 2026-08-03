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
				pending.push(fullPath);
			} else if (entry.isFile() && NATIVE_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
				artifacts.push(fullPath);
			}
		}
	}

	return artifacts.sort((a, b) => a.localeCompare(b));
}

function hashFile(filePath) {
	return crypto.createHash('sha256').update(fs.readFileSync(filePath)).digest('hex');
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
			throw new Error(`Required engine package is missing: ${packagePath}`);
		}

		const packageJson = readJson(packagePath);
		const artifactPaths = listNativeArtifacts(extensionRoot);
		if (artifactPaths.length === 0 && spec.required !== false) {
			throw new Error(`Engine ${spec.id} has no packaged native artifacts`);
		}

		return {
			id: spec.id,
			active: spec.active,
			version: packageJson.version,
			repository: normalizeRepository(packageJson.repository),
			releaseTag: `v${packageJson.version}`,
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

module.exports = { ENGINE_SPECS, generateManifest };
