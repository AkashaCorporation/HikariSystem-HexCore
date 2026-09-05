/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

'use strict';

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { ENGINE_SPECS, runtimeCandidates, generateManifest } = require('./generate-hexcore-engine-manifest.cjs');

const fixtureRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-engine-manifest-'));

try {
	fs.writeFileSync(path.join(fixtureRoot, 'product.json'), JSON.stringify({
		nameLong: 'HikariSystem HexCore',
		hexcoreVersion: '3.8.3',
		commit: '0123456789abcdef'
	}), 'utf8');

	for (const spec of ENGINE_SPECS) {
		const extensionRoot = path.join(fixtureRoot, 'extensions', spec.id);
		fs.mkdirSync(extensionRoot, { recursive: true });
		fs.writeFileSync(path.join(extensionRoot, 'package.json'), JSON.stringify({
			name: spec.id,
			version: '1.2.3',
			repository: { url: `https://github.com/AkashaCorporation/${spec.id}.git` }
		}), 'utf8');
		if (spec.required !== false) {
			const runtime = path.join(extensionRoot, runtimeCandidates(spec.id, 'win32', 'x64')[0]);
			fs.mkdirSync(path.dirname(runtime), { recursive: true });
			fs.writeFileSync(runtime, spec.id, 'utf8');
			if (spec.id === 'hexcore-unicorn' || spec.id === 'hexcore-elixir') fs.writeFileSync(path.join(extensionRoot, 'unicorn.dll'), 'fixture');
			if (spec.id === 'hexcore-remill') fs.writeFileSync(path.join(extensionRoot, 'X86.bc'), 'fixture');
		}
	}

	const outputPath = path.join(fixtureRoot, 'hexcore-engine-manifest.json');
	const manifest = generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' });
	assert.equal(manifest.engines.length, 10);
	assert.equal(manifest.engines.filter(engine => engine.active).length, 9);
	assert.equal(manifest.product.updatePolicy, 'manual');
	assert.deepEqual(manifest.engines.find(engine => engine.id === 'hexcore-rellic').artifacts, []);

	const helix = manifest.engines.find(engine => engine.id === 'hexcore-helix');
	assert.equal(helix.artifacts.length, 1);
	assert.equal(
		helix.artifacts[0].sha256,
		crypto.createHash('sha256').update('hexcore-helix').digest('hex')
	);
	assert.ok(!helix.artifacts[0].path.includes('\\'));

	const helixRoot = path.join(fixtureRoot, 'extensions', 'hexcore-helix');
	const primary = path.join(helixRoot, runtimeCandidates('hexcore-helix', 'win32', 'x64')[0]);
	assert.equal(helix.runtimeValidation, 'presence-only');
	fs.rmSync(primary);
	fs.writeFileSync(path.join(helixRoot, 'irrelevant.dll'), 'not a Helix addon');
	assert.throws(
		() => generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' }),
		/Engine hexcore-helix primary runtime missing/
	);
	fs.writeFileSync(primary, '');
	assert.throws(() => generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' }), /primary runtime missing or empty/);
	fs.writeFileSync(primary, 'hexcore-helix');
	const elixirDll = path.join(fixtureRoot, 'extensions', 'hexcore-elixir', 'unicorn.dll');
	fs.rmSync(elixirDll);
	assert.throws(() => generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' }), /Elixir adjacent Unicorn runtime DLL/);
	fs.writeFileSync(elixirDll, 'fixture');
	fs.rmSync(path.join(fixtureRoot, 'extensions', 'hexcore-rellic'), { recursive: true });
	assert.equal(generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' }).engines.filter(engine => engine.active).length, 9);
	fs.rmSync(path.join(fixtureRoot, 'extensions', 'hexcore-remill', 'X86.bc'));
	assert.throws(() => generateManifest({ appRoot: fixtureRoot, outputPath, platform: 'win32', arch: 'x64' }), /Remill semantics bitcode missing/);

	console.log('HexCore engine manifest tests passed.');
} finally {
	fs.rmSync(fixtureRoot, { recursive: true, force: true });
}
