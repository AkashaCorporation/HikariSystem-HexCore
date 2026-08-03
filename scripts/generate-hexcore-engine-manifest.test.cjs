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
const { ENGINE_SPECS, generateManifest } = require('./generate-hexcore-engine-manifest.cjs');

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
			fs.writeFileSync(path.join(extensionRoot, `${spec.id}.node`), spec.id, 'utf8');
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

	fs.rmSync(path.join(fixtureRoot, 'extensions', 'hexcore-helix', 'hexcore-helix.node'));
	assert.throws(
		() => generateManifest({ appRoot: fixtureRoot, outputPath }),
		/Engine hexcore-helix has no packaged native artifacts/
	);

	console.log('HexCore engine manifest tests passed.');
} finally {
	fs.rmSync(fixtureRoot, { recursive: true, force: true });
}
