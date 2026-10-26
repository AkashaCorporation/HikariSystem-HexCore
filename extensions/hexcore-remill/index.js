/**
 * HexCore Remill - Native Node.js Bindings
 * Lifts machine code to LLVM IR bitcode via Remill
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 *
 * @example
 * const { RemillLifter, ARCH } = require('hexcore-remill');
 *
 * const lifter = new RemillLifter(ARCH.AMD64);
 * const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3]);
 * const result = lifter.liftBytes(code, 0x401000);
 *
 * if (result.success) {
 *   console.log(result.ir);
 * }
 *
 * lifter.close();
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { version: wrapperVersion } = require('./package.json');

const platformDir = './prebuilds/' + process.platform + '-' + process.arch + '/';

let binding;
let loadedArtifactPath;
const errors = [];

// Prefer freshly built local artifacts during development so source changes
// take effect immediately in a checkout. Fall back to packaged prebuilds when
// no local build output exists.
const candidates = [
	{ label: 'build/Release', path: './build/Release/hexcore_remill.node' },
	{ label: 'build/Debug', path: './build/Debug/hexcore_remill.node' },
	{ label: 'prebuild (hyphen)', path: platformDir + 'hexcore-remill.node' },
	{ label: 'prebuild (legacy underscore)', path: platformDir + 'hexcore_remill.node' },
];

for (const candidate of candidates) {
	try {
		loadedArtifactPath = require.resolve(candidate.path);
		binding = require(loadedArtifactPath);
		break;
	} catch (e) {
		errors.push(`  ${candidate.label}: ${e.message}`);
	}
}

if (!binding) {
	throw new Error(
		'Failed to load hexcore-remill native module.\n' +
		'Errors:\n' + errors.join('\n')
	);
}

const canonicalArtifactPath = fs.realpathSync.native(loadedArtifactPath);
const artifactBytes = fs.readFileSync(canonicalArtifactPath);
const runtimeIdentity = Object.freeze({
	component: 'hexcore-remill',
	wrapperVersion,
	nativeVersion: binding.version,
	upstreamVersion: binding.upstreamVersion,
	upstreamCommit: binding.upstreamCommit,
	platform: process.platform,
	arch: process.arch,
	binaryPath: canonicalArtifactPath,
	binarySha256: crypto.createHash('sha256').update(artifactBytes).digest('hex'),
	binaryBytes: fs.statSync(canonicalArtifactPath).size,
	artifactKind: 'native-node',
});

module.exports = binding;
module.exports.default = binding.RemillLifter;
module.exports.RemillLifter = binding.RemillLifter;
module.exports.ARCH = binding.ARCH;
module.exports.OS = binding.OS;
module.exports.version = binding.version;
module.exports.upstreamVersion = binding.upstreamVersion;
module.exports.upstreamCommit = binding.upstreamCommit;
module.exports.runtimeIdentity = runtimeIdentity;
