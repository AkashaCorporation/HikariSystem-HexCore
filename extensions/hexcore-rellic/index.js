/**
 * HexCore Rellic - Native Node.js Bindings
 * Decompiles LLVM IR to pseudo-C via Rellic
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 *
 * @example
 * const { RellicDecompiler } = require('hexcore-rellic');
 *
 * const decompiler = new RellicDecompiler();
 * const result = decompiler.decompile(irText);
 *
 * if (result.success) {
 *   console.log(result.code);
 * }
 *
 * decompiler.close();
 */

'use strict';

const platformDir = './prebuilds/' + process.platform + '-' + process.arch + '/';

let binding;
const errors = [];

// prebuildify uses binding.gyp target name (underscore)
// prebuild-install uses package name (hyphen)
// Try both conventions for maximum compatibility
const candidates = [
	{ label: 'prebuild (underscore)', path: platformDir + 'hexcore_rellic.node' },
	{ label: 'prebuild (hyphen)', path: platformDir + 'hexcore-rellic.node' },
	{ label: 'build/Release', path: './build/Release/hexcore_rellic.node' },
	{ label: 'build/Debug', path: './build/Debug/hexcore_rellic.node' },
];

for (const candidate of candidates) {
	try {
		binding = require(candidate.path);
		break;
	} catch (e) {
		errors.push(`  ${candidate.label}: ${e.message}`);
	}
}

if (!binding) {
	throw new Error(
		'Failed to load hexcore-rellic native module.\n' +
		'Errors:\n' + errors.join('\n')
	);
}

module.exports = binding;
module.exports.default = binding.RellicDecompiler;
module.exports.RellicDecompiler = binding.RellicDecompiler;
module.exports.version = binding.version;
