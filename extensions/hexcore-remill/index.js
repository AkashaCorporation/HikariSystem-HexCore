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

const platformDir = './prebuilds/' + process.platform + '-' + process.arch + '/';

let binding;
const errors = [];

// prebuildify uses binding.gyp target name (underscore)
// prebuild-install uses package name (hyphen)
// Try both conventions for maximum compatibility
const candidates = [
	{ label: 'prebuild (underscore)', path: platformDir + 'hexcore_remill.node' },
	{ label: 'prebuild (hyphen)', path: platformDir + 'hexcore-remill.node' },
	{ label: 'build/Release', path: './build/Release/hexcore_remill.node' },
	{ label: 'build/Debug', path: './build/Debug/hexcore_remill.node' },
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
		'Failed to load hexcore-remill native module.\n' +
		'Errors:\n' + errors.join('\n')
	);
}

module.exports = binding;
module.exports.default = binding.RemillLifter;
module.exports.RemillLifter = binding.RemillLifter;
module.exports.ARCH = binding.ARCH;
module.exports.OS = binding.OS;
module.exports.version = binding.version;
