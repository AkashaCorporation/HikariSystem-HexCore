/**
 * HexCore Capstone - Native Node.js Bindings
 * Modern N-API bindings for Capstone disassembler engine
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 *
 * @example
 * const { Capstone, ARCH, MODE } = require('hexcore-capstone');
 *
 * const cs = new Capstone(ARCH.X86, MODE.MODE_64);
 * const code = Buffer.from([0x55, 0x48, 0x89, 0xe5]);
 * const instructions = cs.disasm(code, 0x1000);
 *
 * for (const insn of instructions) {
 *   console.log(`${insn.address.toString(16)}: ${insn.mnemonic} ${insn.opStr}`);
 * }
 *
 * cs.close();
 */

'use strict';

// Load the native addon
// prebuildify uses binding.gyp target name (hexcore_capstone)
// prebuild-install uses package name (hexcore-capstone)
// node.napi.node is another common convention
// Try all for maximum compatibility
const platformDir = './prebuilds/' + process.platform + '-' + process.arch + '/';

let binding;
const errors = [];

const candidates = [
	{ label: 'prebuild (node.napi)', path: platformDir + 'node.napi.node' },
	{ label: 'prebuild (hyphen)', path: platformDir + 'hexcore-capstone.node' },
	{ label: 'prebuild (underscore)', path: platformDir + 'hexcore_capstone.node' },
	{ label: 'build/Release', path: './build/Release/hexcore_capstone.node' },
	{ label: 'build/Debug', path: './build/Debug/hexcore_capstone.node' },
	// Legacy fallback for transition period
	{ label: 'prebuild (legacy)', path: platformDir + 'capstone_native.node' },
	{ label: 'build/Release (legacy)', path: './build/Release/capstone_native.node' },
	{ label: 'build/Debug (legacy)', path: './build/Debug/capstone_native.node' },
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
		'Failed to load hexcore-capstone native module.\n' +
		'Errors:\n' + errors.join('\n')
	);
}

// Export everything from the binding
module.exports = binding;

// Add convenience aliases
module.exports.default = binding.Capstone;

// Export named constants for easier destructuring
module.exports.Capstone = binding.Capstone;
module.exports.ARCH = binding.ARCH;
module.exports.MODE = binding.MODE;
module.exports.OPT = binding.OPT;
module.exports.OPT_VALUE = binding.OPT_VALUE;
module.exports.ERR = binding.ERR;
module.exports.version = binding.version;
module.exports.support = binding.support;
