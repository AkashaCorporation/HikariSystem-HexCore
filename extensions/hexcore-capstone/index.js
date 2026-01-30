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
let binding;
try {
	// Try to load prebuilt binary first
	binding = require('./prebuilds/' + process.platform + '-' + process.arch + '/node.napi.node');
} catch (e1) {
	try {
		// Fall back to node-gyp built binary
		binding = require('./build/Release/capstone_native.node');
	} catch (e2) {
		try {
			// Try debug build
			binding = require('./build/Debug/capstone_native.node');
		} catch (e3) {
			throw new Error(
				'Failed to load hexcore-capstone native module. ' +
				'Make sure you have run npm install and have the required build tools. ' +
				'Original errors:\n' +
				`  Prebuild: ${e1.message}\n` +
				`  Release: ${e2.message}\n` +
				`  Debug: ${e3.message}`
			);
		}
	}
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
