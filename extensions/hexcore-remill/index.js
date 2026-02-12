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

let binding;
try {
	binding = require('./prebuilds/' + process.platform + '-' + process.arch + '/hexcore_remill.node');
} catch (e1) {
	try {
		binding = require('./build/Release/hexcore_remill.node');
	} catch (e2) {
		try {
			binding = require('./build/Debug/hexcore_remill.node');
		} catch (e3) {
			throw new Error(
				'Failed to load hexcore-remill native module. ' +
				'Errors:\n' +
				`  Prebuild: ${e1.message}\n` +
				`  Release: ${e2.message}\n` +
				`  Debug: ${e3.message}`
			);
		}
	}
}

module.exports = binding;
module.exports.default = binding.RemillLifter;
module.exports.RemillLifter = binding.RemillLifter;
module.exports.ARCH = binding.ARCH;
module.exports.OS = binding.OS;
module.exports.version = binding.version;
