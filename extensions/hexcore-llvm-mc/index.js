'use strict';

const path = require('path');

// Try to load the native module from various locations
// prebuildify uses binding.gyp target name (underscore)
// prebuild-install uses package name (hyphen)
// Try both conventions for maximum compatibility
const possiblePaths = [
    // Prebuilt binaries — underscore (prebuildify)
    path.join(__dirname, 'prebuilds', `${process.platform}-${process.arch}`, 'hexcore_llvm_mc.node'),
    // Prebuilt binaries — hyphen (prebuild-install)
    path.join(__dirname, 'prebuilds', `${process.platform}-${process.arch}`, 'hexcore-llvm-mc.node'),
    // Standard build output
    path.join(__dirname, 'build', 'Release', 'hexcore_llvm_mc.node'),
    path.join(__dirname, 'build', 'Debug', 'hexcore_llvm_mc.node'),
    // Node-pre-gyp style
    path.join(__dirname, 'lib', 'binding', `${process.platform}-${process.arch}`, 'hexcore_llvm_mc.node'),
];

let binding = null;
let loadError = null;

for (const modulePath of possiblePaths) {
    try {
        binding = require(modulePath);
        break;
    } catch (err) {
        if (err.code !== 'MODULE_NOT_FOUND') {
            loadError = err;
        }
    }
}

if (!binding) {
    const error = loadError || new Error(
        'Could not load hexcore-llvm-mc native module. ' +
        'Please ensure the module is built correctly with `npm run build` ' +
        'and that LLVM libraries are properly installed in deps/llvm/.'
    );
    throw error;
}

// Export everything from the native module
module.exports = binding;

// Re-export named exports for convenience
module.exports.LlvmMc = binding.LlvmMc;
module.exports.TRIPLE = binding.TRIPLE;
module.exports.SYNTAX = binding.SYNTAX;
module.exports.OPTION = binding.OPTION;
module.exports.ERR = binding.ERR;
module.exports.CPU = binding.CPU;
module.exports.FEATURES = binding.FEATURES;
module.exports.version = binding.version;
module.exports.getTargets = binding.getTargets;
