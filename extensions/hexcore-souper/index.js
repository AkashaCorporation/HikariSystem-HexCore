'use strict';

const path = require('path');
const fs = require('fs');

// Z3 runtime DLL: add to PATH before loading the addon (same pattern as Unicorn)
if (process.platform === 'win32') {
    const z3DepsDir = path.join(__dirname, 'deps', 'z3');
    if (fs.existsSync(path.join(z3DepsDir, 'libz3.dll'))) {
        process.env.PATH = `${z3DepsDir};${process.env.PATH || ''}`;
    }
    // Also check prebuilds dir for bundled DLL
    const z3PrebuildsDir = path.join(__dirname, 'prebuilds', 'win32-x64');
    if (fs.existsSync(path.join(z3PrebuildsDir, 'libz3.dll'))) {
        process.env.PATH = `${z3PrebuildsDir};${process.env.PATH || ''}`;
    }
}

let binding;
try {
    // 1. Prebuild (underscore convention — prebuildify target_name)
    binding = require('./prebuilds/' + process.platform + '-' + process.arch + '/hexcore_souper.node');
} catch (e1) {
    try {
        // 2. Prebuild (hyphen convention — prebuild-install package name)
        binding = require('./prebuilds/' + process.platform + '-' + process.arch + '/hexcore-souper.node');
    } catch (e2) {
        try {
            // 3. Local Release build
            binding = require('./build/Release/hexcore_souper.node');
        } catch (e3) {
            try {
                // 4. Local Debug build
                binding = require('./build/Debug/hexcore_souper.node');
            } catch (e4) {
                throw new Error(
                    'Failed to load hexcore-souper native module. ' +
                    'Errors:\n' +
                    `  Prebuild (underscore): ${e1.message}\n` +
                    `  Prebuild (hyphen):     ${e2.message}\n` +
                    `  Release build:         ${e3.message}\n` +
                    `  Debug build:           ${e4.message}`
                );
            }
        }
    }
}

module.exports = binding;
module.exports.default = binding.SouperOptimizer;
module.exports.SouperOptimizer = binding.SouperOptimizer;
module.exports.version = binding.version;
