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
    // The native Souper build must not depend on the build machine's absolute
    // Z3 path. Point it at the executable shipped beside the selected runtime.
    for (const dir of [z3PrebuildsDir, z3DepsDir]) {
        const executable = path.join(dir, 'z3.exe');
        if (fs.existsSync(executable)) {
            process.env.HEXCORE_Z3_PATH = executable;
            break;
        }
    }
}

let binding;
const errors = [];
const platformDir = './prebuilds/' + process.platform + '-' + process.arch + '/';

// A checkout must prefer its fresh local build. Published packages do not
// contain build/ and therefore fall through to their packaged prebuild.
const candidates = [
    { label: 'build/Release', path: './build/Release/hexcore_souper.node' },
    { label: 'build/Debug', path: './build/Debug/hexcore_souper.node' },
    { label: 'prebuild (underscore)', path: platformDir + 'hexcore_souper.node' },
    { label: 'prebuild (hyphen)', path: platformDir + 'hexcore-souper.node' },
];

for (const candidate of candidates) {
    try {
        binding = require(candidate.path);
        break;
    } catch (error) {
        errors.push(`  ${candidate.label}: ${error.message}`);
    }
}

if (!binding) {
    throw new Error(
        'Failed to load hexcore-souper native module.\nErrors:\n' +
        errors.join('\n')
    );
}

module.exports = binding;
module.exports.default = binding.SouperOptimizer;
module.exports.SouperOptimizer = binding.SouperOptimizer;
module.exports.version = binding.version;
