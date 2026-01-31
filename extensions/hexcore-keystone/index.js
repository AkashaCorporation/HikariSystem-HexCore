/**
 * HexCore Keystone - Native Node.js Bindings
 * Keystone Assembler Engine
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

'use strict';

// Try to load prebuilt binary, fall back to locally compiled
let binding;
try {
    binding = require('./build/Release/hexcore_keystone.node');
} catch (e) {
    try {
        binding = require('./build/Debug/hexcore_keystone.node');
    } catch (e2) {
        throw new Error(
            'Failed to load hexcore-keystone native module. ' +
            'Make sure it was compiled with `npm run build`. ' +
            'Original error: ' + e.message
        );
    }
}

module.exports = binding;
