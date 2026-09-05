/*---------------------------------------------------------------------------------------------
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License. See License.txt in the project root.
 *--------------------------------------------------------------------------------------------*/
'use strict';
const assert = require('node:assert/strict');
const { verifyRuntimes } = require('./verify-hexcore-runtimes.cjs');
const manifest = { platform: process.platform, arch: process.arch, engines: [
	{ id: 'hexcore-helix', active: true, version: '0.9.3', primaryRuntime: 'extensions/hexcore-helix/addon.node' },
	{ id: 'hexcore-rellic', active: false }
] };
const run = execute => verifyRuntimes({ appRoot: __dirname, manifest, execute });
assert.equal(run(() => ({ status: 0, stdout: 'HEXCORE_RUNTIME_LOADED' }))[0].ok, true);
assert.equal(run(() => ({ status: 1, stderr: 'missing DLL' }))[0].ok, false);
assert.equal(run(() => ({ status: 0, stdout: 'exited before loading' }))[0].ok, false);
assert.equal(run(() => ({ status: null, error: { code: 'ETIMEDOUT', message: 'deadline' } }))[0].timedOut, true);
assert.equal(run((_exe, _args, options) => {
	assert.equal(options.timeout, 30000); assert.equal(options.windowsHide, true);
	return { status: 0, stdout: 'HEXCORE_RUNTIME_LOADED' };
}).length, 1);
assert.throws(() => verifyRuntimes({ appRoot: __dirname, manifest: { ...manifest, platform: 'unsupported' } }), /platform/);
assert.equal(verifyRuntimes({ appRoot: __dirname, manifest: { ...manifest, engines: [
	{ id: 'hexcore-revenant', active: true, version: '0.4.0', primaryRuntime: 'bin/revenant-engine.exe' }
] }, execute: (_exe, args) => {
	assert.deepEqual(args, ['--version']);
	return { status: 0, stdout: 'revenant-engine: 0.4.0\nICSharpCode.Decompiler: fixture' };
} })[0].ok, true);
console.log('Runtime smoke controller tests passed.');
