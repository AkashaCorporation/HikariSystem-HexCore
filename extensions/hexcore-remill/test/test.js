/**
 * HexCore Remill - Smoke Tests
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

'use strict';

const assert = require('assert');
const { RemillLifter, ARCH, OS, version } = require('../index.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
	try {
		fn();
		console.log(`  ✓ ${name}`);
		passed++;
	} catch (err) {
		console.error(`  ✗ ${name}`);
		console.error(`    ${err.message}`);
		failed++;
	}
}

console.log('hexcore-remill smoke tests\n');

// --- Module exports ---

test('module exports RemillLifter class', () => {
	assert.strictEqual(typeof RemillLifter, 'function');
});

test('module exports ARCH constants', () => {
	assert.ok(ARCH);
	assert.strictEqual(ARCH.AMD64, 'amd64');
	assert.strictEqual(ARCH.X86, 'x86');
	assert.strictEqual(ARCH.AARCH64, 'aarch64');
	assert.strictEqual(ARCH.SPARC32, 'sparc32');
	assert.strictEqual(ARCH.SPARC64, 'sparc64');
});

test('module exports OS constants', () => {
	assert.ok(OS);
	assert.strictEqual(OS.LINUX, 'linux');
	assert.strictEqual(OS.WINDOWS, 'windows');
	assert.strictEqual(OS.MACOS, 'macos');
});

test('module exports version string', () => {
	assert.strictEqual(typeof version, 'string');
	assert.ok(version.length > 0);
});

// --- Static methods ---

test('getSupportedArchs returns array', () => {
	const archs = RemillLifter.getSupportedArchs();
	assert.ok(Array.isArray(archs));
	assert.ok(archs.length > 0);
	assert.ok(archs.includes('amd64'));
	assert.ok(archs.includes('x86'));
	assert.ok(archs.includes('aarch64'));
});

// --- Constructor ---

test('constructor with valid arch', () => {
	const lifter = new RemillLifter('amd64');
	assert.ok(lifter.isOpen());
	assert.strictEqual(lifter.getArch(), 'amd64');
	lifter.close();
});

test('constructor with ARCH constant', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	assert.ok(lifter.isOpen());
	lifter.close();
});

test('constructor with OS parameter', () => {
	const lifter = new RemillLifter(ARCH.AMD64, OS.WINDOWS);
	assert.ok(lifter.isOpen());
	lifter.close();
});

test('constructor rejects invalid arch', () => {
	assert.throws(() => new RemillLifter('invalid_arch'), /[Uu]nsupported/);
});

test('constructor rejects missing argument', () => {
	assert.throws(() => new RemillLifter(), /[Ee]xpected/);
});

// --- Lifting ---

test('liftBytes lifts x86-64 push rbp; mov rbp,rsp; ret', () => {
	const lifter = new RemillLifter(ARCH.AMD64);

	// push rbp; mov rbp, rsp; pop rbp; ret
	const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0x5d, 0xc3]);
	const result = lifter.liftBytes(code, 0x401000);

	assert.strictEqual(result.success, true);
	assert.strictEqual(typeof result.ir, 'string');
	assert.ok(result.ir.length > 0, 'IR should not be empty');
	assert.strictEqual(result.address, 0x401000);
	assert.ok(result.bytesConsumed > 0, 'Should consume some bytes');
	assert.ok(result.bytesConsumed <= code.length);

	lifter.close();
});

test('liftBytes returns error for empty buffer', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const result = lifter.liftBytes(Buffer.alloc(0), 0x401000);
	assert.strictEqual(result.success, false);
	lifter.close();
});

test('liftBytes accepts Uint8Array', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const code = new Uint8Array([0x90, 0x90, 0xc3]);  // nop; nop; ret
	const result = lifter.liftBytes(code, 0x1000);
	assert.strictEqual(result.success, true);
	lifter.close();
});

test('liftBytes rejects after close', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	lifter.close();
	assert.strictEqual(lifter.isOpen(), false);
	assert.throws(() => lifter.liftBytes(Buffer.from([0xc3]), 0x1000));
});

// --- Lifecycle ---

test('close is idempotent', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	lifter.close();
	lifter.close();  // should not throw
	assert.strictEqual(lifter.isOpen(), false);
});

// --- Async ---

test('liftBytesAsync returns promise', async () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const code = Buffer.from([0x55, 0x48, 0x89, 0xe5, 0xc3]);
	const result = await lifter.liftBytesAsync(code, 0x401000);

	assert.strictEqual(result.success, true);
	assert.ok(result.ir.length > 0);

	lifter.close();
});

// --- Summary ---

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	process.exit(1);
}
