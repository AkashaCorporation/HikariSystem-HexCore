/**
 * HexCore Rellic - Smoke Tests
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

'use strict';

const assert = require('assert');
const { RellicDecompiler, version } = require('../index.js');

let passed = 0;
let failed = 0;

function test(name, fn) {
	try {
		fn();
		console.log(`  \u2713 ${name}`);
		passed++;
	} catch (err) {
		console.error(`  \u2717 ${name}`);
		console.error(`    ${err.message}`);
		failed++;
	}
}

console.log('hexcore-rellic smoke tests\n');

// --- Module exports ---

test('module exports RellicDecompiler class', () => {
	assert.strictEqual(typeof RellicDecompiler, 'function');
});

test('module exports version string', () => {
	assert.strictEqual(typeof version, 'string');
	assert.ok(version.length > 0);
});

// --- Constructor ---

test('constructor creates instance', () => {
	const decompiler = new RellicDecompiler();
	assert.ok(decompiler);
	assert.ok(decompiler.isOpen());
	decompiler.close();
});

// --- Lifecycle ---

test('isOpen returns true after construction', () => {
	const decompiler = new RellicDecompiler();
	assert.strictEqual(decompiler.isOpen(), true);
	decompiler.close();
});

test('isOpen returns false after close', () => {
	const decompiler = new RellicDecompiler();
	decompiler.close();
	assert.strictEqual(decompiler.isOpen(), false);
});

test('close is idempotent', () => {
	const decompiler = new RellicDecompiler();
	decompiler.close();
	decompiler.close();  // should not throw
	decompiler.close();  // should not throw
	assert.strictEqual(decompiler.isOpen(), false);
});

// --- Decompile ---

test('decompile empty string returns error', () => {
	const decompiler = new RellicDecompiler();
	const result = decompiler.decompile('');
	assert.strictEqual(result.success, false);
	assert.strictEqual(typeof result.error, 'string');
	assert.ok(result.error.length > 0);
	assert.strictEqual(typeof result.code, 'string');
	assert.strictEqual(typeof result.functionCount, 'number');
	decompiler.close();
});

test('decompile returns DecompileResult shape', () => {
	const decompiler = new RellicDecompiler();
	const result = decompiler.decompile('not valid IR');
	assert.strictEqual(typeof result.success, 'boolean');
	assert.strictEqual(typeof result.code, 'string');
	assert.strictEqual(typeof result.error, 'string');
	assert.strictEqual(typeof result.functionCount, 'number');
	decompiler.close();
});

test('decompile after close returns error', () => {
	const decompiler = new RellicDecompiler();
	decompiler.close();
	const result = decompiler.decompile('define i32 @add(i32 %a, i32 %b) { ret i32 0 }');
	assert.strictEqual(result.success, false);
	assert.ok(result.error.includes('closed'));
});

test('decompile with reference IR (stub returns not-implemented)', () => {
	const decompiler = new RellicDecompiler();
	const ir = [
		'define i32 @add(i32 %a, i32 %b) {',
		'entry:',
		'  %sum = add i32 %a, %b',
		'  ret i32 %sum',
		'}',
	].join('\n');
	const result = decompiler.decompile(ir);
	// Stub returns not-implemented, but shape must be correct
	assert.strictEqual(typeof result.success, 'boolean');
	assert.strictEqual(typeof result.code, 'string');
	assert.strictEqual(typeof result.error, 'string');
	assert.strictEqual(typeof result.functionCount, 'number');
	decompiler.close();
});

// --- Async ---

test('decompileAsync returns promise', async () => {
	const decompiler = new RellicDecompiler();
	const promise = decompiler.decompileAsync('test');
	assert.ok(promise instanceof Promise);
	const result = await promise;
	assert.strictEqual(typeof result.success, 'boolean');
	assert.strictEqual(typeof result.code, 'string');
	assert.strictEqual(typeof result.error, 'string');
	assert.strictEqual(typeof result.functionCount, 'number');
	decompiler.close();
});

// --- Summary ---

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	process.exit(1);
}
