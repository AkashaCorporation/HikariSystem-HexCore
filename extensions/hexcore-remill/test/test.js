/**
 * HexCore Remill - Smoke Tests
 *
 * Copyright (c) HikariSystem. All rights reserved.
 * Licensed under MIT License.
 */

'use strict';

const assert = require('assert');
const {
	RemillLifter,
	ARCH,
	OS,
	version,
	upstreamVersion,
	upstreamCommit,
} = require('../index.js');

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
	assert.strictEqual(version, '0.5.1');
	assert.strictEqual(upstreamVersion, '6.0.1');
	assert.strictEqual(upstreamCommit, '0e324aee8c67a63ec759ef379dcfafa0b3cb1448');
});

// --- Static methods ---

test('getSupportedArchs returns array', () => {
	const archs = RemillLifter.getSupportedArchs();
	assert.ok(Array.isArray(archs));
	assert.ok(archs.length > 0);
	assert.ok(archs.includes('amd64'));
	assert.ok(archs.includes('x86'));
	assert.ok(archs.includes('aarch64'));
	assert.ok(!archs.includes('sparc64'));
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

test('every advertised architecture has packaged semantics', () => {
	for (const arch of RemillLifter.getSupportedArchs()) {
		const lifter = new RemillLifter(arch);
		assert.ok(lifter.isOpen(), arch);
		lifter.close();
	}
});

test('constructor rejects invalid arch', () => {
	assert.throws(() => new RemillLifter('invalid_arch'), /[Uu]nsupported/);
});

test('constructor rejects unpackaged SPARC64 without terminating the process', () => {
	assert.throws(() => new RemillLifter(ARCH.SPARC64), /[Uu]navailable/);
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

test('liftBytes keeps a JMP after UD2 out of the trap block', () => {
	// ud2; jmp -4. Remill rejects UD2 and FIX-024 recovers it through XED.
	// The JMP is dead code and must not replace the trap block terminator.
	const code = Buffer.from([0x0f, 0x0b, 0xeb, 0xfc]);
	for (const arch of [ARCH.AMD64, ARCH.AMD64_AVX]) {
		const lifter = new RemillLifter(arch);
		const result = lifter.liftBytes(code, 0x401000);
		assert.strictEqual(result.success, true, `${arch}: ${result.error}`);
		assert.ok(!/call .*JMPI/.test(result.ir), `${arch}: dead JMP after UD2 must not survive`);
		lifter.close();
	}
});

test('liftBytes inlines SSE semantics by default', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const code = Buffer.from([0x0f, 0x58, 0xc1, 0xc3]);  // addps xmm0, xmm1; ret
	const result = lifter.liftBytes(code, 0x401000);

	assert.strictEqual(result.success, true);
	assert.doesNotMatch(result.ir, /call .*ADDPS/);
	assert.match(result.ir, /fadd <2 x float>/);

	lifter.close();
});

test('liftBytes can inline semantics when requested', () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const code = Buffer.from([0x0f, 0x58, 0xc1, 0xc3]);  // addps xmm0, xmm1; ret
	const result = lifter.liftBytes(code, 0x401000, { inlineSemantics: true });

	assert.strictEqual(result.success, true);
	assert.doesNotMatch(result.ir, /call .*ADDPS/);

	lifter.close();
});

test('liftBytes models Remill 6.0.1 BMI and CRC32 semantics', () => {
	const vectors = {
		POPCNT: [0xf3, 0x0f, 0xb8, 0xc1],
		PEXT: [0xc4, 0xe2, 0x72, 0xf5, 0xc2],
		PDEP: [0xc4, 0xe2, 0x73, 0xf5, 0xc2],
		BZHI: [0xc4, 0xe2, 0x68, 0xf5, 0xc1],
		BEXTR: [0xc4, 0xe2, 0x68, 0xf7, 0xc1],
		SHLX: [0xc4, 0xe2, 0x69, 0xf7, 0xc1],
		CRC32: [0xf2, 0x0f, 0x38, 0xf0, 0xc1],
	};
	const lifter = new RemillLifter(ARCH.AMD64_AVX);

	for (const [name, instruction] of Object.entries(vectors)) {
		const result = lifter.liftBytes(
			Buffer.from([...instruction, 0xc3]), 0x401000);
		assert.strictEqual(result.success, true, `${name}: ${result.error}`);
		assert.doesNotMatch(
			result.ir, /HandleUnsupported/, `${name}: fell back to unsupported`);
	}

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

test('liftBytesAsync accepts lift options', async () => {
	const lifter = new RemillLifter(ARCH.AMD64);
	const code = Buffer.from([0x0f, 0x58, 0xc1, 0xc3]);  // addps xmm0, xmm1; ret
	const result = await lifter.liftBytesAsync(code, 0x401000, { inlineSemantics: true });

	assert.strictEqual(result.success, true);
	assert.doesNotMatch(result.ir, /call .*ADDPS/);

	lifter.close();
});

// --- Summary ---

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
	process.exit(1);
}
