/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * Minimal ARM64 emuStart crash reproduction test.
 *
 * This test isolates whether uc_emu_start with ARM64 + count=1 crashes
 * on Windows (STATUS_STACK_BUFFER_OVERRUN / 0xC0000409).
 *
 * Run: node test/test_arm64_crash.js
 */

'use strict';

const { Unicorn, ARCH, MODE, PROT, ARM64_REG, version, archSupported } = require('../index.js');

console.log('Unicorn version:', version().string);
console.log('ARM64 supported:', archSupported(ARCH.ARM64));

if (!archSupported(ARCH.ARM64)) {
	console.log('ARM64 not supported, skipping test.');
	process.exit(0);
}

// ---- Test 1: Bare emuStart with a single NOP instruction ----
console.log('\n--- Test 1: ARM64 NOP (count=1, sync) ---');
try {
	const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);
	console.log('  Engine created OK');

	// Map 4KB at 0x10000
	uc.memMap(0x10000n, 0x1000, PROT.ALL);
	console.log('  Memory mapped OK');

	// Write ARM64 NOP instruction: 0xD503201F
	const nop = Buffer.alloc(4);
	nop.writeUInt32LE(0xD503201F);
	uc.memWrite(0x10000n, nop);
	console.log('  NOP written at 0x10000');

	// Read PC before
	const pcBefore = uc.regRead(ARM64_REG.PC);
	console.log('  PC before:', '0x' + BigInt(pcBefore).toString(16));

	// Set PC to our code
	uc.regWrite(ARM64_REG.PC, 0x10000n);
	console.log('  PC set to 0x10000');

	// Execute exactly 1 instruction synchronously
	console.log('  Calling emuStart(0x10000, 0, 0, 1)...');
	uc.emuStart(0x10000n, 0n, 0, 1);
	console.log('  emuStart returned OK!');

	// Read PC after — should be 0x10004 (NOP is 4 bytes)
	const pcAfter = uc.regRead(ARM64_REG.PC);
	console.log('  PC after:', '0x' + BigInt(pcAfter).toString(16));

	if (BigInt(pcAfter) === 0x10004n) {
		console.log('  [PASS] ARM64 NOP executed correctly');
	} else {
		console.log('  [FAIL] PC not advanced correctly');
	}

	uc.close();
} catch (err) {
	console.log('  [FAIL]', err.message);
}

// ---- Test 2: emuStart with SVC instruction (no hook) ----
console.log('\n--- Test 2: ARM64 SVC #0 (count=1, sync, NO INTR hook) ---');
try {
	const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);

	uc.memMap(0x10000n, 0x1000, PROT.ALL);

	// Write SVC #0: 0xD4000001
	const svc = Buffer.alloc(4);
	svc.writeUInt32LE(0xD4000001);
	uc.memWrite(0x10000n, svc);

	uc.regWrite(ARM64_REG.PC, 0x10000n);

	// Setup a minimal stack
	uc.memMap(0x80000n, 0x1000, PROT.ALL);
	uc.regWrite(ARM64_REG.SP, 0x80FF0n);

	console.log('  Calling emuStart with SVC, no INTR hook...');
	uc.emuStart(0x10000n, 0n, 0, 1);
	console.log('  emuStart returned OK!');

	const pcAfter = uc.regRead(ARM64_REG.PC);
	console.log('  PC after:', '0x' + BigInt(pcAfter).toString(16));
	console.log('  [PASS] SVC without hook did not crash');

	uc.close();
} catch (err) {
	console.log('  [FAIL]', err.message);
}

// ---- Test 3: emuStart with INTR hook (BlockingCall path) ----
console.log('\n--- Test 3: ARM64 SVC #0 (count=1, sync, WITH INTR hook) ---');
try {
	const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);

	uc.memMap(0x10000n, 0x1000, PROT.ALL);

	// Write SVC #0: 0xD4000001
	const svc = Buffer.alloc(4);
	svc.writeUInt32LE(0xD4000001);
	uc.memWrite(0x10000n, svc);

	uc.regWrite(ARM64_REG.PC, 0x10000n);

	uc.memMap(0x80000n, 0x1000, PROT.ALL);
	uc.regWrite(ARM64_REG.SP, 0x80FF0n);

	// Add INTR hook — this uses BlockingCall + condition_variable
	let hookCalled = false;
	const hookHandle = uc.hookAdd(4 /* UC_HOOK_INTR */, (intno) => {
		console.log('  INTR hook fired, intno:', intno);
		hookCalled = true;
	});
	console.log('  INTR hook added, handle:', hookHandle);

	console.log('  Calling emuStart with SVC + INTR hook (THIS MAY CRASH)...');
	uc.emuStart(0x10000n, 0n, 0, 1);
	console.log('  emuStart returned OK! hookCalled:', hookCalled);

	uc.hookDel(hookHandle);
	uc.close();
	console.log('  [PASS] SVC with INTR hook did not crash');
} catch (err) {
	console.log('  [FAIL]', err.message);
}

// ---- Test 4: Multiple instructions with memory fault ----
console.log('\n--- Test 4: ARM64 MOV + unmapped access (count=3, sync) ---');
try {
	const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);

	uc.memMap(0x10000n, 0x1000, PROT.ALL);

	// mov x0, #42   -> 0xD2800540
	// mov x1, #100  -> 0xD2800C81
	// nop           -> 0xD503201F
	const code = Buffer.alloc(12);
	code.writeUInt32LE(0xD2800540, 0);
	code.writeUInt32LE(0xD2800C81, 4);
	code.writeUInt32LE(0xD503201F, 8);
	uc.memWrite(0x10000n, code);

	uc.regWrite(ARM64_REG.PC, 0x10000n);

	uc.memMap(0x80000n, 0x1000, PROT.ALL);
	uc.regWrite(ARM64_REG.SP, 0x80FF0n);

	console.log('  Calling emuStart(0x10000, 0, 0, 3)...');
	uc.emuStart(0x10000n, 0n, 0, 3);
	console.log('  emuStart returned OK!');

	const x0 = uc.regRead(ARM64_REG.X0);
	const x1 = uc.regRead(ARM64_REG.X1);
	const pc = uc.regRead(ARM64_REG.PC);
	console.log('  X0:', BigInt(x0).toString(), '(expected 42)');
	console.log('  X1:', BigInt(x1).toString(), '(expected 100)');
	console.log('  PC:', '0x' + BigInt(pc).toString(16), '(expected 0x1000c)');

	if (BigInt(x0) === 42n && BigInt(x1) === 100n) {
		console.log('  [PASS] ARM64 MOV instructions executed correctly');
	} else {
		console.log('  [FAIL] Incorrect register values');
	}

	uc.close();
} catch (err) {
	console.log('  [FAIL]', err.message);
}

console.log('\n=== All ARM64 crash tests completed ===');
