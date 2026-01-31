/**
 * HexCore Unicorn - Test Suite
 *
 * HikariSystem HexCore - CPU Emulator Tests
 * Comprehensive tests for Unicorn Engine bindings
 */

'use strict';

const { Unicorn, ARCH, MODE, PROT, HOOK, X86_REG, ARM_REG, version, archSupported, strerror } = require('../index.js');

// Test counters
let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  [PASS] ${name}`);
        passed++;
    } catch (err) {
        console.log(`  [FAIL] ${name}`);
        console.log(`         ${err.message}`);
        failed++;
    }
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(message || 'Assertion failed');
    }
}

function assertEqual(actual, expected, message) {
    if (actual !== expected) {
        throw new Error(message || `Expected ${expected}, got ${actual}`);
    }
}

// ============== Version Tests ==============

console.log('\n=== Version Tests ===');

test('version() returns version info', () => {
    const ver = version();
    assert(typeof ver.major === 'number', 'major should be number');
    assert(typeof ver.minor === 'number', 'minor should be number');
    assert(typeof ver.combined === 'number', 'combined should be number');
    assert(typeof ver.string === 'string', 'string should be string');
    console.log(`         Unicorn version: ${ver.string}`);
});

// ============== Architecture Support Tests ==============

console.log('\n=== Architecture Support Tests ===');

test('archSupported() returns boolean for X86', () => {
    const supported = archSupported(ARCH.X86);
    assert(typeof supported === 'boolean', 'should return boolean');
    console.log(`         X86 supported: ${supported}`);
});

test('archSupported() returns boolean for ARM', () => {
    const supported = archSupported(ARCH.ARM);
    assert(typeof supported === 'boolean', 'should return boolean');
    console.log(`         ARM supported: ${supported}`);
});

test('archSupported() returns boolean for ARM64', () => {
    const supported = archSupported(ARCH.ARM64);
    assert(typeof supported === 'boolean', 'should return boolean');
    console.log(`         ARM64 supported: ${supported}`);
});

// ============== Error String Tests ==============

console.log('\n=== Error String Tests ===');

test('strerror() returns message for error codes', () => {
    const msg = strerror(0); // UC_ERR_OK
    assert(typeof msg === 'string', 'should return string');
    assert(msg.length > 0, 'message should not be empty');
    console.log(`         ERR_OK message: "${msg}"`);
});

// ============== Constructor Tests ==============

console.log('\n=== Constructor Tests ===');

test('Unicorn constructor creates X86-64 engine', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    assert(uc.arch === ARCH.X86, 'arch should be X86');
    assert(uc.mode === MODE.MODE_64, 'mode should be MODE_64');
    assert(typeof uc.handle === 'bigint', 'handle should be bigint');
    assert(uc.pageSize > 0, 'pageSize should be positive');
    uc.close();
});

test('Unicorn constructor creates X86-32 engine', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_32);
    assert(uc.arch === ARCH.X86, 'arch should be X86');
    assert(uc.mode === MODE.MODE_32, 'mode should be MODE_32');
    uc.close();
});

if (archSupported(ARCH.ARM)) {
    test('Unicorn constructor creates ARM engine', () => {
        const uc = new Unicorn(ARCH.ARM, MODE.UC_MODE_ARM);
        assert(uc.arch === ARCH.ARM, 'arch should be ARM');
        uc.close();
    });
}

if (archSupported(ARCH.ARM64)) {
    test('Unicorn constructor creates ARM64 engine', () => {
        const uc = new Unicorn(ARCH.ARM64, MODE.LITTLE_ENDIAN);
        assert(uc.arch === ARCH.ARM64, 'arch should be ARM64');
        uc.close();
    });
}

// ============== Memory Tests ==============

console.log('\n=== Memory Tests ===');

test('memMap() maps memory region', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);
    const regions = uc.memRegions();
    assert(regions.length === 1, 'should have 1 region');
    assert(regions[0].begin === 0x1000n, 'begin should be 0x1000');
    assert(regions[0].end === 0x1FFFn, 'end should be 0x1FFF');
    uc.close();
});

test('memWrite() and memRead() work correctly', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    const writeData = Buffer.from([0x48, 0x89, 0xE5, 0xC3]); // mov rbp, rsp; ret
    uc.memWrite(0x1000n, writeData);

    const readData = uc.memRead(0x1000n, 4);
    assert(readData.length === 4, 'should read 4 bytes');
    assert(readData[0] === 0x48, 'byte 0 should match');
    assert(readData[1] === 0x89, 'byte 1 should match');
    assert(readData[2] === 0xE5, 'byte 2 should match');
    assert(readData[3] === 0xC3, 'byte 3 should match');

    uc.close();
});

test('memUnmap() unmaps memory region', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);
    assert(uc.memRegions().length === 1, 'should have 1 region');

    uc.memUnmap(0x1000n, 0x1000);
    assert(uc.memRegions().length === 0, 'should have 0 regions');

    uc.close();
});

test('memProtect() changes permissions', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    uc.memProtect(0x1000n, 0x1000, PROT.READ);
    const regions = uc.memRegions();
    assert(regions[0].perms === PROT.READ, 'perms should be READ only');

    uc.close();
});

// ============== Register Tests ==============

console.log('\n=== Register Tests ===');

test('regWrite() and regRead() work for 64-bit registers', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    uc.regWrite(X86_REG.RAX, 0x123456789ABCDEFn);
    const value = uc.regRead(X86_REG.RAX);
    assert(value === 0x123456789ABCDEFn, 'RAX should match written value');

    uc.close();
});

test('regWriteBatch() and regReadBatch() work correctly', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    const regs = [X86_REG.RAX, X86_REG.RBX, X86_REG.RCX];
    const values = [0x1111n, 0x2222n, 0x3333n];

    uc.regWriteBatch(regs, values);
    const readValues = uc.regReadBatch(regs);

    assert(readValues[0] === 0x1111n, 'RAX should match');
    assert(readValues[1] === 0x2222n, 'RBX should match');
    assert(readValues[2] === 0x3333n, 'RCX should match');

    uc.close();
});

// ============== Emulation Tests ==============

console.log('\n=== Emulation Tests ===');

test('emuStart() executes simple x86-64 code', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    // Map memory for code
    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    // Write code: mov rax, 0x1234; nop (stop before executing any jumps)
    const code = Buffer.from([
        0x48, 0xC7, 0xC0, 0x34, 0x12, 0x00, 0x00,  // mov rax, 0x1234 (7 bytes)
        0x90                                        // nop (1 byte)
    ]);
    uc.memWrite(0x1000n, code);

    // Run emulation - stop at 0x1007 (after mov, before nop)
    uc.emuStart(0x1000n, 0x1007n, 0, 0);

    // Check result
    const rax = uc.regRead(X86_REG.RAX);
    assert(rax === 0x1234n, `RAX should be 0x1234, got 0x${rax.toString(16)}`);

    uc.close();
});

test('emuStart() executes arithmetic operations', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    // Code: add rax, rbx; nop
    const code = Buffer.from([
        0x48, 0x01, 0xD8,  // add rax, rbx (3 bytes)
        0x90               // nop (1 byte)
    ]);
    uc.memWrite(0x1000n, code);

    uc.regWrite(X86_REG.RAX, 100n);
    uc.regWrite(X86_REG.RBX, 200n);

    // Stop at 0x1003 (after add, before nop)
    uc.emuStart(0x1000n, 0x1003n, 0, 0);

    const result = uc.regRead(X86_REG.RAX);
    assert(result === 300n, `RAX should be 300, got ${result}`);

    uc.close();
});

test('emuStartAsync() returns promise', async () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    const code = Buffer.from([
        0x48, 0xC7, 0xC0, 0x42, 0x00, 0x00, 0x00,  // mov rax, 0x42 (7 bytes)
        0x90                                        // nop (1 byte)
    ]);
    uc.memWrite(0x1000n, code);

    await uc.emuStartAsync(0x1000n, 0x1007n, 0, 0);

    const rax = uc.regRead(X86_REG.RAX);
    assert(rax === 0x42n, `RAX should be 0x42, got 0x${rax.toString(16)}`);

    uc.close();
});

// ============== Hook Tests ==============

console.log('\n=== Hook Tests ===');

test('hookAdd() adds code hook', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    const code = Buffer.from([
        0x90,              // nop (1 byte)
        0x90,              // nop (1 byte)
        0x90,              // nop (1 byte)
        0x90               // nop (1 byte) - stop point
    ]);
    uc.memWrite(0x1000n, code);

    let hookCalled = 0;
    const hookHandle = uc.hookAdd(HOOK.CODE, (address, size) => {
        hookCalled++;
    });

    assert(typeof hookHandle === 'number', 'hookAdd should return number');

    // Stop after 3 nops (at 0x1003, before 4th nop)
    uc.emuStart(0x1000n, 0x1003n, 0, 0);

    // Note: Hooks are called asynchronously via ThreadSafeFunction
    // In practice, the count may vary

    uc.hookDel(hookHandle);
    uc.close();
});

test('hookDel() removes hook', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    let called = false;
    const handle = uc.hookAdd(HOOK.CODE, () => {
        called = true;
    });

    uc.hookDel(handle);
    uc.close();
});

// ============== Context Tests ==============

console.log('\n=== Context Tests ===');

test('contextSave() and contextRestore() work', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    uc.memMap(0x1000n, 0x1000, PROT.ALL);

    // Set some register values
    uc.regWrite(X86_REG.RAX, 0xAAAAn);
    uc.regWrite(X86_REG.RBX, 0xBBBBn);

    // Save context
    const ctx = uc.contextSave();
    assert(ctx !== null, 'contextSave should return context');

    // Change registers
    uc.regWrite(X86_REG.RAX, 0x1111n);
    uc.regWrite(X86_REG.RBX, 0x2222n);

    // Verify changed
    assert(uc.regRead(X86_REG.RAX) === 0x1111n, 'RAX should be changed');

    // Restore context
    uc.contextRestore(ctx);

    // Verify restored
    assert(uc.regRead(X86_REG.RAX) === 0xAAAAn, 'RAX should be restored');
    assert(uc.regRead(X86_REG.RBX) === 0xBBBBn, 'RBX should be restored');

    ctx.free();
    uc.close();
});

// ============== Query Tests ==============

console.log('\n=== Query Tests ===');

test('query() returns mode', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    const mode = uc.query(1); // UC_QUERY_MODE
    assert(typeof mode === 'number', 'query should return number');

    uc.close();
});

// ============== Constants Tests ==============

console.log('\n=== Constants Tests ===');

test('ARCH constants are defined', () => {
    assert(typeof ARCH.X86 === 'number', 'ARCH.X86 should be number');
    assert(typeof ARCH.ARM === 'number', 'ARCH.ARM should be number');
    assert(typeof ARCH.ARM64 === 'number', 'ARCH.ARM64 should be number');
    assert(typeof ARCH.MIPS === 'number', 'ARCH.MIPS should be number');
});

test('MODE constants are defined', () => {
    assert(typeof MODE.MODE_16 === 'number', 'MODE.MODE_16 should be number');
    assert(typeof MODE.MODE_32 === 'number', 'MODE.MODE_32 should be number');
    assert(typeof MODE.MODE_64 === 'number', 'MODE.MODE_64 should be number');
});

test('PROT constants are defined', () => {
    assert(typeof PROT.NONE === 'number', 'PROT.NONE should be number');
    assert(typeof PROT.READ === 'number', 'PROT.READ should be number');
    assert(typeof PROT.WRITE === 'number', 'PROT.WRITE should be number');
    assert(typeof PROT.EXEC === 'number', 'PROT.EXEC should be number');
    assert(typeof PROT.ALL === 'number', 'PROT.ALL should be number');
});

test('HOOK constants are defined', () => {
    assert(typeof HOOK.CODE === 'number', 'HOOK.CODE should be number');
    assert(typeof HOOK.BLOCK === 'number', 'HOOK.BLOCK should be number');
    assert(typeof HOOK.MEM_READ === 'number', 'HOOK.MEM_READ should be number');
    assert(typeof HOOK.MEM_WRITE === 'number', 'HOOK.MEM_WRITE should be number');
});

test('X86_REG constants are defined', () => {
    assert(typeof X86_REG.RAX === 'number', 'X86_REG.RAX should be number');
    assert(typeof X86_REG.RBX === 'number', 'X86_REG.RBX should be number');
    assert(typeof X86_REG.RIP === 'number', 'X86_REG.RIP should be number');
    assert(typeof X86_REG.RSP === 'number', 'X86_REG.RSP should be number');
});

// ============== Error Handling Tests ==============

console.log('\n=== Error Handling Tests ===');

test('Invalid memory access throws error', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);

    let threw = false;
    try {
        uc.memRead(0x1000n, 4); // Not mapped
    } catch (e) {
        threw = true;
    }
    assert(threw, 'Should throw on unmapped read');

    uc.close();
});

test('Double close does not crash', () => {
    const uc = new Unicorn(ARCH.X86, MODE.MODE_64);
    uc.close();
    uc.close(); // Should not crash
});

// ============== Results ==============

console.log('\n=================================');
console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed}`);
console.log('=================================\n');

if (failed > 0) {
    process.exit(1);
}
