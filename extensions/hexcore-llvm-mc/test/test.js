'use strict';

const assert = require('assert');
const path = require('path');

// Load the module
let llvmMc;
try {
    llvmMc = require('../index.js');
} catch (err) {
    console.error('Failed to load hexcore-llvm-mc:', err.message);
    console.error('Make sure the module is built with: npm run build');
    process.exit(1);
}

const { LlvmMc, TRIPLE, SYNTAX, OPTION, ERR, CPU, FEATURES, version, getTargets } = llvmMc;

// Test counters
let passed = 0;
let failed = 0;
let skipped = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  \u2713 ${name}`);
        passed++;
    } catch (err) {
        console.log(`  \u2717 ${name}`);
        console.log(`    Error: ${err.message}`);
        failed++;
    }
}

function skip(name, reason) {
    console.log(`  \u25CB ${name} (skipped: ${reason})`);
    skipped++;
}

function testAsync(name, fn) {
    return fn()
        .then(() => {
            console.log(`  \u2713 ${name}`);
            passed++;
        })
        .catch(err => {
            console.log(`  \u2717 ${name}`);
            console.log(`    Error: ${err.message}`);
            failed++;
        });
}

// Check which targets are available
const availableTargets = getTargets().map(t => t.name);
const hasX86 = availableTargets.some(t => t.includes('x86') || t.includes('i686'));
const hasARM = availableTargets.some(t => t.includes('arm') || t.includes('aarch64'));
const hasMIPS = availableTargets.some(t => t.includes('mips'));
const hasRISCV = availableTargets.some(t => t.includes('riscv'));

// ============================================================================
// Module Tests
// ============================================================================

console.log('\n=== Module Tests ===\n');

test('version() returns a string', () => {
    const ver = version();
    assert.strictEqual(typeof ver, 'string');
    assert.match(ver, /^\d+\.\d+\.\d+$/);
    console.log(`    LLVM Version: ${ver}`);
});

test('getTargets() returns array of targets', () => {
    const targets = getTargets();
    assert(Array.isArray(targets));
    assert(targets.length > 0);
    console.log(`    Available targets: ${targets.map(t => t.name).join(', ')}`);
});

test('TRIPLE constants are defined', () => {
    assert.strictEqual(typeof TRIPLE.X86_64, 'string');
    assert.strictEqual(typeof TRIPLE.ARM64, 'string');
    assert.strictEqual(typeof TRIPLE.RISCV64, 'string');
});

test('SYNTAX constants are defined', () => {
    assert.strictEqual(typeof SYNTAX.INTEL, 'number');
    assert.strictEqual(typeof SYNTAX.ATT, 'number');
});

test('ERR constants are defined', () => {
    assert.strictEqual(ERR.OK, 0);
    assert.strictEqual(typeof ERR.INVALID_TRIPLE, 'number');
    assert.strictEqual(typeof ERR.ASM_FAILED, 'number');
});

// ============================================================================
// Constructor Tests
// ============================================================================

console.log('\n=== Constructor Tests ===\n');

test('LlvmMc constructor with valid triple', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    assert(asm.isOpen);
    assert.strictEqual(asm.getTriple(), TRIPLE.X86_64);
    asm.close();
});

test('LlvmMc constructor with CPU', () => {
    const asm = new LlvmMc(TRIPLE.X86_64, 'generic');
    assert.strictEqual(asm.getCpu(), 'generic');
    asm.close();
});

test('LlvmMc constructor with features', () => {
    const asm = new LlvmMc(TRIPLE.X86_64, 'generic', '+avx2');
    assert.strictEqual(asm.getFeatures(), '+avx2');
    asm.close();
});

test('LlvmMc constructor throws on invalid triple', () => {
    assert.throws(() => {
        new LlvmMc('invalid-triple-here');
    }, /Failed to lookup target/);
});

// ============================================================================
// x86-64 Assembly Tests
// ============================================================================

console.log('\n=== x86-64 Assembly Tests ===\n');

if (hasX86) {
    test('x86-64: Basic assembly works', () => {
        const asm = new LlvmMc(TRIPLE.X86_64);
        const result = asm.assemble('nop');
        assert(result.bytes instanceof Buffer);
        assert(result.size > 0);
        asm.close();
    });

    test('x86-64: Assembly result has correct properties', () => {
        const asm = new LlvmMc(TRIPLE.X86_64);
        const result = asm.assemble('ret');
        assert(result.bytes instanceof Buffer);
        assert.strictEqual(typeof result.size, 'number');
        assert.strictEqual(typeof result.address, 'bigint');
        assert.strictEqual(typeof result.statement, 'string');
        asm.close();
    });

    test('x86-64: Intel syntax mov instruction', () => {
        const asm = new LlvmMc(TRIPLE.X86_64);
        asm.setOption(OPTION.SYNTAX, SYNTAX.INTEL);
        const result = asm.assemble('mov rax, rbx');
        assert(result.bytes.length > 0);
        asm.close();
    });

    test('x86-64: Multiple instructions', () => {
        const asm = new LlvmMc(TRIPLE.X86_64);
        const results = asm.assembleMultiple([
            'push rbp',
            'mov rbp, rsp',
            'pop rbp',
            'ret'
        ]);
        assert.strictEqual(results.length, 4);
        results.forEach(r => {
            assert(r.bytes instanceof Buffer);
            assert(r.size > 0);
        });
        asm.close();
    });
} else {
    skip('x86-64 tests', 'X86 target not available');
}

// ============================================================================
// x86 (32-bit) Assembly Tests
// ============================================================================

console.log('\n=== x86 (32-bit) Assembly Tests ===\n');

if (hasX86) {
    test('x86: Basic assembly works', () => {
        const asm = new LlvmMc(TRIPLE.X86);
        const result = asm.assemble('nop');
        assert(result.bytes instanceof Buffer);
        asm.close();
    });

    test('x86: 32-bit register instruction', () => {
        const asm = new LlvmMc(TRIPLE.X86);
        const result = asm.assemble('mov eax, ebx');
        assert(result.bytes.length > 0);
        asm.close();
    });
} else {
    skip('x86 tests', 'X86 target not available');
}

// ============================================================================
// ARM64 Assembly Tests (conditional)
// ============================================================================

console.log('\n=== ARM64 Assembly Tests ===\n');

if (hasARM) {
    test('ARM64: Basic assembly works', () => {
        const asm = new LlvmMc(TRIPLE.ARM64);
        const result = asm.assemble('nop');
        assert(result.bytes instanceof Buffer);
        asm.close();
    });

    test('ARM64: mov instruction', () => {
        const asm = new LlvmMc(TRIPLE.ARM64);
        const result = asm.assemble('mov x0, x1');
        assert(result.bytes.length > 0);
        asm.close();
    });
} else {
    skip('ARM64 tests', 'ARM target not available in this build');
}

// ============================================================================
// Async Assembly Tests
// ============================================================================

console.log('\n=== Async Assembly Tests ===\n');

async function runAsyncTests() {
    if (hasX86) {
        await testAsync('x86-64: Async assembly works', async () => {
            const asm = new LlvmMc(TRIPLE.X86_64);
            const result = await asm.assembleAsync('nop');
            assert(result.bytes instanceof Buffer);
            assert(result.size > 0);
            asm.close();
        });

        await testAsync('x86-64: Async multiple calls', async () => {
            const asm = new LlvmMc(TRIPLE.X86_64);
            const [r1, r2, r3] = await Promise.all([
                asm.assembleAsync('nop'),
                asm.assembleAsync('ret'),
                asm.assembleAsync('push rax')
            ]);
            assert(r1.bytes instanceof Buffer);
            assert(r2.bytes instanceof Buffer);
            assert(r3.bytes instanceof Buffer);
            asm.close();
        });
    }
}

// ============================================================================
// Error Handling Tests
// ============================================================================

console.log('\n=== Error Handling Tests ===\n');

test('Assembly throws on invalid instruction', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    assert.throws(() => {
        asm.assemble('invalidinstruction xyz');
    });
    asm.close();
});

test('close() prevents further operations', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    asm.close();
    assert.strictEqual(asm.isOpen, false);
    assert.throws(() => {
        asm.assemble('nop');
    }, /closed/);
});

test('Multiple close() calls are safe', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    asm.close();
    asm.close(); // Should not throw
    asm.close();
});

// ============================================================================
// Address Tests
// ============================================================================

console.log('\n=== Address Tests ===\n');

test('Assembly with BigInt address', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    const result = asm.assemble('nop', 0x1000n);
    assert.strictEqual(result.address, 0x1000n);
    asm.close();
});

test('Assembly with number address', () => {
    const asm = new LlvmMc(TRIPLE.X86_64);
    const result = asm.assemble('nop', 0x2000);
    assert.strictEqual(result.address, 0x2000n);
    asm.close();
});

// ============================================================================
// CPU and Features Tests
// ============================================================================

console.log('\n=== CPU and Features Tests ===\n');

test('Assembly with specific CPU (skylake)', () => {
    const asm = new LlvmMc(TRIPLE.X86_64, CPU.X86.SKYLAKE);
    const result = asm.assemble('nop');
    assert(result.bytes instanceof Buffer);
    asm.close();
});

test('Assembly with AVX2 feature', () => {
    const asm = new LlvmMc(TRIPLE.X86_64, 'generic', FEATURES.X86.AVX2);
    const result = asm.assemble('vaddps ymm0, ymm1, ymm2');
    assert(result.bytes.length > 0);
    asm.close();
});

// ============================================================================
// Run all tests
// ============================================================================

async function runAllTests() {
    await runAsyncTests();

    console.log('\n========================================');
    console.log(`Tests: ${passed + failed} | Passed: ${passed} | Failed: ${failed} | Skipped: ${skipped}`);
    console.log('========================================\n');

    if (failed > 0) {
        process.exit(1);
    }
}

runAllTests().catch(err => {
    console.error('Test runner error:', err);
    process.exit(1);
});
