'use strict';

/**
 * Quick debug: test if Z3 solver actually works via SMTLIB2
 */

const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const Z3 = 'C:\\Users\\Mazum\\Desktop\\souper-source\\third_party\\z3-install\\bin\\z3.exe';

console.log('=== Z3 Solver Debug ===\n');

// 1. Check z3 exists
console.log(`Z3 path: ${Z3}`);
console.log(`Exists: ${fs.existsSync(Z3)}`);

// 2. Check z3 version
try {
    const ver = execSync(`"${Z3}" --version`, { encoding: 'utf-8', timeout: 5000 });
    console.log(`Version: ${ver.trim()}`);
} catch (e) {
    console.log(`Z3 --version failed: ${e.message}`);
}

// 3. Test SMTLIB2 query (same way Souper uses it)
const smtQuery = `
(set-logic QF_BV)
(declare-fun x () (_ BitVec 32))
(assert (not (= (bvsub x x) (_ bv0 32))))
(check-sat)
(exit)
`;

const tmpFile = path.join(process.env.TEMP || '.', 'souper_z3_test.smt2');
fs.writeFileSync(tmpFile, smtQuery);

console.log(`\nSMTLIB2 test query: (x - x) != 0 → should be UNSAT`);
try {
    const result = execSync(`"${Z3}" -smt2 -in < "${tmpFile}"`, {
        encoding: 'utf-8',
        timeout: 10000,
        shell: true,
    });
    console.log(`Z3 result: ${result.trim()}`);
    if (result.trim() === 'unsat') {
        console.log('✓ Z3 SMTLIB2 solver works correctly!');
    }
} catch (e) {
    console.log(`Z3 SMTLIB2 failed: ${e.message}`);
}

// Cleanup
try { fs.unlinkSync(tmpFile); } catch {}

// 4. Now test Souper module itself
console.log('\n=== Souper Module Debug ===\n');
const souper = require('..');
const opt = new souper.SouperOptimizer();

const testIR = `
define i32 @test_sub_self(i32 %x) {
entry:
  %sub = sub i32 %x, %x
  ret i32 %sub
}
`;

console.log('Testing optimize with simple IR (x - x)...');
const result = opt.optimize(testIR);
console.log(`  success: ${result.success}`);
console.log(`  candidates: ${result.candidatesFound}`);
console.log(`  replaced: ${result.candidatesReplaced}`);
console.log(`  time: ${result.optimizationTimeMs.toFixed(1)}ms`);
console.log(`  error: "${result.error}"`);

if (result.ir) {
    // Check if the IR was actually changed
    const hasSubXX = result.ir.includes('sub i32 %x, %x');
    const hasRetZero = result.ir.includes('ret i32 0');
    console.log(`\n  Original has 'sub i32 %x, %x': true`);
    console.log(`  Output has 'sub i32 %x, %x': ${hasSubXX}`);
    console.log(`  Output has 'ret i32 0': ${hasRetZero}`);
    if (!hasSubXX && hasRetZero) {
        console.log('  ✓ SOUPER ACTUALLY OPTIMIZED THE IR!');
    } else if (hasSubXX) {
        console.log('  ✗ IR unchanged — solver not replacing yet');
    }
}

opt.close();
