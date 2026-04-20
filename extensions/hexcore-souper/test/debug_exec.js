'use strict';
/**
 * Test: Does Z3 actually work via LLVM's sys::ExecuteAndWait?
 * Writes a simple SMTLIB2 query to a temp file, then checks if
 * Souper's external solver can read the response.
 */
const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const Z3 = 'C:\\Users\\Mazum\\Desktop\\souper-source\\third_party\\z3-install\\bin\\z3.exe';

// Test 1: Direct spawn (like LLVM's CreateProcess would)
console.log('=== Test 1: spawnSync z3.exe ===');
const inFile = path.join(process.env.TEMP, 'souper_test_in.smt2');
const outFile = path.join(process.env.TEMP, 'souper_test_out.txt');
const errFile = path.join(process.env.TEMP, 'souper_test_err.txt');

fs.writeFileSync(inFile, '(check-sat)\n(exit)\n');

const r = spawnSync(Z3, ['-smt2', inFile], {
    timeout: 10000,
    encoding: 'utf-8',
});
console.log(`  status: ${r.status}`);
console.log(`  stdout: "${r.stdout?.trim()}"`);
console.log(`  stderr: "${r.stderr?.trim()}"`);
console.log(`  error: ${r.error || 'none'}`);

// Test 2: With stdin redirect (like LLVM does)
console.log('\n=== Test 2: stdin redirect ===');
const r2 = spawnSync(Z3, ['-smt2', '-in'], {
    input: '(check-sat)\n(exit)\n',
    timeout: 10000,
    encoding: 'utf-8',
});
console.log(`  status: ${r2.status}`);
console.log(`  stdout: "${r2.stdout?.trim()}"`);
console.log(`  error: ${r2.error || 'none'}`);

// Test 3: With file as stdin (how LLVM redirects)
console.log('\n=== Test 3: file redirect (LLVM style) ===');
try {
    const fd = fs.openSync(inFile, 'r');
    const r3 = spawnSync(Z3, ['-smt2', '-in'], {
        stdio: [fd, 'pipe', 'pipe'],
        timeout: 10000,
        encoding: 'utf-8',
    });
    fs.closeSync(fd);
    console.log(`  status: ${r3.status}`);
    console.log(`  stdout: "${r3.stdout?.trim()}"`);
    console.log(`  error: ${r3.error || 'none'}`);
} catch (e) {
    console.log(`  Failed: ${e.message}`);
}

// Test 4: Check if path with forward slashes works
console.log('\n=== Test 4: forward slash path ===');
const Z3_FWD = Z3.replace(/\\/g, '/');
const r4 = spawnSync(Z3_FWD, ['--version'], { encoding: 'utf-8', timeout: 5000 });
console.log(`  path: ${Z3_FWD}`);
console.log(`  status: ${r4.status}`);
console.log(`  stdout: "${r4.stdout?.trim()}"`);
console.log(`  error: ${r4.error || 'none'}`);

// Cleanup
try { fs.unlinkSync(inFile); } catch {}
