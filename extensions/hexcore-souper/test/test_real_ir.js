'use strict';

/**
 * hexcore-souper — Real IR test
 * Tests Souper with actual Remill-lifted IR from ROTTR
 *
 * Usage:
 *   node test/test_real_ir.js <path-to-ll-file>
 *   node test/test_real_ir.js   (uses default SetHealth.ll)
 */

const fs = require('fs');
const path = require('path');

const souper = require('..');

const defaultIR = 'C:/Users/Mazum/Desktop/HexCore-LARA/hexcore-reports/11-optimizeIR-AB-test/SetHealth.ll';
const irPath = process.argv[2] || defaultIR;

if (!fs.existsSync(irPath)) {
    console.error(`File not found: ${irPath}`);
    process.exit(1);
}

const irText = fs.readFileSync(irPath, 'utf-8');
const fileName = path.basename(irPath);
const lines = irText.split('\n').length;

console.log(`\n${'='.repeat(60)}`);
console.log(`  Souper v${souper.SouperOptimizer.getVersion()} — Real IR Test`);
console.log(`  File: ${fileName} (${lines} lines, ${(irText.length / 1024).toFixed(1)} KB)`);
console.log(`  Solver: ${souper.SouperOptimizer.getSolverInfo().name} ${souper.SouperOptimizer.getSolverInfo().version}`);
console.log(`${'='.repeat(60)}\n`);

const optimizer = new souper.SouperOptimizer();

console.log('Running Souper optimization...\n');
const result = optimizer.optimize(irText, {
    maxCandidates: 500,
    timeoutMs: 30000,
});

console.log(`  success:            ${result.success}`);
console.log(`  candidatesFound:    ${result.candidatesFound}`);
console.log(`  candidatesReplaced: ${result.candidatesReplaced}`);
console.log(`  optimizationTimeMs: ${result.optimizationTimeMs.toFixed(1)}ms`);
console.log(`  output IR lines:    ${result.ir ? result.ir.split('\n').length : 0}`);

if (result.error) {
    console.log(`  error: ${result.error}`);
}

if (result.success && result.ir) {
    // Save optimized IR
    const outPath = irPath.replace('.ll', '.souper.ll');
    fs.writeFileSync(outPath, result.ir, 'utf-8');
    console.log(`\n  Saved optimized IR to: ${outPath}`);

    // Compare sizes
    const origLines = irText.split('\n').length;
    const optLines = result.ir.split('\n').length;
    const diff = origLines - optLines;
    console.log(`  Original: ${origLines} lines`);
    console.log(`  Optimized: ${optLines} lines`);
    console.log(`  Delta: ${diff > 0 ? '-' : '+'}${Math.abs(diff)} lines (${diff > 0 ? 'reduced' : 'expanded'})`);
}

optimizer.close();

console.log(`\n${'='.repeat(60)}`);
console.log(`  ${result.candidatesFound > 0 ? 'Souper found optimization candidates!' : 'No candidates found.'}`);
console.log(`${'='.repeat(60)}\n`);
