'use strict';

/**
 * hexcore-souper — A/B Test: Helix WITHOUT vs WITH Souper
 *
 * Usage:
 *   node test/ab_test.js <path-to-ll-file>
 *   node test/ab_test.js "C:\Users\Mazum\Desktop\Intigrity\hexcore-reports\fresh-helix\kbase_jit_allocate.ll"
 *
 * What it does:
 *   1. Runs helix_tool.exe on ORIGINAL IR → saves .original.c
 *   2. Runs Souper on the IR → saves .souper.ll
 *   3. Runs helix_tool.exe on SOUPER IR → saves .souper.c
 *   4. Shows comparison
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const HELIX_TOOL = 'C:\\Users\\Mazum\\Desktop\\HexCore-Helix-Original\\HexCore-Helix\\engine\\build\\helix_tool.exe';
const HELIX_FLAGS = '--use-cast-layer';

// ── Parse args ─────────────────────────────────────────────────────────
const irPath = process.argv[2];
if (!irPath || !fs.existsSync(irPath)) {
    console.error('Usage: node test/ab_test.js <path-to-ll-file>');
    console.error(irPath ? `File not found: ${irPath}` : 'No file specified');
    process.exit(1);
}

const souper = require('..');
const fileName = path.basename(irPath, '.ll');
const dir = path.dirname(irPath);
const irText = fs.readFileSync(irPath, 'utf-8');

console.log(`\n${'='.repeat(70)}`);
console.log(`  A/B TEST: Helix WITHOUT vs WITH Souper`);
console.log(`  File: ${fileName}.ll (${irText.split('\n').length} lines)`);
console.log(`${'='.repeat(70)}\n`);

// ── Step 1: Helix on ORIGINAL IR ───────────────────────────────────────
console.log('[A] Running Helix on ORIGINAL IR...');
const originalOut = path.join(dir, `${fileName}.original.c`);
try {
    const helixA = execSync(
        `"${HELIX_TOOL}" ${HELIX_FLAGS} "${irPath}"`,
        { encoding: 'utf-8', timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
    );
    fs.writeFileSync(originalOut, helixA);
    const originalLines = helixA.split('\n').length;
    console.log(`    Output: ${originalLines} lines → ${originalOut}`);
} catch (e) {
    console.log(`    Helix failed on original: ${e.message?.slice(0, 200)}`);
    fs.writeFileSync(originalOut, `// Helix failed: ${e.message?.slice(0, 500)}`);
}

// ── Step 2: Souper optimization ────────────────────────────────────────
console.log('\n[SOUPER] Running Souper optimization...');
const optimizer = new souper.SouperOptimizer();
const souperResult = optimizer.optimize(irText, {
    maxCandidates: 1000,
    timeoutMs: 30000,
});
optimizer.close();

const souperIrPath = path.join(dir, `${fileName}.souper.ll`);
console.log(`    success:            ${souperResult.success}`);
console.log(`    candidatesFound:    ${souperResult.candidatesFound}`);
console.log(`    candidatesReplaced: ${souperResult.candidatesReplaced}`);
console.log(`    time:               ${souperResult.optimizationTimeMs.toFixed(1)}ms`);

if (!souperResult.success || !souperResult.ir) {
    console.log(`    ERROR: ${souperResult.error}`);
    console.log('\nCannot run B test without optimized IR.');
    process.exit(1);
}

fs.writeFileSync(souperIrPath, souperResult.ir);
console.log(`    Saved: ${souperIrPath}`);

// ── Step 3: Helix on SOUPER-optimized IR ───────────────────────────────
console.log('\n[B] Running Helix on SOUPER-OPTIMIZED IR...');
const souperOut = path.join(dir, `${fileName}.souper.c`);
try {
    const helixB = execSync(
        `"${HELIX_TOOL}" ${HELIX_FLAGS} "${souperIrPath}"`,
        { encoding: 'utf-8', timeout: 60000, maxBuffer: 10 * 1024 * 1024 }
    );
    fs.writeFileSync(souperOut, helixB);
    const souperLines = helixB.split('\n').length;
    console.log(`    Output: ${souperLines} lines → ${souperOut}`);
} catch (e) {
    console.log(`    Helix failed on souper IR: ${e.message?.slice(0, 200)}`);
    fs.writeFileSync(souperOut, `// Helix failed: ${e.message?.slice(0, 500)}`);
}

// ── Step 4: Comparison ─────────────────────────────────────────────────
console.log(`\n${'='.repeat(70)}`);
console.log('  COMPARISON');
console.log(`${'='.repeat(70)}`);

const origC = fs.existsSync(originalOut) ? fs.readFileSync(originalOut, 'utf-8') : '';
const soupC = fs.existsSync(souperOut) ? fs.readFileSync(souperOut, 'utf-8') : '';

const origIrLines = irText.split('\n').length;
const soupIrLines = souperResult.ir.split('\n').length;
const origCLines = origC.split('\n').length;
const soupCLines = soupC.split('\n').length;

console.log(`\n  IR:  Original ${origIrLines} lines → Souper ${soupIrLines} lines (${origIrLines - soupIrLines > 0 ? '-' : '+'}${Math.abs(origIrLines - soupIrLines)})`);
console.log(`  C:   Original ${origCLines} lines → Souper ${soupCLines} lines (${origCLines - soupCLines > 0 ? '-' : '+'}${Math.abs(origCLines - soupCLines)})`);
console.log(`\n  Souper candidates: ${souperResult.candidatesFound} found, ${souperResult.candidatesReplaced} replaced`);

console.log(`\n  Files saved:`);
console.log(`    [A] ${originalOut}`);
console.log(`    [S] ${souperIrPath}`);
console.log(`    [B] ${souperOut}`);
console.log(`\n  Compare: diff "${originalOut}" "${souperOut}"`);
console.log(`${'='.repeat(70)}\n`);
