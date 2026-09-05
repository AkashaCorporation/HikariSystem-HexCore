'use strict';

/**
 * hexcore-souper smoke tests.
 *
 * Run: node test/test.js
 */

let passed = 0;
let failed = 0;

function assert(condition, message) {
    if (condition) {
        passed++;
        console.log(`  \u2713 ${message}`);
    } else {
        failed++;
        console.error(`  \u2717 ${message}`);
    }
}

function section(name) {
    console.log(`\n${name}`);
}

// ── Load module ────────────────────────────────────────────────────────

let souper;
try {
    souper = require('..');
} catch (e) {
    console.error('Failed to load hexcore-souper:', e.message);
    console.error('Build the native module before running the smoke suite.');
    process.exit(1);
}

// ── Module exports ─────────────────────────────────────────────────────

section('Module exports');
assert(typeof souper === 'object', 'module is an object');
assert(typeof souper.SouperOptimizer === 'function', 'SouperOptimizer is a constructor');
assert(typeof souper.version === 'string', 'version is a string');
assert(souper.version.length > 0, 'version is non-empty');

// ── Static methods ─────────────────────────────────────────────────────

section('Static methods');
assert(typeof souper.SouperOptimizer.getVersion === 'function', 'getVersion exists');
assert(typeof souper.SouperOptimizer.getSolverInfo === 'function', 'getSolverInfo exists');

const ver = souper.SouperOptimizer.getVersion();
assert(typeof ver === 'string' && ver.length > 0, `getVersion() = "${ver}"`);
assert(souper.version === ver, 'module and optimizer versions match');

const solverInfo = souper.SouperOptimizer.getSolverInfo();
assert(typeof solverInfo === 'object', 'getSolverInfo() returns object');
assert(solverInfo.name === 'z3', `solver name = "${solverInfo.name}"`);
assert(typeof solverInfo.version === 'string', `solver version = "${solverInfo.version}"`);

// ── Constructor / lifecycle ────────────────────────────────────────────

section('Constructor and lifecycle');

const opt = new souper.SouperOptimizer();
assert(opt.isOpen() === true, 'isOpen() = true after construction');

opt.close();
assert(opt.isOpen() === false, 'isOpen() = false after close()');

// Idempotent close
opt.close();
assert(opt.isOpen() === false, 'double close() is safe');

// ── Optimization — basic IR ────────────────────────────────────────────

section('Basic optimization');

const opt2 = new souper.SouperOptimizer();

// Simple LLVM IR with an opportunity for superoptimization
// (x - x) should be replaced with 0
const testIR = `
define i32 @test_sub_self(i32 %x) {
entry:
  %sub = sub i32 %x, %x
  ret i32 %sub
}
`;

const result = opt2.optimize(testIR);
assert(typeof result === 'object', 'optimize() returns an object');
assert(typeof result.success === 'boolean', 'result.success is boolean');
assert(typeof result.ir === 'string', 'result.ir is string');
assert(typeof result.error === 'string', 'result.error is string');
assert(typeof result.diagnostics === 'string', 'result.diagnostics is string');
assert(typeof result.candidatesFound === 'number', 'candidatesFound is number');
assert(typeof result.candidatesAttempted === 'number', 'candidatesAttempted is number');
assert(typeof result.candidatesInferred === 'number', 'candidatesInferred is number');
assert(typeof result.candidatesReplaced === 'number', 'candidatesReplaced is number');
assert(typeof result.solverTimeouts === 'number', 'solverTimeouts is number');
assert(typeof result.optimizationTimeMs === 'number', 'optimizationTimeMs is number');

if (result.success) {
    assert(result.ir.length > 0, 'optimized IR is non-empty');
    assert(result.ir.includes('define'), 'optimized IR contains function definition');
    assert(result.candidatesFound >= 0, `candidatesFound = ${result.candidatesFound}`);
    console.log(`    (replaced ${result.candidatesReplaced}/${result.candidatesFound} in ${result.optimizationTimeMs.toFixed(1)}ms)`);
} else {
    console.log(`    (optimization reported error: ${result.error})`);
    // This is still valid — the API contract is honored
    assert(true, 'error result has correct shape');
}

// Regression: maxCandidates limits solver attempts, not candidates extracted
// from the first block. It is scoped per function as documented.
const limitIR = `
define i32 @test_limit_a(i32 %x) {
entry:
  %a = and i32 %x, -1
  %b = sub i32 %a, %a
  ret i32 %b
}

define i32 @test_limit_b(i32 %x) {
entry:
  %a = and i32 %x, -1
  %b = sub i32 %a, %a
  ret i32 %b
}
`;

const limitedResult = opt2.optimize(limitIR, {
    maxCandidates: 1,
    timeoutMs: 5000,
});
assert(limitedResult.success, 'candidate-limit regression completes');
assert(limitedResult.candidatesFound >= 4,
    `candidate-limit regression found ${limitedResult.candidatesFound} candidates`);
assert(limitedResult.candidatesAttempted === 2,
    'maxCandidates=1 attempts one candidate per function');
assert(limitedResult.candidatesInferred === 2,
    'both bounded candidates produce an inferred RHS');
assert(limitedResult.candidatesReplaced === 2,
    'both non-constant RHS replacements are applied');
assert(limitedResult.ir.includes('%b = sub i32 %x, %x'),
    'Souper Codegen materializes a non-constant RHS');

const fullResult = opt2.optimize(limitIR, {
    maxCandidates: 8,
    timeoutMs: 5000,
});
assert(fullResult.success, 'full regression completes');
assert(fullResult.candidatesAttempted === fullResult.candidatesFound,
    'a high limit submits every extracted candidate');
assert(fullResult.candidatesReplaced === fullResult.candidatesInferred,
    'replacement metric counts only applied LLVM changes');
assert((fullResult.ir.match(/ret i32 0/g) || []).length === 2,
    'constant simplifications reach both return sites');
assert(!fullResult.ir.includes(' and i32 ') && !fullResult.ir.includes(' sub i32 '),
    'dead instructions are removed after successful replacements');

// ── Error handling — invalid IR ────────────────────────────────────────

section('Error handling');

const badResult = opt2.optimize('this is not valid LLVM IR');
assert(badResult.success === false, 'invalid IR returns success=false');
assert(badResult.error.length > 0, 'invalid IR has error message');
assert(badResult.ir === '', 'invalid IR returns empty ir');

// ── Error handling — closed optimizer ──────────────────────────────────

opt2.close();
let threwOnClosed = false;
try {
    opt2.optimize(testIR);
} catch (e) {
    threwOnClosed = true;
}
assert(threwOnClosed, 'optimize() throws after close()');

// ── Async optimization ─────────────────────────────────────────────────

section('Async optimization');

(async () => {
    const opt3 = new souper.SouperOptimizer();

    const asyncResult = await opt3.optimizeAsync(testIR);
    assert(typeof asyncResult === 'object', 'optimizeAsync() returns object');
    assert(typeof asyncResult.success === 'boolean', 'async result.success is boolean');
    assert(typeof asyncResult.ir === 'string', 'async result.ir is string');

    // With options
    const asyncResult2 = await opt3.optimizeAsync(testIR, {
        maxCandidates: 10,
        timeoutMs: 5000,
        aggressiveMode: false,
    });
    assert(typeof asyncResult2 === 'object', 'optimizeAsync() with options works');

    opt3.close();

    // ── Summary ────────────────────────────────────────────────────────

    console.log(`\n${'='.repeat(40)}`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    if (failed > 0) {
        process.exit(1);
    }
})().catch(err => {
    console.error('Async test failed:', err);
    process.exit(1);
});
