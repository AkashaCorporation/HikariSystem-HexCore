#!/usr/bin/env node
/**
 * Elixir breakpoint isolation test.
 *
 * Question we're answering: does the mere presence of a registered
 * breakpoint (or a multi-run pattern) break Azoth's API-hook tracking?
 *
 * Procedure: run four experiments on the same v6.1 binary, each with a
 * fresh Emulator:
 *
 *   A. baseline: emu.run(entry, 0n) once, report apiCallCount.
 *   B. BP at never-hit address: breakpointAdd(0xDEAD), emu.run(entry, 0n).
 *   C. BP at entry, no intervention: breakpointAdd(entry), emu.run(entry, 0n).
 *      Expect: BP fires immediately, apiCallCount=0 (no instructions ran).
 *   D. Full Oracle dance: BP at entry, run → stop at BP → del BP → runN 1
 *      → re-add BP → run(newPc). This mirrors what oracleAdapter does.
 *
 * If A=B=8 APIs and D=0, the dance is breaking state. If A=8 and B=0,
 * the BP hook itself breaks tracking — meaning the Unicorn UC_HOOK_CODE
 * we installed conflicts with Elixir's api-hook code.
 */

import { createRequire } from 'module';
import { pathToFileURL } from 'url';
import { readFileSync } from 'fs';
import path from 'path';

const require = createRequire(import.meta.url);
// Sample to test against — override via ELIXIR_BP_SAMPLE env var.
// Default relative to this script's parent repo is reasonable for CI.
const sample = process.env.ELIXIR_BP_SAMPLE
    || process.argv[2]
    || 'sample.exe';
// Elixir binding resolves relative to this repo (scripts/ → extensions/hexcore-elixir).
// Can be overridden via ELIXIR_MODULE env var for standalone testing.
const elixirModule = process.env.ELIXIR_MODULE
    || new URL('../extensions/hexcore-elixir/index.js', import.meta.url).pathname.replace(/^\//, '');

const elixir = require(elixirModule);
if (!elixir.Emulator) {
    console.error('Elixir not available:', elixir.loadError);
    process.exit(1);
}

function newEmu() {
    return new elixir.Emulator({
        arch: 'x86_64',
        maxInstructions: 2_000_000,
        verbose: false,
    });
}

function runExperiment(name, fn) {
    const emu = newEmu();
    const data = readFileSync(sample);
    const entry = emu.load(data);
    const result = fn(emu, entry);
    const count = emu.getApiCallCount();
    emu.dispose();
    console.log(`${name.padEnd(40)} entry=0x${entry.toString(16)} ${JSON.stringify(result)} apiCount=${count}`);
    return { name, entry, result, count };
}

console.log('=== Elixir breakpoint isolation test ===');
console.log(`Sample: ${sample}\n`);

runExperiment('A: baseline (no BP)', (emu, entry) => {
    const r = emu.run(entry, 0n);
    return { kind: r.kind, insns: r.instructionsExecuted };
});

runExperiment('B: BP at never-hit 0xDEAD', (emu, entry) => {
    emu.breakpointAdd(0xDEAD_0000n);
    const r = emu.run(entry, 0n);
    return { kind: r.kind, insns: r.instructionsExecuted };
});

runExperiment('C: BP at entry, no intervention', (emu, entry) => {
    emu.breakpointAdd(entry);
    const r = emu.run(entry, 0n);
    return { kind: r.kind, insns: r.instructionsExecuted };
});

const UC_X86_REG_RIP = 41;

runExperiment('D: full Oracle dance at entry', (emu, entry) => {
    emu.breakpointAdd(entry);
    const r1 = emu.run(entry, 0n);
    const ripAfterBp = emu.regRead(UC_X86_REG_RIP);
    // step 1 past BP
    emu.breakpointDel(entry);
    const r2 = emu.runN(ripAfterBp, 0n, 1n);
    const ripAfterStep = emu.regRead(UC_X86_REG_RIP);
    emu.breakpointAdd(entry);
    // resume
    const r3 = emu.run(ripAfterStep, 0n);
    return {
        r1: { kind: r1.kind, insns: r1.instructionsExecuted, rip: '0x' + ripAfterBp.toString(16) },
        r2: { kind: r2.kind, insns: r2.instructionsExecuted, rip: '0x' + ripAfterStep.toString(16) },
        r3: { kind: r3.kind, insns: r3.instructionsExecuted },
    };
});
