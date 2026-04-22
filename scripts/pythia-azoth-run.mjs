#!/usr/bin/env node
/**
 * Project Pythia Oracle — Azoth (Elixir) standalone runner.
 *
 * Parallel of scripts/pythia-oracle-run.mjs but uses hexcore-elixir
 * (Project Azoth) as the backend instead of hexcore-debugger/Unicorn.
 * This is the DEMO PATH: Azoth's stricter anti-analysis emulation is what
 * trips v6.1-class samples; Pythia's breakpoints intercept the checks and
 * bypass them so the real payload (beacon URL) surfaces.
 *
 * Invoked directly from Claude Code via Bash — the user's "the agent
 * drives, the IDE just shows results" workflow.
 *
 * Usage:
 *   node scripts/pythia-azoth-run.mjs --job <file.json>
 *   node scripts/pythia-azoth-run.mjs --sample <exe> --pythia <dir>
 *          --triggers '[{"kind":"instruction","value":"0x140001577",...}]'
 *          [--outDir <dir>] [--maxInstructions N] [-v]
 */

import { createRequire } from 'module';
import { dirname, join, resolve } from 'path';
import { fileURLToPath } from 'url';
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync } from 'fs';

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// Unicorn 2.1 x86 register IDs. Elixir's regRead/regWrite take numeric IDs.
// 42 = RIZ (deprecated index-zero, don't use). 43 = RSI. FS_BASE/GS_BASE lack
// stable IDs — omitted here; bridge handles the absence gracefully.
const UC_X86_REG = Object.freeze({
    RAX: 35, RBP: 36, RBX: 37, RCX: 38, RDI: 39, RDX: 40,
    RIP: 41, RSI: 43, RSP: 44,
    R8:  52, R9:  53, R10: 54, R11: 55,
    R12: 56, R13: 57, R14: 58, R15: 59,
    RFLAGS: 25,
});

function load(relPath) {
    const full = join(repoRoot, relPath);
    if (!existsSync(full)) {
        console.error(`[pythia-azoth] missing: ${full}`);
        console.error(`[pythia-azoth] run: cd extensions/hexcore-disassembler && npm run compile`);
        process.exit(2);
    }
    return require(full);
}

const elixir = load('extensions/hexcore-elixir/index.js');
if (!elixir.Emulator) {
    console.error(`[pythia-azoth] Elixir not available: ${elixir.loadError}`);
    process.exit(2);
}

const { OracleSession } = load('extensions/hexcore-disassembler/out/oracle/oracleSession.js');

// ─── Arg parsing ──────────────────────────────────────────────────────────

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--job')              args.job = argv[++i];
        else if (a === '--sample')      args.sample = argv[++i];
        else if (a === '--outDir')      args.outDir = argv[++i];
        else if (a === '--pythia')      args.pythia = argv[++i];
        else if (a === '--triggers')    args.triggers = JSON.parse(argv[++i]);
        else if (a === '--maxInstructions') args.maxInstructions = Number(argv[++i]);
        else if (a === '--verbose' || a === '-v') args.verbose = true;
        else if (a === '--help' || a === '-h') { printHelp(); process.exit(0); }
        else if (a.startsWith('--')) { console.error(`[pythia-azoth] unknown flag: ${a}`); process.exit(2); }
    }
    if (args.job) {
        const jobCfg = JSON.parse(readFileSync(args.job, 'utf8'));
        for (const k of ['sample', 'outDir', 'pythiaRepoPath', 'maxInstructions', 'triggers']) {
            if (args[k === 'pythiaRepoPath' ? 'pythia' : k] === undefined) {
                args[k === 'pythiaRepoPath' ? 'pythia' : k] = jobCfg[k];
            }
        }
    }
    if (!args.sample)  { console.error('[pythia-azoth] --sample required'); process.exit(2); }
    if (!args.pythia)  { console.error('[pythia-azoth] --pythia required'); process.exit(2); }
    if (!args.outDir)  args.outDir = join(repoRoot, 'reports', `azoth-${Date.now()}`);
    if (!args.maxInstructions) args.maxInstructions = 2_000_000;
    if (!args.triggers) args.triggers = [];
    return args;
}

function printHelp() {
    console.log(`Pythia/Azoth standalone runner — see script header for usage.`);
}

// ─── Host adapter (Elixir → OracleHookHost) ──────────────────────────────

function buildHost(emu, sessionId) {
    return {
        sessionId,
        regIds: {
            rax: UC_X86_REG.RAX, rbx: UC_X86_REG.RBX, rcx: UC_X86_REG.RCX, rdx: UC_X86_REG.RDX,
            rsi: UC_X86_REG.RSI, rdi: UC_X86_REG.RDI, rbp: UC_X86_REG.RBP, rsp: UC_X86_REG.RSP,
            r8:  UC_X86_REG.R8,  r9:  UC_X86_REG.R9,  r10: UC_X86_REG.R10, r11: UC_X86_REG.R11,
            r12: UC_X86_REG.R12, r13: UC_X86_REG.R13, r14: UC_X86_REG.R14, r15: UC_X86_REG.R15,
            rip: UC_X86_REG.RIP, rflags: UC_X86_REG.RFLAGS,
            // gsBase/fsBase omitted — Unicorn 2.1 deprecates direct access.
        },
        regRead: async (id) => {
            if (id == null) return 0n;
            try { return BigInt(emu.regRead(Number(id))); }
            catch (e) { throw new Error(`regRead id=${id}: ${e.message}`); }
        },
        regWrite: async (id, value) => {
            try { emu.regWrite(Number(id), typeof value === 'bigint' ? value : BigInt(value)); }
            catch (e) { throw new Error(`regWrite id=${id}: ${e.message}`); }
        },
        memRead: async (addr, size) => emu.memRead(typeof addr === 'bigint' ? addr : BigInt(addr), Number(size)),
        memWrite: async (addr, data) => { emu.memWrite(typeof addr === 'bigint' ? addr : BigInt(addr), Buffer.from(data)); },
        addBreakpoint: async (pc) => emu.breakpointAdd(typeof pc === 'bigint' ? pc : BigInt(pc)),
        removeBreakpoint: async (pc) => emu.breakpointDel(typeof pc === 'bigint' ? pc : BigInt(pc)),
        stepOne: async (pc) => { emu.runN(typeof pc === 'bigint' ? pc : BigInt(pc), 0n, 1n); },
    };
}

// ─── Main ─────────────────────────────────────────────────────────────────

async function main() {
    const args = parseArgs(process.argv.slice(2));
    mkdirSync(args.outDir, { recursive: true });

    const logPath = join(args.outDir, 'oracle-session.log');
    writeFileSync(logPath, '');
    const logLine = (s) => appendFileSync(logPath, `[${new Date().toISOString()}] ${s}\n`);
    const verbose = (s) => { if (args.verbose) console.error(s); logLine(s); };

    logLine(`[pythia-azoth] start sample=${args.sample} triggers=${args.triggers.length}`);

    // Load Elixir Emulator.
    const emu = new elixir.Emulator({
        arch: 'x86_64',
        maxInstructions: args.maxInstructions,
        verbose: !!args.verbose,
    });
    const data = readFileSync(args.sample);
    const entry = emu.load(data);
    verbose(`[pythia-azoth] loaded entry=0x${entry.toString(16)}`);

    const host = buildHost(emu, `azoth_${Date.now().toString(36)}`);

    const decisionsFile = join(args.outDir, 'oracle-decisions.json');
    const decisions = [];

    const session = new OracleSession({
        sessionId: host.sessionId,
        host,
        transport: {
            nodeBin: process.platform === 'win32' ? 'npx.cmd' : 'npx',
            spawnArgs: ['tsx', 'test/pythia-server.ts'],
            cwd: args.pythia,
            env: process.env,
            hexcoreVersion: '3.9.0-preview.oracle.azoth',
            pauseTimeoutMs: 45_000,
            handshakeTimeoutMs: 15_000,
            logger: verbose,
        },
        stepEmulation: async (pc) => {
            let reason;
            try { reason = emu.run(typeof pc === 'bigint' ? pc : BigInt(pc), 0n); }
            catch (e) {
                return { kind: 'exception', intno: 0, rip: typeof pc === 'bigint' ? pc : BigInt(pc) };
            }
            let currentRip;
            try { currentRip = BigInt(emu.regRead(UC_X86_REG.RIP)); }
            catch { currentRip = typeof reason.address === 'bigint' ? reason.address : BigInt(reason.address ?? 0); }
            if (reason.kind === 'breakpoint') return { kind: 'breakpoint', rip: currentRip };
            if (reason.kind === 'exit' || reason.kind === 'insn_limit' || reason.kind === 'user') return { kind: 'completed' };
            return { kind: 'exception', intno: 0, rip: currentRip };
        },
        onPause: (summary) => {
            decisions.push(summary);
            writeFileSync(
                decisionsFile,
                JSON.stringify(decisions, (_k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2),
            );
            logLine(
                `pause#${decisions.length} ${summary.trigger.kind}:${summary.trigger.value} ` +
                `action=${summary.action} patches=${summary.patchesApplied} ` +
                `cost=$${(summary.costUsd ?? 0).toFixed(4)} elapsed=${summary.elapsedMs}ms`,
            );
            if (summary.reasoning) logLine(`  reasoning: ${summary.reasoning}`);
        },
        logger: verbose,
    });

    await session.open();
    verbose(`[pythia-azoth] handshake ok`);
    for (const t of args.triggers) {
        await session.registerTrigger({ kind: t.kind, value: t.value, reason: t.reason || '' });
        verbose(`[pythia-azoth] trigger: ${t.kind}:${t.value}`);
    }

    let runSummary;
    try { runSummary = await session.runLoop(entry); }
    finally { try { await session.close(); } catch {} }

    const apiCallCount = emu.getApiCallCount();
    const apiCalls = emu.getApiCalls() || [];

    const summaryOut = {
        sample: args.sample,
        entry: '0x' + entry.toString(16),
        reason: runSummary.reason,
        pauseCount: runSummary.stats.pauseCount,
        patchesApplied: runSummary.stats.patchesApplied,
        totalCostUsd: runSummary.totalCostUsd,
        apiCallCount,
        apiCallsUnique: [...new Set(apiCalls.map(c => c.name))].sort(),
        apiCallsLast16: apiCalls.slice(-16).map(c => ({
            address: '0x' + BigInt(c.address ?? 0).toString(16),
            name: c.name,
            module: c.module,
            returnValue: '0x' + BigInt(c.returnValue ?? 0).toString(16),
        })),
        generatedAt: new Date().toISOString(),
    };
    writeFileSync(join(args.outDir, 'oracle-summary.json'), JSON.stringify(summaryOut, null, 2));

    // Beacon detection — if LoadLibraryA or ShellExecuteW appear, the Oracle
    // unlocked the payload path.
    const hasBeaconPath = apiCalls.some(c => c.name === 'LoadLibraryA' || c.name === 'ShellExecuteW');

    console.log(JSON.stringify({ ...summaryOut, beaconUnlocked: hasBeaconPath }, null, 2));

    try { emu.dispose(); } catch {}

    process.exit(runSummary.reason === 'emulation_complete' || runSummary.reason === 'aborted' ? 0 : 1);
}

main().catch((e) => {
    console.error(`[pythia-azoth] FATAL: ${e.stack || e.message || e}`);
    process.exit(99);
});
