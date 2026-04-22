#!/usr/bin/env node
/**
 * Project Pythia — Oracle Hook standalone runner.
 *
 * Designed to be invoked by Claude Code (via the hexcore-pythia-oracle skill)
 * or by CI / manual shell. Runs a full Oracle-enabled emulation of a sample
 * binary WITHOUT requiring VS Code to be open.
 *
 * Flow:
 *   1. Load + bootstrap the hexcore-debugger DebugEngine (PE/ELF parsing,
 *      memory mapping, API hook installation).
 *   2. Attach an OracleSession (from hexcore-disassembler) to the emulator:
 *         - Spawn Pythia as a child process, handshake over NDJSON stdio.
 *         - Inject INT3 (0xCC) bytes at each configured trigger PC.
 *   3. Drive emulation via session.runLoop:
 *         - When uc_emu_start throws UC_ERR_EXCEPTION (INT3), match trigger,
 *           await Pythia's DecisionResponse, restore byte, rewind RIP,
 *           apply patches, restart from new PC.
 *         - When emulation completes or aborts, record summary.
 *   4. Write outputs to outDir:
 *         - oracle-session.log      (per-pause trace)
 *         - oracle-decisions.json   (structured decisions + budget totals)
 *         - oracle-summary.json     (final reason + stats)
 *         - emulation.json          (standard emulateFullHeadless result)
 *   5. Dispose engine, exit with 0 on success / 2 on user error / 99 on fatal.
 *
 * Usage:
 *   node scripts/pythia-oracle-run.mjs --job <file.json>
 *   node scripts/pythia-oracle-run.mjs --sample <exe> --pythia <dir> [--triggers <json>] [--outDir <dir>]
 *
 * Job file schema (subset of .hexcore_job.json):
 *   {
 *     "sample": "C:\\path\\to\\binary.exe",
 *     "outDir": "C:\\reports\\oracle-run",
 *     "pythiaRepoPath": "C:\\Users\\Mazum\\Desktop\\HexCore-Oracle-Agent",
 *     "arch": "x64",                 // optional
 *     "maxInstructions": 5000000,    // optional
 *     "permissiveMemoryMapping": true,
 *     "triggers": [
 *       { "kind": "instruction", "value": "0x140001a3f", "reason": "QPC check" },
 *       { "kind": "exception",   "value": "*",           "reason": "fault fallback" }
 *     ]
 *   }
 *
 * The hexcore-debugger + hexcore-disassembler extensions MUST be compiled
 * (npm run compile in each) before running this script. It loads the .js
 * output directly via require().
 */

import { createRequire } from 'module';
import { dirname, join, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { readFileSync, writeFileSync, appendFileSync, mkdirSync, existsSync } from 'fs';

const require = createRequire(import.meta.url);
const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ─── Load compiled extensions ─────────────────────────────────────────────

function load(relPath) {
    const full = join(repoRoot, relPath);
    if (!existsSync(full)) {
        console.error(`[pythia-run] missing compiled output: ${full}`);
        console.error(`[pythia-run] run: cd extensions/hexcore-debugger && npm run compile`);
        console.error(`[pythia-run]  and: cd extensions/hexcore-disassembler && npm run compile`);
        process.exit(2);
    }
    return require(full);
}

const { DebugEngine } = load('extensions/hexcore-debugger/out/debugEngine.js');
const { OracleSession } = load('extensions/hexcore-disassembler/out/oracle/oracleSession.js');

// ─── Argument parsing ─────────────────────────────────────────────────────

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (a === '--job')              args.job = argv[++i];
        else if (a === '--sample')      args.sample = argv[++i];
        else if (a === '--outDir')      args.outDir = argv[++i];
        else if (a === '--pythia')      args.pythia = argv[++i];
        else if (a === '--arch')        args.arch = argv[++i];
        else if (a === '--triggers')    args.triggers = JSON.parse(argv[++i]);
        else if (a === '--maxInstructions') args.maxInstructions = Number(argv[++i]);
        else if (a === '--permissiveMemoryMapping') args.permissiveMemoryMapping = true;
        else if (a === '--verbose' || a === '-v') args.verbose = true;
        else if (a === '--help' || a === '-h') {
            printHelp();
            process.exit(0);
        } else if (a.startsWith('--')) {
            console.error(`[pythia-run] unknown flag: ${a}`);
            process.exit(2);
        }
    }

    if (args.job) {
        const raw = readFileSync(args.job, 'utf8');
        const jobCfg = JSON.parse(raw);
        // Merge: CLI flags override job file fields.
        for (const k of ['sample', 'outDir', 'pythiaRepoPath', 'arch', 'maxInstructions', 'permissiveMemoryMapping', 'triggers']) {
            if (args[k === 'pythiaRepoPath' ? 'pythia' : k] === undefined) {
                args[k === 'pythiaRepoPath' ? 'pythia' : k] = jobCfg[k];
            }
        }
    }

    if (!args.sample)  { console.error('[pythia-run] --sample or job.sample required'); process.exit(2); }
    if (!args.pythia)  { console.error('[pythia-run] --pythia or job.pythiaRepoPath required'); process.exit(2); }
    if (!args.outDir)  args.outDir = join(repoRoot, 'reports', `oracle-${Date.now()}`);
    if (!args.arch)    args.arch = 'x64';
    if (!args.maxInstructions) args.maxInstructions = 5_000_000;
    if (!args.triggers) args.triggers = [{ kind: 'exception', value: '*', reason: 'fault fallback' }];

    return args;
}

function printHelp() {
    console.log(`
Project Pythia — Oracle Hook standalone runner.

Usage:
  node scripts/pythia-oracle-run.mjs --job <file.json>
  node scripts/pythia-oracle-run.mjs --sample <exe> --pythia <pythia-repo>
                                     [--triggers <json>] [--outDir <dir>]
                                     [--arch x64|x86|arm64] [--maxInstructions N]
                                     [--permissiveMemoryMapping] [-v]

Outputs (in outDir):
  oracle-session.log      per-pause trace, human-readable
  oracle-decisions.json   structured decisions + budget totals
  oracle-summary.json     final summary: reason, pauseCount, totalCostUsd
  emulation.json          standard emulation result (registers, stdout, apiCalls, ...)

Env:
  ANTHROPIC_API_KEY is read by Pythia from its own .env in the pythia repo.
`);
}

// ─── Host adapter — plugs UnicornWrapper into OracleHookHost interface ────

function buildHost(args, engine) {
    const emulator = engine.getEmulator();
    if (!emulator) throw new Error('engine.getEmulator() returned undefined — startEmulation did not initialize');

    const uc = emulator.getRawEngine();
    if (!uc) throw new Error('emulator.getRawEngine() returned undefined — Unicorn not initialized');

    const mod = emulator.getUnicornModule();
    if (!mod) throw new Error('emulator.getUnicornModule() returned undefined');

    const R = mod.X86_REG;
    if (!R) throw new Error('UnicornModule.X86_REG missing — non-x86 architectures not supported in v0.1');

    const asBigInt = (v) => (typeof v === 'bigint' ? v : BigInt(v ?? 0));

    // v0.2 (Phase 4): host interface is async. Sync ops on the raw Unicorn
    // handle are wrapped in Promise.resolve so the bridge/registry await'd
    // calls work unchanged. When routing through the PE32 worker (which has
    // native async methods), the wrapper just forwards the promise.
    return {
        sessionId: `cli_${Date.now().toString(36)}`,
        regIds: {
            rax: R.RAX, rbx: R.RBX, rcx: R.RCX, rdx: R.RDX,
            rsi: R.RSI, rdi: R.RDI, rbp: R.RBP, rsp: R.RSP,
            r8:  R.R8,  r9:  R.R9,  r10: R.R10, r11: R.R11,
            r12: R.R12, r13: R.R13, r14: R.R14, r15: R.R15,
            rip: R.RIP, rflags: R.RFLAGS,
            gsBase: R.GS_BASE ?? R.GS ?? undefined,
            fsBase: R.FS_BASE ?? R.FS ?? undefined,
        },
        regRead: async (id) => asBigInt(uc.regRead(id)),
        regWrite: async (id, value) => { uc.regWrite(id, value); },
        memRead: async (addr, size) => uc.memRead(addr, size),
        memWrite: async (addr, data) => { uc.memWrite(addr, data); },
    };
}

// ─── Main ─────────────────────────────────────────────────────────────────

async function main() {
    const args = parseArgs(process.argv.slice(2));
    mkdirSync(args.outDir, { recursive: true });

    const logPath  = join(args.outDir, 'oracle-session.log');
    const logLine  = (s) => appendFileSync(logPath, `[${new Date().toISOString()}] ${s}\n`);
    const verbose  = (s) => { if (args.verbose) console.error(s); logLine(s); };

    writeFileSync(logPath, ''); // truncate
    logLine(`[pythia-run] start — sample=${args.sample} triggers=${JSON.stringify(args.triggers)}`);

    // 1. Bootstrap the emulator.
    const engine = new DebugEngine();
    try {
        await engine.startEmulation(args.sample, args.arch, {
            permissiveMemoryMapping: args.permissiveMemoryMapping === true,
            // Oracle Hook needs synchronous memRead/memWrite to inject INT3
            // bytes. The default PE32 worker process has its own Unicorn
            // state that the host can't sync to atomically.
            skipPe32Worker: true,
        });
    } catch (e) {
        console.error(`[pythia-run] startEmulation failed: ${e.message}`);
        logLine(`[ERROR] startEmulation: ${e.message}`);
        process.exit(99);
    }
    verbose(`[pythia-run] engine started — arch=${engine.getArchitecture()} fileType=${engine.getFileType()}`);

    const entryPc = engine.getEntryPoint();
    if (!entryPc) {
        console.error('[pythia-run] engine.getEntryPoint() returned undefined');
        process.exit(99);
    }
    verbose(`[pythia-run] entry PC: 0x${entryPc.toString(16)}`);

    // 2. Build Oracle session.
    const host = buildHost(args, engine);
    const emulator = engine.getEmulator();
    const uc = emulator.getRawEngine();

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
            hexcoreVersion: '3.9.0-preview.oracle',
            pauseTimeoutMs: 45_000,
            handshakeTimeoutMs: 15_000,
            logger: verbose,
        },
        stepEmulation: async (pc) => {
            try {
                // runSync returns when emulation ends naturally OR errors.
                // maxInstructions is the hard cap across the whole run — we
                // divide per-step to give Oracle a chance to catch runaway loops.
                await emulator.runSync(pc, args.maxInstructions, 0);
                return { kind: 'completed' };
            } catch (e) {
                // Unicorn threw — figure out why. If it's an INT3 we injected,
                // RIP will be 1 byte past the 0xCC. Check the byte AT rip-1.
                let rip = 0n;
                try { rip = await host.regRead(host.regIds.rip); } catch { /* ignore */ }
                let priorByte = null;
                try { priorByte = uc.memRead(rip - 1n, 1)[0]; } catch { /* unmapped — likely true exception */ }

                if (priorByte === 0xcc) {
                    return { kind: 'int3', rip };
                }
                // Not an INT3 we control — treat as generic exception.
                return { kind: 'exception', intno: 0, rip };
            }
        },
        onPause: (summary) => {
            decisions.push(summary);
            // JSON.stringify chokes on bigint (RegisteredTrigger leaks .pc: bigint).
            // Replacer converts bigint -> "0x..." hex.
            writeFileSync(
                decisionsFile,
                JSON.stringify(decisions, (_k, v) => (typeof v === 'bigint' ? '0x' + v.toString(16) : v), 2),
            );
            logLine(
                `pause#${decisions.length} trigger=${summary.trigger.kind}:${summary.trigger.value} ` +
                `→ action=${summary.action} model=${summary.trigger.kind === 'exception' ? '?' : '?'} ` +
                `cost=$${(summary.costUsd ?? 0).toFixed(4)} elapsed=${summary.elapsedMs}ms`,
            );
            if (summary.reasoning) logLine(`  reasoning: ${summary.reasoning}`);
        },
        logger: verbose,
    });

    // 3. Open transport + handshake.
    try {
        const peer = await session.open();
        verbose(`[pythia-run] handshake ok — peer=${peer.pythiaVersion} caps=[${peer.capabilities.join(',')}]`);
    } catch (e) {
        console.error(`[pythia-run] Pythia handshake failed: ${e.message}`);
        logLine(`[ERROR] handshake: ${e.message}`);
        try { await session.close('error'); } catch { /* best effort */ }
        process.exit(99);
    }

    // 4. Register triggers.
    for (const t of args.triggers) {
        try {
            await session.registerTrigger(t);
            logLine(`trigger registered: ${t.kind}:${t.value} (${t.reason || 'no reason'})`);
        } catch (e) {
            logLine(`[WARN] failed to register trigger ${t.kind}:${t.value}: ${e.message}`);
        }
    }

    // 5. Drive the emulation loop.
    let runSummary;
    try {
        runSummary = await session.runLoop(entryPc);
    } catch (e) {
        console.error(`[pythia-run] run loop fatal: ${e.message}`);
        logLine(`[ERROR] runLoop: ${e.message}`);
        runSummary = { reason: 'error', stats: { instructionsExecuted: 0, pauseCount: decisions.length, apisResolved: 0, patchesApplied: 0 }, totalCostUsd: 0 };
    }

    logLine(
        `[pythia-run] done — reason=${runSummary.reason} pauses=${runSummary.stats.pauseCount} ` +
        `patches=${runSummary.stats.patchesApplied} cost=$${runSummary.totalCostUsd.toFixed(4)}`,
    );

    // 6. Collect standard emulation output.
    let emulationSnapshot = null;
    try {
        const registers = await engine.getFullRegistersAsync();
        const apiCalls = engine.getApiCallLog();
        const stdout = engine.getStdoutBuffer();
        emulationSnapshot = {
            file: args.sample,
            architecture: engine.getArchitecture(),
            fileType: engine.getFileType(),
            registers,
            apiCalls: apiCalls.map(c => ({
                dll: c.dll,
                name: c.name,
                returnValue: '0x' + (c.returnValue ?? 0n).toString(16),
            })),
            stdout,
            generatedAt: new Date().toISOString(),
        };
        writeFileSync(join(args.outDir, 'emulation.json'), JSON.stringify(emulationSnapshot, null, 2));
    } catch (e) {
        logLine(`[WARN] emulation snapshot failed: ${e.message}`);
    }

    // 7. Write final summary.
    const summaryOut = {
        reason: runSummary.reason,
        pauseCount: runSummary.stats.pauseCount,
        patchesApplied: runSummary.stats.patchesApplied,
        apisResolved: runSummary.stats.apisResolved,
        totalCostUsd: runSummary.totalCostUsd,
        decisions: decisions.length,
        apiCalls: emulationSnapshot?.apiCalls?.length ?? 0,
        stdoutBytes: emulationSnapshot?.stdout?.length ?? 0,
        outDir: args.outDir,
        generatedAt: new Date().toISOString(),
    };
    writeFileSync(join(args.outDir, 'oracle-summary.json'), JSON.stringify(summaryOut, null, 2));

    // 8. Teardown.
    try { await session.close(runSummary.reason); } catch { /* ignore */ }
    try { engine.disposeEmulation?.(); } catch { /* ignore */ }

    console.log(JSON.stringify(summaryOut, null, 2));

    const exitCode = runSummary.reason === 'emulation_complete' || runSummary.reason === 'aborted' ? 0 : 1;
    process.exit(exitCode);
}

main().catch((e) => {
    console.error(`[pythia-run] FATAL: ${e.stack || e.message || e}`);
    process.exit(99);
});
