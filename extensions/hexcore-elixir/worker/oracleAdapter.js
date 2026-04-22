/*
 * HexCore Elixir — Project Pythia Oracle adapter
 *
 * Invoked by emulateWorker.js when op === 'oracle'. Wires the existing
 * OracleSession (built by hexcore-disassembler on the Unicorn path) onto
 * an Elixir Emulator instance by implementing the OracleHookHost interface
 * against Elixir's NAPI methods.
 *
 * Architecture:
 *   [Extension Host] -IPC-> [this worker (Node)] -stdio spawn-> [Pythia]
 *
 * The worker uses Elixir's new breakpoint_add/del API (v3.9.0-preview.oracle)
 * to install native UC_HOOK_CODE stop points. emu.run() returns cleanly with
 * stopReason.kind === 'breakpoint' when PC reaches a registered address. The
 * session loop picks up the pause, asks Pythia for a decision, applies it,
 * then steps past the BP (del -> run(count=1) -> add) and continues.
 *
 * All state changes (regRead/regWrite/memRead/memWrite) are sync in-process
 * against the live Elixir engine — no IPC crosses back to the parent during
 * the Oracle loop. The parent only sees the final summary.
 */

'use strict';

const path = require('path');
const fs = require('fs');

function hex(v) {
    if (typeof v === 'bigint') return '0x' + v.toString(16);
    if (typeof v === 'number') return '0x' + v.toString(16);
    return String(v);
}

// Map Pythia register names to Elixir register-name strings (the NAPI binding
// uses name-based regRead/regWrite, not numeric IDs).
const REG_NAMES = [
    'rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
    'r8','r9','r10','r11','r12','r13','r14','r15',
    'rip','rflags',
];

// Shim the OracleHookHost's "regIds" interface — Elixir uses names, not IDs.
// We stash the name in the "id" slot and use it back in the host methods.
function buildRegIds() {
    const ids = {};
    for (const n of REG_NAMES) ids[n] = n;
    return ids;
}

/**
 * Build an OracleHookHost against a live Elixir Emulator instance.
 */
function buildHost(emu, sessionId) {
    return {
        sessionId,
        regIds: buildRegIds(),
        regRead: async (name) => {
            // Elixir returns BigInt
            try { return BigInt(emu.regRead(String(name))); }
            catch { return 0n; }
        },
        regWrite: async (name, value) => {
            try { emu.regWrite(String(name), typeof value === 'bigint' ? value : BigInt(value)); }
            catch (e) { throw new Error(`regWrite ${name}: ${e.message}`); }
        },
        memRead: async (addr, size) => {
            try { return emu.memRead(typeof addr === 'bigint' ? addr : BigInt(addr), Number(size)); }
            catch (e) { throw new Error(`memRead 0x${BigInt(addr).toString(16)}+${size}: ${e.message}`); }
        },
        memWrite: async (addr, data) => {
            try { emu.memWrite(typeof addr === 'bigint' ? addr : BigInt(addr), Buffer.from(data)); }
            catch (e) { throw new Error(`memWrite 0x${BigInt(addr).toString(16)}: ${e.message}`); }
        },
        addBreakpoint: async (pc) => {
            emu.breakpointAdd(typeof pc === 'bigint' ? pc : BigInt(pc));
        },
        removeBreakpoint: async (pc) => {
            emu.breakpointDel(typeof pc === 'bigint' ? pc : BigInt(pc));
        },
        stepOne: async (pc) => {
            // v3.9.0-preview.oracle: use runN (per-call cap) to step exactly
            // one instruction. The enclosing applyDecision has already
            // removed the BP at `pc` so we execute the BP'd instruction
            // exactly once, then return to caller for re-add.
            emu.runN(typeof pc === 'bigint' ? pc : BigInt(pc), 0n, 1n);
        },
    };
}

/**
 * Entry point called from emulateWorker.js. Expects:
 *   opts = {
 *     emu,                     // already loaded Elixir Emulator
 *     entry,                   // bigint entry PC
 *     maxInstructions,
 *     oracle: {
 *       triggers: [{kind,value,reason}, ...],
 *       pythiaRepoPath,
 *       pythiaNodeBin?,
 *       pythiaSpawnArgs?,
 *       pauseTimeoutMs?,
 *     },
 *     verbose,
 *     log: (msg) => void,
 *   }
 * Returns { stopReason, apiCallCount, apiCalls, oracle: {decisions, stats} }
 */
async function runOracle(opts) {
    const { emu, entry, maxInstructions, oracle, log } = opts;

    // Lazily require the OracleSession (from the sibling hexcore-disassembler
    // extension's compiled output). This keeps the Elixir worker zero-deps
    // when no Oracle is requested.
    const disasmRoot = path.resolve(__dirname, '..', '..', 'hexcore-disassembler', 'out', 'oracle');
    if (!fs.existsSync(disasmRoot)) {
        throw new Error(
            `oracle: hexcore-disassembler oracle bundle not found at ${disasmRoot}. ` +
            `Compile hexcore-disassembler first (npm run compile).`
        );
    }
    const { OracleSession } = require(path.join(disasmRoot, 'oracleSession.js'));

    const decisions = [];
    const host = buildHost(emu, `elxr_${Date.now().toString(36)}`);

    const triggerPcs = new Set();
    for (const t of oracle.triggers || []) {
        if (t.kind === 'instruction' || t.kind === 'api') {
            try { triggerPcs.add(BigInt(t.value).toString(16)); } catch { /* ignored */ }
        }
    }

    const session = new OracleSession({
        sessionId: host.sessionId,
        host,
        transport: {
            nodeBin: oracle.pythiaNodeBin || (process.platform === 'win32' ? 'npx.cmd' : 'npx'),
            spawnArgs: oracle.pythiaSpawnArgs || ['tsx', 'test/pythia-server.ts'],
            cwd: oracle.pythiaRepoPath,
            env: process.env,
            hexcoreVersion: '3.9.0-preview.oracle.azoth',
            pauseTimeoutMs: oracle.pauseTimeoutMs || 45_000,
            handshakeTimeoutMs: 15_000,
            logger: log,
        },
        stepEmulation: async (pc) => {
            // Elixir run: returns a JsStopReason with kind + address + insns.
            let reason;
            try {
                reason = emu.run(typeof pc === 'bigint' ? pc : BigInt(pc), 0n);
            } catch (e) {
                return { kind: 'exception', intno: 0, rip: typeof pc === 'bigint' ? pc : BigInt(pc) };
            }

            const rip = (async () => {
                try { return BigInt(emu.regRead('rip')); }
                catch { return typeof reason.address === 'bigint' ? reason.address : BigInt(reason.address); }
            });
            const currentRip = await rip();

            if (reason.kind === 'breakpoint') {
                return { kind: 'breakpoint', rip: currentRip };
            }
            if (reason.kind === 'exit' || reason.kind === 'insn_limit' || reason.kind === 'user') {
                return { kind: 'completed' };
            }
            // 'error' or unrecognized
            return { kind: 'exception', intno: 0, rip: currentRip };
        },
        onPause: (summary) => {
            decisions.push(summary);
            log(
                `[oracle-elixir] pause#${decisions.length} ${summary.trigger.kind}:${summary.trigger.value} ` +
                `→ action=${summary.action} cost=$${(summary.costUsd ?? 0).toFixed(4)} elapsed=${summary.elapsedMs}ms`,
            );
            if (summary.reasoning) log(`  reasoning: ${summary.reasoning}`);
        },
        logger: log,
    });

    await session.open();
    log(`[oracle-elixir] handshake ok`);

    for (const t of oracle.triggers || []) {
        try {
            await session.registerTrigger({
                kind: t.kind,
                value: t.value,
                reason: t.reason || '',
            });
            log(`[oracle-elixir] trigger registered: ${t.kind}:${t.value}`);
        } catch (e) {
            log(`[oracle-elixir] WARN trigger ${t.kind}:${t.value}: ${e.message}`);
        }
    }

    let runSummary;
    try {
        runSummary = await session.runLoop(entry);
    } finally {
        try { await session.close(); } catch { /* best-effort */ }
    }

    return {
        runSummary,
        decisions,
    };
}

module.exports = { runOracle };
