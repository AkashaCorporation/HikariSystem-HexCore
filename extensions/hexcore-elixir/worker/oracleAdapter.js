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

// Unicorn x86_64 register IDs. Elixir's regRead/regWrite take numeric IDs,
// not register name strings — the index.d.ts claim of name-based API is a
// documentation lie (regRead is `fn reg_read(reg_id: i32)` in the NAPI
// binding at crates/hexcore-elixir/src/lib.rs:356). Hard-coded here because
// Elixir doesn't export the constants to JS.
// Source: unicorn/x86.h (Unicorn 2.0.1); cross-checked against
// elixir-core/tests/parity_gate_g1.rs which asserts RAX=35, RIP=41, RSP=44.
const UC_X86_REG = Object.freeze({
    RAX: 35, RBP: 36, RBX: 37, RCX: 38, RDI: 39, RDX: 40,
    RIP: 41, RSI: 42, RSP: 44,  // Note: 43 is skipped (IP16?) per parity test
    R8:  52, R9:  53, R10: 54, R11: 55,
    R12: 56, R13: 57, R14: 58, R15: 59,
    RFLAGS: 25,
    // Segment bases (for gs_base/fs_base anti-debug context)
    FS_BASE: 60, GS_BASE: 61,
});

function buildRegIds() {
    return {
        rax: UC_X86_REG.RAX, rbx: UC_X86_REG.RBX, rcx: UC_X86_REG.RCX, rdx: UC_X86_REG.RDX,
        rsi: UC_X86_REG.RSI, rdi: UC_X86_REG.RDI, rbp: UC_X86_REG.RBP, rsp: UC_X86_REG.RSP,
        r8:  UC_X86_REG.R8,  r9:  UC_X86_REG.R9,  r10: UC_X86_REG.R10, r11: UC_X86_REG.R11,
        r12: UC_X86_REG.R12, r13: UC_X86_REG.R13, r14: UC_X86_REG.R14, r15: UC_X86_REG.R15,
        rip: UC_X86_REG.RIP, rflags: UC_X86_REG.RFLAGS,
        gsBase: UC_X86_REG.GS_BASE, fsBase: UC_X86_REG.FS_BASE,
    };
}

/**
 * Build an OracleHookHost against a live Elixir Emulator instance.
 */
function buildHost(emu, sessionId) {
    return {
        sessionId,
        regIds: buildRegIds(),
        // `id` is the Unicorn numeric register ID (from UC_X86_REG).
        regRead: async (id) => {
            try { return BigInt(emu.regRead(Number(id))); }
            catch (e) {
                // Best-effort only for optional segment MSRs (GS_BASE may not
                // be readable on all Unicorn builds). For GPRs, surface the error.
                if (id === UC_X86_REG.GS_BASE || id === UC_X86_REG.FS_BASE) return 0n;
                throw new Error(`regRead id=${id}: ${e.message}`);
            }
        },
        regWrite: async (id, value) => {
            try { emu.regWrite(Number(id), typeof value === 'bigint' ? value : BigInt(value)); }
            catch (e) { throw new Error(`regWrite id=${id}: ${e.message}`); }
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

            // Read RIP via Unicorn numeric ID (41). Elixir's regRead rejects strings.
            let currentRip;
            try { currentRip = BigInt(emu.regRead(UC_X86_REG.RIP)); }
            catch { currentRip = typeof reason.address === 'bigint' ? reason.address : BigInt(reason.address); }

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
