/*
 * HexCore Elixir — Emulation Worker
 *
 * Runs Emulator.load()+.run() inside a forked system Node.exe process.
 * The parent is VS Code's Electron Extension Host, which has ACG (Arbitrary
 * Code Guard) enabled in its PE header — that blocks VirtualAlloc(PAGE_EXECUTE_READWRITE),
 * which Unicorn's TCG JIT needs to allocate RWX pages for generated machine code.
 * When the host runs uc_emu_start directly, the RWX alloc fails with
 * STATUS_ACCESS_VIOLATION (0xC0000005) and the Extension Host dies.
 *
 * System Node.exe binaries do NOT have ACG in their PE header, so forking
 * the worker via child_process.fork({execPath: systemNode}) works.
 * This is the exact pattern hexcore-debugger uses for pe32Worker.
 *
 * IPC protocol:
 *   parent → worker: { op: 'emulate' | 'stalker', binaryPath, maxInstructions, verbose }
 *   worker → parent:
 *     { ok: true, kind: 'emulate', entry, stopReason, apiCallCount, apiCalls }
 *     { ok: true, kind: 'stalker', entry, stopReason, blockCount, drcovBase64 }
 *     { ok: false, error }
 *
 * All BigInts are serialized as '0x...' hex strings because IPC structured-clone
 * doesn't handle BigInt. The parent converts back if needed.
 */

'use strict';

const fs = require('fs');
const path = require('path');

function hex(v) {
    if (typeof v === 'bigint') return '0x' + v.toString(16);
    if (typeof v === 'number') return '0x' + v.toString(16);
    return null;
}

function serializeApiCall(c) {
    return {
        address: c && c.address !== undefined ? hex(c.address) : null,
        name: c ? c.name : null,
        module: c ? c.module : null,
        returnValue: c && c.returnValue !== undefined ? hex(c.returnValue) : null
    };
}

function serializeStopReason(r) {
    return {
        kind: r.kind,
        address: hex(r.address),
        instructionsExecuted: r.instructionsExecuted,
        message: r.message
    };
}

function fail(err) {
    const msg = (err && err.stack) ? err.stack : (err && err.message) ? err.message : String(err);
    try {
        if (process.send) {
            process.send({ ok: false, error: msg });
        } else {
            process.stderr.write('[elixir-worker] ' + msg + '\n');
        }
    } catch { /* ignore */ }
    process.exit(1);
}

process.on('uncaughtException', fail);
process.on('unhandledRejection', fail);

const MACHINE_LABELS = {
    0x014c: 'x86 (PE32, IMAGE_FILE_MACHINE_I386)',
    0x0200: 'ia64 (IMAGE_FILE_MACHINE_IA64)',
    0x8664: 'x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64)',
    0x01c0: 'ARM (IMAGE_FILE_MACHINE_ARM)',
    0xaa64: 'ARM64 (IMAGE_FILE_MACHINE_ARM64)',
    0x01c4: 'ARM Thumb-2 (IMAGE_FILE_MACHINE_ARMNT)'
};

function preflightPe(data, binaryPath) {
    if (data.length < 0x40) {
        throw new Error(`Binary too small to be a PE (${data.length} bytes): ${binaryPath}`);
    }
    if (data[0] !== 0x4d || data[1] !== 0x5a) {
        throw new Error(`Not a PE file (missing MZ magic): ${binaryPath}`);
    }
    const lfanew = data.readUInt32LE(0x3c);
    if (lfanew + 24 > data.length) {
        throw new Error(`Invalid PE header offset 0x${lfanew.toString(16)}: ${binaryPath}`);
    }
    if (data.readUInt32LE(lfanew) !== 0x00004550) {
        throw new Error(`Not a PE file (missing PE\\0\\0 signature): ${binaryPath}`);
    }
    const machine = data.readUInt16LE(lfanew + 4);
    if (machine !== 0x8664) {
        const label = MACHINE_LABELS[machine] || `unknown (0x${machine.toString(16)})`;
        throw new Error(
            `Elixir requires x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64=0x8664); ` +
            `got ${label} — ${path.basename(binaryPath)}. ` +
            `Rebuild the binary as 64-bit or use the legacy debugger (hexcore.emulator="debugger").`
        );
    }
    return machine;
}

// Worker startup diagnostic — fires immediately on fork so we can tell
// the difference between "worker never started" vs "worker started but
// never received IPC message".
process.stderr.write(`[elixir-worker] booted pid=${process.pid} connected=${!!process.send} send-fn=${typeof process.send} at ${new Date().toISOString()}\n`);

// Deadman-switch timer — armed if the parent fork()'s us but never sends
// the initial IPC message (channel-stuck case). We cancel it as soon as a
// message lands so long-running Oracle sessions aren't killed mid-decision.
let deadmanTimer = null;

process.on('message', async (msg) => {
    // Cancel the deadman — the parent did send us a message, now the
    // actual work can take as long as it needs (Oracle decisions routinely
    // run 10-30s while Pythia reasons through anti-analysis context).
    if (deadmanTimer) {
        clearTimeout(deadmanTimer);
        deadmanTimer = null;
    }
    process.stderr.write(`[elixir-worker] received IPC message op=${msg?.op ?? 'unknown'} at ${new Date().toISOString()}\n`);
    let emu = null;
    try {
        if (!msg || typeof msg !== 'object') {
            fail(new Error('Worker received invalid message'));
            return;
        }

        const { op, binaryPath, maxInstructions, verbose, apiCallsOverflowPath, apiCallsOverflowDir, oracle: oracleCfg } = msg;

        const elixir = require(path.join(__dirname, '..', 'index.js'));
        if (!elixir || elixir.isAvailable === false || !elixir.Emulator) {
            fail(new Error('Elixir native binding unavailable: ' + (elixir && elixir.loadError || 'unknown')));
            return;
        }

        if (!binaryPath || typeof binaryPath !== 'string') {
            fail(new Error('binaryPath is required'));
            return;
        }

        const data = fs.readFileSync(binaryPath);

        preflightPe(data, binaryPath);

        emu = new elixir.Emulator({
            arch: 'x86_64',
            maxInstructions: maxInstructions || 1000000,
            verbose: !!verbose
        });

        const entry = emu.load(data);
        process.stderr.write(`[elixir-worker] loaded ${path.basename(binaryPath)} entry=${hex(entry)}\n`);

        let payload;
        if (op === 'emulate') {
            const reason = emu.run(entry, 0n);
            const apiCallCount = emu.getApiCallCount();
            const apiCalls = emu.getApiCalls() || [];
            process.stderr.write(`[elixir-worker] emu.run → ${reason.kind} (${reason.instructionsExecuted} insns, ${apiCallCount} api calls)\n`);
            const serializedCalls = apiCalls.map(serializeApiCall);

            // Always spill apiCalls to a companion file (same pattern as .drcov
            // export) when a path is provided. Keeps the main JSON small and
            // human-readable, scales to MB-sized traces without hitting the
            // IPC channel's 10s drain window. Inline sample (first 10) stays
            // in the main result for quick triage.
            let apiCallsPath = null;
            let apiCallsInline = serializedCalls;
            if (apiCallsOverflowPath) {
                // Containment layer 2 (worker): re-validate that the overflow
                // path the parent asked us to write is inside the declared
                // overflow directory. Defense-in-depth for CWE-22 — the parent
                // already validated, but if an untrusted caller ever forks this
                // worker directly (or if the IPC message is tampered with) we
                // refuse to write outside apiCallsOverflowDir.
                let allowed = false;
                if (apiCallsOverflowDir && typeof apiCallsOverflowDir === 'string') {
                    const resolvedDir = path.resolve(apiCallsOverflowDir);
                    const resolvedTarget = path.resolve(apiCallsOverflowPath);
                    const sep = path.sep;
                    allowed =
                        resolvedTarget === resolvedDir ||
                        resolvedTarget.startsWith(resolvedDir + sep);
                    if (!allowed) {
                        process.stderr.write(
                            `[elixir-worker] refusing apiCalls companion write — ` +
                            `${resolvedTarget} escapes ${resolvedDir}\n`
                        );
                    }
                } else {
                    // Backward-compat: older parents that don't send
                    // apiCallsOverflowDir still work, but log so the missing
                    // containment is observable.
                    allowed = true;
                    process.stderr.write(
                        `[elixir-worker] apiCallsOverflowDir not supplied — ` +
                        `parent-side containment only\n`
                    );
                }
                if (allowed) {
                    try {
                        fs.mkdirSync(path.dirname(apiCallsOverflowPath), { recursive: true });
                        fs.writeFileSync(apiCallsOverflowPath, JSON.stringify(serializedCalls, null, 2));
                        apiCallsPath = apiCallsOverflowPath;
                        apiCallsInline = serializedCalls.slice(0, 10);
                        process.stderr.write(`[elixir-worker] apiCalls → ${apiCallsOverflowPath} (${serializedCalls.length} calls, ${apiCallsInline.length} inlined as preview)\n`);
                    } catch (err) {
                        process.stderr.write(`[elixir-worker] apiCalls companion write failed: ${err.message}\n`);
                    }
                }
            }

            payload = {
                ok: true,
                kind: 'emulate',
                entry: hex(entry),
                stopReason: serializeStopReason(reason),
                apiCallCount,
                apiCalls: apiCallsInline,
                apiCallsPath,
                apiCallsTotal: serializedCalls.length
            };
        } else if (op === 'oracle') {
            // Project Pythia Oracle Hook (v3.9.0-preview.oracle.azoth).
            // Requires the new engine/NAPI breakpoint API — built 2026-04-22.
            if (typeof emu.breakpointAdd !== 'function') {
                fail(new Error('oracle: this hexcore-elixir.node does not expose breakpointAdd. Rebuild required.'));
                return;
            }
            if (!oracleCfg || !oracleCfg.pythiaRepoPath) {
                fail(new Error('oracle: oracleCfg.pythiaRepoPath is required'));
                return;
            }

            const { runOracle } = require('./oracleAdapter');
            const log = (m) => process.stderr.write(`[elixir-worker.oracle] ${m}\n`);

            // runOracle drives the session loop (spawn Pythia, register BPs,
            // stepEmulation→decide→apply→step-over→repeat). Returns a summary.
            const { runSummary, decisions } = await runOracle({
                emu,
                entry,
                maxInstructions: maxInstructions || 2_000_000,
                oracle: oracleCfg,
                verbose: !!verbose,
                log,
            });

            const apiCallCount = emu.getApiCallCount();
            const apiCalls = emu.getApiCalls() || [];
            const serializedCalls = apiCalls.map(serializeApiCall);

            log(
                `oracle done — reason=${runSummary.reason} pauses=${runSummary.stats.pauseCount} ` +
                `patches=${runSummary.stats.patchesApplied} cost=$${runSummary.totalCostUsd.toFixed(4)} ` +
                `apiCalls=${apiCallCount}`,
            );

            // Sanitizer: RegisteredTrigger leaks a bigint .pc field, and
            // Node's IPC structured-clone chokes on bigints inside nested
            // objects. Replace any bigint we encounter with a 0x-hex string.
            // Doing it once here keeps the worker-parent payload contract
            // BigInt-free without touching the Oracle session internals.
            const bigintSafe = (v) => JSON.parse(
                JSON.stringify(v, (_k, val) =>
                    typeof val === 'bigint' ? '0x' + val.toString(16) : val
                )
            );

            payload = {
                ok: true,
                kind: 'oracle',
                entry: hex(entry),
                stopReason: {
                    kind: runSummary.reason,
                    address: hex(0n),
                    instructionsExecuted: runSummary.stats.instructionsExecuted || 0,
                    message: `Oracle session ${runSummary.reason}`,
                },
                oracle: {
                    pauseCount: runSummary.stats.pauseCount,
                    patchesApplied: runSummary.stats.patchesApplied,
                    totalCostUsd: runSummary.totalCostUsd,
                    decisions: decisions.map((d) => bigintSafe({
                        eventId: d.eventId,
                        trigger: d.trigger,
                        action: d.action,
                        patchesApplied: d.patchesApplied,
                        reasoning: d.reasoning,
                        elapsedMs: d.elapsedMs,
                        costUsd: d.costUsd,
                    })),
                },
                apiCallCount,
                apiCalls: serializedCalls.slice(0, 20),
                apiCallsTotal: serializedCalls.length,
            };
        } else if (op === 'stalker') {
            emu.stalkerFollow();
            const reason = emu.run(entry, 0n);
            emu.stalkerUnfollow();
            const blockCount = emu.stalkerBlockCount();
            const drcov = emu.stalkerExportDrcov();
            process.stderr.write(`[elixir-worker] stalker.drcov → ${blockCount} blocks, ${drcov.length} bytes\n`);
            payload = {
                ok: true,
                kind: 'stalker',
                entry: hex(entry),
                stopReason: serializeStopReason(reason),
                blockCount,
                drcovBase64: drcov.toString('base64')
            };
        } else {
            fail(new Error('Unknown op: ' + op));
            return;
        }

        try { emu.dispose(); } catch { /* ignore */ }

        // process.send is async and buffered; for large payloads (stalker
        // base64 drcov can exceed hundreds of KB) the IPC write may not
        // flush before process.exit(0). Use the callback form so we only
        // exit after the message is fully handed to the IPC channel, then
        // disconnect() to drain before exit.
        process.send(payload, undefined, {}, (err) => {
            if (err) {
                process.stderr.write(`[elixir-worker] process.send failed: ${err.message}\n`);
                process.exit(1);
                return;
            }
            if (typeof process.disconnect === 'function') {
                process.once('disconnect', () => process.exit(0));
                try { process.disconnect(); } catch { process.exit(0); }
            } else {
                process.exit(0);
            }
        });
    } catch (err) {
        try { if (emu) emu.dispose(); } catch { /* ignore */ }
        fail(err);
    }
});

// Arm the deadman: 10s to receive the initial IPC message. Cancelled by
// process.on('message') above once the parent actually sends.
deadmanTimer = setTimeout(() => {
    fail(new Error('Worker timed out waiting for IPC message from parent (10s)'));
}, 10000);
deadmanTimer.unref?.();
