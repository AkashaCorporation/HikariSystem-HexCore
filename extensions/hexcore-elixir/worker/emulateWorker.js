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

process.on('message', (msg) => {
    let emu = null;
    try {
        if (!msg || typeof msg !== 'object') {
            fail(new Error('Worker received invalid message'));
            return;
        }

        const { op, binaryPath, maxInstructions, verbose } = msg;

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

        emu = new elixir.Emulator({
            arch: 'x86_64',
            maxInstructions: maxInstructions || 1000000,
            verbose: !!verbose
        });

        const entry = emu.load(data);
        process.stderr.write(`[elixir-worker] loaded ${path.basename(binaryPath)} entry=${hex(entry)}\n`);

        if (op === 'emulate') {
            const reason = emu.run(entry, 0n);
            const apiCallCount = emu.getApiCallCount();
            const apiCalls = emu.getApiCalls() || [];
            process.stderr.write(`[elixir-worker] emu.run → ${reason.kind} (${reason.instructionsExecuted} insns, ${apiCallCount} api calls)\n`);
            process.send({
                ok: true,
                kind: 'emulate',
                entry: hex(entry),
                stopReason: serializeStopReason(reason),
                apiCallCount,
                apiCalls: apiCalls.map(serializeApiCall)
            });
        } else if (op === 'stalker') {
            emu.stalkerFollow();
            const reason = emu.run(entry, 0n);
            emu.stalkerUnfollow();
            const blockCount = emu.stalkerBlockCount();
            const drcov = emu.stalkerExportDrcov();
            process.stderr.write(`[elixir-worker] stalker.drcov → ${blockCount} blocks, ${drcov.length} bytes\n`);
            process.send({
                ok: true,
                kind: 'stalker',
                entry: hex(entry),
                stopReason: serializeStopReason(reason),
                blockCount,
                drcovBase64: drcov.toString('base64')
            });
        } else {
            fail(new Error('Unknown op: ' + op));
            return;
        }

        try { emu.dispose(); } catch { /* ignore */ }
        process.exit(0);
    } catch (err) {
        try { if (emu) emu.dispose(); } catch { /* ignore */ }
        fail(err);
    }
});

setTimeout(() => {
    fail(new Error('Worker timed out waiting for IPC message from parent (10s)'));
}, 10000).unref();
