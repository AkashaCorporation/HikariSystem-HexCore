/**
 * Oracle Hook Bridge — pause-handler that converts a trapped INT3 into
 * a DecisionRequest round-trip and applies the verdict.
 *
 * Design note (history): an earlier draft tried to hook INT3 via Unicorn's
 * `HOOK.INTR` + `BlockingCall` and await the transport from inside the
 * synchronous callback. That doesn't work — awaiting a Promise from a
 * BlockingCall synchronous context deadlocks the event loop (the microtask
 * queue can't drain while the native thread is parked on our return). The
 * clean alternative (and what we do now) is to let `uc_emu_start` return
 * on the exception, handle it in async JS, then restart emulation.
 *
 * This file is transport-facing only. The session's emulation loop drives
 * the cycle:
 *   await emu.emuStartAsync(pc, 0);            // runs until INT3 or done
 *   // on throw, compute logicalPc, match trigger, call bridge.handlePause
 *   const next = await bridge.handlePause(logicalPc, trigger);
 *   // next.continueFromPc tells the loop where to restart, or null to stop
 *
 * Everything runs on the main thread. The transport's child-process stdio
 * is processed by libuv concurrently with our `await`, which is what makes
 * the inner tool round-trip work.
 */

import {
    type DecisionRequest,
    type DecisionResponse,
    type MemoryWindow,
    type Patch,
    type RegisterState,
    type Trigger,
} from './oracle-protocol';
import { OracleTransport } from './oracleTransport';
import {
    type OracleTriggerRegistry,
    type RegisteredTrigger,
} from './oracleTriggerRegistry';

// ─── Host abstraction — lets us unit-test without a real emulator ────────

export interface RegisterIds {
    rax: number; rbx: number; rcx: number; rdx: number;
    rsi: number; rdi: number; rbp: number; rsp: number;
    r8:  number; r9:  number; r10: number; r11: number;
    r12: number; r13: number; r14: number; r15: number;
    rip: number; rflags: number;
    /** Optional segment bases. Unicorn exposes MSR-based reads for these. */
    gsBase?: number;
    fsBase?: number;
}

export interface OracleHookHost {
    /** Whatever the caller passed in as the "logical" session id. */
    sessionId: string;
    /** Numeric register IDs exposed by `hexcore-unicorn`'s X86_REG constants. */
    regIds: RegisterIds;
    // All register/memory ops are async so implementations routing through
    // the PE32 worker process (hexcore-debugger) can be plugged in directly.
    // In-process implementations wrap their return in Promise.resolve().
    regRead(regId: number): Promise<bigint>;
    regWrite(regId: number, value: bigint): Promise<void>;
    memRead(address: bigint, size: number): Promise<Buffer>;
    memWrite(address: bigint, data: Buffer): Promise<void>;
    /**
     * Install a native Unicorn breakpoint. Emulation will stop BEFORE the
     * instruction at `pc` executes (state.currentAddress will equal pc).
     * Does not modify code bytes, so the TB cache stays clean.
     */
    addBreakpoint(pc: bigint): Promise<void>;
    /** Remove a previously installed breakpoint. */
    removeBreakpoint(pc: bigint): Promise<void>;
    /**
     * Run exactly ONE instruction from `pc`. Used after removing a breakpoint
     * to step past the BP'd instruction before re-installing the BP.
     * Throws on emulation error.
     */
    stepOne(pc: bigint): Promise<void>;
}

// ─── Bridge ───────────────────────────────────────────────────────────────

export interface OracleHookBridgeOptions {
    host: OracleHookHost;
    registry: OracleTriggerRegistry;
    transport: OracleTransport;
    memoryWindowBytes?: number;
    onPause?: (summary: OraclePauseSummary) => void;
    logger?: (msg: string) => void;
}

export interface OraclePauseSummary {
    eventId: string;
    trigger: Trigger;
    action: DecisionResponse['action'];
    patchesApplied: number;
    reasoning?: string;
    elapsedMs: number;
    costUsd?: number;
}

export interface PauseOutcome {
    /** Action the session loop should take. */
    kind: 'continue' | 'abort';
    /** Next PC to resume at, or null if `kind === 'abort'`. */
    continueFromPc: bigint | null;
}

const DEFAULT_MEMORY_WINDOW_BYTES = 128;

export class OracleHookBridge {
    private readonly host: OracleHookHost;
    private readonly registry: OracleTriggerRegistry;
    private readonly transport: OracleTransport;
    private readonly memWinBytes: number;
    private readonly onPause?: (s: OraclePauseSummary) => void;
    private readonly log: (m: string) => void;

    private instructionsExecuted = 0;
    private pauseCount = 0;
    private patchesApplied = 0;
    private readonly apisCalled: string[] = [];
    private readonly sessionStartMs = Date.now();

    constructor(opts: OracleHookBridgeOptions) {
        this.host = opts.host;
        this.registry = opts.registry;
        this.transport = opts.transport;
        this.memWinBytes = opts.memoryWindowBytes ?? DEFAULT_MEMORY_WINDOW_BYTES;
        this.onPause = opts.onPause;
        this.log = opts.logger ?? ((m) => console.error(m));
    }

    /**
     * Called by the emulation loop after `uc_emu_start` returns on an INT3.
     * `logicalPc` is the address of the 0xCC byte (one less than current RIP).
     */
    async handlePause(logicalPc: bigint, trigger: RegisteredTrigger): Promise<PauseOutcome> {
        const start = Date.now();
        this.pauseCount++;

        const request = await this.buildDecisionRequest(trigger, logicalPc);
        this.log(`[oracle-bridge] pause #${this.pauseCount} trigger=${trigger.kind}:${trigger.value} eventId=${request.eventId}`);

        const response = await this.transport.decide(request);

        const outcome = await this.applyDecision(trigger, logicalPc, response);

        const summary: OraclePauseSummary = {
            eventId: request.eventId,
            trigger,
            action: response.action,
            patchesApplied: response.patches?.length ?? 0,
            reasoning: response.reasoning ?? undefined,
            elapsedMs: Date.now() - start,
            costUsd: response.costUsd ?? undefined,
        };
        this.onPause?.(summary);

        return outcome;
    }

    /**
     * Session-side: called when `uc_emu_start` returns but we have NO trigger
     * match (e.g. unexpected INT3 the user didn't register). Logs and lets the
     * caller decide whether to rethrow or swallow.
     */
    reportUnmatchedInterrupt(logicalPc: bigint, intno: number): void {
        this.log(
            `[oracle-bridge] interrupt intno=${intno} at ${hex(logicalPc)} has no matching trigger; session will propagate`,
        );
    }

    getSessionStats(): {
        instructionsExecuted: number;
        pauseCount: number;
        apisResolved: number;
        patchesApplied: number;
    } {
        return {
            instructionsExecuted: this.instructionsExecuted,
            pauseCount: this.pauseCount,
            apisResolved: this.apisCalled.length,
            patchesApplied: this.patchesApplied,
        };
    }

    // ─── DecisionRequest construction ─────────────────────────────────────

    private async buildDecisionRequest(trigger: RegisteredTrigger, logicalPc: bigint): Promise<DecisionRequest> {
        const registers = await this.captureRegisterState(logicalPc);
        const memoryWindow = await this.captureMemoryWindow(logicalPc);
        return {
            kind: 'decision_request',
            eventId: OracleTransport.newEventId(`evt_${trigger.kind}`),
            trigger: { kind: trigger.kind, value: trigger.value, reason: trigger.reason },
            context: {
                registers,
                disassembly: [], // v0.1: empty — Capstone integration is Phase 3.5
                callStack: [],   // v0.1: empty — stack walker is Phase 3.5
                memoryWindow,
            },
            session: {
                sessionId: this.host.sessionId,
                instructionsExecuted: this.instructionsExecuted,
                apisCalled: this.apisCalled.slice(-16),
                elapsedMs: Date.now() - this.sessionStartMs,
                pauseCount: this.pauseCount,
            },
        };
    }

    private async captureRegisterState(logicalPc: bigint): Promise<RegisterState> {
        const r = this.host.regIds;
        const read = async (id: number): Promise<string> => hex(await this.host.regRead(id));
        const state: RegisterState = {
            rax: await read(r.rax), rbx: await read(r.rbx), rcx: await read(r.rcx), rdx: await read(r.rdx),
            rsi: await read(r.rsi), rdi: await read(r.rdi), rbp: await read(r.rbp), rsp: await read(r.rsp),
            r8:  await read(r.r8),  r9:  await read(r.r9),  r10: await read(r.r10), r11: await read(r.r11),
            r12: await read(r.r12), r13: await read(r.r13), r14: await read(r.r14), r15: await read(r.r15),
            rip: hex(logicalPc), // override with the logical "user-visible" PC
            rflags: await read(r.rflags),
        };
        if (r.gsBase !== undefined) {
            try { state.gs_base = await read(r.gsBase); } catch { /* segment MSR might not be readable */ }
        }
        if (r.fsBase !== undefined) {
            try { state.fs_base = await read(r.fsBase); } catch { /* ignore */ }
        }
        return state;
    }

    private async captureMemoryWindow(pc: bigint): Promise<MemoryWindow> {
        const half = BigInt(Math.floor(this.memWinBytes / 2));
        const base = pc - half;
        try {
            const buf = await this.host.memRead(base, this.memWinBytes);
            return { base: hex(base), bytes: buf.toString('hex') };
        } catch (e) {
            this.log(`[oracle-bridge] memory window read failed at ${hex(base)}: ${(e as Error).message}`);
            return { base: hex(pc), bytes: '' };
        }
    }

    // ─── DecisionResponse application ─────────────────────────────────────

    private async applyDecision(
        trigger: RegisteredTrigger,
        logicalPc: bigint,
        resp: DecisionResponse,
    ): Promise<PauseOutcome> {
        // Step 1 — Apply patches FIRST (before stepping past the BP so the
        // patched state is visible to the BP'd instruction when it executes).
        if (resp.patches) {
            for (const p of resp.patches) await this.applyPatch(p);
        }

        // Step 2 — Top-level action.
        switch (resp.action) {
            case 'continue':
            case 'patch': {
                // Step-over-breakpoint dance (mirrors unicornWrapper.ts:1656-1666):
                //   a. Remove the BP so the instruction can execute without re-trap.
                //   b. Step exactly ONE instruction. The BP'd instruction runs.
                //   c. Re-add the BP so future passes through this PC trap again.
                // This works because native breakpoints don't modify memory —
                // the TB cache stays valid across the step.
                if (trigger.kind === 'instruction' || trigger.kind === 'api') {
                    await this.registry.restore(trigger);
                    try {
                        await this.host.stepOne(logicalPc);
                    } catch (e) {
                        // Single-step threw — return the exception-style outcome.
                        // The session loop will propagate. Don't re-add BP on error.
                        this.log(`[oracle-bridge] stepOne past BP at ${hex(logicalPc)} threw: ${(e as Error).message}`);
                        return { kind: 'continue', continueFromPc: await this.host.regRead(this.host.regIds.rip) };
                    }
                    await this.registry.reinject(trigger);
                }
                const resumePc = await this.host.regRead(this.host.regIds.rip);
                return { kind: 'continue', continueFromPc: resumePc };
            }
            case 'skip':
            case 'patch_and_skip': {
                // No step-over — we skip the BP'd instruction entirely. Remove
                // the BP (otherwise we'd re-trap if the sample returns here
                // naturally later), jump to target, re-add only if the skip
                // target isn't downstream of the BP (rare edge case — we always
                // re-add for consistency with the demo policy).
                await this.registry.restore(trigger);
                const target = this.resolveSkipTarget(logicalPc, resp.skip);
                const resumePc = target ?? await this.host.regRead(this.host.regIds.rip);
                await this.host.regWrite(this.host.regIds.rip, resumePc);
                await this.registry.reinject(trigger);
                return { kind: 'continue', continueFromPc: resumePc };
            }
            case 'abort':
                this.log(`[oracle-bridge] Pythia requested abort: ${resp.reasoning ?? '(no reason)'}`);
                await this.registry.restore(trigger);
                return { kind: 'abort', continueFromPc: null };
        }
    }

    private async applyPatch(p: Patch): Promise<void> {
        try {
            if (p.target === 'register') {
                const regId = this.regIdFor(p.location);
                if (regId === null) {
                    this.log(`[oracle-bridge] patch targets unknown register '${p.location}'; ignored`);
                    return;
                }
                await this.host.regWrite(regId, parseValue(p.value));
                this.patchesApplied++;
            } else if (p.target === 'memory') {
                const addr = parseAddress(p.location);
                const size = p.size ?? inferSizeFromValue(p.value);
                const buf = bufferFromValue(p.value, size);
                await this.host.memWrite(addr, buf);
                this.patchesApplied++;
            } else if (p.target === 'flag') {
                await this.applyFlagPatch(p.location, parseValue(p.value));
                this.patchesApplied++;
            }
        } catch (e) {
            this.log(`[oracle-bridge] patch failed (${p.target} ${p.location}): ${(e as Error).message}`);
        }
    }

    private async applyFlagPatch(flag: string, set: bigint): Promise<void> {
        const flagBits: Record<string, bigint> = {
            cf: 1n << 0n, pf: 1n << 2n, af: 1n << 4n, zf: 1n << 6n, sf: 1n << 7n, of: 1n << 11n,
        };
        const mask = flagBits[flag.toLowerCase()];
        if (mask === undefined) {
            this.log(`[oracle-bridge] unknown flag '${flag}'; ignored`);
            return;
        }
        const rflags = await this.host.regRead(this.host.regIds.rflags);
        const newRflags = set ? (rflags | mask) : (rflags & ~mask);
        await this.host.regWrite(this.host.regIds.rflags, newRflags);
    }

    private regIdFor(name: string): number | null {
        const r = this.host.regIds;
        const map: Record<string, number> = {
            rax: r.rax, rbx: r.rbx, rcx: r.rcx, rdx: r.rdx,
            rsi: r.rsi, rdi: r.rdi, rbp: r.rbp, rsp: r.rsp,
            r8:  r.r8,  r9:  r.r9,  r10: r.r10, r11: r.r11,
            r12: r.r12, r13: r.r13, r14: r.r14, r15: r.r15,
            rip: r.rip, rflags: r.rflags,
        };
        const v = map[name.toLowerCase()];
        return v === undefined ? null : v;
    }

    private resolveSkipTarget(currentPc: bigint, skip: DecisionResponse['skip']): bigint | null {
        if (!skip) return null;
        if (skip.untilAddress) return parseAddress(skip.untilAddress);
        if (skip.instructions) {
            this.log(
                `[oracle-bridge] skip.instructions=${skip.instructions} — approximating as ${skip.instructions} bytes (Phase 3.5 will integrate Capstone)`,
            );
            return currentPc + BigInt(skip.instructions);
        }
        return null;
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function hex(v: bigint | number): string {
    const b = typeof v === 'bigint' ? v : BigInt(v);
    const s = b.toString(16);
    return '0x' + (s.length % 2 === 0 ? s : '0' + s);
}

function parseValue(s: string): bigint {
    const t = s.trim();
    if (t.toLowerCase().startsWith('0x')) return BigInt(t);
    if (/^-?\d+$/.test(t)) return BigInt(t);
    throw new Error(`oracle: invalid numeric value '${s}'`);
}

function parseAddress(s: string): bigint {
    const t = s.trim();
    const withPrefix = t.toLowerCase().startsWith('0x') ? t : `0x${t}`;
    return BigInt(withPrefix);
}

function inferSizeFromValue(s: string): number {
    const t = s.trim();
    if (t.toLowerCase().startsWith('0x')) {
        const hexDigits = t.slice(2).length;
        return Math.max(1, Math.ceil(hexDigits / 2));
    }
    return 8;
}

function bufferFromValue(s: string, size: number): Buffer {
    const v = parseValue(s);
    const buf = Buffer.alloc(size);
    let tmp = v < 0n ? ((1n << BigInt(size * 8)) + v) : v;
    for (let i = 0; i < size; i++) {
        buf[i] = Number(tmp & 0xffn); // little-endian
        tmp >>= 8n;
    }
    return buf;
}
