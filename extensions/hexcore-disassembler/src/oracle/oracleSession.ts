/**
 * Oracle Session — top-level orchestrator.
 *
 * Ties together:
 *   - OracleTransport       (child process + NDJSON to Pythia)
 *   - OracleTriggerRegistry (INT3 bookkeeping)
 *   - OracleHookBridge      (state capture + decision apply)
 *
 * Exposes:
 *   - `registerTrigger`  — add a trigger; INT3 is injected synchronously
 *   - `onPause`          — subscribe to per-pause telemetry
 *   - `runLoop`          — the async emulation-driver loop (caller plugs in
 *                          a step function that wraps emuStartAsync)
 *   - `close`            — tear everything down
 *
 * Tool call handling: the session owns a small resolver that services
 * Pythia's inspection tools (`read_memory`, `get_imports`, etc.) by delegating
 * to the host. `disassemble`, `query_helix`, and `search_hql` are stubbed for
 * v0.1 and will gain real implementations in Phase 3.5.
 */

import type {
    Handshake,
    SessionEnd,
    ToolCall,
    ToolResult,
    Trigger,
} from './oracle-protocol';
import {
    OracleHookBridge,
    type OracleHookHost,
    type OraclePauseSummary,
    type PauseOutcome,
} from './oracleHookBridge';
import { OracleTransport, type OracleTransportConfig } from './oracleTransport';
import {
    OracleTriggerRegistry,
    type RegisteredTrigger,
} from './oracleTriggerRegistry';

export interface OracleSessionConfig {
    /** Opaque id (e.g. `sess_2026_04_21_0001`); surfaces in DecisionRequests. */
    sessionId: string;
    /** Host abstraction (register/memory ops from the live emulator). */
    host: OracleHookHost;
    /** Transport configuration — `cwd` must point at the Project-Pythia repo. */
    transport: OracleTransportConfig;
    /** Optional imports table (filled by the binary loader; used by `get_imports`). */
    imports?: Record<string, string[]>;
    /** Callback: emulator step function. Runs `emuStartAsync` from `pc` until
     *  it returns (normal completion OR exception). Returns an interruption
     *  descriptor. The session calls this repeatedly until done=true. */
    stepEmulation: (pc: bigint) => Promise<EmulationStepResult>;
    /** Called each pause — for UI / telemetry. */
    onPause?: (s: OraclePauseSummary) => void;
    /** Called on tool calls from Pythia (falls through to the session's default
     *  resolver if this returns null). Typical override point for extensions
     *  that want to implement `disassemble`/`query_helix`. */
    customToolResolver?: (call: ToolCall) => Promise<ToolResult | null>;
    logger?: (msg: string) => void;
    /** HexCore side version for the handshake frame. */
    hexcoreVersion?: string;
}

/**
 * The step function's return contract.
 *   - kind='completed' : emulation reached its natural end (or emuStop)
 *   - kind='int3'      : execution trapped on an injected 0xCC — the session
 *                        will look up the matching trigger, run Pythia, and
 *                        resume at `resumePc` the step function returns.
 *   - kind='exception' : unhandled exception other than INT3 (unmapped mem,
 *                        div/0, etc). `intno` = x86 vector, `rip` = faulting PC.
 *   - kind='error'     : step function failed (e.g. emuStart threw a non-
 *                        exception error). Session propagates the error.
 */
export type EmulationStepResult =
    | { kind: 'completed' }
    | { kind: 'int3'; rip: bigint }
    | { kind: 'exception'; intno: number; rip: bigint }
    | { kind: 'error'; error: Error };

export interface OracleSessionRunSummary {
    reason: SessionEnd['reason'];
    stats: {
        instructionsExecuted: number;
        pauseCount: number;
        apisResolved: number;
        patchesApplied: number;
    };
    totalCostUsd: number;
}

export class OracleSession {
    private readonly cfg: OracleSessionConfig;
    private readonly log: (m: string) => void;
    private readonly transport: OracleTransport;
    private readonly registry: OracleTriggerRegistry;
    private readonly bridge: OracleHookBridge;
    private peerHandshake: Handshake | null = null;
    private totalCostUsd = 0;
    private closed = false;

    constructor(cfg: OracleSessionConfig) {
        this.cfg = cfg;
        this.log = cfg.logger ?? ((m) => console.error(m));

        this.transport = new OracleTransport(cfg.transport);
        this.registry = new OracleTriggerRegistry({
            // Narrow the host's general signature to the trigger registry's
            // (address: bigint | number, size: number) shape. The bridge host
            // accepts bigint | number too via the bigint parameter, so this is
            // a safe widening of the parameter type.
            memRead: (addr, size) => cfg.host.memRead(typeof addr === 'bigint' ? addr : BigInt(addr), size),
            memWrite: (addr, data) => cfg.host.memWrite(typeof addr === 'bigint' ? addr : BigInt(addr), data),
        });
        this.bridge = new OracleHookBridge({
            host: cfg.host,
            registry: this.registry,
            transport: this.transport,
            logger: this.log,
            onPause: (s) => {
                if (s.costUsd) this.totalCostUsd += s.costUsd;
                cfg.onPause?.(s);
            },
        });
    }

    /** Spawn the Pythia child and complete the handshake. */
    async open(): Promise<Handshake> {
        this.peerHandshake = await this.transport.start({
            onToolCall: (call) => this.resolveToolCall(call),
            onChildExit: (code, signal) => {
                this.log(`[oracle-session] Pythia exited code=${code} signal=${signal}`);
            },
            onStderr: (line) => this.log(`[pythia.err] ${line}`),
        });
        this.log(`[oracle-session] open ok — peer=${this.peerHandshake.pythiaVersion}`);
        return this.peerHandshake;
    }

    async registerTrigger(t: Trigger): Promise<RegisteredTrigger> {
        return this.registry.register(t);
    }

    /**
     * Async driver loop. Each iteration:
     *   1. Calls `stepEmulation(currentPc)` — emulates until returned.
     *   2. On INT3: matches trigger, awaits Pythia decision, applies patches.
     *   3. On exception: matches (if registered) exception trigger, ditto.
     *   4. On completed/error: exits the loop.
     */
    async runLoop(entryPc: bigint): Promise<OracleSessionRunSummary> {
        let currentPc = entryPc;
        let reason: SessionEnd['reason'] = 'emulation_complete';

        // Safety cap — prevents runaway loops on pathological triggers.
        const MAX_PAUSE_ITERATIONS = 512;

        for (let iter = 0; iter < MAX_PAUSE_ITERATIONS; iter++) {
            const step = await this.cfg.stepEmulation(currentPc);

            if (step.kind === 'completed') {
                reason = 'emulation_complete';
                break;
            }
            if (step.kind === 'error') {
                this.log(`[oracle-session] step error: ${step.error.message}`);
                reason = 'error';
                break;
            }

            if (step.kind === 'int3') {
                const logicalPc = step.rip - 1n;
                const trig = this.registry.matchByPc(logicalPc);
                if (!trig) {
                    this.log(`[oracle-session] INT3 at ${hex(logicalPc)} unmatched — stopping to avoid corruption`);
                    this.bridge.reportUnmatchedInterrupt(logicalPc, 3);
                    reason = 'error';
                    break;
                }
                const outcome = await this.bridge.handlePause(logicalPc, trig);
                if (outcome.kind === 'abort') {
                    reason = 'aborted';
                    break;
                }
                currentPc = outcome.continueFromPc ?? logicalPc;
                continue;
            }

            if (step.kind === 'exception') {
                const trig = this.registry.matchException();
                if (!trig) {
                    this.log(`[oracle-session] exception intno=${step.intno} at ${hex(step.rip)} — no exception trigger registered; propagating`);
                    reason = 'error';
                    break;
                }
                const outcome = await this.bridge.handlePause(step.rip, trig);
                if (outcome.kind === 'abort') {
                    reason = 'aborted';
                    break;
                }
                currentPc = outcome.continueFromPc ?? step.rip;
                continue;
            }
        }

        return {
            reason,
            stats: this.bridge.getSessionStats(),
            totalCostUsd: this.totalCostUsd,
        };
    }

    /** Clean shutdown — notifies Pythia, kills the child, restores bytes. */
    async close(reason: SessionEnd['reason'] = 'emulation_complete'): Promise<void> {
        if (this.closed) return;
        this.closed = true;

        const stats = this.bridge.getSessionStats();
        const end: SessionEnd = {
            kind: 'session_end',
            sessionId: this.cfg.sessionId,
            reason,
            summary: {
                ...stats,
                totalCostUsd: this.totalCostUsd,
            },
        };
        await this.transport.close(end);
        this.bridge.getSessionStats();
        await this.registry.teardown();
    }

    // ─── Tool resolver ────────────────────────────────────────────────────

    private async resolveToolCall(call: ToolCall): Promise<ToolResult> {
        if (this.cfg.customToolResolver) {
            const override = await this.cfg.customToolResolver(call);
            if (override) return override;
        }

        const base = { kind: 'tool_result' as const, eventId: call.eventId, callId: call.callId };

        try {
            switch (call.tool) {
                case 'read_memory': {
                    const args = call.args as { address?: string; length?: number };
                    if (!args.address || !args.length) {
                        return { ...base, ok: false, error: 'read_memory: address and length required' };
                    }
                    const addr = BigInt(args.address);
                    const buf = await this.cfg.host.memRead(addr, args.length);
                    return {
                        ...base,
                        ok: true,
                        data: { address: args.address, bytes: buf.toString('hex') },
                    };
                }
                case 'get_imports':
                    return {
                        ...base,
                        ok: true,
                        data: this.cfg.imports ?? {},
                    };
                case 'disassemble':
                case 'query_helix':
                case 'search_hql':
                case 'list_strings_near':
                    // v0.1 stubs — Phase 3.5 wires Capstone/Helix/HQL.
                    return {
                        ...base,
                        ok: true,
                        data: this.stubbedToolResponse(call.tool),
                    };
                default:
                    return { ...base, ok: false, error: `unknown tool '${call.tool as string}'` };
            }
        } catch (e) {
            return { ...base, ok: false, error: (e as Error).message };
        }
    }

    private stubbedToolResponse(tool: ToolCall['tool']): unknown {
        switch (tool) {
            case 'disassemble':
                return { note: 'disassemble not wired in v0.1; Phase 3.5 will route through Capstone', items: [] };
            case 'query_helix':
                return { note: 'query_helix not wired in v0.1; Phase 3.5 will call the Helix extension', pseudoC: '', confidence: 0 };
            case 'search_hql':
                return { note: 'search_hql not wired in v0.1; Phase 3.5 will route through hexcore-hql', matches: [] };
            case 'list_strings_near':
                return { note: 'list_strings_near not wired in v0.1', strings: [] };
            default:
                return {};
        }
    }
}

function hex(v: bigint): string {
    const s = v.toString(16);
    return '0x' + (s.length % 2 === 0 ? s : '0' + s);
}
