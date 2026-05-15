/**
 * Oracle Trigger Registry — native breakpoint bookkeeping.
 *
 * v0.3 (2026-04-22): replaces the earlier INT3 (0xCC) byte-injection scheme
 * with Unicorn's native `breakpointAdd` / `breakpointDel`. Rationale:
 * INT3 injection modifies code bytes, which Unicorn caches into Translation
 * Blocks (TB cache). After a trap, restoring the original byte does NOT
 * invalidate the cached TB, so the very next emu_start re-executes the
 * cached INT3 translation, traps again, and `instructionsExecuted` stays
 * at 0. Native breakpoints are a Unicorn-side flag check that doesn't
 * modify memory and doesn't poison the TB cache.
 *
 * A Trigger is "where the oracle wakes up". Three kinds are handled here:
 *   - `instruction`: install a native breakpoint at the trigger PC.
 *   - `api`:         resolved to a PC at setup time (IAT walk) and
 *                    then handled identically to `instruction`.
 *   - `exception`:   doesn't need a breakpoint — Unicorn already surfaces
 *                    the error when the fault occurs. Registry just
 *                    remembers the trigger metadata so the hook bridge
 *                    can tag the DecisionRequest correctly.
 *
 * Heuristic triggers (`timing_check`, `peb_access`, `memory_read/write`) are
 * NOT implemented in v0.3 — the caller registers `instruction` triggers at
 * specific PCs it wants to pause at.
 *
 * Not thread-safe: only the main thread touches the registry.
 */

import type { Trigger, TriggerKind } from './oracle-protocol';

export interface TriggerRegistryHost {
    addBreakpoint(pc: bigint): Promise<void>;
    removeBreakpoint(pc: bigint): Promise<void>;
}

export interface RegisteredTrigger extends Trigger {
    /** Numeric PC — parsed from `Trigger.value` for `instruction`/`api`. */
    pc?: bigint;
    /** Whether the native breakpoint is currently installed. */
    injected: boolean;
}

/** How many instruction triggers a single session is allowed to register. */
const MAX_INSTRUCTION_TRIGGERS = 64;

export class OracleTriggerRegistry {
    private readonly host: TriggerRegistryHost;
    /** Only triggers with a resolved PC go in this map. */
    private readonly byPc = new Map<string, RegisteredTrigger>();
    /** All triggers, indexed by `${kind}:${value}`. */
    private readonly byKey = new Map<string, RegisteredTrigger>();

    constructor(host: TriggerRegistryHost) {
        this.host = host;
    }

    /** Add a trigger. For `instruction`/`api` this installs a native bp. */
    async register(trigger: Trigger): Promise<RegisteredTrigger> {
        const key = `${trigger.kind}:${trigger.value}`;
        const existing = this.byKey.get(key);
        if (existing) return existing;

        if (this.byPc.size >= MAX_INSTRUCTION_TRIGGERS && this.isPcBacked(trigger.kind)) {
            throw new Error(
                `oracle: trigger limit reached (${MAX_INSTRUCTION_TRIGGERS}); close the session or reuse an existing trigger`,
            );
        }

        const entry: RegisteredTrigger = { ...trigger, injected: false };

        if (this.isPcBacked(trigger.kind)) {
            const pc = parseHexAddress(trigger.value);
            entry.pc = pc;
            await this.host.addBreakpoint(pc);
            entry.injected = true;
            this.byPc.set(pcKey(pc), entry);
        }
        // else: exception triggers need no Unicorn-side state.

        this.byKey.set(key, entry);
        return entry;
    }

    /** Look up a trigger by the PC at which emulation paused. */
    matchByPc(pc: bigint): RegisteredTrigger | undefined {
        return this.byPc.get(pcKey(pc));
    }

    /** Look up the exception trigger (if any). */
    matchException(): RegisteredTrigger | undefined {
        for (const t of this.byKey.values()) {
            if (t.kind === 'exception') return t;
        }
        return undefined;
    }

    /**
     * Remove the breakpoint temporarily. The bridge uses this to let the
     * paused-at instruction execute one step before re-adding the bp (so
     * we don't immediately re-trigger). For action="abort" this is also
     * called to clean up without ever re-adding.
     */
    async restore(trigger: RegisteredTrigger): Promise<void> {
        if (!trigger.injected || trigger.pc === undefined) return;
        await this.host.removeBreakpoint(trigger.pc);
        trigger.injected = false;
    }

    /** Re-add the breakpoint after stepping past the triggered instruction. */
    async reinject(trigger: RegisteredTrigger): Promise<void> {
        if (trigger.injected || trigger.pc === undefined) return;
        await this.host.addBreakpoint(trigger.pc);
        trigger.injected = true;
    }

    /** Remove a trigger entirely. */
    async unregister(trigger: RegisteredTrigger): Promise<void> {
        await this.restore(trigger);
        if (trigger.pc !== undefined) this.byPc.delete(pcKey(trigger.pc));
        this.byKey.delete(`${trigger.kind}:${trigger.value}`);
    }

    /** Teardown — remove ALL installed breakpoints. Call from session close(). */
    async teardown(): Promise<void> {
        for (const t of this.byKey.values()) {
            if (t.injected) await this.restore(t);
        }
        this.byPc.clear();
        this.byKey.clear();
    }

    /** Read-only snapshot for UI / logs. */
    list(): ReadonlyArray<RegisteredTrigger> {
        return Array.from(this.byKey.values());
    }

    private isPcBacked(kind: TriggerKind): boolean {
        return kind === 'instruction' || kind === 'api';
    }
}

function parseHexAddress(s: string): bigint {
    const norm = s.trim().toLowerCase();
    const withPrefix = norm.startsWith('0x') ? norm : `0x${norm}`;
    try {
        return BigInt(withPrefix);
    } catch (e) {
        throw new Error(`oracle: invalid address '${s}' (expected 0x-prefixed hex): ${(e as Error).message}`);
    }
}

function pcKey(pc: bigint): string {
    return pc.toString(16);
}
