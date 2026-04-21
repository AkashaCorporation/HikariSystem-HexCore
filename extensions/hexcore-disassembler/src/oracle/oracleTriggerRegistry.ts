/**
 * Oracle Trigger Registry — INT3 injection bookkeeping.
 *
 * A Trigger is "where the oracle wakes up". Three kinds are handled here:
 *   - `instruction`: install a 0xCC byte at the trigger PC so the CPU traps
 *                    with intno=3 when it reaches that address.
 *   - `api`:         resolved to a PC at setup time (IAT walk + stub PC) and
 *                    then handled identically to `instruction`.
 *   - `exception`:   doesn't need INT3 injection — Unicorn already raises
 *                    the interrupt when the fault occurs. Registry just
 *                    remembers the trigger metadata so the hook bridge
 *                    can tag the DecisionRequest correctly.
 *
 * Heuristic triggers (`timing_check`, `peb_access`, `memory_read/write`) are
 * NOT implemented in v0.1 — the caller registers `instruction` triggers at
 * specific PCs it wants to pause at (Pathfinder's disassembler output is the
 * typical source of these PCs).
 *
 * Rules:
 *   - Injection saves the original byte so `restore()` is lossless.
 *   - Triggers are keyed on PC for O(1) lookup by the interrupt handler.
 *   - `handled()` is called after the oracle's DecisionResponse is applied,
 *     so the original byte is back in memory and the next instruction boundary
 *     can resume cleanly.
 *
 * Not thread-safe: only the main thread touches the registry. The emulator
 * worker thread calls through the wrapper's blocking INTR path, which
 * marshals onto the main thread before `match()` runs.
 */

import type { Trigger, TriggerKind } from './oracle-protocol';

export interface TriggerRegistryHost {
    memRead(address: bigint | number, size: number): Buffer;
    memWrite(address: bigint | number, data: Buffer): void;
}

export interface RegisteredTrigger extends Trigger {
    /** Numeric PC — parsed from `Trigger.value` for `instruction`/`api`. */
    pc?: bigint;
    /** Byte overwritten when we injected INT3; restored at teardown. */
    originalByte?: number;
    /** Whether INT3 is currently installed at the trigger PC. */
    injected: boolean;
}

const INT3: number = 0xcc;

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

    /** Add a trigger. For `instruction`/`api` this injects INT3 immediately. */
    register(trigger: Trigger): RegisteredTrigger {
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
            // Read & save the original byte, then write 0xCC.
            const buf = this.host.memRead(pc, 1);
            if (buf.length !== 1) {
                throw new Error(`oracle: memRead at ${trigger.value} returned ${buf.length} bytes (expected 1)`);
            }
            entry.originalByte = buf[0];
            if (entry.originalByte !== INT3) {
                this.host.memWrite(pc, Buffer.from([INT3]));
                entry.injected = true;
            }
            this.byPc.set(pcKey(pc), entry);
        }
        // else: exception triggers need no memory mutation.

        this.byKey.set(key, entry);
        return entry;
    }

    /** Look up a trigger by the PC at which a HOOK.INTR just fired. */
    matchByPc(pc: bigint): RegisteredTrigger | undefined {
        return this.byPc.get(pcKey(pc));
    }

    /** Look up the exception trigger (if any) by its reason string. */
    matchException(): RegisteredTrigger | undefined {
        for (const t of this.byKey.values()) {
            if (t.kind === 'exception') return t;
        }
        return undefined;
    }

    /**
     * Before resuming, restore the original byte at a trigger's PC. The
     * caller can then step the original instruction, reinject (if it wants
     * to pause again next time), or leave the byte restored forever.
     */
    restore(trigger: RegisteredTrigger): void {
        if (!trigger.injected || trigger.pc === undefined || trigger.originalByte === undefined) return;
        this.host.memWrite(trigger.pc, Buffer.from([trigger.originalByte]));
        trigger.injected = false;
    }

    /** Re-inject INT3 after the original instruction stepped past. */
    reinject(trigger: RegisteredTrigger): void {
        if (trigger.injected || trigger.pc === undefined) return;
        this.host.memWrite(trigger.pc, Buffer.from([INT3]));
        trigger.injected = true;
    }

    /** Remove a trigger and restore its original byte. */
    unregister(trigger: RegisteredTrigger): void {
        this.restore(trigger);
        if (trigger.pc !== undefined) this.byPc.delete(pcKey(trigger.pc));
        this.byKey.delete(`${trigger.kind}:${trigger.value}`);
    }

    /** Teardown — restore ALL injected bytes. Call from session close(). */
    teardown(): void {
        for (const t of this.byKey.values()) {
            if (t.injected) this.restore(t);
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
