/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger — Emulation Session Lock
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/**
 * Async single-flight serialization lock for the shared (singleton) DebugEngine.
 *
 * ── Why this exists (GitHub issue #28) ──────────────────────────────────────
 * `extension.activate()` creates ONE `DebugEngine` and shares it across every
 * headless command handler (emulateHeadless, emulateFullHeadless, continueHeadless,
 * writeMemoryHeadless, setStdinHeadless, getStateHeadless, disposeHeadless, ...).
 * That engine owns ONE UnicornWrapper, which owns ONE `_x64ElfWorker` child
 * process. `DebugEngine.startEmulation()` DISPOSES any existing emulator/worker
 * before standing up a fresh one (debugEngine.ts ~line 187; the worker is
 * disposed in unicornWrapper.setElfSyncMode / startEmulation).
 *
 * So when two pipeline jobs run an emulation STEP concurrently on the shared
 * engine, job B's `emulateHeadless` SIGTERMs job A's x64-ELF worker, and job A's
 * later steps (writeMemory / continue / getState) fail with
 *   "X64 ELF worker exited before ready (code=null, signal=SIGTERM)"  or
 *   "No active emulation session. Call emulateHeadless first."
 *
 * ── Design ──────────────────────────────────────────────────────────────────
 * An emulation SESSION must hold the shared engine exclusively from start until
 * dispose. Because the multi-step keepAlive flow spans SEPARATE command
 * invocations (emulate -> writeMemory -> setStdin -> continue -> getState ->
 * dispose), the lock is held ACROSS calls:
 *
 *   acquire():  at session start (emulateHeadless / emulateFullHeadless /
 *               startEmulation). A concurrent acquire() WAITS (FIFO) for the
 *               current holder to release, instead of stomping the shared worker.
 *   release():  on disposeHeadless (multi-step), at the end of a self-contained
 *               emulateFullHeadless run, AND on any error thrown by the guarded
 *               body.
 *   timeout:    each acquired session arms a safety timer. If a session is never
 *               released (crashed / abandoned caller), the timer force-releases
 *               it so future emulations are never deadlocked.
 *
 * The lock is intentionally re-entrancy-free and token-based: release() only
 * succeeds for the token that currently holds the lock, so a late
 * disposeHeadless from an already-timed-out session cannot release a DIFFERENT
 * session that has since acquired the lock.
 */

export interface SessionLockHandle {
	/** Opaque token identifying this acquisition; required to release. */
	readonly token: number;
}

interface Waiter {
	resolve: (handle: SessionLockHandle) => void;
}

export class SessionLock {
	private _held = false;
	private _holderToken: number | undefined;
	private _nextToken = 1;
	private readonly _waiters: Waiter[] = [];
	private _safetyTimer: NodeJS.Timeout | undefined;

	/** Max time a single session may hold the lock before it is force-released. */
	private readonly _maxHoldMs: number;
	private readonly _log: (msg: string) => void;

	constructor(maxHoldMs: number, log?: (msg: string) => void) {
		this._maxHoldMs = maxHoldMs;
		this._log = log ?? (() => { /* no-op */ });
	}

	/** True when some session currently holds the lock. */
	get isHeld(): boolean {
		return this._held;
	}

	/** Number of sessions currently waiting to acquire. */
	get waiterCount(): number {
		return this._waiters.length;
	}

	/**
	 * Acquire the session lock. Resolves immediately if free; otherwise queues
	 * FIFO and resolves when the current holder releases (or is force-released
	 * by its safety timer). The returned handle's token is required by release().
	 */
	acquire(): Promise<SessionLockHandle> {
		if (!this._held) {
			return Promise.resolve(this._grant());
		}
		this._log(`[session-lock] busy (holder=${this._holderToken}); queueing (waiters=${this._waiters.length + 1})`);
		return new Promise<SessionLockHandle>((resolve) => {
			this._waiters.push({ resolve });
		});
	}

	/**
	 * Release the lock for the given handle. No-op (logged) if the handle's token
	 * is not the current holder — this makes a stale/duplicate release from an
	 * already-timed-out session harmless. Hands the lock to the next waiter (if any).
	 */
	release(handle: SessionLockHandle | undefined): void {
		if (!handle) {
			return;
		}
		if (!this._held || handle.token !== this._holderToken) {
			// Stale release: the session that owned this token already lost the
			// lock (e.g. via the safety timer). Do NOT release someone else's hold.
			this._log(`[session-lock] stale release ignored (token=${handle.token}, holder=${this._holderToken ?? 'none'})`);
			return;
		}
		this._dropHold();
	}

	private _grant(): SessionLockHandle {
		this._held = true;
		this._holderToken = this._nextToken++;
		const token = this._holderToken;
		this._armSafetyTimer(token);
		this._log(`[session-lock] acquired (token=${token})`);
		return { token };
	}

	private _dropHold(): void {
		this._clearSafetyTimer();
		const prev = this._holderToken;
		this._held = false;
		this._holderToken = undefined;

		const next = this._waiters.shift();
		if (next) {
			const handle = this._grant();
			this._log(`[session-lock] handed off token ${prev} -> ${handle.token} (waiters=${this._waiters.length})`);
			next.resolve(handle);
		} else {
			this._log(`[session-lock] released (token=${prev}); idle`);
		}
	}

	private _armSafetyTimer(token: number): void {
		this._clearSafetyTimer();
		this._safetyTimer = setTimeout(() => {
			// Only fire if this token is still the holder. A crashed/abandoned
			// session that never called release() would otherwise deadlock all
			// future emulations.
			if (this._held && this._holderToken === token) {
				this._log(`[session-lock] SAFETY TIMEOUT — force-releasing token ${token} after ${this._maxHoldMs}ms (caller never disposed)`);
				this._dropHold();
			}
		}, this._maxHoldMs);
		// Do not keep the event loop alive solely for this timer.
		this._safetyTimer.unref?.();
	}

	private _clearSafetyTimer(): void {
		if (this._safetyTimer) {
			clearTimeout(this._safetyTimer);
			this._safetyTimer = undefined;
		}
	}
}
