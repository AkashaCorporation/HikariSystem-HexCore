/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Trace Manager
 *  Centralized API/libc call trace capture and export
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/**
 * Represents a single API/libc call intercepted during emulation.
 */
export interface TraceEntry {
	/** Name of the intercepted function (e.g. 'malloc', 'CreateFileA') */
	functionName: string;
	/** Library or DLL that provides the function (e.g. 'libc', 'kernel32.dll') */
	library: string;
	/** Arguments passed to the function, formatted as hex/decimal strings */
	arguments: string[];
	/** Return value of the function as a hex string */
	returnValue: string;
	/** Program counter address at the point of the call */
	pcAddress: string;
	/** Timestamp of the call (Date.now()) */
	timestamp: number;
}

/**
 * JSON export format for the trace.
 */
export interface TraceExport {
	entries: TraceEntry[];
	totalEntries: number;
	/** Entries dropped after the cap was hit (0 unless a crafted binary spammed hooked calls). */
	dropped: number;
	generatedAt: string;
}

/**
 * Upper bound on retained trace entries. A crafted binary that loops over a
 * hooked API/syscall would otherwise grow `entries` without bound (it survives
 * across continue calls within a session), so cap retention and count the
 * overflow. Env-overridable, mirroring debugEngine's HEXCORE_SC_MAX_ADDRS.
 */
const TRACE_MAX_ENTRIES: number = (() => {
	const raw = Number(process.env.HEXCORE_TRACE_MAX_ENTRIES);
	return Number.isInteger(raw) && raw > 0 ? raw : 200000;
})();

/**
 * Centralized manager for API/libc call traces during emulation.
 * Receives events from LinuxApiHooks and WinApiHooks, stores them,
 * and supports real-time listeners and JSON export.
 */
export class TraceManager {
	private entries: TraceEntry[] = [];
	private listeners: Array<(entry: TraceEntry) => void> = [];
	private dropped: number = 0;

	/**
	 * Record a new trace entry and notify all registered listeners. Past the
	 * retention cap the entry is dropped (keeping the trace's BEGINNING, the most
	 * useful part) and counted; listeners still fire so real-time streaming
	 * consumers are unaffected.
	 */
	record(entry: TraceEntry): void {
		if (this.entries.length < TRACE_MAX_ENTRIES) {
			this.entries.push(entry);
		} else {
			this.dropped++;
		}
		for (const listener of this.listeners) {
			listener(entry);
		}
	}

	/**
	 * Return a shallow copy of all recorded entries.
	 */
	getEntries(): TraceEntry[] {
		return [...this.entries];
	}

	/**
	 * Clear all recorded entries.
	 */
	clear(): void {
		this.entries = [];
		this.dropped = 0;
	}

	/**
	 * Register a callback that fires whenever a new entry is recorded.
	 */
	onEntry(listener: (entry: TraceEntry) => void): void {
		this.listeners.push(listener);
	}

	/**
	 * Export the trace as a structured JSON object.
	 */
	exportJSON(): TraceExport {
		return {
			entries: this.getEntries(),
			totalEntries: this.entries.length,
			dropped: this.dropped,
			generatedAt: new Date().toISOString(),
		};
	}
}
