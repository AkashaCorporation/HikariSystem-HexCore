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
	generatedAt: string;
}

/**
 * Centralized manager for API/libc call traces during emulation.
 * Receives events from LinuxApiHooks and WinApiHooks, stores them,
 * and supports real-time listeners and JSON export.
 */
export class TraceManager {
	private entries: TraceEntry[] = [];
	private listeners: Array<(entry: TraceEntry) => void> = [];

	/**
	 * Record a new trace entry and notify all registered listeners.
	 */
	record(entry: TraceEntry): void {
		this.entries.push(entry);
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
			generatedAt: new Date().toISOString(),
		};
	}
}
