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
	/** Calling convention applied by the hook dispatcher. */
	callingConvention?: 'win64' | 'stdcall' | 'cdecl' | 'unknown';
	/** Callee-owned argument bytes removed from the stack. */
	stackBytesPopped?: number;
	/** Fidelity promised by the API hook implementation. */
	semanticLevel?: 'implemented' | 'modeled' | 'return-only' | 'unsupported';
	/** Source used to determine the call signature. */
	signatureSource?: 'win64-abi' | 'win32-signature-table' | 'decorated-name' | 'unknown';
	/** Number of consecutive identical calls represented by this row. */
	repeatCount?: number;
	/** Timestamp of the first call when repeatCount is greater than one. */
	firstTimestamp?: number;
	/** Timestamp of the most recent call represented by this row. */
	lastTimestamp?: number;
}

export interface TraceCaptureOptions {
	/** Maximum retained rows after grouping/sampling. */
	maxEntries?: number;
	/** Retain one out of every N non-grouped calls. */
	sampleEvery?: number;
	/** Collapse consecutive identical calls into one row with repeatCount. */
	groupRepeated?: boolean;
}

/**
 * JSON export format for the trace.
 */
export interface TraceExport {
	entries: TraceEntry[];
	/** Retained rows. Kept for compatibility with previous exports. */
	totalEntries: number;
	/** Exact number of calls observed before grouping, sampling, or caps. */
	totalCalls: number;
	retainedEntries: number;
	aggregatedCalls: number;
	sampledOut: number;
	/** Rows dropped after the cap was hit. */
	dropped: number;
	configuration: Required<TraceCaptureOptions>;
	generatedAt: string;
}

/**
 * Upper bound on retained trace entries. A crafted binary that loops over a
 * hooked API/syscall would otherwise grow `entries` without bound (it survives
 * across continue calls within a session), so cap retention and count the
 * overflow. Env-overridable, mirroring debugEngine's HEXCORE_SC_MAX_ADDRS.
 */
const DEFAULT_TRACE_MAX_ENTRIES: number = (() => {
	const raw = Number(process.env.HEXCORE_TRACE_MAX_ENTRIES);
	return Number.isInteger(raw) && raw > 0 ? raw : 20000;
})();

const DEFAULT_TRACE_OPTIONS: Required<TraceCaptureOptions> = {
	maxEntries: DEFAULT_TRACE_MAX_ENTRIES,
	sampleEvery: 1,
	groupRepeated: true,
};

/**
 * Centralized manager for API/libc call traces during emulation.
 * Receives events from LinuxApiHooks and WinApiHooks, stores them,
 * and supports real-time listeners and JSON export.
 */
export class TraceManager {
	private entries: TraceEntry[] = [];
	private listeners: Array<(entry: TraceEntry) => void> = [];
	private dropped: number = 0;
	private totalCalls: number = 0;
	private aggregatedCalls: number = 0;
	private sampledOut: number = 0;
	private lastSignature: string | undefined;
	private options: Required<TraceCaptureOptions>;

	constructor(options?: TraceCaptureOptions) {
		this.options = this.normalizeOptions(options);
	}

	configure(options?: TraceCaptureOptions): void {
		this.options = this.normalizeOptions(options);
	}

	/**
	 * Record a new trace entry and notify all registered listeners. Past the
	 * retention cap the entry is dropped (keeping the trace's BEGINNING, the most
	 * useful part) and counted; listeners still fire so real-time streaming
	 * consumers are unaffected.
	 */
	record(entry: TraceEntry): void {
		this.totalCalls++;
		const signature = this.signature(entry);
		const previous = this.entries[this.entries.length - 1];
		if (this.options.groupRepeated && previous && signature === this.lastSignature) {
			previous.repeatCount = (previous.repeatCount ?? 1) + 1;
			previous.firstTimestamp ??= previous.timestamp;
			previous.lastTimestamp = entry.timestamp;
			this.aggregatedCalls++;
		} else if ((this.totalCalls - 1) % this.options.sampleEvery !== 0) {
			this.sampledOut++;
			this.lastSignature = undefined;
		} else if (this.entries.length < this.options.maxEntries) {
			this.entries.push({ ...entry });
			this.lastSignature = signature;
		} else {
			this.dropped++;
			this.lastSignature = undefined;
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
		this.totalCalls = 0;
		this.aggregatedCalls = 0;
		this.sampledOut = 0;
		this.lastSignature = undefined;
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
			totalCalls: this.totalCalls,
			retainedEntries: this.entries.length,
			aggregatedCalls: this.aggregatedCalls,
			sampledOut: this.sampledOut,
			dropped: this.dropped,
			configuration: { ...this.options },
			generatedAt: new Date().toISOString(),
		};
	}

	private normalizeOptions(options?: TraceCaptureOptions): Required<TraceCaptureOptions> {
		const maxEntries = Number.isInteger(options?.maxEntries) && options!.maxEntries! > 0
			? options!.maxEntries!
			: DEFAULT_TRACE_OPTIONS.maxEntries;
		const sampleEvery = Number.isInteger(options?.sampleEvery) && options!.sampleEvery! > 0
			? options!.sampleEvery!
			: DEFAULT_TRACE_OPTIONS.sampleEvery;
		return {
			maxEntries,
			sampleEvery,
			groupRepeated: options?.groupRepeated ?? DEFAULT_TRACE_OPTIONS.groupRepeated,
		};
	}

	private signature(entry: TraceEntry): string {
		return JSON.stringify([
			entry.functionName,
			entry.library,
			entry.arguments,
			entry.returnValue,
			entry.pcAddress,
		]);
	}
}
