/*---------------------------------------------------------------------------------------------
 *  HexCore IOC Extractor v1.1.0
 *  Shared types and constants
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

/**
 * Supported IOC categories.
 *
 * Each category maps to a family of compiled patterns that the extractor engine
 * runs against printable regions of the target binary.  Categories can be
 * individually toggled by the caller via {@link IOCCommandOptions.categories}.
 */
export type IOCCategory =
	| 'ipv4'
	| 'ipv6'
	| 'url'
	| 'domain'
	| 'email'
	| 'hash'
	| 'filePath'
	| 'registryKey'
	| 'namedPipe'
	| 'mutex'
	| 'userAgent'
	| 'cryptoWallet';

export type IOCStorageMode = 'memory' | 'sqlite' | 'auto';
export type IOCStorageBackend = 'memory' | 'sqlite';

export const ALL_IOC_CATEGORIES: readonly IOCCategory[] = [
	'ipv4', 'ipv6', 'url', 'domain', 'email', 'hash',
	'filePath', 'registryKey', 'namedPipe',
	'mutex', 'userAgent', 'cryptoWallet'
] as const;

/** Single IOC occurrence found in the file. */
export interface IOCMatch {
	/** Which category the match belongs to. */
	category: IOCCategory;
	/** The extracted indicator value (cleaned / normalized). */
	value: string;
	/** Byte offset of the match inside the file. */
	offset: number;
	/** Whether the match came from an ASCII or UTF-16LE region. */
	encoding: 'ASCII' | 'UTF-16LE';
	/**
	 * Up to ±16 bytes of printable context around the match.
	 * Useful for analysts to quickly judge relevance.
	 */
	context: string;
}

/** Per-category summary count. */
export interface IOCSummary {
	totalIndicators: number;
	uniqueIndicators: number;
	categoryCounts: Record<IOCCategory, number>;
	/** True if we hit maxMatches before scanning the whole file. */
	truncated: boolean;
}

/** Complete extraction result returned by the command. */
export interface IOCExtractionResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	storageBackend: IOCStorageBackend;
	summary: IOCSummary;
	/** Unique IOC matches grouped by category for structured consumption. */
	indicators: Record<IOCCategory, IOCMatch[]>;
	/** Pre-rendered Markdown report. */
	reportMarkdown: string;
}

// ---------------------------------------------------------------------------
// Command / pipeline contract types
// ---------------------------------------------------------------------------

export type OutputFormat = 'json' | 'md';

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

export interface IOCCommandOptions {
	/** Target file path (headless). */
	file?: string;
	/** Output destination (headless). */
	output?: CommandOutputOptions;
	/** Suppress all UI when true — required for pipeline. */
	quiet?: boolean;
	/**
	 * Restrict extraction to specific categories.
	 * Defaults to all categories when omitted.
	 */
	categories?: IOCCategory[];
	/**
	 * Filter private/reserved IPs (RFC1918, loopback, link-local).
	 * Defaults to `false`.
	 */
	excludePrivate?: boolean;
	/**
	 * Maximum total unique matches before stopping.
	 * Defaults to 10 000.
	 */
	maxMatches?: number;
	/**
	 * Match storage backend selection.
	 * - `memory`: keep all dedupe and matches in RAM
	 * - `sqlite`: use SQLite-backed incremental dedupe/storage
	 * - `auto`: choose backend based on file size and maxMatches
	 */
	storageMode?: IOCStorageMode;
	/**
	 * Optional sqlite database path when `storageMode` is `sqlite`.
	 * If omitted, HexCore uses a temporary file and cleans it up.
	 */
	sqlitePath?: string;
	/**
	 * Auto-mode threshold: if `maxMatches` is greater than or equal to this
	 * value, SQLite backend is selected.
	 */
	sqliteThresholdMatches?: number;
	/**
	 * Auto-mode threshold in megabytes: if file size is greater than or equal to
	 * this value, SQLite backend is selected.
	 */
	sqliteThresholdFileSizeMB?: number;
}

// ---------------------------------------------------------------------------
// Extraction engine types (internal)
// ---------------------------------------------------------------------------

/** Progress callback shape for UI integration. */
export interface ExtractionProgress {
	processedBytes: number;
	totalBytes: number;
	percent: number;
	indicatorsFound: number;
}

export type ProgressCallback = (event: ExtractionProgress) => void;

/** Raw result from the core engine before report generation. */
export interface CoreExtractionResult {
	fileSize: number;
	storageBackend: IOCStorageBackend;
	indicators: Record<IOCCategory, IOCMatch[]>;
	summary: IOCSummary;
	cancelled: boolean;
}
