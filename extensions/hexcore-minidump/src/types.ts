/*---------------------------------------------------------------------------------------------
 *  HexCore Minidump Parser v1.0.0
 *  Types and constants for Windows Minidump (MDMP) format
 *  Copyright (c) HikariSystem. All rights reserved.
 *
 *  Reference: Microsoft MDMP specification
 *  https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/
 *--------------------------------------------------------------------------------------------*/

// ---------------------------------------------------------------------------
// MDMP Binary Format Constants
// ---------------------------------------------------------------------------

/** "MDMP" as little-endian uint32. */
export const MDMP_SIGNATURE = 0x504D444D;

/** Minidump header is always 32 bytes at offset 0. */
export const MDMP_HEADER_SIZE = 32;

/** Each directory entry is 12 bytes. */
export const DIRECTORY_ENTRY_SIZE = 12;

/**
 * Stream type identifiers from MINIDUMP_STREAM_TYPE.
 * We only parse the ones relevant for forensic triage.
 */
export const enum StreamType {
	UnusedStream = 0,
	ThreadListStream = 3,
	ModuleListStream = 4,
	MemoryListStream = 5,
	ExceptionStream = 6,
	SystemInfoStream = 7,
	ThreadExListStream = 8,
	Memory64ListStream = 9,
	HandleDataStream = 12,
	ThreadInfoListStream = 17,
	MemoryInfoListStream = 16,
}

/**
 * Windows memory protection constants (PAGE_*).
 * Used to decode the `Protect` field in MINIDUMP_MEMORY_INFO.
 */
export const MEMORY_PROTECTION: Record<number, string> = {
	0x01: 'NOACCESS',
	0x02: 'READONLY',
	0x04: 'READWRITE',
	0x08: 'WRITECOPY',
	0x10: 'EXECUTE',
	0x20: 'EXECUTE_READ',
	0x40: 'EXECUTE_READWRITE',
	0x80: 'EXECUTE_WRITECOPY',
};

/** Memory state constants. */
export const MEMORY_STATE: Record<number, string> = {
	0x1000: 'MEM_COMMIT',
	0x2000: 'MEM_RESERVE',
	0x10000: 'MEM_FREE',
};

/** Memory type constants. */
export const MEMORY_TYPE: Record<number, string> = {
	0x20000: 'MEM_PRIVATE',
	0x40000: 'MEM_MAPPED',
	0x1000000: 'MEM_IMAGE',
};

/**
 * Processor architecture identifiers from PROCESSOR_ARCHITECTURE_*.
 */
export const PROCESSOR_ARCH: Record<number, string> = {
	0: 'x86',
	5: 'ARM',
	6: 'IA64',
	9: 'AMD64',
	12: 'ARM64',
};

/**
 * Windows version mapping for major.minor to marketing name.
 */
export const WINDOWS_VERSION: Record<string, string> = {
	'10.0': 'Windows 10/11/Server 2016+',
	'6.3': 'Windows 8.1/Server 2012 R2',
	'6.2': 'Windows 8/Server 2012',
	'6.1': 'Windows 7/Server 2008 R2',
	'6.0': 'Windows Vista/Server 2008',
	'5.2': 'Windows XP 64-bit/Server 2003',
	'5.1': 'Windows XP',
};

/**
 * Common Windows exception codes mapped to human-readable names.
 * Reference: ntstatus.h / winnt.h
 */
export const EXCEPTION_CODES: Record<number, string> = {
	0xC0000005: 'ACCESS_VIOLATION',
	0xC0000006: 'IN_PAGE_ERROR',
	0xC0000008: 'INVALID_HANDLE',
	0xC000000D: 'INVALID_PARAMETER',
	0xC0000017: 'NO_MEMORY',
	0xC000001D: 'ILLEGAL_INSTRUCTION',
	0xC0000025: 'NONCONTINUABLE_EXCEPTION',
	0xC0000026: 'INVALID_DISPOSITION',
	0xC000008C: 'ARRAY_BOUNDS_EXCEEDED',
	0xC000008D: 'FLOAT_DENORMAL_OPERAND',
	0xC000008E: 'FLOAT_DIVIDE_BY_ZERO',
	0xC000008F: 'FLOAT_INEXACT_RESULT',
	0xC0000090: 'FLOAT_INVALID_OPERATION',
	0xC0000091: 'FLOAT_OVERFLOW',
	0xC0000092: 'FLOAT_STACK_CHECK',
	0xC0000093: 'FLOAT_UNDERFLOW',
	0xC0000094: 'INTEGER_DIVIDE_BY_ZERO',
	0xC0000095: 'INTEGER_OVERFLOW',
	0xC0000096: 'PRIVILEGED_INSTRUCTION',
	0xC00000FD: 'STACK_OVERFLOW',
	0xC0000135: 'DLL_NOT_FOUND',
	0xC0000138: 'ORDINAL_NOT_FOUND',
	0xC0000139: 'ENTRYPOINT_NOT_FOUND',
	0xC000013A: 'CONTROL_C_EXIT',
	0xC0000142: 'DLL_INIT_FAILED',
	0xC00002B4: 'FLOAT_MULTIPLE_FAULTS',
	0xC00002B5: 'FLOAT_MULTIPLE_TRAPS',
	0xC00002C9: 'REG_NAT_CONSUMPTION',
	0x80000001: 'GUARD_PAGE_VIOLATION',
	0x80000002: 'DATATYPE_MISALIGNMENT',
	0x80000003: 'BREAKPOINT',
	0x80000004: 'SINGLE_STEP',
	0xE06D7363: 'CPP_EXCEPTION',
	0xE0434352: 'CLR_EXCEPTION',
};

// ---------------------------------------------------------------------------
// Parsed Data Structures
// ---------------------------------------------------------------------------

export interface MinidumpHeader {
	signature: number;
	versionLo: number;
	versionHi: number;
	numberOfStreams: number;
	streamDirectoryRva: number;
	checksum: number;
	timestamp: number;
	flags: bigint;
}

export interface MinidumpDirectory {
	streamType: number;
	dataSize: number;
	rva: number;
}

export interface SystemInfo {
	processorArchitecture: number;
	processorArchitectureName: string;
	processorLevel: number;
	processorRevision: number;
	numberOfProcessors: number;
	osMajorVersion: number;
	osMinorVersion: number;
	osBuildNumber: number;
	osPlatformId: number;
	osVersionString: string;
}

export interface ThreadInfo {
	threadId: number;
	suspendCount: number;
	priorityClass: number;
	priority: number;
	/** Thread Environment Block address. */
	teb: bigint;
	/** Stack start address. */
	stackStartOfMemoryRange: bigint;
	stackDataSize: number;
	/** Thread context RVA (register state). */
	contextRva: number;
	contextSize: number;
}

export interface ThreadExInfo {
	threadId: number;
	createTime: bigint;
	exitTime: bigint;
	kernelTime: bigint;
	userTime: bigint;
	startAddress: bigint;
	affinity: bigint;
}

export interface ModuleInfo {
	baseAddress: bigint;
	size: number;
	checksum: number;
	timestamp: number;
	name: string;
	versionMajor: number;
	versionMinor: number;
}

export interface MemoryRegion {
	baseAddress: bigint;
	allocationBase: bigint;
	allocationProtect: number;
	regionSize: bigint;
	state: number;
	protect: number;
	type: number;
	stateName: string;
	protectName: string;
	typeName: string;
	/** True if region is PAGE_EXECUTE_READWRITE in committed private memory. */
	isSuspicious: boolean;
}

export interface MemoryDescriptor {
	startOfMemoryRange: bigint;
	dataSize: number;
	rva: number;
}

export interface Memory64Descriptor {
	startOfMemoryRange: bigint;
	dataSize: bigint;
}

/** Threat heuristic flags. */
export interface ThreatIndicators {
	rwxRegions: MemoryRegion[];
	nonSystemModules: ModuleInfo[];
	recentThreads: ThreadExInfo[];
	suspiciousStartAddresses: ThreadExInfo[];
}

/** Parsed MINIDUMP_EXCEPTION_STREAM data. */
export interface ExceptionInfo {
	threadId: number;
	exceptionCode: number;
	exceptionName: string;
	exceptionFlags: number;
	exceptionAddress: bigint;
	numberOfParameters: number;
	parameters: bigint[];
}

// ---------------------------------------------------------------------------
// Analysis Result
// ---------------------------------------------------------------------------

export interface MinidumpAnalysisResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	header: MinidumpHeader;
	streamDirectory: MinidumpDirectory[];
	systemInfo?: SystemInfo;
	threads: ThreadInfo[];
	threadExInfo: ThreadExInfo[];
	modules: ModuleInfo[];
	memoryRegions: MemoryRegion[];
	memoryDescriptors: MemoryDescriptor[];
	memory64Descriptors: Memory64Descriptor[];
	exception?: ExceptionInfo;
	threats: ThreatIndicators;
	reportMarkdown: string;
}

// ---------------------------------------------------------------------------
// Command Options (Pipeline Contract)
// ---------------------------------------------------------------------------

export type OutputFormat = 'json' | 'md';

export interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

export interface MinidumpCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
	/** For memory command: filter to only suspicious RWX regions. */
	filterRwx?: boolean;
	/** For modules command: include system modules (default: true). */
	includeSystem?: boolean;
}
