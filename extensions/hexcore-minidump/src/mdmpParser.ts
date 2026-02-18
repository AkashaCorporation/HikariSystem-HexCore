/*---------------------------------------------------------------------------------------------
 *  HexCore Minidump Parser v1.0.0
 *  Core MDMP header and stream directory parser
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import type {
	MinidumpHeader,
	MinidumpDirectory,
	MinidumpAnalysisResult,
	ThreatIndicators,
	ThreadInfo,
	ThreadExInfo,
	ModuleInfo,
	MemoryRegion,
	MemoryDescriptor,
	Memory64Descriptor,
	SystemInfo,
	ExceptionInfo,
} from './types';
import {
	MDMP_SIGNATURE,
	MDMP_HEADER_SIZE,
	DIRECTORY_ENTRY_SIZE,
	StreamType,
} from './types';
import {
	parseThreadListStream,
	parseModuleListStream,
	parseMemoryInfoListStream,
	parseSystemInfoStream,
	parseThreadInfoListStream,
	parseMinidumpString,
	parseMemoryListStream,
	parseMemory64ListStream,
	parseExceptionStream,
} from './streamParsers';

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Parse a Windows Minidump file and return a complete analysis result.
 *
 * The parser uses targeted `fs.readSync` calls at known offsets rather than
 * loading the entire file into memory — dump files can be hundreds of MB.
 */
export function parseMinidump(filePath: string): Omit<MinidumpAnalysisResult, 'reportMarkdown'> {
	const stats = fs.statSync(filePath);
	const fileSize = stats.size;

	if (fileSize < MDMP_HEADER_SIZE) {
		throw new Error(`File too small to be a valid Minidump (${fileSize} bytes, minimum ${MDMP_HEADER_SIZE})`);
	}

	const fd = fs.openSync(filePath, 'r');
	try {
		// Read and validate header
		const header = readHeader(fd);
		if (header.signature !== MDMP_SIGNATURE) {
			const actual = header.signature.toString(16).toUpperCase().padStart(8, '0');
			throw new Error(`Invalid Minidump signature: 0x${actual} (expected 0x${MDMP_SIGNATURE.toString(16).toUpperCase()})`);
		}

		// Read stream directory
		const streamDirectory = readStreamDirectory(
			fd,
			header.streamDirectoryRva,
			header.numberOfStreams,
			fileSize,
		);

		// Parse each relevant stream
		let systemInfo: SystemInfo | undefined;
		let threads: ThreadInfo[] = [];
		let threadExInfo: ThreadExInfo[] = [];
		let modules: ModuleInfo[] = [];
		let memoryRegions: MemoryRegion[] = [];
		let memoryDescriptors: MemoryDescriptor[] = [];
		let memory64Descriptors: Memory64Descriptor[] = [];
		let exception: ExceptionInfo | undefined;

		for (const entry of streamDirectory) {
			if (entry.dataSize === 0 || entry.rva === 0) {
				continue;
			}

			switch (entry.streamType) {
				case StreamType.SystemInfoStream:
					systemInfo = parseSystemInfoStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.ThreadListStream:
					threads = parseThreadListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.ThreadInfoListStream:
					threadExInfo = parseThreadInfoListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.ModuleListStream:
					modules = parseModuleListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.MemoryInfoListStream:
					memoryRegions = parseMemoryInfoListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.MemoryListStream:
					memoryDescriptors = parseMemoryListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.Memory64ListStream:
					memory64Descriptors = parseMemory64ListStream(fd, entry.rva, entry.dataSize);
					break;

				case StreamType.ExceptionStream:
					exception = parseExceptionStream(fd, entry.rva, entry.dataSize);
					break;
			}
		}

		// Run threat heuristics
		const threats = assessThreats(
			memoryRegions,
			modules,
			threadExInfo,
			header.timestamp,
		);

		return {
			fileName: '',    // Set by caller
			filePath,
			fileSize,
			header,
			streamDirectory,
			systemInfo,
			threads,
			threadExInfo,
			modules,
			memoryRegions,
			memoryDescriptors,
			memory64Descriptors,
			exception,
			threats,
		};
	} finally {
		fs.closeSync(fd);
	}
}

// ---------------------------------------------------------------------------
// Header Parsing
// ---------------------------------------------------------------------------

function readHeader(fd: number): MinidumpHeader {
	const buf = readBytes(fd, 0, MDMP_HEADER_SIZE);

	return {
		signature: buf.readUInt32LE(0),
		versionLo: buf.readUInt16LE(4),
		versionHi: buf.readUInt16LE(6),
		numberOfStreams: buf.readUInt32LE(8),
		streamDirectoryRva: buf.readUInt32LE(12),
		checksum: buf.readUInt32LE(16),
		timestamp: buf.readUInt32LE(20),
		flags: buf.readBigUInt64LE(24),
	};
}

// ---------------------------------------------------------------------------
// Stream Directory
// ---------------------------------------------------------------------------

function readStreamDirectory(
	fd: number,
	rva: number,
	count: number,
	fileSize: number,
): MinidumpDirectory[] {
	if (count === 0) {
		return [];
	}

	const totalSize = count * DIRECTORY_ENTRY_SIZE;

	if (rva + totalSize > fileSize) {
		throw new Error(
			`Stream directory at RVA 0x${rva.toString(16)} extends beyond file ` +
			`(${rva + totalSize} > ${fileSize})`
		);
	}

	const buf = readBytes(fd, rva, totalSize);
	const entries: MinidumpDirectory[] = [];

	for (let i = 0; i < count; i++) {
		const offset = i * DIRECTORY_ENTRY_SIZE;
		entries.push({
			streamType: buf.readUInt32LE(offset),
			dataSize: buf.readUInt32LE(offset + 4),
			rva: buf.readUInt32LE(offset + 8),
		});
	}

	return entries;
}

// ---------------------------------------------------------------------------
// Threat Heuristics
// ---------------------------------------------------------------------------

/**
 * Assess threat indicators based on parsed dump data.
 *
 * Heuristics:
 * - RWX memory: PAGE_EXECUTE_READWRITE in committed private memory → shellcode
 * - Non-system modules: DLLs outside %SystemRoot% and %ProgramFiles%
 * - Recent threads: Created within 60 seconds of dump timestamp
 * - Suspicious start: Thread start address in non-image region
 */
function assessThreats(
	memoryRegions: MemoryRegion[],
	modules: ModuleInfo[],
	threadExInfo: ThreadExInfo[],
	dumpTimestamp: number,
): ThreatIndicators {
	// RWX regions in committed private memory
	const rwxRegions = memoryRegions.filter(r =>
		r.isSuspicious
	);

	// Non-system modules
	const systemPrefixes = [
		'c:\\windows\\',
		'c:\\program files\\',
		'c:\\program files (x86)\\',
	];
	const nonSystemModules = modules.filter(m => {
		const lower = m.name.toLowerCase();
		return !systemPrefixes.some(prefix => lower.startsWith(prefix));
	});

	// Recent threads (created within 60s of dump)
	const dumpTimeFileTime = unixToFileTime(dumpTimestamp);
	const sixtySeconds = BigInt(60) * BigInt(10_000_000); // 100ns units
	const recentThreads = threadExInfo.filter(t => {
		if (t.createTime === 0n) { return false; }
		const diff = dumpTimeFileTime - t.createTime;
		return diff >= 0n && diff <= sixtySeconds;
	});

	// Threads with start address not in any module's address range
	const suspiciousStartAddresses = threadExInfo.filter(t => {
		if (t.startAddress === 0n) { return false; }
		return !modules.some(m => {
			const base = m.baseAddress;
			const end = base + BigInt(m.size);
			return t.startAddress >= base && t.startAddress < end;
		});
	});

	return {
		rwxRegions,
		nonSystemModules,
		recentThreads,
		suspiciousStartAddresses,
	};
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

/** Read exactly `size` bytes from `fd` at `offset`. */
export function readBytes(fd: number, offset: number, size: number): Buffer {
	const buf = Buffer.alloc(size);
	const bytesRead = fs.readSync(fd, buf, 0, size, offset);
	if (bytesRead < size) {
		throw new Error(
			`Unexpected EOF: wanted ${size} bytes at offset 0x${offset.toString(16)}, got ${bytesRead}`
		);
	}
	return buf;
}

/**
 * Convert UNIX timestamp (seconds since 1970-01-01) to Windows FILETIME
 * (100ns intervals since 1601-01-01).
 */
function unixToFileTime(unix: number): bigint {
	const EPOCH_DIFF = BigInt(116444736000000000); // 100ns between 1601 and 1970
	return BigInt(unix) * BigInt(10_000_000) + EPOCH_DIFF;
}
