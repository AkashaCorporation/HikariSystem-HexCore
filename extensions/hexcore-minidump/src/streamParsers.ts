/*---------------------------------------------------------------------------------------------
 *  HexCore Minidump Parser v1.0.0
 *  Per-stream-type binary parsers
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import type {
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
	MEMORY_PROTECTION,
	MEMORY_STATE,
	MEMORY_TYPE,
	PROCESSOR_ARCH,
	WINDOWS_VERSION,
	EXCEPTION_CODES,
} from './types';
import { readBytes } from './mdmpParser';

// ---------------------------------------------------------------------------
// ThreadListStream (StreamType 3)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_THREAD_LIST layout:
 *   uint32 NumberOfThreads
 *   MINIDUMP_THREAD[NumberOfThreads]
 *
 * Each MINIDUMP_THREAD is 48 bytes:
 *   uint32 ThreadId
 *   uint32 SuspendCount
 *   uint32 PriorityClass
 *   uint32 Priority
 *   uint64 Teb
 *   MINIDUMP_MEMORY_DESCRIPTOR Stack (16 bytes: uint64 startAddr + uint32 dataSize + uint32 rva)
 *   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext (8 bytes: uint32 dataSize + uint32 rva)
 */
export function parseThreadListStream(fd: number, rva: number, _size: number): ThreadInfo[] {
	const headerBuf = readBytes(fd, rva, 4);
	const count = headerBuf.readUInt32LE(0);

	if (count === 0) { return []; }

	const THREAD_SIZE = 48;
	const dataBuf = readBytes(fd, rva + 4, count * THREAD_SIZE);
	const threads: ThreadInfo[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * THREAD_SIZE;
		threads.push({
			threadId: dataBuf.readUInt32LE(off),
			suspendCount: dataBuf.readUInt32LE(off + 4),
			priorityClass: dataBuf.readUInt32LE(off + 8),
			priority: dataBuf.readUInt32LE(off + 12),
			teb: dataBuf.readBigUInt64LE(off + 16),
			stackStartOfMemoryRange: dataBuf.readBigUInt64LE(off + 24),
			stackDataSize: dataBuf.readUInt32LE(off + 32),
			contextSize: dataBuf.readUInt32LE(off + 40),
			contextRva: dataBuf.readUInt32LE(off + 44),
		});
	}

	return threads;
}

// ---------------------------------------------------------------------------
// ThreadInfoListStream (StreamType 17)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_THREAD_INFO_LIST layout:
 *   uint32 SizeOfHeader
 *   uint32 SizeOfEntry
 *   uint32 NumberOfEntries
 *   MINIDUMP_THREAD_INFO[NumberOfEntries]
 *
 * Each MINIDUMP_THREAD_INFO is typically 56 bytes:
 *   uint32 ThreadId
 *   uint32 DumpFlags
 *   uint32 DumpError
 *   uint32 ExitStatus
 *   uint64 CreateTime    (FILETIME)
 *   uint64 ExitTime      (FILETIME)
 *   uint64 KernelTime    (FILETIME)
 *   uint64 UserTime      (FILETIME)
 *   uint64 StartAddress
 *   uint64 Affinity
 */
export function parseThreadInfoListStream(fd: number, rva: number, _size: number): ThreadExInfo[] {
	const headerBuf = readBytes(fd, rva, 12);
	const sizeOfHeader = headerBuf.readUInt32LE(0);
	const sizeOfEntry = headerBuf.readUInt32LE(4);
	const count = headerBuf.readUInt32LE(8);

	if (count === 0 || sizeOfEntry === 0) { return []; }

	const dataStart = rva + sizeOfHeader;
	const dataBuf = readBytes(fd, dataStart, count * sizeOfEntry);
	const results: ThreadExInfo[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * sizeOfEntry;

		// Ensure we have enough bytes for the full struct
		if (off + 56 > dataBuf.length) { break; }

		results.push({
			threadId: dataBuf.readUInt32LE(off),
			createTime: dataBuf.readBigUInt64LE(off + 16),
			exitTime: dataBuf.readBigUInt64LE(off + 24),
			kernelTime: dataBuf.readBigUInt64LE(off + 32),
			userTime: dataBuf.readBigUInt64LE(off + 40),
			startAddress: dataBuf.readBigUInt64LE(off + 48),
			affinity: sizeOfEntry >= 64 && off + 64 <= dataBuf.length ? dataBuf.readBigUInt64LE(off + 56) : 0n,
		});
	}

	return results;
}

// ---------------------------------------------------------------------------
// ModuleListStream (StreamType 4)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_MODULE_LIST layout:
 *   uint32 NumberOfModules
 *   MINIDUMP_MODULE[NumberOfModules]
 *
 * Each MINIDUMP_MODULE is 108 bytes:
 *   uint64 BaseOfImage
 *   uint32 SizeOfImage
 *   uint32 CheckSum
 *   uint32 TimeDateStamp
 *   uint32 ModuleNameRva    → points to MINIDUMP_STRING
 *   VS_FIXEDFILEINFO VersionInfo (52 bytes)
 *   MINIDUMP_LOCATION_DESCRIPTOR CvRecord (8 bytes)
 *   MINIDUMP_LOCATION_DESCRIPTOR MiscRecord (8 bytes)
 *   uint64 Reserved0
 *   uint64 Reserved1
 */
export function parseModuleListStream(fd: number, rva: number, _size: number): ModuleInfo[] {
	const headerBuf = readBytes(fd, rva, 4);
	const count = headerBuf.readUInt32LE(0);

	if (count === 0) { return []; }

	const MODULE_SIZE = 108;
	const dataBuf = readBytes(fd, rva + 4, count * MODULE_SIZE);
	const modules: ModuleInfo[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * MODULE_SIZE;

		const baseAddress = dataBuf.readBigUInt64LE(off);
		const size = dataBuf.readUInt32LE(off + 8);
		const checksum = dataBuf.readUInt32LE(off + 12);
		const timestamp = dataBuf.readUInt32LE(off + 16);
		const moduleNameRva = dataBuf.readUInt32LE(off + 20);

		// VS_FIXEDFILEINFO starts at off + 24, version at offset 8/12 within it
		const vsMajor = dataBuf.readUInt16LE(off + 24 + 10);
		const vsMinor = dataBuf.readUInt16LE(off + 24 + 8);

		// Read module name from MINIDUMP_STRING
		const name = parseMinidumpString(fd, moduleNameRva);

		modules.push({
			baseAddress,
			size,
			checksum,
			timestamp,
			name,
			versionMajor: vsMajor,
			versionMinor: vsMinor,
		});
	}

	return modules;
}

// ---------------------------------------------------------------------------
// MemoryInfoListStream (StreamType 16)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_MEMORY_INFO_LIST layout:
 *   uint32 SizeOfHeader
 *   uint32 SizeOfEntry
 *   uint64 NumberOfEntries
 *   MINIDUMP_MEMORY_INFO[NumberOfEntries]
 *
 * Each MINIDUMP_MEMORY_INFO is 48 bytes:
 *   uint64 BaseAddress
 *   uint64 AllocationBase
 *   uint32 AllocationProtect
 *   uint32 __alignment1
 *   uint64 RegionSize
 *   uint32 State
 *   uint32 Protect
 *   uint32 Type
 *   uint32 __alignment2
 */
export function parseMemoryInfoListStream(fd: number, rva: number, _size: number): MemoryRegion[] {
	const headerBuf = readBytes(fd, rva, 16);
	const sizeOfHeader = headerBuf.readUInt32LE(0);
	const sizeOfEntry = headerBuf.readUInt32LE(4);
	const count = Number(headerBuf.readBigUInt64LE(8));

	if (count === 0 || sizeOfEntry === 0) { return []; }

	const dataStart = rva + sizeOfHeader;
	const dataBuf = readBytes(fd, dataStart, count * sizeOfEntry);
	const regions: MemoryRegion[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * sizeOfEntry;
		if (off + 48 > dataBuf.length) { break; }

		const state = dataBuf.readUInt32LE(off + 32);
		const protect = dataBuf.readUInt32LE(off + 36);
		const type = dataBuf.readUInt32LE(off + 40);

		const stateName = MEMORY_STATE[state] ?? `0x${state.toString(16)}`;
		const protectName = decodeProtection(protect);
		const typeName = MEMORY_TYPE[type] ?? `0x${type.toString(16)}`;

		// RWX in committed private memory is highly suspicious
		const isSuspicious = (
			state === 0x1000 &&          // MEM_COMMIT
			type === 0x20000 &&          // MEM_PRIVATE
			(protect === 0x40 ||         // PAGE_EXECUTE_READWRITE
				protect === 0x80)           // PAGE_EXECUTE_WRITECOPY
		);

		regions.push({
			baseAddress: dataBuf.readBigUInt64LE(off),
			allocationBase: dataBuf.readBigUInt64LE(off + 8),
			allocationProtect: dataBuf.readUInt32LE(off + 16),
			regionSize: dataBuf.readBigUInt64LE(off + 24),
			state,
			protect,
			type,
			stateName,
			protectName,
			typeName,
			isSuspicious,
		});
	}

	return regions;
}

// ---------------------------------------------------------------------------
// MemoryListStream (StreamType 5)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_MEMORY_LIST:
 *   uint32 NumberOfMemoryRanges
 *   MINIDUMP_MEMORY_DESCRIPTOR[NumberOfMemoryRanges]
 *
 * Each MINIDUMP_MEMORY_DESCRIPTOR is 16 bytes:
 *   uint64 StartOfMemoryRange
 *   uint32 DataSize (of MINIDUMP_LOCATION_DESCRIPTOR)
 *   uint32 Rva     (of MINIDUMP_LOCATION_DESCRIPTOR)
 */
export function parseMemoryListStream(fd: number, rva: number, _size: number): MemoryDescriptor[] {
	const headerBuf = readBytes(fd, rva, 4);
	const count = headerBuf.readUInt32LE(0);

	if (count === 0) { return []; }

	const DESCRIPTOR_SIZE = 16;
	const dataBuf = readBytes(fd, rva + 4, count * DESCRIPTOR_SIZE);
	const descriptors: MemoryDescriptor[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * DESCRIPTOR_SIZE;
		descriptors.push({
			startOfMemoryRange: dataBuf.readBigUInt64LE(off),
			dataSize: dataBuf.readUInt32LE(off + 8),
			rva: dataBuf.readUInt32LE(off + 12),
		});
	}

	return descriptors;
}

// ---------------------------------------------------------------------------
// Memory64ListStream (StreamType 9)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_MEMORY64_LIST:
 *   uint64 NumberOfMemoryRanges
 *   uint64 BaseRva  (base RVA of the first memory range data)
 *   MINIDUMP_MEMORY_DESCRIPTOR64[NumberOfMemoryRanges]
 *
 * Each MINIDUMP_MEMORY_DESCRIPTOR64 is 16 bytes:
 *   uint64 StartOfMemoryRange
 *   uint64 DataSize
 */
export function parseMemory64ListStream(fd: number, rva: number, _size: number): Memory64Descriptor[] {
	const headerBuf = readBytes(fd, rva, 16);
	const count = Number(headerBuf.readBigUInt64LE(0));

	if (count === 0) { return []; }

	const DESCRIPTOR_SIZE = 16;
	const dataBuf = readBytes(fd, rva + 16, count * DESCRIPTOR_SIZE);
	const descriptors: Memory64Descriptor[] = [];

	for (let i = 0; i < count; i++) {
		const off = i * DESCRIPTOR_SIZE;
		if (off + 16 > dataBuf.length) { break; }
		descriptors.push({
			startOfMemoryRange: dataBuf.readBigUInt64LE(off),
			dataSize: dataBuf.readBigUInt64LE(off + 8),
		});
	}

	return descriptors;
}

// ---------------------------------------------------------------------------
// SystemInfoStream (StreamType 7)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_SYSTEM_INFO layout (56 bytes):
 *   uint16 ProcessorArchitecture
 *   uint16 ProcessorLevel
 *   uint16 ProcessorRevision
 *   uint8  NumberOfProcessors
 *   uint8  ProductType
 *   uint32 MajorVersion
 *   uint32 MinorVersion
 *   uint32 BuildNumber
 *   uint32 PlatformId
 *   uint32 CSDVersionRva     → MINIDUMP_STRING
 *   ... (rest is processor-specific)
 */
export function parseSystemInfoStream(fd: number, rva: number, _size: number): SystemInfo {
	const buf = readBytes(fd, rva, 36);

	const arch = buf.readUInt16LE(0);
	const majorVer = buf.readUInt32LE(8);
	const minorVer = buf.readUInt32LE(12);
	const buildNumber = buf.readUInt32LE(16);

	const archName = PROCESSOR_ARCH[arch] ?? `Unknown(${arch})`;
	const verKey = `${majorVer}.${minorVer}`;
	const osName = WINDOWS_VERSION[verKey] ?? `Windows ${verKey}`;

	return {
		processorArchitecture: arch,
		processorArchitectureName: archName,
		processorLevel: buf.readUInt16LE(2),
		processorRevision: buf.readUInt16LE(4),
		numberOfProcessors: buf.readUInt8(6),
		osMajorVersion: majorVer,
		osMinorVersion: minorVer,
		osBuildNumber: buildNumber,
		osPlatformId: buf.readUInt32LE(20),
		osVersionString: `${osName} Build ${buildNumber}`,
	};
}

// ---------------------------------------------------------------------------
// MINIDUMP_STRING
// ---------------------------------------------------------------------------

/**
 * Read a MINIDUMP_STRING at the given RVA.
 *
 * Layout:
 *   uint32 Length (in bytes, NOT characters — UTF-16LE means /2 for char count)
 *   wchar_t[] Buffer (UTF-16LE encoded)
 */
export function parseMinidumpString(fd: number, rva: number): string {
	if (rva === 0) { return '<unknown>'; }

	const lenBuf = readBytes(fd, rva, 4);
	const byteLength = lenBuf.readUInt32LE(0);

	if (byteLength === 0 || byteLength > 32768) {
		return '<invalid>';
	}

	const strBuf = readBytes(fd, rva + 4, byteLength);
	return strBuf.toString('utf16le').replace(/\0+$/, '');
}

// ---------------------------------------------------------------------------
// ExceptionStream (StreamType 6)
// ---------------------------------------------------------------------------

/**
 * MINIDUMP_EXCEPTION_STREAM layout:
 *   uint32 ThreadId
 *   uint32 __alignment
 *   MINIDUMP_EXCEPTION ExceptionRecord:
 *     uint32 ExceptionCode
 *     uint32 ExceptionFlags
 *     uint64 ExceptionRecord (pointer to chained record, usually 0)
 *     uint64 ExceptionAddress
 *     uint32 NumberParameters
 *     uint32 __unusedAlignment
 *     uint64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS=15]
 *   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext (8 bytes)
 */
export function parseExceptionStream(fd: number, rva: number, _size: number): ExceptionInfo {
	// ThreadId (4) + alignment (4) + ExceptionRecord start
	const buf = readBytes(fd, rva, 8 + 32 + 15 * 8);

	const threadId = buf.readUInt32LE(0);
	// ExceptionRecord starts at offset 8
	const exceptionCode = buf.readUInt32LE(8);
	const exceptionFlags = buf.readUInt32LE(12);
	// ExceptionRecord pointer at 16 (uint64, skip)
	const exceptionAddress = buf.readBigUInt64LE(24);
	const numberOfParameters = buf.readUInt32LE(32);
	// alignment at 36

	const paramCount = Math.min(numberOfParameters, 15);
	const parameters: bigint[] = [];
	for (let i = 0; i < paramCount; i++) {
		parameters.push(buf.readBigUInt64LE(40 + i * 8));
	}

	const exceptionName = EXCEPTION_CODES[exceptionCode >>> 0] ?? `0x${(exceptionCode >>> 0).toString(16).toUpperCase()}`;

	return {
		threadId,
		exceptionCode: exceptionCode >>> 0,
		exceptionName,
		exceptionFlags,
		exceptionAddress,
		numberOfParameters: paramCount,
		parameters,
	};
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function decodeProtection(protect: number): string {
	const base = protect & 0xFF;
	const baseName = MEMORY_PROTECTION[base] ?? `0x${protect.toString(16)}`;

	const flags: string[] = [];
	if (protect & 0x100) { flags.push('GUARD'); }
	if (protect & 0x200) { flags.push('NOCACHE'); }
	if (protect & 0x400) { flags.push('WRITECOMBINE'); }

	return flags.length > 0 ? `${baseName}|${flags.join('|')}` : baseName;
}
