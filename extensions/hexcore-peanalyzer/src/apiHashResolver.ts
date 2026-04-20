/*---------------------------------------------------------------------------------------------
 *  HexCore PE Analyzer — API Hash Resolver
 *  v3.8.0-nightly (HEXCORE_DEFEAT Fix #6, Wave 3 expansion)
 *
 *  Detects API hashing (PEB walk + export table iteration) and reverses immediate
 *  constants (uint32 AND uint64) in executable sections against a curated wordlist
 *  of ~400 common Windows APIs + 32 DLL names. Eight hash algorithms are tried:
 *    32-bit: djb2, sdbm, fnv1, fnv1a, ror13, crc32
 *    64-bit: fnv1_64, fnv1a_64
 *
 *  The 64-bit variants cover modern malware (Ashaka Mirage v5 class) that uses
 *  FNV-1a with the standard 64-bit prime 0x100000001B3. The 32-bit pass covers
 *  legacy djb2/ror13/crc32 loaders (Metasploit, Cobalt Strike, older Ashaka).
 *
 *  Pre-filter: only runs when securityIndicators.hasDirectPebAccess is true.
 *  Without that pre-filter the scan would burn CPU on every benign binary.
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { SectionHeader } from './peParser';

export type ApiHashAlgorithm =
	// 32-bit
	| 'djb2' | 'sdbm' | 'fnv1' | 'fnv1a' | 'ror13' | 'crc32'
	// 64-bit
	| 'fnv1_64' | 'fnv1a_64';

export interface ApiHashHit {
	/** File offset where the constant was found */
	offset: number;
	/** The hash constant as hex string — accommodates both uint32 and uint64 */
	constantHex: string;
	/** The numeric constant (number for uint32, string-stringified-bigint for uint64) */
	constant: number | string;
	/** Resolved API name (or DLL name for category='dll') from wordlist */
	apiName: string;
	/** Which algorithm matched */
	algorithm: ApiHashAlgorithm;
	/** Hash width in bits — 32 or 64 */
	width: 32 | 64;
	/** Whether the resolved symbol is an API (function) or DLL name */
	category: 'api' | 'dll';
}

// ---------------------------------------------------------------------------
// Curated WinAPI wordlist — top exports by frequency-of-use in malware
// kernel32 (~50), ntdll (~30), user32 (~15), advapi32 (~15), wininet (~10)
// ---------------------------------------------------------------------------

const WINAPI_WORDLIST: readonly string[] = [
	// kernel32 — process / thread / memory
	'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW',
	'GetProcAddress', 'GetProcAddressForCaller',
	'GetModuleHandleA', 'GetModuleHandleW', 'GetModuleHandleExA', 'GetModuleHandleExW',
	'GetModuleFileNameA', 'GetModuleFileNameW', 'FreeLibrary', 'FreeLibraryAndExitThread',
	'VirtualAlloc', 'VirtualAllocEx', 'VirtualAllocExNuma',
	'VirtualFree', 'VirtualFreeEx', 'VirtualProtect', 'VirtualProtectEx', 'VirtualQuery', 'VirtualQueryEx',
	'VirtualLock', 'VirtualUnlock',
	'HeapAlloc', 'HeapFree', 'HeapCreate', 'HeapDestroy', 'HeapReAlloc', 'HeapSize',
	'HeapValidate', 'HeapWalk', 'GetProcessHeap', 'GetProcessHeaps',
	'CreateFileA', 'CreateFileW', 'CreateFile2', 'OpenFileById',
	'ReadFile', 'ReadFileEx', 'WriteFile', 'WriteFileEx',
	'SetFilePointer', 'SetFilePointerEx', 'GetFileSize', 'GetFileSizeEx',
	'GetFileAttributesA', 'GetFileAttributesW', 'SetFileAttributesA', 'SetFileAttributesW',
	'DeleteFileA', 'DeleteFileW', 'MoveFileA', 'MoveFileW', 'CopyFileA', 'CopyFileW',
	'FindFirstFileA', 'FindFirstFileW', 'FindNextFileA', 'FindNextFileW', 'FindClose',
	'CloseHandle', 'DuplicateHandle', 'GetHandleInformation',
	'CreateProcessA', 'CreateProcessW', 'CreateProcessAsUserA', 'CreateProcessAsUserW',
	'CreateProcessWithTokenW', 'CreateProcessWithLogonW',
	'CreateRemoteThread', 'CreateRemoteThreadEx', 'CreateThread', 'CreateFiberEx',
	'OpenProcess', 'OpenThread', 'TerminateProcess', 'TerminateThread', 'ExitProcess', 'ExitThread',
	'ReadProcessMemory', 'WriteProcessMemory',
	'GetCurrentProcess', 'GetCurrentProcessId', 'GetCurrentThread', 'GetCurrentThreadId',
	'GetProcessId', 'GetThreadId',
	'Sleep', 'SleepEx', 'WaitForSingleObject', 'WaitForSingleObjectEx',
	'WaitForMultipleObjects', 'WaitForMultipleObjectsEx',
	'GetTickCount', 'GetTickCount64', 'QueryPerformanceCounter', 'QueryPerformanceFrequency',
	'GetSystemTime', 'GetLocalTime', 'GetSystemTimeAsFileTime', 'GetSystemTimePreciseAsFileTime',
	'GetComputerNameA', 'GetComputerNameW', 'GetComputerNameExA', 'GetComputerNameExW',
	'GetUserNameA', 'GetUserNameW',
	'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
	'OutputDebugStringA', 'OutputDebugStringW', 'DebugBreak', 'DebugActiveProcess',
	'CreateMutexA', 'CreateMutexW', 'CreateMutexExA', 'CreateMutexExW',
	'OpenMutexA', 'OpenMutexW', 'ReleaseMutex',
	'CreateEventA', 'CreateEventW', 'OpenEventA', 'OpenEventW', 'SetEvent', 'ResetEvent',
	'CreateSemaphoreA', 'CreateSemaphoreW', 'ReleaseSemaphore',
	'GetCommandLineA', 'GetCommandLineW',
	'GetEnvironmentStringsA', 'GetEnvironmentStringsW', 'FreeEnvironmentStringsA', 'FreeEnvironmentStringsW',
	'ExpandEnvironmentStringsA', 'ExpandEnvironmentStringsW', 'GetEnvironmentVariableA', 'GetEnvironmentVariableW',
	'SetEnvironmentVariableA', 'SetEnvironmentVariableW',
	'WinExec', 'ShellExecuteA', 'ShellExecuteW', 'ShellExecuteExA', 'ShellExecuteExW',
	'SetThreadContext', 'GetThreadContext', 'ResumeThread', 'SuspendThread',
	'CreateFileMappingA', 'CreateFileMappingW', 'OpenFileMappingA', 'OpenFileMappingW',
	'MapViewOfFile', 'MapViewOfFileEx', 'UnmapViewOfFile',
	'GlobalAlloc', 'GlobalFree', 'GlobalLock', 'GlobalUnlock', 'GlobalHandle',
	'LocalAlloc', 'LocalFree', 'LocalLock', 'LocalUnlock',
	'GetLastError', 'SetLastError', 'FormatMessageA', 'FormatMessageW',
	'IsWow64Process', 'IsWow64Process2', 'Wow64DisableWow64FsRedirection', 'Wow64RevertWow64FsRedirection',
	'LoadResource', 'LockResource', 'SizeofResource', 'FindResourceA', 'FindResourceW',
	'WriteConsoleA', 'WriteConsoleW', 'GetStdHandle', 'SetConsoleMode',
	'GetSystemDirectoryA', 'GetSystemDirectoryW', 'GetWindowsDirectoryA', 'GetWindowsDirectoryW',
	'GetTempPathA', 'GetTempPathW', 'GetTempFileNameA', 'GetTempFileNameW',
	'DeviceIoControl',

	// ntdll
	'NtCreateFile', 'NtOpenFile', 'NtReadFile', 'NtWriteFile', 'NtClose',
	'NtAllocateVirtualMemory', 'NtFreeVirtualMemory', 'NtProtectVirtualMemory',
	'NtReadVirtualMemory', 'NtWriteVirtualMemory', 'NtQueryVirtualMemory',
	'NtQuerySystemInformation', 'NtQueryInformationProcess', 'NtQueryInformationThread',
	'NtSetInformationProcess', 'NtSetInformationThread',
	'NtCreateThreadEx', 'NtCreateThread', 'NtCreateProcess', 'NtCreateProcessEx',
	'NtCreateSection', 'NtMapViewOfSection', 'NtUnmapViewOfSection',
	'NtOpenProcess', 'NtOpenThread', 'NtTerminateProcess', 'NtTerminateThread',
	'NtSuspendThread', 'NtResumeThread',
	'NtQueueApcThread', 'NtQueueApcThreadEx', 'NtDelayExecution',
	'NtWaitForSingleObject', 'NtWaitForMultipleObjects',
	'NtCreateKey', 'NtOpenKey', 'NtSetValueKey', 'NtQueryValueKey', 'NtEnumerateKey', 'NtDeleteKey',
	'NtCreateEvent', 'NtCreateMutant', 'NtCreateSemaphore',
	'NtSetSystemInformation', 'NtSystemDebugControl',
	'NtRaiseException', 'NtRaiseHardError', 'NtContinue',
	'NtFlushInstructionCache',
	'RtlMoveMemory', 'RtlZeroMemory', 'RtlCompareMemory', 'RtlFillMemory',
	'RtlGetVersion', 'RtlEqualUnicodeString', 'RtlInitUnicodeString', 'RtlInitAnsiString',
	'RtlUnicodeStringToAnsiString', 'RtlAnsiStringToUnicodeString',
	'RtlAddFunctionTable', 'RtlDeleteFunctionTable',
	'RtlAllocateHeap', 'RtlFreeHeap', 'RtlReAllocateHeap',
	'RtlDecompressBuffer', 'RtlCompressBuffer',
	'ZwOpenProcess', 'ZwReadVirtualMemory', 'ZwWriteVirtualMemory',
	'ZwAllocateVirtualMemory', 'ZwProtectVirtualMemory', 'ZwCreateThreadEx',
	'LdrLoadDll', 'LdrUnloadDll', 'LdrGetProcedureAddress', 'LdrGetDllHandle',
	'LdrFindResource_U', 'LdrAccessResource',
	'DbgUiConnectToDbg', 'DbgUiDebugActiveProcess', 'DbgUiStopDebugging',

	// user32
	'MessageBoxA', 'MessageBoxW', 'MessageBoxExA', 'MessageBoxExW',
	'FindWindowA', 'FindWindowW', 'FindWindowExA', 'FindWindowExW',
	'GetForegroundWindow', 'SetForegroundWindow', 'GetActiveWindow',
	'GetWindowTextA', 'GetWindowTextW', 'GetWindowTextLengthA', 'GetWindowTextLengthW',
	'SetWindowsHookExA', 'SetWindowsHookExW', 'UnhookWindowsHookEx', 'CallNextHookEx',
	'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'GetKeyboardLayout',
	'EnumWindows', 'EnumChildWindows', 'EnumDesktopWindows',
	'GetWindowThreadProcessId', 'IsWindowVisible', 'IsWindow',
	'ShowWindow', 'UpdateWindow', 'SetWindowPos',
	'SendMessageA', 'SendMessageW', 'PostMessageA', 'PostMessageW', 'PeekMessageA', 'PeekMessageW',
	'GetMessageA', 'GetMessageW', 'DispatchMessageA', 'DispatchMessageW',
	'BlockInput', 'mouse_event', 'keybd_event', 'SendInput',
	'ExitWindowsEx',

	// advapi32
	'RegOpenKeyA', 'RegOpenKeyW', 'RegOpenKeyExA', 'RegOpenKeyExW',
	'RegCreateKeyA', 'RegCreateKeyW', 'RegCreateKeyExA', 'RegCreateKeyExW',
	'RegSetValueA', 'RegSetValueW', 'RegSetValueExA', 'RegSetValueExW',
	'RegQueryValueA', 'RegQueryValueW', 'RegQueryValueExA', 'RegQueryValueExW',
	'RegDeleteKeyA', 'RegDeleteKeyW', 'RegDeleteKeyExA', 'RegDeleteKeyExW',
	'RegDeleteValueA', 'RegDeleteValueW', 'RegCloseKey',
	'RegEnumKeyA', 'RegEnumKeyW', 'RegEnumKeyExA', 'RegEnumKeyExW',
	'RegEnumValueA', 'RegEnumValueW',
	'OpenProcessToken', 'OpenThreadToken', 'GetTokenInformation', 'SetTokenInformation',
	'AdjustTokenPrivileges', 'AdjustTokenGroups',
	'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'LookupPrivilegeNameA',
	'LookupAccountSidA', 'LookupAccountSidW', 'LookupAccountNameA', 'LookupAccountNameW',
	'CryptAcquireContextA', 'CryptAcquireContextW', 'CryptReleaseContext',
	'CryptCreateHash', 'CryptDestroyHash', 'CryptHashData', 'CryptGetHashParam',
	'CryptEncrypt', 'CryptDecrypt', 'CryptImportKey', 'CryptExportKey', 'CryptGenKey', 'CryptDestroyKey',
	'CreateServiceA', 'CreateServiceW', 'OpenServiceA', 'OpenServiceW',
	'OpenSCManagerA', 'OpenSCManagerW', 'CloseServiceHandle',
	'StartServiceA', 'StartServiceW', 'ControlService', 'DeleteService',
	'QueryServiceStatus', 'QueryServiceConfigA', 'QueryServiceConfigW', 'ChangeServiceConfigA', 'ChangeServiceConfigW',
	'RegisterServiceCtrlHandlerA', 'RegisterServiceCtrlHandlerW',
	'ImpersonateLoggedOnUser', 'RevertToSelf',
	'LogonUserA', 'LogonUserW', 'LogonUserExA', 'LogonUserExW',

	// wininet / winhttp / ws2_32
	'InternetOpenA', 'InternetOpenW', 'InternetConnectA', 'InternetConnectW',
	'InternetOpenUrlA', 'InternetOpenUrlW', 'InternetReadFile', 'InternetWriteFile',
	'InternetCloseHandle', 'InternetSetOptionA', 'InternetSetOptionW',
	'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW',
	'HttpQueryInfoA', 'HttpQueryInfoW', 'HttpAddRequestHeadersA', 'HttpAddRequestHeadersW',
	'InternetCrackUrlA', 'InternetCrackUrlW',
	'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest',
	'WinHttpReceiveResponse', 'WinHttpQueryHeaders', 'WinHttpReadData', 'WinHttpWriteData',
	'WinHttpCloseHandle', 'WinHttpSetOption',
	'WSAStartup', 'WSACleanup', 'WSAGetLastError',
	'socket', 'bind', 'listen', 'accept', 'connect', 'send', 'sendto', 'recv', 'recvfrom',
	'closesocket', 'shutdown', 'gethostbyname', 'gethostname', 'getaddrinfo', 'freeaddrinfo',
	'inet_addr', 'inet_ntoa', 'ntohs', 'htons', 'ntohl', 'htonl',
	'select', 'ioctlsocket', 'setsockopt', 'getsockopt',

	// crypt32 / bcrypt
	'CryptStringToBinaryA', 'CryptStringToBinaryW', 'CryptBinaryToStringA', 'CryptBinaryToStringW',
	'CryptProtectData', 'CryptUnprotectData', 'CryptProtectMemory', 'CryptUnprotectMemory',
	'CertOpenStore', 'CertCloseStore', 'CertFindCertificateInStore',
	'BCryptOpenAlgorithmProvider', 'BCryptCloseAlgorithmProvider',
	'BCryptGenerateSymmetricKey', 'BCryptEncrypt', 'BCryptDecrypt', 'BCryptHash',

	// psapi / dbghelp
	'EnumProcesses', 'EnumProcessModules', 'EnumProcessModulesEx',
	'GetModuleBaseNameA', 'GetModuleBaseNameW', 'GetModuleFileNameExA', 'GetModuleFileNameExW',
	'GetProcessImageFileNameA', 'GetProcessImageFileNameW',
	'GetMappedFileNameA', 'GetMappedFileNameW',
	'MiniDumpWriteDump', 'SymInitialize', 'SymCleanup', 'SymFromAddr', 'SymGetModuleInfo64',

	// shell32 / shlwapi
	'SHGetFolderPathA', 'SHGetFolderPathW', 'SHGetKnownFolderPath',
	'SHGetSpecialFolderPathA', 'SHGetSpecialFolderPathW',
	'PathFileExistsA', 'PathFileExistsW', 'PathCombineA', 'PathCombineW',
	'PathAppendA', 'PathAppendW', 'PathFindFileNameA', 'PathFindFileNameW',

	// tool helper
	'CreateToolhelp32Snapshot', 'Process32First', 'Process32Next',
	'Process32FirstW', 'Process32NextW', 'Module32First', 'Module32Next',
	'Module32FirstW', 'Module32NextW', 'Thread32First', 'Thread32Next',
];

// Curated DLL name wordlist — malware commonly hashes DLL names AND API names
// to locate modules in the InMemoryOrderModuleList. Include both cased and
// lowercased variants since some hashers lowercase the incoming name and some
// don't.
const DLL_WORDLIST: readonly string[] = [
	'ntdll.dll', 'kernel32.dll', 'kernelbase.dll', 'user32.dll', 'advapi32.dll',
	'shell32.dll', 'shlwapi.dll', 'ole32.dll', 'oleaut32.dll', 'gdi32.dll',
	'msvcrt.dll', 'ucrtbase.dll', 'vcruntime140.dll', 'msvcp140.dll',
	'wininet.dll', 'winhttp.dll', 'ws2_32.dll', 'mswsock.dll',
	'crypt32.dll', 'bcrypt.dll', 'ncrypt.dll', 'cryptbase.dll',
	'psapi.dll', 'dbghelp.dll', 'version.dll', 'iphlpapi.dll',
	'urlmon.dll', 'wtsapi32.dll', 'netapi32.dll', 'secur32.dll',
	'comctl32.dll', 'comdlg32.dll', 'rpcrt4.dll',
	// Without extension (some hashers strip .dll)
	'ntdll', 'kernel32', 'kernelbase', 'user32', 'advapi32', 'shell32',
];

// ---------------------------------------------------------------------------
// Hash algorithms (string → uint32)
// ---------------------------------------------------------------------------

function djb2(s: string): number {
	let h = 5381;
	for (let i = 0; i < s.length; i++) {
		h = ((h * 33) + s.charCodeAt(i)) >>> 0;
	}
	return h >>> 0;
}

function sdbm(s: string): number {
	let h = 0;
	for (let i = 0; i < s.length; i++) {
		h = ((h * 65599) + s.charCodeAt(i)) >>> 0;
	}
	return h >>> 0;
}

function fnv1(s: string): number {
	let h = 2166136261;
	for (let i = 0; i < s.length; i++) {
		h = Math.imul(h, 16777619) >>> 0;
		h = (h ^ s.charCodeAt(i)) >>> 0;
	}
	return h >>> 0;
}

function fnv1a(s: string): number {
	let h = 2166136261;
	for (let i = 0; i < s.length; i++) {
		h = (h ^ s.charCodeAt(i)) >>> 0;
		h = Math.imul(h, 16777619) >>> 0;
	}
	return h >>> 0;
}

function ror13(s: string): number {
	let h = 0;
	for (let i = 0; i < s.length; i++) {
		const lo = (h << 19) >>> 0;
		const hi = h >>> 13;
		h = ((lo | hi) + s.charCodeAt(i)) >>> 0;
	}
	return h >>> 0;
}

// IEEE 802.3 CRC-32 (polynomial 0xEDB88320, reflected)
const CRC32_TABLE = (() => {
	const table = new Uint32Array(256);
	for (let i = 0; i < 256; i++) {
		let c = i;
		for (let k = 0; k < 8; k++) {
			c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
		}
		table[i] = c >>> 0;
	}
	return table;
})();

function crc32(s: string): number {
	let h = 0xFFFFFFFF;
	for (let i = 0; i < s.length; i++) {
		h = (CRC32_TABLE[(h ^ s.charCodeAt(i)) & 0xFF] ^ (h >>> 8)) >>> 0;
	}
	return (h ^ 0xFFFFFFFF) >>> 0;
}

// ---------------------------------------------------------------------------
// 64-bit hash algorithms — used by modern malware (Ashaka Mirage v5 class,
// Cobalt Strike custom beacons) that prefer the FNV-1a 64-bit prime for
// reduced collision risk and larger hash-constant immediate in the binary.
// ---------------------------------------------------------------------------

const FNV_OFFSET_BASIS_64 = 0xCBF29CE484222325n;
const FNV_PRIME_64 = 0x100000001B3n;
const MASK_64 = 0xFFFFFFFFFFFFFFFFn;

function fnv1a_64(s: string): bigint {
	let h = FNV_OFFSET_BASIS_64;
	for (let i = 0; i < s.length; i++) {
		h = (h ^ BigInt(s.charCodeAt(i))) & MASK_64;
		h = (h * FNV_PRIME_64) & MASK_64;
	}
	return h;
}

function fnv1_64(s: string): bigint {
	let h = FNV_OFFSET_BASIS_64;
	for (let i = 0; i < s.length; i++) {
		h = (h * FNV_PRIME_64) & MASK_64;
		h = (h ^ BigInt(s.charCodeAt(i))) & MASK_64;
	}
	return h;
}

// ---------------------------------------------------------------------------
// Pre-compute hash → API name maps at module load time
// ~120 APIs × 6 algorithms = ~720 entries. Lookup is O(1).
// ---------------------------------------------------------------------------

// Value = {name, category} so downstream consumers can distinguish API hits
// from DLL hits even when the table is merged.
type HashEntry = { name: string; category: 'api' | 'dll' };

const HASH_TABLES_32: Record<'djb2'|'sdbm'|'fnv1'|'fnv1a'|'ror13'|'crc32', Map<number, HashEntry>> = {
	djb2: new Map(),
	sdbm: new Map(),
	fnv1: new Map(),
	fnv1a: new Map(),
	ror13: new Map(),
	crc32: new Map(),
};

const HASH_TABLES_64: Record<'fnv1_64'|'fnv1a_64', Map<bigint, HashEntry>> = {
	fnv1_64: new Map(),
	fnv1a_64: new Map(),
};

const HASH_FUNCTIONS_32: Record<keyof typeof HASH_TABLES_32, (s: string) => number> = {
	djb2, sdbm, fnv1, fnv1a, ror13, crc32,
};

const HASH_FUNCTIONS_64: Record<keyof typeof HASH_TABLES_64, (s: string) => bigint> = {
	fnv1_64, fnv1a_64,
};

// Populate 32-bit tables with both case variants + Unicode variants.
// Malware often lowercases names before hashing (MSF-style) or uses UTF-16
// directly (some Cobalt Strike variants). We index both case and ascii-byte
// variants so we catch either.
for (const list of [WINAPI_WORDLIST, DLL_WORDLIST]) {
	const category: 'api' | 'dll' = list === DLL_WORDLIST ? 'dll' : 'api';
	for (const name of list) {
		const variants = Array.from(new Set([name, name.toLowerCase(), name.toUpperCase()]));
		for (const variant of variants) {
			for (const algo of Object.keys(HASH_FUNCTIONS_32) as (keyof typeof HASH_TABLES_32)[]) {
				const h = HASH_FUNCTIONS_32[algo](variant);
				if (!HASH_TABLES_32[algo].has(h)) {
					HASH_TABLES_32[algo].set(h, { name, category });
				}
			}
			for (const algo of Object.keys(HASH_FUNCTIONS_64) as (keyof typeof HASH_TABLES_64)[]) {
				const h = HASH_FUNCTIONS_64[algo](variant);
				if (!HASH_TABLES_64[algo].has(h)) {
					HASH_TABLES_64[algo].set(h, { name, category });
				}
			}
		}
	}
}

// Sentinel constants that are NOT hashes — common immediates we should skip
// to avoid false positives. PE magic, common allocation sizes, etc.
const SENTINEL_CONSTANTS = new Set<number>([
	0x00000000, 0xFFFFFFFF, 0x00004550, 0x00005A4D, 0x00010000,
	0x80000000, 0x40000000, 0x20000000, 0x10000000,
	0x00001000, 0x00002000, 0x00004000, 0x00008000,
]);

/**
 * Scan executable sections for 4-byte AND 8-byte immediate constants and
 * try each against every algorithm × every API/DLL. Returns matches.
 *
 * Should only be called when `securityIndicators.hasDirectPebAccess` is true,
 * otherwise this burns CPU on every benign binary with no benefit.
 *
 * Scan strategy:
 *   - Step by 1 byte (not 4) — hash constants live inside `mov reg, imm32`
 *     instructions which can begin at any byte offset
 *   - uint32 scan: reads 4-byte LE, checks 32-bit tables
 *   - uint64 scan: reads 8-byte LE, checks 64-bit tables (v5 Ashaka FNV-1a)
 *   - Deduplicates on (offset, width) so a 4-byte prefix inside an 8-byte
 *     constant isn't reported twice
 */
export function resolveApiHashes(buffer: Buffer, sections: SectionHeader[]): ApiHashHit[] {
	const hits: ApiHashHit[] = [];
	const seenKeys = new Set<string>();

	for (const section of sections) {
		const isExec =
			section.characteristics?.includes('EXECUTE') ||
			section.characteristics?.includes('CODE');
		if (!isExec) { continue; }

		const start = section.pointerToRawData;
		const end = Math.min(start + section.sizeOfRawData, buffer.length);

		for (let i = start; i + 4 <= end; i++) {
			// --- 32-bit pass ---
			const c32 = buffer.readUInt32LE(i);
			if (c32 >= 0x100 && !SENTINEL_CONSTANTS.has(c32)) {
				const key32 = `32:${c32}`;
				if (!seenKeys.has(key32)) {
					for (const algo of Object.keys(HASH_TABLES_32) as (keyof typeof HASH_TABLES_32)[]) {
						const entry = HASH_TABLES_32[algo].get(c32);
						if (entry) {
							hits.push({
								offset: i,
								constant: c32,
								constantHex: '0x' + c32.toString(16).toUpperCase().padStart(8, '0'),
								apiName: entry.name,
								algorithm: algo,
								width: 32,
								category: entry.category,
							});
							seenKeys.add(key32);
							break;
						}
					}
				}
			}

			// --- 64-bit pass ---
			if (i + 8 <= end) {
				const c64 = buffer.readBigUInt64LE(i);
				// Skip low/sentinel values that can't realistically be hash outputs
				if (c64 >= 0x10000n && c64 !== 0xFFFFFFFFFFFFFFFFn) {
					const key64 = `64:${c64.toString(16)}`;
					if (!seenKeys.has(key64)) {
						for (const algo of Object.keys(HASH_TABLES_64) as (keyof typeof HASH_TABLES_64)[]) {
							const entry = HASH_TABLES_64[algo].get(c64);
							if (entry) {
								hits.push({
									offset: i,
									constant: c64.toString(),
									constantHex: '0x' + c64.toString(16).toUpperCase().padStart(16, '0'),
									apiName: entry.name,
									algorithm: algo,
									width: 64,
									category: entry.category,
								});
								seenKeys.add(key64);
								break;
							}
						}
					}
				}
			}
		}
	}

	return hits;
}

/**
 * Test helper: compute hash with a specific algorithm. Exported for unit tests.
 * Returns `number` for 32-bit algorithms and `bigint` for 64-bit algorithms.
 */
export function hashApi(name: string, algo: ApiHashAlgorithm): number | bigint {
	if (algo in HASH_FUNCTIONS_32) {
		return HASH_FUNCTIONS_32[algo as keyof typeof HASH_FUNCTIONS_32](name);
	}
	return HASH_FUNCTIONS_64[algo as keyof typeof HASH_FUNCTIONS_64](name);
}

/**
 * Aggregate statistics for a resolved-hashes scan. Handy for pipeline reports.
 */
export function summarizeHashHits(hits: ApiHashHit[]): {
	total: number;
	byAlgorithm: Record<string, number>;
	byCategory: { api: number; dll: number };
	byWidth: { '32': number; '64': number };
	topResolved: Array<{ name: string; count: number }>;
} {
	const byAlgorithm: Record<string, number> = {};
	const byCategory = { api: 0, dll: 0 };
	const byWidth = { '32': 0, '64': 0 };
	const nameCounts = new Map<string, number>();

	for (const h of hits) {
		byAlgorithm[h.algorithm] = (byAlgorithm[h.algorithm] ?? 0) + 1;
		byCategory[h.category]++;
		byWidth[String(h.width) as '32' | '64']++;
		nameCounts.set(h.apiName, (nameCounts.get(h.apiName) ?? 0) + 1);
	}

	const topResolved = [...nameCounts.entries()]
		.map(([name, count]) => ({ name, count }))
		.sort((a, b) => b.count - a.count)
		.slice(0, 10);

	return { total: hits.length, byAlgorithm, byCategory, byWidth, topResolved };
}
