/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Windows API Hooks
 *  Emulates ~25 common Windows APIs for PE execution in Unicorn
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import { UnicornWrapper, ArchitectureType } from './unicornWrapper';
import { MemoryManager } from './memoryManager';
import { TraceManager, TraceEntry } from './traceManager';

export interface ApiCallLog {
	dll: string;
	name: string;
	args: bigint[];
	returnValue: bigint;
	timestamp: number;
	/** Arguments formatted as hex/decimal strings for trace display */
	arguments: string[];
	/** Program counter address at the point of the call */
	pcAddress: bigint;
	callingConvention?: 'win64' | 'stdcall' | 'cdecl' | 'unknown';
	stackBytesPopped?: number;
	semanticLevel?: 'implemented' | 'modeled' | 'return-only' | 'unsupported';
	signatureSource?: 'win64-abi' | 'win32-signature-table' | 'decorated-name' | 'unknown';
}

export interface WinApiCallContract {
	argumentCount: number;
	callingConvention: 'win64' | 'stdcall' | 'cdecl' | 'unknown';
	stackBytesPopped: number;
	semanticLevel: 'implemented' | 'modeled' | 'return-only' | 'unsupported';
	signatureSource: 'win64-abi' | 'win32-signature-table' | 'decorated-name' | 'unknown';
}

type ApiHandler = (args: bigint[]) => bigint;

const API_CALL_LOG_MAX_ENTRIES = 20000;
const CRT_MEMORY_OPERATION_MAX_BYTES = 64 * 1024 * 1024;
const CRT_STRING_MAX_BYTES = 16 * 1024 * 1024;

const WIN32_STDCALL_ARGUMENT_COUNTS: Readonly<Record<string, number>> = {
	VirtualAlloc: 4, VirtualFree: 3, VirtualProtect: 4,
	HeapCreate: 3, HeapAlloc: 3, HeapFree: 3, GetProcessHeap: 0,
	GetModuleHandleA: 1, GetModuleHandleW: 1, LoadLibraryA: 1, LoadLibraryW: 1,
	LoadLibraryExA: 3, LoadLibraryExW: 3, GetProcAddress: 2,
	GetCurrentProcess: 0, GetCurrentProcessId: 0, GetCurrentThreadId: 0,
	IsDebuggerPresent: 0, CheckRemoteDebuggerPresent: 2, GetThreadContext: 2,
	RaiseException: 4, InitializeCriticalSection: 1, InitializeCriticalSectionAndSpinCount: 2,
	InitializeCriticalSectionEx: 3, EnterCriticalSection: 1, LeaveCriticalSection: 1,
	DeleteCriticalSection: 1, TryEnterCriticalSection: 1,
	TlsAlloc: 0, TlsSetValue: 2, TlsGetValue: 1, TlsFree: 1,
	FlsAlloc: 1, FlsSetValue: 2, FlsGetValue: 1, FlsFree: 1,
	GetLastError: 0, SetLastError: 1, GetTickCount: 0, GetTickCount64: 0, Sleep: 1,
	QueryPerformanceCounter: 1, QueryPerformanceFrequency: 1, GetSystemTimeAsFileTime: 1,
	GetSystemInfo: 1, GetNativeSystemInfo: 1, K32GetProcessMemoryInfo: 3, GetProcessMemoryInfo: 3,
	CreateFileA: 7, CreateFileW: 7, ReadFile: 5, WriteFile: 5, CloseHandle: 1,
	lstrlenA: 1, lstrcpyA: 2, GetStdHandle: 1, WriteConsoleA: 5, WriteConsoleW: 5,
	GetCommandLineA: 0, GetCommandLineW: 0, GetStartupInfoA: 1, GetStartupInfoW: 1,
	WideCharToMultiByte: 8, MultiByteToWideChar: 6, ExitProcess: 1,
	ShellExecuteA: 6, ShellExecuteW: 6, ShellExecuteExA: 1, ShellExecuteExW: 1,
	RegOpenKeyA: 3, RegOpenKeyW: 3, RegOpenKeyExA: 5, RegOpenKeyExW: 5,
	RegCloseKey: 1, RegQueryValueExA: 6, RegQueryValueExW: 6,
	GetComputerNameA: 2, GetComputerNameW: 2,
	BCryptOpenAlgorithmProvider: 4, BCryptSetProperty: 5, BCryptCreateHash: 7,
	BCryptHashData: 4, BCryptFinishHash: 4, BCryptDestroyHash: 1,
	BCryptCloseAlgorithmProvider: 2, BCryptGenerateSymmetricKey: 7, BCryptDecrypt: 10,
};

export function resolveWinApiCallContract(
	architecture: ArchitectureType,
	name: string,
	hasHandler: boolean,
	semanticLevel?: WinApiCallContract['semanticLevel'],
): WinApiCallContract {
	const registeredLevel = semanticLevel ?? (hasHandler ? 'modeled' : 'unsupported');
	if (architecture === 'x64') {
		return {
			argumentCount: WIN32_STDCALL_ARGUMENT_COUNTS[name] ?? 8,
			callingConvention: 'win64',
			stackBytesPopped: 0,
			semanticLevel: registeredLevel,
			signatureSource: 'win64-abi',
		};
	}
	const decorated = /@(\d+)$/.exec(name);
	if (decorated) {
		const stackBytesPopped = Number(decorated[1]);
		return {
			argumentCount: stackBytesPopped / 4,
			callingConvention: 'stdcall',
			stackBytesPopped,
			semanticLevel: registeredLevel,
			signatureSource: 'decorated-name',
		};
	}
	const argumentCount = WIN32_STDCALL_ARGUMENT_COUNTS[name];
	if (argumentCount !== undefined) {
		return {
			argumentCount,
			callingConvention: 'stdcall',
			stackBytesPopped: argumentCount * 4,
			semanticLevel: registeredLevel,
			signatureSource: 'win32-signature-table',
		};
	}
	return {
		argumentCount: 8,
		callingConvention: 'unknown',
		stackBytesPopped: 0,
		semanticLevel: registeredLevel,
		signatureSource: 'unknown',
	};
}

export function decryptAesCbc(input: Buffer, key: Buffer, iv: Buffer, blockPadding: boolean): Buffer {
	if (![16, 24, 32].includes(key.length) || iv.length !== 16 || input.length % 16 !== 0) {
		throw new Error('AES-CBC requires a 128/192/256-bit key, 16-byte IV, and block-aligned input.');
	}
	const decipher = crypto.createDecipheriv(`aes-${key.length * 8}-cbc`, key, iv);
	decipher.setAutoPadding(blockPadding);
	return Buffer.concat([decipher.update(input), decipher.final()]);
}

export class WinApiHooks {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private architecture: ArchitectureType;
	private handlers: Map<string, ApiHandler> = new Map();
	private semanticLevels: Map<string, WinApiCallContract['semanticLevel']> = new Map();
	private callLog: ApiCallLog[] = [];
	private lastCall: ApiCallLog | undefined;
	private lastError: number = 0;
	private tickCount: number = 0;
	private performanceCounter: bigint = 0n;
	private nextHandle: number = 0x100;
	private nextTlsIndex: number = 0;
	private tlsValues: Map<number, bigint> = new Map();
	private commandLineAPtr: bigint = 0n;
	private commandLineWPtr: bigint = 0n;
	private winMainCommandLineWPtr: bigint = 0n;
	private cngAlgorithms: Map<bigint, { algorithm: 'SHA256' | 'AES'; chainingMode: 'CBC' }> = new Map();
	private cngHashes: Map<bigint, { algorithm: 'SHA256'; chunks: Buffer[] }> = new Map();
	private cngKeys: Map<bigint, { algorithm: 'AES'; key: Buffer; chainingMode: 'CBC' }> = new Map();

	// v3.8.0-nightly: CRT data block (HEXCORE_DEFEAT Fix #3). MSVC CRT init
	// calls __p___argv / __p___argc / _get_initial_narrow_environment to obtain
	// live pointers to argv/argc/environ. Without real backing memory, the
	// unstubbed defaults return 0n and the CRT dereferences NULL → crash at
	// ~instruction 239 (RIP 0x1400027fb observed).
	private crtDataPtr: bigint = 0n;
	private crtArgvPtr: bigint = 0n;
	private crtWArgvPtr: bigint = 0n;
	private crtEnvironPtr: bigint = 0n;
	private crtWEnvironPtr: bigint = 0n;
	private readonly crtArgcValue: number = 1;

	// Module handle tracking
	private moduleHandles: Map<string, bigint> = new Map();
	private imageBase: bigint = 0x400000n;

	// v3.8.0-nightly: captured stdout. Populated by the MSVCP140 iostream
	// stubs (sputn, operator<<(const char*)) so pipelines can observe what
	// `std::cout`/`std::cerr` printed during emulation. Retrieved via
	// getStdoutBuffer(); merged into DebugEngine.getStdoutBuffer() output.
	private stdoutBuffer: string = '';

	/** Optional TraceManager for centralized trace recording */
	private traceManager: TraceManager | null = null;

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager, arch: ArchitectureType) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
		this.architecture = arch;
		// FIX: `Date.now() & 0xFFFFFFFF` does a SIGNED int32 mask in JS — when the
		// high bit is set, the result is a negative Number. Use `>>> 0` to coerce
		// to unsigned uint32. Without this, downstream `BigInt(this.tickCount)`
		// produces a negative BigInt and `Buffer.writeBigUInt64LE` throws
		// `"value out of range"` (HEXCORE_DEFEAT_RESULTS.md FAIL 4).
		this.tickCount = (Date.now() & 0xFFFFFFFF) >>> 0;
		this.performanceCounter = BigInt(this.tickCount) * 10000n;
		this.registerAllHandlers();
	}

	/**
	 * Set the image base for GetModuleHandle(NULL)
	 */
	setImageBase(base: bigint): void {
		this.imageBase = base;
	}

	/**
	 * Set the TraceManager instance for centralized trace recording.
	 */
	setTraceManager(manager: TraceManager): void {
		this.traceManager = manager;
	}

	/**
	 * Handle an API call at a stub address.
	 * Reads arguments, calls handler, sets return value, pops return address.
	 */
	handleCall(dll: string, name: string): bigint {
		const key = `${dll.toLowerCase()}!${name}`;
		const keyNoExt = `${dll.toLowerCase().replace('.dll', '')}!${name}`;

		const handler = this.handlers.get(key) || this.handlers.get(keyNoExt);
		const semanticLevel = this.semanticLevels.get(key) || this.semanticLevels.get(keyNoExt);
		const contract = resolveWinApiCallContract(this.architecture, name, handler !== undefined, semanticLevel);

		// Read arguments based on calling convention.
		// A few Win32 APIs we emulate here use 7-8 parameters.
		const args = this.readArguments(contract.argumentCount);

		let returnValue = 0n;
		if (handler) {
			returnValue = handler(args);
		} else {
			// Unknown API - return 0 and log it
			console.log(`Unhandled API: ${dll}!${name}`);
		}

		// Capture PC address from current instruction pointer
		let pcAddress = 0n;
		try {
			if (this.architecture === 'x64') {
				const regs = this.emulator.getRegistersX64();
				pcAddress = regs.rip;
			} else {
				const regs = this.emulator.getRegistersX86();
				pcAddress = BigInt(regs.eip);
			}
		} catch {
			// If we can't read PC, leave as 0
		}

		// Format arguments as hex strings for trace display
		const formattedArgs = args.map(a => '0x' + a.toString(16));
		const timestamp = Date.now();

		this.recordCallLog({
			dll,
			name,
			args,
			returnValue,
			timestamp,
			arguments: formattedArgs,
			pcAddress,
			callingConvention: contract.callingConvention,
			stackBytesPopped: contract.stackBytesPopped,
			semanticLevel: contract.semanticLevel,
			signatureSource: contract.signatureSource,
		});

		// Notify TraceManager if available
		if (this.traceManager) {
			const entry: TraceEntry = {
				functionName: name,
				library: dll,
				arguments: formattedArgs,
				returnValue: '0x' + returnValue.toString(16),
				pcAddress: '0x' + pcAddress.toString(16),
				timestamp,
				callingConvention: contract.callingConvention,
				stackBytesPopped: contract.stackBytesPopped,
				semanticLevel: contract.semanticLevel,
				signatureSource: contract.signatureSource,
			};
			this.traceManager.record(entry);
		}

		return returnValue;
	}

	/**
	 * Read function arguments based on calling convention
	 */
	private readArguments(count: number): bigint[] {
		const args: bigint[] = [];

		if (this.architecture === 'x64') {
			// x64 Windows: RCX, RDX, R8, R9, then stack
			const regs = this.emulator.getRegistersX64();
			args.push(regs.rcx, regs.rdx, regs.r8, regs.r9);

			// Read remaining args from stack (RSP + 0x28, +0x30, ...)
			for (let i = 4; i < count; i++) {
				const stackOffset = regs.rsp + BigInt(0x28 + (i - 4) * 8);
				try {
					const buf = this.emulator.readMemorySync(stackOffset, 8);
					args.push(buf.readBigUInt64LE());
				} catch {
					args.push(0n);
				}
			}
		} else {
			// x86 stdcall: all args on stack (ESP + 4, +8, +12, ...)
			const regs = this.emulator.getRegistersX86();
			const esp = BigInt(regs.esp);
			for (let i = 0; i < count; i++) {
				const stackOffset = esp + BigInt(4 + i * 4);
				try {
					const buf = this.emulator.readMemorySync(stackOffset, 4);
					args.push(BigInt(buf.readUInt32LE()));
				} catch {
					args.push(0n);
				}
			}
		}

		return args;
	}

	/**
	 * Read a null-terminated ASCII string from emulator memory
	 */
	private readStringA(address: bigint): string {
		if (address === 0n) {
			return '';
		}
		try {
			const buf = this.emulator.readMemorySync(address, 256);
			const nullIdx = buf.indexOf(0);
			return buf.toString('ascii', 0, nullIdx >= 0 ? nullIdx : 256);
		} catch {
			return '';
		}
	}

	/**
	 * Read a null-terminated wide (UTF-16LE) string from emulator memory
	 */
	private readStringW(address: bigint): string {
		if (address === 0n) {
			return '';
		}
		try {
			const buf = this.emulator.readMemorySync(address, 512);
			let end = 0;
			for (let i = 0; i < buf.length - 1; i += 2) {
				if (buf[i] === 0 && buf[i + 1] === 0) {
					end = i;
					break;
				}
			}
			return buf.toString('utf16le', 0, end || buf.length);
		} catch {
			return '';
		}
	}

	/**
	 * Write a null-terminated ASCII string to emulator memory
	 */
	private writeStringA(address: bigint, str: string): void {
		const buf = Buffer.alloc(str.length + 1);
		buf.write(str, 'ascii');
		buf[str.length] = 0;
		this.emulator.writeMemorySync(address, buf);
	}

	/**
	 * Write a null-terminated UTF-16LE string to emulator memory
	 */
	private writeStringW(address: bigint, str: string): void {
		const buf = Buffer.from(str + '\0', 'utf16le');
		this.emulator.writeMemorySync(address, buf);
	}

	private ensureAsciiString(value: string, existingPtr: bigint): bigint {
		if (existingPtr !== 0n) {
			return existingPtr;
		}
		const ptr = this.memoryManager.heapAlloc(value.length + 1, true);
		if (ptr === 0n) {
			return 0n;
		}
		this.writeStringA(ptr, value);
		return ptr;
	}

	private ensureWideString(value: string, existingPtr: bigint): bigint {
		if (existingPtr !== 0n) {
			return existingPtr;
		}
		const bytes = Buffer.byteLength(value + '\0', 'utf16le');
		const ptr = this.memoryManager.heapAlloc(bytes, true);
		if (ptr === 0n) {
			return 0n;
		}
		this.writeStringW(ptr, value);
		return ptr;
	}

	private getCommandLineA(): bigint {
		this.commandLineAPtr = this.ensureAsciiString('HexCore.exe', this.commandLineAPtr);
		return this.commandLineAPtr;
	}

	private getCommandLineW(): bigint {
		this.commandLineWPtr = this.ensureWideString('HexCore.exe', this.commandLineWPtr);
		return this.commandLineWPtr;
	}

	private getWinMainCommandLineW(): bigint {
		this.winMainCommandLineWPtr = this.ensureWideString('', this.winMainCommandLineWPtr);
		return this.winMainCommandLineWPtr;
	}

	/**
	 * Lazy-allocate a 256-byte block holding MSVC CRT globals:
	 *   [0x00] narrow program name    "malware.exe\0" (12 bytes)
	 *   [0x10] argv (char**)          [&narrow_name, NULL]
	 *   [0x20] environ (char**)       [NULL]
	 *   [0x28] wide program name      L"malware.exe\0" (24 bytes)
	 *   [0x40] wargv (wchar_t**)      [&wide_name, NULL]
	 *   [0x50] wenviron (wchar_t**)   [NULL]
	 *
	 * This unblocks `_get_initial_narrow_environment` → `__p___argv` CRT
	 * init path that MSVC runs before `main()`. Without real backing memory,
	 * CRT dereferences NULL and faults at ~instruction 239.
	 */
	private ensureCrtDataAllocated(): void {
		if (this.crtDataPtr !== 0n) { return; }

		const base = this.memoryManager.heapAlloc(256, true);
		if (base === 0n) { return; }
		this.crtDataPtr = base;

		const narrowNamePtr = base + 0x00n;
		const argvArrayPtr  = base + 0x10n;
		const environArrayPtr = base + 0x20n;
		const wideNamePtr   = base + 0x28n;
		const wargvArrayPtr = base + 0x40n;
		const wenvironArrayPtr = base + 0x50n;

		const narrowName = Buffer.from('malware.exe\0', 'ascii');
		const wideName = Buffer.alloc(24);
		const wideStr = 'malware.exe\0';
		for (let i = 0; i < wideStr.length; i++) {
			wideName.writeUInt16LE(wideStr.charCodeAt(i), i * 2);
		}

		const argvArr = Buffer.alloc(16);
		argvArr.writeBigUInt64LE(narrowNamePtr, 0);
		argvArr.writeBigUInt64LE(0n, 8);

		const environArr = Buffer.alloc(8);  // single NULL terminator

		const wargvArr = Buffer.alloc(16);
		wargvArr.writeBigUInt64LE(wideNamePtr, 0);
		wargvArr.writeBigUInt64LE(0n, 8);

		const wenvironArr = Buffer.alloc(8);

		try {
			this.emulator.writeMemorySync(narrowNamePtr, narrowName);
			this.emulator.writeMemorySync(argvArrayPtr, argvArr);
			this.emulator.writeMemorySync(environArrayPtr, environArr);
			this.emulator.writeMemorySync(wideNamePtr, wideName);
			this.emulator.writeMemorySync(wargvArrayPtr, wargvArr);
			this.emulator.writeMemorySync(wenvironArrayPtr, wenvironArr);
		} catch {
			// If write fails we've still stashed the pointers; CRT will read
			// zeros, which is better than the NULL-deref crash.
		}

		this.crtArgvPtr = argvArrayPtr;
		this.crtEnvironPtr = environArrayPtr;
		this.crtWArgvPtr = wargvArrayPtr;
		this.crtWEnvironPtr = wenvironArrayPtr;
	}

	private readVariadicArgs(argListPtr: bigint, maxCount: number = 8): bigint[] {
		if (argListPtr === 0n) {
			return [];
		}
		const args: bigint[] = [];
		for (let i = 0; i < maxCount; i++) {
			try {
				const entryPtr = argListPtr + BigInt(i * 8);
				const buf = this.emulator.readMemorySync(entryPtr, 8);
				args.push(buf.readBigUInt64LE(0));
			} catch {
				break;
			}
		}
		return args;
	}

	private simpleFormatA(format: string, args: bigint[]): string {
		let result = '';
		let argIdx = 0;
		let i = 0;

		while (i < format.length) {
			if (format[i] !== '%') {
				result += format[i];
				i++;
				continue;
			}

			i++;
			if (i >= format.length) {
				break;
			}

			while (i < format.length && '-+0 #'.includes(format[i])) { i++; }
			while (i < format.length && format[i] >= '0' && format[i] <= '9') { i++; }
			if (i < format.length && format[i] === '.') {
				i++;
				while (i < format.length && format[i] >= '0' && format[i] <= '9') { i++; }
			}

			let lengthMod = '';
			if (i < format.length && (format[i] === 'l' || format[i] === 'h' || format[i] === 'z')) {
				lengthMod += format[i];
				i++;
				if (i < format.length && format[i] === 'l') {
					lengthMod += format[i];
					i++;
				}
			}

			if (i >= format.length) {
				break;
			}

			const spec = format[i];
			const arg = argIdx < args.length ? args[argIdx] : 0n;

			switch (spec) {
				case '%':
					result += '%';
					break;
				case 's':
					result += lengthMod.startsWith('l') ? this.readStringW(arg) : this.readStringA(arg);
					argIdx++;
					break;
				case 'c':
					result += String.fromCharCode(Number(arg & 0xFFn));
					argIdx++;
					break;
				case 'd':
				case 'i': {
					const val = Number(arg & 0xFFFFFFFFn);
					const signed = val > 0x7FFFFFFF ? val - 0x100000000 : val;
					result += signed.toString();
					argIdx++;
					break;
				}
				case 'u':
					result += (arg & 0xFFFFFFFFn).toString();
					argIdx++;
					break;
				case 'x':
					result += (arg & 0xFFFFFFFFn).toString(16);
					argIdx++;
					break;
				case 'X':
					result += (arg & 0xFFFFFFFFn).toString(16).toUpperCase();
					argIdx++;
					break;
				case 'p':
					result += '0x' + arg.toString(16);
					argIdx++;
					break;
				default:
					result += '%' + spec;
					argIdx++;
					break;
			}

			i++;
		}

		return result;
	}

	/**
	 * Get a new fake handle value
	 */
	private allocHandle(): bigint {
		return BigInt(this.nextHandle++);
	}

	/**
	 * Register all Windows API handlers
	 */
	private registerAllHandlers(): void {
		// ===== Memory Management =====
		this.handlers.set('kernel32!VirtualAlloc', (args) => {
			const [addr, size, allocType, protect] = args;
			return this.memoryManager.virtualAlloc(addr, Number(size), Number(allocType), Number(protect));
		});

		this.handlers.set('kernel32!VirtualFree', (args) => {
			const [addr, size, freeType] = args;
			return this.memoryManager.virtualFree(addr, Number(size), Number(freeType)) ? 1n : 0n;
		});

		this.handlers.set('kernel32!VirtualProtect', (args) => {
			const [addr, size, newProtect, oldProtectPtr] = args;
			const result = this.memoryManager.virtualProtect(addr, Number(size), Number(newProtect));
			if (oldProtectPtr !== 0n) {
				try {
					const buf = Buffer.alloc(4);
					buf.writeUInt32LE(result.oldProtect);
					this.emulator.writeMemorySync(oldProtectPtr, buf);
				} catch { /* ignore */ }
			}
			return result.success ? 1n : 0n;
		});

		// ===== Heap Management =====
		this.handlers.set('kernel32!HeapCreate', (_args) => {
			return this.allocHandle(); // Return a fake heap handle
		});

		this.handlers.set('kernel32!HeapAlloc', (args) => {
			const [_heap, flags, size] = args;
			const zeroMemory = (Number(flags) & 0x08) !== 0; // HEAP_ZERO_MEMORY
			return this.memoryManager.heapAlloc(Number(size), zeroMemory);
		});

		this.handlers.set('kernel32!HeapFree', (args) => {
			const [_heap, _flags, ptr] = args;
			return this.memoryManager.heapFree(ptr) ? 1n : 0n;
		});

		this.handlers.set('kernel32!GetProcessHeap', (_args) => {
			return 0x00050000n; // Fake heap handle matching our heap base
		});

		// ===== CRT memory primitives =====
		// These functions are commonly imported from VCRUNTIME rather than the
		// UCRT. Falling through to the generic unknown-API return value used to
		// make a successful memset look like a NULL result to the caller.
		const checkedLength = (raw: bigint): number | undefined => {
			if (raw < 0n || raw > BigInt(CRT_MEMORY_OPERATION_MAX_BYTES)) {
				this.lastError = 87; // ERROR_INVALID_PARAMETER
				return undefined;
			}
			return Number(raw);
		};
		const crtMemset = (args: bigint[]): bigint => {
			const [destination, value, rawLength] = args;
			const length = checkedLength(rawLength);
			if (length === undefined || (destination === 0n && length > 0)) { return 0n; }
			const chunkSize = 64 * 1024;
			const chunk = Buffer.alloc(Math.min(length, chunkSize), Number(value & 0xFFn));
			for (let offset = 0; offset < length; offset += chunkSize) {
				const writeSize = Math.min(chunkSize, length - offset);
				this.emulator.writeMemorySync(destination + BigInt(offset), chunk.subarray(0, writeSize));
			}
			return destination;
		};
		const crtMemcpy = (args: bigint[]): bigint => {
			const [destination, source, rawLength] = args;
			const length = checkedLength(rawLength);
			if (length === undefined || ((destination === 0n || source === 0n) && length > 0)) { return 0n; }
			if (length > 0) {
				const snapshot = Buffer.from(this.emulator.readMemorySync(source, length));
				this.emulator.writeMemorySync(destination, snapshot);
			}
			return destination;
		};
		const crtMemcmp = (args: bigint[]): bigint => {
			const [left, right, rawLength] = args;
			const length = checkedLength(rawLength);
			if (length === undefined || ((left === 0n || right === 0n) && length > 0)) { return 0n; }
			const a = length > 0 ? this.emulator.readMemorySync(left, length) : Buffer.alloc(0);
			const b = length > 0 ? this.emulator.readMemorySync(right, length) : Buffer.alloc(0);
			for (let i = 0; i < length; i++) {
				if (a[i] !== b[i]) { return a[i] < b[i] ? -1n : 1n; }
			}
			return 0n;
		};
		for (const dll of [
			'vcruntime140.dll', 'vcruntime140_1.dll', 'msvcrt.dll', 'ucrtbase.dll',
			'api-ms-win-crt-string-l1-1-0.dll',
		]) {
			this.handlers.set(`${dll}!memset`, crtMemset);
			this.handlers.set(`${dll}!memcpy`, crtMemcpy);
			this.handlers.set(`${dll}!memmove`, crtMemcpy); // snapshot preserves overlap semantics
			this.handlers.set(`${dll}!memcmp`, crtMemcmp);
			this.handlers.set(`${dll}!strlen`, (args) => {
				const length = this.readStringLengthA(args[0] ?? 0n);
				if (length === undefined) {
					this.lastError = 998; // ERROR_NOACCESS
					return 0n;
				}
				return BigInt(length);
			});
		}

		// ===== Module Management =====
		this.handlers.set('kernel32!GetModuleHandleA', (args) => {
			const [namePtr] = args;
			if (namePtr === 0n) {
				return this.imageBase;
			}
			const name = this.readStringA(namePtr).toLowerCase();
			return this.moduleHandles.get(name) ?? 0n;
		});

		this.handlers.set('kernel32!GetModuleHandleW', (args) => {
			const [namePtr] = args;
			if (namePtr === 0n) {
				return this.imageBase;
			}
			const name = this.readStringW(namePtr).toLowerCase();
			return this.moduleHandles.get(name) ?? 0n;
		});

		this.handlers.set('kernel32!LoadLibraryA', (args) => {
			const [namePtr] = args;
			const name = this.readStringA(namePtr).toLowerCase();
			const existing = this.moduleHandles.get(name);
			if (existing) {
				return existing;
			}
			// Fake module handle
			const handle = this.allocHandle();
			this.moduleHandles.set(name, handle);
			return handle;
		});

		this.handlers.set('kernel32!LoadLibraryW', (args) => {
			const [namePtr] = args;
			const name = this.readStringW(namePtr).toLowerCase();
			const existing = this.moduleHandles.get(name);
			if (existing) {
				return existing;
			}
			const handle = this.allocHandle();
			this.moduleHandles.set(name, handle);
			return handle;
		});

		this.handlers.set('kernel32!LoadLibraryExA', (args) => {
			const name = this.readStringA(args[0]).toLowerCase();
			const existing = this.moduleHandles.get(name);
			if (existing) { return existing; }
			const handle = this.allocHandle();
			this.moduleHandles.set(name, handle);
			return handle;
		});

		this.handlers.set('kernel32!LoadLibraryExW', (args) => {
			const name = this.readStringW(args[0]).toLowerCase();
			const existing = this.moduleHandles.get(name);
			if (existing) { return existing; }
			const handle = this.allocHandle();
			this.moduleHandles.set(name, handle);
			return handle;
		});

		this.handlers.set('kernel32!GetProcAddress', (args) => {
			const [_module, namePtr] = args;
			// We can't truly resolve this in emulation - return 0 (fail)
			// The caller should check for NULL
			if (namePtr < 0x10000n) {
				// Import by ordinal
				console.log(`GetProcAddress by ordinal: ${namePtr}`);
			} else {
				const name = this.readStringA(namePtr);
				console.log(`GetProcAddress: ${name}`);
			}
			return 0n;
		});

		// ===== Process Info =====
		this.handlers.set('kernel32!GetCurrentProcess', (_args) => {
			return 0xFFFFFFFFFFFFFFFFn; // -1 = current process pseudo-handle
		});

		this.handlers.set('kernel32!GetCurrentProcessId', (_args) => {
			return 0x1000n; // Fake PID
		});

		this.handlers.set('kernel32!GetCurrentThreadId', (_args) => {
			return 0x1004n; // Fake TID
		});

		this.handlers.set('kernel32!IsDebuggerPresent', (_args) => {
			return 0n; // FALSE - anti-anti-debug
		});

		this.handlers.set('kernel32!CheckRemoteDebuggerPresent', (args) => {
			const debuggerPresentPtr = args[1] ?? 0n;
			if (debuggerPresentPtr !== 0n) {
				try { this.emulator.writeMemorySync(debuggerPresentPtr, Buffer.alloc(4)); } catch { /* ignore */ }
			}
			return 1n; // API succeeded; output flag is FALSE.
		});

		const getThreadContext = (args: bigint[]): bigint => {
			const contextPtr = args[1] ?? 0n;
			if (contextPtr === 0n) { return 0n; }
			try {
				if (this.architecture === 'x64') {
					for (const offset of [0x48n, 0x50n, 0x58n, 0x60n, 0x68n, 0x70n]) {
						this.emulator.writeMemorySync(contextPtr + offset, Buffer.alloc(8));
					}
				} else {
					this.emulator.writeMemorySync(contextPtr + 4n, Buffer.alloc(24));
				}
				return 1n;
			} catch {
				return 0n;
			}
		};
		this.handlers.set('kernel32!GetThreadContext', getThreadContext);
		this.handlers.set('kernelbase!GetThreadContext', getThreadContext);

		// Exception-based debugger probes expect execution to continue when the
		// synthetic analysis environment consumes their private exception code.
		this.handlers.set('kernel32!RaiseException', (_args) => 0n);
		this.handlers.set('kernelbase!RaiseException', (_args) => 0n);

		// MSVC CRT startup requires these success/void contracts. Returning the
		// generic zero for InitializeCriticalSectionAndSpinCount incorrectly sends
		// otherwise valid programs into their fatal startup/unwind path.
		this.handlers.set('kernel32!InitializeCriticalSection', (_args) => 0n);
		this.handlers.set('kernel32!InitializeCriticalSectionAndSpinCount', (_args) => 1n);
		this.handlers.set('kernel32!InitializeCriticalSectionEx', (_args) => 1n);
		this.handlers.set('kernel32!EnterCriticalSection', (_args) => 0n);
		this.handlers.set('kernel32!LeaveCriticalSection', (_args) => 0n);
		this.handlers.set('kernel32!DeleteCriticalSection', (_args) => 0n);
		this.handlers.set('kernel32!TryEnterCriticalSection', (_args) => 1n);

		this.handlers.set('kernel32!TlsAlloc', (_args) => BigInt(this.nextTlsIndex++));
		this.handlers.set('kernel32!TlsSetValue', (args) => {
			this.tlsValues.set(Number(args[0]), args[1] ?? 0n);
			return 1n;
		});
		this.handlers.set('kernel32!TlsGetValue', (args) => this.tlsValues.get(Number(args[0])) ?? 0n);
		this.handlers.set('kernel32!TlsFree', (args) => {
			this.tlsValues.delete(Number(args[0]));
			return 1n;
		});
		this.handlers.set('kernel32!FlsAlloc', (_args) => BigInt(this.nextTlsIndex++));
		this.handlers.set('kernel32!FlsSetValue', (args) => {
			this.tlsValues.set(Number(args[0]), args[1] ?? 0n);
			return 1n;
		});
		this.handlers.set('kernel32!FlsGetValue', (args) => this.tlsValues.get(Number(args[0])) ?? 0n);
		this.handlers.set('kernel32!FlsFree', (args) => {
			this.tlsValues.delete(Number(args[0]));
			return 1n;
		});

		// ===== Error Handling =====
		this.handlers.set('kernel32!GetLastError', (_args) => {
			return BigInt(this.lastError);
		});

		this.handlers.set('kernel32!SetLastError', (args) => {
			this.lastError = Number(args[0]);
			return 0n;
		});

		// ===== Timing =====
		this.handlers.set('kernel32!GetTickCount', (_args) => {
			this.tickCount += 16; // Advance by ~16ms each call
			// FIX: `& 0xFFFFFFFF` returns signed int32 in JS — coerce to uint32
			// with `>>> 0` before BigInt() so the result is never negative.
			return BigInt((this.tickCount & 0xFFFFFFFF) >>> 0);
		});

		this.handlers.set('kernel32!GetTickCount64', (_args) => {
			this.tickCount += 16;
			// FIX: tickCount may have been seeded from `Date.now() & 0xFFFFFFFF`
			// (a signed int32) — coerce to unsigned before BigInt().
			return BigInt((this.tickCount & 0xFFFFFFFF) >>> 0);
		});

		this.handlers.set('kernel32!Sleep', (args) => {
			// Do not block the emulator, but advance both Windows time domains.
			// GetTickCount is milliseconds; QPC below runs at 10 MHz.
			const milliseconds = Number((args[0] ?? 0n) & 0xFFFFFFFFn);
			this.tickCount = (this.tickCount + milliseconds) >>> 0;
			this.performanceCounter += BigInt(milliseconds) * 10000n;
			return 0n;
		});

		this.handlers.set('kernel32!QueryPerformanceCounter', (args) => {
			const [counterPtr] = args;
			if (counterPtr !== 0n) {
				this.performanceCounter += 10000n; // one virtual millisecond per query
				const buf = Buffer.alloc(8);
				buf.writeBigUInt64LE(this.performanceCounter & 0xFFFFFFFFFFFFFFFFn);
				try {
					this.emulator.writeMemorySync(counterPtr, buf);
				} catch { /* ignore */ }
			}
			return 1n; // TRUE
		});

		this.handlers.set('kernel32!QueryPerformanceFrequency', (args) => {
			const [freqPtr] = args;
			if (freqPtr !== 0n) {
				const buf = Buffer.alloc(8);
				buf.writeBigUInt64LE(10000000n); // 10MHz
				try {
					this.emulator.writeMemorySync(freqPtr, buf);
				} catch { /* ignore */ }
			}
			return 1n;
		});

		this.handlers.set('kernel32!GetSystemTimeAsFileTime', (args) => {
			const [fileTimePtr] = args;
			if (fileTimePtr !== 0n) {
				const now = BigInt(Date.now());
				const unixEpochToFileTime = 11644473600000n;
				const fileTime = (now + unixEpochToFileTime) * 10000n;
				const buf = Buffer.alloc(8);
				buf.writeBigUInt64LE(fileTime);
				try {
					this.emulator.writeMemorySync(fileTimePtr, buf);
				} catch { /* ignore */ }
			}
			return 0n;
		});

		this.handlers.set('kernel32!GetSystemInfo', (args) => {
			const [systemInfoPtr] = args;
			if (systemInfoPtr !== 0n) {
				const buf = Buffer.alloc(this.architecture === 'x64' ? 48 : 36);
				buf.writeUInt16LE(this.architecture === 'x64' ? 9 : 0, 0); // PROCESSOR_ARCHITECTURE_AMD64 / INTEL
				buf.writeUInt32LE(0x1000, 4); // dwPageSize
				if (this.architecture === 'x64') {
					buf.writeBigUInt64LE(0x10000n, 8); // lpMinimumApplicationAddress
					buf.writeBigUInt64LE(0x00007FFFFFFEFFFFn, 16); // lpMaximumApplicationAddress
					buf.writeBigUInt64LE(1n, 24); // dwActiveProcessorMask
					buf.writeUInt32LE(8, 32); // dwNumberOfProcessors
					buf.writeUInt32LE(8664, 36); // dwProcessorType / PROCESSOR_AMD_X8664
					buf.writeUInt32LE(0x10000, 40); // dwAllocationGranularity
					buf.writeUInt16LE(6, 44); // wProcessorLevel
					buf.writeUInt16LE(0x3A09, 46); // wProcessorRevision
				} else {
					buf.writeUInt32LE(0x10000, 8);
					buf.writeUInt32LE(0x7FFEFFFF, 12);
					buf.writeUInt32LE(1, 16);
					buf.writeUInt32LE(4, 20);
					buf.writeUInt32LE(586, 24); // Pentium-class placeholder
					buf.writeUInt32LE(0x10000, 28);
					buf.writeUInt16LE(6, 32);
					buf.writeUInt16LE(0x3A09, 34);
				}
				try {
					this.emulator.writeMemorySync(systemInfoPtr, buf);
				} catch { /* ignore */ }
			}
			return 0n;
		});

		this.handlers.set('kernel32!GetNativeSystemInfo', (args) => {
			return this.handlers.get('kernel32!GetSystemInfo')!(args);
		});

		this.handlers.set('kernel32!K32GetProcessMemoryInfo', (args) => {
			const [_processHandle, countersPtr, cb] = args;
			if (countersPtr === 0n) {
				this.lastError = 87; // ERROR_INVALID_PARAMETER
				return 0n;
			}

			const requestedSize = Number(cb & 0xFFFFFFFFn);
			const regions = this.memoryManager.getAllocations();
			let workingSet = 0n;
			for (const region of regions) {
				workingSet += BigInt(region.size);
			}

			const size = this.architecture === 'x64' ? 72 : 40;
			const buf = Buffer.alloc(size);
			buf.writeUInt32LE(size, 0);
			buf.writeUInt32LE(0, 4); // PageFaultCount

			if (this.architecture === 'x64') {
				buf.writeBigUInt64LE(workingSet, 8);   // PeakWorkingSetSize
				buf.writeBigUInt64LE(workingSet, 16);  // WorkingSetSize
				buf.writeBigUInt64LE(workingSet / 4n, 24);
				buf.writeBigUInt64LE(workingSet / 4n, 32);
				buf.writeBigUInt64LE(workingSet / 8n, 40);
				buf.writeBigUInt64LE(workingSet / 8n, 48);
				buf.writeBigUInt64LE(workingSet, 56);  // PagefileUsage
				buf.writeBigUInt64LE(workingSet, 64);  // PeakPagefileUsage
			} else {
				const ws32 = Number(workingSet & 0xFFFFFFFFn);
				buf.writeUInt32LE(ws32, 8);
				buf.writeUInt32LE(ws32, 12);
				buf.writeUInt32LE(Math.floor(ws32 / 4), 16);
				buf.writeUInt32LE(Math.floor(ws32 / 4), 20);
				buf.writeUInt32LE(Math.floor(ws32 / 8), 24);
				buf.writeUInt32LE(Math.floor(ws32 / 8), 28);
				buf.writeUInt32LE(ws32, 32);
				buf.writeUInt32LE(ws32, 36);
			}

			try {
				this.emulator.writeMemorySync(countersPtr, requestedSize > 0 ? buf.subarray(0, Math.min(requestedSize, buf.length)) : buf);
			} catch {
				return 0n;
			}
			return 1n;
		});

		this.handlers.set('psapi!GetProcessMemoryInfo', (args) => {
			return this.handlers.get('kernel32!K32GetProcessMemoryInfo')!(args);
		});

		// ===== File I/O (stubs) =====
		this.handlers.set('kernel32!CreateFileA', (_args) => {
			return 0xFFFFFFFFFFFFFFFFn; // INVALID_HANDLE_VALUE - we don't support file I/O
		});

		this.handlers.set('kernel32!CreateFileW', (_args) => {
			return 0xFFFFFFFFFFFFFFFFn;
		});

		this.handlers.set('kernel32!ReadFile', (_args) => {
			return 0n; // FALSE
		});

		this.handlers.set('kernel32!WriteFile', (_args) => {
			return 0n; // FALSE
		});

		this.handlers.set('kernel32!CloseHandle', (_args) => {
			return 1n; // TRUE
		});

		// ===== String Functions =====
		this.handlers.set('kernel32!lstrlenA', (args) => {
			const [strPtr] = args;
			const str = this.readStringA(strPtr);
			return BigInt(str.length);
		});

		this.handlers.set('kernel32!lstrcpyA', (args) => {
			const [destPtr, srcPtr] = args;
			const str = this.readStringA(srcPtr);
			this.writeStringA(destPtr, str);
			return destPtr;
		});

		// ===== Console =====
		this.handlers.set('kernel32!GetStdHandle', (args) => {
			const [handleType] = args;
			switch (Number(handleType) & 0xFFFFFFFF) {
				case 0xFFFFFFF6: return 0x10n; // STD_INPUT_HANDLE
				case 0xFFFFFFF5: return 0x11n; // STD_OUTPUT_HANDLE
				case 0xFFFFFFF4: return 0x12n; // STD_ERROR_HANDLE
				default: return 0xFFFFFFFFFFFFFFFFn;
			}
		});

		this.handlers.set('kernel32!WriteConsoleA', (args) => {
			const [_handle, bufPtr, charsToWrite, charsWrittenPtr] = args;
			const text = this.readStringA(bufPtr);
			console.log(`[Console Output] ${text.substring(0, Number(charsToWrite))}`);
			if (charsWrittenPtr !== 0n) {
				const buf = Buffer.alloc(4);
				buf.writeUInt32LE(Number(charsToWrite));
				try {
					this.emulator.writeMemorySync(charsWrittenPtr, buf);
				} catch { /* ignore */ }
			}
			return 1n;
		});

		this.handlers.set('kernel32!WriteConsoleW', (args) => {
			const [_handle, bufPtr, charsToWrite, charsWrittenPtr] = args;
			const text = this.readStringW(bufPtr);
			console.log(`[Console Output] ${text.substring(0, Number(charsToWrite))}`);
			if (charsWrittenPtr !== 0n) {
				const buf = Buffer.alloc(4);
				buf.writeUInt32LE(Number(charsToWrite));
				try {
					this.emulator.writeMemorySync(charsWrittenPtr, buf);
				} catch { /* ignore */ }
			}
			return 1n;
		});

		// ===== Environment =====
		this.handlers.set('kernel32!GetCommandLineA', (_args) => {
			return this.getCommandLineA();
		});

		this.handlers.set('kernel32!GetCommandLineW', (_args) => {
			return this.getCommandLineW();
		});

		this.handlers.set('kernel32!GetStartupInfoW', (args) => {
			const [startupInfoPtr] = args;
			if (startupInfoPtr !== 0n) {
				const size = this.architecture === 'x64' ? 104 : 68;
				const buf = Buffer.alloc(size);
				buf.writeUInt32LE(size, 0);
				// dwFlags = 0, all handles zeroed, desktop/title empty.
				try {
					this.emulator.writeMemorySync(startupInfoPtr, buf);
				} catch { /* ignore */ }
			}
			return 0n;
		});

		this.handlers.set('kernel32!GetStartupInfoA', (args) => {
			return this.handlers.get('kernel32!GetStartupInfoW')!(args);
		});

		this.handlers.set('kernel32!WideCharToMultiByte', (args) => {
			const [codePage, _flags, widePtr, cchWideChar, multiPtr, cbMultiByte] = args;
			if (widePtr === 0n) {
				return 0n;
			}

			const wideCount = Number(BigInt.asIntN(32, cchWideChar));
			const outCapacity = Number(BigInt.asIntN(32, cbMultiByte));
			const useUtf8 = Number(codePage & 0xFFFFFFFFn) === 65001;

			let text = '';
			let includeNull = false;
			try {
				if (wideCount === 0) {
					return 0n;
				}
				if (wideCount < 0) {
					text = this.readStringW(widePtr);
					includeNull = true;
				} else {
					const buf = this.emulator.readMemorySync(widePtr, wideCount * 2);
					text = buf.toString('utf16le');
				}
			} catch {
				return 0n;
			}

			const encoded = Buffer.from(includeNull ? text + '\0' : text, useUtf8 ? 'utf8' : 'latin1');

			if (multiPtr === 0n || outCapacity <= 0) {
				return BigInt(encoded.length);
			}

			if (encoded.length > outCapacity) {
				this.lastError = 122; // ERROR_INSUFFICIENT_BUFFER
				return 0n;
			}

			try {
				this.emulator.writeMemorySync(multiPtr, encoded);
			} catch {
				return 0n;
			}

			return BigInt(encoded.length);
		});

		this.handlers.set('kernel32!MultiByteToWideChar', (args) => {
			const [codePage, _flags, multiPtr, cbMultiByte, widePtr, cchWideChar] = args;
			if (multiPtr === 0n) {
				return 0n;
			}

			const inputCount = Number(BigInt.asIntN(32, cbMultiByte));
			const outCapacity = Number(BigInt.asIntN(32, cchWideChar));
			const useUtf8 = Number(codePage & 0xFFFFFFFFn) === 65001;

			let text = '';
			let includeNull = false;
			try {
				if (inputCount === 0) {
					return 0n;
				}
				if (inputCount < 0) {
					const bytes = this.emulator.readMemorySync(multiPtr, 512);
					const end = bytes.indexOf(0);
					const slice = end >= 0 ? bytes.subarray(0, end) : bytes;
					text = slice.toString(useUtf8 ? 'utf8' : 'latin1');
					includeNull = true;
				} else {
					const bytes = this.emulator.readMemorySync(multiPtr, inputCount);
					text = bytes.toString(useUtf8 ? 'utf8' : 'latin1');
				}
			} catch {
				return 0n;
			}

			const wideBuf = Buffer.from(includeNull ? text + '\0' : text, 'utf16le');
			const wideChars = Math.floor(wideBuf.length / 2);

			if (widePtr === 0n || outCapacity <= 0) {
				return BigInt(wideChars);
			}

			if (wideChars > outCapacity) {
				this.lastError = 122; // ERROR_INSUFFICIENT_BUFFER
				return 0n;
			}

			try {
				this.emulator.writeMemorySync(widePtr, wideBuf);
			} catch {
				return 0n;
			}

			return BigInt(wideChars);
		});

		this.handlers.set('api-ms-win-crt-runtime-l1-1-0.dll!_get_wide_winmain_command_line', (_args) => {
			return this.getWinMainCommandLineW();
		});

		// ===== v3.8.0-nightly: MSVC CRT init stubs (HEXCORE_DEFEAT Fix #3) =====
		// These four unblock `__scrt_common_main_seh` → `main()` transition.
		// _initterm is a no-op (static initializers skipped); upgrade to a real
		// walker in v3.8.1 if any sample actually requires initializer execution.
		const crtArgv = (_args: bigint[]): bigint => {
			this.ensureCrtDataAllocated();
			return this.crtArgvPtr;
		};
		const crtArgc = (_args: bigint[]): bigint => {
			this.ensureCrtDataAllocated();
			// __p___argc returns a pointer to int. Reuse the environ slot tail
			// as scratch storage for the argc int — actually, write into offset
			// 0x58 of the CRT data block which is unused.
			if (this.crtDataPtr !== 0n) {
				try {
					const argcPtr = this.crtDataPtr + 0x58n;
					const buf = Buffer.alloc(4);
					buf.writeInt32LE(this.crtArgcValue, 0);
					this.emulator.writeMemorySync(argcPtr, buf);
					return argcPtr;
				} catch { /* fall through */ }
			}
			return BigInt(this.crtArgcValue);
		};
		const crtInitterm = (args: bigint[]): bigint => {
			// _initterm(start, end) — walk function pointer table, call each.
			// For v3.8.0 we skip execution. Return void (0n).
			const [start, end] = args;
			const slots = end > start ? Number((end - start) / 8n) : 0;
			console.log(`[crt] _initterm(0x${start.toString(16)}, 0x${end.toString(16)}) skipped — ${slots} slots`);
			return 0n;
		};
		const crtIntiterm_e = (args: bigint[]): bigint => {
			const [start, end] = args;
			const slots = end > start ? Number((end - start) / 8n) : 0;
			console.log(`[crt] _initterm_e(0x${start.toString(16)}, 0x${end.toString(16)}) skipped — ${slots} slots`);
			return 0n; // success
		};
		const crtGetNarrowEnv = (_args: bigint[]): bigint => {
			this.ensureCrtDataAllocated();
			return this.crtEnvironPtr;
		};
		const crtGetWideEnv = (_args: bigint[]): bigint => {
			this.ensureCrtDataAllocated();
			return this.crtWEnvironPtr;
		};

		for (const dll of ['api-ms-win-crt-runtime-l1-1-0.dll', 'ucrtbase.dll', 'msvcrt.dll']) {
			this.handlers.set(`${dll}!__p___argv`, crtArgv);
			this.handlers.set(`${dll}!__p___argc`, crtArgc);
			this.handlers.set(`${dll}!_initterm`, crtInitterm);
			this.handlers.set(`${dll}!_initterm_e`, crtIntiterm_e);
			this.handlers.set(`${dll}!_get_initial_narrow_environment`, crtGetNarrowEnv);
			this.handlers.set(`${dll}!_get_initial_wide_environment`, crtGetWideEnv);
		}

		this.handlers.set('api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsprintf_s', (args) => {
			const [_options, bufferPtr, bufferCount, formatPtr, _locale, argListPtr] = args;
			if (bufferPtr === 0n || formatPtr === 0n) {
				this.lastError = 87; // ERROR_INVALID_PARAMETER
				return BigInt(-1);
			}

			const capacity = Number(bufferCount & 0xFFFFFFFFFFFFFFFFn);
			if (capacity <= 0) {
				this.lastError = 122; // ERROR_INSUFFICIENT_BUFFER
				return BigInt(-1);
			}

			let format = '';
			try {
				format = this.readStringA(formatPtr);
			} catch {
				return BigInt(-1);
			}

			const vaArgs = this.readVariadicArgs(argListPtr, 16);
			const rendered = this.simpleFormatA(format, vaArgs);
			const bytes = Buffer.from(rendered + '\0', 'ascii');

			if (bytes.length > capacity) {
				this.lastError = 122; // ERROR_INSUFFICIENT_BUFFER
				try {
					this.emulator.writeMemorySync(bufferPtr, Buffer.from([0]));
				} catch { /* ignore */ }
				return BigInt(-1);
			}

			try {
				this.emulator.writeMemorySync(bufferPtr, bytes);
			} catch {
				return BigInt(-1);
			}

			return BigInt(rendered.length);
		});

		this.handlers.set('ucrtbase.dll!__stdio_common_vsprintf_s', (args) => {
			return this.handlers.get('api-ms-win-crt-stdio-l1-1-0.dll!__stdio_common_vsprintf_s')!(args);
		});

		// ===== CRT / ntdll =====
		this.handlers.set('ntdll!RtlGetVersion', (args) => {
			const [versionInfoPtr] = args;
			if (versionInfoPtr !== 0n) {
				// OSVERSIONINFOEXW - report as Windows 10
				const buf = Buffer.alloc(284);
				buf.writeUInt32LE(284, 0); // dwOSVersionInfoSize
				buf.writeUInt32LE(10, 4);  // dwMajorVersion
				buf.writeUInt32LE(0, 8);   // dwMinorVersion
				buf.writeUInt32LE(19041, 12); // dwBuildNumber
				buf.writeUInt32LE(2, 16);  // dwPlatformId (VER_PLATFORM_WIN32_NT)
				try {
					this.emulator.writeMemorySync(versionInfoPtr, buf);
				} catch { /* ignore */ }
			}
			return 0n; // STATUS_SUCCESS
		});

		// ExitProcess - stop emulation
		this.handlers.set('kernel32!ExitProcess', (_args) => {
			this.emulator.stop();
			return 0n;
		});

		// v3.8.0-nightly: CRT exit variants also stop emulation. Without these,
		// `exit(0)` returns from the stub and falls into garbage code, causing
		// the emulator to loop until it hits the instruction cap. (Observed on
		// `Malware HexCore Defeat.exe` v3: 23,128 api calls, 1M instructions,
		// emulation trapped re-executing fragments of main's cout chain.)
		const crtExit = (_args: bigint[]): bigint => {
			this.emulator.stop();
			return 0n;
		};
		for (const dll of ['api-ms-win-crt-runtime-l1-1-0.dll', 'ucrtbase.dll', 'msvcrt.dll']) {
			this.handlers.set(`${dll}!exit`, crtExit);
			this.handlers.set(`${dll}!_exit`, crtExit);
			this.handlers.set(`${dll}!_Exit`, crtExit);
			this.handlers.set(`${dll}!quick_exit`, crtExit);
			this.handlers.set(`${dll}!abort`, crtExit);
		}

		// ── MSVCP140 / iostream stubs ──────────────────────────────────────
		// v3.8.0-nightly: the malware's cout/cerr usage calls these mangled
		// MSVCP140 methods. Without stubs, each call logs "Unhandled API" and
		// returns 0 which is correct behavior but floods the trace with 40+
		// noise lines per emulation cycle. The sputn + operator<<(const char*)
		// stubs additionally capture the string payload into `stdoutBuffer`
		// so pipelines can observe what the emulated program printed.
		const ostreamNop = (_args: bigint[]): bigint => 0n;
		// ios_base::good() → return true (1) so the stream appears healthy
		const iosGood = (_args: bigint[]): bigint => 1n;
		// operator<< with endl/flush manipulator → append newline and return 'this'
		const ostreamEndl = (args: bigint[]): bigint => {
			this.stdoutBuffer += '\n';
			return args[0] ?? 0n;
		};

		// streambuf::sputn(s, n) — this is where the actual string bytes flow
		// for `std::cout << "text"`. Read n bytes from args[1] and append.
		// Returns n (all bytes "written").
		const sputnCapture = (args: bigint[]): bigint => {
			const strPtr = args[1];
			const n = args[2];
			if (!strPtr || strPtr === 0n || !n || n === 0n) { return n ?? 0n; }
			const len = Number(n);
			if (len <= 0 || len > 65536) { return n; } // sanity cap
			try {
				const bytes = this.emulator.readMemorySync(strPtr, len);
				this.stdoutBuffer += bytes.toString('utf8');
			} catch { /* ignore unmapped reads */ }
			return n;
		};

		// operator<<(ostream&, const char*) — method form (ostream receives
		// const char*). args[0]=this, args[1]=char*. Walks until NUL.
		const ostreamWriteCStr = (args: bigint[]): bigint => {
			const strPtr = args[1];
			if (strPtr && strPtr !== 0n) {
				try {
					// Read up to 4KB, stop at NUL
					const bytes = this.emulator.readMemorySync(strPtr, 4096);
					const nulIdx = bytes.indexOf(0);
					const end = nulIdx >= 0 ? nulIdx : bytes.length;
					this.stdoutBuffer += bytes.subarray(0, end).toString('utf8');
				} catch { /* ignore */ }
			}
			return args[0] ?? 0n;
		};

		// operator<<(numeric) — format the arg as decimal (we don't track
		// ostream-per-stream std::hex/dec state; defaulting to decimal gets
		// ~all real-world diagnostic output right) and append to stdout.
		// CRITICAL: must return args[0] (the ostream `this` pointer) so the
		// chained `<< "x" << n << "y"` expression dereferences a valid
		// ostream on the next call. Returning 0 → UC_ERR_READ_UNMAPPED
		// when the caller reads ios_base state off the null ostream.
		const makeNumericStub = (formatter: (v: bigint) => string) => (args: bigint[]): bigint => {
			const v = args[1] ?? 0n;
			this.stdoutBuffer += formatter(v);
			return args[0] ?? 0n;
		};
		const asDec = (v: bigint) => v.toString(10);
		const asDecSigned32 = (v: bigint) => {
			const low = Number(v & 0xFFFFFFFFn);
			return ((low | 0) as number).toString(10); // signed 32-bit
		};
		const asDecSigned64 = (v: bigint) => {
			const hi = v & (1n << 63n);
			return hi ? (v - (1n << 64n)).toString(10) : v.toString(10);
		};

		const msvcp140Stubs: [string, (args: bigint[]) => bigint][] = [
			['?good@ios_base@std@@QEBA_NXZ', iosGood],
			['?setstate@?$basic_ios@DU?$char_traits@D@std@@@std@@QEAAXH_N@Z', ostreamNop],
			['?uncaught_exception@std@@YA_NXZ', ostreamNop],
			['?_Osfx@?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAXXZ', ostreamNop],
			// operator<<(ostream&(*)(ostream&)) — endl/flush. Append newline.
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV01@AEAV01@@Z@Z', ostreamEndl],
			// operator<<(ios_base&(*)(ios_base&)) — std::hex / std::dec / std::oct
			// / std::noboolalpha / etc. Pure formatting manipulator, no output
			// byte emitted. MUST return args[0] (ostream this) to keep the
			// chained `<< std::hex << n << std::dec` expression alive.
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAVios_base@1@AEAV21@@Z@Z', (args) => args[0] ?? 0n],
			// operator<<(basic_ios&(*)(basic_ios&)) — resetiosflags etc.
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@P6AAEAV?$basic_ios@DU?$char_traits@D@std@@@1@AEAV21@@Z@Z', (args) => args[0] ?? 0n],
			// streambuf::sputn — captures actual payload bytes for const char*.
			['?sputn@?$basic_streambuf@DU?$char_traits@D@std@@@std@@QEAA_JPEBD_J@Z', sputnCapture],
			// operator<<(ostream&, const char*) — free function form (MSVC free fn)
			['??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@PEBD@Z', ostreamWriteCStr],
			// operator<<(const char*) — method form (some MSVC versions emit this)
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBD@Z', ostreamWriteCStr],
			// operator<<(char) — single char literal
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@D@Z', (args) => {
				const ch = Number(args[1] ?? 0n) & 0xff;
				if (ch > 0) { this.stdoutBuffer += String.fromCharCode(ch); }
				return args[0] ?? 0n;
			}],
			// operator<<(numeric) — MSVC mangled suffixes: H=int F=short I=unsigned E=ushort
			// J=long K=ulong _J=__int64 _K=uint64 M=float N=double O=long double
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@H@Z',  makeNumericStub(asDecSigned32)],  // int
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@I@Z',  makeNumericStub(asDec)],          // unsigned
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@F@Z',  makeNumericStub(asDecSigned32)],  // short
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@G@Z',  makeNumericStub(asDec)],          // ushort
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@J@Z',  makeNumericStub(asDecSigned32)],  // long (32 on Win)
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@K@Z',  makeNumericStub(asDec)],          // unsigned long
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_J@Z', makeNumericStub(asDecSigned64)],  // __int64
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@_K@Z', makeNumericStub(asDec)],          // uint64
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@N@Z',  makeNumericStub(asDec)],          // bool
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEBX@Z', makeNumericStub(v => '0x' + v.toString(16))], // const void*
			['??6?$basic_ostream@DU?$char_traits@D@std@@@std@@QEAAAEAV01@PEAX@Z', makeNumericStub(v => '0x' + v.toString(16))], // void*
			// Free-function wide-string operator<< — msvcp140 sometimes routes
			// small formatters through it. Pass through to preserve chain.
			['??$?6U?$char_traits@D@std@@@std@@YAAEAV?$basic_ostream@DU?$char_traits@D@std@@@0@AEAV10@D@Z', (args) => {
				const ch = Number(args[1] ?? 0n) & 0xff;
				if (ch > 0) { this.stdoutBuffer += String.fromCharCode(ch); }
				return args[0] ?? 0n;
			}],
		];
		for (const [name, handler] of msvcp140Stubs) {
			this.handlers.set(`msvcp140.dll!${name}`, handler);
		}

		// ── Windows CNG (BCrypt) ─────────────────────────────────────────
		// Stateful SHA-256 and AES-CBC are sufficient for the native analysis
		// corpus. Unsupported algorithms fail with NTSTATUS instead of claiming
		// success without creating handles or writing output.
		const STATUS_SUCCESS = 0n;
		const STATUS_INVALID_HANDLE = 0xC0000008n;
		const STATUS_INVALID_PARAMETER = 0xC000000Dn;
		const STATUS_BUFFER_TOO_SMALL = 0xC0000023n;
		const STATUS_DATA_ERROR = 0xC000003En;
		const STATUS_NOT_SUPPORTED = 0xC00000BBn;
		const writePointer = (address: bigint, value: bigint): boolean => {
			if (address === 0n) { return false; }
			try {
				const buffer = Buffer.alloc(this.architecture === 'x64' ? 8 : 4);
				if (this.architecture === 'x64') {
					buffer.writeBigUInt64LE(value);
				} else {
					buffer.writeUInt32LE(Number(value & 0xFFFFFFFFn));
				}
				this.emulator.writeMemorySync(address, buffer);
				return true;
			} catch {
				return false;
			}
		};
		const writeUInt32 = (address: bigint, value: number): boolean => {
			if (address === 0n) { return false; }
			try {
				const buffer = Buffer.alloc(4);
				buffer.writeUInt32LE(value >>> 0);
				this.emulator.writeMemorySync(address, buffer);
				return true;
			} catch {
				return false;
			}
		};
		const cngKey = (name: string) => `bcrypt.dll!${name}`;
		this.handlers.set(cngKey('BCryptOpenAlgorithmProvider'), (args) => {
			const [handleSlot, algorithmNamePtr] = args;
			const requested = this.readStringW(algorithmNamePtr).replace(/[-_]/g, '').toUpperCase();
			const algorithm = requested === 'SHA256' ? 'SHA256' : requested === 'AES' ? 'AES' : undefined;
			if (!algorithm) { return STATUS_NOT_SUPPORTED; }
			const handle = this.allocHandle();
			if (!writePointer(handleSlot, handle)) { return STATUS_INVALID_PARAMETER; }
			this.cngAlgorithms.set(handle, { algorithm, chainingMode: 'CBC' });
			return STATUS_SUCCESS;
		});
		this.handlers.set(cngKey('BCryptSetProperty'), (args) => {
			const [handle, propertyNamePtr, inputPtr] = args;
			const algorithm = this.cngAlgorithms.get(handle);
			const key = this.cngKeys.get(handle);
			if (!algorithm && !key) { return STATUS_INVALID_HANDLE; }
			const propertyName = this.readStringW(propertyNamePtr);
			if (propertyName !== 'ChainingMode') { return STATUS_NOT_SUPPORTED; }
			const value = this.readStringW(inputPtr);
			if (value !== 'ChainingModeCBC') { return STATUS_NOT_SUPPORTED; }
			if (algorithm) { algorithm.chainingMode = 'CBC'; }
			if (key) { key.chainingMode = 'CBC'; }
			return STATUS_SUCCESS;
		});
		this.handlers.set(cngKey('BCryptCreateHash'), (args) => {
			const [algorithmHandle, hashSlot, _hashObject, _hashObjectSize, secret, secretSize] = args;
			const algorithm = this.cngAlgorithms.get(algorithmHandle);
			if (!algorithm) { return STATUS_INVALID_HANDLE; }
			if (algorithm.algorithm !== 'SHA256' || secret !== 0n || secretSize !== 0n) {
				return STATUS_NOT_SUPPORTED;
			}
			const hashHandle = this.allocHandle();
			if (!writePointer(hashSlot, hashHandle)) { return STATUS_INVALID_PARAMETER; }
			this.cngHashes.set(hashHandle, { algorithm: 'SHA256', chunks: [] });
			return STATUS_SUCCESS;
		});
		this.handlers.set(cngKey('BCryptHashData'), (args) => {
			const [hashHandle, inputPtr, rawInputSize] = args;
			const hash = this.cngHashes.get(hashHandle);
			if (!hash) { return STATUS_INVALID_HANDLE; }
			const inputSize = Number(rawInputSize);
			if (!Number.isSafeInteger(inputSize) || inputSize < 0 || (inputPtr === 0n && inputSize > 0)) {
				return STATUS_INVALID_PARAMETER;
			}
			try {
				hash.chunks.push(inputSize > 0 ? Buffer.from(this.emulator.readMemorySync(inputPtr, inputSize)) : Buffer.alloc(0));
				return STATUS_SUCCESS;
			} catch {
				return STATUS_INVALID_PARAMETER;
			}
		});
		this.handlers.set(cngKey('BCryptFinishHash'), (args) => {
			const [hashHandle, outputPtr, rawOutputSize] = args;
			const hash = this.cngHashes.get(hashHandle);
			if (!hash) { return STATUS_INVALID_HANDLE; }
			const outputSize = Number(rawOutputSize);
			if (outputPtr === 0n || !Number.isSafeInteger(outputSize) || outputSize < 32) {
				return STATUS_BUFFER_TOO_SMALL;
			}
			const digest = crypto.createHash('sha256').update(Buffer.concat(hash.chunks)).digest();
			try {
				this.emulator.writeMemorySync(outputPtr, digest);
				return STATUS_SUCCESS;
			} catch {
				return STATUS_INVALID_PARAMETER;
			}
		});
		this.handlers.set(cngKey('BCryptDestroyHash'), (args) =>
			this.cngHashes.delete(args[0]) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE);
		this.handlers.set(cngKey('BCryptCloseAlgorithmProvider'), (args) =>
			this.cngAlgorithms.delete(args[0]) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE);
		this.handlers.set(cngKey('BCryptGenerateSymmetricKey'), (args) => {
			const [algorithmHandle, keySlot, _keyObject, _keyObjectSize, secretPtr, rawSecretSize] = args;
			const algorithm = this.cngAlgorithms.get(algorithmHandle);
			const secretSize = Number(rawSecretSize);
			if (!algorithm) { return STATUS_INVALID_HANDLE; }
			if (algorithm.algorithm !== 'AES' || ![16, 24, 32].includes(secretSize) || secretPtr === 0n) {
				return STATUS_NOT_SUPPORTED;
			}
			try {
				const keyHandle = this.allocHandle();
				const key = Buffer.from(this.emulator.readMemorySync(secretPtr, secretSize));
				if (!writePointer(keySlot, keyHandle)) { return STATUS_INVALID_PARAMETER; }
				this.cngKeys.set(keyHandle, { algorithm: 'AES', key, chainingMode: algorithm.chainingMode });
				return STATUS_SUCCESS;
			} catch {
				return STATUS_INVALID_PARAMETER;
			}
		});
		this.handlers.set(cngKey('BCryptDecrypt'), (args) => {
			const [keyHandle, inputPtr, rawInputSize, paddingInfo, ivPtr, rawIvSize,
				outputPtr, rawOutputSize, resultSizePtr, rawFlags] = args;
			const key = this.cngKeys.get(keyHandle);
			if (!key) { return STATUS_INVALID_HANDLE; }
			if (key.chainingMode !== 'CBC' || paddingInfo !== 0n) { return STATUS_NOT_SUPPORTED; }
			const inputSize = Number(rawInputSize);
			const ivSize = Number(rawIvSize);
			const outputSize = Number(rawOutputSize);
			if (inputPtr === 0n || ivPtr === 0n || ivSize !== 16 || !Number.isSafeInteger(inputSize) || inputSize < 0) {
				return STATUS_INVALID_PARAMETER;
			}
			// CNG permits a size-probe call with pbOutput == NULL. Do not attempt
			// padding validation yet: the caller is only asking how much storage
			// to allocate, and the ciphertext size is a safe upper bound.
			if (outputPtr === 0n) {
				return writeUInt32(resultSizePtr, inputSize) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
			}
			try {
				const input = Buffer.from(this.emulator.readMemorySync(inputPtr, inputSize));
				const iv = Buffer.from(this.emulator.readMemorySync(ivPtr, ivSize));
				const plaintext = decryptAesCbc(input, key.key, iv, (Number(rawFlags) & 0x1) !== 0);
				if (!writeUInt32(resultSizePtr, plaintext.length)) { return STATUS_INVALID_PARAMETER; }
				if (outputSize < plaintext.length) { return STATUS_BUFFER_TOO_SMALL; }
				this.emulator.writeMemorySync(outputPtr, plaintext);
				return STATUS_SUCCESS;
			} catch {
				return STATUS_DATA_ERROR;
			}
		});
		for (const name of [
			'BCryptOpenAlgorithmProvider', 'BCryptSetProperty', 'BCryptCreateHash', 'BCryptHashData',
			'BCryptFinishHash', 'BCryptDestroyHash', 'BCryptCloseAlgorithmProvider',
			'BCryptGenerateSymmetricKey', 'BCryptDecrypt',
		]) {
			this.semanticLevels.set(cngKey(name), 'implemented');
		}

		// ── shell32 ShellExecute* stubs ──────────────────────────────────
		// v3.8.0-nightly: return 42 (any value > 32) to signal "success"
		// per MSDN ShellExecute return codes. Legitimate ShellExecute would
		// open the URL in the default browser; under emulation we just
		// acknowledge without side effects. The log entry captures what URL
		// the malware was trying to beacon to.
		const shellExecuteOk = (args: bigint[]): bigint => {
			// args[2] (x64 fastcall) is lpFile — for ShellExecuteW it's a
			// wide string. Read and log the target URL for the trace.
			const lpFile = args[2] ?? 0n;
			if (lpFile && lpFile !== 0n) {
				try {
					const buf = this.emulator.readMemorySync(lpFile, 512);
					// Wide string: read until double-null
					let end = 0;
					while (end + 1 < buf.length) {
						if (buf[end] === 0 && buf[end + 1] === 0) { break; }
						end += 2;
					}
					const wstr = buf.subarray(0, end).toString('utf16le');
					this.stdoutBuffer += `[emulator] ShellExecute target: ${wstr}\n`;
				} catch { /* ignore */ }
			}
			return 42n; // > 32 = success
		};
		this.handlers.set('shell32.dll!ShellExecuteA', shellExecuteOk);
		this.handlers.set('shell32.dll!ShellExecuteW', shellExecuteOk);
		this.handlers.set('shell32!ShellExecuteA', shellExecuteOk);
		this.handlers.set('shell32!ShellExecuteW', shellExecuteOk);
		this.handlers.set('shell32.dll!ShellExecuteExA', (_args) => 1n);
		this.handlers.set('shell32.dll!ShellExecuteExW', (_args) => 1n);

		// ── advapi32 registry stubs ──────────────────────────────────────
		// v3.8.0-nightly: RegOpenKeyA/RegCloseKey are called by the malware's
		// anti-VM checks. Without stubs they log "Unhandled API" noise.
		// RegOpenKey returns ERROR_FILE_NOT_FOUND (2) to signal "key not found"
		// which makes anti-VM checks think the VM isn't present.
		this.handlers.set('advapi32.dll!RegOpenKeyA', (_args) => 2n);
		this.handlers.set('advapi32.dll!RegOpenKeyExA', (_args) => 2n);
		this.handlers.set('advapi32.dll!RegOpenKeyW', (_args) => 2n);
		this.handlers.set('advapi32.dll!RegOpenKeyExW', (_args) => 2n);
		this.handlers.set('advapi32.dll!RegCloseKey', (_args) => 0n);
		this.handlers.set('advapi32.dll!RegQueryValueExA', (_args) => 2n);
		this.handlers.set('advapi32.dll!RegQueryValueExW', (_args) => 2n);

		// kernel32!GetComputerNameA — return a fake name so anti-VM
		// checks don't see "DESKTOP-SANDBOX" or similar VM indicators.
		// Honors the nSize-in/out contract: if caller-provided capacity
		// is insufficient, write required size and return 0 (so active
		// anti-emulation probes with tiny buffers cannot fingerprint us).
		this.handlers.set('kernel32.dll!GetComputerNameA', (args) => {
			if (!args[0] || args[0] === 0n || !args[1] || args[1] === 0n) { return 0n; }
			const NAME = 'WORKSTATION';
			const required = NAME.length + 1; // includes NUL
			const capBuf = this.emulator.readMemorySync(args[1], 4);
			const capacity = capBuf.readUInt32LE(0);
			if (capacity < required) {
				const sz = Buffer.alloc(4);
				sz.writeUInt32LE(required);
				this.emulator.writeMemorySync(args[1], sz);
				return 0n; // ERROR_BUFFER_OVERFLOW (122) on real Windows
			}
			this.emulator.writeMemorySync(args[0], Buffer.from(`${NAME}\0`, 'ascii'));
			const sz = Buffer.alloc(4);
			sz.writeUInt32LE(NAME.length); // chars written, excluding NUL
			this.emulator.writeMemorySync(args[1], sz);
			return 1n;
		});
		this.handlers.set('kernel32.dll!GetComputerNameW', (args) => {
			if (!args[0] || args[0] === 0n || !args[1] || args[1] === 0n) { return 0n; }
			const NAME = 'WORKSTATION';
			const required = NAME.length + 1; // TCHARs including NUL
			const capBuf = this.emulator.readMemorySync(args[1], 4);
			const capacity = capBuf.readUInt32LE(0);
			if (capacity < required) {
				const sz = Buffer.alloc(4);
				sz.writeUInt32LE(required);
				this.emulator.writeMemorySync(args[1], sz);
				return 0n;
			}
			this.emulator.writeMemorySync(args[0], Buffer.from(`${NAME}\0`, 'utf16le'));
			const sz = Buffer.alloc(4);
			sz.writeUInt32LE(NAME.length);
			this.emulator.writeMemorySync(args[1], sz);
			return 1n;
		});
	}

	/**
	 * Get the call log
	 */
	getCallLog(): ApiCallLog[] {
		return this.callLog;
	}

	/**
	 * Clear the call log
	 */
	clearCallLog(): void {
		this.callLog = [];
		this.lastCall = undefined;
	}

	/**
	 * Get the most recent API call
	 */
	getLastCall(): ApiCallLog | undefined {
		return this.lastCall;
	}

	private readStringLengthA(address: bigint): number | undefined {
		if (address === 0n) { return undefined; }
		let length = 0;
		while (length < CRT_STRING_MAX_BYTES) {
			const cursor = address + BigInt(length);
			const pageRemaining = 0x1000 - Number(cursor & 0xFFFn);
			const readSize = Math.min(pageRemaining, CRT_STRING_MAX_BYTES - length);
			let chunk: Buffer;
			try {
				chunk = this.emulator.readMemorySync(cursor, readSize);
			} catch {
				return undefined;
			}
			const terminator = chunk.indexOf(0);
			if (terminator >= 0) { return length + terminator; }
			length += chunk.length;
			if (chunk.length !== readSize) { return undefined; }
		}
		return undefined;
	}

	private recordCallLog(entry: ApiCallLog): void {
		this.lastCall = entry;
		if (this.callLog.length < API_CALL_LOG_MAX_ENTRIES) {
			this.callLog.push(entry);
		}
	}

	/**
	 * Check if an API has a registered handler
	 */
	hasHandler(dll: string, name: string): boolean {
		const key = `${dll.toLowerCase()}!${name}`;
		const keyNoExt = `${dll.toLowerCase().replace('.dll', '')}!${name}`;
		return this.handlers.has(key) || this.handlers.has(keyNoExt);
	}

	/**
	 * Get the stdout buffer populated by iostream stubs (sputn, operator<<).
	 * Returns whatever `std::cout`/`std::cerr` emitted during emulation.
	 */
	getStdoutBuffer(): string {
		return this.stdoutBuffer;
	}

	/**
	 * v3.8.0-nightly: pre-populate the moduleHandles map with synthetic
	 * DllBases from PELoader.setupSyntheticDlls(). After this call,
	 * LoadLibraryA("shell32.dll") / GetModuleHandle("kernel32") return
	 * the real PE-header-bearing synthetic base so hash-resolving
	 * shellcode can parse the export directory from there.
	 */
	registerSyntheticModules(modules: Map<string, bigint>): void {
		for (const [name, base] of modules) {
			this.moduleHandles.set(name, base);
		}
	}

	/**
	 * Clear the captured stdout buffer.
	 */
	clearStdoutBuffer(): void {
		this.stdoutBuffer = '';
	}
}
