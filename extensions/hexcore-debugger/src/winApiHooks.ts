/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Windows API Hooks
 *  Emulates ~25 common Windows APIs for PE execution in Unicorn
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

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
}

type ApiHandler = (args: bigint[]) => bigint;

export class WinApiHooks {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private architecture: ArchitectureType;
	private handlers: Map<string, ApiHandler> = new Map();
	private callLog: ApiCallLog[] = [];
	private lastError: number = 0;
	private tickCount: number = 0;
	private nextHandle: number = 0x100;
	private commandLineAPtr: bigint = 0n;
	private commandLineWPtr: bigint = 0n;
	private winMainCommandLineWPtr: bigint = 0n;

	// Module handle tracking
	private moduleHandles: Map<string, bigint> = new Map();
	private imageBase: bigint = 0x400000n;

	/** Optional TraceManager for centralized trace recording */
	private traceManager: TraceManager | null = null;

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager, arch: ArchitectureType) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
		this.architecture = arch;
		this.tickCount = Date.now() & 0xFFFFFFFF;
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

		// Read arguments based on calling convention.
		// A few Win32 APIs we emulate here use 7-8 parameters.
		const args = this.readArguments(8);

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

		this.callLog.push({
			dll,
			name,
			args,
			returnValue,
			timestamp,
			arguments: formattedArgs,
			pcAddress,
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
			return BigInt(this.tickCount & 0xFFFFFFFF);
		});

		this.handlers.set('kernel32!GetTickCount64', (_args) => {
			this.tickCount += 16;
			return BigInt(this.tickCount);
		});

		this.handlers.set('kernel32!Sleep', (_args) => {
			// No-op in emulation
			return 0n;
		});

		this.handlers.set('kernel32!QueryPerformanceCounter', (args) => {
			const [counterPtr] = args;
			if (counterPtr !== 0n) {
				this.tickCount += 1000;
				const buf = Buffer.alloc(8);
				buf.writeBigUInt64LE(BigInt(this.tickCount));
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
	}

	/**
	 * Get the most recent API call
	 */
	getLastCall(): ApiCallLog | undefined {
		return this.callLog[this.callLog.length - 1];
	}

	/**
	 * Check if an API has a registered handler
	 */
	hasHandler(dll: string, name: string): boolean {
		const key = `${dll.toLowerCase()}!${name}`;
		const keyNoExt = `${dll.toLowerCase().replace('.dll', '')}!${name}`;
		return this.handlers.has(key) || this.handlers.has(keyNoExt);
	}
}
