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

		// Read arguments based on calling convention
		const args = this.readArguments(6); // Read up to 6 args

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
			// Return pointer to empty string at a known location
			return 0n;
		});

		this.handlers.set('kernel32!GetCommandLineW', (_args) => {
			return 0n;
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
