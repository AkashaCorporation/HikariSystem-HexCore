/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Linux API Hooks
 *  Emulates common libc functions for ELF execution in Unicorn
 *  Mirrors WinApiHooks pattern but for Linux/glibc functions
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

export class LinuxApiHooks {
	private emulator: UnicornWrapper;
	private memoryManager: MemoryManager;
	private architecture: ArchitectureType;
	private handlers: Map<string, ApiHandler> = new Map();
	private callLog: ApiCallLog[] = [];
	private lastErrno: number = 0;

	// Emulated state
	private imageBase: bigint = 0n;
	private nextMmapBase: bigint = 0x20000000n;
	private stdoutBuffer: string = '';

	// When a handler needs to redirect execution (e.g. __libc_start_main jumping to main),
	// it sets this to the target address. The interceptor should set RIP to this instead of
	// doing the normal popReturnAddress flow.
	private _redirectAddress: bigint | null = null;

	// Configurable stdin buffer for scanf/read emulation
	private stdinBuffer: string = '';
	private stdinOffset: number = 0;
	// Optional synthetic return address used when redirecting __libc_start_main -> main.
	private mainReturnAddress: bigint | null = null;

	/** Optional TraceManager for centralized trace recording */
	private traceManager: TraceManager | null = null;

	constructor(emulator: UnicornWrapper, memoryManager: MemoryManager, arch: ArchitectureType) {
		this.emulator = emulator;
		this.memoryManager = memoryManager;
		this.architecture = arch;
		this.registerAllHandlers();
	}

	/**
	 * Set the image base for getauxval-like queries
	 */
	setImageBase(base: bigint): void {
		this.imageBase = base;
	}

	/**
	 * Set stdin buffer content for scanf/read emulation.
	 * Multiple inputs can be separated by newlines.
	 */
	setStdinBuffer(input: string): void {
		this.stdinBuffer = input;
		this.stdinOffset = 0;
	}

	setMainReturnAddress(address: bigint | null): void {
		this.mainReturnAddress = address;
	}

	/**
	 * Set the TraceManager instance for centralized trace recording.
	 */
	setTraceManager(manager: TraceManager): void {
		this.traceManager = manager;
	}

	/**
	 * Read a line from the stdin buffer (for scanf/fgets emulation).
	 * Returns empty string if buffer is exhausted.
	 */
	private readStdinLine(): string {
		if (this.stdinOffset >= this.stdinBuffer.length) {
			return '';
		}
		const nlIdx = this.stdinBuffer.indexOf('\n', this.stdinOffset);
		let line: string;
		if (nlIdx >= 0) {
			line = this.stdinBuffer.substring(this.stdinOffset, nlIdx);
			this.stdinOffset = nlIdx + 1;
		} else {
			line = this.stdinBuffer.substring(this.stdinOffset);
			this.stdinOffset = this.stdinBuffer.length;
		}
		return line;
	}

	/**
	 * Read N bytes from stdin buffer (for read() syscall).
	 */
	private readStdinBytes(count: number): string {
		if (this.stdinOffset >= this.stdinBuffer.length) {
			return '';
		}
		const end = Math.min(this.stdinOffset + count, this.stdinBuffer.length);
		const data = this.stdinBuffer.substring(this.stdinOffset, end);
		this.stdinOffset = end;
		return data;
	}

	/**
	 * Check if the last handler wants to redirect execution (e.g. __libc_start_main → main).
	 * Returns the target address or null if normal return flow should be used.
	 */
	getRedirectAddress(): bigint | null {
		const addr = this._redirectAddress;
		this._redirectAddress = null;
		return addr;
	}

	/**
	 * Handle a libc API call at a stub address.
	 * Reads arguments via System V AMD64 ABI (RDI, RSI, RDX, RCX, R8, R9, stack)
	 */
	handleCall(library: string, name: string): bigint {
		const key = name.toLowerCase();

		const handler = this.handlers.get(key);

		// Reset redirect address
		this._redirectAddress = null;

		// Read arguments based on System V AMD64 ABI
		const args = this.readArguments(6);

		let returnValue = 0n;
		if (handler) {
			try {
				returnValue = handler(args);
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				console.warn(`[linuxApiHooks] Handler error for ${library}!${name}: ${message}`);
				returnValue = 0n;
			}
		} else {
			// Unknown API - return 0 and log it
			console.log(`Unhandled libc: ${library}!${name}`);
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
			dll: library,
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
				library,
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
	 * Read function arguments based on System V AMD64 ABI
	 * x64: RDI, RSI, RDX, RCX, R8, R9, then stack
	 * x86: all on stack (cdecl)
	 */
	private readArguments(count: number): bigint[] {
		const args: bigint[] = [];

		if (this.architecture === 'x64') {
			// System V AMD64 ABI: RDI, RSI, RDX, RCX, R8, R9
			const regs = this.emulator.getRegistersX64();
			args.push(regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9);

			// Read remaining args from stack (RSP + 8, +16, ...)
			for (let i = 6; i < count; i++) {
				const stackOffset = regs.rsp + BigInt(8 + (i - 6) * 8);
				try {
					const buf = this.emulator.readMemorySync(stackOffset, 8);
					args.push(buf.readBigUInt64LE());
				} catch {
					args.push(0n);
				}
			}
		} else {
			// x86 cdecl: all args on stack (ESP + 4, +8, +12, ...)
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
	 * Read a null-terminated string from emulator memory
	 */
	private readString(address: bigint, maxLen: number = 1024): string {
		if (address === 0n) { return ''; }
		try {
			const buf = this.emulator.readMemorySync(address, maxLen);
			const nullIdx = buf.indexOf(0);
			if (nullIdx === 0) {
				console.log(`[readString] string at 0x${address.toString(16)} is EMPTY (starts with null byte)`);
				this.stdoutBuffer += `[DEBUG readString] string at 0x${address.toString(16)} is EMPTY\n`;
			}
			return buf.toString('utf8', 0, nullIdx >= 0 ? nullIdx : maxLen);
		} catch (err) {
			console.log(`[readString] failed to read from 0x${address.toString(16)}: ${err}`);
			this.stdoutBuffer += `[DEBUG readString] failed to read 0x${address.toString(16)}: ${err}\n`;
			return '';
		}
	}

	/**
	 * Write a null-terminated string to emulator memory
	 */
	private writeString(address: bigint, str: string): void {
		const buf = Buffer.alloc(str.length + 1);
		buf.write(str, 'ascii');
		buf[str.length] = 0;
		this.emulator.writeMemorySync(address, buf);
	}

	/**
	 * Register all libc handlers
	 */
	private registerAllHandlers(): void {
		// ============ I/O Functions ============

		// int puts(const char *s) - print string + newline
		this.handlers.set('puts', (args) => {
			const str = this.readString(args[0]);
			console.log(`[stdout] ${str}`);
			this.stdoutBuffer += str + '\n';
			return BigInt(str.length + 1);
		});

		// int printf(const char *format, ...) - formatted output
		this.handlers.set('printf', (args) => {
			const format = this.readString(args[0]);
			// Simple format string handling
			const output = this.simpleFormat(format, args.slice(1));
			console.log(`[stdout] ${output}`);
			this.stdoutBuffer += output;
			return BigInt(output.length);
		});

		// int fprintf(FILE *stream, const char *format, ...)
		this.handlers.set('fprintf', (args) => {
			const format = this.readString(args[1]);
			const output = this.simpleFormat(format, args.slice(2));
			console.log(`[stream] ${output}`);
			return BigInt(output.length);
		});

		// int sprintf(char *str, const char *format, ...)
		this.handlers.set('sprintf', (args) => {
			const str = this.formatString(args[1], args, 2);
			this.writeString(args[0], str);
			return BigInt(str.length);
		});

		// int snprintf(char *str, size_t size, const char *format, ...)
		this.handlers.set('snprintf', (args) => {
			const size = Number(args[1]);
			if (size === 0) {
				const str = this.formatString(args[2], args, 3);
				return BigInt(str.length); // POSIX: return what *would* have been written
			}
			let str = this.formatString(args[2], args, 3);
			if (str.length >= size) {
				str = str.substring(0, size - 1);
			}
			this.writeString(args[0], str);
			return BigInt(str.length);
		});

		// int __printf_chk(int flag, const char *format, ...)
		// This is a secure version of printf. args[0] is the flag.
		// args[1] is the format string. args[2...] are the format arguments.
		this.handlers.set('__printf_chk', (args) => {
			const formatStr = this.readString(args[1]);
			this.stdoutBuffer += `[DEBUG __printf_chk] flag: ${args[0]}, format_ptr: 0x${args[1].toString(16)}, formatStr: ${formatStr}, a2: 0x${args[2].toString(16)}\n`;

			const str = this.formatString(args[1], args, 2);
			this.stdoutBuffer += `[DEBUG resulting string] ${str}\n`;
			this.stdoutBuffer += str;
			return BigInt(str.length);
		});

		// ssize_t write(int fd, const void *buf, size_t count)
		this.handlers.set('write', (args) => {
			const fd = Number(args[0]);
			const count = Number(args[2]);
			if (count <= 0 || count > 0x10000) { return 0n; }
			try {
				const data = this.emulator.readMemorySync(args[1], count);
				const str = data.toString('utf8');
				if (fd === 1 || fd === 2) {
					console.log(`[fd${fd}] ${str}`);
					if (fd === 1) { this.stdoutBuffer += str; }
				}
				return BigInt(count);
			} catch {
				return BigInt(-1);
			}
		});

		// ssize_t read(int fd, void *buf, size_t count)
		this.handlers.set('read', (args) => {
			const fd = Number(args[0]);
			const bufAddr = args[1];
			const count = Number(args[2]);

			if (fd === 0) {
				// stdin - read from stdin buffer
				const data = this.readStdinBytes(count);
				if (data.length === 0) {
					console.log('[stdin] read(0): stdin buffer exhausted, returning 0 (EOF)');
					return 0n;
				}
				try {
					const buf = Buffer.from(data, 'utf8');
					this.emulator.writeMemorySync(bufAddr, buf);
					console.log(`[stdin] read(0): ${data.length} bytes`);
					return BigInt(data.length);
				} catch {
					return BigInt(-1);
				}
			}
			// Other fds - not supported
			return 0n;
		});

		// int scanf(const char *format, ...)
		// Supports %d, %s, %x, %c, %f (basic emulation)
		const scanfHandler = (args: bigint[]): bigint => {
			const fmt = this.readString(args[0]);
			const line = this.readStdinLine();

			if (line.length === 0) {
				console.log(`[stdin] scanf("${fmt}"): stdin buffer exhausted, returning 0`);
				return 0n;
			}

			console.log(`[stdin] scanf("${fmt}"): input="${line}"`);

			// Parse format specifiers and write values to argument pointers
			let itemsRead = 0;
			let argIdx = 1; // args[1] is the first output pointer
			let inputPos = 0;

			const specRegex = /%(\d*)(l{0,2})([diouxXeEfgGscpn%])/g;
			let match;

			while ((match = specRegex.exec(fmt)) !== null) {
				const longMod = match[2];
				const spec = match[3];

				// Skip whitespace in input
				while (inputPos < line.length && line[inputPos] === ' ') { inputPos++; }
				if (inputPos >= line.length && spec !== '%') { break; }

				const destAddr = args[argIdx];
				if (!destAddr || destAddr === 0n) { argIdx++; continue; }

				try {
					if (spec === 'd' || spec === 'i') {
						// Integer
						const numMatch = line.substring(inputPos).match(/^-?\d+/);
						if (!numMatch) { break; }
						const val = parseInt(numMatch[0], 10);
						inputPos += numMatch[0].length;

						const isLong = longMod === 'l' || longMod === 'll';
						if (isLong) {
							const buf = Buffer.alloc(8);
							buf.writeBigInt64LE(BigInt(val));
							this.emulator.writeMemorySync(destAddr, buf);
						} else {
							const buf = Buffer.alloc(4);
							buf.writeInt32LE(val);
							this.emulator.writeMemorySync(destAddr, buf);
						}
						itemsRead++;
					} else if (spec === 'u') {
						const numMatch = line.substring(inputPos).match(/^\d+/);
						if (!numMatch) { break; }
						const val = parseInt(numMatch[0], 10);
						inputPos += numMatch[0].length;

						const buf = Buffer.alloc(4);
						buf.writeUInt32LE(val >>> 0);
						this.emulator.writeMemorySync(destAddr, buf);
						itemsRead++;
					} else if (spec === 'x' || spec === 'X') {
						const hexMatch = line.substring(inputPos).match(/^(?:0[xX])?([0-9a-fA-F]+)/);
						if (!hexMatch) { break; }
						const val = parseInt(hexMatch[1], 16);
						inputPos += hexMatch[0].length;

						const buf = Buffer.alloc(4);
						buf.writeUInt32LE(val >>> 0);
						this.emulator.writeMemorySync(destAddr, buf);
						itemsRead++;
					} else if (spec === 's') {
						const strMatch = line.substring(inputPos).match(/^\S+/);
						if (!strMatch) { break; }
						inputPos += strMatch[0].length;

						const strBuf = Buffer.from(strMatch[0] + '\0', 'utf8');
						this.emulator.writeMemorySync(destAddr, strBuf);
						itemsRead++;
					} else if (spec === 'c') {
						if (inputPos < line.length) {
							const charBuf = Buffer.alloc(1);
							charBuf[0] = line.charCodeAt(inputPos);
							inputPos++;
							this.emulator.writeMemorySync(destAddr, charBuf);
							itemsRead++;
						}
					}
				} catch (e) {
					console.warn(`[stdin] scanf: failed to write to 0x${destAddr.toString(16)}: ${e}`);
					break;
				}

				argIdx++;
			}

			console.log(`[stdin] scanf: ${itemsRead} items read`);
			return BigInt(itemsRead);
		};

		this.handlers.set('__isoc99_scanf', scanfHandler);
		this.handlers.set('scanf', scanfHandler);
		this.handlers.set('sscanf', scanfHandler); // sscanf uses same pattern (approx)

		// int getchar(void)
		this.handlers.set('getchar', (_args) => {
			const data = this.readStdinBytes(1);
			if (data.length === 0) {
				return BigInt(-1); // EOF
			}
			return BigInt(data.charCodeAt(0));
		});

		// char *fgets(char *s, int size, FILE *stream)
		this.handlers.set('fgets', (args) => {
			const bufAddr = args[0];
			const size = Number(args[1]);

			const line = this.readStdinLine();
			if (line.length === 0) {
				return 0n; // NULL (EOF)
			}

			// Write line + newline + null terminator
			const toWrite = line.substring(0, size - 2) + '\n';
			try {
				const buf = Buffer.from(toWrite + '\0', 'utf8');
				this.emulator.writeMemorySync(bufAddr, buf);
				return bufAddr; // Return buffer pointer on success
			} catch {
				return 0n;
			}
		});

		// void perror(const char *s)
		this.handlers.set('perror', (args) => {
			const prefix = this.readString(args[0]);
			console.log(`[perror] ${prefix}: error ${this.lastErrno}`);
			return 0n;
		});

		// ============ String Functions ============

		// size_t strlen(const char *s)
		this.handlers.set('strlen', (args) => {
			const str = this.readString(args[0], 4096);
			return BigInt(str.length);
		});

		// char *strcpy(char *dest, const char *src)
		this.handlers.set('strcpy', (args) => {
			const src = this.readString(args[1], 4096);
			this.writeString(args[0], src);
			return args[0];
		});

		// char *strncpy(char *dest, const char *src, size_t n)
		this.handlers.set('strncpy', (args) => {
			const n = Number(args[2]);
			const src = this.readString(args[1], n);
			const buf = Buffer.alloc(n);
			buf.write(src, 'ascii');
			try { this.emulator.writeMemorySync(args[0], buf); } catch { }
			return args[0];
		});

		// int strcmp(const char *s1, const char *s2)
		this.handlers.set('strcmp', (args) => {
			const s1 = this.readString(args[0]);
			const s2 = this.readString(args[1]);
			if (s1 < s2) { return BigInt(-1) & 0xFFFFFFFFFFFFFFFFn; }
			if (s1 > s2) { return 1n; }
			return 0n;
		});

		// int strncmp(const char *s1, const char *s2, size_t n)
		this.handlers.set('strncmp', (args) => {
			const n = Number(args[2]);
			const s1 = this.readString(args[0], n).substring(0, n);
			const s2 = this.readString(args[1], n).substring(0, n);
			if (s1 < s2) { return BigInt(-1) & 0xFFFFFFFFFFFFFFFFn; }
			if (s1 > s2) { return 1n; }
			return 0n;
		});

		// char *strcat(char *dest, const char *src)
		this.handlers.set('strcat', (args) => {
			const dest = this.readString(args[0], 4096);
			const src = this.readString(args[1], 4096);
			this.writeString(args[0], dest + src);
			return args[0];
		});

		// char *strchr(const char *s, int c)
		this.handlers.set('strchr', (args) => {
			const s = this.readString(args[0], 4096);
			const c = String.fromCharCode(Number(args[1]) & 0xFF);
			const idx = s.indexOf(c);
			if (idx === -1) { return 0n; }
			return args[0] + BigInt(idx);
		});

		// char *strstr(const char *haystack, const char *needle)
		this.handlers.set('strstr', (args) => {
			const haystack = this.readString(args[0], 4096);
			const needle = this.readString(args[1], 256);
			const idx = haystack.indexOf(needle);
			if (idx === -1) { return 0n; }
			return args[0] + BigInt(idx);
		});

		// ============ Memory Functions ============

		// void *memcpy(void *dest, const void *src, size_t n)
		this.handlers.set('memcpy', (args) => {
			const n = Number(args[2]);
			if (n <= 0 || n > 0x1000000) { return args[0]; }
			try {
				const data = this.emulator.readMemorySync(args[1], n);
				this.emulator.writeMemorySync(args[0], data);
			} catch { }
			return args[0];
		});

		// void *memmove(void *dest, const void *src, size_t n)
		this.handlers.set('memmove', (args) => {
			const n = Number(args[2]);
			if (n <= 0 || n > 0x1000000) { return args[0]; }
			try {
				const data = Buffer.from(this.emulator.readMemorySync(args[1], n));
				this.emulator.writeMemorySync(args[0], data);
			} catch { }
			return args[0];
		});

		// void *memset(void *s, int c, size_t n)
		this.handlers.set('memset', (args) => {
			const c = Number(args[1]) & 0xFF;
			const n = Number(args[2]);
			if (n <= 0 || n > 0x1000000) { return args[0]; }
			try {
				const buf = Buffer.alloc(n, c);
				this.emulator.writeMemorySync(args[0], buf);
			} catch { }
			return args[0];
		});

		// int memcmp(const void *s1, const void *s2, size_t n)
		this.handlers.set('memcmp', (args) => {
			const n = Number(args[2]);
			if (n <= 0) { return 0n; }
			try {
				const b1 = this.emulator.readMemorySync(args[0], n);
				const b2 = this.emulator.readMemorySync(args[1], n);
				return BigInt(b1.compare(b2));
			} catch {
				return 0n;
			}
		});

		// ============ Heap Functions ============

		// void *malloc(size_t size)
		this.handlers.set('malloc', (args) => {
			const size = Number(args[0]);
			if (size <= 0 || size > 0x10000000) { return 0n; }
			return this.memoryManager.heapAlloc(size, false);
		});

		// void *calloc(size_t nmemb, size_t size)
		this.handlers.set('calloc', (args) => {
			const total = Number(args[0]) * Number(args[1]);
			if (total <= 0 || total > 0x10000000) { return 0n; }
			return this.memoryManager.heapAlloc(total, true); // zero-fill
		});

		// void *realloc(void *ptr, size_t size)
		this.handlers.set('realloc', (args) => {
			const ptr = args[0];
			const size = Number(args[1]);
			if (size <= 0) {
				if (ptr !== 0n) { this.memoryManager.heapFree(ptr); }
				return 0n;
			}
			// Simple realloc: allocate new, copy old data, free old
			const newPtr = this.memoryManager.heapAlloc(size, false);
			if (newPtr !== 0n && ptr !== 0n) {
				try {
					// Copy up to size bytes from old allocation
					const copySize = Math.min(size, 4096);
					const data = this.emulator.readMemorySync(ptr, copySize);
					this.emulator.writeMemorySync(newPtr, data);
				} catch { }
				this.memoryManager.heapFree(ptr);
			}
			return newPtr;
		});

		// void free(void *ptr)
		this.handlers.set('free', (args) => {
			if (args[0] !== 0n) {
				this.memoryManager.heapFree(args[0]);
			}
			return 0n;
		});

		// ============ Conversion Functions ============

		// long strtol(const char *nptr, char **endptr, int base)
		this.handlers.set('strtol', (args) => {
			const str = this.readString(args[0], 64);
			const base = Number(args[2]);
			try {
				const result = parseInt(str, base || 10);
				if (isNaN(result)) { return 0n; }
				return BigInt(result) & 0xFFFFFFFFFFFFFFFFn;
			} catch {
				return 0n;
			}
		});

		// int atoi(const char *nptr)
		this.handlers.set('atoi', (args) => {
			const str = this.readString(args[0], 32);
			const result = parseInt(str, 10);
			if (isNaN(result)) { return 0n; }
			return BigInt(result) & 0xFFFFFFFFn;
		});

		// long atol(const char *nptr)
		this.handlers.set('atol', (args) => {
			const str = this.readString(args[0], 32);
			const result = parseInt(str, 10);
			if (isNaN(result)) { return 0n; }
			return BigInt(result) & 0xFFFFFFFFFFFFFFFFn;
		});

		// ============ Process Functions ============

		// void exit(int status)
		this.handlers.set('exit', (args) => {
			const code = Number(args[0]);
			console.log(`[exit] Process exited with code ${code}`);
			this.emulator.stop();
			return 0n;
		});

		// void _exit(int status)
		this.handlers.set('_exit', (args) => {
			const code = Number(args[0]);
			console.log(`[exit] _exit(${code})`);
			this.emulator.stop();
			return 0n;
		});

		// void abort(void)
		this.handlers.set('abort', (_args) => {
			console.log('[abort] Process aborted');
			this.emulator.stop();
			return 0n;
		});

		// pid_t getpid(void)
		this.handlers.set('getpid', (_args) => {
			return 0x1000n; // Fake PID
		});

		// pid_t getppid(void)
		this.handlers.set('getppid', (_args) => {
			return 1n; // Fake parent PID (init)
		});

		// uid_t getuid(void)
		this.handlers.set('getuid', (_args) => {
			return 1000n; // Regular user
		});

		// uid_t geteuid(void)
		this.handlers.set('geteuid', (_args) => {
			return 1000n;
		});

		// ============ Stack Protection ============

		// void __stack_chk_fail(void) - stack canary check failure
		this.handlers.set('__stack_chk_fail', (_args) => {
			console.log('[SECURITY] Stack smashing detected - __stack_chk_fail called');
			this.emulator.stop();
			return 0n;
		});

		// ============ libc init ============

		// int __libc_start_main(main, argc, argv, init, fini, rtld_fini, stack_end)
		// This is the CRT entry that calls main(). We redirect execution to main directly.
		this.handlers.set('__libc_start_main', (args) => {
			try {
				// args[0] = main function pointer
				// args[1] = argc
				// args[2] = argv
				const mainAddr = args[0];
				const rawArgc = args[1];
				const rawArgv = args[2];

				// Keep argc in a sane range for analysis scenarios.
				const argc = rawArgc > 0n && rawArgc <= 1024n ? rawArgc : 1n;
				let argv = rawArgv;
				const pointerSize = this.architecture === 'x64' ? 8 : 4;

				// Validate argv pointer without writing memory. Native Unicorn binding
				// forbids memWrite/regWrite directly during active emulation callbacks.
				if (argv !== 0n) {
					try {
						this.emulator.readMemorySync(argv, pointerSize);
					} catch {
						argv = 0n;
					}
				}

				console.log(
					`[libc] __libc_start_main: main=0x${mainAddr.toString(16)}, argc=${argc}, argv=0x${argv.toString(16)}`
				);

				// Prepare main(argc, argv, envp) registers.
				// The wrapper applies queued register writes safely after emulation stops.
				if (this.architecture === 'x64') {
					this.emulator.setRegisterSync('rdi', argc);
					this.emulator.setRegisterSync('rsi', argv);
					this.emulator.setRegisterSync('rdx', 0n);

					// Ensure main() has a deterministic return target.
					// Without this, returning from main may jump to argc/garbage and fault.
					const regs = this.emulator.getRegistersX64();
					const syntheticReturn = this.mainReturnAddress ?? regs.rip;
					const newRsp = regs.rsp - 8n;
					const retBuf = Buffer.alloc(8);
					retBuf.writeBigUInt64LE(syntheticReturn);
					this.emulator.writeMemorySync(newRsp, retBuf);
					this.emulator.setRegisterSync('rsp', newRsp);
				}

				if (mainAddr === 0n) {
					this._redirectAddress = null;
					return 0n;
				}

				// Redirect execution to main() instead of returning to _start.
				this._redirectAddress = mainAddr;
				return 0n;
			} catch (error: unknown) {
				const message = error instanceof Error ? error.message : String(error);
				console.warn(`[linuxApiHooks] __libc_start_main handler failed: ${message}`);
				this._redirectAddress = null;
				return 0n;
			}
		});

		// ============ Math Functions ============

		// int abs(int n)
		this.handlers.set('abs', (args) => {
			const n = Number(args[0] & 0xFFFFFFFFn);
			const signed = n > 0x7FFFFFFF ? n - 0x100000000 : n;
			return BigInt(Math.abs(signed));
		});

		// ============ Environment ============

		// char *getenv(const char *name)
		this.handlers.set('getenv', (_args) => {
			return 0n; // NULL - no environment variables
		});

		// ============ Time Functions ============

		// time_t time(time_t *tloc)
		this.handlers.set('time', (args) => {
			const now = BigInt(Math.floor(Date.now() / 1000));
			if (args[0] !== 0n) {
				try {
					const buf = Buffer.alloc(8);
					buf.writeBigInt64LE(now);
					this.emulator.writeMemorySync(args[0], buf);
				} catch { }
			}
			return now;
		});

		// int clock_gettime(clockid_t clk_id, struct timespec *tp)
		this.handlers.set('clock_gettime', (args) => {
			if (args[1] !== 0n) {
				try {
					const buf = Buffer.alloc(16);
					const now = Date.now();
					buf.writeBigInt64LE(BigInt(Math.floor(now / 1000)), 0); // tv_sec
					buf.writeBigInt64LE(BigInt((now % 1000) * 1000000), 8); // tv_nsec
					this.emulator.writeMemorySync(args[1], buf);
				} catch { }
			}
			return 0n; // Success
		});

		// unsigned int sleep(unsigned int seconds)
		this.handlers.set('sleep', (_args) => {
			return 0n; // No-op, return 0 (no remaining time)
		});

		// int usleep(useconds_t usec)
		this.handlers.set('usleep', (_args) => {
			return 0n; // No-op
		});

		// ============ File I/O (Stubs) ============

		// int open(const char *pathname, int flags, ...)
		this.handlers.set('open', (_args) => {
			return BigInt(-1); // -1 = error (ENOENT)
		});

		// int close(int fd)
		this.handlers.set('close', (_args) => {
			return 0n; // Success
		});

		// FILE *fopen(const char *pathname, const char *mode)
		this.handlers.set('fopen', (_args) => {
			return 0n; // NULL
		});

		// int fclose(FILE *stream)
		this.handlers.set('fclose', (_args) => {
			return 0n;
		});

		// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
		this.handlers.set('fread', (_args) => {
			return 0n;
		});

		// ssize_t getline(char **lineptr, size_t *n, FILE *stream)
		this.handlers.set('getline', (args) => {
			const lineptrAddr = args[0];
			const nAddr = args[1];
			// stream is args[2], ignored for now (assumed stdin)

			if (lineptrAddr === 0n || nAddr === 0n) {
				return BigInt(-1);
			}

			// Read from our stdin buffer up to the next newline
			let lineStr = '';
			const remaining = this.stdinBuffer.length - this.stdinOffset;
			if (remaining <= 0) {
				return BigInt(-1); // EOF
			}

			const nextNewline = this.stdinBuffer.indexOf('\n', this.stdinOffset);
			if (nextNewline !== -1) {
				lineStr = this.stdinBuffer.substring(this.stdinOffset, nextNewline + 1);
				this.stdinOffset = nextNewline + 1;
			} else {
				lineStr = this.stdinBuffer.substring(this.stdinOffset);
				this.stdinOffset = this.stdinBuffer.length;
			}

			const lineBuf = Buffer.from(lineStr + '\0', 'utf8');
			const requiredSize = lineBuf.length;

			try {
				const ptrBuf = this.emulator.readMemorySync(lineptrAddr, 8);
				let lineptr = ptrBuf.readBigUInt64LE();

				const sizeBuf = this.emulator.readMemorySync(nAddr, 8);
				let n = Number(sizeBuf.readBigUInt64LE());

				if (lineptr === 0n || n < requiredSize) {
					// Allocate or reallocate
					if (lineptr !== 0n) {
						this.memoryManager.heapFree(lineptr);
					}
					n = Math.max(requiredSize, 128); // minimum 128 bytes
					lineptr = this.memoryManager.heapAlloc(n, false);

					// Write back the new pointer and size
					const newPtrBuf = Buffer.alloc(8);
					newPtrBuf.writeBigUInt64LE(lineptr);
					this.emulator.writeMemorySync(lineptrAddr, newPtrBuf);

					const newSizeBuf = Buffer.alloc(8);
					newSizeBuf.writeBigUInt64LE(BigInt(n));
					this.emulator.writeMemorySync(nAddr, newSizeBuf);
				}

				// Write the string data to the buffer
				this.emulator.writeMemorySync(lineptr, lineBuf);

				// Return characters written (excluding null terminator)
				return BigInt(lineBuf.length - 1);
			} catch (err) {
				console.warn(`[linuxApiHooks] getline failed: ${err}`);
				return BigInt(-1);
			}
		});

		// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
		this.handlers.set('fwrite', (args) => {
			const size = Number(args[1]);
			const nmemb = Number(args[2]);
			const total = size * nmemb;
			if (total > 0 && total < 0x10000) {
				try {
					const data = this.emulator.readMemorySync(args[0], total);
					console.log(`[fwrite] ${data.toString('utf8')}`);
				} catch { }
			}
			return BigInt(nmemb);
		});

		// ============ mmap/mprotect ============

		// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
		this.handlers.set('mmap', (args) => {
			const length = Number(args[1]);
			const prot = Number(args[2]);
			if (length <= 0 || length > 0x10000000) {
				return BigInt(-1) & 0xFFFFFFFFFFFFFFFFn; // MAP_FAILED
			}

			// Convert mmap prot to Unicorn prot
			let ucProt = 0;
			if (prot & 1) { ucProt |= 1; } // PROT_READ
			if (prot & 2) { ucProt |= 2; } // PROT_WRITE
			if (prot & 4) { ucProt |= 4; } // PROT_EXEC

			const addr = this.nextMmapBase;
			const pageSize = BigInt(this.emulator.getPageSize());
			const alignedSize = ((BigInt(length) + pageSize - 1n) / pageSize) * pageSize;

			try {
				this.emulator.mapMemoryRaw(addr, Number(alignedSize), ucProt || 1);
				this.memoryManager.trackAllocation(addr, Number(alignedSize), ucProt || 1, 'mmap');
				this.nextMmapBase += alignedSize;
				return addr;
			} catch {
				return BigInt(-1) & 0xFFFFFFFFFFFFFFFFn;
			}
		});

		// int munmap(void *addr, size_t length)
		this.handlers.set('munmap', (_args) => {
			return 0n; // Success (we don't actually unmap)
		});

		// int mprotect(void *addr, size_t len, int prot)
		this.handlers.set('mprotect', (args) => {
			const prot = Number(args[2]);
			let ucProt = 0;
			if (prot & 1) { ucProt |= 1; }
			if (prot & 2) { ucProt |= 2; }
			if (prot & 4) { ucProt |= 4; }
			try {
				this.emulator.memProtect(args[0], Number(args[1]), ucProt || 1);
				return 0n;
			} catch {
				return BigInt(-1) & 0xFFFFFFFFFFFFFFFFn;
			}
		});
	}

	/**
	 * Read formatting string from memory and expand it using simpleFormat.
	 */
	private formatString(formatAddr: bigint, args: bigint[], argsStartIndex: number): string {
		const format = this.readString(formatAddr);
		return this.simpleFormat(format, args.slice(argsStartIndex));
	}

	/**
	 * Simple printf-style format string expansion.
	 * Handles %s, %d, %x, %u, %p, %c, %ld, %lu, %lx, %lld, %%
	 */
	private simpleFormat(format: string, args: bigint[]): string {
		let result = '';
		let argIdx = 0;
		let i = 0;

		while (i < format.length) {
			if (format[i] === '%') {
				i++;
				if (i >= format.length) { break; }

				// Skip flags and width
				while (i < format.length && '-+0 #'.includes(format[i])) { i++; }
				while (i < format.length && format[i] >= '0' && format[i] <= '9') { i++; }
				if (i < format.length && format[i] === '.') {
					i++;
					while (i < format.length && format[i] >= '0' && format[i] <= '9') { i++; }
				}

				// Skip length modifiers
				let isLong = false;
				if (i < format.length && (format[i] === 'l' || format[i] === 'h' || format[i] === 'z')) {
					isLong = format[i] === 'l';
					i++;
					if (i < format.length && format[i] === 'l') { i++; } // ll
				}

				if (i >= format.length) { break; }
				const spec = format[i];
				const arg = argIdx < args.length ? args[argIdx] : 0n;

				switch (spec) {
					case '%':
						result += '%';
						break;
					case 's': {
						result += this.readString(arg, 256);
						argIdx++;
						break;
					}
					case 'd':
					case 'i': {
						const val = Number(arg & 0xFFFFFFFFn);
						const signed = val > 0x7FFFFFFF ? val - 0x100000000 : val;
						result += signed.toString();
						argIdx++;
						break;
					}
					case 'u': {
						result += (arg & 0xFFFFFFFFn).toString();
						argIdx++;
						break;
					}
					case 'x': {
						result += (arg & 0xFFFFFFFFn).toString(16);
						argIdx++;
						break;
					}
					case 'X': {
						result += (arg & 0xFFFFFFFFn).toString(16).toUpperCase();
						argIdx++;
						break;
					}
					case 'p': {
						result += '0x' + arg.toString(16);
						argIdx++;
						break;
					}
					case 'c': {
						result += String.fromCharCode(Number(arg & 0xFFn));
						argIdx++;
						break;
					}
					case 'n': {
						// %n - write count of chars written so far (security risk, skip)
						argIdx++;
						break;
					}
					default:
						result += '%' + spec;
						argIdx++;
						break;
				}
			} else {
				result += format[i];
			}
			i++;
		}

		return result;
	}

	/**
	 * Handle a Linux x64 syscall
	 * RAX = syscall number, args in RDI, RSI, RDX, R10, R8, R9
	 */
	handleSyscall(): bigint {
		const regs = this.emulator.getRegistersX64();
		const syscallNum = Number(regs.rax);
		const args = [regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9];

		let result = 0n;

		switch (syscallNum) {
			case 0: // read(fd, buf, count)
				result = 0n; // EOF
				break;
			case 1: { // write(fd, buf, count)
				const count = Number(args[2]);
				if (count > 0 && count < 0x10000) {
					try {
						const data = this.emulator.readMemorySync(args[1], count);
						const fd = Number(args[0]);
						console.log(`[syscall write fd${fd}] ${data.toString('utf8')}`);
						if (fd === 1) { this.stdoutBuffer += data.toString('utf8'); }
						result = BigInt(count);
					} catch {
						result = BigInt(-14); // -EFAULT
					}
				}
				break;
			}
			case 3: // close(fd)
				result = 0n;
				break;
			case 9: { // mmap
				const length = Number(args[1]);
				const prot = Number(args[2]);
				if (length > 0 && length < 0x10000000) {
					let ucProt = 0;
					if (prot & 1) { ucProt |= 1; }
					if (prot & 2) { ucProt |= 2; }
					if (prot & 4) { ucProt |= 4; }
					const addr = this.nextMmapBase;
					const pageSize = BigInt(this.emulator.getPageSize());
					const alignedSize = ((BigInt(length) + pageSize - 1n) / pageSize) * pageSize;
					try {
						this.emulator.mapMemoryRaw(addr, Number(alignedSize), ucProt || 1);
						this.memoryManager.trackAllocation(addr, Number(alignedSize), ucProt || 1, 'mmap-syscall');
						this.nextMmapBase += alignedSize;
						result = addr;
					} catch {
						result = BigInt(-12); // -ENOMEM
					}
				}
				break;
			}
			case 10: // mprotect
				result = 0n;
				break;
			case 11: // munmap
				result = 0n;
				break;
			case 12: { // brk
				result = 0x06000000n; // Return end of heap
				break;
			}
			case 39: // getpid
				result = 0x1000n;
				break;
			case 60: // exit
				console.log(`[syscall exit] code=${Number(args[0])}`);
				this.emulator.stop();
				result = 0n;
				break;
			case 102: // getuid
				result = 1000n;
				break;
			case 104: // getgid
				result = 1000n;
				break;
			case 107: // geteuid
				result = 1000n;
				break;
			case 108: // getegid
				result = 1000n;
				break;
			case 158: { // arch_prctl
				// Used for setting FS/GS base (TLS)
				// args[0] = code (ARCH_SET_FS=0x1002, ARCH_GET_FS=0x1003, ARCH_SET_GS=0x1001, ARCH_GET_GS=0x1004)
				// args[1] = addr
				const code = Number(args[0]);
				const addr = args[1];
				if (code === 0x1002) { // ARCH_SET_FS
					try {
						this.emulator.setRegisterSync('fs_base', addr);
						console.log(`[syscall] arch_prctl ARCH_SET_FS = 0x${addr.toString(16)}`);
					} catch (e) {
						console.warn(`[syscall] arch_prctl ARCH_SET_FS failed: ${e}`);
					}
				} else if (code === 0x1001) { // ARCH_SET_GS
					try {
						this.emulator.setRegisterSync('gs_base', addr);
						console.log(`[syscall] arch_prctl ARCH_SET_GS = 0x${addr.toString(16)}`);
					} catch (e) {
						console.warn(`[syscall] arch_prctl ARCH_SET_GS failed: ${e}`);
					}
				} else {
					console.log(`[syscall] arch_prctl code=0x${code.toString(16)} addr=0x${addr.toString(16)}`);
				}
				result = 0n;
				break;
			}
			case 231: // exit_group
				console.log(`[syscall exit_group] code=${Number(args[0])}`);
				this.emulator.stop();
				result = 0n;
				break;
			default:
				console.log(`[syscall] Unhandled syscall ${syscallNum}`);
				result = BigInt(-38); // -ENOSYS
				break;
		}

		this.callLog.push({
			dll: 'syscall',
			name: `sys_${syscallNum}`,
			args: args.slice(0, 3),
			returnValue: result,
			timestamp: Date.now(),
			arguments: args.slice(0, 3).map(a => '0x' + a.toString(16)),
			pcAddress: regs.rip,
		});

		// Notify TraceManager if available
		if (this.traceManager) {
			const entry: TraceEntry = {
				functionName: `sys_${syscallNum}`,
				library: 'syscall',
				arguments: args.slice(0, 3).map(a => '0x' + a.toString(16)),
				returnValue: '0x' + result.toString(16),
				pcAddress: '0x' + regs.rip.toString(16),
				timestamp: Date.now(),
			};
			this.traceManager.record(entry);
		}

		return result;
	}

	// ============ Public API ============

	getCallLog(): ApiCallLog[] {
		return this.callLog;
	}

	clearCallLog(): void {
		this.callLog = [];
	}

	getLastCall(): ApiCallLog | undefined {
		return this.callLog[this.callLog.length - 1];
	}

	hasHandler(name: string): boolean {
		return this.handlers.has(name.toLowerCase());
	}

	getStdoutBuffer(): string {
		return this.stdoutBuffer;
	}

	clearStdoutBuffer(): void {
		this.stdoutBuffer = '';
	}
}
