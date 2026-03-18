/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * x64 ELF Unicorn Worker
 *
 * Runs the Unicorn engine in a separate child_process.fork() to avoid
 * Chromium UtilityProcess security restrictions (ACG / CFG) that cause
 * STATUS_HEAP_CORRUPTION (0xC0000374) when Unicorn's QEMU TCG backend
 * allocates executable memory for JIT code generation on x64 ELF binaries.
 *
 * Communication with the parent (extension host) is via IPC messages.
 * All Unicorn API calls are serialized as { id, method, args } messages,
 * and results are sent back as { id, result } or { id, error }.
 *
 * BigInt values are serialized as strings prefixed with "BI:" to survive
 * JSON-based IPC (structured clone in Node.js IPC handles BigInt, but
 * we use a safe encoding for compatibility).
 */

const path = require('path');

// ---- BigInt-safe serialization ----

function serialize(value) {
	if (typeof value === 'bigint') {
		return 'BI:' + value.toString();
	}
	if (value === null || value === undefined) {
		return value;
	}
	if (Buffer.isBuffer(value)) {
		return { __type: 'Buffer', data: value.toString('base64') };
	}
	if (Array.isArray(value)) {
		return value.map(serialize);
	}
	if (typeof value === 'object') {
		const result = {};
		for (const key of Object.keys(value)) {
			result[key] = serialize(value[key]);
		}
		return result;
	}
	return value;
}

function deserialize(value) {
	if (typeof value === 'string' && value.startsWith('BI:')) {
		return BigInt(value.slice(3));
	}
	if (value === null || value === undefined) {
		return value;
	}
	if (typeof value === 'object' && value.__type === 'Buffer') {
		return Buffer.from(value.data, 'base64');
	}
	if (Array.isArray(value)) {
		return value.map(deserialize);
	}
	if (typeof value === 'object') {
		const result = {};
		for (const key of Object.keys(value)) {
			result[key] = deserialize(value[key]);
		}
		return result;
	}
	return value;
}

// ---- Unicorn Engine State ----

let uc = null;     // The hexcore-unicorn module
let engine = null; // The Unicorn instance
const hookCallbacks = new Map(); // hookHandle → native hook handle
let permissiveMemoryMapping = false; // When true, auto-map with RWX; when false, use restrictive perms

function loadModule() {
	const possiblePaths = [
		path.join(__dirname, '..', '..', 'hexcore-unicorn'),
		path.join(__dirname, '..', '..', '..', 'hexcore-unicorn'),
	];

	for (const p of possiblePaths) {
		try {
			uc = require(p);
			return;
		} catch { /* try next */ }
	}
	throw new Error('Failed to load hexcore-unicorn module');
}

// ---- Method Handlers ----

const handlers = {
	initialize(arch, mode) {
		if (!uc) {
			loadModule();
		}
		if (engine) {
			engine.close();
		}
		engine = new uc.Unicorn(arch, mode);
		return {
			handle: engine.handle,
			pageSize: engine.pageSize,
			version: uc.version().string
		};
	},

	getConstants() {
		if (!uc) {
			loadModule();
		}
		return {
			ARCH: uc.ARCH,
			MODE: uc.MODE,
			PROT: uc.PROT,
			HOOK: uc.HOOK,
			X86_REG: uc.X86_REG,
			ARM64_REG: uc.ARM64_REG
		};
	},

	// Set permissive memory mapping flag (Req 1.4: RWX for all ELF segments when true)
	setPermissiveMapping(flag) {
		permissiveMemoryMapping = !!flag;
	},

	version() {
		if (!uc) {
			loadModule();
		}
		return uc.version();
	},

	memMap(address, size, perms) {
		engine.memMap(BigInt(address), size, perms);
	},

	memRead(address, size) {
		return engine.memRead(BigInt(address), size);
	},

	memWrite(address, data) {
		engine.memWrite(BigInt(address), data);
	},

	memProtect(address, size, perms) {
		engine.memProtect(BigInt(address), size, perms);
	},

	memRegions() {
		return engine.memRegions();
	},

	regRead(regId) {
		return engine.regRead(regId);
	},

	regWrite(regId, value) {
		// Value may be bigint or number
		engine.regWrite(regId, typeof value === 'string' ? BigInt(value) : value);
	},

	emuStart(begin, until, timeout, count) {
		engine.emuStart(BigInt(begin), BigInt(until), timeout || 0, count || 0);
	},

	emuStop() {
		engine.emuStop();
	},

	hookAdd(type, begin, end) {
		const handle = engine.hookAdd(type, (...args) => {
			process.send({ type: 'hook-event', hookType: type, args: serialize(args) });
		}, begin ? BigInt(begin) : undefined, end ? BigInt(end) : undefined);
		return handle;
	},

	hookDel(handle) {
		engine.hookDel(handle);
	},

	contextSave() {
		const ctx = engine.contextSave();
		const id = Date.now();
		if (!handlers._contexts) {
			handlers._contexts = new Map();
		}
		handlers._contexts.set(id, ctx);
		return id;
	},

	contextRestore(contextId) {
		const ctx = handlers._contexts?.get(contextId);
		if (!ctx) {
			throw new Error('Context not found');
		}
		engine.contextRestore(ctx);
	},

	contextFree(contextId) {
		const ctx = handlers._contexts?.get(contextId);
		if (ctx) {
			ctx.free();
			handlers._contexts.delete(contextId);
		}
	},

	close() {
		if (engine) {
			engine.close();
			engine = null;
		}
	},

	// Batch operation: execute N instructions sync with SYSCALL/INT 0x80 detection
	// Returns: { pc, instructionsExecuted, stopped, error, syscallEncountered, syscallPc, syscallType }
	// terminalRanges: optional array of [start, end) pairs — if PC falls within any range, stop.
	executeBatch(startPc, count, terminalAddresses, terminalRanges) {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}

		const X86_REG = uc.X86_REG;
		const results = {
			pc: startPc,
			instructionsExecuted: 0,
			stopped: false,
			error: null,
			syscallEncountered: false,
			syscallPc: null,
			syscallType: null
		};

		const terminals = new Set(terminalAddresses.map(a => BigInt(a)));
		// Add well-known terminal addresses
		terminals.add(0n);
		terminals.add(0xDEAD0000n);
		terminals.add(0xDEADDEADn);
		terminals.add(0xDEADDEADDEADDEADn);

		// Parse terminal ranges (array of {start, end} objects)
		const ranges = [];
		if (Array.isArray(terminalRanges)) {
			for (const r of terminalRanges) {
				ranges.push({ start: BigInt(r.start), end: BigInt(r.end) });
			}
		}

		let currentPc = BigInt(startPc);

		for (let i = 0; i < count; i++) {
			// Terminal address check (exact match)
			if (terminals.has(currentPc)) {
				results.stopped = true;
				break;
			}

			// Terminal range check — stop if PC is within any [start, end) range
			let inRange = false;
			for (const r of ranges) {
				if (currentPc >= r.start && currentPc < r.end) {
					inRange = true;
					break;
				}
			}
			if (inRange) {
				results.stopped = true;
				break;
			}

			// Read 2 bytes at PC to detect SYSCALL / INT 0x80
			try {
				const opcodes = engine.memRead(currentPc, 2);
				const b0 = opcodes[0];
				const b1 = opcodes[1];

				// SYSCALL: 0x0F 0x05
				if (b0 === 0x0F && b1 === 0x05) {
					results.syscallEncountered = true;
					results.syscallPc = currentPc;
					results.syscallType = 'syscall';
					results.pc = currentPc;
					return results;
				}

				// INT 0x80: 0xCD 0x80
				if (b0 === 0xCD && b1 === 0x80) {
					results.syscallEncountered = true;
					results.syscallPc = currentPc;
					results.syscallType = 'int80';
					results.pc = currentPc;
					return results;
				}
			} catch {
				// Let emuStart handle unmapped memory
			}

			// Execute 1 instruction
			try {
				engine.emuStart(currentPc, 0n, 0, 1);
			} catch (error) {
				// Check for memory faults
				const msg = error.message || String(error);
				const codeMatch = /\(code:\s*([678])\)/.exec(msg);
				if (codeMatch) {
					const errCode = Number(codeMatch[1]);
					let faultAddr = 0n;

					if (errCode === 8) {
						// UC_ERR_FETCH_UNMAPPED: RIP points to unmapped code
						faultAddr = BigInt(engine.regRead(X86_REG.RIP));
					} else {
						// UC_ERR_READ_UNMAPPED / UC_ERR_WRITE_UNMAPPED:
						// Heuristic: RSP is the most common data fault source (stack access)
						faultAddr = BigInt(engine.regRead(X86_REG.RSP));

						// If RSP is in a low/null region, try RBP
						if (faultAddr < 0x1000n) {
							faultAddr = BigInt(engine.regRead(X86_REG.RBP));
						}

						// Last resort: use RIP
						if (faultAddr < 0x1000n) {
							faultAddr = BigInt(engine.regRead(X86_REG.RIP));
						}
					}

					// Reject NULL page and very high addresses
					if (faultAddr >= 0x1000n && faultAddr <= 0x00007FFFFFFFFFFFn) {
						const pageSize = BigInt(engine.pageSize);
						const aligned = (faultAddr / pageSize) * pageSize;
						// When permissiveMemoryMapping is true, map with RWX (UC_PROT_ALL = 7).
						// When false, map with read+write only (no execute) to preserve
						// segment permission semantics and catch UC_ERR_FETCH_PROT on
						// non-executable regions.
						const autoMapPerms = permissiveMemoryMapping ? 7 : 3; // 7=RWX, 3=RW
						try {
							engine.memMap(aligned, Number(pageSize), autoMapPerms);
							i--; // Retry this instruction
							continue;
						} catch { /* fall through to error */ }
					}
				}

				results.error = msg;
				break;
			}

			results.instructionsExecuted++;
			currentPc = BigInt(engine.regRead(X86_REG.RIP));
		}

		results.pc = currentPc;
		return results;
	},

	// Read all x64 registers in one call (avoids per-register IPC overhead)
	readAllX64Registers() {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}
		const R = uc.X86_REG;
		const regs = {};
		regs.rax = engine.regRead(R.RAX);
		regs.rbx = engine.regRead(R.RBX);
		regs.rcx = engine.regRead(R.RCX);
		regs.rdx = engine.regRead(R.RDX);
		regs.rsi = engine.regRead(R.RSI);
		regs.rdi = engine.regRead(R.RDI);
		regs.rbp = engine.regRead(R.RBP);
		regs.rsp = engine.regRead(R.RSP);
		regs.r8 = engine.regRead(R.R8);
		regs.r9 = engine.regRead(R.R9);
		regs.r10 = engine.regRead(R.R10);
		regs.r11 = engine.regRead(R.R11);
		regs.r12 = engine.regRead(R.R12);
		regs.r13 = engine.regRead(R.R13);
		regs.r14 = engine.regRead(R.R14);
		regs.r15 = engine.regRead(R.R15);
		regs.rip = engine.regRead(R.RIP);
		regs.rflags = engine.regRead(R.RFLAGS);
		return regs;
	},

	// Batch register write (avoids per-register IPC overhead)
	writeRegisters(regWrites) {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}
		const R = uc.X86_REG;
		for (const [name, value] of Object.entries(regWrites)) {
			const regId = R[name.toUpperCase()];
			if (regId !== undefined) {
				engine.regWrite(regId, BigInt(value));
			}
		}
	}
};

// ---- IPC Message Loop ----

process.on('message', (msg) => {
	const { id, method, args } = msg;

	try {
		const deserializedArgs = (args || []).map(deserialize);
		const result = handlers[method](...deserializedArgs);
		process.send({ id, result: serialize(result) });
	} catch (error) {
		process.send({ id, error: error.message || String(error) });
	}
});

// Signal ready
process.send({ type: 'ready' });
