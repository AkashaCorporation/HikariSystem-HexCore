/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * ARM64 Unicorn Worker
 *
 * Runs the Unicorn engine in a separate child_process.fork() to avoid
 * Chromium UtilityProcess security restrictions (ACG / CFG) that cause
 * STATUS_STACK_BUFFER_OVERRUN (0xC0000409) when Unicorn's QEMU TCG
 * backend allocates executable memory for JIT code generation.
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
let hookCallbacks = new Map(); // hookHandle → native hook handle

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
		// Hooks are handled specially — the callback is in the parent process.
		// For ARM64 sync execution, we don't use native hooks, so this is
		// primarily for non-ARM64 or future use.
		// For now, we add a native hook that sends an IPC message on each event.
		const handle = engine.hookAdd(type, (...args) => {
			// Serialize and send hook event to parent
			process.send({ type: 'hook-event', hookType: type, args: serialize(args) });
		}, begin ? BigInt(begin) : undefined, end ? BigInt(end) : undefined);
		return handle;
	},

	hookDel(handle) {
		engine.hookDel(handle);
	},

	contextSave() {
		const ctx = engine.contextSave();
		// Store context internally (can't serialize across IPC)
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

	// Batch operation: execute N instructions sync with SVC detection
	// Returns: { pc, instructionsExecuted, stopped, error, svcList }
	// svcList contains PCs where SVC was detected (caller handles syscall dispatch)
	executeBatch(startPc, count, svcMask, svcValue, terminalAddresses) {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}

		const ARM64_REG = uc.ARM64_REG;
		const results = {
			pc: startPc,
			instructionsExecuted: 0,
			stopped: false,
			error: null,
			svcEncountered: false,
			svcPc: null
		};

		const terminals = new Set(terminalAddresses.map(a => BigInt(a)));

		let currentPc = BigInt(startPc);

		for (let i = 0; i < count; i++) {
			// Terminal address check
			if (terminals.has(currentPc) || currentPc === 0n) {
				results.stopped = true;
				break;
			}

			// Read instruction
			let insn = 0;
			try {
				const insnBuf = engine.memRead(currentPc, 4);
				insn = insnBuf.readUInt32LE(0);
			} catch {
				// Let emuStart handle it
			}

			// SVC check
			if ((insn & svcMask) === svcValue) {
				// Don't execute SVC — return to parent for syscall dispatch
				results.svcEncountered = true;
				results.svcPc = currentPc;
				results.pc = currentPc;
				return results;
			}

			// Execute 1 instruction
			try {
				engine.emuStart(currentPc, 0n, 0, 1);
			} catch (error) {
				// Check for memory faults
				const msg = error.message || String(error);
				const codeMatch = /\(code:\s*([678])\)/.exec(msg);
				if (codeMatch) {
					// Auto-map the faulting page
					const errCode = Number(codeMatch[1]);
					let faultAddr = 0n;

					if (errCode === 8) {
						faultAddr = BigInt(engine.regRead(ARM64_REG.PC));
					} else {
						// Try to decode the base register from the instruction
						const pc = BigInt(engine.regRead(ARM64_REG.PC));
						try {
							const ib = engine.memRead(pc, 4);
							const ins = ib.readUInt32LE(0);
							const rn = (ins >> 5) & 0x1F;
							const regMap = {};
							for (let r = 0; r <= 28; r++) {
								regMap[r] = ARM64_REG[`X${r}`];
							}
							regMap[29] = ARM64_REG.X29;
							regMap[30] = ARM64_REG.X30;
							if (rn <= 30) {
								const bv = BigInt(engine.regRead(regMap[rn]));
								if (bv >= 0x1000n) {
									faultAddr = bv;
								}
							}
						} catch { /* fallback below */ }

						if (faultAddr === 0n) {
							faultAddr = BigInt(engine.regRead(ARM64_REG.SP));
						}
					}

					if (faultAddr >= 0x1000n && faultAddr <= 0x00007FFFFFFFFFFFn) {
						const pageSize = BigInt(engine.pageSize);
						const aligned = (faultAddr / pageSize) * pageSize;
						try {
							engine.memMap(aligned, Number(pageSize), uc.PROT.ALL);
							i--; // Retry
							continue;
						} catch { /* fall through to error */ }
					}
				}

				results.error = msg;
				break;
			}

			results.instructionsExecuted++;
			currentPc = BigInt(engine.regRead(ARM64_REG.PC));
		}

		results.pc = currentPc;
		return results;
	},

	// Read all ARM64 registers in one call (avoids per-register IPC overhead)
	readAllArm64Registers() {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}
		const R = uc.ARM64_REG;
		const regs = {};
		for (let i = 0; i <= 30; i++) {
			regs[`x${i}`] = engine.regRead(R[`X${i}`]);
		}
		regs.sp = engine.regRead(R.SP);
		regs.pc = engine.regRead(R.PC);
		regs.lr = engine.regRead(R.LR);
		regs.fp = engine.regRead(R.FP);
		regs.nzcv = engine.regRead(R.NZCV);
		return regs;
	},

	// Batch register write (avoids per-register IPC overhead)
	writeRegisters(regWrites) {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}
		const R = uc.ARM64_REG;
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
