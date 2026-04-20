/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

/**
 * PE32 Unicorn Worker
 *
 * Runs the Unicorn engine in a separate child_process.fork() to avoid
 * Chromium UtilityProcess security restrictions (ACG / CFG) that cause
 * STATUS_HEAP_CORRUPTION (0xC0000374) when Unicorn's QEMU TCG backend
 * allocates executable memory for JIT code generation on PE32 binaries
 * (both x86 and x64).
 *
 * Communication with the parent (extension host) is via IPC messages.
 * All Unicorn API calls are serialized as { id, method, args } messages,
 * and results are sent back as { id, result } or { id, error }.
 *
 * BigInt values are serialized as strings prefixed with "BI:" to survive
 * JSON-based IPC (structured clone in Node.js IPC handles BigInt, but
 * we use a safe encoding for compatibility).
 *
 * Key difference from x64ElfWorker.js:
 * - executeBatch detects stub addresses (PE import stubs) instead of SYSCALL/INT 0x80
 * - Supports both x86 and x64 register reading (readAllX86Registers / readAllX64Registers)
 * - Auto-mapping heuristics handle both x86 (ESP/EBP/EIP) and x64 (RSP/RBP/RIP) registers
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
let currentArch = null; // Architecture from initialize() — used for register heuristics
let currentMode = null; // Architecture mode from initialize() — used for register heuristics
const hookCallbacks = new Map(); // hookHandle → native hook handle
let permissiveMemoryMapping = false; // When true, auto-map with RWX; when false, use restrictive perms

function collectCandidateDiagnostics(candidates, maxAddr) {
	if (!engine) {
		return { selected: 0n, candidates: [] };
	}

	let regions = [];
	try {
		regions = engine.memRegions();
	} catch {
		regions = [];
	}

	const diagnostics = [];
	let selected = 0n;

	for (const candidate of candidates) {
		try {
			const value = BigInt(engine.regRead(candidate.regId));
			const inRange = value >= 0x1000n && value <= maxAddr;
			const mapped = inRange && regions.some(r => {
				const begin = BigInt(r.begin);
				const end = BigInt(r.end);
				return value >= begin && value <= end;
			});
			diagnostics.push({
				register: candidate.name,
				value: value.toString(),
				inRange,
				mapped
			});
			if (selected === 0n && inRange && !mapped) {
				selected = value;
			}
		} catch (error) {
			diagnostics.push({
				register: candidate.name,
				error: error.message || String(error)
			});
		}
	}

	return { selected, candidates: diagnostics };
}

function firstUnmappedCandidate(regIds, maxAddr) {
	if (!engine) {
		return 0n;
	}

	let regions = [];
	try {
		regions = engine.memRegions();
	} catch {
		regions = [];
	}

	for (const regId of regIds) {
		try {
			const value = BigInt(engine.regRead(regId));
			if (value < 0x1000n || value > maxAddr) {
				continue;
			}
			const mapped = regions.some(r => {
				const begin = BigInt(r.begin);
				const end = BigInt(r.end);
				return value >= begin && value <= end;
			});
			if (!mapped) {
				return value;
			}
		} catch {
			// Ignore heuristic read failures.
		}
	}

	return 0n;
}

/**
 * Convert PE section characteristics to Unicorn protection flags.
 * Used when permissiveMemoryMapping is false to apply section-specific permissions.
 * @param {number} characteristics - PE section characteristics bitmask
 * @returns {number} Unicorn protection flags (UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
 */
function sectionPermsToUnicorn(characteristics) {
	// PE section characteristic flags
	const IMAGE_SCN_MEM_EXECUTE = 0x20000000;
	const IMAGE_SCN_MEM_READ = 0x40000000;
	const IMAGE_SCN_MEM_WRITE = 0x80000000;

	// UC_PROT constants: READ=1, WRITE=2, EXEC=4
	let perms = 0;
	if (characteristics & IMAGE_SCN_MEM_READ) { perms |= 1; }
	if (characteristics & IMAGE_SCN_MEM_WRITE) { perms |= 2; }
	if (characteristics & IMAGE_SCN_MEM_EXECUTE) { perms |= 4; }

	// Ensure at least read permission (sections without any flags are still readable)
	return perms || 1;
}

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
		currentArch = arch;
		currentMode = mode;
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

	// Set permissive memory mapping flag (Req 1.3: RWX for all PE sections when true)
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
		currentMode = null;
	},

	// Batch operation: execute N instructions sync with stub address detection
	// Returns: { pc, instructionsExecuted, stopped, error, stubHit, stubAddress }
	// Instead of detecting SYSCALL/INT 0x80 (ELF), PE32 detects when PC enters
	// a stub address range (PE import stubs) provided by the host.
	// terminalRanges: optional array of {start, end} pairs — if PC falls within any range, stop.
	executeBatch(startPc, count, terminalAddresses, terminalRanges, stubRangeStart, stubRangeEnd, additionalStubRanges) {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}

		const X86_REG = uc.X86_REG;
		const isX86Mode =
			currentArch === uc.ARCH.X86 &&
			currentMode === uc.MODE.MODE_32;
		const pcReg = isX86Mode ? X86_REG.EIP : X86_REG.RIP;

		const results = {
			pc: startPc,
			instructionsExecuted: 0,
			stopped: false,
			error: null,
			stubHit: false,
			stubAddress: null,
			faultInfo: null
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

		// Parse stub range for PE import stub detection
		const stubStart = stubRangeStart !== undefined && stubRangeStart !== null ? BigInt(stubRangeStart) : null;
		const stubEnd = stubRangeEnd !== undefined && stubRangeEnd !== null ? BigInt(stubRangeEnd) : null;
		// v3.8.0-nightly: additional stub ranges (e.g. synthetic DLL region
		// 0x72000000..0x72040000). Hash-resolving shellcode jumps into these
		// ranges after resolving exports from the synth PE; without this
		// check, PC lands in the range but the worker doesn't yield to the
		// host, so the RET stub runs and returns garbage.
		const extraRanges = [];
		if (Array.isArray(additionalStubRanges)) {
			for (const r of additionalStubRanges) {
				extraRanges.push({ start: BigInt(r.start), end: BigInt(r.end) });
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

			// Stub address detection — when PC enters the stub range, return to host for API dispatch
			if (stubStart !== null && stubEnd !== null && currentPc >= stubStart && currentPc < stubEnd) {
				results.stubHit = true;
				results.stubAddress = currentPc;
				results.pc = currentPc;
				return results;
			}
			// Additional stub ranges (synthetic DLL export stubs)
			for (const r of extraRanges) {
				if (currentPc >= r.start && currentPc < r.end) {
					results.stubHit = true;
					results.stubAddress = currentPc;
					results.pc = currentPc;
					return results;
				}
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
					let candidateDiagnostics = [];
					let attemptedMap = false;
					let selectedAutoMapPerms = null;
					let alignedAddress = null;

					if (errCode === 8) {
						// UC_ERR_FETCH_UNMAPPED: PC points to unmapped code
						faultAddr = BigInt(engine.regRead(pcReg));
					} else if (isX86Mode) {
						const candidateSet = [
							{ name: 'esp', regId: X86_REG.ESP },
							{ name: 'ebp', regId: X86_REG.EBP },
							{ name: 'ecx', regId: X86_REG.ECX },
							{ name: 'edx', regId: X86_REG.EDX },
							{ name: 'esi', regId: X86_REG.ESI },
							{ name: 'edi', regId: X86_REG.EDI },
							{ name: 'eax', regId: X86_REG.EAX },
							{ name: 'ebx', regId: X86_REG.EBX },
							{ name: 'eip', regId: X86_REG.EIP }
						];
						const candidateResult = collectCandidateDiagnostics(candidateSet, 0xFFFFFFFFn);
						faultAddr = candidateResult.selected;
						candidateDiagnostics = candidateResult.candidates;
					} else {
						const candidateSet = [
							{ name: 'rsp', regId: X86_REG.RSP },
							{ name: 'rbp', regId: X86_REG.RBP },
							{ name: 'rcx', regId: X86_REG.RCX },
							{ name: 'rdx', regId: X86_REG.RDX },
							{ name: 'r8', regId: X86_REG.R8 },
							{ name: 'r9', regId: X86_REG.R9 },
							{ name: 'rsi', regId: X86_REG.RSI },
							{ name: 'rdi', regId: X86_REG.RDI },
							{ name: 'rax', regId: X86_REG.RAX },
							{ name: 'rbx', regId: X86_REG.RBX },
							{ name: 'r10', regId: X86_REG.R10 },
							{ name: 'r11', regId: X86_REG.R11 },
							{ name: 'r12', regId: X86_REG.R12 },
							{ name: 'r13', regId: X86_REG.R13 },
							{ name: 'r14', regId: X86_REG.R14 },
							{ name: 'r15', regId: X86_REG.R15 },
							{ name: 'rip', regId: X86_REG.RIP }
						];
						const candidateResult = collectCandidateDiagnostics(candidateSet, 0x00007FFFFFFFFFFFn);
						faultAddr = candidateResult.selected;
						candidateDiagnostics = candidateResult.candidates;
					}

					// Reject NULL page and very high addresses
					const maxAddr = isX86Mode ? 0xFFFFFFFFn : 0x00007FFFFFFFFFFFn;
					if (faultAddr >= 0x1000n && faultAddr <= maxAddr) {
						const pageSize = BigInt(engine.pageSize);
						const aligned = (faultAddr / pageSize) * pageSize;
						alignedAddress = aligned.toString();
						// When permissiveMemoryMapping is true, map with RWX (UC_PROT_ALL = 7).
						// When false, map with read+write only (no execute) to preserve
						// section permission semantics and catch UC_ERR_FETCH_PROT on
						// non-executable regions.
						const autoMapPerms = permissiveMemoryMapping ? 7 : 3; // 7=RWX, 3=RW
						selectedAutoMapPerms = autoMapPerms;
						try {
							attemptedMap = true;
							engine.memMap(aligned, Number(pageSize), autoMapPerms);
							i--; // Retry this instruction
							continue;
						} catch { /* fall through to error */ }
					}

					results.faultInfo = {
						errCode,
						currentPc: currentPc.toString(),
						faultAddress: faultAddr.toString(),
						alignedAddress,
						permissiveMemoryMapping,
						attemptedMap,
						autoMapPerms: selectedAutoMapPerms,
						candidates: candidateDiagnostics
					};
				}

				results.error = msg;
				break;
			}

			results.instructionsExecuted++;
			currentPc = BigInt(engine.regRead(pcReg));
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

	// Read all x86 (32-bit) registers in one call
	readAllX86Registers() {
		if (!engine || !uc) {
			throw new Error('Engine not initialized');
		}
		const R = uc.X86_REG;
		const regs = {};
		regs.eax = engine.regRead(R.EAX);
		regs.ebx = engine.regRead(R.EBX);
		regs.ecx = engine.regRead(R.ECX);
		regs.edx = engine.regRead(R.EDX);
		regs.esi = engine.regRead(R.ESI);
		regs.edi = engine.regRead(R.EDI);
		regs.ebp = engine.regRead(R.EBP);
		regs.esp = engine.regRead(R.ESP);
		regs.eip = engine.regRead(R.EIP);
		regs.eflags = engine.regRead(R.EFLAGS);
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
