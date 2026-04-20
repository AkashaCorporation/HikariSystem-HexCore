/*---------------------------------------------------------------------------------------------
 *  HexCore Pathfinder — CFG Recovery Engine (v3.8.0, v0.2.0)
 *
 *  Runs BEFORE the Remill lifter to produce CFGHints containing:
 *  - Function boundaries (from .pdata, .symtab)
 *  - Basic block leaders (from full-function decode + recursive descent)
 *  - Resolved jump tables
 *  - Tail call detection
 *  - NOP/padding ranges to skip
 *
 *  v0.2.0: Full-function linear decode for ARM64 (fixed-width instructions).
 *  Loads the entire function via .pdata/.symtab boundaries and extracts ALL
 *  branch targets in a single Capstone batch call. For x86, recursive descent
 *  is augmented with gap scanning for unreached code.
 *
 *  The Remill lifter consumes these hints via additionalLeaders + knownFunctionEnds
 *  to produce complete, accurate LLVM IR.
 *---------------------------------------------------------------------------------------------*/

import type { DisassemblerEngine } from './disassemblerEngine';
import type { PdataEntry } from './disassemblerEngine';
import type { CapstoneWrapper, DisassembledInstruction } from './capstoneWrapper';
import type { ArchitectureConfig } from './capstoneWrapper';

// ─── CFGHints Schema ───────────────────────────────────────────────────

export interface CFGHints {
	/** All discovered basic block entry addresses */
	leaders: number[];

	/** Known function start addresses within the lift range */
	functionStarts: number[];

	/** Known function end addresses (from .pdata, symtab, or RET scan) */
	functionEnds: number[];

	/** Resolved indirect jump targets (jump tables, switch/case) */
	indirectJumps: IndirectJumpResolution[];

	/** Addresses of JMPs that are tail calls, not internal branches */
	tailCalls: number[];

	/** Byte ranges to skip (endbr64, ftrace NOPs, alignment padding) */
	nopRanges: ByteRange[];

	/** Detected calling convention for the function */
	callingConvention: 'msvc_x64' | 'sysv_amd64' | 'fastcall' | 'cdecl' | 'unknown';

	/** Addresses of known data embedded in .text (jump tables, constants) */
	embeddedData: ByteRange[];

	/** Confidence: 0-100, how complete is this CFG analysis */
	confidence: number;

	/** Debug: number of instructions decoded in recursive descent */
	instructionsDecoded: number;

	/** Debug: number of unresolved indirect jumps */
	unresolvedIndirects: number;
}

export interface IndirectJumpResolution {
	/** Address of the indirect jump instruction */
	instructionAddress: number;
	/** All resolved target addresses */
	targets: number[];
	/** Type of indirect jump */
	type: 'jump_table' | 'vtable_call' | 'computed_goto' | 'unknown';
	/** Address of the jump table in .rodata (if applicable) */
	tableAddress?: number;
	/** Number of entries in the table */
	tableSize?: number;
}

export interface ByteRange {
	start: number;
	size: number;
	kind: 'endbr' | 'ftrace_nop' | 'alignment' | 'int3_padding' | 'jump_table_data';
}

// ─── Binary Context (Phase 1 output) ───────────────────────────────────

interface FunctionBoundary {
	start: number;  // Absolute virtual address
	end: number;    // Absolute virtual address (first byte AFTER function)
}

interface BinaryContext {
	functionBoundaries: FunctionBoundary[];
	rodataRanges: ByteRange[];
	entryPoints: number[];
	format: 'PE64' | 'ELF' | 'ELF_REL' | 'unknown';
}

// ═══════════════════════════════════════════════════════════════════════
//  Phase 1: Binary Context Provider
// ═══════════════════════════════════════════════════════════════════════

/**
 * Extract binary context from a PE64 file using .pdata for function boundaries.
 *
 * For ROTTR.exe, .pdata has ~50,000 entries. Every non-leaf function's
 * exact boundaries are known without heuristics.
 */
function extractPE64Context(engine: DisassemblerEngine): BinaryContext {
	const context: BinaryContext = {
		functionBoundaries: [],
		rodataRanges: [],
		entryPoints: [],
		format: 'PE64',
	};

	const fileInfo = engine.getFileInfo();
	if (!fileInfo) { return context; }

	const baseAddress = fileInfo.baseAddress ?? 0;

	// 1. Parse .pdata — EXACT function boundaries
	const pdataEntries = engine.getPdataEntries();
	for (const entry of pdataEntries) {
		context.functionBoundaries.push({
			start: entry.beginAddress + baseAddress,
			end: entry.endAddress + baseAddress,
		});
	}

	// 1b. Supplement with PDB function symbols when available.
	// `.pdata` only covers non-leaf functions (those with SEH unwind info).
	// Leaf functions (no frame, small helpers) have no .pdata entry — PDB
	// exposes ALL S_GPROC32/S_LPROC32 symbols, filling that gap.
	// .pdata wins on address collisions; PDB is additive only.
	// Note: loaded lazily via (engine as any).pePdbBoundaries cache populated
	// by the caller before extractPE64Context runs. When unavailable the
	// array is empty and this block is a no-op.
	const pdbBoundaries = (engine as any).pePdbBoundaries as
		import('./elfBtfLoader').FunctionBoundaryInfo[] | undefined;
	if (pdbBoundaries && pdbBoundaries.length > 0) {
		const seen = new Set<number>(context.functionBoundaries.map(fb => fb.start));
		let added = 0;
		for (const b of pdbBoundaries) {
			if (!seen.has(b.lowPc)) {
				context.functionBoundaries.push({ start: b.lowPc, end: b.highPc });
				context.entryPoints.push(b.lowPc);
				seen.add(b.lowPc);
				added++;
			}
		}
		if (added > 0) {
			console.log(`[pathfinder] PDB supplemented .pdata: +${added} function boundaries (total ${context.functionBoundaries.length})`);
		}
	}

	// 2. Map .rdata sections (jump table data lives here)
	const sections = engine.getSections();
	for (const sec of sections) {
		if (sec.name === '.rdata' || sec.name === '.rodata') {
			context.rodataRanges.push({
				start: sec.virtualAddress,
				size: sec.virtualSize,
				kind: 'jump_table_data',
			});
		}
	}

	// 3. Entry points
	context.entryPoints.push(fileInfo.entryPoint);

	// TLS callbacks
	const dataDirs = engine.getPEDataDirectories();
	if (dataDirs.tls?.callbackAddresses) {
		for (const cb of dataDirs.tls.callbackAddresses) {
			context.entryPoints.push(cb);
		}
	}

	// Exports
	for (const exp of engine.getExports()) {
		if (exp.address) {
			context.entryPoints.push(exp.address);
		}
	}

	return context;
}

/**
 * Extract binary context from an ELF file using .symtab for function boundaries.
 */
function extractELFContext(engine: DisassemblerEngine): BinaryContext {
	const context: BinaryContext = {
		functionBoundaries: [],
		rodataRanges: [],
		entryPoints: [],
		format: 'ELF',
	};

	const fileInfo = engine.getFileInfo();
	if (!fileInfo) { return context; }

	// 1. Parse .symtab — every STT_FUNC gives start + size
	const elfData = engine.getELFAnalysis();
	if (elfData) {
		for (const sym of (elfData as any).symbols ?? []) {
			if (sym.type === 'FUNC' && sym.size > 0) {
				context.functionBoundaries.push({
					start: sym.value,
					end: sym.value + sym.size,
				});
			}
		}
	}

	// 1b. Supplement with DWARF boundaries when available. DWARF fills
	// gaps on stripped .ko (no .symtab) and additionally covers inline
	// instantiations and declaration-only functions that .symtab may
	// omit. .symtab wins on address collisions; DWARF is additive only.
	const dwarfBoundaries = (elfData as any)?.dwarfStructInfo?.boundaries as
		import('./elfBtfLoader').FunctionBoundaryInfo[] | undefined;
	if (dwarfBoundaries && dwarfBoundaries.length > 0) {
		const seen = new Set<number>(context.functionBoundaries.map(fb => fb.start));
		let added = 0;
		for (const b of dwarfBoundaries) {
			if (!seen.has(b.lowPc)) {
				context.functionBoundaries.push({ start: b.lowPc, end: b.highPc });
				context.entryPoints.push(b.lowPc);
				seen.add(b.lowPc);
				added++;
			}
		}
		if (added > 0) {
			console.log(`[pathfinder] DWARF supplemented .symtab: +${added} function boundaries (total ${context.functionBoundaries.length})`);
		}
	}

	// 2. .rodata sections
	const sections = engine.getSections();
	for (const sec of sections) {
		if (sec.name === '.rodata' || sec.name.startsWith('.rodata.')) {
			context.rodataRanges.push({
				start: sec.virtualAddress,
				size: sec.virtualSize,
				kind: 'jump_table_data',
			});
		}
	}

	// 3. Entry point
	context.entryPoints.push(fileInfo.entryPoint);

	return context;
}

// ═══════════════════════════════════════════════════════════════════════
//  Phase 2: Recursive Descent Scanner
// ═══════════════════════════════════════════════════════════════════════

/**
 * Recursive descent disassembler that discovers ALL reachable basic blocks.
 *
 * Unlike linear sweep (which stops at the first problem), recursive descent
 * follows all branches, calls, and fall-throughs to discover complete CFGs.
 *
 * Uses .pdata function boundaries for:
 * - Tail call detection (JMP to another function = tail call, not internal branch)
 * - Scope limiting (don't scan beyond function end)
 * - Data avoidance (don't decode .rodata)
 */
class RecursiveDescentScanner {
	private worklist: number[] = [];
	private visited: Set<number> = new Set();
	private decoded: Map<number, DisassembledInstruction> = new Map();
	private leaders: Set<number> = new Set();
	private tailCalls: Set<number> = new Set();
	private callTargets: Set<number> = new Set();
	private indirectJumpAddrs: number[] = [];
	private functionBounds: Map<number, number>; // start → end
	private rodataRanges: ByteRange[];
	private instructionsDecoded = 0;
	private unresolvedIndirects = 0;

	constructor(
		private capstone: CapstoneWrapper,
		private bytes: Buffer,
		private baseAddress: number,
		private context: BinaryContext,
	) {
		this.functionBounds = new Map();
		for (const fb of context.functionBoundaries) {
			this.functionBounds.set(fb.start, fb.end);
		}
		this.rodataRanges = context.rodataRanges;
	}

	/**
	 * Run recursive descent from the given entry point.
	 */
	async scan(entryPoint: number, functionEnd?: number): Promise<void> {
		this.worklist.push(entryPoint);
		this.leaders.add(entryPoint);

		let iterations = 0;
		const maxIterations = 50000; // Safety cap

		while (this.worklist.length > 0 && iterations < maxIterations) {
			const addr = this.worklist.pop()!;
			iterations++;

			if (this.visited.has(addr)) { continue; }
			if (this.isInRodata(addr)) { continue; }
			if (functionEnd && addr >= functionEnd) { continue; }

			await this.scanBlock(addr, functionEnd);
		}
	}

	private async scanBlock(startAddr: number, functionEnd?: number): Promise<void> {
		let pc = startAddr;
		const maxAddr = functionEnd ?? (startAddr + 0x10000); // 64KB safety

		while (pc < maxAddr) {
			if (this.visited.has(pc)) {
				// Already decoded — merge point, mark as leader
				this.leaders.add(pc);
				break;
			}

			const offset = pc - this.baseAddress;
			if (offset < 0 || offset >= this.bytes.length) { break; }

			// Decode one instruction via Capstone
			const remaining = this.bytes.subarray(offset, Math.min(offset + 15, this.bytes.length));
			let insn: DisassembledInstruction;
			try {
				const result = await this.capstone.disassemble(Buffer.from(remaining), pc, 1);
				if (!result || result.length === 0) { break; }
				insn = result[0];
			} catch {
				break; // Decode failure
			}

			this.visited.add(pc);
			this.decoded.set(pc, insn);
			this.instructionsDecoded++;
			const nextPC = pc + insn.size;

			// ── Classify instruction ───────────────────────────────
			if (insn.isRet) {
				// End of path
				break;

			} else if (insn.isJump && !insn.isConditional) {
				// Unconditional jump
				if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
					if (this.isTailCall(pc, insn.targetAddress, functionEnd)) {
						this.tailCalls.add(pc);
					} else {
						this.leaders.add(insn.targetAddress);
						this.addToWorklist(insn.targetAddress);
					}
				} else if (insn.opStr?.includes('[')) {
					// Indirect jump (potential jump table) — track for Phase 3
					this.indirectJumpAddrs.push(pc);
					this.unresolvedIndirects++;
				}
				break; // Don't fall through

			} else if (insn.isJump && insn.isConditional) {
				// Conditional jump — both paths are leaders
				if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
					this.leaders.add(insn.targetAddress);
					this.addToWorklist(insn.targetAddress);
				}
				// Fall-through
				this.leaders.add(nextPC);
				this.addToWorklist(nextPC);
				break;

			} else if (insn.isCall) {
				// Record call target (function entry point)
				if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
					this.callTargets.add(insn.targetAddress);
				}
				// Continue — call returns to next instruction
				pc = nextPC;

			} else if (insn.mnemonic === 'endbr64' || insn.mnemonic === 'endbr32') {
				// CET instruction — skip, continue
				pc = nextPC;

			} else if (insn.mnemonic === 'nop' || insn.mnemonic === 'int3') {
				// NOP/INT3 padding — skip
				pc = nextPC;

			} else {
				// Normal instruction
				pc = nextPC;
			}
		}
	}

	/**
	 * Tail call detection using .pdata boundaries.
	 * A JMP to an address OUTSIDE our function = tail call.
	 * A JMP to another function start = tail call.
	 */
	private isTailCall(fromAddr: number, targetAddr: number, functionEnd?: number): boolean {
		if (functionEnd && targetAddr >= functionEnd) { return true; }
		if (this.functionBounds.has(targetAddr) && targetAddr !== fromAddr) {
			return true;
		}
		return false;
	}

	private isInRodata(addr: number): boolean {
		for (const range of this.rodataRanges) {
			if (addr >= range.start && addr < range.start + range.size) { return true; }
		}
		return false;
	}

	private addToWorklist(addr: number): void {
		if (!this.visited.has(addr) && !this.isInRodata(addr)) {
			this.worklist.push(addr);
		}
	}

	// ── Results ──────────────────────────────────────────────
	getLeaders(): number[] { return [...this.leaders].sort((a, b) => a - b); }
	getVisited(): Set<number> { return this.visited; }
	getTailCalls(): number[] { return [...this.tailCalls].sort((a, b) => a - b); }
	getCallTargets(): number[] { return [...this.callTargets].sort((a, b) => a - b); }
	getIndirectJumps(): IndirectJumpResolution[] { return this.resolvedJumpTables; }
	getInstructionsDecoded(): number { return this.instructionsDecoded; }
	getUnresolvedIndirects(): number { return this.unresolvedIndirects; }

	// Jump table storage (populated during scan)
	private resolvedJumpTables: IndirectJumpResolution[] = [];

	/**
	 * After scan completes, resolve indirect jumps as jump tables.
	 * Adds resolved targets as new leaders and re-scans from them.
	 */
	async resolveJumpTables(): Promise<void> {
		if (this.indirectJumpAddrs.length === 0) { return; }

		const resolver = new JumpTableResolver(
			this.bytes, this.baseAddress, this.decoded, this.context.rodataRanges
		);

		for (const jumpAddr of this.indirectJumpAddrs) {
			const resolution = resolver.resolve(jumpAddr, this.bytes, this.baseAddress);
			if (resolution) {
				this.resolvedJumpTables.push(resolution);
				for (const target of resolution.targets) {
					this.leaders.add(target);
					this.addToWorklist(target);
				}
				this.unresolvedIndirects = Math.max(0, this.unresolvedIndirects - 1);
			}
		}

		// Re-scan from newly discovered jump table targets
		if (this.worklist.length > 0) {
			let iterations = 0;
			while (this.worklist.length > 0 && iterations < 10000) {
				const addr = this.worklist.pop()!;
				iterations++;
				if (this.visited.has(addr)) { continue; }
				if (this.isInRodata(addr)) { continue; }
				await this.scanBlock(addr, undefined);
			}
		}
	}
}

// ═══════════════════════════════════════════════════════════════════════
//  Phase 3: Jump Table Resolver
// ═══════════════════════════════════════════════════════════════════════

/**
 * Resolve jump tables by backward slicing from indirect jumps.
 *
 * MSVC x64 pattern:
 *   cmp  ecx, N            ; limit check
 *   ja   default_label      ; unsigned compare (switch default)
 *   lea  rdx, [rip+TABLE]  ; load table base
 *   movsxd rax, [rdx+rcx*4]; load relative offset (32-bit signed)
 *   add  rax, rdx           ; compute absolute target
 *   jmp  rax                ; indirect jump
 *
 * GCC pattern:
 *   cmp  edi, N
 *   ja   default
 *   lea  rsi, [rip+TABLE]
 *   movsxd rdi, [rsi+rdi*4]
 *   add  rdi, rsi
 *   jmp  rdi
 */
class JumpTableResolver {
	constructor(
		private fullBytes: Buffer,
		private fullBase: number,
		private decoded: Map<number, DisassembledInstruction>,
		private rodataRanges: ByteRange[],
	) {}

	/**
	 * Attempt to resolve an indirect jump at the given address.
	 */
	resolve(jumpAddr: number, bytes: Buffer, baseAddress: number): IndirectJumpResolution | null {
		// Backward slice: collect the last 15 decoded instructions before the jump
		const slice = this.getBackwardSlice(jumpAddr, 15);
		if (slice.length < 3) { return null; }

		// Pattern match: look for CMP + LEA [rip+X]
		let tableBase: number | undefined;
		let maxEntries: number | undefined;

		for (const insn of slice) {
			// CMP reg, imm — gives us max entries
			if (insn.mnemonic === 'cmp' && !maxEntries) {
				const imm = this.extractImmediate(insn.opStr);
				if (imm !== undefined && imm > 0 && imm < 4096) {
					maxEntries = imm + 1; // 0-based → N+1 cases
				}
			}

			// LEA reg, [rip+OFFSET] — gives us table address
			if (insn.mnemonic === 'lea' && insn.opStr?.includes('rip')) {
				const ripOffset = this.extractRipRelativeOffset(insn);
				if (ripOffset !== undefined) {
					tableBase = insn.address + insn.size + ripOffset;
				}
			}
		}

		if (!tableBase || !maxEntries) { return null; }

		// Validate: table should be in .rdata or near the code
		if (!this.isInRodata(tableBase) && !this.isNearCode(tableBase, jumpAddr)) {
			return null;
		}

		// Read table entries (32-bit signed relative offsets from tableBase)
		const targets: number[] = [];
		const tableOffset = tableBase - this.fullBase;

		for (let i = 0; i < maxEntries && i < 1024; i++) {
			const entryOff = tableOffset + i * 4;
			if (entryOff < 0 || entryOff + 4 > this.fullBytes.length) { break; }

			const relOffset = this.fullBytes.readInt32LE(entryOff);
			const target = tableBase + relOffset;

			// Sanity: target should be near the jump (< 1MB away)
			if (Math.abs(target - jumpAddr) > 0x100000) { break; }

			// Sanity: target should be a reasonable code address
			if (target < this.fullBase || target >= this.fullBase + this.fullBytes.length) { break; }

			targets.push(target);
		}

		if (targets.length < 2) { return null; } // Need at least 2 cases

		return {
			instructionAddress: jumpAddr,
			targets: [...new Set(targets)], // deduplicate
			type: 'jump_table',
			tableAddress: tableBase,
			tableSize: targets.length,
		};
	}

	private getBackwardSlice(addr: number, count: number): DisassembledInstruction[] {
		// Collect decoded instructions before the jump address, sorted descending
		const before = [...this.decoded.entries()]
			.filter(([a]) => a < addr && a >= addr - 200)
			.sort(([a], [b]) => b - a)
			.slice(0, count)
			.map(([, insn]) => insn);
		return before.reverse(); // chronological order
	}

	private extractImmediate(opStr: string | undefined): number | undefined {
		if (!opStr) { return undefined; }
		const match = opStr.match(/,\s*(?:0x)?([0-9a-fA-F]+)$/);
		if (match) { return parseInt(match[1], 16); }
		const dec = opStr.match(/,\s*(\d+)$/);
		if (dec) { return parseInt(dec[1], 10); }
		return undefined;
	}

	private extractRipRelativeOffset(insn: DisassembledInstruction): number | undefined {
		if (!insn.opStr) { return undefined; }
		// Match: [rip + 0x12345] or [rip - 0x12345]
		const match = insn.opStr.match(/\[rip\s*([+-])\s*(?:0x)?([0-9a-fA-F]+)\]/i);
		if (match) {
			const val = parseInt(match[2], 16);
			return match[1] === '-' ? -val : val;
		}
		return undefined;
	}

	private isInRodata(addr: number): boolean {
		for (const range of this.rodataRanges) {
			if (addr >= range.start && addr < range.start + range.size) { return true; }
		}
		return false;
	}

	private isNearCode(tableAddr: number, jumpAddr: number): boolean {
		return Math.abs(tableAddr - jumpAddr) < 0x100000; // Within 1MB
	}
}

// ═══════════════════════════════════════════════════════════════════════
//  Phase 2b: ARM64 Full-Function Linear Decode
// ═══════════════════════════════════════════════════════════════════════

/** ARM64 NOP/padding detection constants (little-endian u32 encoding) */
const ARM64_NOP   = 0xD503201F; // nop
const ARM64_BRK_0 = 0xD4200000; // brk #0
const ARM64_UDF   = 0x00000000; // udf #0 (zero word)

interface ARM64ScanResult {
	leaders: number[];
	tailCalls: number[];
	indirectJumps: number[];
	instructionsDecoded: number;
	nopRanges: ByteRange[];
}

/**
 * Full-function linear decode for ARM64 (AArch64).
 *
 * ARM64 uses fixed 4-byte instructions, so we can reliably decode the
 * ENTIRE function in a single Capstone batch call and extract every branch
 * target. This is fundamentally more complete than recursive descent because
 * it sees code that no branch reaches (exception handlers, dead code,
 * functions only called via pointer).
 */
async function linearDecodeARM64(
	capstone: CapstoneWrapper,
	functionBytes: Buffer,
	functionStart: number,
	functionEnd: number,
	context: BinaryContext,
): Promise<ARM64ScanResult> {
	const leaders = new Set<number>();
	const tailCalls = new Set<number>();
	const indirectJumps: number[] = [];
	let instructionsDecoded = 0;
	const nopRanges: ByteRange[] = [];

	// Build function start lookup for tail call detection
	const functionStarts = new Set<number>();
	for (const fb of context.functionBoundaries) {
		functionStarts.add(fb.start);
	}

	// Function entry is always a leader
	leaders.add(functionStart);

	// Batch decode the entire function in one Capstone call
	const functionSize = functionEnd - functionStart;
	const maxInsns = Math.ceil(functionSize / 4) + 16; // ARM64 = 4 bytes/insn
	let allInsns: DisassembledInstruction[];
	try {
		allInsns = await capstone.disassemble(Buffer.from(functionBytes), functionStart, maxInsns);
	} catch {
		return { leaders: [functionStart], tailCalls: [], indirectJumps: [], instructionsDecoded: 0, nopRanges: [] };
	}

	if (!allInsns || allInsns.length === 0) {
		return { leaders: [functionStart], tailCalls: [], indirectJumps: [], instructionsDecoded: 0, nopRanges: [] };
	}

	instructionsDecoded = allInsns.length;

	// Track NOP runs for nopRanges detection
	let nopRunStart = -1;
	let nopRunSize = 0;

	for (let i = 0; i < allInsns.length; i++) {
		const insn = allInsns[i];
		const nextAddr = insn.address + insn.size;

		// ── NOP/padding tracking ──
		const isNopLike = insn.mnemonic === 'nop' || insn.mnemonic === 'brk' || insn.mnemonic === 'udf';
		if (isNopLike) {
			if (nopRunStart < 0) { nopRunStart = insn.address; nopRunSize = 0; }
			nopRunSize += insn.size;
		} else {
			if (nopRunStart >= 0 && nopRunSize >= 8) {
				nopRanges.push({ start: nopRunStart, size: nopRunSize, kind: 'alignment' });
			}
			nopRunStart = -1;
			nopRunSize = 0;
		}

		// ── Branch classification ──
		if (insn.isRet) {
			// Code after ret is a potential leader (exception handler, separate code path)
			if (nextAddr < functionEnd) {
				// Check next instruction isn't padding
				const nextOffset = nextAddr - functionStart;
				if (nextOffset + 4 <= functionBytes.length) {
					const nextWord = functionBytes.readUInt32LE(nextOffset);
					if (nextWord !== ARM64_NOP && nextWord !== ARM64_BRK_0 && nextWord !== ARM64_UDF) {
						leaders.add(nextAddr);
					}
				}
			}

		} else if (insn.isJump && !insn.isConditional) {
			// Unconditional branch (b, br)
			if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
				if (insn.targetAddress >= functionStart && insn.targetAddress < functionEnd) {
					// Internal branch — target is a leader
					leaders.add(insn.targetAddress);
				} else if (functionStarts.has(insn.targetAddress) || insn.targetAddress >= functionEnd) {
					// Tail call to another function
					tailCalls.add(insn.address);
				}
			} else {
				// Indirect branch (br Xn) — potential jump table
				indirectJumps.push(insn.address);
			}
			// Code after unconditional branch is a potential leader
			if (nextAddr < functionEnd) {
				const nextOffset = nextAddr - functionStart;
				if (nextOffset + 4 <= functionBytes.length) {
					const nextWord = functionBytes.readUInt32LE(nextOffset);
					if (nextWord !== ARM64_NOP && nextWord !== ARM64_BRK_0 && nextWord !== ARM64_UDF) {
						leaders.add(nextAddr);
					}
				}
			}

		} else if (insn.isJump && insn.isConditional) {
			// Conditional branch (b.eq, cbz, cbnz, tbz, tbnz)
			if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
				if (insn.targetAddress >= functionStart && insn.targetAddress < functionEnd) {
					leaders.add(insn.targetAddress);
				}
			}
			// Fallthrough is also a leader
			if (nextAddr < functionEnd) {
				leaders.add(nextAddr);
			}

		} else if (insn.isCall) {
			// bl/blr — call instruction
			if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
				// Internal call target within function bounds = leader
				if (insn.targetAddress >= functionStart && insn.targetAddress < functionEnd) {
					leaders.add(insn.targetAddress);
				}
			}
			// Instruction after call is always a leader (return point)
			if (nextAddr < functionEnd) {
				leaders.add(nextAddr);
			}
		}
	}

	// Flush trailing NOP run
	if (nopRunStart >= 0 && nopRunSize >= 8) {
		nopRanges.push({ start: nopRunStart, size: nopRunSize, kind: 'alignment' });
	}

	return {
		leaders: [...leaders].sort((a, b) => a - b),
		tailCalls: [...tailCalls].sort((a, b) => a - b),
		indirectJumps,
		instructionsDecoded,
		nopRanges,
	};
}

// ═══════════════════════════════════════════════════════════════════════
//  Phase 2c: x86 Gap Scanning (post-recursive-descent)
// ═══════════════════════════════════════════════════════════════════════

/** x86-64 prologue byte patterns for gap scanning */
const X86_PROLOGUES: { bytes: number[], mask?: number[] }[] = [
	// push rbp; mov rbp, rsp  (55 48 89 E5)
	{ bytes: [0x55, 0x48, 0x89, 0xE5] },
	// sub rsp, imm8  (48 83 EC XX)
	{ bytes: [0x48, 0x83, 0xEC], mask: [0xFF, 0xFF, 0xFF] },
	// sub rsp, imm32  (48 81 EC XX XX XX XX)
	{ bytes: [0x48, 0x81, 0xEC], mask: [0xFF, 0xFF, 0xFF] },
	// endbr64  (F3 0F 1E FA)
	{ bytes: [0xF3, 0x0F, 0x1E, 0xFA] },
	// mov [rsp+8], rcx — MSVC fastcall  (48 89 4C 24 08)
	{ bytes: [0x48, 0x89, 0x4C, 0x24, 0x08] },
	// push rbx  (53) followed by 48 or 41 REX prefix
	{ bytes: [0x53, 0x48], mask: [0xFF, 0xF8] },
	// push r12-r15  (41 54, 41 55, 41 56, 41 57)
	{ bytes: [0x41, 0x54], mask: [0xFF, 0xFC] },
];

/**
 * After recursive descent exhausts the worklist, scan gaps within
 * [functionStart, functionEnd) for x86 function prologues that were
 * never reached (code only callable via indirect calls / function pointers).
 */
async function scanGapsForCode(
	capstone: CapstoneWrapper,
	bytes: Buffer,
	baseAddress: number,
	visited: Set<number>,
	functionStart: number,
	functionEnd: number,
): Promise<number[]> {
	const discoveredLeaders: number[] = [];

	// Build sorted list of visited addresses
	const sortedVisited = [...visited]
		.filter(a => a >= functionStart && a < functionEnd)
		.sort((a, b) => a - b);

	if (sortedVisited.length === 0) { return discoveredLeaders; }

	// Find gaps > 16 bytes between visited addresses
	let prevAddr = functionStart;
	for (let idx = 0; idx <= sortedVisited.length; idx++) {
		const nextVisited = idx < sortedVisited.length ? sortedVisited[idx] : functionEnd;
		const gapStart = prevAddr;
		const gapEnd = nextVisited;

		if (gapEnd - gapStart > 16) {
			// Scan this gap for prologues
			for (let scan = gapStart; scan < gapEnd - 4; scan++) {
				const offset = scan - baseAddress;
				if (offset < 0 || offset + 8 > bytes.length) { continue; }

				if (matchesPrologue(bytes, offset)) {
					// Verify with Capstone: decode a few instructions to confirm valid code
					try {
						const window = bytes.subarray(offset, Math.min(offset + 64, bytes.length));
						const insns = await capstone.disassemble(Buffer.from(window), scan, 5);
						if (insns && insns.length >= 3) {
							discoveredLeaders.push(scan);
							scan += 16; // Skip ahead to avoid overlapping detections
						}
					} catch {
						// Not valid code — continue scanning
					}
				}
			}
		}

		// Advance past this visited address (rough: we don't track exact insn sizes)
		if (idx < sortedVisited.length) {
			prevAddr = sortedVisited[idx] + 1;
		}
	}

	return discoveredLeaders;
}

/**
 * Check if bytes at the given offset match any known x86-64 function prologue.
 */
function matchesPrologue(bytes: Buffer, offset: number): boolean {
	for (const pattern of X86_PROLOGUES) {
		const len = pattern.bytes.length;
		if (offset + len > bytes.length) { continue; }

		let match = true;
		for (let i = 0; i < len; i++) {
			const mask = pattern.mask ? pattern.mask[i] ?? 0xFF : 0xFF;
			if ((bytes[offset + i] & mask) !== (pattern.bytes[i] & mask)) {
				match = false;
				break;
			}
		}
		if (match) { return true; }
	}
	return false;
}

// ═══════════════════════════════════════════════════════════════════════
//  Pathfinder — Main API
// ═══════════════════════════════════════════════════════════════════════

/**
 * Run Pathfinder analysis for a specific address range.
 *
 * Phase 1: Uses .pdata/.symtab for function boundaries.
 * Phase 2: Architecture-aware code discovery:
 *   - ARM64: Full-function linear decode (single Capstone batch call)
 *   - x86/x64: Recursive descent + gap scanning with prologue detection
 * Phase 3: Jump table resolution (x86).
 *
 * @param engine The disassembler engine with a loaded file
 * @param targetAddress Address to analyze
 * @param bytes Raw bytes at the target address (fallback for recursive descent)
 * @returns CFGHints for the Remill lifter
 */
export async function runPathfinder(
	engine: DisassemblerEngine,
	targetAddress: number,
	bytes?: Buffer,
): Promise<CFGHints> {
	const fileInfo = engine.getFileInfo();
	if (!fileInfo) {
		return emptyHints();
	}

	// v3.8.1: Ensure BTF/DWARF debug info is loaded before we extract the
	// binary context so Pathfinder can merge DWARF boundaries and Helix
	// can consume struct/function types downstream.  Idempotent — early
	// returns if already loaded.  Guarantees type info reaches the
	// liftToIR hot path even when the caller skipped analyzeELFHeadless.
	const isELF = fileInfo.format === 'ELF32' || fileInfo.format === 'ELF64';
	if (isELF && typeof (engine as any).ensureDebugInfoLoaded === 'function') {
		try {
			await (engine as any).ensureDebugInfoLoaded();
		} catch (e) {
			console.warn('[pathfinder] ensureDebugInfoLoaded failed (non-fatal):', e);
		}
	}

	// Phase 1: Extract binary context (.pdata / .symtab).
	// For PE, lazily load PDB function symbols on first run — the loader
	// spawns llvm-pdbutil once and caches the result on the engine for
	// subsequent calls in the same analysis session.
	const isPE = fileInfo.format === 'PE' || fileInfo.format === 'PE64';
	if (isPE && (engine as any).pePdbBoundaries === undefined) {
		(engine as any).pePdbBoundaries = [];  // sentinel — "we tried" (avoid re-spawning on failure)
		try {
			const peFilePath = engine.getFilePath?.();
			if (peFilePath) {
				const dataDirs = engine.getPEDataDirectories?.();
				const codeViewPdbPath = dataDirs?.debug?.find(d => d.type === 2)?.pdbPath;
				const { discoverPdbPath, loadPdbFunctionBoundaries } = await import('./pdbLoader');
				const pdbPath = discoverPdbPath(peFilePath, codeViewPdbPath);
				if (pdbPath) {
					const imageBase = fileInfo.baseAddress ?? 0;
					(engine as any).pePdbBoundaries = await loadPdbFunctionBoundaries(pdbPath, imageBase);
				}
			}
		} catch (e) {
			console.warn(`[pathfinder] PDB load failed (non-fatal):`, e);
		}
	}
	const context = isPE
		? extractPE64Context(engine)
		: extractELFContext(engine);

	// Find function boundaries for the target address
	let boundary = findFunctionBoundary(context, targetAddress);

	// Fallback: engine's function table handles ELF REL address space correctly
	// when Phase 1 context has mismatched symtab addresses.
	// IMPORTANT: engine may have OVERLAPPING functions (imperfect prologue
	// detection). We pick the INNERMOST containing function (largest start
	// address among containing functions) to avoid scanning unrelated code.
	if (!boundary) {
		const allFuncs = engine.getFunctions(); // sorted by address ASC
		let best: { address: number; endAddress: number } | undefined;
		for (const func of allFuncs) {
			if (func.address > targetAddress) { break; } // past target, stop
			if (func.address <= targetAddress && func.endAddress > targetAddress) {
				// Found a containing function; prefer the innermost (latest start)
				if (!best || func.address > best.address) {
					best = { address: func.address, endAddress: func.endAddress };
				}
			}
		}
		if (best) {
			boundary = { start: best.address, end: best.endAddress };
		}
	}

	// Detect architecture for Phase 2 dispatch
	const arch: ArchitectureConfig = engine.getArchitecture();
	const isARM64 = arch === 'arm64';

	// FIX-026: Do NOT send functionEnds that would truncate the Remill scan.
	// The caller's bytes buffer IS the authoritative scan range. .pdata/.symtab
	// boundaries are used for tail call detection and leader discovery, but
	// they must NOT stop Remill from scanning the full buffer.
	//
	// PE64 .pdata covers the SEH unwind extent, which can be SHORTER than the
	// actual function (tail calls, padding, code after epilogue). Sending a
	// .pdata end as knownFunctionEnds caused Remill Phase 1 to stop early,
	// producing 5x smaller .ll files (948→197 lines on ObjectManager-Create).
	//
	// We still send functionEnds for addresses BEYOND the caller's buffer
	// (informational for multi-function scenarios), but filter out any end
	// that falls within the caller's scan range.
	const callerEnd = targetAddress + (bytes?.length ?? 0);
	const safeEnds: number[] = [];
	if (boundary) {
		// Only include the end if it's beyond what the caller already covers
		if (boundary.end > callerEnd) {
			safeEnds.push(boundary.end);
		}
	}

	const hints: CFGHints = {
		leaders: [],
		functionStarts: [],
		functionEnds: safeEnds,
		indirectJumps: [],
		tailCalls: [],
		nopRanges: [],
		callingConvention: isPE ? 'msvc_x64' : (isARM64 ? 'sysv_amd64' : 'sysv_amd64'),
		embeddedData: [],
		confidence: boundary ? 50 : 10,
		instructionsDecoded: 0,
		unresolvedIndirects: 0,
	};

	if (boundary) {
		hints.leaders.push(boundary.start);

		// Nearby function starts for tail call detection
		const nearbyFunctions = context.functionBoundaries.filter(fb =>
			fb.start > boundary.start && fb.start < boundary.start + 0x10000
		);
		for (const fb of nearbyFunctions) {
			hints.functionStarts.push(fb.start);
		}
	}

	const capstone = engine.getCapstone();
	if (!capstone) {
		console.log(`[pathfinder v0.2.0] no Capstone available, returning Phase 1 hints only`);
		return hints;
	}

	// ── Diagnostic logging ──
	console.log(`[pathfinder v0.2.0] arch=${arch} isARM64=${isARM64} boundary=${boundary ? `[0x${boundary.start.toString(16)},0x${boundary.end.toString(16)})` : 'NONE'} targetAddr=0x${targetAddress.toString(16)} callerBytes=${bytes?.length ?? 0} contextBoundaries=${context.functionBoundaries.length}`);

	// ── Determine scan range ──
	// CRITICAL: The scan range MUST match what Remill will see, otherwise
	// leaders found outside Remill's buffer are useless (Remill can't lift them).
	// Caller's bytes ARE Remill's bytes. We use them directly.
	// The boundary is only used for metadata (functionEnds) and context.
	const functionBytes: Buffer | undefined = bytes;
	const scanStart = targetAddress;
	const scanEnd = targetAddress + (bytes?.length ?? 0);

	if (!functionBytes || functionBytes.length === 0) {
		console.log(`[pathfinder v0.2.0] no bytes available, returning Phase 1 hints only`);
		return hints;
	}

	console.log(`[pathfinder v0.2.0] scan range: ${functionBytes.length} bytes [0x${scanStart.toString(16)},0x${scanEnd.toString(16)})`);

	// ── Phase 2: Architecture-aware code discovery ──
	if (isARM64) {
		// ARM64: Full-function linear decode — single Capstone batch call.
		try {
			const arm64Result = await linearDecodeARM64(
				capstone, functionBytes, scanStart, scanEnd, context
			);

			console.log(`[pathfinder v0.2.0] ARM64 linear decode: ${arm64Result.instructionsDecoded} insns, ${arm64Result.leaders.length} leaders, ${arm64Result.tailCalls.length} tail-calls, ${arm64Result.indirectJumps.length} indirect`);

			// Merge ARM64 results into hints
			const mergedLeaders = new Set([...hints.leaders, ...arm64Result.leaders]);
			hints.leaders = [...mergedLeaders].sort((a, b) => a - b);
			hints.tailCalls = arm64Result.tailCalls;
			hints.nopRanges = arm64Result.nopRanges;
			hints.instructionsDecoded = arm64Result.instructionsDecoded;
			hints.unresolvedIndirects = arm64Result.indirectJumps.length;

			// ARM64 linear decode is highly complete
			hints.confidence = arm64Result.instructionsDecoded > 0 ? 95 : 50;

		} catch (e) {
			// Non-fatal: ARM64 linear decode failed, Phase 1 hints still valid
			console.warn(`[pathfinder v0.2.0] ARM64 linear decode FAILED:`, e);
		}
	} else {
		// x86/x64: Prefer full-function linear sweep via Capstone batch decode.
		// For x86 we CAN'T trust linear sweep starting from arbitrary addresses
		// (data in code), but starting from the function entry (targetAddress)
		// Capstone will decode all instructions until it hits something invalid.
		// Every branch target within the scan range becomes a leader.
		try {
			// Batch decode the entire buffer in one Capstone call
			const maxInsns = Math.max(4096, Math.ceil(functionBytes.length / 2));
			let allInsns: DisassembledInstruction[] = [];
			try {
				allInsns = await capstone.disassemble(Buffer.from(functionBytes), scanStart, maxInsns);
			} catch (e) {
				console.warn(`[pathfinder v0.2.0] x86 batch decode threw:`, e);
			}

			const leadersSet = new Set<number>();
			const tailCallsSet = new Set<number>();
			leadersSet.add(scanStart);

			for (let i = 0; i < allInsns.length; i++) {
				const insn = allInsns[i];
				const nextAddr = insn.address + insn.size;

				if (insn.isRet) {
					// Code after ret is a potential leader
					if (nextAddr < scanEnd) {
						leadersSet.add(nextAddr);
					}
				} else if (insn.isJump && !insn.isConditional) {
					// Unconditional jump
					if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
						if (insn.targetAddress >= scanStart && insn.targetAddress < scanEnd) {
							leadersSet.add(insn.targetAddress);
						} else {
							// Tail call to outside our function
							tailCallsSet.add(insn.address);
						}
					}
					// Code after unconditional jump is a potential leader
					if (nextAddr < scanEnd) {
						leadersSet.add(nextAddr);
					}
				} else if (insn.isJump && insn.isConditional) {
					// Conditional jump — target + fallthrough are leaders
					if (insn.targetAddress !== undefined && insn.targetAddress !== 0) {
						if (insn.targetAddress >= scanStart && insn.targetAddress < scanEnd) {
							leadersSet.add(insn.targetAddress);
						}
					}
					if (nextAddr < scanEnd) {
						leadersSet.add(nextAddr);
					}
				} else if (insn.isCall) {
					// Instruction after call is a leader (return point)
					if (nextAddr < scanEnd) {
						leadersSet.add(nextAddr);
					}
					// Internal call target = leader
					if (insn.targetAddress !== undefined && insn.targetAddress >= scanStart && insn.targetAddress < scanEnd) {
						leadersSet.add(insn.targetAddress);
					}
				}
			}

			console.log(`[pathfinder v0.2.0] x86 linear decode: ${allInsns.length} insns, ${leadersSet.size} leaders, ${tailCallsSet.size} tail-calls`);

			// Merge into hints
			const mergedLeaders = new Set([...hints.leaders, ...leadersSet]);
			hints.leaders = [...mergedLeaders].sort((a, b) => a - b);
			hints.tailCalls = [...tailCallsSet].sort((a, b) => a - b);
			hints.instructionsDecoded = allInsns.length;
			hints.confidence = allInsns.length > 0 ? 90 : 50;

			// Log a few sample leaders for debugging
			if (leadersSet.size > 0) {
				const sampleLeaders = [...leadersSet].sort((a, b) => a - b).slice(0, 10);
				console.log(`[pathfinder v0.2.0] x86 first leaders: [${sampleLeaders.map(l => '0x' + l.toString(16)).join(', ')}${leadersSet.size > 10 ? '...' : ''}]`);
			}
		} catch (e) {
			console.warn(`[pathfinder v0.2.0] x86 linear decode FAILED:`, e);
		}
	}

	console.log(`[pathfinder v0.2.0] final hints: ${hints.leaders.length} leaders, confidence=${hints.confidence}%`);
	return hints;
}

/**
 * Get .pdata function count for diagnostic display.
 */
export function getPdataFunctionCount(engine: DisassemblerEngine): number {
	return engine.getPdataEntries().length;
}

/**
 * Find the function boundary that contains the target address.
 * Uses binary search on sorted .pdata entries for O(log n) lookup.
 */
function findFunctionBoundary(
	context: BinaryContext,
	targetAddress: number,
): FunctionBoundary | undefined {
	const boundaries = context.functionBoundaries;
	if (boundaries.length === 0) { return undefined; }

	// Binary search for the function containing targetAddress
	let lo = 0;
	let hi = boundaries.length - 1;

	while (lo <= hi) {
		const mid = (lo + hi) >>> 1;
		const fb = boundaries[mid];

		if (targetAddress < fb.start) {
			hi = mid - 1;
		} else if (targetAddress >= fb.end) {
			lo = mid + 1;
		} else {
			// targetAddress is within [fb.start, fb.end)
			return fb;
		}
	}

	return undefined;
}

function emptyHints(): CFGHints {
	return {
		leaders: [],
		functionStarts: [],
		functionEnds: [],
		indirectJumps: [],
		tailCalls: [],
		nopRanges: [],
		callingConvention: 'unknown',
		embeddedData: [],
		confidence: 0,
		instructionsDecoded: 0,
		unresolvedIndirects: 0,
	};
}
