/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { CapstoneWrapper, ArchitectureConfig, DisassembledInstruction } from './capstoneWrapper';
import { LlvmMcWrapper, PatchResult, AssembleResult } from './llvmMcWrapper';
import { SessionStore } from './sessionStore';
import { lookupApi, formatApiSignature, formatApiSignatureCompact, ApiSignature, ApiCategory, CATEGORY_LABELS } from './peApiDatabase';

// Types
export interface Instruction {
	address: number;
	bytes: Buffer;
	mnemonic: string;
	opStr: string;
	size: number;
	comment?: string;
	isCall: boolean;
	isJump: boolean;
	isRet: boolean;
	isConditional: boolean;
	targetAddress?: number;
}

export interface Function {
	address: number;
	name: string;
	size: number;
	endAddress: number;
	instructions: Instruction[];
	callers: number[];
	callees: number[];
}

export interface StringReference {
	address: number;
	string: string;
	encoding: 'ascii' | 'unicode';
	references: number[];
}

export interface XRef {
	from: number;
	to: number;
	type: 'call' | 'jump' | 'data' | 'string';
}

// Section information
export interface Section {
	name: string;
	virtualAddress: number;
	virtualSize: number;
	rawAddress: number;
	rawSize: number;
	characteristics: number;
	permissions: string;  // "r-x", "rw-", etc
	isCode: boolean;
	isData: boolean;
	isReadable: boolean;
	isWritable: boolean;
	isExecutable: boolean;
}

// Import information
export interface ImportFunction {
	name: string;
	ordinal?: number;
	address: number;  // IAT address
	hint?: number;
}

export interface ImportLibrary {
	name: string;
	functions: ImportFunction[];
}

// Export information
export interface ExportFunction {
	name: string;
	ordinal: number;
	address: number;
	isForwarder: boolean;
	forwarderName?: string;
}

// v3.7.5: Enhanced ELF analysis data
export interface ELFProgramHeader {
	type: number;
	typeName: string;
	flags: number;
	permissions: string;
	offset: number;
	vaddr: number;
	paddr: number;
	filesz: number;
	memsz: number;
	align: number;
	/** For PT_INTERP: the interpreter path */
	interpreter?: string;
}

export interface ELFSymbolEntry {
	name: string;
	value: number;
	size: number;
	binding: string;     // LOCAL, GLOBAL, WEAK
	type: string;        // NOTYPE, OBJECT, FUNC, SECTION, FILE, TLS, GNU_IFUNC
	visibility: string;  // DEFAULT, HIDDEN, PROTECTED, INTERNAL
	sectionIndex: number;
	sectionName: string;
	isImport: boolean;
	isExport: boolean;
}

export interface ELFRelocationEntry {
	offset: number;
	type: number;
	typeName: string;
	symbolName: string;
	addend: number;
	sectionName: string; // which section this relocation belongs to
}

export interface ELFDynamicEntry {
	tag: number;
	tagName: string;
	value: number;
	/** For DT_NEEDED, DT_SONAME, DT_RPATH: the string value */
	stringValue?: string;
}

export interface ELFModuleInfo {
	name?: string;
	version?: string;
	description?: string;
	author?: string;
	license?: string;
	srcversion?: string;
	depends?: string[];
	vermagic?: string;
	intree?: boolean;
	retpoline?: boolean;
	parmDescriptions?: Array<{ name: string; description: string }>;
}

export interface ELFAnalysis {
	programHeaders: ELFProgramHeader[];
	symbols: ELFSymbolEntry[];
	relocations: ELFRelocationEntry[];
	dynamicEntries: ELFDynamicEntry[];
	moduleInfo?: ELFModuleInfo;
	/** Needed shared libraries (from DT_NEEDED) */
	neededLibraries: string[];
	/** SONAME if present */
	soname?: string;
	/** Interpreter path (from PT_INTERP) */
	interpreter?: string;
	/** ELF type: ET_REL, ET_EXEC, ET_DYN, ET_CORE */
	elfType: string;
	elfTypeValue: number;
	/** v3.8.0: Confidence score for analysis quality */
	confidenceScore?: ConfidenceScore;
	/** Executable sections with semantic classification */
	executableSections?: ELFExecutableSection[];
	/** BTF type data loaded from the binary or vmlinux */
	btfData?: import('./elfBtfLoader').BTFData;
	/** v3.8.0: DWARF struct info (fallback when no BTF) — same JSON format as BTF export */
	dwarfStructInfo?: import('./elfBtfLoader').StructInfoJson;
}

/**
 * Confidence score for ELF kernel module analysis quality.
 * Each component is normalized to [0, 1], overall is the weighted average.
 */
export interface ConfidenceScore {
	/** Weighted average of all components (0-1) */
	overall: number;
	/** Percentage of external calls resolved via .rela.text relocations (weight: 0.30) */
	symbolResolution: number;
	/** CFG complexity ratio: basic blocks per function (weight: 0.20) */
	cfgComplexity: number;
	/** Recognition of known kernel API patterns (weight: 0.20) */
	patternRecognition: number;
	/** Percentage of external call targets with known signatures (weight: 0.20) */
	externalCallCoverage: number;
	/** Completeness of symtab function entries (weight: 0.10) */
	symtabCompleteness: number;
	/** Individual pattern match details */
	detectedPatterns: string[];
}

/**
 * Executable section descriptor for section-aware kernel module analysis.
 */
export interface ELFExecutableSection {
	/** Section name (e.g., '.text', '.init.text', '.exit.text') */
	name: string;
	/** File offset of section data */
	offset: number;
	/** Section size in bytes */
	size: number;
	/** Section flags (SHF_EXECINSTR, SHF_ALLOC, etc.) */
	flags: number;
	/** Virtual address (or 0 for ET_REL) */
	virtualAddress: number;
	/** Semantic purpose of this section */
	purpose: 'runtime' | 'module_init' | 'module_cleanup' | 'trampoline' | 'unknown';
}

/**
 * Calculate confidence score for ELF kernel module analysis.
 */
function calculateConfidenceScore(params: {
	symbols: ELFSymbolEntry[];
	relocations: ELFRelocationEntry[];
	sections: Array<{ name: string; size: number; flags: number }>;
	totalFunctions: number;
	totalBasicBlocks: number;
	resolvedExternalCalls: number;
	totalExternalCalls: number;
	hasBtfInfo: boolean;
	hasDwarfInfo: boolean;
}): ConfidenceScore {
	const {
		symbols,
		relocations,
		totalFunctions,
		totalBasicBlocks,
		resolvedExternalCalls,
		totalExternalCalls,
		hasBtfInfo,
		hasDwarfInfo
	} = params;

	// Known kernel API patterns by category
	const memoryPatterns = ['kmalloc', 'kfree', 'vmalloc', 'vfree', 'kzalloc', 'krealloc'];
	const refcountPatterns = ['kref_get', 'kref_put', 'atomic_inc', 'atomic_dec', 'refcount_inc', 'refcount_dec'];
	const syncPatterns = ['mutex_lock', 'mutex_unlock', 'spin_lock', 'spin_unlock', 'down_read', 'up_read', 'down_write', 'up_write'];
	const userIoPatterns = ['copy_from_user', 'copy_to_user', 'get_user', 'put_user'];
	const dmaPatterns = ['dma_map_sg', 'dma_unmap_sg', 'dma_alloc_coherent', 'dma_free_coherent'];
	const processPatterns = ['capable', 'current_cred', 'ns_capable'];

	const allPatterns = [...memoryPatterns, ...refcountPatterns, ...syncPatterns, ...userIoPatterns, ...dmaPatterns, ...processPatterns];

	// Collect all symbol names for pattern matching
	const symbolNames = symbols.map(s => s.name);
	const importNames = symbols.filter(s => s.isImport).map(s => s.name);

	// a) symbolResolution (weight 0.30): resolvedExternalCalls / totalExternalCalls.
	// Clamp to [0,1] defensively: callers must feed commensurate units (both
	// call-site counts), but a stray mismatch must never break the 0-1 contract.
	const symbolResolution = totalExternalCalls > 0
		? Math.min(1.0, resolvedExternalCalls / totalExternalCalls)
		: 1.0;

	// b) cfgComplexity (weight 0.20): Normalize totalBasicBlocks / totalFunctions ratio
	// Target ratio ~5-10 BBs/func is ideal (score 1.0). Below 2 = score 0.3. Above 20 = score 0.7.
	let cfgComplexity = 0.5;
	if (totalFunctions > 0) {
		const ratio = totalBasicBlocks / totalFunctions;
		if (ratio < 2) {
			// Linear sweep quality - low complexity
			cfgComplexity = 0.3 + (ratio / 2) * 0.3;
		} else if (ratio >= 2 && ratio <= 10) {
			// Ideal range - sigmoid curve peaking at 1.0
			cfgComplexity = 0.6 + 0.4 * Math.sin((ratio - 2) / 8 * Math.PI / 2);
		} else if (ratio > 10 && ratio <= 20) {
			// Good but getting complex
			cfgComplexity = 1.0 - (ratio - 10) / 10 * 0.3;
		} else {
			// Very complex - cap at 0.7
			cfgComplexity = 0.7;
		}
	}

	// c) patternRecognition (weight 0.20): Scan resolved symbol names for known kernel patterns
	const detectedPatterns: string[] = [];
	const categoriesFound = new Set<string>();

	for (const name of symbolNames) {
		for (const pattern of memoryPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`memory:${pattern}`)) {
				detectedPatterns.push(`memory:${pattern}`);
				categoriesFound.add('memory');
			}
		}
		for (const pattern of refcountPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`refcount:${pattern}`)) {
				detectedPatterns.push(`refcount:${pattern}`);
				categoriesFound.add('refcount');
			}
		}
		for (const pattern of syncPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`sync:${pattern}`)) {
				detectedPatterns.push(`sync:${pattern}`);
				categoriesFound.add('sync');
			}
		}
		for (const pattern of userIoPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`userio:${pattern}`)) {
				detectedPatterns.push(`userio:${pattern}`);
				categoriesFound.add('userio');
			}
		}
		for (const pattern of dmaPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`dma:${pattern}`)) {
				detectedPatterns.push(`dma:${pattern}`);
				categoriesFound.add('dma');
			}
		}
		for (const pattern of processPatterns) {
			if (name.includes(pattern) && !detectedPatterns.includes(`process:${pattern}`)) {
				detectedPatterns.push(`process:${pattern}`);
				categoriesFound.add('process');
			}
		}
	}

	// Score = min(1.0, recognized_categories / 5) — finding 5+ distinct categories = perfect score
	const patternRecognition = Math.min(1.0, categoriesFound.size / 5);

	// d) externalCallCoverage (weight 0.20): Percentage of external symbols matching known patterns
	let matchedExternalCalls = 0;
	for (const name of importNames) {
		for (const pattern of allPatterns) {
			if (name.includes(pattern)) {
				matchedExternalCalls++;
				break;
			}
		}
	}
	const externalCallCoverage = importNames.length > 0 ? matchedExternalCalls / importNames.length : 0;

	// e) symtabCompleteness (weight 0.10): Check ratio of STT_FUNC symbols with st_size > 0 vs total STT_FUNC
	const funcSymbols = symbols.filter(s => s.type === 'FUNC');
	const funcWithSize = funcSymbols.filter(s => s.size > 0);
	let symtabCompleteness = funcSymbols.length > 0 ? funcWithSize.length / funcSymbols.length : 0;

	// If hasBtfInfo or hasDwarfInfo, add 0.2 bonus (capped at 1.0)
	if (hasBtfInfo || hasDwarfInfo) {
		symtabCompleteness = Math.min(1.0, symtabCompleteness + 0.2);
	}

	// f) overall: Weighted sum of all components (weights sum to 1.0)
	const overall =
		symbolResolution * 0.30 +
		cfgComplexity * 0.20 +
		patternRecognition * 0.20 +
		externalCallCoverage * 0.20 +
		symtabCompleteness * 0.10;

	return {
		overall: Math.round(overall * 100) / 100,
		symbolResolution: Math.round(symbolResolution * 100) / 100,
		cfgComplexity: Math.round(cfgComplexity * 100) / 100,
		patternRecognition: Math.round(patternRecognition * 100) / 100,
		externalCallCoverage: Math.round(externalCallCoverage * 100) / 100,
		symtabCompleteness: Math.round(symtabCompleteness * 100) / 100,
		detectedPatterns
	};
}

// v3.7.5: Enhanced PE data directories
export interface TLSDirectory {
	startAddressOfRawData: number;
	endAddressOfRawData: number;
	addressOfIndex: number;
	addressOfCallBacks: number;
	callbackAddresses: number[];
	characteristics: number;
}

export interface DebugDirectoryEntry {
	type: number;
	typeName: string;
	timestamp: Date;
	majorVersion: number;
	minorVersion: number;
	size: number;
	addressOfRawData: number;
	pointerToRawData: number;
	pdbPath?: string;
	pdbGuid?: string;
}

export interface DelayImportLibrary {
	name: string;
	handle: number;
	delayIAT: number;
	delayINT: number;
	functions: ImportFunction[];
}

export interface CLRHeader {
	majorRuntimeVersion: number;
	minorRuntimeVersion: number;
	metadataRVA: number;
	metadataSize: number;
	flags: number;
	entryPointToken: number;
	/** COMIMAGE_FLAGS_ILONLY (0x01): pure managed image, no embedded native code. */
	ilOnly: boolean;
	/** COMIMAGE_FLAGS_NATIVE_ENTRYPOINT (0x10): EntryPointToken is an RVA to native entry code. */
	isNative: boolean;
	/** COMIMAGE_FLAGS_32BITREQUIRED (0x02). */
	is32BitRequired: boolean;
}

/** v3.8.0 Pathfinder: PE64 .pdata function entry (RUNTIME_FUNCTION) */
export interface PdataEntry {
	/** Function start RVA */
	beginAddress: number;
	/** Function end RVA (first byte AFTER the function) */
	endAddress: number;
	/** RVA of UNWIND_INFO structure */
	unwindInfoAddress: number;
}

export interface PEDataDirectories {
	tls?: TLSDirectory;
	debug?: DebugDirectoryEntry[];
	delayImport?: DelayImportLibrary[];
	clr?: CLRHeader;
	/** v3.8.0 Pathfinder: .pdata function entries */
	pdata?: PdataEntry[];
	resourceRVA?: number;
	resourceSize?: number;
	securitySize?: number;
	relocSize?: number;
	loadConfigSize?: number;
}

// v3.7.5: Typed import with resolved API signature
export interface TypedImportFunction extends ImportFunction {
	signature?: ApiSignature;
}

export interface TypedImportLibrary {
	name: string;
	functions: TypedImportFunction[];
}

// v3.7.5: Import category summary for security analysis
export interface ImportCategorySummary {
	category: ApiCategory;
	label: string;
	count: number;
	functions: string[];
	tags: string[];
}

// File header info
export interface FileInfo {
	format: 'PE' | 'PE64' | 'ELF32' | 'ELF64' | 'MachO' | 'Raw';
	architecture: ArchitectureConfig;
	entryPoint: number;
	baseAddress: number;
	imageSize: number;
	timestamp?: Date;
	subsystem?: string;
	characteristics?: string[];
	/** v3.7.4: True when target is an ELF ET_REL (relocatable / .ko kernel module) */
	isRelocatable?: boolean;
}

export interface DisassemblyOptions {
	architecture: ArchitectureConfig;
	baseAddress: number;
	entryPoint?: number;
}

/**
 * v3.8.5: decode the absolute IAT-slot VA referenced by a memory-indirect `call`/`jmp` operand.
 * Shared single source of truth used by BOTH the engine post-pass (`applyIatCallNames`, which
 * stamps `instruction.comment`) AND the interactive `resolveInstructionComment` path in
 * `extension.ts` (which re-disassembles fresh), so the two paths cannot drift in their handling
 * of the operand-decode subtleties (rip-relative sign, next-instruction base, register rejection).
 *
 * PE32: the operand is `dword ptr [<abs32>]` -- the bracketed value is the absolute VA.
 * PE64: the operand is `qword ptr [rip + <disp>]` (or `- <disp>`) -- RIP-relative, so the target
 *       VA is (address of the NEXT instruction) + disp. Capstone reports the displacement, not
 *       the resolved absolute, in the opStr, so compute it here.
 *
 * Returns undefined when the operand has a base/index register other than a bare `rip` (e.g.
 * `[rax]`, `[rbx + rcx*4]`, `[rsp + 0x20]`) or is register-indirect (`rax`) -- those are not IAT
 * references and must be left alone (avoids ghost-naming a vtable / jump-table / stack slot).
 *
 * @param opStr        Capstone operand string (Intel syntax), any case.
 * @param instrAddress VA of the instruction itself (number; bigint callers must Number() first).
 * @param instrSize    encoded length in bytes (needed for the rip-relative next-instruction base).
 */
export function decodeIatOperandVA(opStr: string, instrAddress: number, instrSize: number): number | undefined {
	const op = opStr.toLowerCase();
	const lb = op.indexOf('[');
	const rb = op.indexOf(']', lb + 1);
	if (lb < 0 || rb < 0) {
		return undefined;
	}
	const inner = op.slice(lb + 1, rb).trim();

	// PE64 rip-relative: `rip + 0x...` or `rip - 0x...`.
	const ripMatch = inner.match(/^rip\s*([+-])\s*0x([0-9a-f]+)$/);
	if (ripMatch) {
		const disp = parseInt(ripMatch[2], 16);
		const signed = ripMatch[1] === '-' ? -disp : disp;
		// RIP points at the next instruction.
		const nextVA = instrAddress + instrSize;
		return (nextVA + signed) >>> 0;
	}

	// PE32 absolute: `0x...` (no base/index register). Reject anything with a register inside.
	const absMatch = inner.match(/^0x([0-9a-f]+)$/);
	if (absMatch) {
		return parseInt(absMatch[1], 16) >>> 0;
	}

	return undefined;
}

export class DisassemblerEngine {
	private currentFile?: string;
	private fileBuffer?: Buffer;
	private baseAddress: number = 0x400000;
	private architecture: ArchitectureConfig = 'x64';
	private instructions: Map<number, Instruction> = new Map();
	private functions: Map<number, Function> = new Map();
	private strings: Map<number, StringReference> = new Map();
	private comments: Map<number, string> = new Map();
	private xrefs: Map<number, XRef[]> = new Map();

	// File analysis data
	private fileInfo?: FileInfo;
	private sections: Section[] = [];
	private imports: ImportLibrary[] = [];
	private exports: ExportFunction[] = [];
	/** v3.7.5: Enhanced PE data directories (TLS, Debug, Delay Import, CLR) */
	private peDataDirectories: PEDataDirectories = {};
	/** v3.7.5: Enhanced ELF analysis data (program headers, symbols, relocations, dynamic, modinfo) */
	private elfAnalysis?: ELFAnalysis;

	/** v3.7.4 FIX-011: .rela.text relocations for ET_REL files (kernel modules, .o files).
	 *  Maps file offset (in .text) → {symbolName, relocType, addend} */
	private textRelocations: Map<number, { name: string; type: number; addend: number }> = new Map();

	/** FIX-097: .rela.text DATA relocations (R_X86_64_32/32S) against SECTION
	 *  symbols — i.e. string/constant loads like `mov rdi, .rodata.str1.1+OFF`.
	 *  These carry an empty symbol name (st_name=0 for STT_SECTION) so FIX-011
	 *  skipped them, which is why `printk(fmt, ...)` lifted as `printk(0, ...)`:
	 *  the format-string operand was never relocated and stayed `i64 0`.
	 *  Maps file offset (in .text) → {target sectionName, addend, relocType}. */
	private dataRelocations: Map<number, { sectionName: string; type: number; addend: number }> = new Map();

	/** v0.9.1 (G-001): ELF code/data sections keyed by name. Lets us resolve
	 *  a symbol's bytes when ET_REL has multiple sections all at VA 0
	 *  (`.text` / `.init.text` / `.text.unlikely` / `.exit.text`). */
	private elfSectionFileMap: Map<string, { fileOffset: number; size: number; flags: number }> = new Map();

	/** v0.9.1 (G-001): function symbols from .symtab keyed by symbol name.
	 *  Each entry tells us which section the function lives in and its
	 *  offset within that section, so we can compute the exact file offset
	 *  of its bytes. Required for ET_REL where every section starts at
	 *  VA 0 and `address: "0x0"` alone is ambiguous. */
	private elfFunctionByName: Map<string, { sectionName: string; offsetInSection: number; size: number }> = new Map();

	// Capstone Engine
	private capstone: CapstoneWrapper;
	private capstoneInitialized: boolean = false;
	private capstoneError?: string;

	// LLVM MC Assembler (for patching)
	private llvmMc: LlvmMcWrapper;
	private llvmMcInitialized: boolean = false;
	private llvmMcError?: string;

	// Configurable limits
	private maxFunctions: number = 5000;
	private maxFunctionSize: number = 65536;

	// A-lazy function discovery: every .pdata function is registered as a cheap
	// navigable STUB (correct address + endAddress, empty `instructions`) so the
	// function LIST is complete and the lift gets exact bounds (it reads bytes via
	// getBytes + the stub's endAddress, never func.instructions). The body is
	// disassembled ON DEMAND by materializeFunction() the first time its instruction
	// listing is actually read (the disasm view). This set tracks which registered
	// functions are still unmaterialized stubs. maxStubFunctions is a high ceiling so
	// ALL .pdata functions register (stubs are ~tens of bytes each, so 40K-159K stubs
	// cost tens of MB, not the 6 GB an eager body-disassembly of every one would).
	private unmaterializedStubs: Set<number> = new Set<number>();
	private maxStubFunctions: number = 250000;

	// Cache for text section byte-pattern scan results
	private _textScanCache?: Map<number, number[]>;

	// v3.7.1: VM detection results from last analyzeAll() with detectVM: true
	private _vmDetectionResults?: Map<number, { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number }>;

	// v3.8.2: linear-sweep instruction stream over ALL executable sections, built on
	// demand by analyzeAll when detectVM/detectPRNG/filterJunk is requested. This is
	// the obfuscation-resistant detection source: prologue-based function discovery
	// collapses under callfuscation/flattening (~7 functions found), so detectVM/
	// detectPRNG that only walked this.functions found nothing despite a real VM +
	// srand. The linear sweep does not depend on function discovery (same model as
	// detectCallfuscation's byte scan). x86/x64 only.
	private _execScan?: Instruction[];

	// v3.8.2: PLT-stub VA -> dynamic-symbol name (from .rela.plt + .dynsym). Used by
	// detectPRNG to resolve `call <pltStub>` to srand/rand/etc. even when the import
	// table left an entry at 0x0. Populated during ELF PLT parsing.
	private _pltSymbolMap: Map<number, string> = new Map();

	// v3.8.5: GOT-slot VA -> dynamic-symbol name (from .rela.plt r_offset + .dynsym). Lets a
	// `.plt.sec`/`.plt.got` stub (CET/IBT: endbr64 ; bnd jmp *GOT[n](%rip)) be resolved to its
	// import by reading its rip-relative GOT reference, which _pltSymbolMap (keyed by the legacy
	// `.plt` VA) cannot do on IBT binaries that call the `.plt.sec` thunk instead.
	private _gotSymbolMap: Map<number, string> = new Map();

	// v3.8.5: trap-handler gate. True when the binary installs a SIGILL/SIGTRAP/SIGSEGV
	// signal handler (sigaction/signal) and the handler ADVANCES past the faulting
	// instruction (the "behind the scenes" anti-disassembly idiom). When set, analyzeFunction
	// treats ud2/int3/hlt as NON-terminating and keeps sweeping past them, because the handler
	// resumes execution at trap_addr + trap_size. Strictly gated so that binaries which use
	// ud2/int3 as GENUINE terminators (__builtin_trap, unreachable) -- and install no trap
	// handler -- are byte-identical. Computed once in loadFile, before any analyzeFunction call.
	private trapHandlerGate: boolean = false;

	// v3.7.4: Persistent session store (renames, retypes, comments, bookmarks, analyze cache)
	private sessionStore?: SessionStore;

	constructor() {
		this.capstone = new CapstoneWrapper();
		this.llvmMc = new LlvmMcWrapper();
		this.loadConfig();
	}

	/** v3.7.4: Add XRef to the indexed map (O(1) lookup by target address). */
	private addXRef(xref: XRef): void {
		const list = this.xrefs.get(xref.to);
		if (list) {
			list.push(xref);
		} else {
			this.xrefs.set(xref.to, [xref]);
		}
	}

	private loadConfig(): void {
		const config = vscode.workspace.getConfiguration('hexcore.disassembler');
		this.maxFunctions = this.normalizePositiveInteger(config.get<number>('maxFunctions', 5000), 5000, 100, 50000);
		this.maxFunctionSize = this.normalizePositiveInteger(config.get<number>('maxFunctionSize', 65536), 65536, 1024, 1048576);
	}

	public reloadConfig(): void {
		this.loadConfig();
	}

	public getAnalysisLimits(): { maxFunctions: number; maxFunctionSize: number } {
		return {
			maxFunctions: this.maxFunctions,
			maxFunctionSize: this.maxFunctionSize
		};
	}

	public setAnalysisLimits(maxFunctions?: number, maxFunctionSize?: number): void {
		if (typeof maxFunctions === 'number') {
			this.maxFunctions = this.normalizePositiveInteger(maxFunctions, this.maxFunctions, 100, 50000);
		}
		if (typeof maxFunctionSize === 'number') {
			this.maxFunctionSize = this.normalizePositiveInteger(maxFunctionSize, this.maxFunctionSize, 1024, 1048576);
		}
	}

	private normalizePositiveInteger(
		value: number | undefined,
		fallback: number,
		minValue: number,
		maxValue: number
	): number {
		if (typeof value !== 'number' || !Number.isFinite(value)) {
			return fallback;
		}
		const normalized = Math.floor(value);
		if (normalized < minValue) {
			return minValue;
		}
		if (normalized > maxValue) {
			return maxValue;
		}
		return normalized;
	}

	/**
	 * Initialize Capstone for the given architecture
	 */
	private async ensureCapstoneInitialized(): Promise<void> {
		if (!this.capstoneInitialized) {
			try {
				await this.capstone.initialize(this.architecture);
				this.capstoneInitialized = true;
				this.capstoneError = undefined;
				console.log(`Capstone initialized for ${this.architecture}`);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				this.capstoneInitialized = false;
				this.capstoneError = `${message} ${this.getDisassemblerFallbackMessage()}`.trim();
				console.warn('Capstone initialization failed, falling back to basic decoder:', error);
			}
		} else if (this.capstone.getArchitecture() !== this.architecture) {
			await this.capstone.setArchitecture(this.architecture);
		}
	}

	private getDisassemblerFallbackMessage(): string {
		switch (this.architecture) {
			case 'x86':
			case 'x64':
			case 'arm':
			case 'arm64':
				return 'Fallback: basic built-in decoder is available for this architecture.';
			case 'mips':
			case 'mips64':
				return `Fallback: no safe instruction decoder exists for ${this.architecture}; HexCore will expose raw byte directives instead of guessing instruction semantics.`;
			default:
				return `Fallback: no safe decoder exists for architecture '${this.architecture}'.`;
		}
	}

	async loadFile(filePath: string): Promise<boolean> {
		try {
			this.loadConfig();

			if (!fs.existsSync(filePath)) {
				return false;
			}

			const stats = fs.statSync(filePath);
			const MAX_FILE_SIZE = 512 * 1024 * 1024; // 512MB
			if (stats.size > MAX_FILE_SIZE) {
				throw new Error(`File too large (${(stats.size / (1024 * 1024)).toFixed(0)}MB). Maximum supported size is 512MB.`);
			}

			this.currentFile = filePath;
			this.fileBuffer = fs.readFileSync(filePath);
			// Reset state
			this.sections = [];
			this.imports = [];
			this.exports = [];
			this.functions.clear();
			this.instructions.clear();
			this.comments.clear();
			this.xrefs.clear();
			this.strings.clear();
			this.textRelocations.clear();
			this.elfSectionFileMap.clear();
			this.elfFunctionByName.clear();
			this._textScanCache = undefined;
			this._execScan = undefined;
			this._pltSymbolMap.clear();
			this._gotSymbolMap.clear();
			this.trapHandlerGate = false;

			// v3.7.4: Initialize persistent session store
			try {
				this.sessionStore?.dispose();
				this.sessionStore = new SessionStore(filePath);
				// Import legacy annotations if they exist
				const annotationsPath = path.join(path.dirname(filePath), '.hexcore-annotations.json');
				this.sessionStore.importAnnotations(annotationsPath);
			} catch (err: unknown) {
				// SQLite unavailable or file locked — continue without persistence
				const msg = err instanceof Error ? err.message : String(err);
				console.warn(`[HexCore] SessionStore init failed: ${msg}`);
				this.sessionStore = undefined;
			}

			// Initialize architecture first (needed for base address detection in PE)
			this.architecture = this.detectArchitecture();

			// Parse file structure (sets baseAddress, fileInfo, sections, imports, exports)
			if (this.isPEFile()) {
				this.parsePEStructure();
			} else if (this.isELFFile()) {
				this.parseELFStructure();
			} else {
				this.baseAddress = 0x400000;
				this.parseRawFile();
			}

			await this.ensureCapstoneInitialized();

			// v3.8.5: decide the trap-handler gate BEFORE any function discovery runs, so
			// analyzeFunction can sweep past ud2/int3/hlt on trap-handler binaries.
			this.detectTrapHandlerGate();

			// Initial analysis from entry point
			const entryPoint = this.detectEntryPoint();
			if (entryPoint) {
				await this.analyzeFunction(entryPoint, 'entry_point');
			}

			// Analyze functions from exports
			for (const exp of this.exports) {
				if (!exp.isForwarder && exp.address > 0 && !this.functions.has(exp.address)) {
					await this.analyzeFunction(exp.address, exp.name);
				}
			}

			// Find strings
			this.findStrings();

			return true;
		} catch (error) {
			const msg = error instanceof Error ? `${error.message}\n${error.stack}` : String(error);
			console.log(`[HexCore] loadFile FAILED: ${msg}`);
			console.error('[HexCore] loadFile error:', error);
			return false;
		}
	}

	/**
	 * Load a raw buffer for disassembly without a file on disk.
	 * After calling this, use disassembleRange() to disassemble the buffer contents.
	 * Requirements: 8.2, 8.3
	 */
	loadBuffer(buffer: Buffer, baseAddress: number, arch: ArchitectureConfig): void {
		this.fileBuffer = buffer;
		this.baseAddress = baseAddress;
		this.architecture = arch;
	}

	/**
	 * Full analysis: entry point + exports + prolog scan + re-analyze empty functions
	 */
	async analyzeAll(options?: { filterJunk?: boolean; detectVM?: boolean; detectPRNG?: boolean }): Promise<number> {
		if (!this.fileBuffer) {
			return 0;
		}

		const countBefore = this.functions.size;

		// v3.7.4: Restore function table from session cache (skip re-analysis)
		if (this.sessionStore && this.functions.size === 0) {
			const cached = this.sessionStore.getCachedFunctions();
			if (cached.length > 0) {
				for (const entry of cached) {
					const addr = parseInt(entry.address, 16);
					if (!this.functions.has(addr)) {
						try {
							await this.analyzeFunction(addr, entry.name);
						} catch {
							// If analysis fails, skip this cached entry
						}
					}
				}
			}
		}

		// Scan for function prologs in code sections
		await this.scanForFunctionPrologs();

		// Re-analyze functions that ended up with 0 bytes (failed disassembly)
		const emptyFuncs = Array.from(this.functions.values()).filter(f => f.size === 0);
		for (const func of emptyFuncs) {
			// Remove and re-analyze with fresh attempt
			this.functions.delete(func.address);
			try {
				await this.analyzeFunction(func.address, func.name);
			} catch {
				// If still fails, restore the empty entry so we don't lose the name
				if (!this.functions.has(func.address)) {
					this.functions.set(func.address, func);
				}
			}
		}

		// v3.8.3 Gap-A: anchor the function table to authoritative PE64 .pdata
		// boundaries (no-op when .pdata is absent: ELF/x86/ARM64 stay byte-identical).
		await this.reconcileFunctionsWithPdata();

		// v3.8.3 Gap-K: add tail-call / trampoline edges (unconditional jmp/B to another
		// function entry) that prologue-time wiring missed. Additive; runs after reconcile
		// so the rebuilt (call-only) PE64 graph also gains its tail edges.
		this.addTailCallEdges();

		// v3.8.3: relabel ELF PLT-stub functions (auto-named sub_*) with their resolved
		// import name from the .rela.plt/.dynsym map (e.g. sub_555555555030 -> puts@plt),
		// so calls through the PLT are readable instead of anonymous.
		this.applyPltStubNames();

		// v3.8.5: PE analog of @plt naming. The engine resolves the IAT (parsePEImports records
		// each import's slot VA) but never wired it onto the call sites, so PE disassembly showed
		// `call dword ptr [0x402000]` instead of `call ReadFile`. Stamp instruction.comment with
		// the import name on every direct call/jmp through an IAT slot (PE32 abs + PE64 rip-rel).
		// PE-gated and additive (only fills an empty comment); ELF/string-xref/PLT logic untouched.
		this.applyIatCallNames();

		// v3.8.3: drop mid-function prologue ghost functions on ELF (no .pdata). Runs AFTER
		// addTailCallEdges so callers are fully populated; only an interior function with NO
		// callers (a ghost - a real function is reached by a call/tail-jump) is removed.
		this.dropInteriorGhostFunctions();

		// v3.8.3 Gap-A follow-on: drop interior ghosts on PE binaries WITHOUT usable .pdata
		// even when they carry (spurious) caller edges. Closes the 32-bit-PE / no-.pdata-x64-PE
		// case (debugme: 284, maze: 1124) that neither reconcileFunctionsWithPdata (needs
		// .pdata) nor dropInteriorGhostFunctions (zero-caller only) reaches. PE-only,
		// .pdata-absent, non-ET_REL gated; ELF and x64-PE-with-.pdata are byte-identical.
		this.dropInteriorGhostFunctionsPE();

		// v3.8.3: scrub dangling callees across ALL binaries. analyzeFunction wires a callee
		// for any call to executable bytes even when the target is not a discovered function
		// (PLT-less externals, filtered/data code), leaving call-graph edges that point at
		// nothing. The PE64 path was cleaned by reconcileFunctionsWithPdata's rebuild; this
		// makes the ELF / no-.pdata call graph consistent too (e.g. mali had ~1600 dangling).
		this.scrubDanglingCallees();

		// Build string cross-references
		this.buildStringXrefs();

		// v3.8.2: Build the obfuscation-resistant linear instruction sweep ONCE when
		// any of the v3.7 detection passes is requested. detectVM/detectPRNG read it
		// directly so they work even when prologue discovery collapses under
		// callfuscation/flattening. Cost is bounded and only paid when requested.
		if (options?.detectVM || options?.detectPRNG || options?.filterJunk) {
			await this.buildExecScan();
		}

		// v3.7.1: Apply junk instruction filtering to all analyzed functions
		if (options?.filterJunk) {
			for (const func of this.functions.values()) {
				if (func.instructions.length > 0) {
					const { filtered } = this.filterJunkInstructions(func.instructions);
					func.instructions = filtered;
				}
			}
		}

		// v3.7.1: Run VM detection on all analyzed functions
		if (options?.detectVM) {
			this._vmDetectionResults = new Map();
			for (const func of this.functions.values()) {
				if (func.instructions.length > 0) {
					const vmResult = this.detectVM(func.address);
					this._vmDetectionResults.set(func.address, vmResult);
				}
			}
		}

		// v3.7.4: Persist discovered functions to session cache
		if (this.sessionStore) {
			try {
				this.sessionStore.clearCache();
				for (const func of this.functions.values()) {
					this.sessionStore.cacheFunction(
						`0x${func.address.toString(16)}`,
						func.name,
						func.size,
						func.endAddress
					);
				}
			} catch {
				// Non-critical — continue without cache persistence
			}
		}

		return this.functions.size - countBefore;
	}


	/**
	 * Detect architecture from file headers
	 */
	private detectArchitecture(): ArchitectureConfig {
		if (!this.fileBuffer) {
			return 'x64';
		}

		if (this.isPEFile()) {
			const peOffset = this.fileBuffer.readUInt32LE(0x3C);
			if (peOffset + 6 < this.fileBuffer.length) {
				const machine = this.fileBuffer.readUInt16LE(peOffset + 4);
				switch (machine) {
					case 0x014c: return 'x86';   // IMAGE_FILE_MACHINE_I386
					case 0x8664: return 'x64';   // IMAGE_FILE_MACHINE_AMD64
					case 0x01c0: return 'arm';   // IMAGE_FILE_MACHINE_ARM
					case 0xaa64: return 'arm64'; // IMAGE_FILE_MACHINE_ARM64
				}
			}
		}

		if (this.isELFFile()) {
			const elfClass = this.fileBuffer[4];
			const isLE = this.fileBuffer[5] === 1;
			const machine = isLE
				? this.fileBuffer.readUInt16LE(18)
				: this.fileBuffer.readUInt16BE(18);
			switch (machine) {
				case 0x03: return elfClass === 2 ? 'x64' : 'x86';
				case 0x3E: return 'x64';
				case 0x28: return 'arm';
				case 0xB7: return 'arm64';
				case 0x08: return 'mips';
			}
		}

		return 'x64';
	}

	async disassembleRange(startAddr: number, size: number): Promise<Instruction[]> {
		await this.ensureCapstoneInitialized();

		const offset = this.addressToOffset(startAddr);
		if (offset < 0 || offset >= this.fileBuffer!.length) {
			return [];
		}

		const endOffset = Math.min(offset + size, this.fileBuffer!.length);
		const bytesToDisasm = this.fileBuffer!.subarray(offset, endOffset);

		if (this.capstoneInitialized) {
			const rawInstructions = await this.capstone.disassemble(bytesToDisasm, startAddr, 1000);
			return rawInstructions.map(inst => this.convertCapstoneInstruction(inst));
		}

		return this.disassembleRangeFallback(startAddr, size);
	}

	private convertCapstoneInstruction(inst: DisassembledInstruction): Instruction {
		const instruction: Instruction = {
			address: inst.address,
			bytes: inst.bytes,
			mnemonic: inst.mnemonic,
			opStr: inst.opStr,
			size: inst.size,
			comment: this.comments.get(inst.address),
			isCall: inst.isCall,
			isJump: inst.isJump,
			isRet: inst.isRet,
			isConditional: inst.isConditional,
			targetAddress: inst.targetAddress
		};

		this.instructions.set(inst.address, instruction);
		return instruction;
	}

	/**
	 * Fallback disassembly for when Capstone is not available.
	 * Supports x86/x64 and basic ARM64/ARM32 decoding.
	 */
	private disassembleRangeFallback(startAddr: number, size: number): Instruction[] {
		const instructions: Instruction[] = [];
		let offset = this.addressToOffset(startAddr);
		let addr = startAddr;
		const endOffset = Math.min(offset + size, this.fileBuffer!.length);
		const isARM64 = this.architecture === 'arm64';
		const isARM32 = this.architecture === 'arm';
		const isStructuredFallback = isARM64 || isARM32 || this.architecture === 'x86' || this.architecture === 'x64';

		if (isARM64 || isARM32) {
			// ARM: Fixed-width 4-byte instructions
			while (offset + 4 <= endOffset && instructions.length < 1000) {
				const word = this.fileBuffer!.readUInt32LE(offset);
				const bytes = this.fileBuffer!.subarray(offset, offset + 4);
				const inst = isARM64
					? this.decodeARM64Fallback(word, addr, bytes)
					: this.decodeARM32Fallback(word, addr, bytes);
				instructions.push(inst);
				this.instructions.set(addr, inst);
				offset += 4;
				addr += 4;
			}
		} else if (isStructuredFallback) {
			// x86/x64: Variable-length instructions
			while (offset < endOffset && instructions.length < 1000) {
				const inst = this.disassembleInstructionFallback(offset, addr);
				if (inst) {
					instructions.push(inst);
					this.instructions.set(addr, inst);
					offset += inst.size;
					addr += inst.size;
				} else {
					const dataByte = this.fileBuffer![offset];
					instructions.push({
						address: addr,
						bytes: Buffer.from([dataByte]),
						mnemonic: 'db',
						opStr: `0x${dataByte.toString(16).padStart(2, '0').toUpperCase()}`,
						size: 1,
						isCall: false,
						isJump: false,
						isRet: false,
						isConditional: false
					});
					offset++;
					addr++;
				}
			}
		} else {
			while (offset < endOffset && instructions.length < 1000) {
				const dataByte = this.fileBuffer![offset];
				const inst = this.createInstruction(
					addr,
					Buffer.from([dataByte]),
					'.byte',
					`0x${dataByte.toString(16).padStart(2, '0').toUpperCase()}`,
					1,
					false,
					false,
					false,
					false
				);
				instructions.push(inst);
				this.instructions.set(addr, inst);
				offset++;
				addr++;
			}
		}

		return instructions;
	}

	/**
	 * Basic ARM64 (AArch64) instruction decoder fallback.
	 * Only decodes the most common instructions for function discovery.
	 */
	private decodeARM64Fallback(word: number, addr: number, bytes: Buffer): Instruction {
		// NOP: 0xD503201F
		if (word === 0xD503201F) {
			return this.createInstruction(addr, bytes, 'nop', '', 4, false, false, false, false);
		}

		// RET: 0xD65F03C0 (ret x30)
		if ((word & 0xFFFFFC1F) === 0xD65F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'ret', rn === 30 ? '' : `x${rn}`, 4, false, false, true, false);
		}

		// BL imm26 (call): 1001_01ii_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0xFC000000) === 0x94000000) {
			let imm26 = word & 0x03FFFFFF;
			if (imm26 & 0x02000000) { imm26 |= ~0x03FFFFFF; } // sign extend
			const target = addr + (imm26 << 2);
			return this.createInstruction(addr, bytes, 'bl', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, true, false, false, false, target);
		}

		// B imm26 (jump): 0001_01ii_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0xFC000000) === 0x14000000) {
			let imm26 = word & 0x03FFFFFF;
			if (imm26 & 0x02000000) { imm26 |= ~0x03FFFFFF; }
			const target = addr + (imm26 << 2);
			return this.createInstruction(addr, bytes, 'b', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, false, target);
		}

		// B.cond imm19: 0101_0100_iiii_iiii_iiii_iiii_iii0_cccc
		if ((word & 0xFF000010) === 0x54000000) {
			const cond = word & 0xF;
			const condNames = ['eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc', 'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv'];
			let imm19 = (word >> 5) & 0x7FFFF;
			if (imm19 & 0x40000) { imm19 |= ~0x7FFFF; }
			const target = addr + (imm19 << 2);
			return this.createInstruction(addr, bytes, `b.${condNames[cond]}`, `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, cond !== 14, target);
		}

		// CBZ/CBNZ: x011_010x_iiii_iiii_iiii_iiii_iiit_tttt
		if ((word & 0x7E000000) === 0x34000000) {
			const is64 = (word >> 31) & 1;
			const isNZ = (word >> 24) & 1;
			const rt = word & 0x1F;
			let imm19 = (word >> 5) & 0x7FFFF;
			if (imm19 & 0x40000) { imm19 |= ~0x7FFFF; }
			const target = addr + (imm19 << 2);
			const regPrefix = is64 ? 'x' : 'w';
			return this.createInstruction(addr, bytes, isNZ ? 'cbnz' : 'cbz', `${regPrefix}${rt}, #0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, true, target);
		}

		// STP x29, x30, [sp, #imm] — common prolog (any addressing mode)
		if ((word & 0xFC407FFF) === 0xA8007BFD) {
			const imm7 = (word >> 15) & 0x7F;
			const offset = ((imm7 & 0x40) ? (imm7 | ~0x7F) : imm7) * 8;
			return this.createInstruction(addr, bytes, 'stp', `x29, x30, [sp, #${offset}]!`, 4, false, false, false, false);
		}

		// LDP x29, x30, [sp], #imm — common epilog
		if ((word & 0xFFFF83FF) === 0xA8C003FD) {
			const imm7 = (word >> 15) & 0x7F;
			const offset = ((imm7 & 0x40) ? (imm7 | ~0x7F) : imm7) * 8;
			return this.createInstruction(addr, bytes, 'ldp', `x29, x30, [sp], #${offset}`, 4, false, false, false, false);
		}

		// BLR Xn (indirect call): 1101_0110_0011_1111_0000_00nn_nnn0_0000
		if ((word & 0xFFFFFC1F) === 0xD63F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'blr', `x${rn}`, 4, true, false, false, false);
		}

		// BR Xn (indirect jump): 1101_0110_0001_1111_0000_00nn_nnn0_0000
		if ((word & 0xFFFFFC1F) === 0xD61F0000) {
			const rn = (word >> 5) & 0x1F;
			return this.createInstruction(addr, bytes, 'br', `x${rn}`, 4, false, true, false, false);
		}

		// Default: emit as .word
		return this.createInstruction(addr, bytes, '.word', `0x${word.toString(16).padStart(8, '0').toUpperCase()}`, 4, false, false, false, false);
	}

	/**
	 * Basic ARM32 instruction decoder fallback.
	 */
	private decodeARM32Fallback(word: number, addr: number, bytes: Buffer): Instruction {
		const cond = (word >>> 28) & 0xF;

		// NOP: E320F000 or E1A00000 (mov r0, r0)
		if (word === 0xE320F000 || word === 0xE1A00000) {
			return this.createInstruction(addr, bytes, 'nop', '', 4, false, false, false, false);
		}

		// BX LR (return): cond_0001_0010_1111_1111_1111_0001_1110 = xxE12FFF1E
		if ((word & 0x0FFFFFFF) === 0x012FFF1E) {
			return this.createInstruction(addr, bytes, 'bx', 'lr', 4, false, false, true, false);
		}

		// POP {pc} or LDM SP!, {... pc} — also a return
		// LDMIA SP!, {reglist} with bit 15 set (PC): cond_1000_1011_1101_RRRR_RRRR_RRRR_RRRR
		if ((word & 0x0FFF0000) === 0x08BD0000 && (word & (1 << 15)) !== 0) {
			return this.createInstruction(addr, bytes, 'pop', '{..., pc}', 4, false, false, true, false);
		}

		// BL imm24 (call): cond_1011_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0x0F000000) === 0x0B000000) {
			let imm24 = word & 0x00FFFFFF;
			if (imm24 & 0x00800000) { imm24 |= ~0x00FFFFFF; }
			const target = addr + 8 + (imm24 << 2); // ARM32: PC+8 pipeline
			return this.createInstruction(addr, bytes, 'bl', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, true, false, false, false, target);
		}

		// B imm24 (jump): cond_1010_iiii_iiii_iiii_iiii_iiii_iiii
		if ((word & 0x0F000000) === 0x0A000000) {
			let imm24 = word & 0x00FFFFFF;
			if (imm24 & 0x00800000) { imm24 |= ~0x00FFFFFF; }
			const target = addr + 8 + (imm24 << 2);
			const isConditional = cond !== 0xE; // 0xE = always
			return this.createInstruction(addr, bytes, 'b', `#0x${(target >>> 0).toString(16).toUpperCase()}`, 4, false, true, false, isConditional, target);
		}

		// PUSH {reglist}: STMDB SP!, {reglist} = cond_1001_0010_1101_RRRR_RRRR_RRRR_RRRR
		if ((word & 0x0FFF0000) === 0x092D0000) {
			return this.createInstruction(addr, bytes, 'push', '{...}', 4, false, false, false, false);
		}

		// Default: emit as .word
		return this.createInstruction(addr, bytes, '.word', `0x${word.toString(16).padStart(8, '0').toUpperCase()}`, 4, false, false, false, false);
	}

	private disassembleInstructionFallback(offset: number, addr: number): Instruction | null {
		if (offset >= this.fileBuffer!.length) {
			return null;
		}

		const byte = this.fileBuffer![offset];

		if (byte === 0x90) {
			return this.createInstruction(addr, Buffer.from([byte]), 'nop', '', 1, false, false, false, false);
		}
		if (byte === 0xC3) {
			return this.createInstruction(addr, Buffer.from([byte]), 'ret', '', 1, false, false, true, false);
		}
		if (byte === 0xCC) {
			return this.createInstruction(addr, Buffer.from([byte]), 'int3', '', 1, false, false, false, false);
		}

		// CALL rel32
		if (byte === 0xE8 && offset + 5 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt32LE(offset + 1);
			const target = addr + 5 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'call', `0x${target.toString(16).toUpperCase()}`,
				5, true, false, false, false, target
			);
		}

		// JMP rel32
		if (byte === 0xE9 && offset + 5 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt32LE(offset + 1);
			const target = addr + 5 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'jmp', `0x${target.toString(16).toUpperCase()}`,
				5, false, true, false, false, target
			);
		}

		// JMP rel8
		if (byte === 0xEB && offset + 2 <= this.fileBuffer!.length) {
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 2),
				'jmp', `0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, false, target
			);
		}

		// PUSH r64 (0x50-0x57)
		if (byte >= 0x50 && byte <= 0x57) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(addr, Buffer.from([byte]), 'push', regs[byte - 0x50], 1, false, false, false, false);
		}

		// POP r64 (0x58-0x5F)
		if (byte >= 0x58 && byte <= 0x5F) {
			const regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi'];
			return this.createInstruction(addr, Buffer.from([byte]), 'pop', regs[byte - 0x58], 1, false, false, false, false);
		}

		// Conditional jumps (0x70-0x7F)
		if (byte >= 0x70 && byte <= 0x7F && offset + 2 <= this.fileBuffer!.length) {
			const conditions = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe', 's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle'];
			const rel = this.fileBuffer!.readInt8(offset + 1);
			const target = addr + 2 + rel;
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 2),
				`j${conditions[byte - 0x70]}`, `0x${target.toString(16).toUpperCase()}`,
				2, false, true, false, true, target
			);
		}

		// MOV reg, imm (0xB8-0xBF for 32/64-bit)
		if (byte >= 0xB8 && byte <= 0xBF && offset + 5 <= this.fileBuffer!.length) {
			const regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi'];
			const imm = this.fileBuffer!.readUInt32LE(offset + 1);
			return this.createInstruction(
				addr, this.fileBuffer!.subarray(offset, offset + 5),
				'mov', `${regs[byte - 0xB8]}, 0x${imm.toString(16).toUpperCase()}`,
				5, false, false, false, false
			);
		}

		// SUB RSP, imm8 (0x48 0x83 0xEC imm8) - common x64 prolog
		if (byte === 0x48 && offset + 4 <= this.fileBuffer!.length) {
			const byte2 = this.fileBuffer![offset + 1];
			const byte3 = this.fileBuffer![offset + 2];
			if (byte2 === 0x83 && byte3 === 0xEC) {
				const imm = this.fileBuffer![offset + 3];
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 4),
					'sub', `rsp, 0x${imm.toString(16).toUpperCase()}`,
					4, false, false, false, false
				);
			}
			// MOV RBP, RSP (0x48 0x89 0xE5)
			if (byte2 === 0x89 && byte3 === 0xE5) {
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 3),
					'mov', 'rbp, rsp',
					3, false, false, false, false
				);
			}
		}

		// 2-byte conditional jumps (0x0F 0x80-0x8F)
		if (byte === 0x0F && offset + 6 <= this.fileBuffer!.length) {
			const byte2 = this.fileBuffer![offset + 1];
			if (byte2 >= 0x80 && byte2 <= 0x8F) {
				const conditions = ['o', 'no', 'b', 'nb', 'z', 'nz', 'be', 'nbe', 's', 'ns', 'p', 'np', 'l', 'nl', 'le', 'nle'];
				const rel = this.fileBuffer!.readInt32LE(offset + 2);
				const target = addr + 6 + rel;
				return this.createInstruction(
					addr, this.fileBuffer!.subarray(offset, offset + 6),
					`j${conditions[byte2 - 0x80]}`, `0x${target.toString(16).toUpperCase()}`,
					6, false, true, false, true, target
				);
			}
		}

		return null;
	}

	private createInstruction(
		address: number, bytes: Buffer, mnemonic: string, opStr: string, size: number,
		isCall: boolean = false, isJump: boolean = false, isRet: boolean = false,
		isConditional: boolean = false, targetAddress?: number
	): Instruction {
		return { address, bytes, mnemonic, opStr, size, comment: this.comments.get(address), isCall, isJump, isRet, isConditional, targetAddress };
	}

	// ============================================================================
	// String Analysis
	// ============================================================================

	/**
	 * Extract strings from the binary.
	 * @param sectionNames - Optional list of PE section names to limit scanning (e.g. [".rdata", ".data"]).
	 *                       When omitted, scans the entire file buffer.
	 * @param minLength - Minimum string length (default: 4).
	 */
	async findStrings(sectionNames?: string[], minLength: number = 4): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		// v3.7.4: Compute scan ranges from section names
		let scanRanges: Array<{ start: number; end: number }>;
		if (sectionNames && sectionNames.length > 0) {
			scanRanges = [];
			for (const secName of sectionNames) {
				const sec = this.sections.find(s => s.name === secName || s.name === secName.replace(/^\./, ''));
				if (sec) {
					scanRanges.push({ start: sec.rawAddress, end: sec.rawAddress + sec.rawSize });
				}
			}
			if (scanRanges.length === 0) { return; } // no matching sections
		} else {
			scanRanges = [{ start: 0, end: this.fileBuffer.length }];
		}

		// ASCII strings
		const asciiPattern = new RegExp(`[\\x20-\\x7E]{${minLength},}`, 'g');

		for (const range of scanRanges) {
			const text = this.fileBuffer.subarray(range.start, range.end).toString('binary');
			let match;
			while ((match = asciiPattern.exec(text)) !== null) {
				if (match[0].length <= 16384) {
					const offset = range.start + match.index;
					const str = match[0];
					const addr = this.offsetToAddress(offset);
					this.strings.set(addr, { address: addr, string: str, encoding: 'ascii', references: [] });
				}
			}
		}

		// Unicode strings (UTF-16 LE)
		for (const range of scanRanges) {
			const rangeStart = range.start % 2 === 0 ? range.start : range.start + 1; // align to 2
			for (let i = rangeStart; i < range.end - 8; i += 2) {
				let len = 0;
				while (i + len * 2 < range.end - 1) {
					const char = this.fileBuffer.readUInt16LE(i + len * 2);
					if (char === 0 || char > 0x7E) {
						break;
					}
					len++;
				}
				if (len >= minLength && len <= 512) {
					const str = this.fileBuffer.toString('utf16le', i, i + len * 2);
					const addr = this.offsetToAddress(i);
					if (!this.strings.has(addr)) {
						this.strings.set(addr, { address: addr, string: str, encoding: 'unicode', references: [] });
					}
					i += len * 2;
				}
			}
		}
	}

	/**
	 * Build string cross-references from disassembled instructions
	 */
	private buildStringXrefs(): void {
		const addrRegex = /0x([0-9a-fA-F]+)/g;

		for (const inst of this.instructions.values()) {
			if (!inst.opStr) {
				continue;
			}
			let addrMatch;
			while ((addrMatch = addrRegex.exec(inst.opStr)) !== null) {
				const targetAddr = parseInt(addrMatch[1], 16);
				const strRef = this.strings.get(targetAddr);
				if (strRef) {
					if (!strRef.references.includes(inst.address)) {
						strRef.references.push(inst.address);
					}
					this.addXRef({ from: inst.address, to: targetAddr, type: 'string' });
				}
			}
			addrRegex.lastIndex = 0;

			// Data xrefs: any address reference to non-string data
			if (inst.targetAddress && !inst.isCall && !inst.isJump) {
				this.addXRef({ from: inst.address, to: inst.targetAddress, type: 'data' });
			}
		}

		// Complement with byte-pattern scan for strings with no xrefs from this.instructions
		const unresolvedAddrs = new Set<number>();
		for (const strRef of this.strings.values()) {
			if (strRef.references.length === 0) {
				unresolvedAddrs.add(strRef.address);
			}
		}

		if (unresolvedAddrs.size > 0) {
			const scanResults = this.scanTextSectionForStringRefs(unresolvedAddrs);
			for (const [strAddr, instrAddrs] of scanResults) {
				const strRef = this.strings.get(strAddr);
				if (strRef) {
					for (const instrAddr of instrAddrs) {
						if (!strRef.references.includes(instrAddr)) {
							strRef.references.push(instrAddr);
						}
						this.addXRef({ from: instrAddr, to: strAddr, type: 'string' });
					}
				}
			}
		}
	}

	/**
	 * Scan executable sections (.text) for byte patterns that reference known string addresses.
	 * Complements buildStringXrefs() which only scans this.instructions.
	 *
	 * For x64: Scans for LEA RIP-relative (48 8D xx [disp32]) and absolute address patterns.
	 *          Also scans for LEA without REX.W prefix (8D xx [disp32]) — 6-byte form.
	 * For x86: Scans for absolute 4-byte addresses in little-endian.
	 *
	 * @param targetAddresses Set of virtual addresses of strings to search for
	 * @returns Map from string address to array of instruction addresses that reference it
	 */
	private scanTextSectionForStringRefs(targetAddresses: Set<number>): Map<number, number[]> {
		const result = new Map<number, number[]>();

		if (!this.fileBuffer || targetAddresses.size === 0) {
			return result;
		}

		// Return cached results if available and covers requested addresses
		if (this._textScanCache) {
			let allCached = true;
			for (const addr of targetAddresses) {
				if (!this._textScanCache.has(addr)) {
					allCached = false;
					break;
				}
			}
			if (allCached) {
				for (const addr of targetAddresses) {
					const refs = this._textScanCache.get(addr);
					if (refs && refs.length > 0) {
						result.set(addr, refs);
					}
				}
				return result;
			}
		}

		// Find executable sections
		const execSections = this.sections.filter(s => s.isCode || s.isExecutable);
		if (execSections.length === 0) {
			return result;
		}

		const buf = this.fileBuffer;

		for (const section of execSections) {
			const rawStart = section.rawAddress;
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
			if (rawStart >= buf.length || rawEnd <= rawStart) {
				continue;
			}

			if (this.architecture === 'x64') {
				// --- LEA RIP-relative with REX.W prefix: 48 8D [ModR/M] [disp32] (7 bytes) ---
				for (let i = rawStart; i + 7 <= rawEnd; i++) {
					if (buf[i] === 0x48 && buf[i + 1] === 0x8D && (buf[i + 2] & 0xC7) === 0x05) {
						const disp32 = buf.readInt32LE(i + 3);
						const instrVA = this.sectionOffsetToAddress(i, section);
						const targetAddr = instrVA + 7 + disp32;
						if (targetAddresses.has(targetAddr)) {
							let refs = result.get(targetAddr);
							if (!refs) {
								refs = [];
								result.set(targetAddr, refs);
							}
							if (!refs.includes(instrVA)) {
								refs.push(instrVA);
							}
						}
					}
				}

				// --- LEA RIP-relative without REX.W prefix: 8D [ModR/M] [disp32] (6 bytes) ---
				for (let i = rawStart; i + 6 <= rawEnd; i++) {
					if (buf[i] === 0x8D && (buf[i + 1] & 0xC7) === 0x05) {
						// Skip if previous byte is 0x48 (already handled above as REX.W LEA)
						if (i > rawStart && buf[i - 1] === 0x48) {
							continue;
						}
						const disp32 = buf.readInt32LE(i + 2);
						const instrVA = this.sectionOffsetToAddress(i, section);
						const targetAddr = instrVA + 6 + disp32;
						if (targetAddresses.has(targetAddr)) {
							let refs = result.get(targetAddr);
							if (!refs) {
								refs = [];
								result.set(targetAddr, refs);
							}
							if (!refs.includes(instrVA)) {
								refs.push(instrVA);
							}
						}
					}
				}

				// --- Absolute 4-byte addresses (MOV with immediate, etc.) ---
				for (let i = rawStart; i + 4 <= rawEnd; i++) {
					const val = buf.readUInt32LE(i);
					if (targetAddresses.has(val)) {
						const instrVA = this.sectionOffsetToAddress(i, section);
						let refs = result.get(val);
						if (!refs) {
							refs = [];
							result.set(val, refs);
						}
						if (!refs.includes(instrVA)) {
							refs.push(instrVA);
						}
					}
				}
			} else if (this.architecture === 'x86') {
				// --- x86: Absolute 4-byte addresses in little-endian ---
				for (let i = rawStart; i + 4 <= rawEnd; i++) {
					const val = buf.readUInt32LE(i);
					if (targetAddresses.has(val)) {
						const instrVA = this.sectionOffsetToAddress(i, section);
						let refs = result.get(val);
						if (!refs) {
							refs = [];
							result.set(val, refs);
						}
						if (!refs.includes(instrVA)) {
							refs.push(instrVA);
						}
					}
				}
			} else if (this.architecture === 'arm64') {
				// --- ARM64: ADRP Xn, #imm  +  ADD Xn, Xn, #imm12 ---
				// Reference: ARM ARM DDI 0487 C6.2.12 (ADRP), C6.2.4 (ADD imm).
				// ADRP encoding: 1_immlo(2)_10000_immhi(19)_Rd(5), opcode bits
				//   top byte = 1xx_10000 → mask 0x9F000000, value 0x90000000.
				// Result: PC-relative page base (bit 12 aligned), target = page | add_imm12.
				// ADD imm: sf=1, opc=0b00 (ADD), sh(0/1), imm12, Rn, Rd.
				//   mask 0xFF800000, value 0x91000000 (sf=1, imm shift=0),
				//   variant with imm<<12 (sh=1) → value 0x91400000; covers both.
				// Track pending page base per destination register; when matching ADD
				// with same Rn==Rd resolves within a short window, compute target.
				// Also pattern: ADRP + LDR Xd, [Xn, #:lo12:sym]  (mask 0xFFC00000 / 0xF9400000)
				// Windows short — 8 instructions — keeps false positives down.
				const WINDOW = 8 * 4; // instructions * bytes
				const pageBases = new Map<number, { page: number; addr: number }>();
				for (let i = rawStart; i + 4 <= rawEnd; i += 4) {
					const word = buf.readUInt32LE(i);
					const instrVA = this.sectionOffsetToAddress(i, section);

					// ADRP — note: do NOT use >>> 0 to truncate. On PIE AArch64 the base
					// can be 0x5555_5555_4000 which exceeds 32 bits. Using JS arithmetic
					// on a plain number keeps up to 53-bit precision, enough for page
					// bases on any realistic ELF/Mach-O/PE ARM64 binary.
					if ((word & 0x9F000000) === 0x90000000) {
						const rd = word & 0x1F;
						const immlo = (word >>> 29) & 0x3;
						const immhi = (word >>> 5) & 0x7FFFF;
						let imm = (immhi << 2) | immlo;
						if (imm & 0x100000) { imm |= ~0x1FFFFF; } // sign-extend 21-bit
						// instrVA & ~0xFFF is safe because ~0xFFF becomes -0x1000 (i32),
						// which produces wrong high bits for addresses >= 2^31. Use
						// arithmetic form instead: (instrVA - (instrVA % 0x1000)).
						const pcPage = instrVA - (instrVA % 0x1000);
						const page = pcPage + imm * 0x1000;
						pageBases.set(rd, { page, addr: instrVA });
						continue;
					}

					// ADD (immediate, 64-bit): sf=1, op=0, S=0, shift={00|01}
					// mask 0xFFC00000 matches both shift=0 and shift=1 variants when using
					// 0x91000000; explicitly cover shift=1 (imm<<12) variant 0x91400000 too.
					if ((word & 0xFF800000) === 0x91000000 || (word & 0xFF800000) === 0x91400000) {
						const rd = word & 0x1F;
						const rn = (word >>> 5) & 0x1F;
						const imm12 = (word >>> 10) & 0xFFF;
						const shift = ((word >>> 22) & 0x1) ? 12 : 0;
						const base = pageBases.get(rn);
						if (base && rn === rd && instrVA - base.addr <= WINDOW) {
							// No >>> 0 truncation — page can exceed 2^32 on PIE.
							const target = base.page + imm12 * (1 << shift);
							if (targetAddresses.has(target)) {
								let refs = result.get(target);
								if (!refs) { refs = []; result.set(target, refs); }
								if (!refs.includes(base.addr)) { refs.push(base.addr); }
								if (!refs.includes(instrVA)) { refs.push(instrVA); }
							}
							pageBases.delete(rd);
						}
						continue;
					}

					// LDR (immediate, unsigned offset, 64-bit): size=11, V=0, opc=01
					// Encoding 1111 1001 01ii iiii iiii iinn nnnd dddd → mask 0xFFC00000,
					// value 0xF9400000. imm12 is scaled by 8.
					if ((word & 0xFFC00000) === 0xF9400000) {
						const rn = (word >>> 5) & 0x1F;
						const imm12 = (word >>> 10) & 0xFFF;
						const base = pageBases.get(rn);
						if (base && instrVA - base.addr <= WINDOW) {
							const target = base.page + imm12 * 8;
							if (targetAddresses.has(target)) {
								let refs = result.get(target);
								if (!refs) { refs = []; result.set(target, refs); }
								if (!refs.includes(base.addr)) { refs.push(base.addr); }
								if (!refs.includes(instrVA)) { refs.push(instrVA); }
							}
							// Do not invalidate page base — the same ADRP may feed multiple loads.
						}
					}
				}

				// --- ARM64: also scan for absolute 8-byte addresses in exec sections
				// (vtables, jump tables embedded in .text are rare but occur in Go/Rust).
				for (let i = rawStart; i + 8 <= rawEnd; i += 4) {
					const val = Number(buf.readBigUInt64LE(i));
					if (targetAddresses.has(val)) {
						const instrVA = this.sectionOffsetToAddress(i, section);
						let refs = result.get(val);
						if (!refs) { refs = []; result.set(val, refs); }
						if (!refs.includes(instrVA)) { refs.push(instrVA); }
					}
				}
			}
		}

		// Cache results
		if (!this._textScanCache) {
			this._textScanCache = new Map();
		}
		for (const addr of targetAddresses) {
			const refs = result.get(addr);
			this._textScanCache.set(addr, refs ?? []);
		}

		return result;
	}

	async analyzeEntryPoint(): Promise<void> {
		const ep = this.detectEntryPoint();
		if (ep) {
			await this.analyzeFunction(ep, '_start');
		}
	}

	private isPEFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 64) {
			return false;
		}
		return this.fileBuffer[0] === 0x4D && this.fileBuffer[1] === 0x5A;
	}

	private isELFFile(): boolean {
		if (!this.fileBuffer || this.fileBuffer.length < 16) {
			return false;
		}
		return this.fileBuffer[0] === 0x7F &&
			this.fileBuffer[1] === 0x45 &&
			this.fileBuffer[2] === 0x4C &&
			this.fileBuffer[3] === 0x46;
	}

	// ============================================================================
	// PE Structure Parsing (inline - no external extension dependency)
	// ============================================================================

	private parsePEStructure(): void {
		if (!this.fileBuffer || this.fileBuffer.length < 64) {
			return;
		}

		const peOffset = this.fileBuffer.readUInt32LE(0x3C);
		if (peOffset + 24 >= this.fileBuffer.length) {
			return;
		}

		// Verify PE signature
		const peSignature = this.fileBuffer.readUInt32LE(peOffset);
		if (peSignature !== 0x00004550) { // "PE\0\0"
			return;
		}

		// COFF Header (20 bytes after signature)
		const coffOffset = peOffset + 4;
		const machine = this.fileBuffer.readUInt16LE(coffOffset);
		const numberOfSections = this.fileBuffer.readUInt16LE(coffOffset + 2);
		const timeDateStamp = this.fileBuffer.readUInt32LE(coffOffset + 4);
		const sizeOfOptionalHeader = this.fileBuffer.readUInt16LE(coffOffset + 16);

		// Optional Header
		const optOffset = coffOffset + 20;
		if (optOffset + 2 >= this.fileBuffer.length) {
			return;
		}
		const magic = this.fileBuffer.readUInt16LE(optOffset);
		const is64 = magic === 0x20B; // PE32+

		let imageBase: number;
		let entryPointRVA: number;
		let sizeOfImage: number;
		let numberOfRvaAndSizes: number;
		let dataDirectoryOffset: number;
		let subsystem: number;

		if (is64) {
			entryPointRVA = this.fileBuffer.readUInt32LE(optOffset + 16);
			imageBase = Number(this.fileBuffer.readBigUInt64LE(optOffset + 24));
			sizeOfImage = this.fileBuffer.readUInt32LE(optOffset + 56);
			subsystem = this.fileBuffer.readUInt16LE(optOffset + 68);
			numberOfRvaAndSizes = this.fileBuffer.readUInt32LE(optOffset + 108);
			dataDirectoryOffset = optOffset + 112;
		} else {
			entryPointRVA = this.fileBuffer.readUInt32LE(optOffset + 16);
			imageBase = this.fileBuffer.readUInt32LE(optOffset + 28);
			sizeOfImage = this.fileBuffer.readUInt32LE(optOffset + 56);
			subsystem = this.fileBuffer.readUInt16LE(optOffset + 68);
			numberOfRvaAndSizes = this.fileBuffer.readUInt32LE(optOffset + 92);
			dataDirectoryOffset = optOffset + 96;
		}

		this.baseAddress = imageBase;

		// Decode subsystem name
		const subsystemNames: Record<number, string> = {
			1: 'Native', 2: 'Windows GUI', 3: 'Windows CUI',
			5: 'OS/2 CUI', 7: 'POSIX CUI', 9: 'Windows CE GUI',
			10: 'EFI Application', 14: 'Xbox'
		};

		this.fileInfo = {
			format: is64 ? 'PE64' : 'PE',
			architecture: this.architecture,
			entryPoint: entryPointRVA + imageBase,
			baseAddress: imageBase,
			imageSize: sizeOfImage,
			timestamp: timeDateStamp > 0 ? new Date(timeDateStamp * 1000) : undefined,
			subsystem: subsystemNames[subsystem] || subsystem.toString()
		};

		// Parse section table
		const sectionTableOffset = optOffset + sizeOfOptionalHeader;
		this.parsePESections(sectionTableOffset, numberOfSections);

		// Parse imports (DataDirectory[1])
		if (numberOfRvaAndSizes > 1) {
			const importDirRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 8);
			const importDirSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 12);
			if (importDirRVA > 0 && importDirSize > 0) {
				this.parsePEImports(importDirRVA, is64);
			}
		}

		// Parse exports (DataDirectory[0])
		if (numberOfRvaAndSizes > 0) {
			const exportDirRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset);
			const exportDirSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 4);
			if (exportDirRVA > 0 && exportDirSize > 0) {
				this.parsePEExports(exportDirRVA, exportDirSize);
			}
		}

		// v3.7.5: Parse additional data directories
		this.peDataDirectories = {};

		// DataDirectory[2]: Resource Directory (size only)
		if (numberOfRvaAndSizes > 2) {
			const rva = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 16);
			const size = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 20);
			if (rva > 0 && size > 0) {
				this.peDataDirectories.resourceRVA = rva;
				this.peDataDirectories.resourceSize = size;
			}
		}

		// DataDirectory[4]: Certificate/Security (size only)
		if (numberOfRvaAndSizes > 4) {
			const size = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 36);
			if (size > 0) {
				this.peDataDirectories.securitySize = size;
			}
		}

		// DataDirectory[5]: Base Relocation (size only)
		if (numberOfRvaAndSizes > 5) {
			const size = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 44);
			if (size > 0) {
				this.peDataDirectories.relocSize = size;
			}
		}

		// DataDirectory[6]: Debug Directory
		if (numberOfRvaAndSizes > 6) {
			const debugRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 48);
			const debugSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 52);
			if (debugRVA > 0 && debugSize > 0) {
				this.parsePEDebugDirectory(debugRVA, debugSize);
			}
		}

		// DataDirectory[9]: TLS Directory
		if (numberOfRvaAndSizes > 9) {
			const tlsRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 72);
			const tlsSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 76);
			if (tlsRVA > 0 && tlsSize > 0) {
				this.parsePETLSDirectory(tlsRVA, is64);
			}
		}

		// DataDirectory[10]: Load Config (size only)
		if (numberOfRvaAndSizes > 10) {
			const size = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 84);
			if (size > 0) {
				this.peDataDirectories.loadConfigSize = size;
			}
		}

		// DataDirectory[3]: Exception Directory (.pdata) — v3.8.0 Pathfinder
		// Each RUNTIME_FUNCTION: BeginAddress(u32) + EndAddress(u32) + UnwindInfoAddress(u32) = 12 bytes
		// Gives EXACT function boundaries for every non-leaf x64 function.
		if (numberOfRvaAndSizes > 3) {
			const pdataRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 24);
			const pdataSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 28);
			if (pdataRVA > 0 && pdataSize > 0 && is64) {
				this.parsePdataDirectory(pdataRVA, pdataSize);
			}
		}

		// DataDirectory[13]: Delay Import Directory
		if (numberOfRvaAndSizes > 13) {
			const delayRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 104);
			const delaySize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 108);
			if (delayRVA > 0 && delaySize > 0) {
				this.parsePEDelayImportDirectory(delayRVA, is64);
			}
		}

		// DataDirectory[14]: CLR Runtime Header
		if (numberOfRvaAndSizes > 14) {
			const clrRVA = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 112);
			const clrSize = this.fileBuffer.readUInt32LE(dataDirectoryOffset + 116);
			if (clrRVA > 0 && clrSize > 0) {
				this.parsePECLRHeader(clrRVA);
			}
		}
	}

	private parsePESections(offset: number, count: number): void {
		if (!this.fileBuffer) {
			return;
		}

		for (let i = 0; i < count; i++) {
			const secOffset = offset + i * 40;
			if (secOffset + 40 > this.fileBuffer.length) {
				break;
			}

			// Section name (8 bytes, null-padded)
			let name = '';
			for (let j = 0; j < 8; j++) {
				const ch = this.fileBuffer[secOffset + j];
				if (ch === 0) { break; }
				name += String.fromCharCode(ch);
			}

			const virtualSize = this.fileBuffer.readUInt32LE(secOffset + 8);
			const virtualAddress = this.fileBuffer.readUInt32LE(secOffset + 12);
			const rawSize = this.fileBuffer.readUInt32LE(secOffset + 16);
			const rawAddress = this.fileBuffer.readUInt32LE(secOffset + 20);
			const characteristics = this.fileBuffer.readUInt32LE(secOffset + 36);

			const isReadable = (characteristics & 0x40000000) !== 0;
			const isWritable = (characteristics & 0x80000000) !== 0;
			const isExecutable = (characteristics & 0x20000000) !== 0;
			const isCode = (characteristics & 0x00000020) !== 0;
			const isData = (characteristics & 0x00000040) !== 0;

			let permissions = isReadable ? 'r' : '-';
			permissions += isWritable ? 'w' : '-';
			permissions += isExecutable ? 'x' : '-';

			this.sections.push({
				name,
				virtualAddress: virtualAddress + this.baseAddress,
				virtualSize,
				rawAddress,
				rawSize,
				characteristics,
				permissions,
				isCode,
				isData,
				isReadable,
				isWritable,
				isExecutable
			});
		}
	}

	private parsePEImports(importDirRVA: number, is64: boolean): void {
		if (!this.fileBuffer) {
			return;
		}

		const importDirOffset = this.rvaToFileOffset(importDirRVA);
		if (importDirOffset < 0 || importDirOffset >= this.fileBuffer.length) {
			return;
		}

		// Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes
		let descOffset = importDirOffset;
		for (let i = 0; i < 256; i++) { // Safety limit
			if (descOffset + 20 > this.fileBuffer.length) {
				break;
			}

			const originalFirstThunk = this.fileBuffer.readUInt32LE(descOffset);     // ILT RVA
			const nameRVA = this.fileBuffer.readUInt32LE(descOffset + 12);            // DLL name RVA
			const firstThunk = this.fileBuffer.readUInt32LE(descOffset + 16);         // IAT RVA

			// Null terminator
			if (nameRVA === 0 && firstThunk === 0) {
				break;
			}

			// Read DLL name
			const nameOffset = this.rvaToFileOffset(nameRVA);
			let dllName = '';
			if (nameOffset >= 0 && nameOffset < this.fileBuffer.length) {
				for (let j = nameOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
					dllName += String.fromCharCode(this.fileBuffer[j]);
					if (dllName.length > 256) { break; }
				}
			}

			if (dllName.length === 0) {
				descOffset += 20;
				continue;
			}

			// Walk the ILT (or IAT if ILT is zero)
			const thunkRVA = originalFirstThunk > 0 ? originalFirstThunk : firstThunk;
			const functions: ImportFunction[] = [];
			const entrySize = is64 ? 8 : 4;

			let thunkOffset = this.rvaToFileOffset(thunkRVA);
			let iatRVA = firstThunk;

			for (let j = 0; j < 4096; j++) { // Safety limit
				if (thunkOffset < 0 || thunkOffset + entrySize > this.fileBuffer.length) {
					break;
				}

				let entry: number;
				let isOrdinal: boolean;

				if (is64) {
					const val = this.fileBuffer.readBigUInt64LE(thunkOffset);
					if (val === 0n) { break; }
					isOrdinal = (val & 0x8000000000000000n) !== 0n;
					entry = Number(isOrdinal ? (val & 0xFFFFn) : val);
				} else {
					entry = this.fileBuffer.readUInt32LE(thunkOffset);
					if (entry === 0) { break; }
					isOrdinal = (entry & 0x80000000) !== 0;
					if (isOrdinal) {
						entry = entry & 0xFFFF;
					}
				}

				if (isOrdinal) {
					functions.push({
						name: `Ordinal_${entry}`,
						ordinal: entry,
						address: iatRVA + this.baseAddress,
						hint: 0
					});
				} else {
					// Name import: entry is RVA to IMAGE_IMPORT_BY_NAME (hint + name)
					const nameEntryOffset = this.rvaToFileOffset(entry);
					if (nameEntryOffset >= 0 && nameEntryOffset + 2 < this.fileBuffer.length) {
						const hint = this.fileBuffer.readUInt16LE(nameEntryOffset);
						let funcName = '';
						for (let k = nameEntryOffset + 2; k < this.fileBuffer.length && this.fileBuffer[k] !== 0; k++) {
							funcName += String.fromCharCode(this.fileBuffer[k]);
							if (funcName.length > 256) { break; }
						}
						functions.push({
							name: funcName || `Unknown_${j}`,
							ordinal: undefined,
							address: iatRVA + this.baseAddress,
							hint
						});
					}
				}

				thunkOffset += entrySize;
				iatRVA += entrySize;
			}

			if (functions.length > 0) {
				this.imports.push({ name: dllName, functions });
			}

			descOffset += 20;
		}
	}

	private parsePEExports(exportDirRVA: number, exportDirSize: number): void {
		if (!this.fileBuffer) {
			return;
		}

		const exportOffset = this.rvaToFileOffset(exportDirRVA);
		if (exportOffset < 0 || exportOffset + 40 > this.fileBuffer.length) {
			return;
		}

		const numberOfFunctions = this.fileBuffer.readUInt32LE(exportOffset + 20);
		const numberOfNames = this.fileBuffer.readUInt32LE(exportOffset + 24);
		const addressOfFunctions = this.fileBuffer.readUInt32LE(exportOffset + 28);   // RVA
		const addressOfNames = this.fileBuffer.readUInt32LE(exportOffset + 32);       // RVA
		const addressOfOrdinals = this.fileBuffer.readUInt32LE(exportOffset + 36);    // RVA
		const ordinalBase = this.fileBuffer.readUInt32LE(exportOffset + 16);

		// Sanity check: corrupt export table (e.g. LARA.dll has numFuncs=281000)
		// Max reasonable: 16384 exports. Also validate against file size.
		const maxReasonableExports = 16384;
		if (numberOfFunctions > maxReasonableExports || numberOfNames > maxReasonableExports) {
			console.warn(`Export table looks corrupt: numFuncs=${numberOfFunctions}, numNames=${numberOfNames} - skipping`);
			return;
		}
		if (numberOfNames > numberOfFunctions) {
			console.warn(`Export table invalid: numNames(${numberOfNames}) > numFuncs(${numberOfFunctions}) - skipping`);
			return;
		}

		const funcTableOffset = this.rvaToFileOffset(addressOfFunctions);
		const nameTableOffset = this.rvaToFileOffset(addressOfNames);
		const ordTableOffset = this.rvaToFileOffset(addressOfOrdinals);

		if (funcTableOffset < 0 || nameTableOffset < 0 || ordTableOffset < 0) {
			return;
		}

		// Validate table offsets are within file bounds
		if (funcTableOffset + numberOfFunctions * 4 > this.fileBuffer.length ||
			nameTableOffset + numberOfNames * 4 > this.fileBuffer.length ||
			ordTableOffset + numberOfNames * 2 > this.fileBuffer.length) {
			console.warn('Export table extends beyond file bounds - skipping');
			return;
		}

		// Build name → ordinal mapping
		const nameMap = new Map<number, string>();
		for (let i = 0; i < numberOfNames && i < 4096; i++) {
			const nameRVAOff = nameTableOffset + i * 4;
			const ordOff = ordTableOffset + i * 2;
			if (nameRVAOff + 4 > this.fileBuffer.length || ordOff + 2 > this.fileBuffer.length) {
				break;
			}

			const nameRVA = this.fileBuffer.readUInt32LE(nameRVAOff);
			const ordinal = this.fileBuffer.readUInt16LE(ordOff);

			const nameFileOffset = this.rvaToFileOffset(nameRVA);
			if (nameFileOffset >= 0 && nameFileOffset < this.fileBuffer.length) {
				let name = '';
				for (let j = nameFileOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
					name += String.fromCharCode(this.fileBuffer[j]);
					if (name.length > 256) { break; }
				}
				nameMap.set(ordinal, name);
			}
		}

		// Build export entries
		for (let i = 0; i < numberOfFunctions && i < 4096; i++) {
			const funcRVAOff = funcTableOffset + i * 4;
			if (funcRVAOff + 4 > this.fileBuffer.length) {
				break;
			}

			const funcRVA = this.fileBuffer.readUInt32LE(funcRVAOff);
			if (funcRVA === 0) {
				continue;
			}

			// Check if forwarder (RVA falls within export directory)
			const isForwarder = funcRVA >= exportDirRVA && funcRVA < exportDirRVA + exportDirSize;
			let forwarderName: string | undefined;

			if (isForwarder) {
				const fwdOffset = this.rvaToFileOffset(funcRVA);
				if (fwdOffset >= 0 && fwdOffset < this.fileBuffer.length) {
					forwarderName = '';
					for (let j = fwdOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						forwarderName += String.fromCharCode(this.fileBuffer[j]);
						if (forwarderName.length > 256) { break; }
					}
				}
			}

			const name = nameMap.get(i) || '';
			this.exports.push({
				name: name || `Ordinal_${i + ordinalBase}`,
				ordinal: i + ordinalBase,
				address: isForwarder ? 0 : funcRVA + this.baseAddress,
				isForwarder,
				forwarderName
			});
		}
	}

	// ============================================================================
	// v3.7.5: Enhanced PE Data Directory Parsing
	// ============================================================================

	private parsePEDebugDirectory(debugRVA: number, debugSize: number): void {
		if (!this.fileBuffer) { return; }
		const debugOffset = this.rvaToFileOffset(debugRVA);
		if (debugOffset < 0 || debugOffset >= this.fileBuffer.length) { return; }

		const DEBUG_TYPE_NAMES: Record<number, string> = {
			0: 'Unknown', 1: 'COFF', 2: 'CodeView', 3: 'FPO', 4: 'Misc',
			5: 'Exception', 6: 'Fixup', 7: 'OMAP_TO_SRC', 8: 'OMAP_FROM_SRC',
			9: 'Borland', 10: 'Reserved', 11: 'CLSID', 12: 'VC_FEATURE',
			13: 'POGO', 14: 'ILTCG', 16: 'Repro', 17: 'Embedded'
		};

		const entries: DebugDirectoryEntry[] = [];
		const entrySize = 28; // sizeof(IMAGE_DEBUG_DIRECTORY)
		const numEntries = Math.min(Math.floor(debugSize / entrySize), 16);

		for (let i = 0; i < numEntries; i++) {
			const off = debugOffset + i * entrySize;
			if (off + entrySize > this.fileBuffer.length) { break; }

			const type = this.fileBuffer.readUInt32LE(off + 12);
			const sizeOfData = this.fileBuffer.readUInt32LE(off + 16);
			const addressOfRawData = this.fileBuffer.readUInt32LE(off + 20);
			const pointerToRawData = this.fileBuffer.readUInt32LE(off + 24);
			const timestamp = this.fileBuffer.readUInt32LE(off + 4);
			const majorVersion = this.fileBuffer.readUInt16LE(off + 8);
			const minorVersion = this.fileBuffer.readUInt16LE(off + 10);

			const entry: DebugDirectoryEntry = {
				type,
				typeName: DEBUG_TYPE_NAMES[type] || `Type_${type}`,
				timestamp: timestamp > 0 ? new Date(timestamp * 1000) : new Date(0),
				majorVersion,
				minorVersion,
				size: sizeOfData,
				addressOfRawData,
				pointerToRawData
			};

			// Parse CodeView (type 2) for PDB path
			if (type === 2 && pointerToRawData > 0 && pointerToRawData + 24 < this.fileBuffer.length) {
				const cvSig = this.fileBuffer.readUInt32LE(pointerToRawData);
				if (cvSig === 0x53445352) { // 'RSDS'
					// GUID: 16 bytes at offset 4
					const guidBytes = this.fileBuffer.subarray(pointerToRawData + 4, pointerToRawData + 20);
					const p1 = guidBytes.readUInt32LE(0).toString(16).padStart(8, '0');
					const p2 = guidBytes.readUInt16LE(4).toString(16).padStart(4, '0');
					const p3 = guidBytes.readUInt16LE(6).toString(16).padStart(4, '0');
					const p4 = Array.from(guidBytes.subarray(8, 10)).map(b => b.toString(16).padStart(2, '0')).join('');
					const p5 = Array.from(guidBytes.subarray(10, 16)).map(b => b.toString(16).padStart(2, '0')).join('');
					entry.pdbGuid = `${p1}-${p2}-${p3}-${p4}-${p5}`.toUpperCase();

					// PDB path: null-terminated string after GUID + age (4 bytes)
					const pathStart = pointerToRawData + 24;
					const pathEnd = Math.min(pathStart + 260, pointerToRawData + sizeOfData, this.fileBuffer.length);
					let pdbPath = '';
					for (let j = pathStart; j < pathEnd && this.fileBuffer[j] !== 0; j++) {
						pdbPath += String.fromCharCode(this.fileBuffer[j]);
					}
					if (pdbPath.length > 0) {
						entry.pdbPath = pdbPath;
					}
				}
			}

			entries.push(entry);
		}

		if (entries.length > 0) {
			this.peDataDirectories.debug = entries;
		}
	}

	/**
	 * v3.8.0 Pathfinder: Parse .pdata (Exception Directory) for PE64 files.
	 * Each RUNTIME_FUNCTION entry gives exact function boundaries (BeginAddress, EndAddress).
	 * ROTTR.exe has ~50,000 entries — every non-leaf function's boundaries are known.
	 */
	private parsePdataDirectory(pdataRVA: number, pdataSize: number): void {
		if (!this.fileBuffer) { return; }
		const offset = this.rvaToFileOffset(pdataRVA);
		if (offset < 0) { return; }

		const entrySize = 12; // RUNTIME_FUNCTION: BeginAddress(4) + EndAddress(4) + UnwindInfoAddress(4)
		// A-lazy: raised 100K -> 250K so every .pdata function registers as a stub on the largest
		// real targets (WWZ .pdata = 159,694 entries; ROTTR = 71,280). Stubs are cheap, so the
		// higher cap costs only the stub registration (tens of MB), not a body disassembly each.
		const count = Math.min(Math.floor(pdataSize / entrySize), 250000); // Safety cap at 250K

		const entries: PdataEntry[] = [];
		for (let i = 0; i < count; i++) {
			const off = offset + i * entrySize;
			if (off + entrySize > this.fileBuffer.length) { break; }

			const begin = this.fileBuffer.readUInt32LE(off);
			const end = this.fileBuffer.readUInt32LE(off + 4);
			const unwind = this.fileBuffer.readUInt32LE(off + 8);

			// Sentinel: all zeros means end of table
			if (begin === 0 && end === 0) { break; }

			// Sanity: end must be after begin
			if (end <= begin) { continue; }

			entries.push({ beginAddress: begin, endAddress: end, unwindInfoAddress: unwind });
		}

		this.peDataDirectories.pdata = entries;
	}

	/**
	 * v3.8.0 Pathfinder: Get .pdata entries for function boundary discovery.
	 * Returns empty array if not a PE64 file or .pdata not present.
	 */
	getPdataEntries(): PdataEntry[] {
		return this.peDataDirectories.pdata ?? [];
	}

	private parsePETLSDirectory(tlsRVA: number, is64: boolean): void {
		if (!this.fileBuffer) { return; }
		const tlsOffset = this.rvaToFileOffset(tlsRVA);
		if (tlsOffset < 0) { return; }

		const minSize = is64 ? 40 : 24;
		if (tlsOffset + minSize > this.fileBuffer.length) { return; }

		let startAddr: number, endAddr: number, indexAddr: number, callbackAddr: number, characteristics: number;

		if (is64) {
			startAddr = Number(this.fileBuffer.readBigUInt64LE(tlsOffset));
			endAddr = Number(this.fileBuffer.readBigUInt64LE(tlsOffset + 8));
			indexAddr = Number(this.fileBuffer.readBigUInt64LE(tlsOffset + 16));
			callbackAddr = Number(this.fileBuffer.readBigUInt64LE(tlsOffset + 24));
			characteristics = this.fileBuffer.readUInt32LE(tlsOffset + 36);
		} else {
			startAddr = this.fileBuffer.readUInt32LE(tlsOffset);
			endAddr = this.fileBuffer.readUInt32LE(tlsOffset + 4);
			indexAddr = this.fileBuffer.readUInt32LE(tlsOffset + 8);
			callbackAddr = this.fileBuffer.readUInt32LE(tlsOffset + 12);
			characteristics = this.fileBuffer.readUInt32LE(tlsOffset + 20);
		}

		// Walk TLS callback array (VA pointers, null-terminated)
		const callbackAddresses: number[] = [];
		if (callbackAddr > 0) {
			// Convert VA to file offset
			const cbRVA = callbackAddr - this.baseAddress;
			const cbFileOff = this.rvaToFileOffset(cbRVA);
			if (cbFileOff >= 0) {
				const ptrSize = is64 ? 8 : 4;
				for (let i = 0; i < 32; i++) {
					const off = cbFileOff + i * ptrSize;
					if (off + ptrSize > this.fileBuffer.length) { break; }

					let addr: number;
					if (is64) {
						addr = Number(this.fileBuffer.readBigUInt64LE(off));
					} else {
						addr = this.fileBuffer.readUInt32LE(off);
					}

					if (addr === 0) { break; }
					callbackAddresses.push(addr);
				}
			}
		}

		this.peDataDirectories.tls = {
			startAddressOfRawData: startAddr,
			endAddressOfRawData: endAddr,
			addressOfIndex: indexAddr,
			addressOfCallBacks: callbackAddr,
			callbackAddresses,
			characteristics
		};
	}

	private parsePEDelayImportDirectory(delayRVA: number, is64: boolean): void {
		if (!this.fileBuffer) { return; }
		const delayOffset = this.rvaToFileOffset(delayRVA);
		if (delayOffset < 0 || delayOffset >= this.fileBuffer.length) { return; }

		const libraries: DelayImportLibrary[] = [];
		const entrySize = 32; // sizeof(ImgDelayDescr)

		for (let i = 0; i < 128; i++) {
			const off = delayOffset + i * entrySize;
			if (off + entrySize > this.fileBuffer.length) { break; }

			const attributes = this.fileBuffer.readUInt32LE(off);
			const nameRVA = this.fileBuffer.readUInt32LE(off + 4);
			const handleRVA = this.fileBuffer.readUInt32LE(off + 8);
			const iatRVA = this.fileBuffer.readUInt32LE(off + 12);
			const intRVA = this.fileBuffer.readUInt32LE(off + 16);

			if (nameRVA === 0 && iatRVA === 0) { break; }

			// Read DLL name
			const nameOffset = this.rvaToFileOffset(nameRVA);
			let dllName = '';
			if (nameOffset >= 0 && nameOffset < this.fileBuffer.length) {
				for (let j = nameOffset; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
					dllName += String.fromCharCode(this.fileBuffer[j]);
					if (dllName.length > 256) { break; }
				}
			}

			if (dllName.length === 0) { continue; }

			// Walk INT (Import Name Table) to get function names
			const functions: ImportFunction[] = [];
			if (intRVA > 0) {
				const intOffset = this.rvaToFileOffset(intRVA);
				const ptrSize = is64 ? 8 : 4;
				let iatEntry = iatRVA;

				for (let j = 0; j < 4096; j++) {
					const entryOff = intOffset + j * ptrSize;
					if (entryOff < 0 || entryOff + ptrSize > this.fileBuffer.length) { break; }

					let entry: number;
					if (is64) {
						const val = this.fileBuffer.readBigUInt64LE(entryOff);
						if (val === 0n) { break; }
						entry = Number(val & 0x7FFFFFFFFFFFFFFFn);
					} else {
						entry = this.fileBuffer.readUInt32LE(entryOff);
						if (entry === 0) { break; }
						entry = entry & 0x7FFFFFFF;
					}

					const hintOff = this.rvaToFileOffset(entry);
					if (hintOff >= 0 && hintOff + 2 < this.fileBuffer.length) {
						const hint = this.fileBuffer.readUInt16LE(hintOff);
						let funcName = '';
						for (let k = hintOff + 2; k < this.fileBuffer.length && this.fileBuffer[k] !== 0; k++) {
							funcName += String.fromCharCode(this.fileBuffer[k]);
							if (funcName.length > 256) { break; }
						}
						functions.push({
							name: funcName || `DelayOrdinal_${j}`,
							hint,
							address: iatEntry + this.baseAddress
						});
					}

					iatEntry += ptrSize;
				}
			}

			libraries.push({
				name: dllName,
				handle: handleRVA + this.baseAddress,
				delayIAT: iatRVA + this.baseAddress,
				delayINT: intRVA + this.baseAddress,
				functions
			});
		}

		if (libraries.length > 0) {
			this.peDataDirectories.delayImport = libraries;
		}
	}

	private parsePECLRHeader(clrRVA: number): void {
		if (!this.fileBuffer) { return; }
		const clrOffset = this.rvaToFileOffset(clrRVA);
		if (clrOffset < 0 || clrOffset + 72 > this.fileBuffer.length) { return; }

		const headerSize = this.fileBuffer.readUInt32LE(clrOffset);
		if (headerSize < 72) { return; }

		const majorVersion = this.fileBuffer.readUInt16LE(clrOffset + 4);
		const minorVersion = this.fileBuffer.readUInt16LE(clrOffset + 6);
		const metadataRVA = this.fileBuffer.readUInt32LE(clrOffset + 8);
		const metadataSize = this.fileBuffer.readUInt32LE(clrOffset + 12);
		const flags = this.fileBuffer.readUInt32LE(clrOffset + 16);
		const entryPointToken = this.fileBuffer.readUInt32LE(clrOffset + 20);

		this.peDataDirectories.clr = {
			majorRuntimeVersion: majorVersion,
			minorRuntimeVersion: minorVersion,
			metadataRVA,
			metadataSize,
			flags,
			entryPointToken,
			// Issue #32 honesty: derive these from the correct COMIMAGE_FLAGS bits (ECMA-335 /
			// corhdr.h). The previous `isNative: (flags & 0x01)` read the ILONLY bit and named it
			// `isNative`, so a pure-managed assembly reported isNative:true — exactly backwards.
			ilOnly: (flags & 0x01) !== 0,           // COMIMAGE_FLAGS_ILONLY
			isNative: (flags & 0x10) !== 0,         // COMIMAGE_FLAGS_NATIVE_ENTRYPOINT
			is32BitRequired: (flags & 0x02) !== 0   // COMIMAGE_FLAGS_32BITREQUIRED
		};
	}

	// ============================================================================
	// v3.7.5: Typed Import Resolution (Windows API Signature Database)
	// ============================================================================

	/**
	 * Resolve imports against the Windows API signature database.
	 * Returns enriched import data with type signatures and categories.
	 */
	getTypedImports(): TypedImportLibrary[] {
		return this.imports.map(lib => ({
			name: lib.name,
			functions: lib.functions.map(func => ({
				...func,
				signature: lookupApi(func.name)
			}))
		}));
	}

	/**
	 * Build a summary of imported API categories for security analysis.
	 * Groups imports by category and lists security-relevant tags.
	 */
	getImportCategorySummary(): ImportCategorySummary[] {
		const categoryMap = new Map<ApiCategory, { functions: string[]; tags: Set<string> }>();

		for (const lib of this.imports) {
			for (const func of lib.functions) {
				const sig = lookupApi(func.name);
				if (!sig) { continue; }

				let entry = categoryMap.get(sig.category);
				if (!entry) {
					entry = { functions: [], tags: new Set() };
					categoryMap.set(sig.category, entry);
				}
				entry.functions.push(func.name);
				for (const tag of sig.tags) {
					entry.tags.add(tag);
				}
			}
		}

		const result: ImportCategorySummary[] = [];
		for (const [category, data] of categoryMap) {
			result.push({
				category,
				label: CATEGORY_LABELS[category] || category,
				count: data.functions.length,
				functions: data.functions,
				tags: Array.from(data.tags).sort()
			});
		}

		// Sort: highest-count categories first
		result.sort((a, b) => b.count - a.count);
		return result;
	}

	/**
	 * Get the parsed PE data directories.
	 */
	getPEDataDirectories(): PEDataDirectories {
		return this.peDataDirectories;
	}

	/**
	 * v3.7.5 P4: Get the enhanced ELF analysis data.
	 */
	getELFAnalysis(): ELFAnalysis | undefined {
		return this.elfAnalysis;
	}

	/**
	 * Extract all executable sections from an ELF binary with semantic classification.
	 * For kernel modules (.ko), maps section names to their purpose:
	 * - .text -> 'runtime' (main runtime code)
	 * - .init.text -> 'module_init' (module initialization, runs once)
	 * - .exit.text -> 'module_cleanup' (module unload cleanup)
	 * - .text.unlikely -> 'runtime' (cold code paths)
	 * - .text.hot -> 'runtime' (hot code paths)
	 * - Other executable -> 'unknown'
	 *
	 * @param elfSections - Raw ELF section headers from parsing
	 * @returns Array of executable sections with semantic classification
	 */
	private extractExecutableSections(
		elfSections: Array<{ name: string; type: number; flags: number; addr: number; offset: number; size: number }>
	): ELFExecutableSection[] {
		const executableSections: ELFExecutableSection[] = [];

		for (const sec of elfSections) {
			// Check SHF_EXECINSTR flag (0x4)
			const isExecutable = (sec.flags & 0x4) !== 0;
			if (!isExecutable) {
				continue;
			}

			// Determine semantic purpose based on section name
			let purpose: ELFExecutableSection['purpose'] = 'unknown';

			switch (sec.name) {
				case '.text':
				case '.text.hot':
				case '.text.unlikely':
				case '.text.rare':
					purpose = 'runtime';
					break;
				case '.init.text':
					purpose = 'module_init';
					break;
				case '.exit.text':
					purpose = 'module_cleanup';
					break;
				case '.plt':
				case '.plt.got':
					purpose = 'trampoline';
					break;
				default:
					// Check for .text.* patterns (e.g., .text.funcname from -ffunction-sections)
					if (sec.name.startsWith('.text.')) {
						purpose = 'runtime';
					}
					break;
			}

			executableSections.push({
				name: sec.name,
				offset: sec.offset,
				size: sec.size,
				flags: sec.flags,
				virtualAddress: sec.addr,
				purpose
			});
		}

		// Sort by file offset for consistent ordering
		return executableSections.sort((a, b) => a.offset - b.offset);
	}

	/**
	 * v3.8.1: Idempotent lazy load of BTF/DWARF debug info.  Safe to call
	 * from hot paths (liftToIR, Pathfinder) — early-returns if already
	 * loaded.  Split out from computeELFConfidenceScore so decompilation
	 * flows that don't run the full confidence-score pipeline (liftToIR
	 * direct, automation job without analyzeELFHeadless step) still pick
	 * up type info before Helix emits the `.c` file.
	 */
	async ensureDebugInfoLoaded(): Promise<void> {
		if (!this.elfAnalysis || !this.fileBuffer || !this.currentFile) {
			return;
		}

		const hasBtfInfo = this.sections.some(s => s.name === '.BTF' || s.name === '.BTF.ext');
		const hasDwarfInfo = this.sections.some(s =>
			s.name.startsWith('.debug_') || s.name === '.eh_frame' || s.name === '.eh_frame_hdr'
		);

		// BTF takes priority when available — gate DWARF on its absence.
		if (hasBtfInfo && !this.elfAnalysis.btfData) {
			try {
				const { loadBtfFromFile } = await import('./elfBtfLoader');
				const btfData = await loadBtfFromFile(this.currentFile);
				if (btfData) {
					this.elfAnalysis.btfData = btfData;
				}
			} catch (error) {
				console.warn('Failed to load BTF data:', error);
			}
		}

		if (!this.elfAnalysis.btfData && hasDwarfInfo && !this.elfAnalysis.dwarfStructInfo) {
			try {
				const { loadDwarfStructInfo } = await import('./elfDwarfLoader');
				const dwarfStructInfo = await loadDwarfStructInfo(this.currentFile);
				if (dwarfStructInfo) {
					this.elfAnalysis.dwarfStructInfo = dwarfStructInfo;
					console.log(`[dwarf] Loaded ${Object.keys(dwarfStructInfo.structs).length} structs, ${Object.keys(dwarfStructInfo.functions).length} functions, ${dwarfStructInfo.boundaries?.length ?? 0} boundaries`);
				}
			} catch (error) {
				console.warn('Failed to load DWARF struct info:', error);
			}
		}
	}

	/**
	 * v3.8.0: Compute and attach confidence score to ELF analysis.
	 * Should be called after analyzeAll() for accurate CFG metrics.
	 * Also loads BTF type information when available.
	 */
	async computeELFConfidenceScore(): Promise<ConfidenceScore | undefined> {
		if (!this.elfAnalysis || !this.fileBuffer) {
			return undefined;
		}

		// Load BTF / DWARF debug info (idempotent — safe if already loaded).
		await this.ensureDebugInfoLoaded();

		// External-call resolution as a real 0-1 ratio.
		// BUG (v3.8.1): resolvedExternalCalls was textRelocations.size (one entry per
		// CALL SITE, e.g. 15233) and totalExternalCalls was the distinct-import count
		// (e.g. 342) -> ratio 44.5, poisoning `overall` to ~13.78 and breaking the
		// documented 0-1 contract. Both terms must be the same UNIT. Each
		// textRelocations entry is an external call/jump site; it is "resolved" when it
		// carries a symbol name. So the honest metric is resolvedCallSites/totalCallSites.
		let resolvedExternalCalls = 0;
		const totalExternalCalls = this.textRelocations.size;
		for (const r of this.textRelocations.values()) {
			if (r.name && r.name.length > 0) { resolvedExternalCalls++; }
		}

		// Count total basic blocks across all functions
		let totalBasicBlocks = 0;
		for (const func of this.functions.values()) {
			// Simple BB count: count leaders (entry point + targets of jumps/calls)
			const leaders = new Set<number>();
			leaders.add(func.address);
			for (const inst of func.instructions) {
				if (inst.isJump || inst.isCall) {
					if (inst.targetAddress && inst.targetAddress >= func.address && inst.targetAddress < func.endAddress) {
						leaders.add(inst.targetAddress);
					}
				}
			}
			totalBasicBlocks += leaders.size;
		}

		// Prepare sections data for scoring
		const sectionsData = this.sections.map(s => ({
			name: s.name,
			size: s.rawSize,
			flags: s.characteristics
		}));

		const hasBtfInfo = this.sections.some(s => s.name === '.BTF' || s.name === '.BTF.ext');
		const hasDwarfInfo = this.sections.some(s =>
			s.name.startsWith('.debug_') || s.name === '.eh_frame' || s.name === '.eh_frame_hdr'
		);
		const score = calculateConfidenceScore({
			symbols: this.elfAnalysis.symbols,
			relocations: this.elfAnalysis.relocations,
			sections: sectionsData,
			totalFunctions: this.functions.size,
			totalBasicBlocks,
			resolvedExternalCalls,
			totalExternalCalls,
			hasBtfInfo,
			hasDwarfInfo
		});

		this.elfAnalysis.confidenceScore = score;
		return score;
	}

	/**
	 * v3.7.5: Get the size of a function/symbol at the given address.
	 * Checks: (1) function table from analyzeAll, (2) ELF symbol table st_size,
	 * (3) PE export table. Returns 0 if unknown.
	 */
	getSymbolSizeAt(address: number): number {
		// 1. Function table (from analyzeAll)
		const func = this.functions.get(address);
		if (func && func.size > 0) {
			return func.size;
		}

		// 2. ELF symbol table: search for FUNC symbol at this address
		if (this.elfAnalysis) {
			for (const sym of this.elfAnalysis.symbols) {
				if (sym.type === 'FUNC' && sym.value === address && sym.size > 0) {
					return sym.size;
				}
			}
			// Also try with PIE adjustment
			if (this.fileInfo?.characteristics?.includes('PIE')) {
				const rawAddr = address - this.baseAddress;
				for (const sym of this.elfAnalysis.symbols) {
					if (sym.type === 'FUNC' && sym.value === rawAddr && sym.size > 0) {
						return sym.size;
					}
				}
			}
		}

		// 3. Scan nearby function table entries to find the gap
		if (this.functions.size > 0) {
			const sortedAddrs = [...this.functions.keys()].sort((a, b) => a - b);
			const idx = sortedAddrs.indexOf(address);
			if (idx >= 0 && idx + 1 < sortedAddrs.length) {
				return sortedAddrs[idx + 1] - address;
			}
			// Binary search for the next function after this address
			let lo = 0, hi = sortedAddrs.length - 1;
			while (lo <= hi) {
				const mid = (lo + hi) >> 1;
				if (sortedAddrs[mid] <= address) { lo = mid + 1; }
				else { hi = mid - 1; }
			}
			if (lo < sortedAddrs.length) {
				const gap = sortedAddrs[lo] - address;
				if (gap > 0 && gap <= 65536) {
					return gap;
				}
			}
		}

		return 0;
	}

	/**
	 * v3.7.5: Get the buffer size needed to fully lift a function.
	 * Returns the actual function/symbol size if known, otherwise a conservative fallback.
	 */
	getRecommendedLiftSize(address: number, fallback: number = 4096): number {
		const symbolSize = this.getSymbolSizeAt(address);
		if (symbolSize > 0) {
			// Add 16 bytes padding for alignment/epilogue
			return symbolSize + 16;
		}
		return fallback;
	}

	// ============================================================================
	// ELF Structure Parsing
	// ============================================================================

	private parseELFStructure(): void {
		if (!this.fileBuffer) {
			return;
		}

		const is64Bit = this.fileBuffer[4] === 2;
		const isLittleEndian = this.fileBuffer[5] === 1;

		// Helper for endian-aware reads
		const readU16 = (off: number): number =>
			isLittleEndian ? this.fileBuffer!.readUInt16LE(off) : this.fileBuffer!.readUInt16BE(off);
		const readU32 = (off: number): number =>
			isLittleEndian ? this.fileBuffer!.readUInt32LE(off) : this.fileBuffer!.readUInt32BE(off);
		const readU64 = (off: number): bigint =>
			isLittleEndian ? this.fileBuffer!.readBigUInt64LE(off) : this.fileBuffer!.readBigUInt64BE(off);
		const readAddr = (off: number): number =>
			is64Bit ? Number(readU64(off)) : readU32(off);

		const entryPoint = readAddr(24);
		const phoff = is64Bit ? Number(readU64(32)) : readU32(28);
		const shoff = is64Bit ? Number(readU64(40)) : readU32(32);
		const phentsize = readU16(is64Bit ? 54 : 42);
		const phnum = readU16(is64Bit ? 56 : 44);
		const shentsize = readU16(is64Bit ? 58 : 46);
		const shnum = readU16(is64Bit ? 60 : 48);
		const shstrndx = readU16(is64Bit ? 62 : 50);

		// Detect ELF type: ET_EXEC=2 (fixed base), ET_DYN=3 (PIE or shared object)
		const eType = readU16(16);
		const isPIE = eType === 3; // ET_DYN - Position Independent Executable

		// v3.7.4: FIX-014 — Warn on ET_REL (relocatable object / kernel module)
		if (eType === 1) {
			console.warn(
				'[HexCore] [WARN] Target is a relocatable ELF (ET_REL / .ko kernel module). ' +
				'External calls are unresolved relocations — decompilation will be limited. ' +
				'Tip: Link against a dummy kernel image or process relocations first.'
			);
		}

		// Detect base address from first LOAD segment
		let baseAddr = 0x400000;
		if (phoff > 0 && phnum > 0) {
			// First pass: find lowest LOAD segment vaddr to detect PIE
			let lowestVaddr = Number.MAX_SAFE_INTEGER;
			for (let i = 0; i < phnum; i++) {
				const phOff = phoff + i * phentsize;
				if (phOff + phentsize > this.fileBuffer.length) { break; }
				const pType = readU32(phOff);
				if (pType === 1) { // PT_LOAD
					const pVaddr = is64Bit ? Number(readU64(phOff + 16)) : readU32(phOff + 8);
					if (pVaddr < lowestVaddr) {
						lowestVaddr = pVaddr;
					}
				}
			}

			if (lowestVaddr !== Number.MAX_SAFE_INTEGER) {
				if (isPIE && lowestVaddr === 0) {
					// PIE binary: virtual addresses start at 0, use conventional base
					// Linux kernel typically loads PIE at 0x555555554000 for x64, 0x56555000 for x86
					baseAddr = is64Bit ? 0x555555554000 : 0x56555000;
				} else if (lowestVaddr > 0) {
					baseAddr = lowestVaddr;
				}
				// If lowestVaddr is 0 and NOT PIE, keep default 0x400000
			}
		}
		this.baseAddress = baseAddr;

		// For PIE binaries, adjust entry point by adding the chosen base address
		const adjustedEntryPoint = (isPIE && entryPoint < this.baseAddress) ? entryPoint + this.baseAddress : entryPoint;

		this.fileInfo = {
			format: is64Bit ? 'ELF64' : 'ELF32',
			architecture: this.architecture,
			entryPoint: adjustedEntryPoint,
			baseAddress: this.baseAddress,
			imageSize: this.fileBuffer.length,
			characteristics: isPIE ? ['ELF', 'PIE'] : eType === 1 ? ['ELF', 'ET_REL'] : ['ELF'],
			isRelocatable: eType === 1
		};

		// Parse section headers - collect raw info for symbol parsing
		interface ElfSection {
			name: string;
			type: number;
			flags: number;
			addr: number;
			offset: number;
			size: number;
			link: number;
			info: number;   // sh_info: for SHT_RELA, index of section relocations apply to
			entsize: number;
		}
		const elfSections: ElfSection[] = [];

		if (shoff > 0 && shnum > 0 && shstrndx < shnum) {
			// Get section name string table
			const shstrtabOff = shoff + shstrndx * shentsize;
			const shstrtabFileOff = is64Bit
				? Number(readU64(shstrtabOff + 24))
				: readU32(shstrtabOff + 16);

			for (let i = 0; i < shnum; i++) {
				const secOff = shoff + i * shentsize;
				if (secOff + shentsize > this.fileBuffer.length) {
					break;
				}

				const nameIdx = readU32(secOff);
				const type = readU32(secOff + 4);
				const flags = is64Bit ? Number(readU64(secOff + 8)) : readU32(secOff + 8);
				const addr = is64Bit ? Number(readU64(secOff + 16)) : readU32(secOff + 12);
				const offset = is64Bit ? Number(readU64(secOff + 24)) : readU32(secOff + 16);
				const size = is64Bit ? Number(readU64(secOff + 32)) : readU32(secOff + 20);
				const link = readU32(is64Bit ? secOff + 40 : secOff + 24);
				const info = readU32(is64Bit ? secOff + 44 : secOff + 28);
				const entsize = is64Bit ? Number(readU64(secOff + 56)) : readU32(secOff + 36);

				// Read section name
				let name = '';
				if (shstrtabFileOff + nameIdx < this.fileBuffer.length) {
					for (let j = shstrtabFileOff + nameIdx; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						name += String.fromCharCode(this.fileBuffer[j]);
					}
				}
				if (name.length === 0) {
					name = `section_${i}`;
				}

				// For PIE: adjust section addresses by adding base
				const adjustedAddr = (isPIE && addr > 0 && addr < this.baseAddress) ? addr + this.baseAddress : addr;

				elfSections.push({ name, type, flags, addr: adjustedAddr, offset, size, link, info, entsize });

				const isWritable = (flags & 0x1) !== 0;
				const isAlloc = (flags & 0x2) !== 0;
				const isExecutable = (flags & 0x4) !== 0;

				if (!isAlloc && type !== 1) {
					continue;
				}

				let permissions = 'r';
				permissions += isWritable ? 'w' : '-';
				permissions += isExecutable ? 'x' : '-';

				this.sections.push({
					name,
					virtualAddress: adjustedAddr,
					virtualSize: size,
					rawAddress: offset,
					rawSize: size,
					characteristics: flags,
					permissions,
					isCode: isExecutable,
					isData: !isExecutable && isWritable,
					isReadable: true,
					isWritable,
					isExecutable
				});

				// v0.9.1 (G-001): index this section by name for the
				// symbol-name → file-offset lookup used by `liftToIR
				// symbolName:`. Multiple ELF objects can have name
				// collisions (e.g. two `.note.*` sections); we keep the
				// first one — `.text`/`.init.text`/etc. are guaranteed
				// unique in well-formed objects.
				if (!this.elfSectionFileMap.has(name)) {
					this.elfSectionFileMap.set(name, {
						fileOffset: offset,
						size,
						flags,
					});
				}
			}
		}

		// Parse symbol tables (SHT_SYMTAB=2 and SHT_DYNSYM=11)
		for (const sec of elfSections) {
			if (sec.type !== 2 && sec.type !== 11) {
				continue;
			}
			if (sec.entsize === 0 || sec.size === 0) {
				continue;
			}

			// Get associated string table
			const strTabSec = elfSections[sec.link];
			if (!strTabSec) {
				continue;
			}

			const symCount = Math.floor(sec.size / sec.entsize);
			const isDynSym = sec.type === 11;

			for (let i = 0; i < symCount && i < 8192; i++) {
				const symOff = sec.offset + i * sec.entsize;
				if (symOff + sec.entsize > this.fileBuffer.length) {
					break;
				}

				let stName: number, stInfo: number, stShndx: number, stValue: number, stSize: number;

				if (is64Bit) {
					stName = readU32(symOff);
					stInfo = this.fileBuffer[symOff + 4];
					stShndx = readU16(symOff + 6);
					stValue = Number(readU64(symOff + 8));
					stSize = Number(readU64(symOff + 16));
				} else {
					stName = readU32(symOff);
					stValue = readU32(symOff + 4);
					stSize = readU32(symOff + 8);
					stInfo = this.fileBuffer[symOff + 12];
					stShndx = readU16(symOff + 14);
				}

				const stBind = stInfo >> 4;   // STB_LOCAL=0, STB_GLOBAL=1, STB_WEAK=2
				const stType = stInfo & 0xF;  // STT_FUNC=2, STT_OBJECT=1

				// Read symbol name
				let symName = '';
				const nameOff = strTabSec.offset + stName;
				if (nameOff < this.fileBuffer.length) {
					for (let j = nameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						symName += String.fromCharCode(this.fileBuffer[j]);
						if (symName.length > 256) { break; }
					}
				}

				if (symName.length === 0) {
					continue;
				}

				const SHN_UNDEF = 0;
				const isUndefined = stShndx === SHN_UNDEF;

				if (isUndefined && (stBind === 1 || stBind === 2)) {
					// Import: undefined global/weak symbol
					// Group by library name (use "external" as fallback since ELF doesn't specify per-symbol)
					let libEntry = this.imports.find(lib => lib.name === 'external');
					if (!libEntry) {
						libEntry = { name: 'external', functions: [] };
						this.imports.push(libEntry);
					}
					libEntry.functions.push({
						name: symName,
						ordinal: i,
						address: stValue || 0,
						hint: 0
					});
				} else if (!isUndefined && (stBind === 1 || stBind === 2) && stType === 2) {
					// Export: defined global/weak function symbol
					const adjustedSymAddr = (isPIE && stValue > 0 && stValue < this.baseAddress) ? stValue + this.baseAddress : stValue;
					this.exports.push({
						name: symName,
						ordinal: i,
						address: adjustedSymAddr,
						isForwarder: false
					});
				}

				// v0.9.1 (G-001): record every defined function symbol by
				// name regardless of binding. Local STT_FUNC symbols
				// (stBind=0, file-scope `static int helper(void)`) are
				// also tracked because they are equally callable by the
				// user via `symbolName:`. Skip undefined and non-function
				// symbols.
				if (!isUndefined && stType === 2 &&
				    stShndx > 0 && stShndx < elfSections.length) {
					const sec = elfSections[stShndx];
					if (sec && symName.length > 0) {
						// Section.name was set in the section-table walk
						// above; both maps share its lifetime.
						if (!this.elfFunctionByName.has(symName)) {
							this.elfFunctionByName.set(symName, {
								sectionName: sec.name,
								offsetInSection: stValue,
								size: stSize,
							});
						}
					}
				}
			}
		}

		// Parse .dynamic section for NEEDED entries (shared library names)
		for (const sec of elfSections) {
			if (sec.type !== 6) { // SHT_DYNAMIC
				continue;
			}

			const dynStrSec = elfSections[sec.link];
			if (!dynStrSec) {
				continue;
			}

			const entrySize = is64Bit ? 16 : 8;
			const numEntries = Math.floor(sec.size / entrySize);

			for (let i = 0; i < numEntries; i++) {
				const entOff = sec.offset + i * entrySize;
				if (entOff + entrySize > this.fileBuffer.length) {
					break;
				}

				const dTag = is64Bit ? Number(readU64(entOff)) : readU32(entOff);
				const dVal = is64Bit ? Number(readU64(entOff + 8)) : readU32(entOff + 4);

				if (dTag === 0) { break; } // DT_NULL
				if (dTag === 1) { // DT_NEEDED
					let libName = '';
					const nameOff = dynStrSec.offset + dVal;
					if (nameOff < this.fileBuffer.length) {
						for (let j = nameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
							libName += String.fromCharCode(this.fileBuffer[j]);
							if (libName.length > 256) { break; }
						}
					}
					// Re-group import symbols under their actual library name
					if (libName) {
						const existing = this.imports.find(lib => lib.name === libName);
						if (!existing) {
							this.imports.push({ name: libName, functions: [] });
						}
					}
				}
			}
		}

		// Parse PLT section to get actual call addresses for imports
		// PLT entries are small stubs that indirect through GOT
		const pltSection = elfSections.find(s => s.name === '.plt' || s.name === '.plt.got' || s.name === '.plt.sec');
		if (pltSection && pltSection.addr > 0) {
			// Parse .rela.plt to map GOT slots to symbol names
			const relaPlt = elfSections.find(s => s.name === '.rela.plt' || s.name === '.rel.plt');
			const dynsymSec = elfSections.find(s => s.type === 11); // SHT_DYNSYM
			const dynstrSec = dynsymSec ? elfSections[dynsymSec.link] : undefined;

			if (relaPlt && dynsymSec && dynstrSec) {
				const isRela = relaPlt.name.startsWith('.rela');
				const relEntSize = isRela ? (is64Bit ? 24 : 12) : (is64Bit ? 16 : 8);
				const numRel = relEntSize > 0 ? Math.floor(relaPlt.size / relEntSize) : 0;

				for (let i = 0; i < numRel && i < 4096; i++) {
					const relOff = relaPlt.offset + i * relEntSize;
					if (relOff + relEntSize > this.fileBuffer.length) { break; }

					const rOffset = is64Bit ? Number(readU64(relOff)) : readU32(relOff);
					const rInfo = is64Bit ? Number(readU64(relOff + 8)) : readU32(relOff + 4);

					// Extract symbol index from r_info.
					// BUG (pre-v3.8.2): `rInfo >> 32` on a JS number coerces to int32 first
					// (shift count is mod 32), so it was effectively `>> 0` -> ALL .rela.plt
					// entries resolved to the SAME wrong symbol (observed: every PLT stub
					// mapped to "rand"). For 64-bit, the symbol index is the high dword:
					// use float division, not the bitwise shift.
					const symIdx = is64Bit ? Math.floor(rInfo / 0x100000000) : (rInfo >> 8);

					// Read symbol name from .dynsym
					const symEntSize = is64Bit ? 24 : 16;
					const symOff = dynsymSec.offset + symIdx * symEntSize;
					if (symOff + symEntSize > this.fileBuffer.length) { continue; }

					const stName = readU32(symOff);
					let symName = '';
					const symNameOff = dynstrSec.offset + stName;
					if (symNameOff < this.fileBuffer.length) {
						for (let j = symNameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
							symName += String.fromCharCode(this.fileBuffer[j]);
							if (symName.length > 256) { break; }
						}
					}

					if (symName.length === 0) { continue; }

					// PLT entry address: PLT base + (i+1) * PLT entry size (first entry is stub)
					// Standard PLT entry size is 16 bytes on x86-64
					const pltEntrySize = is64Bit ? 16 : 16;
					const pltAddr = pltSection.addr + (i + 1) * pltEntrySize;

					// Adjust for PIE
					const adjustedPltAddr = (isPIE && pltAddr > 0 && pltAddr < this.baseAddress) ? pltAddr + this.baseAddress : pltAddr;
					const adjustedGotAddr = (isPIE && rOffset > 0 && rOffset < this.baseAddress) ? rOffset + this.baseAddress : rOffset;

					// v3.8.2: authoritative PLT-stub-VA -> dynsym-name map. The import-table
					// update below only sets the FIRST matching import's address and can
					// leave some imports at 0x0 (observed: srand). This map is complete and
					// is what detectPRNG uses to resolve `call <pltStub>` -> symbol name.
					this._pltSymbolMap.set(adjustedPltAddr, symName);

					// v3.8.5: also key by the GOT slot VA. On CET/IBT binaries the call site
					// targets the `.plt.sec` thunk (endbr64 ; bnd jmp *GOT[n](%rip)), whose VA is
					// NOT adjustedPltAddr; resolving it requires reading its GOT reference and
					// matching it here. (Used by the trap-handler gate and PLT-stub naming.)
					if (adjustedGotAddr > 0) {
						this._gotSymbolMap.set(adjustedGotAddr, symName);
					}

					// Update import entries with PLT addresses
					for (const lib of this.imports) {
						const func = lib.functions.find(f => f.name === symName);
						if (func) {
							func.address = adjustedPltAddr;
							break;
						}
					}
				}
			}
		}

		// v3.7.4 FIX-011: Parse .rela.text relocations for ET_REL (relocatable objects)
		// Maps each call/jump site in .text to its external symbol name so the
		// lifter can generate `declare @mutex_lock(...)` instead of `call sub_0`.
		//
		// v3.7.4-fix: Process ALL .rela sections targeting .text (not just the first),
		// handle -ffunction-sections (.rela.text.funcname), use sh_info for matching,
		// expand relocation types for x86_64 (GOTPCRELX) and AArch64 (CALL26).
		if (eType === 1 /* ET_REL */) {
			console.log(`[HexCore] FIX-011: ET_REL detected. elfSections.length=${elfSections.length}, shnum=${shnum}`);

			// Collect ALL text-like sections (handles -ffunction-sections: .text.funcname)
			const textSections = elfSections.filter(s =>
				s.name === '.text' || s.name.startsWith('.text.'));
			const textSecIndices = new Set(textSections.map(s => elfSections.indexOf(s)));

			// Find the symtab + its strtab (SHT_SYMTAB = 2)
			const symtabSec = elfSections.find(s => s.type === 2);
			const strtabSec = symtabSec ? elfSections[symtabSec.link] : undefined;

			console.log(`[HexCore] FIX-011: text sections=${textSections.length} (${textSections.map(s => s.name).join(', ')}), ` +
				`symtab=${symtabSec ? `found(link=${symtabSec.link})` : 'NOT FOUND'}, ` +
				`strtab=${strtabSec ? `found(off=${strtabSec.offset},size=${strtabSec.size})` : 'NOT FOUND'}`);

			if (textSections.length > 0 && symtabSec && strtabSec) {
				// Collect ALL .rela/.rel sections that target text sections.
				// Match by sh_info (points to the section being relocated) OR by name.
				const relaSections = elfSections.filter(s =>
					(s.type === 4 /* SHT_RELA */ || s.type === 9 /* SHT_REL */) &&
					(textSecIndices.has(s.info) ||
						s.name === '.rela.text' || s.name === '.rel.text' ||
						s.name.startsWith('.rela.text.') || s.name.startsWith('.rel.text.')));

				console.log(`[HexCore] FIX-011: Found ${relaSections.length} text relocation sections: ` +
					relaSections.map(s => `"${s.name}"(type=${s.type},size=${s.size},info=${s.info})`).join(', '));

				// All rela/rel sections for debugging
				const allRelaSecs = elfSections.filter(s => s.type === 4 || s.type === 9);
				console.log(`[HexCore] FIX-011: Total relocation sections in file: ${allRelaSecs.length}: ` +
					allRelaSecs.map(s => `"${s.name}"(info=${s.info})`).join(', '));

				// Architecture-aware relocation type filter
				// x86_64: PC32=2, PLT32=4, GOTPCREL=9, 32S=11, GOTPCRELX=41, REX_GOTPCRELX=42
				// AArch64: ADR_PREL_PG_HI21=275, ADD_ABS_LO12_NC=277, JUMP26=282, CALL26=283, LDST64=286
				// ARM32: THM_CALL=10, CALL=28, JUMP24=29, THM_JUMP24=30
				const isX86 = this.architecture === 'x86' || this.architecture === 'x64';
				const isARM64 = this.architecture === 'arm64';
				const isARM32 = this.architecture === 'arm';
				const callRelTypes: Set<number> = new Set();
				if (isX86) {
					[2, 4, 9, 11, 41, 42].forEach(t => callRelTypes.add(t));
				} else if (isARM64) {
					[275, 277, 282, 283, 286].forEach(t => callRelTypes.add(t));
				} else if (isARM32) {
					[10, 28, 29, 30].forEach(t => callRelTypes.add(t));
				} else {
					// Fallback: accept common x86_64 + AArch64 call types
					[2, 4, 9, 41, 42, 282, 283].forEach(t => callRelTypes.add(t));
				}

				const symEntSize = is64Bit ? 24 : 16;
				let totalParsed = 0;

				for (const relaSec of relaSections) {
					const isRela = relaSec.type === 4; // SHT_RELA has addend field
					const relEntSize = isRela ? (is64Bit ? 24 : 12) : (is64Bit ? 16 : 8);
					const numRel = relEntSize > 0 ? Math.floor(relaSec.size / relEntSize) : 0;

					// Determine base offset of the target section relative to main .text
					// so rOffset values from per-function sections are globally consistent.
					const targetSec = elfSections[relaSec.info];
					const mainText = textSections.find(s => s.name === '.text');
					const sectionBase = (targetSec && mainText)
						? (targetSec.offset - mainText.offset)
						: 0;

					for (let i = 0; i < numRel && i < 262144; i++) {
						const relOff = relaSec.offset + i * relEntSize;
						if (relOff + relEntSize > this.fileBuffer.length) { break; }

						const rOffset = is64Bit ? Number(readU64(relOff)) : readU32(relOff);
						const rInfo = is64Bit ? Number(readU64(relOff + 8)) : readU32(relOff + 4);
						// r_addend is SIGNED — must read as signed int64, not unsigned
						const rAddendRaw = isRela
							? (is64Bit ? readU64(relOff + 16) : BigInt(readU32(relOff + 8)))
							: 0n;
						const rAddend = typeof rAddendRaw === 'bigint'
							? Number(BigInt.asIntN(64, rAddendRaw))
							: Number(rAddendRaw);

						const symIdx = is64Bit ? Math.trunc(rInfo / 0x100000000) : (rInfo >> 8);
						const relType = is64Bit ? (rInfo & 0xFFFFFFFF) : (rInfo & 0xFF);

						// Read the symbol table entry. Layouts differ by class:
						//   Elf64_Sym: name@0(4) info@4(1) other@5(1) shndx@6(2) value@8(8)
						//   Elf32_Sym: name@0(4) value@4(4) size@8(4) info@12(1) shndx@14(2)
						const symOff = symtabSec.offset + symIdx * symEntSize;
						if (symOff + symEntSize > this.fileBuffer.length) { continue; }
						const stName = readU32(symOff);
						const stInfoByte = this.fileBuffer[is64Bit ? symOff + 4 : symOff + 12];
						const stType = stInfoByte & 0xf;            // STT_* (3 = SECTION)
						const shndxOff = is64Bit ? symOff + 6 : symOff + 14;
						const stShndx = this.fileBuffer[shndxOff] | (this.fileBuffer[shndxOff + 1] << 8);
						const stValue = is64Bit ? Number(readU64(symOff + 8)) : readU32(symOff + 4);

						let symName = '';
						const symNameOff = strtabSec.offset + stName;
						if (symNameOff < this.fileBuffer.length) {
							for (let j = symNameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
								symName += String.fromCharCode(this.fileBuffer[j]);
								if (symName.length > 256) { break; }
							}
						}

						// FIX-097: DATA relocations (R_X86_64_32=10 / R_X86_64_32S=11)
						// are absolute references into a data section — overwhelmingly a
						// string/constant load (`mov rdi, .rodata.str1.1+OFF`). They point
						// at a SECTION symbol (st_name=0 => empty name) so FIX-011's
						// empty-name skip dropped them, leaving the operand `i64 0` — the
						// root of `printk(0, ...)`. Route them to dataRelocations keyed by
						// the TARGET section name + effective in-section offset, so liftToIR
						// can read the bytes and feed the string to the decompiler.
						if (relType === 10 || relType === 11) {
							const targetSec = (stShndx > 0 && stShndx < elfSections.length)
								? elfSections[stShndx] : undefined;
							// STT_SECTION(3): st_value is 0, the addend is the full offset.
							// Named data object: in-section offset = st_value + addend.
							const inSecOff = (stType === 3 ? 0 : stValue) + rAddend;
							const secName = targetSec?.name ?? symName;
							if (secName && secName.length > 0) {
								this.dataRelocations.set(sectionBase + rOffset, {
									sectionName: secName,
									type: relType,
									addend: inSecOff
								});
							}
							continue; // absolute data ref — never a call/jump
						}

						if (!callRelTypes.has(relType)) {
							continue;
						}
						if (symName.length === 0) { continue; }

						// rOffset is relative to target section; adjust to overall .text start
						this.textRelocations.set(sectionBase + rOffset, {
							name: symName,
							type: relType,
							addend: rAddend
						});
					}
					totalParsed += numRel;
				}
				console.log(`[HexCore] FIX-011: Parsed ${totalParsed} reloc entries across ${relaSections.length} sections, ` +
					`${this.textRelocations.size} call/jump relocations stored. ` +
					`First 10: ${[...this.textRelocations.entries()].slice(0, 10).map(([off, r]) => `0x${off.toString(16)}→${r.name}(type=${r.type})`).join(', ')}`);
				console.log(`[HexCore] FIX-097: ${this.dataRelocations.size} data relocations (string/constant loads) stored. ` +
					`First 10: ${[...this.dataRelocations.entries()].slice(0, 10).map(([off, r]) => `0x${off.toString(16)}→${r.sectionName}+0x${r.addend.toString(16)}(type=${r.type})`).join(', ')}`);

				if (this.textRelocations.size === 0 && totalParsed > 0) {
					console.warn(`[HexCore] FIX-011: ${totalParsed} relocation entries found but NONE matched call/jump types ` +
						`(arch=${this.architecture}, accepted types=[${[...callRelTypes].join(',')}]). ` +
						`Check if architecture detection is correct.`);
				}
			} else {
				console.warn(`[HexCore] FIX-011: ET_REL missing required sections — textSections=${textSections.length}, symtabSec=${!!symtabSec}, strtabSec=${!!strtabSec}`);
			}
		}

		// =====================================================================
		// v3.7.5 P4: Enhanced ELF Analysis — build comprehensive ELF data
		// =====================================================================

		const ELF_TYPE_NAMES: Record<number, string> = {
			0: 'ET_NONE', 1: 'ET_REL', 2: 'ET_EXEC', 3: 'ET_DYN', 4: 'ET_CORE'
		};

		const PT_NAMES: Record<number, string> = {
			0: 'PT_NULL', 1: 'PT_LOAD', 2: 'PT_DYNAMIC', 3: 'PT_INTERP',
			4: 'PT_NOTE', 5: 'PT_SHLIB', 6: 'PT_PHDR', 7: 'PT_TLS',
			0x6474E550: 'PT_GNU_EH_FRAME', 0x6474E551: 'PT_GNU_STACK',
			0x6474E552: 'PT_GNU_RELRO', 0x6474E553: 'PT_GNU_PROPERTY'
		};

		const STB_NAMES = ['LOCAL', 'GLOBAL', 'WEAK'];
		const STT_NAMES = ['NOTYPE', 'OBJECT', 'FUNC', 'SECTION', 'FILE', 'COMMON', 'TLS'];
		const STV_NAMES = ['DEFAULT', 'INTERNAL', 'HIDDEN', 'PROTECTED'];

		// Relocation type name maps
		const RELT_X86_64: Record<number, string> = {
			0: 'R_X86_64_NONE', 1: 'R_X86_64_64', 2: 'R_X86_64_PC32',
			4: 'R_X86_64_PLT32', 5: 'R_X86_64_COPY', 6: 'R_X86_64_GLOB_DAT',
			7: 'R_X86_64_JUMP_SLOT', 8: 'R_X86_64_RELATIVE', 9: 'R_X86_64_GOTPCREL',
			10: 'R_X86_64_32', 11: 'R_X86_64_32S', 41: 'R_X86_64_GOTPCRELX',
			42: 'R_X86_64_REX_GOTPCRELX'
		};
		const RELT_AARCH64: Record<number, string> = {
			275: 'R_AARCH64_ADR_PREL_PG_HI21', 277: 'R_AARCH64_ADD_ABS_LO12_NC',
			282: 'R_AARCH64_JUMP26', 283: 'R_AARCH64_CALL26',
			257: 'R_AARCH64_ABS64', 258: 'R_AARCH64_ABS32'
		};
		const relocTypeNames = (this.architecture === 'arm64') ? RELT_AARCH64 : RELT_X86_64;

		const DT_NAMES: Record<number, string> = {
			0: 'DT_NULL', 1: 'DT_NEEDED', 2: 'DT_PLTRELSZ', 3: 'DT_PLTGOT',
			4: 'DT_HASH', 5: 'DT_STRTAB', 6: 'DT_SYMTAB', 7: 'DT_RELA',
			8: 'DT_RELASZ', 9: 'DT_RELAENT', 10: 'DT_STRSZ', 11: 'DT_SYMENT',
			12: 'DT_INIT', 13: 'DT_FINI', 14: 'DT_SONAME', 15: 'DT_RPATH',
			20: 'DT_PLTREL', 21: 'DT_DEBUG', 23: 'DT_JMPREL',
			24: 'DT_BIND_NOW', 25: 'DT_INIT_ARRAY', 26: 'DT_FINI_ARRAY',
			27: 'DT_INIT_ARRAYSZ', 28: 'DT_FINI_ARRAYSZ', 29: 'DT_RUNPATH',
			30: 'DT_FLAGS', 0x6FFFFFFB: 'DT_FLAGS_1', 0x6FFFFFF0: 'DT_VERSYM',
			0x6FFFFFFD: 'DT_VERDEF', 0x6FFFFFFE: 'DT_VERNEED',
			0x6FFFFFF9: 'DT_RELACOUNT', 0x6FFFFFFA: 'DT_RELCOUNT',
			0x6FFFFFF5: 'DT_GNU_PRELINKED', 0x6FFFFFF3: 'DT_GNU_CONFLICT',
			0x6FFFFEF5: 'DT_GNU_HASH'
		};

		// -- 1. Program Headers --
		const programHeaders: ELFProgramHeader[] = [];
		let interpPath: string | undefined;
		if (phoff > 0 && phnum > 0) {
			for (let i = 0; i < phnum; i++) {
				const phOff = phoff + i * phentsize;
				if (phOff + phentsize > this.fileBuffer.length) { break; }

				const pType = readU32(phOff);
				const pFlags = is64Bit ? readU32(phOff + 4) : readU32(phOff + 24);
				const pOffset = is64Bit ? Number(readU64(phOff + 8)) : readU32(phOff + 4);
				const pVaddr = is64Bit ? Number(readU64(phOff + 16)) : readU32(phOff + 8);
				const pPaddr = is64Bit ? Number(readU64(phOff + 24)) : readU32(phOff + 12);
				const pFilesz = is64Bit ? Number(readU64(phOff + 32)) : readU32(phOff + 16);
				const pMemsz = is64Bit ? Number(readU64(phOff + 40)) : readU32(phOff + 20);
				const pAlign = is64Bit ? Number(readU64(phOff + 48)) : readU32(phOff + 28);

				let perms = '';
				perms += (pFlags & 4) ? 'r' : '-';
				perms += (pFlags & 2) ? 'w' : '-';
				perms += (pFlags & 1) ? 'x' : '-';

				const ph: ELFProgramHeader = {
					type: pType,
					typeName: PT_NAMES[pType] || `PT_0x${pType.toString(16)}`,
					flags: pFlags,
					permissions: perms,
					offset: pOffset,
					vaddr: pVaddr,
					paddr: pPaddr,
					filesz: pFilesz,
					memsz: pMemsz,
					align: pAlign
				};

				// PT_INTERP: read interpreter path
				if (pType === 3 && pOffset > 0 && pOffset + pFilesz <= this.fileBuffer.length) {
					let interp = '';
					for (let j = pOffset; j < pOffset + pFilesz && this.fileBuffer[j] !== 0; j++) {
						interp += String.fromCharCode(this.fileBuffer[j]);
					}
					if (interp.length > 0) {
						ph.interpreter = interp;
						interpPath = interp;
					}
				}

				programHeaders.push(ph);
			}
		}

		// -- 2. Full Symbol Table --
		const allSymbols: ELFSymbolEntry[] = [];
		for (const sec of elfSections) {
			if (sec.type !== 2 && sec.type !== 11) { continue; }
			if (sec.entsize === 0 || sec.size === 0) { continue; }
			const strTabSec = elfSections[sec.link];
			if (!strTabSec) { continue; }

			const symCount = Math.min(Math.floor(sec.size / sec.entsize), 16384);
			for (let i = 0; i < symCount; i++) {
				const symOff = sec.offset + i * sec.entsize;
				if (symOff + sec.entsize > this.fileBuffer.length) { break; }

				let stName: number, stInfo: number, stOther: number, stShndx: number, stValue: number, stSize: number;
				if (is64Bit) {
					stName = readU32(symOff);
					stInfo = this.fileBuffer[symOff + 4];
					stOther = this.fileBuffer[symOff + 5];
					stShndx = readU16(symOff + 6);
					stValue = Number(readU64(symOff + 8));
					stSize = Number(readU64(symOff + 16));
				} else {
					stName = readU32(symOff);
					stValue = readU32(symOff + 4);
					stSize = readU32(symOff + 8);
					stInfo = this.fileBuffer[symOff + 12];
					stOther = this.fileBuffer[symOff + 13];
					stShndx = readU16(symOff + 14);
				}

				let symName = '';
				const nameOff = strTabSec.offset + stName;
				if (nameOff < this.fileBuffer.length) {
					for (let j = nameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
						symName += String.fromCharCode(this.fileBuffer[j]);
						if (symName.length > 256) { break; }
					}
				}
				if (symName.length === 0 && i === 0) { continue; } // skip null symbol

				const stBind = stInfo >> 4;
				const stType = stInfo & 0xF;
				const stVis = stOther & 0x3;

				const secName = (stShndx > 0 && stShndx < elfSections.length)
					? elfSections[stShndx].name
					: stShndx === 0 ? 'UND' : stShndx === 0xFFF1 ? 'ABS' : stShndx === 0xFFF2 ? 'COM' : `sec_${stShndx}`;

				allSymbols.push({
					name: symName || `sym_${i}`,
					value: stValue,
					size: stSize,
					binding: STB_NAMES[stBind] || `BIND_${stBind}`,
					type: STT_NAMES[stType] || (stType === 10 ? 'GNU_IFUNC' : `TYPE_${stType}`),
					visibility: STV_NAMES[stVis] || `VIS_${stVis}`,
					sectionIndex: stShndx,
					sectionName: secName,
					isImport: stShndx === 0 && (stBind === 1 || stBind === 2),
					isExport: stShndx !== 0 && (stBind === 1 || stBind === 2) && stType === 2
				});
			}
		}

		// -- 3. All Relocations (human-readable) --
		const allRelocations: ELFRelocationEntry[] = [];
		for (const sec of elfSections) {
			if (sec.type !== 4 && sec.type !== 9) { continue; } // SHT_RELA=4, SHT_REL=9
			if (sec.entsize === 0 || sec.size === 0) { continue; }

			const isRela = sec.type === 4;
			const relEntSize = isRela ? (is64Bit ? 24 : 12) : (is64Bit ? 16 : 8);
			const numRel = Math.min(Math.floor(sec.size / relEntSize), 65536);

			// Find associated symtab + strtab
			const relSymtab = elfSections[sec.link];
			const relStrtab = relSymtab ? elfSections[relSymtab.link] : undefined;

			for (let i = 0; i < numRel; i++) {
				const relOff = sec.offset + i * relEntSize;
				if (relOff + relEntSize > this.fileBuffer.length) { break; }

				const rOffset = is64Bit ? Number(readU64(relOff)) : readU32(relOff);
				const rInfo = is64Bit ? Number(readU64(relOff + 8)) : readU32(relOff + 4);
				const rAddend = isRela ? (is64Bit ? Number(BigInt.asIntN(64, readU64(relOff + 16))) : readU32(relOff + 8)) : 0;

				const symIdx = is64Bit ? Math.trunc(rInfo / 0x100000000) : (rInfo >> 8);
				const relType = is64Bit ? (rInfo & 0xFFFFFFFF) : (rInfo & 0xFF);

				// Resolve symbol name
				let symName = '';
				if (relSymtab && relStrtab) {
					const symEntSz = is64Bit ? 24 : 16;
					const sOff = relSymtab.offset + symIdx * symEntSz;
					if (sOff + symEntSz <= this.fileBuffer.length) {
						const sName = readU32(sOff);
						const sNameOff = relStrtab.offset + sName;
						if (sNameOff < this.fileBuffer.length) {
							for (let j = sNameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
								symName += String.fromCharCode(this.fileBuffer[j]);
								if (symName.length > 256) { break; }
							}
						}
					}
				}

				allRelocations.push({
					offset: rOffset,
					type: relType,
					typeName: relocTypeNames[relType] || `REL_${relType}`,
					symbolName: symName || `sym_${symIdx}`,
					addend: rAddend,
					sectionName: sec.name
				});
			}
		}

		// -- 4. Dynamic Entries --
		const dynamicEntries: ELFDynamicEntry[] = [];
		const neededLibs: string[] = [];
		let soname: string | undefined;
		for (const sec of elfSections) {
			if (sec.type !== 6) { continue; } // SHT_DYNAMIC
			const dynStrSec = elfSections[sec.link];
			const entrySize = is64Bit ? 16 : 8;
			const numEntries = Math.floor(sec.size / entrySize);

			for (let i = 0; i < numEntries; i++) {
				const entOff = sec.offset + i * entrySize;
				if (entOff + entrySize > this.fileBuffer.length) { break; }

				const dTag = is64Bit ? Number(readU64(entOff)) : readU32(entOff);
				const dVal = is64Bit ? Number(readU64(entOff + 8)) : readU32(entOff + 4);

				if (dTag === 0) { break; } // DT_NULL

				const entry: ELFDynamicEntry = {
					tag: dTag,
					tagName: DT_NAMES[dTag] || `DT_0x${dTag.toString(16)}`,
					value: dVal
				};

				// Resolve string values for DT_NEEDED, DT_SONAME, DT_RPATH, DT_RUNPATH
				if (dynStrSec && (dTag === 1 || dTag === 14 || dTag === 15 || dTag === 29)) {
					let str = '';
					const sOff = dynStrSec.offset + dVal;
					if (sOff < this.fileBuffer.length) {
						for (let j = sOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
							str += String.fromCharCode(this.fileBuffer[j]);
							if (str.length > 256) { break; }
						}
					}
					entry.stringValue = str;

					if (dTag === 1 && str) { neededLibs.push(str); }
					if (dTag === 14 && str) { soname = str; }
				}

				dynamicEntries.push(entry);
			}
		}

		// -- 5. .modinfo parsing for kernel modules (.ko) --
		let moduleInfo: ELFModuleInfo | undefined;
		if (eType === 1) {
			const modinfoSec = elfSections.find(s => s.name === '.modinfo');
			if (modinfoSec && modinfoSec.size > 0 && modinfoSec.offset + modinfoSec.size <= this.fileBuffer.length) {
				moduleInfo = {};
				const parmDescs: Array<{ name: string; description: string }> = [];

				// .modinfo is a sequence of null-terminated "key=value" strings
				let pos = modinfoSec.offset;
				const end = modinfoSec.offset + modinfoSec.size;
				while (pos < end) {
					// Skip null bytes between entries
					while (pos < end && this.fileBuffer[pos] === 0) { pos++; }
					if (pos >= end) { break; }

					let entry = '';
					while (pos < end && this.fileBuffer[pos] !== 0) {
						entry += String.fromCharCode(this.fileBuffer[pos]);
						pos++;
						if (entry.length > 1024) { break; }
					}

					const eq = entry.indexOf('=');
					if (eq <= 0) { continue; }
					const key = entry.substring(0, eq);
					const val = entry.substring(eq + 1);

					switch (key) {
						case 'name': moduleInfo.name = val; break;
						case 'version': moduleInfo.version = val; break;
						case 'description': moduleInfo.description = val; break;
						case 'author': moduleInfo.author = val; break;
						case 'license': moduleInfo.license = val; break;
						case 'srcversion': moduleInfo.srcversion = val; break;
						case 'vermagic': moduleInfo.vermagic = val; break;
						case 'intree':
							moduleInfo.intree = val === 'Y';
							break;
						case 'retpoline':
							moduleInfo.retpoline = val === 'Y';
							break;
						case 'depends':
							moduleInfo.depends = val.length > 0 ? val.split(',').filter(s => s.length > 0) : [];
							break;
						case 'parmtype': break; // skip, we use parm
						case 'parm': {
							const colonIdx = val.indexOf(':');
							if (colonIdx > 0) {
								parmDescs.push({ name: val.substring(0, colonIdx), description: val.substring(colonIdx + 1) });
							}
							break;
						}
					}
				}

				if (parmDescs.length > 0) {
					moduleInfo.parmDescriptions = parmDescs;
				}

				// If empty, discard
				if (!moduleInfo.name && !moduleInfo.license && !moduleInfo.vermagic) {
					moduleInfo = undefined;
				}
			}
		}

		// -- Extract executable sections with semantic classification --
		const executableSections = this.extractExecutableSections(elfSections);

		// -- Store the complete analysis --
		this.elfAnalysis = {
			programHeaders,
			symbols: allSymbols,
			relocations: allRelocations,
			dynamicEntries,
			moduleInfo,
			neededLibraries: neededLibs,
			soname,
			interpreter: interpPath,
			elfType: ELF_TYPE_NAMES[eType] || `ET_${eType}`,
			elfTypeValue: eType,
			executableSections
		};
	}

	private parseRawFile(): void {
		if (!this.fileBuffer) {
			return;
		}

		this.fileInfo = {
			format: 'Raw',
			architecture: this.architecture,
			entryPoint: this.baseAddress,
			baseAddress: this.baseAddress,
			imageSize: this.fileBuffer.length
		};

		this.sections.push({
			name: '.code',
			virtualAddress: this.baseAddress,
			virtualSize: this.fileBuffer.length,
			rawAddress: 0,
			rawSize: this.fileBuffer.length,
			characteristics: 0,
			permissions: 'rwx',
			isCode: true,
			isData: false,
			isReadable: true,
			isWritable: true,
			isExecutable: true
		});
	}

	private rvaToFileOffset(rva: number): number {
		if (!this.fileBuffer) {
			return -1;
		}

		for (const section of this.sections) {
			const sectionRVA = section.virtualAddress - this.baseAddress;
			if (rva >= sectionRVA && rva < sectionRVA + section.virtualSize) {
				return section.rawAddress + (rva - sectionRVA);
			}
		}

		return rva;
	}

	// ============================================================================
	// Function Analysis
	// ============================================================================

	/**
	 * v3.8.5: Resolve a PLT-family stub VA (`.plt`, `.plt.sec`, `.plt.got`) to its import
	 * symbol name, or undefined if it is not a stub. Two paths:
	 *   (1) direct hit in _pltSymbolMap (legacy `.plt` VA, keyed during .rela.plt parse), or
	 *   (2) the IBT/CET `.plt.sec` thunk: endbr64 (F3 0F 1E FA) ; bnd jmp *off(%rip)
	 *       (F2 FF 25 disp32) -- decode the rip-relative GOT slot and look it up in
	 *       _gotSymbolMap. (Also handles the non-bnd `FF 25 disp32` form.)
	 * x86/x64 only; returns undefined on other arches.
	 */
	private resolveStubSymbol(stubVA: number): string | undefined {
		const direct = this._pltSymbolMap.get(stubVA);
		if (direct) { return direct.split('@')[0]; }
		if (!this.fileBuffer) { return undefined; }
		if (this.architecture !== 'x64' && this.architecture !== 'x86') { return undefined; }

		const off = this.addressToOffset(stubVA);
		if (off < 0 || off + 16 > this.fileBuffer.length) { return undefined; }
		const buf = this.fileBuffer;

		// Skip an optional endbr64 (F3 0F 1E FA) prefix.
		let p = off;
		if (buf[p] === 0xF3 && buf[p + 1] === 0x0F && buf[p + 2] === 0x1E && buf[p + 3] === 0xFA) {
			p += 4;
		}
		// Optional bnd prefix (F2) before the indirect jmp.
		let insVA = stubVA + (p - off);
		if (buf[p] === 0xF2) { p += 1; insVA += 1; }
		// jmp [rip + disp32]  ->  FF 25 disp32  (6 bytes incl. the FF 25)
		if (buf[p] === 0xFF && buf[p + 1] === 0x25 && p + 6 <= this.fileBuffer.length) {
			const disp32 = buf.readInt32LE(p + 2);
			const gotVA = insVA + 6 + disp32; // rip points past the 6-byte instruction
			const sym = this._gotSymbolMap.get(gotVA);
			return sym ? sym.split('@')[0] : undefined;
		}
		return undefined;
	}

	/**
	 * v3.8.5: Is `va` inside the IBT/CET `.plt.sec` stub section?
	 *
	 * Used to bound the extent of `.plt.sec` thunks. A `.plt.sec` thunk is `endbr64 ; bnd jmp
	 * *GOT[n](%rip)` padded to a 16-byte stride: Capstone folds the F2 (BND) prefix into the
	 * mnemonic ("bnd jmp"), so the wrapper classifies it isJump=false, AND it is an indirect
	 * jump with no immediate target. analyzeFunction's end-detection therefore never terminates
	 * on it, so the stub runs on into the next thunk and, on IBT binaries that also trip the
	 * trap-handler gate, all the way to the shared `hlt` padding at the section tail (observed:
	 * every `.plt.sec` entry on behindthescenes over-read to one shared end). Clamping is gated
	 * to `.plt.sec` so legacy `.plt`/`.plt.got` stubs and normal indirect `jmp [rip+disp]`
	 * (jump tables / tail calls) are byte-identical -- the legacy `.plt` end-handling is
	 * unchanged (its stubs are not over-read on the regression set; only the new IBT thunk was).
	 * x86/x64 only -- `.plt.sec` is an x86 CET construct; other arches have no such section.
	 */
	private isPltSecAddress(va: number): boolean {
		if (this.architecture !== 'x64' && this.architecture !== 'x86') { return false; }
		for (const s of this.sections) {
			if (s.name === '.plt.sec' &&
				va >= s.virtualAddress && va < s.virtualAddress + s.virtualSize) {
				return true;
			}
		}
		return false;
	}

	/**
	 * v3.8.5: Is this instruction an x86 trap/undefined opcode that a SIGILL/SIGTRAP
	 * handler can skip over? ud2 (0F 0B, 2 bytes), int3 (CC, 1 byte), hlt (F4, 1 byte).
	 * Used only when trapHandlerGate is active.
	 */
	private isTrapMnemonic(mnemonic: string): boolean {
		const m = mnemonic.toLowerCase();
		return m === 'ud2' || m === 'ud2a' || m === 'ud2b' || m === 'int3' || m === 'hlt';
	}

	/**
	 * v3.8.5: Decide whether to treat ud2/int3/hlt as NON-terminating during discovery.
	 *
	 * The "behind the scenes" anti-disassembly idiom installs a SIGILL/SIGTRAP/SIGSEGV
	 * handler (via sigaction/signal) whose body reads ucontext->uc_mcontext.gregs[REG_RIP],
	 * adds the trap-instruction length, and writes it back -- so after every ud2 the program
	 * RESUMES at trap_addr + 2. The real function body is interleaved between ud2 separators.
	 * A linear/CFG sweep that treats ud2 as a return (HexCore classifies ud2 as isRet so the
	 * CFG ends cleanly on __builtin_trap) truncates the function at the FIRST ud2 and leaves
	 * the entire body in a discovery hole.
	 *
	 * The gate is deliberately TIGHT so binaries that use ud2/int3 as GENUINE terminators and
	 * install NO trap handler stay byte-identical:
	 *   (1) a handler-installer symbol (sigaction/signal/...) must be linked via the PLT, AND
	 *   (2) there must be a real `call` to that PLT stub in an executable section, AND
	 *   (3) where recoverable, the System V first argument (signum, in EDI) at that call site
	 *       must be a trap-class signal (SIGILL=4 / SIGTRAP=5 / SIGSEGV=11 / SIGBUS=7 / SIGFPE=8).
	 * If the signum cannot be recovered but a handler-installer is genuinely called, the gate
	 * still trips (conservative "imported AND used"): the only behavioural change is at trap
	 * instructions, which a non-trap-idiom binary would not place inside live code anyway.
	 *
	 * x86/x64 ELF/PIE only (the idiom is x86-specific: it depends on REG_RIP advancement and
	 * the 0F 0B / CC / F4 encodings). Other arches: gate stays off, byte-identical.
	 */
	private detectTrapHandlerGate(): void {
		this.trapHandlerGate = false;
		if (!this.fileBuffer) { return; }
		if (this.architecture !== 'x64' && this.architecture !== 'x86') { return; }

		// Handler-installer symbols. Installing a handler for SIGILL/SIGTRAP/SIGSEGV is what
		// makes a trap resumable; sigaction/signal/sigaction64 and the BSD/SysV aliases.
		const installerNames = new Set([
			'sigaction', '__sigaction', '__sigaction_internal', 'sigaction64',
			'signal', '__signal', 'bsd_signal', 'sysv_signal', '__sysv_signal',
			'__libc_sigaction', 'sigvec'
		]);

		// Fast reject: a handler installer must at least be linked (PLT/GOT or import table).
		let installerLinked = false;
		for (const sym of this._pltSymbolMap.values()) {
			if (installerNames.has(sym.split('@')[0])) { installerLinked = true; break; }
		}
		if (!installerLinked) {
			for (const sym of this._gotSymbolMap.values()) {
				if (installerNames.has(sym.split('@')[0])) { installerLinked = true; break; }
			}
		}
		if (!installerLinked) {
			for (const lib of this.imports) {
				if (lib.functions.some(f => installerNames.has(f.name.split('@')[0]))) {
					installerLinked = true; break;
				}
			}
		}
		if (!installerLinked) { return; }

		// SysV/x86: signum is the 1st integer arg -> EDI. Trap-class signals only.
		const TRAP_SIGNALS = new Set([4 /*SIGILL*/, 5 /*SIGTRAP*/, 7 /*SIGBUS*/, 8 /*SIGFPE*/, 11 /*SIGSEGV*/]);

		const buf = this.fileBuffer;
		const execSections = this.sections.filter(s => s.isCode || s.isExecutable);
		let calledInstaller = false;
		let trapSignumSeen = false;

		for (const section of execSections) {
			const rawStart = section.rawAddress;
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
			if (rawStart >= buf.length || rawEnd <= rawStart) { continue; }

			// Scan for direct near calls: E8 rel32 (and E9 rel32 tail-jumps into the stub).
			// Resolve the target through any PLT-family stub (.plt / .plt.sec / .plt.got) so
			// IBT/CET binaries that call the `.plt.sec` thunk are detected too.
			for (let i = rawStart; i + 5 <= rawEnd; i++) {
				const op = buf[i];
				if (op !== 0xE8 && op !== 0xE9) { continue; }
				const rel32 = buf.readInt32LE(i + 1);
				const instrVA = this.sectionOffsetToAddress(i, section);
				const targetVA = instrVA + 5 + rel32;
				const tgtSym = this.resolveStubSymbol(targetVA);
				if (!tgtSym || !installerNames.has(tgtSym)) { continue; }
				calledInstaller = true;

				// Look back up to 64 bytes for the most recent `mov edi, imm32` (BF id) or
				// `mov dil/edi/rdi` setup that fixes the signum. EDI is the SysV 1st arg.
				const lookback = Math.max(rawStart, i - 64);
				let foundImm: number | undefined;
				for (let j = i - 1; j >= lookback; j--) {
					// mov edi, imm32  ->  BF id   (5 bytes)
					if (buf[j] === 0xBF && j + 5 <= rawEnd) {
						foundImm = buf.readUInt32LE(j + 1) | 0;
						break;
					}
					// mov edi, imm32 via REX (48/40 BF) is non-canonical; xor edi,edi -> 0.
					// xor edi, edi -> 31 FF  (signum 0; never a trap signal, ignore)
					if (buf[j] === 0x31 && j + 1 < rawEnd && buf[j + 1] === 0xFF) {
						foundImm = 0;
						break;
					}
				}
				if (foundImm !== undefined && TRAP_SIGNALS.has(foundImm >>> 0)) {
					trapSignumSeen = true;
				}
			}
		}

		// Gate ON when: a trap-class signum was set at a handler-installer call site, OR a
		// handler installer is genuinely called but no signum could be recovered (conservative).
		this.trapHandlerGate = trapSignumSeen || calledInstaller;
		if (this.trapHandlerGate) {
			console.log(`[HexCore] trap-handler gate ON (installer called=${calledInstaller}, trap-signum=${trapSignumSeen}); ud2/int3/hlt treated as non-terminating.`);
		}
	}

	/** v3.8.5: external read of the trap-handler gate (tests/harness). */
	public isTrapHandlerGateActive(): boolean {
		return this.trapHandlerGate;
	}

	/**
	 * A-lazy function discovery: materialize a STUB function on demand. reconcileFunctionsWithPdata
	 * registers every .pdata function as a lightweight stub (correct [address,endAddress), empty
	 * `instructions`) so the function list is complete and the lift gets exact bounds WITHOUT paying
	 * for per-function body disassembly up front. The body is disassembled here the FIRST time its
	 * instruction listing is actually needed (the disasm view / CFG / single-function export).
	 *
	 * Idempotent:
	 *  - address not in the table        -> undefined (nothing to materialize)
	 *  - address not a tracked stub      -> already materialized (or never was a stub); return it as-is
	 *  - otherwise                       -> disassemble [address,endAddress), filter to the function's
	 *                                       bounds, assign instructions, recompute size, drop the stub flag
	 *
	 * Body disassembly is NON-recursive (it does not follow call/jump children) -- it mirrors
	 * reconcileFunctionsWithPdata step (2): we already have the authoritative .pdata bounds, so the
	 * call graph is rebuilt elsewhere and we must not re-explode into ghost children here.
	 */
	async materializeFunction(address: number): Promise<Function | undefined> {
		// Safety: coerce BigInt from Capstone prebuilds to number (same as analyzeFunction).
		if (typeof address === 'bigint') { address = Number(address); }
		const fn = this.functions.get(address);
		if (!fn) {
			return undefined; // not a known function -- nothing to materialize
		}
		if (!this.unmaterializedStubs.has(address)) {
			return fn; // already materialized (or never a stub) -- return as-is
		}

		const endAddress = typeof fn.endAddress === 'bigint' ? Number(fn.endAddress) : fn.endAddress;
		const span = (endAddress - address) || this.maxFunctionSize;
		const size = Math.min(span, this.maxFunctionSize);

		let insns: Instruction[] = [];
		try {
			const rawInsns = await this.disassembleRange(address, size);
			// Clamp to the authoritative .pdata bounds [address,endAddress); disassembleRange may
			// over-read past the real end into a neighbour (same filter as reconcile step 2).
			insns = rawInsns.filter(inst => {
				const a = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
				return a >= address && a < endAddress;
			});
		} catch {
			insns = [];
		}

		fn.instructions = insns;
		// Recompute size/end from the last recovered instruction (reuse analyzeFunction's
		// BigInt coercion + last-instruction end-handling style), never exceeding the .pdata end.
		const last = insns[insns.length - 1];
		if (last) {
			const la = typeof last.address === 'bigint' ? Number(last.address) : last.address;
			const ls = typeof last.size === 'bigint' ? Number(last.size) : last.size;
			const recomputedEnd = Math.min(endAddress, la + ls);
			fn.endAddress = recomputedEnd;
			fn.size = recomputedEnd - address;
		}
		// else: body could not be linearly recovered (obfuscated/VM-protected) -- keep the
		// authoritative .pdata bounds the stub already carried.

		this.unmaterializedStubs.delete(address);
		return fn;
	}

	async analyzeFunction(address: number, name?: string): Promise<Function> {
		// Safety: coerce BigInt from Capstone prebuilds to number
		if (typeof address === 'bigint') { address = Number(address); }
		const existing = this.functions.get(address);
		if (existing) {
			return existing;
		}

		if (!this.isAnalyzableFunctionAddress(address)) {
			return {
				address,
				name: name || `sub_${address.toString(16).toUpperCase()}`,
				size: 0,
				endAddress: address,
				instructions: [],
				callers: [],
				callees: []
			};
		}

		const instructions = await this.disassembleRange(address, this.maxFunctionSize);

		if (instructions.length === 0) {
			const offset = this.addressToOffset(address);
			if (offset >= 0 && offset < this.fileBuffer!.length) {
				const byteCount = Math.min(16, this.fileBuffer!.length - offset);
				instructions.push({
					address,
					bytes: this.fileBuffer!.subarray(offset, offset + byteCount),
					mnemonic: 'db',
					opStr: Array.from(this.fileBuffer!.subarray(offset, offset + byteCount))
						.map(b => `0x${b.toString(16).padStart(2, '0').toUpperCase()}`).join(', '),
					size: byteCount,
					isCall: false,
					isJump: false,
					isRet: false,
					isConditional: false
				});
			}
		}

		// Find function end - handle multiple RETs, look for the last one followed by
		// padding or another function prolog. Architecture-aware detection.
		const isARM = this.architecture === 'arm64' || this.architecture === 'arm';

		// v3.8.5: `.plt.sec` extent clamp. An IBT/CET `.plt.sec` thunk ends at its `bnd jmp
		// *GOT(%rip)` indirect tail-transfer -- which carries no immediate target AND is reported
		// isJump=false (Capstone folds the BND prefix into the mnemonic), so the generic
		// end-detection below never terminates on it and the stub over-reads into the next thunk
		// / shared `hlt` padding (worse under the trap-handler gate, which makes `hlt`
		// non-terminating). When the function entry is in `.plt.sec`, clamp the extent to its
		// first unconditional jmp. Gated strictly to `.plt.sec` so legacy `.plt`/`.plt.got` and
		// normal indirect `jmp [rip+disp]` (jump tables / tail calls) stay byte-identical.
		const addrForRegion = typeof address === 'bigint' ? Number(address) : address;
		const isPltStub = this.isPltSecAddress(addrForRegion);

		let endIdx = instructions.length;
		let lastRetIdx = -1;
		for (let i = 0; i < instructions.length; i++) {
			// v3.8.5: `.plt.sec` extent clamp (see above). Runs BEFORE the trap-handler-gate
			// skip so a stub's `bnd jmp` terminator wins even when the gate would otherwise
			// keep sweeping through the section's shared `hlt` padding.
			//
			// NOTE: a `.plt.sec` thunk's tail transfer is `bnd jmp *GOT(%rip)`. Capstone folds
			// the F2 (BND) prefix INTO the mnemonic ("bnd jmp"), so the wrapper's plain-`jmp`
			// jump-set classification reports isJump=false for it (this is also why the generic
			// unconditional-jump end-detection below never terminates the stub). Recognize the
			// terminator here by stripping the leading bnd/notrack prefix from the mnemonic, so
			// the clamp catches both `jmp` and `bnd jmp`.
			if (isPltStub) {
				const m = instructions[i].mnemonic.toLowerCase().replace(/^(?:bnd|notrack)\s+/, '');
				if (m === 'jmp') {
					endIdx = i + 1;
					break;
				}
			}
			// v3.8.5: trap-handler idiom. When the binary installs a SIGILL/SIGTRAP/SIGSEGV
			// handler that advances RIP past the faulting instruction, ud2/int3/hlt are NOT
			// function terminators -- execution resumes at trap_addr + trap_size. Skip the
			// termination handling so the sweep continues through the real body that follows
			// the trap. Bounded by maxFunctionSize (disassembleRange already capped the input)
			// so a runaway sweep cannot explode. Note ud2 is classified isRet by the wrapper
			// (for __builtin_trap CFG cleanliness); this guard runs BEFORE the isRet branch so
			// it is the gate, not the classifier, that decides termination here.
			if (this.trapHandlerGate && this.isTrapMnemonic(instructions[i].mnemonic) &&
				(instructions[i].address - address) < this.maxFunctionSize) {
				if (!this.comments.has(instructions[i].address)) {
					this.comments.set(instructions[i].address, 'trap skipped by signal handler (RIP advanced)');
					instructions[i].comment = 'trap skipped by signal handler (RIP advanced)';
				}
				continue;
			}
			if (instructions[i].isRet) {
				lastRetIdx = i;
				// Check if next instruction is padding or unreachable
				if (i + 1 < instructions.length) {
					const next = instructions[i + 1];

					if (isARM) {
						// ARM/ARM64: Check if next instruction is a new function prolog or padding
						if (next.bytes.length >= 4) {
							const nextWord = next.bytes.readUInt32LE(0);
							const isARM64Prolog =
								(nextWord & 0xFC407FFF) === 0xA8007BFD ||  // STP x29, x30, [sp, #off]
								nextWord === 0xD503233F ||                  // PACIASP
								((nextWord & 0xFF0003FF) === 0xD10003FF && ((nextWord >> 5) & 0x1F) === 31); // SUB SP, SP, #N
							const isARM32Prolog =
								(nextWord & 0xFFFF0000) === 0xE92D0000 && (nextWord & (1 << 14)) !== 0; // PUSH {..., lr}
							const isNop =
								nextWord === 0xD503201F ||  // ARM64 NOP
								nextWord === 0xE320F000 ||  // ARM32 NOP (mov r0, r0)
								nextWord === 0xE1A00000;    // ARM32 NOP (mov r0, r0 alt)
							const isUDF = (nextWord & 0xFFFF0000) === 0x00000000; // UDF (undefined) as padding

							if (isARM64Prolog || isARM32Prolog || isNop || isUDF) {
								endIdx = i + 1;
								break;
							}
						}
					} else {
						// x86/x64: INT3 (0xCC), NOP (0x90), or push rbp (0x55)
						const nextByte = next.bytes[0];
						if (nextByte === 0xCC || nextByte === 0x90 || nextByte === 0x55) {
							endIdx = i + 1;
							break;
						}
					}

					// If next instruction is a jump target from within the function, continue
					const isJumpTarget = instructions.slice(0, i).some(
						inst => inst.targetAddress === next.address
					);
					if (!isJumpTarget) {
						endIdx = i + 1;
						break;
					}
					// Otherwise continue (this RET is in a branch, not the end)
				} else {
					endIdx = i + 1;
					break;
				}
			}
			if (instructions[i].isJump && !instructions[i].isConditional) {
				if (instructions[i].targetAddress &&
					(instructions[i].targetAddress! < address ||
						instructions[i].targetAddress! > address + this.maxFunctionSize)) {
					// Check if there are more reachable instructions after
					if (i + 1 < instructions.length) {
						const nextIsTarget = instructions.slice(0, i).some(
							inst => inst.targetAddress === instructions[i + 1].address
						);
						if (!nextIsTarget) {
							endIdx = i + 1;
							break;
						}
					} else {
						endIdx = i + 1;
						break;
					}
				}
			}
		}

		// If we never found a clear end, use last RET if found
		if (endIdx === instructions.length && lastRetIdx >= 0) {
			endIdx = lastRetIdx + 1;
		}

		const funcInstructions = instructions.slice(0, endIdx);

		// Coerce address to number — Capstone prebuilds may return BigInt for 64-bit addresses
		const addrNum = typeof address === 'bigint' ? Number(address) : address;
		const lastInst = funcInstructions.length > 0 ? funcInstructions[funcInstructions.length - 1] : undefined;
		const lastAddr = lastInst ? (typeof lastInst.address === 'bigint' ? Number(lastInst.address) : lastInst.address) : addrNum;
		const lastSize = lastInst ? (typeof lastInst.size === 'bigint' ? Number(lastInst.size) : lastInst.size) : 0;

		const func: Function = {
			address: addrNum,
			name: name || `sub_${addrNum.toString(16).toUpperCase()}`,
			size: lastInst ? (lastAddr + lastSize - addrNum) : 0,
			endAddress: lastInst ? (lastAddr + lastSize) : addrNum,
			instructions: funcInstructions,
			callers: [],
			callees: []
		};

		this.functions.set(address, func);

		// Collect child targets for analysis (calls + trampoline jumps)
		const childTargets: number[] = [];

		for (const inst of funcInstructions) {
			if (inst.isCall && inst.targetAddress && this.functions.size < this.maxFunctions) {
				// Ghost-function guard: only treat the call target as a function if it
				// lies in an executable/code section. A direct `call 0x402000` into .data
				// or .rdata must not spawn a sub_402000 stub — that pollutes the function
				// list with hundreds of fake entries on obfuscated/packed binaries.
				// Xref to the target is still recorded (useful for data-ref UI), but we
				// only add it to callees when it's really code.
				const targetIsCode = this.isAnalyzableFunctionAddress(inst.targetAddress);
				this.addXRef({
					from: inst.address,
					to: inst.targetAddress,
					type: targetIsCode ? 'call' : 'data'
				});

				if (targetIsCode) {
					func.callees.push(inst.targetAddress);

					// Track caller in target function
					const target = this.functions.get(inst.targetAddress);
					if (target) {
						if (!target.callers.includes(inst.address)) {
							target.callers.push(inst.address);
						}
					}

					if (!this.functions.has(inst.targetAddress)) {
						childTargets.push(inst.targetAddress);
					}
				}
			}

			// Record jump xrefs and follow unconditional jump targets as new functions
			if (inst.isJump && inst.targetAddress) {
				const jumpTargetIsCode = this.isAnalyzableFunctionAddress(inst.targetAddress);
				this.addXRef({
					from: inst.address,
					to: inst.targetAddress,
					type: jumpTargetIsCode ? 'jump' : 'data'
				});

				// Follow unconditional jumps whose targets are outside this function
				// (trampolines, tail calls, thunks) — treat target as a new function
				// ONLY when the target is actually in a code section. Otherwise a tail
				// jmp into an import thunk / absolute data pointer becomes sub_XX ghost.
				//
				// v3.8.5: when the trap-handler gate extended this function PAST trap
				// separators, the body now contains many interior `jmp <join>` edges (the
				// success/failure landing pads that converge on the epilogue). Those targets
				// lie INSIDE [address, endAddress) and are intra-function CFG joins, not tail
				// calls -- following them would mint interior ghost functions (e.g. a fake
				// sub_<join> at main's stack-canary epilogue). Suppress targets interior to
				// the just-swept body. Gated on trapHandlerGate so non-trap binaries, whose
				// interior-ghost cleanup is handled post-hoc by dropInteriorGhostFunctions*,
				// stay byte-identical.
				const interiorToSelf = this.trapHandlerGate &&
					inst.targetAddress > addrNum && inst.targetAddress < func.endAddress;
				if (jumpTargetIsCode &&
					!inst.isConditional &&
					inst.targetAddress !== address &&
					!interiorToSelf &&
					!this.functions.has(inst.targetAddress) &&
					this.functions.size < this.maxFunctions) {
					childTargets.push(inst.targetAddress);
				}
			}
		}

		// Await child analysis to avoid race conditions with floating promises
		for (const target of childTargets) {
			if (!this.functions.has(target) && this.functions.size < this.maxFunctions) {
				await this.analyzeFunction(target);
			}
		}

		return func;
	}

	private isAnalyzableFunctionAddress(address: number): boolean {
		if (!this.fileBuffer || !Number.isFinite(address) || address <= 0) {
			return false;
		}

		if (this.sections.length > 0) {
			return this.sections.some(section =>
				(section.isCode || section.isExecutable) &&
				address >= section.virtualAddress &&
				address < section.virtualAddress + Math.max(section.virtualSize, section.rawSize)
			);
		}

		const offset = this.addressToOffset(address);
		return offset >= 0 && offset < this.fileBuffer.length;
	}

	/**
	 * Scan code sections for function prologs.
	 * Supports x86/x64 and ARM64/ARM32 prolog patterns.
	 */
	/**
	 * v3.8.3 Gap-A: Reconcile the discovered function table against the authoritative
	 * PE64 .pdata (exception directory) RUNTIME_FUNCTION boundaries.
	 *
	 * Prologue scanning + call/jump following over-produce overlapping "ghost" functions
	 * from mid-function byte patterns (e.g. a CRT exception-data cascade decoded as dozens
	 * of fake sub_* with sizes decreasing by a fixed stride), and occasionally miss real
	 * functions reached only by indirection. When .pdata is present (MSVC x64) every real
	 * function has an exact [begin,end) range, so this pass:
	 *   (1) ensures a function exists at each .pdata begin,
	 *   (2) drops any function whose start is interior to a .pdata range but is not itself
	 *       a begin (the ghosts),
	 *   (3) clamps over-long functions (disassembly ran past the real end into a neighbour)
	 *       to their authoritative .pdata extent, then
	 *   (4) rebuilds callers/callees over the survivors so no call-graph edge dangles at a
	 *       removed ghost.
	 *
	 * Restricted to x64 (AMD64) PE. ARM64 PE is also is64 and carries a .pdata, but its
	 * RUNTIME_FUNCTION second DWORD is packed UnwindData, not an EndAddress, so the ranges
	 * would be garbage; ELF / x86 have no .pdata. All of those are byte-identical to before.
	 * Leaf functions MSVC omits from .pdata are preserved (they neither nest in nor span
	 * another function's range).
	 */
	private async reconcileFunctionsWithPdata(): Promise<void> {
		// .pdata begin/end is the AMD64 RUNTIME_FUNCTION layout only (see header note).
		if (this.architecture !== 'x64') {
			return;
		}
		const pdata = this.getPdataEntries();
		if (pdata.length === 0 || !this.fileBuffer) {
			return;
		}
		const base = this.baseAddress;
		const rawRanges = pdata
			.map(p => ({ begin: p.beginAddress + base, end: p.endAddress + base, unwind: p.unwindInfoAddress }))
			.filter(r => r.end > r.begin)
			.sort((a, b) => a.begin - b.begin);
		if (rawRanges.length === 0) {
			return;
		}

		// v3.8.2 FIX-027: merge MSVC chained-unwind function FRAGMENTS into one logical
		// function. A large/optimized function is emitted by MSVC as several CONTIGUOUS
		// RUNTIME_FUNCTION records (end[i] == begin[i+1]); every continuation fragment's
		// UNWIND_INFO carries UNW_FLAG_CHAININFO (0x4) plus a trailing RUNTIME_FUNCTION that
		// chains (transitively) back to the PRIMARY fragment (the one holding the prologue).
		// IDA / the Windows unwinder treat the whole chain as ONE function. The prior code
		// dropped only FULLY NESTED records, so each CONTIGUOUS fragment survived as a
		// SEPARATE function. That both fragmented the function table AND poisoned the Remill
		// lift: extension.ts injects every function end into knownFunctionEnds, and the PE64
		// scan-break (remill_wrapper.cpp) stops at the FIRST one, truncating any chained
		// function to its first fragment (observed on SOTTR sub_140253A70: 6 fragments ->
		// lift stopped at 0x49 of 0x2bd bytes, leaving Helix a 6-line stub).
		//
		// Read each fragment's UNW_FLAG_CHAININFO and resolve its chain-root. A chained
		// continuation that is CONTIGUOUS with (and roots back to) the currently-open primary
		// is absorbed into it; a non-chained record opens a new function. NO-OP on clean
		// binaries: when no fragment is chained the ranges are identical to before.
		const readChain = (unwindRva: number): { chained: boolean; targetBeginVa: number } => {
			const buf = this.fileBuffer;
			if (!buf) { return { chained: false, targetBeginVa: 0 }; }
			// v3.8.2 FIX-027b (#5): only trust UNWIND_INFO that actually lives inside a section.
			// rvaToFileOffset returns the RVA UNCHANGED for an out-of-section address (forged PE),
			// which would otherwise let attacker-chosen bytes be read as unwind info.
			let unwindInSection = false;
			for (const section of this.sections) {
				const sRva = section.virtualAddress - this.baseAddress;
				if (unwindRva >= sRva && unwindRva < sRva + section.virtualSize) { unwindInSection = true; break; }
			}
			if (!unwindInSection) { return { chained: false, targetBeginVa: 0 }; }
			const uoff = this.rvaToFileOffset(unwindRva);
			if (uoff < 0 || uoff + 4 > buf.length) { return { chained: false, targetBeginVa: 0 }; }
			const verFlags = buf[uoff];
			const version = verFlags & 0x7;
			if (version !== 1 && version !== 2) { return { chained: false, targetBeginVa: 0 }; }
			const chained = ((verFlags >> 3) & 0x4) !== 0; // UNW_FLAG_CHAININFO
			if (!chained) { return { chained: false, targetBeginVa: 0 }; }
			const codeCount = buf[uoff + 2];
			// Unwind codes are 2 bytes each, padded to an even count; the chained
			// RUNTIME_FUNCTION follows them.
			const trailing = uoff + 4 + 2 * ((codeCount + 1) & ~1);
			if (trailing < 0 || trailing + 12 > buf.length) { return { chained: true, targetBeginVa: 0 }; }
			const targetBeginRva = buf.readUInt32LE(trailing);
			return { chained: true, targetBeginVa: targetBeginRva + base };
		};

		const chainByBegin = new Map<number, { chained: boolean; targetBeginVa: number }>();
		for (const r of rawRanges) {
			const info = readChain(r.unwind);
			const existing = chainByBegin.get(r.begin);
			// v3.8.2 FIX-027b (#4): on a duplicate begin (forged/unusual PE), prefer the
			// NON-chained record so a real primary is never misclassified as a continuation
			// and dropped.
			if (existing === undefined || (existing.chained && !info.chained)) {
				chainByBegin.set(r.begin, info);
			}
		}
		// Resolve a fragment's transitive chain-root primary (the non-chained ancestor).
		const rootCache = new Map<number, number>();
		const resolveRoot = (beginVa: number): number => {
			let cur = beginVa;
			const seen: number[] = [];
			for (let depth = 0; depth < 64; depth++) {
				const cached = rootCache.get(cur);
				if (cached !== undefined) { cur = cached; break; }
				if (seen.includes(cur)) { break; } // cycle guard (malformed/forged PE)
				seen.push(cur);
				const ci = chainByBegin.get(cur);
				if (!ci || !ci.chained) { break; }       // non-chained -> this is the root
				if (!chainByBegin.has(ci.targetBeginVa)) { break; } // target outside table
				cur = ci.targetBeginVa;
			}
			for (const v of seen) { rootCache.set(v, cur); }
			return cur;
		};

		const ranges: { begin: number; end: number }[] = [];
		let coverEnd = Number.NEGATIVE_INFINITY;
		for (const r of rawRanges) {
			if (r.end <= coverEnd) {
				continue; // fully nested in an earlier kept range -> same function (legacy drop)
			}
			const ci = chainByBegin.get(r.begin);
			const isContinuation = !!ci && ci.chained;
			if (isContinuation && ranges.length > 0) {
				const open = ranges[ranges.length - 1];
				// Absorb a chained continuation contiguous/overlapping with the open primary
				// AND rooting back to it (the contiguous-fragment case).
				if (r.begin <= coverEnd && resolveRoot(r.begin) === open.begin) {
					open.end = r.end;
					coverEnd = r.end;
					continue;
				}
			}
			// v3.8.2 FIX-027b (#2/#3): everything NOT absorbed above -- a non-chained primary,
			// an ORPHAN continuation (CHAININFO set but its primary is absent from the table),
			// or a NON-CONTIGUOUS cold/out-of-line continuation -- opens its OWN range. This
			// matches the pre-FIX-027 coverage (a non-nested fragment stayed a standalone
			// function), so no function / byte coverage is ever dropped; ONLY genuinely
			// contiguous same-function fragments are merged away by the absorb branch above.
			ranges.push({ begin: r.begin, end: r.end });
			coverEnd = r.end;
		}
		const begins = new Set<number>(ranges.map(r => r.begin));
		const beginsArr = ranges.map(r => r.begin); // sorted ascending (rawRanges was sorted)

		// Overlap sweep helper: no function may start strictly inside another. Any NON-begin
		// whose start is already covered by an earlier function, or whose extent winds across
		// a real .pdata begin, is a ghost (mid-function prologue match, size-decreasing sub_*
		// cascades in exception data / jump tables) and is removed. Authoritative .pdata
		// begins are never dropped.
		const sweepOverlaps = () => {
			const sorted = Array.from(this.functions.values()).sort((a, b) => a.address - b.address);
			let maxEnd = Number.NEGATIVE_INFINITY;
			for (const fn of sorted) {
				if (!begins.has(fn.address)) {
					if (fn.address < maxEnd || this.spansAnyBegin(fn.address, fn.endAddress, beginsArr)) {
						this.functions.delete(fn.address);
						continue;
					}
				}
				if (fn.endAddress > maxEnd) {
					maxEnd = fn.endAddress;
				}
			}
		};

		// (1) Sweep prologue-scan ghosts FIRST, so the maxFunctions budget is free for the
		// real .pdata begins. On heavily-obfuscated binaries the prologue scan over-produces
		// massively (Vanguard vgk.sys: ~10600 functions before reconcile, ~75% ghosts) and
		// would otherwise fill the cap before step (2) can ensure the begins.
		sweepOverlaps();

		// (2) Ensure a function exists at every authoritative .pdata begin. A-lazy: register a
		// cheap STUB at the authoritative [begin,end) -- correct address + endAddress, EMPTY
		// `instructions` -- WITHOUT disassembling the body. The stub is fully navigable/countable
		// and a valid decompile/lift target (the lift reads bytes via getBytes + the stub's
		// endAddress for size; it never iterates func.instructions). The body is disassembled on
		// demand by materializeFunction() the first time its instruction listing is actually read
		// (the disasm view). This is what makes the full table affordable: on a large PE
		// (ROTTR ~40K functions, WWZ ~159K) eager per-begin disassembly cost 7+ min / 6+ GB and
		// hit the 5000 cap at 13% coverage; ~300-byte stubs cost tens of MB and register them all.
		//
		// The cap here is the high maxStubFunctions ceiling (not maxFunctions): stubs are cheap,
		// so all .pdata begins must register or the table is incomplete again. A begin already
		// discovered by the prologue scan / call graph (real instructions) is kept as-is.
		for (const r of ranges) {
			if (this.functions.size >= this.maxStubFunctions) {
				break;
			}
			if (this.functions.has(r.begin)) {
				continue; // already discovered by the prologue scan / call graph; keep it
			}
			this.functions.set(r.begin, {
				address: r.begin,
				name: `sub_${r.begin.toString(16).toUpperCase()}`,
				size: r.end - r.begin,
				endAddress: r.end,
				instructions: [],
				callers: [],
				callees: []
			});
			this.unmaterializedStubs.add(r.begin);
		}

		// (3) Reconcile each authoritative function's extent to its merged .pdata range:
		//   - clamp DOWN an over-long function (disassembly ran past the real end into a
		//     neighbour), and
		//   - v3.8.2 FIX-027b (#1): extend UP an under-discovered chained-unwind primary whose
		//     prologue-scan end fell SHORT of the merged .pdata end (the control-flow scan
		//     stopped at an interior `ret` before an out-of-line / cold block of the SAME
		//     function). Without the extend-up the function keeps its short end, that short end
		//     lands in knownFunctionEnds, and the PE64 lift re-truncates -- the exact bug
		//     FIX-027 targets, surviving for the pre-discovered-short sub-case.
		for (const r of ranges) {
			const fn = this.functions.get(r.begin);
			if (!fn) {
				continue;
			}
			if (fn.endAddress > r.end) {
				fn.instructions = fn.instructions.filter(inst => {
					const a = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
					return a < r.end;
				});
				const last = fn.instructions[fn.instructions.length - 1];
				if (last) {
					const la = typeof last.address === 'bigint' ? Number(last.address) : last.address;
					const ls = typeof last.size === 'bigint' ? Number(last.size) : last.size;
					fn.endAddress = Math.min(r.end, la + ls);
				} else {
					fn.endAddress = r.end;
				}
				fn.size = fn.endAddress - fn.address;
			} else if (fn.endAddress < r.end) {
				const shortEnd = fn.endAddress;
				try {
					// Recover the gap [shortEnd, r.end) non-recursively (like step 2) and append.
					const gapInsns = await this.disassembleRange(
						shortEnd, Math.min(r.end - shortEnd, this.maxFunctionSize));
					for (const inst of gapInsns) {
						const a = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
						if (a >= shortEnd && a < r.end) {
							fn.instructions.push(inst);
						}
					}
				} catch {
					// Cold bytes could not be linearly recovered; still advance the authoritative
					// end below so knownFunctionEnds carries the real .pdata boundary.
				}
				fn.endAddress = r.end;
				fn.size = fn.endAddress - fn.address;
			}
		}

		// (4) Sweep again: step (2)'s analyzeFunction recursion may have re-introduced ghost
		// children. Remove them now that all begins exist.
		sweepOverlaps();

		// (4) Rebuild callers/callees over the survivors. The sweep deleted ghost functions
		// whose addresses would otherwise dangle in other functions' callees, and whose own
		// call-sites would dangle in surviving functions' callers. Reconstruct the call-only
		// edges from the surviving instruction streams (matching analyzeFunction's wiring),
		// so the call graph stays consistent with the function table.
		for (const fn of this.functions.values()) {
			fn.callees = [];
			fn.callers = [];
		}
		for (const fn of this.functions.values()) {
			const seen = new Set<number>();
			for (const inst of fn.instructions) {
				if (!inst.isCall || inst.targetAddress === undefined) {
					continue;
				}
				const t = typeof inst.targetAddress === 'bigint' ? Number(inst.targetAddress) : inst.targetAddress;
				const target = this.functions.get(t);
				if (!target) {
					continue;
				}
				if (!seen.has(t)) {
					seen.add(t);
					fn.callees.push(t);
				}
				const callSite = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
				target.callers.push(callSite);
			}
		}
	}

	/**
	 * True when (start,end) strictly contains any authoritative .pdata begin from the
	 * ascending beginsArr (the function winds across a real function start, so it is a
	 * sweep ghost rather than a real function). Binary search for the first begin > start.
	 */
	private spansAnyBegin(start: number, end: number, beginsArr: number[]): boolean {
		let lo = 0;
		let hi = beginsArr.length - 1;
		let firstGreater = beginsArr.length;
		while (lo <= hi) {
			const mid = (lo + hi) >> 1;
			if (beginsArr[mid] > start) {
				firstGreater = mid;
				hi = mid - 1;
			} else {
				lo = mid + 1;
			}
		}
		return firstGreater < beginsArr.length && beginsArr[firstGreater] < end;
	}

	/**
	 * v3.8.3 Gap-K: add tail-call / trampoline edges to the call graph. An unconditional
	 * jmp/B whose target is ANOTHER function's entry is a real call-graph edge (tail call,
	 * thunk, trampoline), but analyzeFunction wired only `call` edges -- so e.g. an ELF/ARM64
	 * `entry: b main` left entry.callees and main.callers empty, disconnecting the graph at
	 * the root. Additive and deduped: existing edges are untouched; only missing
	 * jump-to-function-entry edges are added. Intra-function jumps (loops) are excluded
	 * because their targets are not function entries in the table.
	 */
	private addTailCallEdges(): void {
		for (const fn of this.functions.values()) {
			for (const inst of fn.instructions) {
				if (!inst.isJump || inst.isConditional || inst.targetAddress === undefined) {
					continue;
				}
				const t = typeof inst.targetAddress === 'bigint' ? Number(inst.targetAddress) : inst.targetAddress;
				if (t === fn.address) {
					continue;
				}
				const target = this.functions.get(t);
				if (!target) {
					continue;
				}
				if (!fn.callees.includes(t)) {
					fn.callees.push(t);
				}
				const site = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
				if (!target.callers.includes(site)) {
					target.callers.push(site);
				}
			}
		}
	}

	/**
	 * v3.8.3: relabel ELF PLT-stub functions with their resolved import name. The
	 * `.rela.plt`/`.dynsym`-derived `_pltSymbolMap` (PLT-stub VA -> symbol) was only used by
	 * detectPRNG; discovered PLT thunks stayed `sub_<addr>`. This names them `<symbol>@plt`
	 * (e.g. `puts@plt`) so calls through the PLT are readable. Only the auto-generated
	 * `sub_*` name is replaced, preserving any user / session rename. No-op for non-ELF.
	 *
	 * v3.8.5: IBT/CET fallback. On modern PIE ELF the linker emits BOTH a legacy `.plt`
	 * (keyed in _pltSymbolMap) AND an `endbr64`-guarded `.plt.sec` thunk that the code
	 * actually calls. Function discovery lands functions at the `.plt.sec` VA, which is NOT
	 * a _pltSymbolMap key, so the direct lookup misses and the stub stays `sub_*`. When the
	 * direct lookup misses, fall back to resolveStubSymbol() -- it decodes the thunk's
	 * `bnd jmp *GOT(%rip)` GOT reference and resolves it via _gotSymbolMap -- so the
	 * `.plt.sec` thunk is named `<symbol>@plt` too. Still ELF-gated (resolveStubSymbol is a
	 * no-op when the maps are empty / on non-x86) and still only replaces auto `sub_*` names.
	 */
	private applyPltStubNames(): void {
		if (this._pltSymbolMap.size === 0) {
			return;
		}
		for (const fn of this.functions.values()) {
			if (!/^sub_[0-9a-fA-F]+$/i.test(fn.name)) {
				continue;
			}
			const sym = this._pltSymbolMap.get(fn.address) ?? this.resolveStubSymbol(fn.address);
			if (sym) {
				fn.name = `${sym}@plt`;
			}
		}
	}

	/**
	 * v3.8.5: annotate PE indirect call/jmp sites that go through the Import Address Table (IAT)
	 * with the imported API name, so PE disassembly reads `call ReadFile` instead of the opaque
	 * `call dword ptr [0x402000]`. This is the PE analog of the ELF `<symbol>@plt` naming done by
	 * applyPltStubNames: the engine already RESOLVES the imports (parsePEImports records each
	 * import function's IAT-slot VA in ImportFunction.address) but never wired them onto the call
	 * sites, so a reverse engineer saw the raw IAT address.
	 *
	 * Mechanism: builds a Map<iatVA, "<dll>!<api>"> from getImports() (each import function's
	 * `.address` IS its IAT slot VA), then walks every instruction and, for each direct `call`/`jmp`
	 * through the IAT, stamps `instruction.comment` with the import name (same stamping mechanism
	 * the trap-handler skip used). Handles BOTH addressing forms:
	 *   - PE32: `call/jmp dword ptr [<abs32>]`     -> iatVA is the absolute operand.
	 *   - PE64: `call/jmp qword ptr [rip + <disp>]` -> iatVA = (addr of NEXT instruction) + disp.
	 *
	 * Gated PE-only (fileInfo.format starts with "PE"); ELF keeps the `@plt` path (no-op here, the
	 * IAT map is empty for ELF anyway). Only the indirect call/jmp through a KNOWN IAT slot is
	 * touched -- an indirect call/jmp to a non-IAT pointer (vtable, jump table, local function
	 * pointer) is left untouched -- and an existing comment is preserved (we only fill an empty
	 * one), so this never disturbs string-xref / PLT logic and only ADDS comments.
	 */
	private applyIatCallNames(): void {
		// PE only. ELF's import-through-PLT path is named by applyPltStubNames; for ELF getImports()
		// carries no IAT-slot addresses, so this would be a no-op regardless -- but gate explicitly.
		if (!this.fileInfo || !this.fileInfo.format.startsWith('PE')) {
			return;
		}

		// Build the IAT-slot -> "<dll>!<api>" map. ImportFunction.address is the absolute VA of the
		// FirstThunk slot the loader patches -- exactly what `call [iatVA]` references.
		const iatNames = new Map<number, string>();
		for (const lib of this.imports) {
			for (const fn of lib.functions) {
				if (fn.address > 0) {
					iatNames.set(fn.address >>> 0, `${lib.name}!${fn.name}`);
				}
			}
		}
		if (iatNames.size === 0) {
			return;
		}

		for (const func of this.functions.values()) {
			for (const ins of func.instructions) {
				const m = ins.mnemonic.toLowerCase();
				if (m !== 'call' && m !== 'jmp') {
					continue;
				}
				// Only memory-indirect operands carry an IAT reference: `... ptr [ ... ]`.
				const op = ins.opStr;
				if (!op || op.indexOf('[') < 0) {
					continue;
				}
				const iatVA = this.resolveIatOperandVA(ins);
				if (iatVA === undefined) {
					continue;
				}
				const name = iatNames.get(iatVA >>> 0);
				if (name && !ins.comment) {
					ins.comment = name;
				}
			}
		}
	}

	/**
	 * v3.8.5: resolve the absolute IAT-slot VA referenced by a memory-indirect `call`/`jmp`.
	 * Thin wrapper over the shared, pure `decodeIatOperandVA` (module-level) so the engine
	 * post-pass and the interactive `resolveInstructionComment` path share ONE decode and cannot
	 * drift. See `decodeIatOperandVA` for the PE32-absolute / PE64-rip-relative / register-reject
	 * semantics.
	 */
	private resolveIatOperandVA(ins: Instruction): number | undefined {
		const addr = typeof ins.address === 'number' ? ins.address : Number(ins.address);
		return decodeIatOperandVA(ins.opStr, addr, ins.size);
	}

	/**
	 * v3.8.3: drop mid-function prologue ghost functions on ELF without .pdata. The prologue
	 * scanner registers extra "functions" a few bytes into a real one (e.g. sub_159D@0x159d
	 * plus ghosts at 0x15a1/0x15b8, each disassembling to the same end). Like the PE64 overlap
	 * sweep, but without .pdata ground truth, so it is guarded:
	 *  - only when .pdata is absent (PE64 uses reconcileFunctionsWithPdata),
	 *  - NOT for ET_REL (.ko): its symtab st_value is section-relative, defeating symbol
	 *    cross-checks; skipping it keeps the mali tripwire byte-identical,
	 *  - only an interior function with ZERO callers is dropped. A real function never nests
	 *    inside another AND is reached by a call/tail-jump (callers populated by then), so the
	 *    "interior + no callers" pair is a ghost; a real function with callers is never touched.
	 */
	private dropInteriorGhostFunctions(): void {
		if (this.getPdataEntries().length > 0 || this.fileInfo?.isRelocatable) {
			return;
		}
		const sorted = Array.from(this.functions.values()).sort((a, b) => a.address - b.address);
		let maxEnd = Number.NEGATIVE_INFINITY;
		const dropped = new Set<number>();
		for (const fn of sorted) {
			if (fn.address < maxEnd && fn.callers.length === 0) {
				this.functions.delete(fn.address);
				dropped.add(fn.address);
				continue;
			}
			if (fn.endAddress > maxEnd) {
				maxEnd = fn.endAddress;
			}
		}
		// Scrub callee references to the removed ghosts so no call-graph edge dangles.
		if (dropped.size > 0) {
			for (const fn of this.functions.values()) {
				if (fn.callees.some(c => dropped.has(c))) {
					fn.callees = fn.callees.filter(c => !dropped.has(c));
				}
			}
		}
	}

	/**
	 * v3.8.3 Gap-A follow-on: drop interior ghost functions on PE binaries that have NO
	 * usable .pdata ground truth -- EVEN WHEN they carry (spurious) caller edges. This is the
	 * case `dropInteriorGhostFunctions` (zero-caller only) and `reconcileFunctionsWithPdata`
	 * (needs .pdata) both leave alone:
	 *   - 32-bit PE has no .pdata directory at all (RUNTIME_FUNCTION is x64-only), so the
	 *     prologue scan + unconditional-jump-following over-produce in-body labels as fake
	 *     sub_* with non-empty callers (e.g. debugme.exe: 284 interior ghosts), and
	 *   - some x64 PEs ship without a usable exception directory (e.g. maze.exe: .pdata absent,
	 *     1124 interior ghosts), so reconcile never runs.
	 *
	 * Ground truth is unavailable here, so the drop predicate is conservative and edge-based.
	 * Field measurement on both targets: EVERY interior ghost's entry is a real instruction
	 * boundary of its container (mid-instruction byte-pattern ghosts do not occur here), and
	 * every caller edge into the drop set originates either inside the container itself or
	 * inside another interior ghost -- i.e. they are intra-function CFG labels (unconditional
	 * `jmp` targets that analyzeFunction promoted to functions) plus over-extended containers
	 * that swallowed a genuinely-shared inner routine. The two are separated by ONE signal:
	 *
	 *   An interior function is KEPT iff some CALL targets it from a site that is BOTH
	 *   (a) outside its containing function's [start,end) range AND
	 *   (b) inside a function that is itself NOT interior (a top-level survivor).
	 *   Otherwise it is DROPPED.
	 *
	 * (a)+(b) is the signature of a genuinely-shared callee (a real function the container's
	 * decode merely ran past): it is reached by a `call` from elsewhere in the program, not by
	 * the container's own control flow. An in-body jump label has only intra-container jumps /
	 * calls-from-other-ghosts and is removed. This preserves the 6 (debugme) / 44 (maze) real
	 * shared inner routines while dropping 278 / 1080 ghosts, and -- verified on the targets --
	 * never drops a function reached by a CALL from a top-level survivor (zero such edges exist
	 * in the drop set). The entry point and exported functions are top-level and never interior.
	 *
	 * Strictly gated: PE only (format starts with "PE"), .pdata ABSENT (x64-PE-with-.pdata uses
	 * reconcileFunctionsWithPdata), and never ET_REL. ELF keeps its own dropInteriorGhost pass.
	 * After deletion the call graph is rebuilt over survivors (call + tail-jump edges, mirroring
	 * analyzeFunction/addTailCallEdges) so no edge dangles at a removed ghost (the Gap-A
	 * dangling-callees regression), then scrubDanglingCallees finishes the cleanup.
	 */
	private dropInteriorGhostFunctionsPE(): void {
		// PE only, .pdata absent, not relocatable. ELF / x64-PE-with-.pdata are handled elsewhere.
		if (!this.fileInfo || !this.fileInfo.format.startsWith('PE')) {
			return;
		}
		if (this.getPdataEntries().length > 0 || this.fileInfo.isRelocatable) {
			return;
		}

		const sorted = Array.from(this.functions.values()).sort((a, b) => a.address - b.address);
		if (sorted.length === 0) {
			return;
		}

		// Protected roots: the entry point and every export are reached by the OS loader or by
		// name, NOT by a `call` from another function, so they would fail the "genuine external
		// call" test and be wrongly dropped if discovery placed them just inside a spurious
		// container start (observed on maze.exe: EP 0x14000b680 nests in a prologue-scan false
		// start at 0x14000b659). Never drop a protected root regardless of interior status.
		const protectedRoots = new Set<number>();
		const ep = this.detectEntryPoint();
		if (ep !== undefined) {
			protectedRoots.add(typeof ep === 'bigint' ? Number(ep) : ep);
		}
		for (const exp of this.exports) {
			if (!exp.isForwarder && exp.address > 0) {
				protectedRoots.add(exp.address);
			}
		}

		// (1) Determine each function's nearest enclosing container (the function whose
		// [address,endAddress) strictly contains its start) and thus which functions are
		// interior. A single ascending sweep with a stack of open ranges yields the nearest
		// container in O(n log n)-ish time without an O(n^2) scan.
		const containerOf = new Map<number, Function>();
		const open: Function[] = []; // stack of enclosing functions, by increasing end
		for (const fn of sorted) {
			// Pop ranges that have ended at or before this start (no longer enclosing).
			while (open.length > 0 && open[open.length - 1].endAddress <= fn.address) {
				open.pop();
			}
			if (open.length > 0) {
				// The deepest still-open range strictly contains fn.address (start is inside it,
				// and start > that range's address since we are ascending). It is the container.
				const c = open[open.length - 1];
				if (fn.address > c.address && fn.address < c.endAddress) {
					containerOf.set(fn.address, c);
				}
			}
			open.push(fn);
		}
		const isInterior = (addr: number): boolean => containerOf.has(addr);

		// (2) Index every instruction address to its owning function so a caller site can be
		// classified (CALL vs jump) and attributed to a function (interior vs top-level).
		const ownerByInsn = new Map<number, { isCall: boolean; ownerAddr: number }>();
		for (const fn of sorted) {
			for (const inst of fn.instructions) {
				const a = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
				ownerByInsn.set(a, { isCall: inst.isCall, ownerAddr: fn.address });
			}
		}

		// (3) Decide the drop set. KEEP an interior function iff some CALL into it comes from a
		// site OUTSIDE its container AND inside a NON-interior (top-level) function.
		const dropped = new Set<number>();
		for (const fn of sorted) {
			const container = containerOf.get(fn.address);
			if (!container) {
				continue; // not interior -> never dropped here
			}
			if (protectedRoots.has(fn.address)) {
				continue; // entry point / export -> a real root, never a ghost
			}
			let hasGenuineExternalCall = false;
			for (const site of fn.callers) {
				const s = typeof site === 'bigint' ? Number(site) : site;
				const rec = ownerByInsn.get(s);
				if (!rec || !rec.isCall) {
					continue; // jump/branch edge, or unknown site -> not a genuine call signal
				}
				const siteInsideContainer = s >= container.address && s < container.endAddress;
				if (siteInsideContainer) {
					continue; // call from within the container -> intra-function, not external
				}
				if (isInterior(rec.ownerAddr)) {
					continue; // call from another interior ghost -> edge vanishes with that ghost
				}
				hasGenuineExternalCall = true;
				break;
			}
			if (!hasGenuineExternalCall) {
				dropped.add(fn.address);
			}
		}

		if (dropped.size === 0) {
			return;
		}

		// (4) Delete the drop set.
		for (const addr of dropped) {
			this.functions.delete(addr);
		}

		// (5) Rebuild callers/callees over the survivors so no edge dangles at a removed ghost
		// (the Gap-A dangling-callees regression: deleting functions without rebuilding left
		// stale edges and silently zeroed call graphs). Reconstruct call edges (matching
		// analyzeFunction) plus unconditional-jump-to-entry tail edges (matching
		// addTailCallEdges) from the surviving instruction streams only.
		for (const fn of this.functions.values()) {
			fn.callers = [];
			fn.callees = [];
		}
		for (const fn of this.functions.values()) {
			const seenCallees = new Set<number>();
			for (const inst of fn.instructions) {
				if (inst.targetAddress === undefined) {
					continue;
				}
				const t = typeof inst.targetAddress === 'bigint' ? Number(inst.targetAddress) : inst.targetAddress;
				const target = this.functions.get(t);
				if (!target) {
					continue;
				}
				const isCallEdge = inst.isCall;
				const isTailEdge = inst.isJump && !inst.isConditional && t !== fn.address;
				if (!isCallEdge && !isTailEdge) {
					continue;
				}
				if (!seenCallees.has(t)) {
					seenCallees.add(t);
					fn.callees.push(t);
				}
				const site = typeof inst.address === 'bigint' ? Number(inst.address) : inst.address;
				if (!target.callers.includes(site)) {
					target.callers.push(site);
				}
			}
		}
	}

	/**
	 * v3.8.3: remove call-graph edges that point at addresses which are not functions.
	 * analyzeFunction pushes a callee for any `call <code>` even when the target was never
	 * promoted to a function; those dangling edges break the call graph. Idempotent and safe
	 * (only non-function callee entries are removed); no-op once the table is consistent.
	 */
	private scrubDanglingCallees(): void {
		for (const fn of this.functions.values()) {
			if (fn.callees.some(c => !this.functions.has(c))) {
				fn.callees = fn.callees.filter(c => this.functions.has(c));
			}
		}
	}

	private async scanForFunctionPrologs(): Promise<void> {
		if (!this.fileBuffer) {
			return;
		}

		const isARM64 = this.architecture === 'arm64';
		const isARM32 = this.architecture === 'arm';

		for (const section of this.sections) {
			if (!section.isCode && !section.isExecutable) {
				continue;
			}

			const secOffset = section.rawAddress;
			const secEnd = secOffset + section.rawSize;

			if (isARM64) {
				// ARM64: Fixed-width 4-byte instructions, must be 4-byte aligned
				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off += 4) {
					if (off + 4 > this.fileBuffer.length) { break; }
					const word = this.fileBuffer.readUInt32LE(off);

					// Pattern 1: STP X29, X30, [SP, #imm] (any addressing mode)
					// Encoding: 10 101 0 0mm iiiiiii 11110 11111 11101
					// mm = addressing mode (01=signed-offset, 10=post-index, 11=pre-index)
					// Check: opc=10, fixed=101, V=0, L=0(store), Rt2=30, Rn=31(SP), Rt=29
					// Mask out: mode bits[25:23], imm7 bits[21:15]
					// Mask: 0xFC407FFF  Value: 0xA8007BFD
					if ((word & 0xFC407FFF) === 0xA8007BFD) {
						// STP x29, x30, [sp, #off] — classic ARM64 prolog
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 2: SUB SP, SP, #imm (frame setup without STP)
					// Encoding: 1101_0001_00ii_iiii_iiii_ii11_111x_xxxx
					// Check: bits[31]=1(64-bit), [30]=1(SUB), [29]=0, [28:24]=10001, Rn=SP(31), Rd=SP(31)
					if ((word & 0xFF0003FF) === 0xD10003FF && ((word >> 5) & 0x1F) === 31) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 3: PACIASP (pointer auth prolog, common in hardened ARM64)
					// Encoding: 0xD503233F
					if (word === 0xD503233F) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}
				}
			} else if (isARM32) {
				// ARM32: Fixed-width 4-byte instructions
				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off += 4) {
					if (off + 4 > this.fileBuffer.length) { break; }
					const word = this.fileBuffer.readUInt32LE(off);

					// Pattern 1: PUSH {fp, lr} or PUSH {r4-r11, lr} — STMDB SP!, {...}
					// ARM32 PUSH is STMDB SP! with cond=1110(always)
					// Encoding: 1110_1001_0010_1101_RRRR_RRRR_RRRR_RRRR
					// Mask: 0xFFFF0000 = 0xE92D, reglist includes LR(bit14)
					if ((word & 0xFFFF0000) === 0xE92D0000 && (word & (1 << 14)) !== 0) {
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}

					// Pattern 2: PUSH {r11, lr} — short form: 0xE52DE004 style or STR LR, [SP, #-4]!
					// Simpler check: MOV R11, SP (0xE1A0B00D) often follows PUSH
					if ((word & 0xFFFFF000) === 0xE52DE000) {
						// STR LR, [SP, #-imm]!
						const addr = this.sectionOffsetToAddress(off, section);
						if (addr > 0 && !this.functions.has(addr)) {
							await this.analyzeFunction(addr);
						}
						continue;
					}
				}
			} else {
				// x86/x64: Variable-length instructions

				// v3.7.4: Helper to measure multi-byte NOP size (FIX-015 ftrace preamble)
				const nopSize = (buf: Buffer, pos: number, end: number): number => {
					if (pos >= end) { return 0; }
					if (buf[pos] === 0x90) { return 1; } // single-byte NOP
					if (buf[pos] === 0x0F && pos + 1 < end && buf[pos + 1] === 0x1F) {
						// Multi-byte NOP: 0F 1F /0 (3-9 bytes depending on ModRM + displacement)
						if (pos + 2 < end && buf[pos + 2] === 0x00) { return 3; } // 0F 1F 00
						if (pos + 3 < end && buf[pos + 2] === 0x40 && buf[pos + 3] === 0x00) { return 4; } // 0F 1F 40 00
						if (pos + 4 < end && buf[pos + 2] === 0x44 && buf[pos + 3] === 0x00 && buf[pos + 4] === 0x00) { return 5; } // 0F 1F 44 00 00
						return 3; // default 3-byte NOP
					}
					if (buf[pos] === 0x66 && pos + 1 < end && buf[pos + 1] === 0x0F && pos + 2 < end && buf[pos + 2] === 0x1F) {
						// 66 0F 1F ... (4-9 byte NOP with operand size prefix)
						if (pos + 3 < end && buf[pos + 3] === 0x44) { return 5; } // 66 0F 1F 44 00
						if (pos + 3 < end && buf[pos + 3] === 0x84) { return 8; } // 66 0F 1F 84 00 00 00 00
						return 4;
					}
					return 0; // not a NOP
				};

				for (let off = secOffset; off < secEnd - 4 && this.functions.size < this.maxFunctions; off++) {
					const byte = this.fileBuffer[off];

					// v3.7.4: Detect ftrace __pfx_ NOP sled → skip to endbr64/real prologue (FIX-015)
					// Pattern: (NOP){8,32} [endbr64] [call __fentry__] push rbp
					if (byte === 0x0F && off + 1 < secEnd && this.fileBuffer[off + 1] === 0x1F) {
						// Potential multi-byte NOP sled start — measure total length
						let nopEnd = off;
						let nopBytes = 0;
						while (nopEnd < secEnd) {
							const ns = nopSize(this.fileBuffer, nopEnd, secEnd);
							if (ns === 0) { break; }
							nopEnd += ns;
							nopBytes += ns;
						}
						if (nopBytes >= 8 && nopEnd + 4 <= secEnd) {
							// Check for endbr64 (F3 0F 1E FA) at end of NOP sled
							if (this.fileBuffer[nopEnd] === 0xF3 && this.fileBuffer[nopEnd + 1] === 0x0F &&
								this.fileBuffer[nopEnd + 2] === 0x1E && this.fileBuffer[nopEnd + 3] === 0xFA) {
								// Register function at endbr64, not at __pfx_ NOP sled
								const addr = this.sectionOffsetToAddress(nopEnd, section);
								if (addr > 0 && !this.functions.has(addr)) {
									await this.analyzeFunction(addr);
								}
								off = nopEnd + 3; // skip past endbr64
								continue;
							}
							// No endbr64 — check for push rbp directly after sled
							if (this.fileBuffer[nopEnd] === 0x55) {
								const addr = this.sectionOffsetToAddress(nopEnd, section);
								if (addr > 0 && !this.functions.has(addr)) {
									await this.analyzeFunction(addr);
								}
								off = nopEnd;
								continue;
							}
						}
					}

					// v3.7.4: endbr64 (F3 0F 1E FA) as function start — CET-enabled binaries
					if (byte === 0xF3 && off + 3 < secEnd &&
						this.fileBuffer[off + 1] === 0x0F &&
						this.fileBuffer[off + 2] === 0x1E &&
						this.fileBuffer[off + 3] === 0xFA) {
						// endbr64 followed by push rbp or sub rsp
						if (off + 4 < secEnd && (this.fileBuffer[off + 4] === 0x55 || this.fileBuffer[off + 4] === 0x48)) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
							continue;
						}
					}

					// x64: push rbp (0x55) followed by mov rbp, rsp (0x48 0x89 0xE5)
					if (byte === 0x55 && off + 3 < secEnd) {
						if (this.fileBuffer[off + 1] === 0x48 &&
							this.fileBuffer[off + 2] === 0x89 &&
							this.fileBuffer[off + 3] === 0xE5) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
							continue;
						}
						// x86: push ebp (0x55) followed by mov ebp, esp (0x89 0xE5)
						if (this.fileBuffer[off + 1] === 0x89 &&
							this.fileBuffer[off + 2] === 0xE5) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
							continue;
						}
					}

					// x64: sub rsp, imm8 (0x48 0x83 0xEC imm8) - frameless function
					if (byte === 0x48 && off + 3 < secEnd) {
						if (this.fileBuffer[off + 1] === 0x83 &&
							this.fileBuffer[off + 2] === 0xEC) {
							const addr = this.sectionOffsetToAddress(off, section);
							if (addr > 0 && !this.functions.has(addr)) {
								await this.analyzeFunction(addr);
							}
						}
					}
				}
			}
		}
	}

	private sectionOffsetToAddress(fileOffset: number, section: Section): number {
		return section.virtualAddress + (fileOffset - section.rawAddress);
	}

	// ============================================================================
	// Getters
	// ============================================================================

	getFileInfo(): FileInfo | undefined {
		return this.fileInfo;
	}

	getSections(): Section[] {
		return this.sections;
	}

	getImports(): ImportLibrary[] {
		return this.imports;
	}

	getExports(): ExportFunction[] {
		return this.exports;
	}

	/** FIX-097: Get .rela.text DATA relocations (string/constant loads) for
	 *  ET_REL files. Returns Map<textOffset, {sectionName, type, addend}> where
	 *  addend is the in-section byte offset of the referenced datum. */
	getDataRelocations(): Map<number, { sectionName: string; type: number; addend: number }> {
		return this.dataRelocations;
	}

	/** FIX-097: Return the raw bytes of a named ELF section (e.g. `.rodata.str1.1`)
	 *  from the file image, or undefined if the section/file is unavailable.
	 *  Used by liftToIR to feed string-table bytes to the decompiler so a
	 *  relocated `mov rdi, .rodata+OFF` renders as the actual string literal. */
	getSectionBytesByName(name: string): Buffer | undefined {
		if (!this.fileBuffer) { return undefined; }
		const sec = this.elfSectionFileMap.get(name);
		if (!sec) { return undefined; }
		const start = sec.fileOffset;
		const end = start + sec.size;
		if (start < 0 || end > this.fileBuffer.length || sec.size <= 0) { return undefined; }
		return this.fileBuffer.subarray(start, end);
	}

	/** v3.7.4 FIX-011: Get .rela.text relocations for ET_REL files.
	 *  Returns Map<textOffset, {name, type, addend}> */
	getTextRelocations(): Map<number, { name: string; type: number; addend: number }> {
		return this.textRelocations;
	}

	/**
	 * v0.9.1 (G-001): resolve a function symbol by name and return its
	 * bytes + addressing context. Designed to close the ET_REL section
	 * collision where multiple code sections (`.text`, `.init.text`,
	 * `.text.unlikely`, `.exit.text`) all start at VA 0 and `address:
	 * "0x0"` is ambiguous — `liftToIR` now accepts `symbolName: "<sym>"`
	 * which calls this method and feeds the returned bytes directly to
	 * the lifter, bypassing the address-based function table that can
	 * only hold one entry per `address`.
	 *
	 * Returns `undefined` when:
	 * - the file is not ELF (only ELF symbol tables are walked here);
	 * - the symbol is not present in `.symtab` as a defined STT_FUNC;
	 * - the resolved file offset would read past the buffer end;
	 * - `st_size` is zero (unsized symbol — caller can use `count` instead).
	 */
	findFunctionSymbolByName(name: string): {
		bytes: Buffer;
		address: number;
		section: string;
		size: number;
	} | undefined {
		if (!this.fileBuffer) return undefined;
		const sym = this.elfFunctionByName.get(name);
		if (!sym) return undefined;
		const sec = this.elfSectionFileMap.get(sym.sectionName);
		if (!sec) return undefined;
		const fileOff = sec.fileOffset + sym.offsetInSection;
		const sz = sym.size;
		if (sz <= 0) return undefined;
		if (fileOff < 0 || fileOff + sz > this.fileBuffer.length) {
			return undefined;
		}
		return {
			bytes: this.fileBuffer.subarray(fileOff, fileOff + sz),
			// For ET_REL, the address Remill stamps into the lifted IR
			// is the symbol's section-relative offset (`st_value`). This
			// keeps the lifted `@lifted_<addr>` consistent with the
			// existing ET_REL convention (every section starts at 0).
			address: sym.offsetInSection,
			section: sym.sectionName,
			size: sz,
		};
	}

	/** v0.9.1 (G-001): list every ELF function symbol the engine indexed,
	 * along with its section. Useful for UI / diagnostics — e.g. when a
	 * user passes `address: "0x0"` on an ET_REL with collisions, the
	 * `liftToIR` handler emits this list as a hint of which `symbolName:`
	 * values disambiguate the request. */
	getElfFunctionSymbols(): Array<{ name: string; section: string; size: number; offsetInSection: number }> {
		const out: Array<{ name: string; section: string; size: number; offsetInSection: number }> = [];
		for (const [name, sym] of this.elfFunctionByName) {
			out.push({
				name,
				section: sym.sectionName,
				size: sym.size,
				offsetInSection: sym.offsetInSection,
			});
		}
		return out.sort((a, b) =>
			a.section === b.section
				? a.offsetInSection - b.offsetInSection
				: a.section.localeCompare(b.section)
		);
	}

	getFileName(): string {
		return this.currentFile ? path.basename(this.currentFile) : 'Unknown';
	}

	getFilePath(): string | undefined {
		return this.currentFile;
	}

	async findCrossReferences(address: number): Promise<XRef[]> {
		return this.xrefs.get(address) ?? [];
	}

	async searchStringReferences(query: string): Promise<StringReference[]> {
		const results: StringReference[] = [];
		const lowerQuery = query.toLowerCase();

		for (const strRef of this.strings.values()) {
			if (strRef.string.toLowerCase().includes(lowerQuery)) {
				results.push(strRef);
			}
		}

		// On-demand byte-pattern scan for strings with empty references
		const unresolvedAddrs = new Set<number>();
		for (const strRef of results) {
			if (strRef.references.length === 0) {
				unresolvedAddrs.add(strRef.address);
			}
		}

		if (unresolvedAddrs.size > 0) {
			const scanResults = this.scanTextSectionForStringRefs(unresolvedAddrs);
			for (const [strAddr, instrAddrs] of scanResults) {
				const strRef = this.strings.get(strAddr);
				if (strRef) {
					for (const instrAddr of instrAddrs) {
						if (!strRef.references.includes(instrAddr)) {
							strRef.references.push(instrAddr);
						}
						this.addXRef({ from: instrAddr, to: strAddr, type: 'string' });
					}
				}
			}
		}

		return results;
	}



	async exportAssembly(filePath: string): Promise<void> {
		const lines: string[] = [];
		lines.push(`; Disassembly of ${path.basename(this.currentFile || 'unknown')}`);
		lines.push(`; Generated by HexCore Disassembler (Capstone Engine)`);
		lines.push(`; Architecture: ${this.architecture}`);
		lines.push('');
		lines.push(this.architecture.includes('64') ? 'BITS 64' : 'BITS 32');
		lines.push(`ORG 0x${this.baseAddress.toString(16).toUpperCase()}`);
		lines.push('');

		for (const func of this.functions.values()) {
			lines.push(`; ============================================`);
			lines.push(`; Function: ${func.name}`);
			lines.push(`; Address: 0x${func.address.toString(16).toUpperCase()}`);
			lines.push(`; Size: ${func.size} bytes`);
			lines.push(`; ============================================`);
			lines.push(`${func.name}:`);

			for (const inst of func.instructions) {
				const addrStr = inst.address.toString(16).toUpperCase().padStart(16, '0');
				const bytesStr = Array.from(inst.bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
				const comment = inst.comment ? ` ; ${inst.comment}` : '';
				lines.push(`    ${inst.mnemonic.toLowerCase().padEnd(10)} ${inst.opStr.padEnd(30)} ; 0x${addrStr} | ${bytesStr}${comment}`);
			}
			lines.push('');
		}

		fs.writeFileSync(filePath, lines.join('\n'));
	}

	addComment(address: number, comment: string): void {
		this.comments.set(address, comment);
		const inst = this.instructions.get(address);
		if (inst) {
			inst.comment = comment;
		}
	}

	renameFunction(address: number, name: string): void {
		const func = this.functions.get(address);
		if (func) {
			func.name = name;
		}
		// v3.7.4: Persist to session store
		this.sessionStore?.renameFunction(`0x${address.toString(16)}`, name);
	}

	getFunctionName(address: number): string | undefined {
		// v3.7.4: Check session store first for user-defined names
		const sessionName = this.sessionStore?.getFunction(`0x${address.toString(16)}`)?.name;
		if (sessionName) {
			return sessionName;
		}
		return this.functions.get(address)?.name;
	}

	// v3.7.4: Session-backed rename/retype for variables, fields, comments, bookmarks

	renameVariable(funcAddress: number, originalName: string, newName: string): void {
		this.sessionStore?.renameVariable(`0x${funcAddress.toString(16)}`, originalName, newName);
	}

	retypeVariable(funcAddress: number, originalName: string, newType: string): void {
		this.sessionStore?.retypeVariable(`0x${funcAddress.toString(16)}`, originalName, newType);
	}

	retypeFunction(address: number, returnType: string): void {
		this.sessionStore?.retypeFunction(`0x${address.toString(16)}`, returnType);
	}

	setSessionComment(address: number, comment: string): void {
		this.comments.set(address, comment);
		this.sessionStore?.setComment(`0x${address.toString(16)}`, comment);
	}

	setBookmark(address: number, label: string): void {
		this.sessionStore?.setBookmark(`0x${address.toString(16)}`, label);
	}

	removeBookmark(address: number): void {
		this.sessionStore?.removeBookmark(`0x${address.toString(16)}`);
	}

	getAllBookmarks(): Array<{ address: string; label: string; updated_at: string }> {
		return this.sessionStore?.getAllBookmarks() ?? [];
	}

	getSessionStore(): SessionStore | undefined {
		return this.sessionStore;
	}

	getFunctions(): Function[] {
		return Array.from(this.functions.values()).sort((a, b) => a.address - b.address);
	}

	getStrings(): StringReference[] {
		return Array.from(this.strings.values()).sort((a, b) => a.address - b.address);
	}

	getComments(): Map<number, string> {
		return this.comments;
	}

	getStringsMap(): Map<number, StringReference> {
		return this.strings;
	}

	getFunctionsMap(): Map<number, Function> {
		return this.functions;
	}


	getFunctionAt(address: number): Function | undefined {
		return this.functions.get(address);
	}

	/**
	 * A-lazy view accessor: return a function's instruction listing, materializing it on demand if
	 * it is still an unmaterialized .pdata stub. Use this at VIEW / render / single-function-export
	 * call sites that need to DISPLAY a function's body. Do NOT use it on the lift/decompile path
	 * (that reads bytes via getBytes + endAddress, not instructions) or on whole-table analysis
	 * passes (materializing every function would re-introduce the eager cost lazy discovery removes).
	 * Returns [] when the address is not a known function.
	 */
	async getFunctionInstructions(address: number): Promise<Instruction[]> {
		const fn = await this.materializeFunction(address);
		return fn ? fn.instructions : [];
	}

	/**
	 * Find the start of the function containing the given address.
	 * First checks already-discovered functions, then falls back to
	 * native prologue scanning if available (FEAT-CAP-010 / FEAT-DISASM-004).
	 */
	async findFunctionStartForAddress(address: number, forceProbe = false): Promise<number | undefined> {
		// 1. Check if address is already a known function start (skip when forceProbe)
		if (!forceProbe && this.functions.has(address)) {
			return address;
		}

		// 2. Check if address falls within a known function's range (ALWAYS, even forceProbe)
		for (const [, func] of this.functions) {
			if (address > func.address && address < func.endAddress) {
				return func.address;
			}
		}

		// 3. Try native function boundary detection via Capstone
		if (this.capstone && this.capstoneInitialized && this.fileBuffer) {
			try {
				// Scan a region around the target address (up to 64KB before, 4KB after)
				const scanBefore = 0x10000; // 64KB before
				const scanAfter = 0x1000;   // 4KB after
				const scanStart = Math.max(this.baseAddress, address - scanBefore);
				const scanEnd = Math.min(
					this.baseAddress + this.fileBuffer.length,
					address + scanAfter
				);
				const offset = this.addressToOffset(scanStart);
				const endOffset = this.addressToOffset(scanEnd);
				if (offset >= 0 && endOffset > offset) {
					const scanBuffer = this.fileBuffer.subarray(offset, endOffset);
					const functionStart = await this.capstone.findFunctionStart(
						scanBuffer, address, scanStart
					);
					const result = Number(functionStart);
					if (result !== address && result >= scanStart && result <= address) {
						return result;
					}
				}
			} catch {
				// Native detection not available or failed — fall through
			}
		}

		// 4. v3.7.4: Capstone backward disassembly — try disassembling from addr-N
		//    to find which instruction sequence lands exactly on target address.
		//    This works for dense code (D lang, optimized) without CC/90 padding.
		if (this.capstone && this.capstoneInitialized && this.fileBuffer) {
			for (let delta = 1; delta <= 16; delta++) {
				const tryAddr = address - delta;
				const tryOffset = this.addressToOffset(tryAddr);
				if (tryOffset < 0) { continue; }
				const windowEnd = Math.min(tryOffset + delta + 64, this.fileBuffer.length);
				const window = this.fileBuffer.subarray(tryOffset, windowEnd);
				try {
					const insns = await this.capstone.disassemble(window, tryAddr, 32);
					if (insns.length < 3) { continue; } // need >= 3 valid instructions

					// Check if any instruction boundary lands on target
					let validChain = 0;
					for (const insn of insns) {
						validChain++;
						const endAddr = insn.address + insn.size;
						if (endAddr === address && validChain >= 3) {
							// Found valid instruction chain ending at target.
							// Now scan backwards from tryAddr for a prologue to find the real function start.
							const scanBack = Math.min(tryAddr - this.baseAddress, 0x2000);
							const probeStart = tryAddr - scanBack;
							const probeOffset = this.addressToOffset(probeStart);
							if (probeOffset >= 0) {
								// Look for nearest ret+prologue or padding+prologue before tryAddr
								for (let scan = this.addressToOffset(tryAddr) - 1; scan >= probeOffset; scan--) {
									const sb = this.fileBuffer![scan];
									if (sb === 0xC3 || sb === 0xCC) {
										let funcOff = scan + 1;
										while (funcOff < this.addressToOffset(tryAddr) && (this.fileBuffer![funcOff] === 0xCC || this.fileBuffer![funcOff] === 0x90)) {
											funcOff++;
										}
										const fb = this.fileBuffer![funcOff];
										if (fb === 0x55 || fb === 0x53 || fb === 0x48 || fb === 0x4C ||
											fb === 0x56 || fb === 0x57 || fb === 0x40 || fb === 0x41 ||
											fb === 0xF3) { // F3 = endbr64 prefix
											return this.offsetToAddress(funcOff);
										}
										break;
									}
								}
							}
							// If no prologue found, the tryAddr itself might be close to function start
							return tryAddr;
						}
						if (endAddr > address) { break; } // overshot
					}
				} catch {
					// Disassembly failed at this offset — try next
				}
			}
		}

		// 5. Byte-level boundary scanner: look for function boundaries
		//    scanning backwards from the target address.
		//    Detects: INT3 padding (CC), NOP padding (90), ret+prologue (C3+XX)
		if (this.fileBuffer) {
			const maxScan = 0x10000; // 64KB back
			const targetOffset = this.addressToOffset(address);

			const isPrologue = (b: number) =>
				b === 0x48 || b === 0x4C || // REX.W / REX.WR
				b === 0x40 || b === 0x41 || // REX / REX.B
				b === 0x55 || b === 0x53 || // push rbp / push rbx
				b === 0x56 || b === 0x57 || // push rsi / push rdi
				b === 0x44 || b === 0x45 || // REX.R / REX.RB
				b === 0x50 || b === 0x51 || // push rax / push rcx
				b === 0x52;                 // push rdx

			// v3.7.4: Extended multi-byte prologue recognition
			const isExtendedPrologue = (off: number): boolean => {
				if (off + 5 > this.fileBuffer!.length) { return false; }
				const buf = this.fileBuffer!;
				// mov [rsp+8], rcx (fastcall save): 48 89 4C 24 08
				if (buf[off] === 0x48 && buf[off + 1] === 0x89 && buf[off + 2] === 0x4C &&
					buf[off + 3] === 0x24 && buf[off + 4] === 0x08) { return true; }
				// endbr64: F3 0F 1E FA
				if (off + 4 <= this.fileBuffer!.length &&
					buf[off] === 0xF3 && buf[off + 1] === 0x0F && buf[off + 2] === 0x1E &&
					buf[off + 3] === 0xFA) { return true; }
				// mov [rsp+10h], rdx (fastcall save 2nd arg): 48 89 54 24 10
				if (buf[off] === 0x48 && buf[off + 1] === 0x89 && buf[off + 2] === 0x54 &&
					buf[off + 3] === 0x24 && buf[off + 4] === 0x10) { return true; }
				return false;
			};

			const isPadding = (b: number) => b === 0xCC || b === 0x90;

			if (targetOffset >= 2) {
				const scanEnd = Math.max(0, targetOffset - maxScan);
				for (let off = targetOffset - 1; off > scanEnd; off--) {
					const b = this.fileBuffer[off];

					// Pattern 1: 2+ padding bytes (CC or 90)
					if (isPadding(b) && off > 0 && isPadding(this.fileBuffer[off - 1])) {
						let funcOff = off + 1;
						while (funcOff < targetOffset && isPadding(this.fileBuffer[funcOff])) {
							funcOff++;
						}
						if (funcOff >= targetOffset) { break; } // target is IN padding
						if (isPrologue(this.fileBuffer[funcOff]) || isExtendedPrologue(funcOff)) {
							const funcAddr = this.offsetToAddress(funcOff);
							if (funcAddr < address) { return funcAddr; }
						}
						break; // only check nearest padding boundary
					}

					// Pattern 2: ret (C3) followed by prologue or padding+prologue
					if (b === 0xC3 && off + 1 < targetOffset) {
						let funcOff = off + 1;
						// Skip optional padding after ret
						while (funcOff < targetOffset && isPadding(this.fileBuffer[funcOff])) {
							funcOff++;
						}
						if (funcOff >= targetOffset) { continue; }
						if (isPrologue(this.fileBuffer[funcOff]) || isExtendedPrologue(funcOff)) {
							const funcAddr = this.offsetToAddress(funcOff);
							if (funcAddr < address) { return funcAddr; }
						}
					}
				}
			}
		}

		return undefined;
	}

	/**
	 * v3.7.4: IMP-001 — Verify that an address falls on an instruction boundary.
	 * Disassembles backwards from a known good region and checks if any instruction
	 * boundary matches the target address exactly.
	 * @returns aligned=true if on boundary, or suggestedAddress pointing to the nearest valid boundary.
	 */
	async verifyInstructionAlignment(targetAddress: number, lookbackBytes: number = 64): Promise<{
		aligned: boolean;
		suggestedAddress?: number;
	}> {
		if (!this.capstone || !this.capstoneInitialized || !this.fileBuffer) {
			return { aligned: true }; // can't verify, assume OK
		}

		const startAddr = Math.max(this.baseAddress, targetAddress - lookbackBytes);
		const offset = this.addressToOffset(startAddr);
		const endOffset = this.addressToOffset(targetAddress + 16);
		if (offset < 0 || endOffset < 0 || endOffset <= offset) {
			return { aligned: true };
		}

		try {
			const buf = this.fileBuffer.subarray(offset, endOffset);
			const insns = await this.capstone.disassemble(buf, startAddr, 1000);

			for (const insn of insns) {
				if (insn.address === targetAddress) {
					return { aligned: true };
				}
				if (insn.address > targetAddress) {
					// Previous instruction spans over target — mid-instruction
					return { aligned: false, suggestedAddress: insn.address };
				}
			}
		} catch {
			// Disassembly failed — assume aligned
		}

		return { aligned: true };
	}

	getArchitecture(): ArchitectureConfig {
		return this.architecture;
	}

	/**
	 * Returns per-function VM detection results from the last `analyzeAll({ detectVM: true })` call.
	 * Returns undefined if VM detection was not run.
	 */
	getVmDetectionResults(): Map<number, { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number }> | undefined {
		return this._vmDetectionResults;
	}

	getBaseAddress(): number {
		return this.baseAddress;
	}

	/**
	 * Returns true when a file has been loaded into the engine.
	 */
	isFileLoaded(): boolean {
		return this.fileBuffer !== undefined && this.fileBuffer.length > 0;
	}

	/**
	 * Returns the size of the loaded file buffer in bytes, or 0 if no file is loaded.
	 */
	getBufferSize(): number {
		return this.fileBuffer?.length ?? 0;
	}

	/**
	 * Extract raw bytes from the loaded file at the given virtual address.
	 * Returns undefined if no file is loaded or the address is out of bounds.
	 */
	/** v3.7.5 FIX-022c: Expose Capstone for backtrack validation in liftToIR */
	getCapstone(): CapstoneWrapper | undefined {
		return this.capstoneInitialized ? this.capstone : undefined;
	}

	getBytes(address: number, size: number): Buffer | undefined {
		if (!this.fileBuffer) {
			return undefined;
		}
		const offset = this.addressToOffset(address);
		if (offset < 0 || offset >= this.fileBuffer.length) {
			return undefined;
		}
		const end = Math.min(offset + size, this.fileBuffer.length);
		return this.fileBuffer.subarray(offset, end);
	}

	private addressToOffset(address: number): number {
		const rva = address - this.baseAddress;

		if (this.isPEFile() && this.fileBuffer) {
			return this.rvaToFileOffset(rva);
		}

		// For ELF, use section mapping
		// v3.7.5 FIX-018: For ET_REL files, multiple sections have virtualAddress=0
		// (e.g. __bug_table, .text, .rodata all start at VA 0). The first match wins,
		// but __bug_table often comes before .text in the section list. Prioritize
		// executable (.text) sections to avoid reading from data/debug sections.
		if (this.isELFFile()) {
			// Pass 1: prefer code/executable sections
			for (const section of this.sections) {
				if (address >= section.virtualAddress &&
					address < section.virtualAddress + section.virtualSize &&
					(section.isCode || section.isExecutable)) {
					return section.rawAddress + (address - section.virtualAddress);
				}
			}
			// Pass 2: any matching section (fallback for data addresses)
			for (const section of this.sections) {
				if (address >= section.virtualAddress &&
					address < section.virtualAddress + section.virtualSize) {
					return section.rawAddress + (address - section.virtualAddress);
				}
			}
		}

		return rva;
	}

	private offsetToAddress(offset: number): number {
		// For PE/ELF, try section-based mapping
		for (const section of this.sections) {
			if (offset >= section.rawAddress && offset < section.rawAddress + section.rawSize) {
				return section.virtualAddress + (offset - section.rawAddress);
			}
		}
		return offset + this.baseAddress;
	}

	private detectBaseAddress(): number {
		if (this.fileInfo) {
			return this.fileInfo.baseAddress;
		}
		if (this.isPEFile()) {
			return 0x400000;
		}
		return 0x400000;
	}

	private detectEntryPoint(): number | undefined {
		if (this.fileInfo) {
			return this.fileInfo.entryPoint;
		}

		if (this.isELFFile() && this.fileBuffer) {
			const is64Bit = this.fileBuffer[4] === 2;
			const isLE = this.fileBuffer[5] === 1;
			if (is64Bit) {
				return Number(isLE ? this.fileBuffer.readBigUInt64LE(24) : this.fileBuffer.readBigUInt64BE(24));
			} else {
				return isLE ? this.fileBuffer.readUInt32LE(24) : this.fileBuffer.readUInt32BE(24);
			}
		}

		return this.baseAddress;
	}

	// ============================================================================
	// Assembly & Patching (LLVM MC)
	// ============================================================================

	private async ensureLlvmMcInitialized(): Promise<void> {
		if (!this.llvmMcInitialized) {
			try {
				await this.llvmMc.initialize(this.architecture);
				this.llvmMcInitialized = true;
				this.llvmMcError = undefined;
				console.log(`LLVM MC initialized for ${this.architecture}`);
			} catch (error) {
				const message = error instanceof Error ? error.message : String(error);
				this.llvmMcInitialized = false;
				this.llvmMcError = message;
				console.warn('LLVM MC initialization failed:', error);
			}
		} else if (this.llvmMc.getArchitecture() !== this.architecture) {
			await this.llvmMc.setArchitecture(this.architecture);
		}
	}

	async getDisassemblerAvailability(): Promise<{ available: boolean; error?: string; fallbackMode?: 'basic-decoder' | 'raw-byte' }> {
		await this.ensureCapstoneInitialized();
		return {
			available: this.capstoneInitialized,
			error: this.capstoneError ?? this.capstone.getLastError(),
			fallbackMode: this.capstoneInitialized
				? undefined
				: ((this.architecture === 'x86' || this.architecture === 'x64' || this.architecture === 'arm' || this.architecture === 'arm64')
					? 'basic-decoder'
					: 'raw-byte')
		};
	}

	async getAssemblerAvailability(): Promise<{ available: boolean; error?: string; cpu?: string; features?: string; addressSemanticsNote?: string }> {
		await this.ensureLlvmMcInitialized();
		return {
			available: this.llvmMcInitialized,
			error: this.llvmMcError ?? this.llvmMc.getLastError(),
			cpu: this.llvmMc.getCpu(),
			features: this.llvmMc.getFeatures(),
			addressSemanticsNote: this.llvmMc.getAddressSemanticsNote()
		};
	}

	async assemble(code: string, address?: number): Promise<AssembleResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { success: false, bytes: Buffer.alloc(0), size: 0, statement: code, error: this.llvmMcError ?? 'LLVM MC not available' };
		}
		return this.llvmMc.assembleAsync(code, address !== undefined ? BigInt(address) : undefined);
	}

	async assembleMultiple(instructions: string[], startAddress?: number): Promise<AssembleResult[]> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return instructions.map(code => ({
				success: false, bytes: Buffer.alloc(0), size: 0, statement: code,
				error: this.llvmMcError ?? 'LLVM MC not available'
			}));
		}
		return this.llvmMc.assembleMultiple(instructions, startAddress !== undefined ? BigInt(startAddress) : undefined);
	}

	async patchInstruction(address: number, newInstruction: string): Promise<PatchResult> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { success: false, bytes: Buffer.alloc(0), size: 0, originalSize: 0, nopPadding: 0, error: this.llvmMcError ?? 'LLVM MC not available' };
		}

		let original = this.instructions.get(address);
		if (!original) {
			const disasm = await this.disassembleRange(address, 16);
			if (disasm.length === 0) {
				return { success: false, bytes: Buffer.alloc(0), size: 0, originalSize: 0, nopPadding: 0, error: 'Could not find instruction at address' };
			}
			original = disasm[0];
			this.instructions.set(original.address, original);
		}

		return this.llvmMc.createPatch(newInstruction, original.size, BigInt(address));
	}

	applyPatch(address: number, patchBytes: Buffer): boolean {
		if (!this.fileBuffer) {
			return false;
		}

		const offset = this.addressToOffset(address);
		if (offset < 0 || offset + patchBytes.length > this.fileBuffer.length) {
			return false;
		}

		patchBytes.copy(this.fileBuffer, offset);

		for (let i = 0; i < patchBytes.length; i++) {
			this.instructions.delete(address + i);
		}

		return true;
	}

	async nopInstruction(address: number): Promise<boolean> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return false;
		}

		const original = this.instructions.get(address);
		if (!original) {
			return false;
		}

		const nopSled = this.llvmMc.createNopSled(original.size);
		return this.applyPatch(address, nopSled);
	}

	savePatched(outputPath: string): void {
		if (!this.fileBuffer) {
			throw new Error('No file loaded');
		}
		fs.writeFileSync(outputPath, this.fileBuffer);
	}

	async validateInstruction(code: string): Promise<{ valid: boolean; error?: string }> {
		await this.ensureLlvmMcInitialized();
		if (!this.llvmMcInitialized) {
			return { valid: false, error: this.llvmMcError ?? 'LLVM MC not available' };
		}
		return this.llvmMc.validate(code);
	}

	getNop(): Buffer {
		if (!this.llvmMcInitialized) {
			switch (this.architecture) {
				case 'x86':
				case 'x64':
					return Buffer.from([0x90]);
				case 'arm':
					return Buffer.from([0x00, 0x00, 0xA0, 0xE1]);
				case 'arm64':
					return Buffer.from([0x1F, 0x20, 0x03, 0xD5]);
				default:
					return Buffer.from([0x90]);
			}
		}
		return this.llvmMc.getNop();
	}

	getLlvmVersion(): string {
		if (!this.llvmMcInitialized) {
			return 'not initialized';
		}
		return this.llvmMc.getVersion();
	}

	setAssemblySyntax(syntax: 'intel' | 'att'): void {
		this.llvmMc.setSyntax(syntax);
	}

	async setAssemblerTargetOptions(options: { cpu?: string; features?: string }): Promise<void> {
		await this.llvmMc.setTargetOptions(options);
		if (this.llvmMcInitialized) {
			this.llvmMcError = this.llvmMc.getLastError();
		}
	}

	getAssemblerTargetOptions(): { cpu: string; features: string } {
		return {
			cpu: this.llvmMc.getCpu(),
			features: this.llvmMc.getFeatures()
		};
	}

	// ============ v3.7: Junk Instruction Filtering ============

	/**
	 * Filter junk/obfuscation instructions from an instruction array.
	 * Detects and removes common obfuscation patterns:
	 *  - call next; pop reg (callfuscation)
	 *  - add/sub reg, 0 (no-op arithmetic)
	 *  - nop / nop dword [...]
	 *  - push reg; pop reg (same register, identity)
	 *  - xchg reg, reg (same register)
	 *  - mov reg, reg (same register)
	 *  - lea reg, [reg+0] / lea reg, [reg] (identity LEA)
	 */
	filterJunkInstructions(instructions: Instruction[]): { filtered: Instruction[]; junkCount: number; junkRatio: number } {
		const filtered: Instruction[] = [];
		let junkCount = 0;
		const len = instructions.length;

		for (let i = 0; i < len; i++) {
			const curr = instructions[i];
			const next = i + 1 < len ? instructions[i + 1] : null;
			const mn = curr.mnemonic.toLowerCase();
			const op = curr.opStr.toLowerCase().replace(/\s+/g, '');

			// Pattern 1: call next_addr; pop reg (callfuscation)
			if (mn === 'call' && next) {
				const nextMn = next.mnemonic.toLowerCase();
				if (nextMn === 'pop' && curr.targetAddress === next.address) {
					junkCount += 2;
					i++; // skip both
					continue;
				}
			}

			// Pattern 2: add/sub reg, 0
			if ((mn === 'add' || mn === 'sub') && (op.endsWith(',0') || op.endsWith(',0x0'))) {
				junkCount++;
				continue;
			}

			// Pattern 3: nop (any variant)
			if (mn === 'nop') {
				junkCount++;
				continue;
			}

			// Pattern 4: push reg; pop reg (same register)
			if (mn === 'push' && next && next.mnemonic.toLowerCase() === 'pop') {
				const pushReg = op.trim();
				const popReg = next.opStr.toLowerCase().replace(/\s+/g, '').trim();
				if (pushReg === popReg) {
					junkCount += 2;
					i++; // skip both
					continue;
				}
			}

			// Pattern 5: xchg reg, reg (same register)
			if (mn === 'xchg') {
				const parts = op.split(',');
				if (parts.length === 2 && parts[0].trim() === parts[1].trim()) {
					junkCount++;
					continue;
				}
			}

			// Pattern 6: mov reg, reg (same register)
			if (mn === 'mov') {
				const parts = op.split(',');
				if (parts.length === 2 && parts[0].trim() === parts[1].trim()) {
					junkCount++;
					continue;
				}
			}

			// Pattern 7: lea reg, [reg+0] or lea reg, [reg]
			if (mn === 'lea') {
				const parts = op.split(',');
				if (parts.length === 2) {
					const dst = parts[0].trim();
					const src = parts[1].trim();
					// Match [reg], [reg+0], [reg+0x0]
					const leaMatch = src.match(/^\[(\w+)(?:\+0(?:x0)?)?\]$/);
					if (leaMatch && leaMatch[1] === dst) {
						junkCount++;
						continue;
					}
				}
			}

			filtered.push(curr);
		}

		return {
			filtered,
			junkCount,
			junkRatio: len > 0 ? junkCount / len : 0
		};
	}

	// ============ v3.8.2: obfuscation-resistant linear instruction sweep ============

	/**
	 * Linearly disassemble EVERY executable section into a flat instruction stream,
	 * independent of function discovery. Cached in `_execScan`. This is the detection
	 * source for detectVM/detectPRNG on obfuscated binaries where prologue-based
	 * discovery finds almost nothing. x86/x64 only (the detection heuristics that
	 * consume it are x86-specific; other arches just get an empty scan).
	 *
	 * A pure linear sweep over packed x86 will desync at embedded data, but VM
	 * dispatchers / srand call sites are dense real code, so a single forward sweep
	 * recovers them reliably enough for a boolean "is this a VM? / does it seed a
	 * PRNG?" signal. Bounded to keep cost predictable on huge binaries.
	 */
	private async buildExecScan(): Promise<Instruction[]> {
		if (this._execScan) { return this._execScan; }
		const out: Instruction[] = [];
		if (!this.fileBuffer) { this._execScan = out; return out; }
		if (this.architecture !== 'x64' && this.architecture !== 'x86') {
			this._execScan = out; return out;
		}

		// Cap total decoded bytes so a pathological binary can't stall analyzeAll.
		const MAX_SCAN_BYTES = 4 * 1024 * 1024; // 4 MiB of code
		const buf = this.fileBuffer;
		const byAddr = new Map<number, Instruction>();
		let scanned = 0;
		const execSections = this.sections.filter(s => s.isCode || (s as { isExecutable?: boolean }).isExecutable);

		// Pass 1: forward linear sweep of each executable section.
		for (const section of execSections) {
			const rawStart = (section as { rawAddress?: number }).rawAddress ?? -1;
			if (rawStart < 0) { continue; }
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
			const sectionBytes = rawEnd - rawStart;
			if (sectionBytes <= 0) { continue; }
			const startVA = this.sectionOffsetToAddress(rawStart, section);
			const budget = Math.min(sectionBytes, MAX_SCAN_BYTES - scanned);
			if (budget <= 0) { break; }
			try {
				const instrs = await this.disassembleRange(startVA, budget);
				for (const inst of instrs) { byAddr.set(inst.address, inst); }
			} catch {
				// Section decode failed (Capstone hiccup) — skip; per-function path
				// still works as a fallback.
			}
			scanned += budget;
			if (scanned >= MAX_SCAN_BYTES) { break; }
		}

		// Pass 2: leader-seeded recovery. A plain forward sweep DESYNCS on callfuscation
		// (call-as-jmp chains chop the real stream into thousands of tiny nodes), so the
		// VM dispatcher / operand-stack code is never seen by Pass 1. Byte-scan for
		// E8(call)/E9(jmp) rel32 branch targets and decode a short window at each target;
		// this re-anchors the decoder on the real chain nodes. Deduped by address so the
		// stream stays consistent and bounded. x86-specific.
		const WINDOW = 40;
		const MAX_LEADERS = 65536;
		const leaders = new Set<number>();
		for (const section of execSections) {
			const rawStart = (section as { rawAddress?: number }).rawAddress ?? -1;
			if (rawStart < 0) { continue; }
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
			for (let i = rawStart; i + 5 <= rawEnd; i++) {
				const b = buf[i];
				if (b !== 0xe8 && b !== 0xe9) { continue; } // call/jmp rel32
				const rel = buf.readInt32LE(i + 1);
				const instrVA = this.sectionOffsetToAddress(i, section);
				const targetVA = instrVA + 5 + rel;
				if (!byAddr.has(targetVA)) { leaders.add(targetVA); }
				if (leaders.size >= MAX_LEADERS) { break; }
			}
			if (leaders.size >= MAX_LEADERS) { break; }
		}
		for (const va of leaders) {
			try {
				const instrs = await this.disassembleRange(va, WINDOW);
				for (const inst of instrs) {
					if (!byAddr.has(inst.address)) { byAddr.set(inst.address, inst); }
				}
			} catch {
				// skip unresolvable leader
			}
		}

		for (const inst of byAddr.values()) { out.push(inst); }
		out.sort((a, b) => a.address - b.address);
		this._execScan = out;
		return out;
	}

	// ============ v3.7: VM Detection & Analysis ============

	/**
	 * Detect VM-based obfuscation patterns.
	 *
	 * Heuristics:
	 *  - Dispatcher: 3+ sequential cmp reg,imm followed by conditional jumps
	 *  - Operand stacks: [rbp+rax*4-offset] memory patterns
	 *  - Handler tables: indirect jumps via [reg*scale+base]
	 *  - Junk ratio: high % of junk instructions
	 *
	 * Source selection (v3.8.2): when an explicit `funcAddress` is given, scan that
	 * function. Otherwise prefer the linear executable sweep (`_execScan`, built by
	 * analyzeAll) so detection survives obfuscation that defeats function discovery;
	 * fall back to the largest discovered function only when no sweep is available.
	 */
	detectVM(funcAddress?: number): {
		vmDetected: boolean;
		vmType: string;
		dispatcher: string | null;
		opcodeCount: number;
		stackArrays: Array<{ base: string; type: string }>;
		junkRatio: number;
	} {
		// Get instructions for the target function (or the whole image if not specified)
		let instrs: Instruction[] = [];
		if (funcAddress !== undefined) {
			const func = this.functions.get(funcAddress);
			if (func) { instrs = func.instructions; }
		} else if (this._execScan && this._execScan.length > 0) {
			// v3.8.2: prefer the linear executable sweep so VM dispatchers in
			// un-discovered (obfuscated) code are still seen.
			instrs = this._execScan;
		} else {
			// Fallback: largest discovered function (legacy behavior).
			let largest: Function | undefined;
			for (const f of this.functions.values()) {
				if (!largest || f.instructions.length > largest.instructions.length) {
					largest = f;
				}
			}
			if (largest) { instrs = largest.instructions; }
		}

		if (instrs.length === 0) {
			return { vmDetected: false, vmType: 'none', dispatcher: null, opcodeCount: 0, stackArrays: [], junkRatio: 0 };
		}

		// Junk ratio
		const { junkRatio } = this.filterJunkInstructions(instrs);

		// Dispatcher detection: find sequences of cmp reg,imm + jcc
		let dispatcherAddr: string | null = null;
		let maxOpcodeCount = 0;

		for (let i = 0; i < instrs.length - 2; i++) {
			let cmpCount = 0;
			let startIdx = i;

			while (i < instrs.length) {
				const mn = instrs[i].mnemonic.toLowerCase();
				if (mn === 'cmp') {
					cmpCount++;
					i++;
					// Expect a conditional jump after cmp
					if (i < instrs.length && instrs[i].isConditional && instrs[i].isJump) {
						i++;
					}
				} else {
					break;
				}
			}

			if (cmpCount >= 3 && cmpCount > maxOpcodeCount) {
				maxOpcodeCount = cmpCount;
				dispatcherAddr = '0x' + instrs[startIdx].address.toString(16);
			}
		}

		// Operand stack detection: look for indexed [reg+reg*N-offset] accesses --
		// the hallmark of a stack-VM operand stack / VM-program array, e.g.
		// `mov eax, dword ptr [rbp + rax*4 - 0x950]`. Accept *4 and *8 scales.
		const stackArrays: Array<{ base: string; type: string }> = [];
		// Tolerate Capstone's spaced operand syntax: `[rbp + rax*4 - 0x950]`.
		const stackPatternRegex = /\[(\w+)\s*[+-]\s*\w+\*[48]\s*[+-]\s*(0x[\da-f]+|\d+)\]/i;
		const seenStacks = new Set<string>();
		let operandStackAccesses = 0; // total (not distinct) indexed accesses

		// Indirect dispatch: `jmp reg`, `jmp [mem]`, `call reg`, `call [mem]` -- the
		// computed-goto / handler-table dispatch a VM interpreter uses instead of (or
		// alongside) a cmp ladder.
		let indirectDispatch = 0;
		let firstIndirectDispatchAddr: string | null = null;

		// A real VM operand stack / program array lives in a SMALL frame displacement
		// (the crackme stack-VM used `-0x950`). Indexed accesses with a huge displacement
		// (e.g. `[r11 + rax*4 - 0xf21d0]`, ~991 KB) are global/section accesses in ordinary
		// code (D appender, biguint, CRT) and were the source of vmDetection FALSE POSITIVES
		// and the fake "stackArrays" that polluted downstream type inference. Gate on a sane
		// stack-frame bound so only plausible operand-stack accesses count.
		const MAX_STACK_DISP = 0x10000;
		for (const inst of instrs) {
			const match = inst.opStr.match(stackPatternRegex);
			if (match) {
				const disp = Number(match[2]);
				if (Number.isFinite(disp) && disp <= MAX_STACK_DISP) {
					operandStackAccesses++;
					const key = `${match[1]}-${match[2]}`;
					if (!seenStacks.has(key)) {
						seenStacks.add(key);
						stackArrays.push({
							base: `${match[1]}-${match[2]}`,
							type: stackArrays.length === 0 ? 'operand-stack' : 'vm-program'
						});
					}
				}
			}
			const mn = inst.mnemonic.toLowerCase();
			if (mn === 'jmp' || mn === 'call') {
				const op = inst.opStr.trim();
				// indirect = not a plain `0x...` direct target
				if (op.length > 0 && !/^0x[\da-f]+$/i.test(op)) {
					indirectDispatch++;
					if (!firstIndirectDispatchAddr) {
						firstIndirectDispatchAddr = '0x' + inst.address.toString(16);
					}
				}
			}
		}

		// VM verdict (v3.8.2): a LONG cmp-ladder dispatcher OR a stack-VM signature
		// (multiple distinct operand-stack arrays with repeated indexed accesses AND an
		// indirect dispatch).
		//
		// The cmp-ladder threshold is 6 (not 3): when scanning the WHOLE image, short
		// 3-cmp runs occur constantly in ordinary code (kernel modules tripped the old
		// >=3 gate as a false positive). A genuine bytecode dispatcher compares the
		// opcode against many handler ids. The stack-VM path is what HTB callfuscated/
		// stack-VM samples exhibit -- a computed-goto interpreter with no cmp ladder.
		const LADDER_MIN = 6;
		// Density gate: a real VM operand stack is a FEW arrays hit MANY times (the hot
		// interpreter loop). Ordinary array-heavy code (e.g. D BigInt/appender) produces
		// MANY distinct indexed bases each touched only a few times -- high array count, low
		// density. Requiring >=4 accesses per distinct array rejects that false positive
		// (dudidudida: 11 scattered arrays) while keeping a genuine stack VM (few dense
		// operand stacks).
		const stackVmSignature = stackArrays.length >= 2
			&& operandStackAccesses >= 8
			&& operandStackAccesses >= stackArrays.length * 4
			&& indirectDispatch >= 1;
		const ladderDispatch = maxOpcodeCount >= LADDER_MIN;
		const vmDetected = ladderDispatch
			|| stackVmSignature
			|| (junkRatio > 0.4 && stackArrays.length > 0);
		const vmType = vmDetected
			? (ladderDispatch ? 'bytecode-interpreter'
				: stackVmSignature ? 'stack-machine'
					: 'obfuscated-vm')
			: 'none';

		return {
			vmDetected,
			vmType,
			// Report the cmp-ladder address when that's the trigger; otherwise the
			// first indirect dispatch site for a stack VM.
			dispatcher: ladderDispatch ? dispatcherAddr : (stackVmSignature ? firstIndirectDispatchAddr : null),
			// For a stack-VM with no cmp ladder, report the distinct operand-stack
			// array count as the "opcode" proxy so consumers get a non-zero signal.
			opcodeCount: ladderDispatch ? maxOpcodeCount : (stackVmSignature ? stackArrays.length : 0),
			// Only surface stackArrays when this is actually judged a VM. When vmDetected is
			// false they are incidental indexed accesses (not a VM operand stack) and were
			// being consumed downstream as fake struct fields -- a no-op detector must not
			// emit signal that degrades other passes.
			stackArrays: vmDetected ? stackArrays : [],
			junkRatio
		};
	}

	// ============ v3.7: PRNG Analysis Helper ============

	/**
	 * Map a call target VA to a PRNG symbol name (srand/rand/random/srandom), if any.
	 * Resolves through: (1) the authoritative .rela.plt-derived PLT map, (2) the
	 * import table, (3) the discovered-function table. Returns the lowercase symbol
	 * stem or null.
	 */
	private resolvePrngTargetName(targetVA: number): string | null {
		const prng = ['srandom', 'srand', 'random', 'rand']; // longest-first to avoid 'rand' eating 'srand'
		const tryName = (raw: string | undefined): string | null => {
			if (!raw) { return null; }
			const n = raw.toLowerCase();
			for (const p of prng) {
				if (n === p || n === `${p}@plt` || n === `_${p}`) { return p; }
			}
			return null;
		};
		// 1. PLT map (authoritative, complete)
		const m1 = tryName(this._pltSymbolMap.get(targetVA));
		if (m1) { return m1; }
		// 2. import table (PLT-stub addresses assigned during parse)
		for (const lib of this.imports) {
			for (const f of lib.functions) {
				if (f.address === targetVA) {
					const m = tryName(f.name);
					if (m) { return m; }
				}
			}
		}
		// 3. discovered function table
		const m3 = tryName(this.functions.get(targetVA)?.name);
		if (m3) { return m3; }
		return null;
	}

	/**
	 * Detect PRNG usage patterns in the analyzed binary.
	 *
	 * v3.8.2 rework: this is a BYTE SCAN over executable sections (the same
	 * obfuscation-resistant model as detectCallfuscation), NOT a walk of discovered
	 * functions. Prologue-based discovery collapses under callfuscation/flattening,
	 * so the previous function-walking version found nothing on real obfuscated CTF
	 * binaries despite a live srand/rand. It also resolves PLT/GOT call targets to
	 * symbol names (the import table can leave entries at 0x0) and extracts the srand
	 * seed immediate from the preceding `mov edi/rdi, imm` (SysV first arg).
	 *
	 * Handles:
	 *  - E8 rel32         direct call to a PLT stub
	 *  - FF 15 disp32     call qword ptr [rip+disp] -> GOT slot (-fno-plt / PIC)
	 * x86/x64 only.
	 */
	detectPRNG(): {
		prngDetected: boolean;
		seedSource: string | null;
		seedValue: number | null;
		randCallCount: number;
		callSites: Array<{ address: string; function: string; context: string }>;
	} {
		const empty = { prngDetected: false, seedSource: null, seedValue: null, randCallCount: 0, callSites: [] as Array<{ address: string; function: string; context: string }> };
		if (!this.fileBuffer) { return empty; }
		if (this.architecture !== 'x64' && this.architecture !== 'x86') { return empty; }
		const buf = this.fileBuffer;

		const callSites: Array<{ address: string; function: string; context: string }> = [];
		let seedSource: string | null = null;
		let seedValue: number | null = null;
		let randCallCount = 0;

		const seen = new Set<number>();
		const srandCallVAs: number[] = []; // for chain-aware seed recovery below

		const execSections = this.sections.filter(s => s.isCode || (s as { isExecutable?: boolean }).isExecutable);
		for (const section of execSections) {
			const rawStart = (section as { rawAddress?: number }).rawAddress ?? -1;
			if (rawStart < 0) { continue; }
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);

			for (let i = rawStart; i + 5 <= rawEnd; i++) {
				let targetVA: number | null = null;

				if (buf[i] === 0xe8) {
					// E8 rel32 : direct call. target = nextInstrVA + rel32
					const rel = buf.readInt32LE(i + 1);
					const instrVA = this.sectionOffsetToAddress(i, section);
					targetVA = instrVA + 5 + rel;
				} else if (buf[i] === 0xff && i + 6 <= rawEnd && buf[i + 1] === 0x15) {
					// FF 15 disp32 : call qword ptr [rip + disp32] -> GOT slot VA
					const disp = buf.readInt32LE(i + 2);
					const instrVA = this.sectionOffsetToAddress(i, section);
					targetVA = instrVA + 6 + disp; // GOT slot VA
				} else {
					continue;
				}

				if (targetVA === null) { continue; }
				const matched = this.resolvePrngTargetName(targetVA);
				if (!matched) { continue; }

				const callVA = this.sectionOffsetToAddress(i, section);
				if (seen.has(callVA)) { continue; }
				seen.add(callVA);

				if (matched === 'rand' || matched === 'random') {
					randCallCount++;
				}

				let context = matched;
				if (matched === 'srand' || matched === 'srandom') {
					srandCallVAs.push(callVA);
					// Contiguous fast path: `mov edi/rdi, imm` directly before the call
					// (non-obfuscated layout). The chain-aware scan below covers the
					// callfuscated layout where the seed load lives in a different node.
					const lookbackStart = Math.max(rawStart, i - 24);
					for (let k = i - 1; k >= lookbackStart; k--) {
						if (buf[k] === 0xbf && k + 5 <= rawEnd) { // mov edi, imm32
							const imm = buf.readUInt32LE(k + 1);
							seedValue = imm;
							seedSource = `immediate(0x${imm.toString(16)})`;
							context = `srand(0x${imm.toString(16)})`;
							break;
						}
						if (buf[k] === 0x48 && k + 7 <= rawEnd && buf[k + 1] === 0xc7 && buf[k + 2] === 0xc7) { // mov rdi, imm32
							const imm = buf.readInt32LE(k + 3);
							seedValue = imm;
							seedSource = `immediate(0x${(imm >>> 0).toString(16)})`;
							context = `srand(0x${(imm >>> 0).toString(16)})`;
							break;
						}
					}
				}

				callSites.push({
					address: '0x' + callVA.toString(16),
					function: matched,
					context
				});
			}
		}

		// Chain-aware seed recovery (v3.8.2): under callfuscation the seed load and the
		// srand call live in DIFFERENT chain nodes, linked by a call-as-jmp. The seed
		// node looks like `mov edi, imm32 ; E8 rel32` where the E8 target lands at (or a
		// few bytes before, past the pop-discard) a srand call node. Byte-scan the whole
		// executable region for that signature when the contiguous fast path failed.
		if (seedValue === null && srandCallVAs.length > 0) {
			const SEED_LINK_WINDOW = 8; // pop-discard prefix (1-2 bytes) tolerance
			const isNearSrandNode = (targetVA: number): boolean =>
				srandCallVAs.some(sv => targetVA >= sv - SEED_LINK_WINDOW && targetVA <= sv + SEED_LINK_WINDOW);
			outer:
			for (const section of execSections) {
				const rawStart = (section as { rawAddress?: number }).rawAddress ?? -1;
				if (rawStart < 0) { continue; }
				const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
				for (let i = rawStart; i + 10 <= rawEnd; i++) {
					let immVal: number | null = null;
					let afterMov = -1;
					if (buf[i] === 0xbf) { // mov edi, imm32 ; <5 bytes>
						immVal = buf.readUInt32LE(i + 1);
						afterMov = i + 5;
					} else if (buf[i] === 0x48 && buf[i + 1] === 0xc7 && buf[i + 2] === 0xc7) { // mov rdi, imm32
						immVal = buf.readInt32LE(i + 3) >>> 0;
						afterMov = i + 7;
					} else {
						continue;
					}
					// must be immediately followed by E8/E9 rel32 (the chain link)
					if (afterMov + 5 > rawEnd) { continue; }
					const op = buf[afterMov];
					if (op !== 0xe8 && op !== 0xe9) { continue; }
					const rel = buf.readInt32LE(afterMov + 1);
					const linkVA = this.sectionOffsetToAddress(afterMov, section) + 5 + rel;
					if (isNearSrandNode(linkVA)) {
						seedValue = immVal;
						seedSource = `immediate(0x${immVal.toString(16)})`;
						// annotate the srand call site context
						for (const cs of callSites) {
							if (cs.function === 'srand' || cs.function === 'srandom') {
								cs.context = `srand(0x${immVal.toString(16)})`;
							}
						}
						break outer;
					}
				}
			}
		}

		return {
			prngDetected: callSites.length > 0,
			seedSource,
			seedValue,
			randCallCount,
			callSites
		};
	}

	/**
	 * Detect "callfuscation" control-flow obfuscation (HTB "Callfuscated" family).
	 *
	 * The obfuscator chops the real linear instruction stream into thousands of
	 * tiny nodes connected by `call <next>` used as an obfuscated `jmp`: the target
	 * of each such call begins with a `pop` that immediately DISCARDS the just-pushed
	 * return address. The defining byte signature is:
	 *
	 *     E8 rel32              ; call <target>
	 *     <target>: 58..5F      ; pop r{a..d}{x}/rsi/rdi/rbp/rsp  (1-byte)
	 *           or  41 58..5F   ; pop r8..r15                      (REX.B 2-byte)
	 *
	 * This shatters prologue-based function discovery (no node has a real prologue)
	 * and starves every downstream pass (VM/PRNG/junk detection) that only inspects
	 * discovered functions. This detector is a pure byte scan over executable
	 * sections, so it works even when function discovery finds nothing — giving
	 * pipeline consumers an honest "this binary is callfuscated" signal plus the
	 * gadget count needed to drive a deflattening pass.
	 *
	 * x86/x64 only (the gadget encoding is x86-specific).
	 */
	detectCallfuscation(): {
		detected: boolean;
		gadgetCount: number;
		callCount: number;
		ratio: number;
		discardRegisters: string[];
	} {
		const empty = { detected: false, gadgetCount: 0, callCount: 0, ratio: 0, discardRegisters: [] as string[] };
		if (!this.fileBuffer) { return empty; }
		if (this.architecture !== 'x64' && this.architecture !== 'x86') { return empty; }
		const buf = this.fileBuffer;

		const REG1 = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']; // 0x58..0x5F
		const REG2 = ['r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'];  // 41 0x58..0x5F
		const isPopAt = (off: number): string | null => {
			if (off < 0 || off >= buf.length) { return null; }
			const b = buf[off];
			if (b >= 0x58 && b <= 0x5f) { return REG1[b - 0x58]; }
			if (b === 0x41 && off + 1 < buf.length) {
				const b2 = buf[off + 1];
				if (b2 >= 0x58 && b2 <= 0x5f) { return REG2[b2 - 0x58]; }
			}
			return null;
		};

		let gadgetCount = 0;
		let callCount = 0;
		const discardCounts = new Map<string, number>();

		const execSections = this.sections.filter(s => s.isCode || (s as { isExecutable?: boolean }).isExecutable);
		for (const section of execSections) {
			const rawStart = (section as { rawAddress?: number }).rawAddress ?? -1;
			if (rawStart < 0) { continue; }
			const rawEnd = Math.min(rawStart + section.rawSize, buf.length);
			for (let i = rawStart; i + 5 <= rawEnd; i++) {
				if (buf[i] !== 0xe8) { continue; } // call rel32
				callCount++;
				const rel = buf.readInt32LE(i + 1);
				const instrVA = this.sectionOffsetToAddress(i, section);
				const targetVA = instrVA + 5 + rel;
				// Resolve the call target to a file offset and check it starts with a pop discard.
				let targetOff = -1;
				try { targetOff = this.addressToOffset(targetVA); } catch { targetOff = -1; }
				const reg = isPopAt(targetOff);
				if (reg) {
					gadgetCount++;
					discardCounts.set(reg, (discardCounts.get(reg) ?? 0) + 1);
				}
			}
		}

		const ratio = callCount > 0 ? gadgetCount / callCount : 0;
		// Heuristic: callfuscation produces thousands of these and dominates the call
		// population. A handful of legitimate `call $+5; pop` (PIC idioms) won't trip this.
		const detected = gadgetCount >= 16 && ratio >= 0.5;
		const discardRegisters = [...discardCounts.entries()]
			.sort((a, b) => b[1] - a[1])
			.map(([r]) => r);

		return { detected, gadgetCount, callCount, ratio, discardRegisters };
	}

	dispose(): void {
		this.capstone.dispose();
		this.capstoneInitialized = false;
		this.llvmMc.dispose();
		this.llvmMcInitialized = false;
	}
}
