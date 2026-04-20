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

	// a) symbolResolution (weight 0.30): resolvedExternalCalls / totalExternalCalls
	const symbolResolution = totalExternalCalls > 0 ? resolvedExternalCalls / totalExternalCalls : 1.0;

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
	isNative: boolean;
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

	// Cache for text section byte-pattern scan results
	private _textScanCache?: Map<number, number[]>;

	// v3.7.1: VM detection results from last analyzeAll() with detectVM: true
	private _vmDetectionResults?: Map<number, { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number }>;

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
			this._textScanCache = undefined;

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
	async analyzeAll(options?: { filterJunk?: boolean; detectVM?: boolean }): Promise<number> {
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

		// Build string cross-references
		this.buildStringXrefs();

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
		const count = Math.min(Math.floor(pdataSize / entrySize), 100000); // Safety cap at 100K

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
			isNative: (flags & 0x01) !== 0,        // COMIMAGE_FLAGS_ILONLY inverted
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

		// Count external calls from text relocations
		const resolvedExternalCalls = this.textRelocations.size;
		const totalExternalCalls = this.elfAnalysis.symbols.filter(s => s.isImport).length;

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

					// Extract symbol index from r_info
					const symIdx = is64Bit ? (rInfo >> 32) : (rInfo >> 8);

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

						if (!callRelTypes.has(relType)) {
							continue;
						}

						// Read symbol name from .symtab
						const symOff = symtabSec.offset + symIdx * symEntSize;
						if (symOff + symEntSize > this.fileBuffer.length) { continue; }
						const stName = readU32(symOff);

						let symName = '';
						const symNameOff = strtabSec.offset + stName;
						if (symNameOff < this.fileBuffer.length) {
							for (let j = symNameOff; j < this.fileBuffer.length && this.fileBuffer[j] !== 0; j++) {
								symName += String.fromCharCode(this.fileBuffer[j]);
								if (symName.length > 256) { break; }
							}
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

		let endIdx = instructions.length;
		let lastRetIdx = -1;
		for (let i = 0; i < instructions.length; i++) {
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
				if (jumpTargetIsCode &&
					!inst.isConditional &&
					inst.targetAddress !== address &&
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

	/** v3.7.4 FIX-011: Get .rela.text relocations for ET_REL files.
	 *  Returns Map<textOffset, {name, type, addend}> */
	getTextRelocations(): Map<number, { name: string; type: number; addend: number }> {
		return this.textRelocations;
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

	// ============ v3.7: VM Detection & Analysis ============

	/**
	 * Detect VM-based obfuscation patterns in a function's instructions.
	 * Heuristics:
	 *  - Dispatcher: 3+ sequential cmp reg,imm followed by conditional jumps
	 *  - Operand stacks: [rbp+rax*4-offset] memory patterns
	 *  - Handler tables: indirect jumps via [reg*scale+base]
	 *  - Junk ratio: high % of junk instructions
	 */
	detectVM(funcAddress?: number): {
		vmDetected: boolean;
		vmType: string;
		dispatcher: string | null;
		opcodeCount: number;
		stackArrays: Array<{ base: string; type: string }>;
		junkRatio: number;
	} {
		// Get instructions for the target function (or all if not specified)
		let instrs: Instruction[] = [];
		if (funcAddress !== undefined) {
			const func = this.functions.get(funcAddress);
			if (func) { instrs = func.instructions; }
		} else {
			// Analyze largest function
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

		// Operand stack detection: look for [reg+reg*4-offset] patterns
		const stackArrays: Array<{ base: string; type: string }> = [];
		const stackPatternRegex = /\[(\w+)[+-]\w+\*4[+-](0x[\da-f]+|\d+)\]/i;
		const seenStacks = new Set<string>();

		for (const inst of instrs) {
			const match = inst.opStr.match(stackPatternRegex);
			if (match) {
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

		const vmDetected = maxOpcodeCount >= 3 || (junkRatio > 0.4 && stackArrays.length > 0);
		const vmType = vmDetected
			? (maxOpcodeCount >= 3 ? 'bytecode-interpreter' : 'obfuscated-vm')
			: 'none';

		return {
			vmDetected,
			vmType,
			dispatcher: dispatcherAddr,
			opcodeCount: maxOpcodeCount,
			stackArrays,
			junkRatio
		};
	}

	// ============ v3.7: PRNG Analysis Helper ============

	/**
	 * Detect PRNG usage patterns in the analyzed binary.
	 * Scans for PLT calls to srand/rand/random/srandom, identifies seed sources.
	 */
	detectPRNG(): {
		prngDetected: boolean;
		seedSource: string | null;
		seedValue: number | null;
		randCallCount: number;
		callSites: Array<{ address: string; function: string; context: string }>;
	} {
		const callSites: Array<{ address: string; function: string; context: string }> = [];
		let seedSource: string | null = null;
		let seedValue: number | null = null;
		let randCallCount = 0;
		const prngFunctions = ['srand', 'rand', 'random', 'srandom'];

		for (const func of this.functions.values()) {
			for (let i = 0; i < func.instructions.length; i++) {
				const inst = func.instructions[i];
				if (!inst.isCall) { continue; }

				// Check if this call targets a known PRNG function
				const targetFunc = this.functions.get(inst.targetAddress ?? 0);
				const targetName = targetFunc?.name?.toLowerCase() ?? '';

				// Also check if the opStr references a PRNG name (PLT calls often show the symbol)
				const opLower = inst.opStr.toLowerCase();
				const matchedPrng = prngFunctions.find(fn => targetName.includes(fn) || opLower.includes(fn));

				if (!matchedPrng) { continue; }

				if (matchedPrng === 'rand' || matchedPrng === 'random') {
					randCallCount++;
				}

				// For srand/srandom, look back for the seed value (mov edi, imm before call)
				let context = matchedPrng;
				if (matchedPrng === 'srand' || matchedPrng === 'srandom') {
					// Look back up to 5 instructions for the seed loading
					for (let j = Math.max(0, i - 5); j < i; j++) {
						const prev = func.instructions[j];
						const prevMn = prev.mnemonic.toLowerCase();
						const prevOp = prev.opStr.toLowerCase();

						// mov edi, <imm> or mov rdi, <imm> (System V ABI, first arg)
						if (prevMn === 'mov' && (prevOp.startsWith('edi,') || prevOp.startsWith('rdi,'))) {
							const parts = prevOp.split(',');
							if (parts.length === 2) {
								const valStr = parts[1].trim();
								const parsed = parseInt(valStr, valStr.startsWith('0x') ? 16 : 10);
								if (!isNaN(parsed)) {
									seedValue = parsed;
									seedSource = `immediate(${valStr})`;
									context = `srand(${valStr})`;
								}
							}
						}
					}
				}

				callSites.push({
					address: '0x' + inst.address.toString(16),
					function: matchedPrng,
					context
				});
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

	dispose(): void {
		this.capstone.dispose();
		this.capstoneInitialized = false;
		this.llvmMc.dispose();
		this.llvmMcInitialized = false;
	}
}
