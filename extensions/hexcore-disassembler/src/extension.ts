/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as v8 from 'v8';
import * as zlib from 'zlib';
import * as vscode from 'vscode';
import { encodeX86PcRelativeDataDisplacement } from './elfTextRelocation';
import { DisassemblyEditorProvider } from './disassemblyEditor';
import { FunctionTreeProvider } from './functionTree';
import { StringRefProvider } from './stringRefTree';
import { SectionTreeProvider } from './sectionTree';
import { ImportTreeProvider } from './importTree';
import { ExportTreeProvider } from './exportTree';
import { DisassemblerEngine, ImportLibrary, Instruction, TypedImportLibrary, TypedImportFunction, ImportCategorySummary, PEDataDirectories, ELFAnalysis, ELFExecutableSection, decodeIatOperandVA, type AssemblyExportResult, type FunctionBodyStatus, type FunctionAnalysisMaterialization } from './disassemblerEngine';
import { formatApiSignatureCompact, CATEGORY_LABELS } from './peApiDatabase';
import { DisassemblerFactory } from './disassemblerFactory';
import { GraphViewProvider } from './graphViewProvider';
import {
	AnalysisCenterProvider,
	type AnalysisActionResult,
	type AnalysisCenterRequest,
	type AnalysisCenterSnapshot,
	type AnalysisFinding
} from './analysisCenter';
import {
	buildStringInvestigationFindings,
	resolveInvestigationQueries,
	assertFindingMatchesActiveTarget,
	type InvestigationPreset
} from './investigationModel';
import { createInvestigationJob, sanitizeInvestigationJobName } from './investigationJob';
import { inspectHelixOutputQuality, stampHelixConfidenceAxes } from './helixOutputQuality';
import { assessLiftSemanticCoverage, formatLiftSemanticHeader } from './liftSemanticCoverage';
import {
	assessFunctionMaterialization,
	normalizeFunctionMaterializationPolicy,
} from './functionMaterializationCoverage';
import { decideAnalysisContextOwnership } from './analysisContextOwnership';
import { describeCanonicalArtifactIdentity } from './artifactNormalization';
import { describeQueueObservation, type QueueQueryContext } from './queueObservation';
import { analyzeAllProcessController, type NativeAnalyzeExecution } from './analyzeAllProcess';
import { findRecordedAutoRunAttempt, recoverStaleAutoRunAttempt } from './autoRunAttempt';
import {
	classifyDisassemblyInstructionRole,
	type DisassemblyInstructionRole,
} from './disassemblyInstructionRole';
import type { InvestigationFindingEntry, SessionStore } from './sessionStore';
import { resolvePathWithinRoots, type AnalysisEngineIdentity } from 'hexcore-common';
import { decorateOkResult, decoratePipelineRunStatus, decorateValidationReport, type ContractDecorated } from './commandResult';
import {
	AutomationPipelineRunner,
	PipelineDoctorReport,
	PipelineJobValidationReport,
	PipelineRunStatus,
	listCapabilities,
	runPipelineDoctor,
	getJobQueueManagerInstance,
	disposeJobQueueManagerInstance,
	JobPriority,
	JOB_STATUS_FILENAME,
	JOB_LOG_FILENAME
} from './automationPipelineRunner';
import { QueuedJob, QueueStats, JobStatusReport, jobPathIdentity } from './jobQueueManager';
import { buildInstructionFormula, FormulaBuildResult } from './formulaBuilder';
import { solveConstraints, type ConstraintSolverOptions } from './constraintSolver';
import { analyzeConstantSanity, ConstantSanityAnalysis } from './constantSanityChecker';
import { RemillWrapper, buildIRHeader, type LiftResult, type RemillLiftOptions } from './remillWrapper';
import {
	runPathfinder,
	getPdataFunctionCount,
	isBacktrackContinuityValid,
} from './pathfinder';
import { RellicWrapper, buildPseudoCHeader } from './rellicWrapper';
import { HelixWrapper } from './helixWrapper';
import {
	loadHql,
	getHqlLoadError,
	runHqlScanBatch,
	buildScanTargets,
	scanOneTarget,
	createLiveHqlSessionReader,
	DEFAULT_HQL_BATCH_BUDGET,
	type HqlScanTarget,
	type HelixDecompileQuietResult,
} from './hqlScanner';
import { readPeDataSections, type DataSection as PeDataSection } from './peDataSections';
import { SouperWrapper, decideSouperGate } from './souperWrapper';
import { getStructInfoForFunction, exportStructInfoJson, scopeStructInfoForFunctions, type StructInfoJson } from './elfBtfLoader';
import { auditRefcount } from './refcountAuditScanner';
import { readAuditInputQuality } from './auditInputQuality';
import { mapCapstoneToRemill } from './archMapper';
import { planLiftPreamble, type LiftPreambleTransformation } from './liftPreamble';
import {
	PipelineJobTemplate,
	PipelinePreset,
	getBuiltInPipelinePresets,
	getWorkspacePresetFilePath,
	loadWorkspacePipelinePresets,
	materializePresetJob,
	normalizeJobTemplateFromExistingJob,
	saveWorkspacePipelinePreset
} from './pipelineProfiles';
import {
	buildHelixFunctionStarts,
	resolveHelixBaseOptions,
	wantsHelixFunctionStarts,
	resolveLiftByteSize,
	assessByteRangeCompletion,
	assessLiftRangeCompletion,
	coercePositiveInt,
	getAuthoritativeFunctionExtent,
	shouldHonorExplicitLiftWindow,
	isBacktrackWithinSection,
	hasHeadlessHelixIrInput,
	type ResolvedLiftByteSize,
} from './helixPackaging';
import {
	buildImportSymbolMap,
	applyImportSymbolNamesToSource,
} from './importSymbolNames';
import { classifyDisassemblyStop, type DisassemblyStopReason } from './disassemblyStop';
import { applyHonestyConfidenceCap, type HonestyEvidence } from './honestyConfidenceCap';
import { detectPacker, packerCapabilityTags } from './packerDetect';
import { isSingleFileBundle } from './managedDotNetDetector';
import {
	createHelixAnalysisContext,
	type HelixAnalysisContext,
} from './helixAnalysisContext';
import { buildWindowsFilesystemAudit } from './windowsFilesystemAudit';
import {
	decorateSemanticCommandResult,
	prepareSemanticCommandService,
	readSemanticImportInput,
	resolveSemanticOutputPath,
	semanticCommandCallbacks,
	type SemanticCommandInvocationOptions,
} from './semanticCommandIntegration';
import type {
	ApplyPrototypeRequest,
	ClearOverrideRequest,
	ExplainPrototypeRequest,
	SemanticCommandExportEnvelope,
	SetCallingConventionRequest,
	SetParameterRequest,
} from './semanticCommandService';
import {
	syncTypedReferenceGraph,
	type ReferenceGraphProducerBudgets,
	type ReferenceGraphSyncResult,
} from './typedReferenceGraphProducer';
import {
	runReferenceGraphExport,
	runReferenceGraphQuery,
	type ReferenceGraphExportCommandOptions,
	type ReferenceGraphQueryCommandOptions,
} from './typedReferenceGraphCommands';
import {
	runPropagationExport,
	runPropagationSolve,
	runPropagationStatus,
	type PropagationCommandOptions,
} from './wholeProgramPropagationCommands';
import {
	runDebugTypeIngest,
	runRecordRecovery,
	runTypeCreate,
	runTypeDelete,
	runTypeExport,
	runTypeImport,
	runTypeList,
	runTypeRename,
	runTypeUpdate,
	runTypeUndo,
} from './typeManagerCommands';
import type { TypeManagerExport } from './typeManager';
import { importPdbSemantics } from './pdbSemanticImport';
import { resolvePdbFromSymbolServers } from './pdbProvider';
import { applyImportSignatureProvider } from './signatureProvider';
import { SemanticExplorerPanel } from './semanticExplorer';

type OutputFormat = 'json' | 'md';

interface AnalyzeAllOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface WindowsFilesystemAuditCommandOptions {
	file?: string;
	output?: { path: string; format?: 'json' };
	quiet?: boolean;
	maxStringSignals?: number;
}

interface SemanticImportCommandOptions extends SemanticCommandInvocationOptions {
	input?: unknown;
	inputPath?: string;
}

interface ReferenceGraphCommandInvocationOptions {
	file?: string;
	quiet?: boolean;
	output?: string | { path?: string };
	producerBudgets?: Partial<ReferenceGraphProducerBudgets>;
}

interface AnalyzeAllCommandOptions {
	file?: string;
	output?: AnalyzeAllOutputOptions;
	quiet?: boolean;
	maxFunctions?: number;
	maxFunctionSize?: number;
	forceReload?: boolean;
	includeInstructions?: boolean;
	/** Architecture override for headerless raw binaries only. */
	arch?: 'x86' | 'x64' | 'arm' | 'arm64' | 'mips' | 'mips64';
	/** Virtual load base for headerless raw binaries only. */
	baseAddress?: string | number;
	// v3.7 options
	filterJunk?: boolean;
	detectVM?: boolean;
	detectPRNG?: boolean;
	/** Explicitly accept deferred function bodies in reconnaissance jobs. */
	allowLazy?: boolean;
	/** Explicitly accept entries whose decoder returned no instructions. */
	allowDecodeEmpty?: boolean;
	/** Optional minimum decoded-body ratio, from 0.0 to 1.0. */
	minMaterializedRatio?: number;
	/** Supplied by the pipeline runner; direct callers may set a bounded native deadline. */
	pipelineTimeoutMs?: number;
}

interface BuildFormulaCommandOptions {
	file?: string;
	startAddress?: string | number;
	endAddress?: string | number;
	addresses?: Array<string | number>;
	targetRegister?: string;
	output?: AnalyzeAllOutputOptions;
	quiet?: boolean;
}

interface CheckConstantsCommandOptions {
	file?: string;
	notesFile?: string;
	maxFindings?: number;
	output?: AnalyzeAllOutputOptions;
	quiet?: boolean;
}

interface AnalyzeAllInstructionEntry {
	address: string;
	mnemonic: string;
	operands: string;
	bytes: string;
}

interface AnalyzeAllFunctionSummary {
	address: string;
	name: string;
	size: number;
	instructionCount: number;
	bodyStatus: FunctionBodyStatus;
	bodyReason?: 'deferred-until-requested' | 'decoder-returned-no-instructions';
	callers: number;
	callees: number;
	discoveryEvidence?: Array<{
		kind: string;
		sourceAddress?: string;
		consumerAddress?: string;
		confidence?: number;
	}>;
	instructions?: AnalyzeAllInstructionEntry[];
	xrefsTo?: string[];
	xrefsFrom?: string[];
}

interface AnalyzeAllStringEntry {
	address: string;
	value: string;
	encoding: string;
	referencedBy: string[];
}

interface AnalyzeAllResult {
	status: 'ok' | 'partial';
	analysisDepth: ReturnType<typeof assessFunctionMaterialization>['analysisDepth'];
	negativeEvidenceUsable: false;
	functionsMaterialized: number;
	partialFunctions: number;
	warning?: string;
	filePath: string;
	fileName: string;
	newFunctions: number;
	removedFunctions: number;
	functionNetChange: number;
	totalFunctions: number;
	functionsWithInstructions: number;
	functionsWithoutInstructions: number;
	lazyFunctions: number;
	decodeEmptyFunctions: number;
	materializedFunctionRatio: number;
	materializationPolicy: {
		allowLazy: boolean;
		allowDecodeEmpty: boolean;
		minMaterializedRatio: number;
	};
	closureRestoration: ReturnType<DisassemblerEngine['getAnalysisClosureRestoration']>;
	nativeExecution?: NativeAnalyzeExecution;
	totalFunctionInstructions: number;
	totalStrings: number;
	architecture: string;
	baseAddress: string;
	sections: number;
	imports: number;
	/** v3.8.3: total imported FUNCTION count (the `imports` field is the library count;
	 *  for ELF an "imports: 2" of [external(22 funcs), libc.so.6(0)] read as 2 vs the ELF
	 *  analyzer's 22 -- this disambiguates by also giving the function total). */
	importedFunctions?: number;
	exports: number;
	// v3.8.3: detailed section/import/export arrays (the counts above are kept for
	// backward compatibility). Previously analyzeAll exported only the integer counts,
	// so the import table (the strongest capability/IOC signal, e.g. an injector's
	// CreateRemoteThread/WriteProcessMemory set) was absent from the function-map output.
	sectionDetails?: Array<{ name: string; virtualAddress: string; virtualSize: number; rawSize: number; permissions: string; isCode: boolean }>;
	importDetails?: Array<{ dll: string; functionCount: number; functions: Array<{ name: string; address: string; ordinal?: number }> }>;
	exportDetails?: Array<{ name: string; address: string; ordinal: number; isForwarder: boolean }>;
	// v3.8.3: high-signal capability tags derived from imports / sections / CLR header,
	// so the orchestrator/analyst gets a behavior summary (injector, self-modifying, .NET,
	// ...) instead of having to hand-read the import table. Best-effort, import/section based.
	capabilities?: string[];
	functions: AnalyzeAllFunctionSummary[];
	strings?: AnalyzeAllStringEntry[];
	reportMarkdown: string;
	// v3.7 analysis data
	junkAnalysis?: { totalInstructions: number; junkCount: number; junkRatio: number };
	vmDetection?: { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number };
	prngDetection?: { prngDetected: boolean; seedSource: string | null; seedValue: number | null; randCallCount: number; callSites: Array<{ address: string; function: string; context: string }> };
	// v3.8.1: callfuscation (call-as-jmp control-flow obfuscation) detection.
	// Pure byte scan — independent of function discovery, so it reports the
	// obfuscation even when prologue-based discovery finds nothing.
	callfuscation?: { detected: boolean; gadgetCount: number; callCount: number; ratio: number; discardRegisters: string[] };
	referenceGraph?: ReferenceGraphSyncResult | { status: 'error'; reason: string };
}

interface BuildFormulaResult {
	filePath: string;
	fileName: string;
	startAddress: string;
	endAddress: string;
	instructionCount: number;
	targetRegister: string;
	expression: string;
	registerExpressions: Record<string, string>;
	steps: FormulaBuildResult['steps'];
	unsupportedInstructions: FormulaBuildResult['unsupportedInstructions'];
	reportMarkdown: string;
	generatedAt: string;
}

interface ConstantSanityResult extends ConstantSanityAnalysis {
	filePath: string;
	fileName: string;
	generatedAt: string;
}

interface RunJobCommandOptions {
	jobFile?: string;
	quiet?: boolean;
}

interface CommandOutputOptions {
	output?: string | { path?: string };
}

interface ValidateJobCommandOptions extends RunJobCommandOptions, CommandOutputOptions { }

interface DoctorCommandOptions extends CommandOutputOptions {
	quiet?: boolean;
}

interface ValidateWorkspaceCommandOptions extends CommandOutputOptions {
	quiet?: boolean;
	glob?: string;
}

interface WorkspaceValidationEntry {
	jobFile: string;
	ok: boolean;
	totalSteps: number;
	errors: number;
	warnings: number;
	error?: string;
}

interface WorkspaceValidationReport {
	generatedAt: string;
	workspaceRoots: string[];
	totalJobs: number;
	passedJobs: number;
	failedJobs: number;
	entries: WorkspaceValidationEntry[];
}

interface CreatePresetJobCommandOptions extends CommandOutputOptions {
	preset?: string;
	file?: string;
	outDir?: string;
	jobPath?: string;
	quiet?: boolean;
}

interface SaveJobAsProfileCommandOptions extends CommandOutputOptions {
	name?: string;
	description?: string;
	jobFile?: string;
	quiet?: boolean;
}

export interface DisassembleAtInstructionEntry {
	address: string;         // VA in hex
	bytes: string;           // Hex with spaces (e.g. "48 89 5C 24 08")
	mnemonic: string;
	operands: string;
	comment: string;         // Resolved reference or ""
	size: number;
	isContext: boolean;      // true for context instructions
	role: DisassemblyInstructionRole;
}

export interface DisassembleAtResult {
	status: 'ok' | 'partial';
	semanticWarning?: string;
	address: string;         // VA requested in hex
	effectiveAddress?: string;
	addressMapping?: ReturnType<DisassemblerEngine['getAddressMapping']>;
	effectiveAddressMapping?: ReturnType<DisassemblerEngine['getAddressMapping']>;
	count: number;           // Requested count
	effectiveCount: number;  // Count accepted for this page
	countingDomain: 'byte-range' | 'instruction-count';
	context: number;         // Requested context
	contextRecovery: ContextRecoverySummary;
	actualCount: number;     // Total instructions returned (context + main)
	returnedMainCount: number;
	semanticInstructionCount: number;
	paddingInstructionCount: number;
	unclassifiedInstructionCount: number;
	analysisClosure: {
		status: FunctionAnalysisMaterialization['status'] | 'display-only';
		functionAddress?: string;
		bodyStatus: FunctionBodyStatus;
		changed: boolean;
		auditUniverseChanged: boolean;
		instructionsAdded: number;
		engineGenerationBefore: number;
		engineGenerationAfter: number;
		sessionGenerationBefore?: number;
		sessionGenerationAfter?: number;
		reason: string;
	};
	truncated: boolean;
	truncationReason?: 'count-limit' | 'decode-failure';
	stopReason: DisassemblyStopReason;
	pageFillRatio: number;
	requestedWindowCoverage: number;
	decodedByteCoverage?: number;
	requestedByteRange?: {
		start: string;
		endExclusive: string;
		size: number;
		reached: boolean;
		byteCoverage: number;
		source: 'explicit-endExclusive' | 'function-boundary';
	};
	functionBoundary?: {
		start: string;
		endExclusive: string;
		/** @deprecated Alias of endExclusive for 3.8.x consumers. */
		end: string;
		semanticEnd?: string;
		paddingBytes?: number;
		size: number;
		source: 'function-table' | 'pdata' | 'recommended' | 'none';
		reached: boolean;
		crossed: boolean;
		byteCoverage: number;
	};
	maxCount: number;
	nextAddress?: string;
	instructions: DisassembleAtInstructionEntry[];
	generatedAt: string;     // ISO 8601 timestamp
}

export interface ContextRecoverySummary {
	status: 'complete' | 'partial' | 'unavailable';
	requestedCount: number;
	returnedCount: number;
	contiguous: boolean;
	targetAddress: string;
	reason?: 'disabled' | 'binary-boundary' | 'insufficient-contiguous-predecessors' | 'no-contiguous-predecessor';
}

/**
 * Builds a flat lookup map from ImportLibrary[] for O(1) address-based import resolution.
 * Each import function address maps to its library name and function name.
 */
export function buildImportLookup(
	imports: ImportLibrary[]
): Map<number, { library: string; functionName: string }> {
	const lookup = new Map<number, { library: string; functionName: string }>();
	for (const lib of imports) {
		for (const fn of lib.functions) {
			lookup.set(fn.address, { library: lib.name, functionName: fn.name });
		}
	}
	return lookup;
}

/**
 * Pure function that resolves the comment for a disassembled instruction based on
 * reference maps (strings, functions, imports) and user comments.
 *
 * Priority (descending): string > import(direct target) > function > raw address >
 * IAT indirect call/jmp > empty. User comments are prepended with " | " separator when a
 * reference also exists.
 *
 * v3.8.5: the LAST resort (only when nothing higher matched) is the PE IAT indirect-call name.
 * This mirrors the engine post-pass `applyIatCallNames` so the interactive `disassembleAtInstruction`
 * path -- which re-disassembles fresh via `disassembleRange` and derives comments here -- surfaces
 * `call ReadFile` for `call dword ptr [0x402000]` (PE32) / `call qword ptr [rip+disp]` (PE64)
 * exactly like the function-view path. It is kept LOWEST priority and never overrides an existing
 * string-xref / function / direct-import / user comment. PE-gated (`isPE`); no-op for ELF.
 */
export function resolveInstructionComment(
	instruction: { targetAddress?: number; comment?: string; mnemonic?: string; opStr?: string; size?: number; address?: number },
	strings: Map<number, { string: string; address: number }>,
	functions: Map<number, { name: string; address: number }>,
	imports: { name: string; functions: { name: string; address: number }[] }[],
	userComments: Map<number, string>,
	instructionAddress: number,
	isPE: boolean = false
): string {
	let resolved = '';

	const target = instruction.targetAddress;
	if (target !== undefined && target !== null) {
		const strRef = strings.get(target);
		if (strRef) {
			resolved = `-> "${strRef.string}" (0x${target.toString(16).toUpperCase()})`;
		} else {
			// Build import lookup inline for correctness — caller may also use buildImportLookup for batch
			let importMatch: { library: string; functionName: string } | undefined;
			for (const lib of imports) {
				for (const fn of lib.functions) {
					if (fn.address === target) {
						importMatch = { library: lib.name, functionName: fn.name };
						break;
					}
				}
				if (importMatch) {
					break;
				}
			}

			if (importMatch) {
				resolved = `-> import:${importMatch.library}!${importMatch.functionName} (0x${target.toString(16).toUpperCase()})`;
			} else {
				const funcRef = functions.get(target);
				if (funcRef) {
					resolved = `-> func:${funcRef.name} (0x${target.toString(16).toUpperCase()})`;
				} else {
					resolved = `-> 0x${target.toString(16).toUpperCase()}`;
				}
			}
		}
	}

	// v3.8.5: lowest-priority PE IAT indirect call/jmp name. Only when nothing above resolved
	// (memory-indirect `[...]` operands carry NO targetAddress, so the block above never fires for
	// them), and never overriding a higher reference. Same `<dll>!<api>` format as applyIatCallNames.
	if (!resolved && isPE) {
		const m = (instruction.mnemonic ?? '').toLowerCase();
		const op = instruction.opStr ?? '';
		if ((m === 'call' || m === 'jmp') && op.indexOf('[') >= 0) {
			const iatVA = decodeIatOperandVA(op, instruction.address ?? instructionAddress, instruction.size ?? 0);
			if (iatVA !== undefined) {
				for (const lib of imports) {
					const hit = lib.functions.find(fn => (fn.address >>> 0) === (iatVA >>> 0));
					if (hit) {
						resolved = `${lib.name}!${hit.name}`;
						break;
					}
				}
			}
		}
	}

	const userComment = userComments.get(instructionAddress);
	if (userComment) {
		if (resolved) {
			return `${userComment} | ${resolved}`;
		}
		return userComment;
	}

	return resolved;
}

export const DEFAULT_COUNT = 30;
export const DEFAULT_CONTEXT = 0;
export const MAX_INSTRUCTION_SIZE_X86 = 15;  // bytes
export const MAX_INSTRUCTION_SIZE_ARM = 4;   // bytes

/**
 * Parses and validates the arguments for the disassembleAtHeadless command.
 * Converts hex address string to number, applies defaults for count/context,
 * and passes through file, output, quiet as-is.
 */
/**
 * v3.8.0-nightly — Trampoline following. When the target of a decompile/lift
 * operation is a single unconditional JMP (typical of packer unpacking stubs,
 * VMP/Themida wrapped entries, and anti-analysis binaries like `vgk.sys` whose
 * exposed entry is `JMP virtualized_code`), follow the JMP chain to the real
 * entry. Stops at:
 *   - a non-JMP / conditional JMP / CALL / RET
 *   - a target outside the loaded binary (import thunks, external fixups)
 *   - a cycle
 *   - 8 hops (safety cap)
 *
 * Returns the final resolved target + the chain of hops taken.
 */
export async function followTrampolineChain(
	engine: any /* DisassemblerEngine */,
	startAddress: number,
	maxHops = 8
): Promise<{ target: number; hops: Array<{ from: number; to: number; mnemonic: string }> }> {
	const hops: Array<{ from: number; to: number; mnemonic: string }> = [];
	const visited = new Set<number>();
	let current = startAddress;

	const baseAddress = typeof engine.getBaseAddress === 'function' ? engine.getBaseAddress() : 0;
	const bufferSize = typeof engine.getBufferSize === 'function' ? engine.getBufferSize() : 0;
	if (bufferSize === 0) { return { target: startAddress, hops: [] }; }
	const bufferEnd = baseAddress + bufferSize;

	for (let hop = 0; hop < maxHops; hop++) {
		if (visited.has(current)) { break; }
		visited.add(current);

		let insns: Array<{ mnemonic: string; opStr: string; isJump?: boolean; isCall?: boolean; isRet?: boolean; isConditional?: boolean; targetAddress?: number; size: number }>;
		try {
			insns = await engine.disassembleRange(current, 16);
		} catch {
			break;
		}
		if (!insns || insns.length === 0) { break; }

		const first = insns[0];
		if (!first.isJump || first.isConditional || first.isCall || first.isRet) { break; }
		if (first.targetAddress === undefined || first.targetAddress === 0) { break; }
		const next = Number(first.targetAddress);
		if (next < baseAddress || next >= bufferEnd) { break; }

		hops.push({ from: current, to: next, mnemonic: `${first.mnemonic} ${first.opStr}`.trim() });
		current = next;
	}

	return { target: current, hops };
}

export const MAX_DISASSEMBLE_AT_COUNT = 10000;

export interface ParsedDisassembleAtAddress {
	address: number;
	count: number;
	effectiveCount: number;
	countingDomain: 'byte-range' | 'instruction-count';
	endExclusive?: number;
	stopAtFunctionBoundary: boolean;
	context: number;
	file?: string;
	output?: { path: string };
	quiet?: boolean;
}

function parseRequiredHexAddress(rawAddress: unknown, field: 'address' | 'endExclusive'): number {
	const message = field === 'address'
		? "disassembleAtHeadless requires a valid hex 'address' argument (e.g. '0x401000')."
		: "disassembleAtHeadless: 'endExclusive' must be a valid hex address.";
	if (rawAddress === undefined || rawAddress === null || rawAddress === '' || typeof rawAddress !== 'string') {
		throw new Error(message);
	}
	let hexStr = rawAddress;
	if (hexStr.startsWith('0x') || hexStr.startsWith('0X')) {
		hexStr = hexStr.slice(2);
	}
	if (hexStr.length === 0 || !/^[0-9a-fA-F]+$/.test(hexStr)) {
		throw new Error(message);
	}
	const parsed = parseInt(hexStr, 16);
	if (!Number.isSafeInteger(parsed)) {
		throw new Error(message);
	}
	return parsed;
}

export function parseDisassembleAtAddress(args: any): ParsedDisassembleAtAddress {
	// --- address (required, hex string) ---
	const address = parseRequiredHexAddress(args?.address, 'address');
	if (args?.stopAtFunctionBoundary !== undefined && typeof args.stopAtFunctionBoundary !== 'boolean') {
		throw new Error("disassembleAtHeadless: 'stopAtFunctionBoundary' must be a boolean.");
	}
	const stopAtFunctionBoundary = args?.stopAtFunctionBoundary === true;
	const endExclusive = args?.endExclusive !== undefined && args?.endExclusive !== null
		? parseRequiredHexAddress(args.endExclusive, 'endExclusive')
		: undefined;
	if (endExclusive !== undefined && endExclusive <= address) {
		throw new Error("disassembleAtHeadless: 'endExclusive' must be greater than 'address'.");
	}
	const countingDomain = endExclusive !== undefined || stopAtFunctionBoundary
		? 'byte-range' as const
		: 'instruction-count' as const;

	// In byte-range mode count is only a decoder safety ceiling, never the scope.
	let count = countingDomain === 'byte-range' ? MAX_DISASSEMBLE_AT_COUNT : DEFAULT_COUNT;
	if (args?.count !== undefined && args?.count !== null) {
		count = args.count;
		if (typeof count !== 'number' || !Number.isInteger(count) || count <= 0) {
			throw new Error("disassembleAtHeadless: 'count' must be a positive integer.");
		}
	}

	// --- context (optional, non-negative integer, default 0) ---
	let context = DEFAULT_CONTEXT;
	if (args?.context !== undefined && args?.context !== null) {
		context = args.context;
		if (typeof context !== 'number' || !Number.isInteger(context) || context < 0) {
			throw new Error("disassembleAtHeadless: 'context' must be a non-negative integer.");
		}
	}

	return {
		address,
		count,
		effectiveCount: Math.min(count, MAX_DISASSEMBLE_AT_COUNT),
		countingDomain,
		...(endExclusive !== undefined ? { endExclusive } : {}),
		stopAtFunctionBoundary,
		context,
		file: args?.file,
		output: args?.output,
		quiet: args?.quiet,
	};
}

/**
 * Computes context instructions by backtracking from the target address.
 * Disassembles forward from an estimated start point and returns the last
 * `contextCount` instructions whose address is strictly before `targetAddress`.
 *
 * When the backtrack start falls before the binary base address, the base
 * address is used instead, returning fewer context instructions than requested.
 */
export async function computeContextInstructions(
	engine: DisassemblerEngine,
	targetAddress: number,
	contextCount: number,
	maxInstructionSize: number
): Promise<Instruction[]> {
	return (await computeContextRecovery(engine, targetAddress, contextCount, maxInstructionSize)).instructions;
}

export async function computeContextRecovery(
	engine: DisassemblerEngine,
	targetAddress: number,
	contextCount: number,
	maxInstructionSize: number
): Promise<{ instructions: Instruction[]; summary: ContextRecoverySummary }> {
	const targetHex = `0x${targetAddress.toString(16).toUpperCase()}`;
	if (contextCount <= 0) {
		return {
			instructions: [],
			summary: { status: 'complete', requestedCount: 0, returnedCount: 0, contiguous: true, targetAddress: targetHex, reason: 'disabled' }
		};
	}

	const baseAddress = engine.getBaseAddress();
	const backtrackBytes = contextCount * maxInstructionSize;
	let startAddr = targetAddress - backtrackBytes;

	// Clamp to base address when backtrack goes before the buffer start
	if (startAddr < baseAddress) {
		startAddr = baseAddress;
	}

	const rangeSize = targetAddress - startAddr;
	if (rangeSize <= 0) {
		return {
			instructions: [],
			summary: { status: 'partial', requestedCount: contextCount, returnedCount: 0, contiguous: true, targetAddress: targetHex, reason: 'binary-boundary' }
		};
	}

	const allInstructions = await engine.disassembleRange(startAddr, rangeSize);

	// Keep only instructions strictly before the target address. An arbitrary
	// byte estimate can decode a valid prefix and then stop at an undecodable
	// barrier; never concatenate that prefix with the requested target.
	const beforeTarget = allInstructions.filter(instr => instr.address < targetAddress);
	const contiguousReversed: Instruction[] = [];
	let expectedEnd = targetAddress;
	for (let i = beforeTarget.length - 1; i >= 0 && contiguousReversed.length < contextCount; i--) {
		const instr = beforeTarget[i];
		const instructionEnd = instr.address + instr.size;
		if (instructionEnd === expectedEnd) {
			contiguousReversed.push(instr);
			expectedEnd = instr.address;
			continue;
		}
		if (instructionEnd < expectedEnd) {
			break;
		}
	}
	const instructions = contiguousReversed.reverse();
	if (instructions.length === 0) {
		return {
			instructions,
			summary: {
				status: 'unavailable', requestedCount: contextCount, returnedCount: 0,
				contiguous: false, targetAddress: targetHex, reason: 'no-contiguous-predecessor'
			}
		};
	}
	return {
		instructions,
		summary: {
			status: instructions.length === contextCount ? 'complete' : 'partial',
			requestedCount: contextCount,
			returnedCount: instructions.length,
			contiguous: true,
			targetAddress: targetHex,
			...(instructions.length === contextCount ? {} : { reason: 'insufficient-contiguous-predecessors' as const })
		}
	};
}


export function activate(context: vscode.ExtensionContext): void {
	// Issue #25: prime the Job Queue worker pool from the
	// hexcore.pipeline.queue.poolSize setting BEFORE anything lazily creates
	// the singleton with the default. The pool size is fixed for the life of
	// the extension host -- a setting change applies on the NEXT reload (we do
	// NOT resize a live pool; in-flight jobs finish on their current workers).
	const configuredPoolSize = vscode.workspace
		.getConfiguration('hexcore.pipeline.queue')
		.get<number>('poolSize', 2);
	getJobQueueManagerInstance(configuredPoolSize);
	context.subscriptions.push(
		vscode.workspace.onDidChangeConfiguration(e => {
			if (e.affectsConfiguration('hexcore.pipeline.queue.poolSize')) {
				console.warn(
					'[HexCore] hexcore.pipeline.queue.poolSize changed; the new pool ' +
					'size takes effect on the NEXT extension reload. The live worker ' +
					'pool is not resized and in-flight jobs finish on their current workers.'
				);
				void vscode.window.showWarningMessage(
					'HexCore: queue pool size change takes effect on the next window reload.'
				);
			}
		})
	);

	// Emulator switcher — UX entry point for the hexcore.emulator setting.
	// Status bar item + QuickPick command so users don't need to hand-edit
	// settings.json to switch between Azoth, legacy debugger, or both.
	setupEmulatorSwitcher(context);

	// Project Pythia — Oracle Hook (Issue #17). Registers three commands
	// under `hexcore.oracle.*`. Gated by `hexcore.oracle.enabled` setting
	// which is false by default, so this is a no-op for regular users.
	void import('./oracle/oracleCommands').then((m) => m.registerOracleCommands(context));

	// Use Factory to get the initial global engine (or specific if we knew context)
	const factory = DisassemblerFactory.getInstance();
	const engine = factory.getEngine(); // Default global engine for now

	// Event emitter for synchronization between views
	const onDidChangeActiveEditor = new vscode.EventEmitter<string | undefined>();

	const disasmEditorProvider = new DisassemblyEditorProvider(context, engine, onDidChangeActiveEditor);
	const functionProvider = new FunctionTreeProvider(engine);
	const stringRefProvider = new StringRefProvider(engine);
	const sectionProvider = new SectionTreeProvider(engine);
	const importProvider = new ImportTreeProvider(engine);
	const exportProvider = new ExportTreeProvider(engine);
	const graphViewProvider = new GraphViewProvider(context.extensionUri, engine);

	const ensureAssemblerAvailable = async (): Promise<boolean> => {
		const availability = await engine.getAssemblerAvailability();
		if (availability.available) {
			return true;
		}

		const detail = availability.error ? ` ${availability.error}` : '';
		vscode.window.showErrorMessage(
			vscode.l10n.t('LLVM MC engine is not available.{0}', detail)
		);
		return false;
	};

	const remillWrapper = new RemillWrapper();
	context.subscriptions.push({ dispose: () => remillWrapper.dispose() });
	vscode.commands.executeCommand('setContext', 'hexcore:remillAvailable', remillWrapper.isAvailable());

	const rellicWrapper = new RellicWrapper();
	context.subscriptions.push({ dispose: () => rellicWrapper.dispose() });
	vscode.commands.executeCommand('setContext', 'hexcore:rellicAvailable', rellicWrapper.isAvailable());

	const helixWrapper = new HelixWrapper();
	context.subscriptions.push({ dispose: () => helixWrapper.dispose() });

	// HQL scanner output channel -- created lazily on first interactive scan so
	// pure-headless sessions never spawn an empty "HexCore HQL" channel.
	let hqlChannel: vscode.OutputChannel | undefined;
	const hqlOutputChannel = (): vscode.OutputChannel => {
		if (!hqlChannel) {
			hqlChannel = vscode.window.createOutputChannel('HexCore HQL');
			context.subscriptions.push(hqlChannel);
		}
		return hqlChannel;
	};

	// Cache PE data sections per-binary so the pipeline doesn't re-read the
	// .exe for every function it decompiles.  Keyed by absolute binary path;
	// `null` means the file isn't a PE (or we already failed to parse it).
	const peDataSectionsCache = new Map<string, PeDataSection[] | null>();
	const getDataSectionsFor = async (
		binaryPath: string | undefined
	): Promise<PeDataSection[] | undefined> => {
		if (!binaryPath) { return undefined; }
		const key = path.resolve(binaryPath);
		if (peDataSectionsCache.has(key)) {
			const cached = peDataSectionsCache.get(key);
			return cached === null ? undefined : cached;
		}
		try {
			const sections = await readPeDataSections(key);
			peDataSectionsCache.set(key, sections);
			return sections === null ? undefined : sections;
		} catch (err) {
			console.warn(`[helix] PE parse failed for ${key}:`, err);
			peDataSectionsCache.set(key, null);
			return undefined;
		}
	};

	// Issue #32 (HONESTY): detect a managed .NET (CIL) assembly before the native
	// x86 lift/decompile path runs. On a .NET PE the `.text` holds CIL + metadata, not
	// native machine code — lifting it as x86 produces the `_CorExeMain` thunk plus a
	// run of mis-decoded "add byte ptr [eax], al" (zero padding) and Helix then emits a
	// confident `void entry_point(void){return;}` "stub function" at ~85%. A confident
	// fake reads as success and hides the entire managed program, so the native path must
	// instead surface an honest "not applicable; use an IL decompiler" signal (D4 honesty).
	//
	type ManagedDotNetTarget =
		| { kind: 'clr'; clr: import('./disassemblerEngine').CLRHeader }
		| { kind: 'single-file' };

	// Returns the target shape when the input is managed, else undefined. Classic managed
	// assemblies are identified by PE data directory 14. Self-contained single-file apps
	// are native apphosts without that directory, so they require the bundle-marker probe.
	const detectManagedDotNet = async (
		options: Record<string, unknown>
	): Promise<ManagedDotNetTarget | undefined> => {
		const filePath = typeof options.file === 'string' ? options.file : undefined;
		const candidatePath = filePath ?? engine.getFilePath();
		if (candidatePath && isSingleFileBundle(candidatePath)) {
			return { kind: 'single-file' };
		}
		if (filePath) {
			try {
				if (!engine.isFileLoaded() || engine.getFilePath() !== filePath) {
					await engine.loadFile(filePath);
				}
			} catch (err) {
				console.warn(`[helix] managed-dotnet probe: load failed for ${filePath}:`, err);
				return undefined;
			}
		}
		const clr = engine.getPEDataDirectories().clr;
		return clr ? { kind: 'clr', clr } : undefined;
	};

	// Issue #32: the honest managed-code marker written in place of the native stub. Plain
	// C comments so it round-trips through the .helix.c consumers without a fake function.
	const buildManagedDotNetMarker = (target: ManagedDotNetTarget): string => {
		const detail = target.kind === 'clr'
			? [
				'// This target carries a CLR Runtime Header (PE data directory 14), so its',
				`// .text section holds CIL bytecode + .NET metadata (runtime v${target.clr.majorRuntimeVersion}.${target.clr.minorRuntimeVersion}), not`,
				'// native machine code. The native Remill→Helix pipeline cannot decompile it;',
			]
			: [
				'// This target is a .NET single-file bundle: its native apphost wraps one or',
				'// more managed assemblies in an appended payload. Decompiling only the apphost',
				'// would hide the actual application, so the native pipeline is not applicable;',
			];
		return [
			'// ─────────────────────────────────────────────────────────────',
			'// Managed .NET (CIL) assembly — native x86 decompile not applicable',
			'// ─────────────────────────────────────────────────────────────',
			'//',
			...detail,
			'// disassembling the entry point yields the _CorExeMain thunk followed by',
			'// metadata bytes that mis-decode as "add byte ptr [eax], al".',
			'//',
			'// Use a .NET/IL decompiler (ILSpy / dnSpyEx / ilspycmd / dotPeek) on this',
			'// assembly. (HexCore issue #32: do not emit a confident native stub here.)',
			''
		].join('\n');
	};

	const souperWrapper = new SouperWrapper();
	context.subscriptions.push({ dispose: () => souperWrapper.dispose() });
	vscode.commands.executeCommand('setContext', 'hexcore:helixAvailable', helixWrapper.isAvailable());

	let activeInvestigationId: string | undefined;
	const resolveFindingFunction = async (
		store: SessionStore,
		finding: InvestigationFindingEntry
	): Promise<{ address: string; name: string }> => {
		let functionAddress = finding.function_address;
		let functionName = finding.function_name;
		if (!functionAddress) {
			const referenceAddress = parseAddressValue(finding.reference_address ?? undefined);
			if (referenceAddress === undefined) {
				throw new Error('This finding has no code reference from which to resolve a function.');
			}
			const resolvedAddress = await engine.findFunctionStartForAddress(referenceAddress);
			if (resolvedAddress === undefined) {
				throw new Error(
					`Function boundary unresolved for ${finding.reference_address}. Run Analyze and try again.`
				);
			}
			if (!engine.getFunctionAt(resolvedAddress)) {
				await engine.analyzeFunction(resolvedAddress, `sub_${resolvedAddress.toString(16).toUpperCase()}`);
				functionProvider.refresh();
			}
			functionAddress = `0x${resolvedAddress.toString(16).toUpperCase()}`;
			functionName = engine.getFunctionName(resolvedAddress) ?? `sub_${resolvedAddress.toString(16).toUpperCase()}`;
			store.setInvestigationFindingFunction(finding.id, functionAddress, functionName);
		}

		const numericAddress = parseAddressValue(functionAddress);
		if (numericAddress === undefined) {
			throw new Error(`Invalid function address stored for finding ${finding.id}.`);
		}
		return {
			address: functionAddress,
			name: functionName ?? engine.getFunctionName(numericAddress) ?? `sub_${numericAddress.toString(16).toUpperCase()}`,
		};
	};

	const getAnalysisCenterSnapshot = async (): Promise<AnalysisCenterSnapshot> => {
		const [disassembler, assembler, jobUris, targetUris] = await Promise.all([
			engine.getDisassemblerAvailability(),
			engine.getAssemblerAvailability(),
			vscode.workspace.findFiles(
				'**/*.hexcore_job.json',
				'**/{node_modules,.git,out,dist}/**',
				20
			),
			vscode.workspace.findFiles(
				'**/*.{exe,dll,sys,ocx,scr,cpl,elf,so,a,o,ko,bin,raw,dmp}',
				'**/{node_modules,.git,out,dist,hexcore-reports,hexcore-reports-*}/**',
				80
			)
		]);
		const fileInfo = engine.getFileInfo();
		const loaded = engine.isFileLoaded();
		const filePath = engine.getFilePath() ?? '';
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
		const formatJobPath = (uri: vscode.Uri): string => workspaceRoot
			? path.relative(workspaceRoot, uri.fsPath)
			: uri.fsPath;
		const sessionStore = engine.getSessionStore();
		maybeRecordSessionManifest(sessionStore, { capstone: disassembler.available, llvmMc: assembler.available });
		const analysisTarget = sessionStore?.getAnalysisTarget() ?? null;
		const analysisSession = sessionStore?.getAnalysisSession() ?? null;
		const investigations = sessionStore?.getRecentInvestigations(20) ?? [];
		const visibleInvestigationId = investigations.some(item => item.id === activeInvestigationId)
			? activeInvestigationId
			: investigations[0]?.id;
		const recentFindings = visibleInvestigationId
			? sessionStore?.getInvestigationFindings(visibleInvestigationId) ?? []
			: [];
		const toFinding = (finding: typeof recentFindings[number]): AnalysisFinding => ({
			id: finding.id,
			investigationId: finding.investigation_id,
			query: finding.query,
			label: finding.label,
			stringAddress: finding.string_address,
			referenceAddress: finding.reference_address,
			functionAddress: finding.function_address,
			functionName: finding.function_name,
			encoding: finding.encoding,
			saved: finding.saved === 1
		});
		const status = (
			id: string,
			label: string,
			available: boolean,
			detail?: string
		): AnalysisCenterSnapshot['engines'][number] => ({
			id,
			label,
			status: available ? 'ready' : 'unavailable',
			detail: available ? 'Native runtime loaded' : (detail || 'Native runtime unavailable')
		});

		return {
			loaded,
			fileName: loaded ? engine.getFileName() : '',
			filePath,
			format: fileInfo?.format ?? 'Not detected',
			architecture: String(fileInfo?.architecture ?? engine.getArchitecture()),
			entryPoint: fileInfo?.entryPoint ?? 0,
			baseAddress: fileInfo?.baseAddress ?? engine.getBaseAddress(),
			imageSize: fileInfo?.imageSize ?? engine.getBufferSize(),
			metrics: {
				functions: engine.getFunctions().length,
				sections: engine.getSections().length,
				imports: engine.getImports().reduce((total, library) => total + library.functions.length, 0),
				exports: engine.getExports().length,
				strings: engine.getStrings().length,
				bookmarks: engine.getAllBookmarks().length,
			},
			engines: [
				status('capstone', 'Capstone', disassembler.available, disassembler.error),
				status('llvm-mc', 'LLVM MC', assembler.available, assembler.error),
				status('remill', 'Remill', remillWrapper.isAvailable(), remillWrapper.getLastError()),
				status('helix', 'Helix', helixWrapper.isAvailable(), helixWrapper.getLastError()),
				status('souper', 'Souper', souperWrapper.isAvailable(), souperWrapper.getLastError()),
				{
					id: 'rellic',
					label: 'Rellic',
					status: 'disabled',
					detail: 'Disabled compatibility backend'
				}
			],
			emulator: readCurrentEmulator(),
			workspaceName: vscode.workspace.name ?? '',
			jobFiles: jobUris.map(formatJobPath).sort((a, b) => a.localeCompare(b)),
			sessionPath: loaded ? path.join(path.dirname(filePath), '.hexcore_session.db') : '',
			sessionPersistence: loaded && engine.getSessionStore() !== undefined,
			analysisTarget,
			analysisSession,
			workspaceTargets: targetUris.map(uri => ({
				name: path.basename(uri.fsPath),
				path: uri.fsPath,
				relativePath: formatJobPath(uri)
			})).sort((a, b) => a.relativePath.localeCompare(b.relativePath)),
			investigations: investigations.map(item => ({
				id: item.id,
				title: item.title,
				kind: item.kind,
				query: item.query,
				status: item.status,
				resultCount: item.result_count,
				createdAt: item.created_at
			})),
			recentFindings: recentFindings.map(toFinding),
			savedFindings: (sessionStore?.getSavedInvestigationFindings(250) ?? []).map(toFinding),
		};
	};

	// 3.8.4 C3: record the engine manifest once per session DB. Best-effort
	// observability — recording must never break analysis or the UI.
	const maybeRecordSessionManifest = (
		sessionStore: SessionStore | undefined,
		nativeAvailability: { capstone: boolean; llvmMc: boolean }
	): void => {
		if (!sessionStore || sessionStore.getEngineManifest()) {
			return;
		}
		try {
			const engines: AnalysisEngineIdentity[] = [];
			const extensionVersion = vscode.extensions.getExtension('hikarisystem.hexcore-disassembler')?.packageJSON?.version;
			if (typeof extensionVersion === 'string' && extensionVersion.length > 0) {
				engines.push({ id: 'hikarisystem.hexcore-disassembler', version: extensionVersion });
			}
			const helixVersion = helixWrapper.isAvailable() ? helixWrapper.getVersion() : undefined;
			if (helixVersion) {
				engines.push({ id: 'hikarisystem.hexcore-helix', version: helixVersion });
			}
			const config = vscode.workspace.getConfiguration('hexcore');
			sessionStore.recordEngineManifest(engines, {
				'pipeline.queue.poolSize': config.get('pipeline.queue.poolSize'),
				'disassembler.defaultArchitecture': config.get('disassembler.defaultArchitecture'),
				'disassembler.syntaxFlavor': config.get('disassembler.syntaxFlavor'),
				'disassembler.maxFunctions': config.get('disassembler.maxFunctions'),
				'disassembler.maxFunctionSize': config.get('disassembler.maxFunctionSize'),
				engineAvailability: {
					capstone: nativeAvailability.capstone,
					'llvm-mc': nativeAvailability.llvmMc,
					remill: remillWrapper.isAvailable(),
					helix: helixWrapper.isAvailable(),
					souper: souperWrapper.isAvailable(),
				},
			});
		} catch {
			// Manifest recording is diagnostics, not a gate.
		}
	};

	const analysisCenterProvider = new AnalysisCenterProvider(
		getAnalysisCenterSnapshot,
		async (request: AnalysisCenterRequest): Promise<AnalysisActionResult | void> => {
			const currentFile = engine.getFilePath();
			const currentUri = currentFile ? vscode.Uri.file(currentFile) : undefined;
			if (request.type === 'loadTarget') {
				const uri = vscode.Uri.file(request.path);
				if (!vscode.workspace.getWorkspaceFolder(uri) || !fs.existsSync(uri.fsPath) || !fs.statSync(uri.fsPath).isFile()) {
					throw new Error('The selected target is not a readable file in this workspace.');
				}
				await vscode.commands.executeCommand('vscode.openWith', uri, DisassemblyEditorProvider.viewType);
				activeInvestigationId = undefined;
				return { title: 'Binary loaded', message: uri.fsPath };
			}

			if (request.type === 'runInvestigation') {
				if (!engine.isFileLoaded()) {
					throw new Error('Load a binary before running an investigation.');
				}
				const store = engine.getSessionStore();
				if (!store) {
					throw new Error('Session persistence is unavailable for this binary.');
				}
				const queries = resolveInvestigationQueries(request.preset, request.query);
				if (queries.length === 0) {
					throw new Error('Enter a string or term to investigate.');
				}
				const investigationId = crypto.randomUUID();
				const matches: Array<{
					query: string; address: number; string: string; encoding: string; references: number[];
				}> = [];
				for (const query of queries) {
					const results = await engine.searchStringReferences(query, 500);
					for (const result of results) {
						matches.push({ query, ...result });
					}
				}
				const findings = buildStringInvestigationFindings(
					investigationId,
					matches,
					engine.getFunctions(),
					250,
					{ target: store.getAnalysisTarget() }
				);
				const presetTitles: Record<InvestigationPreset, string> = {
					custom: request.query.trim(),
					health: 'Health / state',
					'anti-debug': 'Anti-debug',
					network: 'Network / URLs',
					credentials: 'Credentials / secrets'
				};
				const truncated = findings.length >= 250;
				store.recordInvestigation({
					id: investigationId,
					title: presetTitles[request.preset] || 'String investigation',
					kind: 'string-reference',
					query: queries.join(', '),
					status: truncated ? 'complete-truncated' : 'complete'
				}, findings);
				activeInvestigationId = investigationId;
				return {
					title: 'Investigation complete',
					message: `${truncated ? 'First ' : ''}${findings.length} findings recorded in ${store.getDbPath()}`
				};
			}

			if (request.type === 'openInvestigation') {
				const store = engine.getSessionStore();
				const exists = store?.getRecentInvestigations(100).some(item => item.id === request.id);
				if (!exists) {
					throw new Error('This investigation is no longer available in the active session.');
				}
				activeInvestigationId = request.id;
				return { title: 'Investigation opened', message: `${store!.getInvestigationFindings(request.id).length} findings` };
			}

			if (request.type === 'createInvestigationJob') {
				if (!currentFile || !engine.isFileLoaded()) {
					throw new Error('Load a binary before creating an investigation job.');
				}
				const store = engine.getSessionStore();
				const finding = store?.getInvestigationFinding(request.findingId);
				if (!store || !finding || finding.saved !== 1) {
					throw new Error('Select a finding that is saved in the active session.');
				}
				assertFindingMatchesActiveTarget(request.findingId, store.getAnalysisTarget());
				const targetWorkspaceFolder = vscode.workspace.getWorkspaceFolder(vscode.Uri.file(currentFile));
				const workspaceFolder = targetWorkspaceFolder ?? vscode.workspace.workspaceFolders?.[0];
				if (!workspaceFolder) {
					throw new Error('Open a workspace before creating a reusable job.');
				}

				const resolved = await resolveFindingFunction(store, finding);
				const functionInfo = engine.getFunctionAt(parseAddressValue(resolved.address)!);
				const instructionCount = Math.max(150, Math.min(10000, (functionInfo?.instructions.length ?? 268) + 32));
				const slug = sanitizeInvestigationJobName(request.name);
				const jobsDirectory = path.join(workspaceFolder.uri.fsPath, 'hexcore-jobs');
				const outputDirectory = path.join(workspaceFolder.uri.fsPath, 'hexcore-reports', 'investigations', slug);
				const definition = createInvestigationJob({
					targetPath: targetWorkspaceFolder ? path.relative(jobsDirectory, currentFile) : currentFile,
					outputDirectory: path.relative(jobsDirectory, outputDirectory),
					name: request.name,
					query: finding.query,
					functionAddress: resolved.address,
					instructionCount,
				});
				const jobPath = path.join(jobsDirectory, definition.fileName);
				if (fs.existsSync(jobPath)) {
					throw new Error(`A job named "${definition.slug}" already exists.`);
				}
				fs.mkdirSync(jobsDirectory, { recursive: true });
				fs.writeFileSync(jobPath, `${JSON.stringify(definition.job, null, 2)}\n`, { encoding: 'utf8', flag: 'wx' });
				return {
					title: 'Investigation job created',
					message: `${path.relative(workspaceFolder.uri.fsPath, jobPath)} queued; output: ${path.relative(workspaceFolder.uri.fsPath, outputDirectory)}`
				};
			}

			if (request.type === 'finding') {
				const store = engine.getSessionStore();
				const finding = store?.getInvestigationFinding(request.id);
				if (!store || !finding) {
					throw new Error('This finding is no longer available in the active session.');
				}
				assertFindingMatchesActiveTarget(request.id, store.getAnalysisTarget());
				if (request.action === 'save' || request.action === 'unsave') {
					store.setInvestigationFindingSaved(request.id, request.action === 'save');
					return {
						title: request.action === 'save' ? 'Finding saved' : 'Finding removed',
						message: finding.function_name || finding.label
					};
				}
				if (request.action === 'open') {
					const address = parseAddressValue(finding.reference_address ?? finding.function_address ?? undefined);
					if (address === undefined) {
						throw new Error('This finding has no code reference to open.');
					}
					await vscode.commands.executeCommand('hexcore.disasm.goToAddress', address);
					return { title: 'Reference opened', message: `0x${address.toString(16).toUpperCase()}` };
				}
				const resolved = await resolveFindingFunction(store, finding);
				await vscode.commands.executeCommand('hexcore.helix.decompile', {
					file: currentFile,
					address: resolved.address,
					quiet: false
				});
				return { title: 'Decompile complete', message: resolved.name };
			}

			switch (request.action) {
				case 'openBinary':
					await vscode.commands.executeCommand('hexcore.disasm.openFile');
					return { title: 'Binary opened', message: engine.getFilePath() ?? 'No target selected' };
				case 'analyze':
					const analysis = await vscode.commands.executeCommand<any>('hexcore.disasm.analyzeAll', currentUri);
					return analysis
						? {
							title: 'Analysis complete',
							message: `${analysis.newFunctions ?? 0} added, ${analysis.removedFunctions ?? 0} pruned; ${analysis.totalFunctions ?? engine.getFunctions().length} total. Cache: ${path.join(path.dirname(currentFile!), '.hexcore_session.db')}`
						}
						: { title: 'Analysis finished', message: `${engine.getFunctions().length} functions indexed` };
				case 'lift':
					await vscode.commands.executeCommand('hexcore.disasm.liftToIR');
					return { title: 'Lift complete', message: 'LLVM IR opened in the editor' };
				case 'decompile':
					await vscode.commands.executeCommand('hexcore.helix.decompile');
					return { title: 'Decompile complete', message: 'Helix output opened in the editor' };
				case 'hex':
					await vscode.commands.executeCommand('hexcore.openHexView', currentUri);
					return { title: 'Hex Viewer opened', message: path.basename(currentFile!) };
				case 'yara':
					await vscode.commands.executeCommand('hexcore.yara.scan', currentUri);
					return { title: 'YARA scan complete', message: path.basename(currentFile!) };
				case 'entropy':
					await vscode.commands.executeCommand('hexcore.entropy.analyze', currentUri);
					return { title: 'Entropy analysis complete', message: path.basename(currentFile!) };
				case 'pe':
					await vscode.commands.executeCommand('hexcore.peanalyzer.analyze', currentUri);
					return { title: 'PE analysis complete', message: path.basename(currentFile!) };
				case 'runJob':
					await vscode.commands.executeCommand('hexcore.pipeline.runJob');
					return { title: 'Pipeline finished', message: 'Job status refreshed' };
				case 'doctor':
					await vscode.commands.executeCommand('hexcore.pipeline.doctor');
					return { title: 'Pipeline Doctor complete', message: 'Diagnostic report opened' };
				case 'nativeStatus':
					await vscode.commands.executeCommand('hexcore.disasm.nativeStatus');
					return { title: 'Engine status refreshed', message: 'Native runtime checks complete' };
			}
			analysisCenterProvider.refresh();
		}
	);
	context.subscriptions.push(analysisCenterProvider);

	let shownExperimentalNotice = false;

	const showNativeStatus = async (): Promise<void> => {
		const disassembler = await engine.getDisassemblerAvailability();
		const assembler = await engine.getAssemblerAvailability();
		const remillAvailable = remillWrapper.isAvailable();
		const helixAvailable = helixWrapper.isAvailable();
		const souperAvailable = souperWrapper.isAvailable();

		if (disassembler.available && assembler.available && remillAvailable && helixAvailable && souperAvailable) {
			vscode.window.showInformationMessage(
				vscode.l10n.t('Active native engines are available for this session (Capstone + LLVM MC + Remill + Helix + Souper). Rellic is disabled compatibility scope.')
			);
			return;
		}

		const parts: string[] = [];
		if (!disassembler.available) {
			const fallbackNote = disassembler.fallbackMode === 'basic-decoder'
				? vscode.l10n.t(' (fallback: basic decoder)')
				: disassembler.fallbackMode === 'raw-byte'
					? vscode.l10n.t(' (fallback: raw byte directives)')
					: '';
			parts.push(
				vscode.l10n.t('Capstone: {0}{1}', disassembler.error ?? vscode.l10n.t('Unavailable'), fallbackNote)
			);
		}
		if (!assembler.available) {
			parts.push(
				vscode.l10n.t('LLVM MC: {0}', assembler.error ?? vscode.l10n.t('Unavailable'))
			);
		}
		if (!remillAvailable) {
			parts.push(
				vscode.l10n.t('Remill: {0}', remillWrapper.getLastError() ?? vscode.l10n.t('Unavailable'))
			);
		}
		if (!helixAvailable) {
			parts.push(
				vscode.l10n.t('Helix: {0}', helixWrapper.getLastError() ?? vscode.l10n.t('Unavailable'))
			);
		}
		if (!souperAvailable) {
			parts.push(
				vscode.l10n.t('Souper: {0}', souperWrapper.getLastError() ?? vscode.l10n.t('Unavailable'))
			);
		}

		vscode.window.showWarningMessage(
			vscode.l10n.t('Native engine status: {0}', parts.join(' | '))
		);
	};

	const pipelineRunner = new AutomationPipelineRunner();
	const semanticInvocation = (arg: unknown): Record<string, unknown> & SemanticCommandInvocationOptions =>
		isRecord(arg) ? arg as Record<string, unknown> & SemanticCommandInvocationOptions : {};
	const selectedSemanticFunctionIdentity = (): string | undefined => {
		const address = disasmEditorProvider.getCurrentFunctionAddress()
			?? graphViewProvider.getCurrentFunctionAddress();
		return address === undefined ? undefined : `0x${address.toString(16)}`;
	};
	const semanticFunctionIdentity = (
		options: Record<string, unknown>,
		label = 'functionIdentity',
	): string => {
		const raw = options.functionIdentity ?? options.functionAddress ?? options.address;
		if (typeof raw === 'string' && raw.trim().length > 0) {
			return raw.trim();
		}
		if (typeof raw === 'number' && Number.isSafeInteger(raw) && raw >= 0) {
			return `0x${raw.toString(16)}`;
		}
		const selected = selectedSemanticFunctionIdentity();
		if (selected) { return selected; }
		throw new Error(`Semantic command requires ${label} or a selected function.`);
	};
	const semanticService = async (options: SemanticCommandInvocationOptions) =>
		prepareSemanticCommandService(engine, options.file, session => ({
			producer: 'hexcore-disassembler:types-command-r32',
			callbacks: semanticCommandCallbacks(session, engine),
		}));
	const prepareReferenceGraphTarget = async (options: ReferenceGraphCommandInvocationOptions): Promise<void> => {
		if (typeof options.file === 'string' && options.file.trim().length > 0) {
			const requested = path.resolve(options.file);
			if (engine.getFilePath() !== requested) {
				const loaded = await engine.loadFile(requested);
				if (!loaded) { throw new Error(`Failed to load reference-graph target: ${requested}`); }
			}
		}
		if (!engine.isFileLoaded()) {
			throw new Error('Reference graph command requires a loaded binary or an explicit file path.');
		}
	};
	const writeReferenceGraphOutput = (options: ReferenceGraphCommandInvocationOptions, result: unknown): string | undefined => {
		const rawOutput = options.output as unknown;
		const outputPath = typeof rawOutput === 'string'
			? rawOutput
			: isRecord(rawOutput) && typeof rawOutput.path === 'string'
				? rawOutput.path
				: undefined;
		if (!outputPath) { return undefined; }
		const resolved = path.resolve(outputPath);
		writeJsonFile(resolved, result);
		return resolved;
	};
	const writeSemanticCommandOutput = (
		options: SemanticCommandInvocationOptions,
		result: unknown,
		canonicalText?: string,
	): string | undefined => {
		const outputPath = resolveSemanticOutputPath(options.output);
		if (!outputPath) { return undefined; }
		if (canonicalText !== undefined) {
			fs.mkdirSync(path.dirname(outputPath), { recursive: true });
			fs.writeFileSync(outputPath, `${canonicalText}\n`, 'utf8');
		} else {
			writeJsonFile(outputPath, result);
		}
		return outputPath;
	};
	const refreshAfterSemanticCommand = (): void => {
		functionProvider.refresh();
		disasmEditorProvider.refresh();
		analysisCenterProvider.refresh();
	};
	const announceSemanticCommand = (
		options: SemanticCommandInvocationOptions,
		result: {
			ok?: unknown;
			reason?: unknown;
			status?: unknown;
			semanticStatus?: unknown;
			semanticWarning?: unknown;
		},
		label: string,
		outputPath?: string,
	): void => {
		if (options.quiet) { return; }
		const suffix = outputPath ? ` Output: ${outputPath}` : '';
		if (result.ok === false) {
			vscode.window.showErrorMessage(`${label}: ${String(result.reason ?? result.status ?? 'failed')}.${suffix}`);
		} else if (result.semanticStatus === 'partial') {
			vscode.window.showWarningMessage(`${label}: ${String(result.semanticWarning ?? 'caller propagation is incomplete')}.${suffix}`);
		} else {
			vscode.window.showInformationMessage(`${label} completed.${suffix}`);
		}
	};
	const interactivePrototypeRequest = async (
		identity: string,
	): Promise<ApplyPrototypeRequest | undefined> => {
		const architecture = String(engine.getArchitecture()).toLowerCase();
		const callingConventionId = architecture === 'x86' ? 'cdecl'
			: architecture === 'arm' ? 'aapcs32'
				: architecture === 'arm64' ? 'aapcs64'
					: 'win64';
		const value = await vscode.window.showInputBox({
			prompt: 'Full semantic prototype as JSON',
			value: JSON.stringify({
				functionIdentity: identity,
				functionAddress: identity,
				returnType: 'int32_t',
				callingConventionId,
				parameters: [],
			}),
			ignoreFocusOut: true,
		});
		if (value === undefined) { return undefined; }
		const parsed = JSON.parse(value) as Partial<ApplyPrototypeRequest>;
		return { ...parsed, functionIdentity: parsed.functionIdentity ?? identity } as ApplyPrototypeRequest;
	};
	const pendingJobRuns = new Map<string, NodeJS.Timeout>();
	const activeJobRuns = new Set<string>();
	const queuedAutoRuns = new Set<string>();

	// Bug #36/4: loop-breaker state for the *.hexcore_job.json FileSystemWatcher.
	// Auto Save flushes the open dirty job buffer on every keystroke window, and
	// jobs finish sub-second, so the queued/running dedup in JobQueueManager is not
	// enough — each save re-enqueues. We additionally key on the job file's CONTENT
	// (sha1) plus a per-path cooldown so an UNCHANGED file inside the cooldown window
	// is skipped, while a real edit (changed bytes) still re-runs.
	const lastWatcherRun = new Map<string, { hash: string; ts: number }>();
	// Cooldown (ms) after a watcher-triggered run during which onDidChange for the
	// SAME path with the SAME content is ignored, absorbing save/format churn.
	const WATCHER_COOLDOWN_MS = 2500;

	const executePipelineJob = async (
		jobFilePath: string,
		quiet: boolean,
		autoTriggered: boolean
	): Promise<PipelineRunStatus | undefined> => {
		const normalizedPath = jobPathIdentity(jobFilePath);
		if (activeJobRuns.has(normalizedPath)) {
			if (autoTriggered) {
				queuedAutoRuns.add(normalizedPath);
				return undefined;
			}
			if (!quiet) {
				vscode.window.showWarningMessage(`A HexCore job is already running: ${normalizedPath}`);
			}
			return undefined;
		}

		activeJobRuns.add(normalizedPath);
		try {
			const status = await pipelineRunner.runJobFile(normalizedPath, true);
			if (!quiet) {
				if (status.status === 'ok') {
					vscode.window.showInformationMessage(`Pipeline completed successfully. Status file: ${path.join(status.outDir, 'hexcore-pipeline.status.json')}`);
				} else if (status.status === 'partial') {
					vscode.window.showWarningMessage(`Pipeline finished partially (some steps failed, continueOnError kept the job running). Check: ${path.join(status.outDir, 'hexcore-pipeline.log')}`);
				} else {
					vscode.window.showWarningMessage(`Pipeline halted on error. Check: ${path.join(status.outDir, 'hexcore-pipeline.log')}`);
				}
			}
			return status;
		} catch (error: unknown) {
			if (!quiet) {
				vscode.window.showErrorMessage(`Pipeline execution failed: ${toErrorMessage(error)}`);
			}
			throw error;
		} finally {
			activeJobRuns.delete(normalizedPath);
			if (queuedAutoRuns.delete(normalizedPath)) {
				scheduleJobRun(normalizedPath);
			}
		}
	};

	const runPipelineJob = async (arg?: vscode.Uri | string | RunJobCommandOptions): Promise<ContractDecorated<PipelineRunStatus> | undefined> => {
		const options = normalizeRunJobCommandOptions(arg);
		const quiet = options.quiet ?? false;
		const jobFilePath = await resolveJobFilePath(arg, options.jobFile, { interactive: !quiet });
		if (!jobFilePath) {
			if (!quiet) {
				vscode.window.showWarningMessage('No .hexcore_job.json file was found.');
			}
			return undefined;
		}

		const result = await executePipelineJob(jobFilePath, quiet, false);
		return result ? decoratePipelineRunStatus(result) : undefined;
	};

	// Bug #36/4: a job-file written INSIDE an outDir self-matches the recursive
	// `**/*.hexcore_job.json` glob and would loop with no editor at all. An outDir
	// is identified by also containing the pipeline status file. We also never let
	// the generated status/log files themselves trigger a run (they cannot match the
	// job glob, but the check is cheap and future-proofs a rename). Returns the
	// reason string when the path must be skipped, or undefined when it may run.
	const watcherTriggerSkipReason = (normalizedPath: string): string | undefined => {
		const base = path.basename(normalizedPath);
		if (base === JOB_STATUS_FILENAME || base === JOB_LOG_FILENAME) {
			return `generated pipeline file (${base})`;
		}
		// If the job file sits in a directory that ALSO holds a status file, that
		// directory is an outDir and the job is a generated artifact — skip it so a
		// job written under an outDir cannot self-trigger an unbounded loop.
		try {
			if (fs.existsSync(path.join(path.dirname(normalizedPath), JOB_STATUS_FILENAME))) {
				return 'job file lives inside a resolved outDir (contains a status file)';
			}
		} catch {
			/* stat failure — fall through and allow the run */
		}
		return undefined;
	};

	// Auto-run + FileSystemWatcher submissions go through the SAME JobQueueManager
	// as the `hexcore.pipeline.queueJob` command, so concurrency is bounded by the
	// pool size (default 2) instead of firing every root job at once (issue #27).
	//
	// Dedup / loop-breaker layers preserved here (Bug #36/4):
	//   1. The 350ms debounce (pendingJobRuns) coalesces rapid save events for the
	//      same path BEFORE anything reaches the queue.
	//   2. queueJobIfAbsent() refuses to enqueue a path that already has a queued
	//      or running job in the manager, covering saves that arrive after the
	//      debounce window while the prior run is still in-flight.
	//   3. Content-hash + cooldown: an UNCHANGED job file re-saved within the
	//      cooldown window is skipped (Auto Save flushes the dirty buffer repeatedly
	//      and jobs finish sub-second, defeating layers 1+2). A genuine edit changes
	//      the bytes, so its hash differs and it still re-runs.
	//   4. Generated-artifact exclusion: status/log files and job files inside an
	//      outDir never trigger a run (watcherTriggerSkipReason).
	// NOTE: this loop-breaker lives ONLY on the watcher/auto-run path. The manual
	// `hexcore.pipeline.queueJob` command intentionally bypasses it so a user can
	// re-run an unchanged job on demand.
	// Auto/watcher jobs are submitted at LOW priority so they never starve
	// user-submitted (normal/high) jobs from the queueJob command.
	const scheduleJobRun = (jobFilePath: string): void => {
		const normalizedPath = jobPathIdentity(jobFilePath);

		// Cheap, synchronous exclusion before we even debounce: never let a
		// generated artifact or an in-outDir job file enter the scheduler.
		const skipReason = watcherTriggerSkipReason(normalizedPath);
		if (skipReason) {
			console.log(`[HexCore][autoRun] skipped (${skipReason}): ${normalizedPath}`);
			return;
		}
		const staleRunningMs = vscode.workspace.getConfiguration('hexcore.pipeline').get<number>('staleRunningMs', 15 * 60_000);
		const recordedAttempt = findRecordedAutoRunAttempt(normalizedPath, Date.now(), staleRunningMs);
		if (recordedAttempt) {
			if (recordedAttempt.stale) {
				const recovery = recoverStaleAutoRunAttempt(recordedAttempt);
				if (recovery.recovered) {
					console.warn(`[HexCore][autoRun] recovered stale attempt (${recordedAttempt.ageMs}ms): ${normalizedPath}`);
				} else {
					console.warn(`[HexCore][autoRun] stale attempt recovery failed (${recovery.reason ?? 'unknown'}): ${normalizedPath}`);
					return;
				}
			} else {
			console.log(
				`[HexCore][autoRun] skipped (unchanged revision already attempted: ` +
				`status=${recordedAttempt.status}, startedAt=${recordedAttempt.startedAt}): ${normalizedPath}`
			);
			return;
			}
		}

		const existing = pendingJobRuns.get(normalizedPath);
		if (existing) {
			clearTimeout(existing);
		}

		const timeoutHandle = setTimeout(() => {
			pendingJobRuns.delete(normalizedPath);
			try {
				// Content-hash + cooldown loop-breaker. Read the (now-stable, post-
				// debounce) bytes and hash them. If the hash is unchanged AND we are
				// still inside the cooldown window since the last run for this path,
				// skip — this is the save/format churn that caused the unbounded loop.
				// Changed bytes (a real edit) always fall through and run.
				let hash: string | undefined;
				try {
					hash = crypto.createHash('sha1').update(fs.readFileSync(normalizedPath)).digest('hex');
				} catch (readErr) {
					console.warn(`[HexCore][autoRun] could not read job for hashing (will still run): ${normalizedPath}`, readErr);
				}
				if (hash !== undefined) {
					const prev = lastWatcherRun.get(normalizedPath);
					if (prev && prev.hash === hash && (Date.now() - prev.ts) < WATCHER_COOLDOWN_MS) {
						console.log(`[HexCore][autoRun] skipped (unchanged within ${WATCHER_COOLDOWN_MS}ms cooldown): ${normalizedPath}`);
						return;
					}
					// Record BEFORE enqueue so concurrent save events racing this same
					// tick are absorbed by the cooldown rather than stacking runs.
					lastWatcherRun.set(normalizedPath, { hash, ts: Date.now() });
				}

				const manager = getJobQueueManagerInstance();
				const { jobId, deduped } = manager.queueJobIfAbsent(normalizedPath, 'low');
				if (deduped) {
					console.log(`[HexCore][autoRun] already queued/running, skipped: ${normalizedPath} (job ${jobId})`);
				} else {
					console.log(`[HexCore][autoRun] enqueued (low priority) job ${jobId}: ${normalizedPath}`);
				}
			} catch (error) {
				console.error('[HexCore][autoRun] failed to enqueue job:', error);
			}
		}, 350);
		pendingJobRuns.set(normalizedPath, timeoutHandle);
	};

	const autoRunExistingJobs = (): void => {
		// Intentionally ROOT-ONLY (not recursive). Auto-executing every job buried
		// in a workspace the moment a window opens is a foot-gun; startup auto-run
		// is therefore limited to jobs the user placed at the workspace root.
		// Subfolder jobs run via the recursive FileSystemWatcher (on save), or
		// interactively via "Run Job" (resolveJobFilePath offers a picker when the
		// jobs live only in subfolders).
		const folders = vscode.workspace.workspaceFolders ?? [];
		// DIAGNOSTIC (3.8.2): the startup retry-all was reported as not firing.
		// Log what this pass actually sees so a reload reveals the cause.
		console.log(`[HexCore][autoRun] workspaceFolders=${folders.length}`);
		let scheduledCount = 0;
		for (const folder of folders) {
			// Primary: check for .hexcore_job.json (the canonical name)
			const jobFilePath = path.join(folder.uri.fsPath, '.hexcore_job.json');
			if (fs.existsSync(jobFilePath)) {
				scheduleJobRun(jobFilePath);
				scheduledCount++;
			}
			// Also scan for named jobs (*.hexcore_job.json) in workspace root
			try {
				const files = fs.readdirSync(folder.uri.fsPath);
				const named = files.filter(f => f.endsWith('.hexcore_job.json') && f !== '.hexcore_job.json');
				console.log(`[HexCore][autoRun] ${folder.uri.fsPath} -> ${named.length} named job(s): ${named.join(', ') || '(none)'}`);
				for (const file of named) {
					const namedJobPath = path.join(folder.uri.fsPath, file);
					scheduleJobRun(namedJobPath);
					scheduledCount++;
				}
			} catch (err) {
				console.error(`[HexCore][autoRun] readdir failed for ${folder.uri.fsPath}:`, err);
			}
		}
		console.log(`[HexCore][autoRun] scheduled ${scheduledCount} job(s)`);
	};

	// Sync tree views when editor changes
	onDidChangeActiveEditor.event(() => {
		functionProvider.refresh();
		stringRefProvider.refresh();
		sectionProvider.refresh();
		importProvider.refresh();
		exportProvider.refresh();
		analysisCenterProvider.refresh();
	});

	// Register Custom Editor (Main disassembly view)
	context.subscriptions.push(
		vscode.window.registerCustomEditorProvider(
			DisassemblyEditorProvider.viewType,
			disasmEditorProvider,
			{
				webviewOptions: { retainContextWhenHidden: true },
				supportsMultipleEditorsPerDocument: false
			}
		)
	);

	// Register Webview Providers (Sidebar)
	context.subscriptions.push(
		vscode.window.registerWebviewViewProvider(
			AnalysisCenterProvider.viewType,
			analysisCenterProvider,
			{ webviewOptions: { retainContextWhenHidden: true } }
		),
		vscode.window.registerWebviewViewProvider(
			'hexcore.disassembler.graphView',
			graphViewProvider,
			{ webviewOptions: { retainContextWhenHidden: true } }
		)
	);

	// Register Tree Providers
	context.subscriptions.push(
		vscode.window.registerTreeDataProvider('hexcore.disassembler.functions', functionProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.strings', stringRefProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.sections', sectionProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.imports', importProvider),
		vscode.window.registerTreeDataProvider('hexcore.disassembler.exports', exportProvider)
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.analysis.openCenter', () => {
			analysisCenterProvider.show();
		}),
		vscode.commands.registerCommand('hexcore.pipeline.runJob', async (arg?: vscode.Uri | string | RunJobCommandOptions) => {
			return runPipelineJob(arg);
		}),
		vscode.commands.registerCommand('hexcore.pipeline.listCapabilities', async (options?: { output?: string | { path?: string }; quiet?: boolean }) => {
			const capabilities = listCapabilities();
			const outputPath = resolveOptionalOutputPath(options?.output);

			if (outputPath) {
				fs.writeFileSync(outputPath, JSON.stringify(capabilities, null, 2), 'utf8');
				if (!options?.quiet) {
					vscode.window.showInformationMessage(`Pipeline capabilities written to ${outputPath}`);
				}
				return decorateOkResult(capabilities);
			}
			showCapabilitiesInOutputChannel(capabilities);
			return decorateOkResult(capabilities);
		}),
		vscode.commands.registerCommand('hexcore.pipeline.validateJob', async (arg?: vscode.Uri | string | ValidateJobCommandOptions) => {
			const options = normalizeValidateJobCommandOptions(arg);
			const quiet = options.quiet ?? false;
			const jobFilePath = await resolveJobFilePath(arg, options.jobFile, { interactive: !quiet });
			if (!jobFilePath) {
				if (!quiet) {
					vscode.window.showWarningMessage('No .hexcore_job.json file was found.');
				}
				return undefined;
			}

			const report = await pipelineRunner.validateJobFile(jobFilePath, true);
			const outputPath = resolveOptionalOutputPath(options.output);
			if (outputPath) {
				writeJsonFile(outputPath, report);
				if (!quiet) {
					vscode.window.showInformationMessage(`Pipeline validation report written to ${outputPath}`);
				}
			} else if (!quiet) {
				showValidationReportInOutputChannel(report);
			}

			if (!quiet) {
				if (report.ok) {
					vscode.window.showInformationMessage(`Pipeline validation passed: ${report.totalSteps} steps checked.`);
				} else {
					const errors = report.issues.filter(issue => issue.level === 'error').length;
					const warnings = report.issues.filter(issue => issue.level === 'warning').length;
					vscode.window.showWarningMessage(`Pipeline validation found issues (${errors} errors, ${warnings} warnings).`);
				}
			}

			return decorateValidationReport(report);
		}),
		vscode.commands.registerCommand('hexcore.pipeline.validateWorkspace', async (arg?: ValidateWorkspaceCommandOptions) => {
			const options = normalizeValidateWorkspaceCommandOptions(arg);
			const quiet = options.quiet ?? false;
			const includePattern = options.glob ?? '**/*.hexcore_job.json';
			const excludePattern = '**/{node_modules,.git,out,dist}/**';
			const jobFiles = await vscode.workspace.findFiles(includePattern, excludePattern);

			const workspaceRoots = (vscode.workspace.workspaceFolders ?? []).map(folder => folder.uri.fsPath);
			const report: WorkspaceValidationReport = {
				generatedAt: new Date().toISOString(),
				workspaceRoots,
				totalJobs: 0,
				passedJobs: 0,
				failedJobs: 0,
				entries: []
			};

			if (jobFiles.length === 0) {
				const outputPath = resolveOptionalOutputPath(options.output);
				if (outputPath) {
					writeJsonFile(outputPath, report);
				}
				if (!quiet) {
					vscode.window.showWarningMessage('No .hexcore_job.json files were found in this workspace.');
				}
				return report;
			}

			for (const jobFile of jobFiles.sort((left, right) => left.fsPath.localeCompare(right.fsPath))) {
				try {
					const validation = await pipelineRunner.validateJobFile(jobFile.fsPath, true);
					const errors = validation.issues.filter(issue => issue.level === 'error').length;
					const warnings = validation.issues.filter(issue => issue.level === 'warning').length;
					report.entries.push({
						jobFile: jobFile.fsPath,
						ok: validation.ok,
						totalSteps: validation.totalSteps,
						errors,
						warnings
					});
				} catch (error: unknown) {
					report.entries.push({
						jobFile: jobFile.fsPath,
						ok: false,
						totalSteps: 0,
						errors: 1,
						warnings: 0,
						error: toErrorMessage(error)
					});
				}
			}

			report.totalJobs = report.entries.length;
			report.passedJobs = report.entries.filter(entry => entry.ok).length;
			report.failedJobs = report.totalJobs - report.passedJobs;

			const outputPath = resolveOptionalOutputPath(options.output);
			if (outputPath) {
				writeJsonFile(outputPath, report);
				if (!quiet) {
					vscode.window.showInformationMessage(`Workspace pipeline validation written to ${outputPath}`);
				}
			} else if (!quiet) {
				showWorkspaceValidationInOutputChannel(report);
			}

			if (!quiet) {
				if (report.failedJobs > 0) {
					vscode.window.showWarningMessage(`Workspace pipeline validation found issues in ${report.failedJobs}/${report.totalJobs} job files.`);
				} else {
					vscode.window.showInformationMessage(`Workspace pipeline validation passed for ${report.totalJobs} job files.`);
				}
			}

			return report;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.createPresetJob', async (arg?: CreatePresetJobCommandOptions) => {
			const options = normalizeCreatePresetJobCommandOptions(arg);
			const quiet = options.quiet === true;
			const workspaceRoot = getWorkspaceRootPath();
			if (!workspaceRoot) {
				throw new Error('No workspace folder is open.');
			}

			const presets = [
				...getBuiltInPipelinePresets(),
				...loadWorkspacePipelinePresets(workspaceRoot)
			];
			if (presets.length === 0) {
				throw new Error('No pipeline presets are available.');
			}

			let selectedPreset = resolvePipelinePreset(presets, options.preset);
			if (!selectedPreset && !quiet) {
				const picked = await vscode.window.showQuickPick(
					presets.map(preset => ({
						label: preset.name,
						description: preset.source === 'builtin' ? 'Built-in' : 'Workspace',
						detail: preset.description,
						preset
					})),
					{ placeHolder: 'Select a pipeline preset to generate .hexcore_job.json' }
				);
				selectedPreset = picked?.preset;
			}
			if (!selectedPreset) {
				throw new Error('No preset selected. Pass "preset" in options or choose one interactively.');
			}

			const filePath = await resolvePresetTargetFilePath(options, quiet, workspaceRoot);
			if (!filePath) {
				throw new Error('No target file selected for preset job generation.');
			}

			const outDir = resolvePresetOutDirPath(options, workspaceRoot, selectedPreset.id);
			const jobPath = resolvePresetJobFilePath(options, workspaceRoot);
			const job = materializePresetJob(selectedPreset.template, filePath, outDir);

			writeJsonFile(jobPath, job);
			if (!quiet) {
				vscode.window.showInformationMessage(`Preset job created (${selectedPreset.name}) at ${jobPath}`);
			}

			const result = {
				presetId: selectedPreset.id,
				presetName: selectedPreset.name,
				jobFile: jobPath,
				file: filePath,
				outDir,
				steps: job.steps.length
			};

			const outputPath = resolveOptionalOutputPath(options.output);
			if (outputPath) {
				writeJsonFile(outputPath, result);
			}

			return result;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.saveJobAsProfile', async (arg?: SaveJobAsProfileCommandOptions) => {
			const options = normalizeSaveJobAsProfileCommandOptions(arg);
			const quiet = options.quiet === true;
			const workspaceRoot = getWorkspaceRootPath();
			if (!workspaceRoot) {
				throw new Error('No workspace folder is open.');
			}

			const jobFilePath = resolveSaveProfileJobFilePath(options, workspaceRoot);
			if (!fs.existsSync(jobFilePath)) {
				throw new Error(`Job file not found: ${jobFilePath}`);
			}

			const raw = JSON.parse(fs.readFileSync(jobFilePath, 'utf8')) as PipelineJobTemplate;
			validatePipelineJobTemplate(raw, jobFilePath);

			let name = options.name?.trim();
			if (!name && !quiet) {
				name = (await vscode.window.showInputBox({
					prompt: 'Profile name',
					placeHolder: 'ctf-reverse-custom'
				}))?.trim();
			}
			if (!name) {
				throw new Error('Profile name is required.');
			}

			const description = options.description?.trim()
				?? `Saved from ${path.basename(jobFilePath)}`;
			const template = normalizeJobTemplateFromExistingJob(raw);
			const preset = saveWorkspacePipelinePreset(workspaceRoot, name, description, template);
			const presetFilePath = getWorkspacePresetFilePath(workspaceRoot);

			if (!quiet) {
				vscode.window.showInformationMessage(`Workspace profile saved (${preset.name}) to ${presetFilePath}`);
			}

			const result = {
				id: preset.id,
				name: preset.name,
				presetFile: presetFilePath,
				jobFile: jobFilePath
			};

			const outputPath = resolveOptionalOutputPath(options.output);
			if (outputPath) {
				writeJsonFile(outputPath, result);
			}

			return result;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.doctor', async (options?: DoctorCommandOptions) => {
			const report = await runPipelineDoctor();
			const quiet = options?.quiet === true;
			const outputPath = resolveOptionalOutputPath(options?.output);

			if (outputPath) {
				writeJsonFile(outputPath, report);
				if (!quiet) {
					vscode.window.showInformationMessage(`Pipeline doctor report written to ${outputPath}`);
				}
			} else if (!quiet) {
				showDoctorReportInOutputChannel(report);
			}

			if (!quiet) {
				if (report.missingCommands > 0 || report.degradedCommands > 0) {
					vscode.window.showWarningMessage(
						`Pipeline doctor found ${report.missingCommands} missing and ${report.degradedCommands} degraded commands.`
					);
				} else {
					vscode.window.showInformationMessage(`Pipeline doctor is healthy: ${report.readyCommands}/${report.totalCapabilities} commands ready.`);
				}
			}

			return report;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.queueJob', async (arg?: { jobFile?: string; file?: string; priority?: JobPriority; sessionId?: string; quiet?: boolean }) => {
			// Accept both `jobFile` (original) and `file` (documented in
			// HEXCORE_AUTOMATION.md + the orchestrator templates). When run as a
			// pipeline step, the runner forwards the step-level `file`/`jobFile`
			// job-path as `jobFile` (it sets `file` to the target binary), so
			// `jobFile` takes precedence here.
			const jobPathArg = arg?.jobFile ?? arg?.file;
			const jobFilePath = jobPathArg
				? path.resolve(jobPathArg)
				: await pickJobFile();
			if (!jobFilePath) {
				if (!arg?.quiet) {
					vscode.window.showWarningMessage('No job file selected.');
				}
				return undefined;
			}

			if (!fs.existsSync(jobFilePath)) {
				throw new Error(`Job file not found: ${jobFilePath}`);
			}

			const priority: JobPriority = arg?.priority ?? 'normal';
			// Issue #26: optional keepAlive sessionId pins all same-session jobs
			// to one worker (sticky routing). Omitted -> stateless (unchanged).
			const sessionId = arg?.sessionId;
			const manager = getJobQueueManagerInstance();
			const jobId = manager.queueJob(jobFilePath, priority, sessionId);

			if (!arg?.quiet) {
				const sessionNote = sessionId ? `, session: ${sessionId}` : '';
				vscode.window.showInformationMessage(`Job queued with ID: ${jobId} (priority: ${priority}${sessionNote})`);
			}

			return decorateOkResult({ jobId, filePath: jobFilePath, priority, ...(sessionId ? { sessionId } : {}) });
		}),
		vscode.commands.registerCommand('hexcore.pipeline.cancelJob', async (arg?: { jobId?: string; quiet?: boolean }) => {
			let jobId = arg?.jobId;
			if (!jobId) {
				// Show quick pick with running/queued jobs
				const manager = getJobQueueManagerInstance();
				const jobs = manager.getAllJobs().filter(j => j.status === 'queued' || j.status === 'running');
				if (jobs.length === 0) {
					if (!arg?.quiet) {
						vscode.window.showInformationMessage('No queued or running jobs to cancel.');
					}
					return false;
				}
				const picked = await vscode.window.showQuickPick(
					jobs.map(job => ({
						label: `${job.jobId.substring(0, 8)}...`,
						description: `${job.status} | ${path.basename(job.filePath)}`,
						detail: `Priority: ${job.priority}`,
						job
					})),
					{ placeHolder: 'Select a job to cancel' }
				);
				if (!picked) {
					return false;
				}
				jobId = picked.job.jobId;
			}

			const manager = getJobQueueManagerInstance();
			const cancelled = manager.cancelJob(jobId);

			if (!arg?.quiet) {
				if (cancelled) {
					vscode.window.showInformationMessage(`Job ${jobId.substring(0, 8)}... cancelled.`);
				} else {
					vscode.window.showWarningMessage(`Job ${jobId.substring(0, 8)}... could not be cancelled (not found or already completed).`);
				}
			}

			return cancelled;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.jobStatus', async (arg?: { jobId?: string; quiet?: boolean; output?: string | { path?: string }; pipelineQueryContext?: QueueQueryContext }) => {
			const manager = getJobQueueManagerInstance();
			const outputPath = resolveOptionalOutputPath(arg?.output);

			if (arg?.jobId) {
				// Issue #24/#26: return the public status report, which carries
				// the dispatch-order `position` while queued (null otherwise)
				// and echoes the keepAlive `sessionId` when present.
				const report = manager.getJobStatusReport(arg.jobId);
				if (!arg.quiet) {
					if (report) {
						showJobStatusInOutputChannel(report);
					} else {
						vscode.window.showWarningMessage(`Job not found: ${arg.jobId}`);
					}
				}
				const result = report ? decorateOkResult(report) : report;
				if (outputPath && result) {
					writeJsonFile(outputPath, result);
				}
				return result;
			}

			const allJobs = manager.getAllJobs();
			const stats = manager.getQueueStats();

			if (!arg?.quiet) {
				showQueueStatusInOutputChannel(allJobs, stats);
			}

			const result = decorateOkResult({ jobs: allJobs, stats, ...describeQueueObservation(allJobs, arg?.pipelineQueryContext) });
			if (outputPath) {
				writeJsonFile(outputPath, result);
			}
			return result;
		})
	);

	// Register JobQueueManager disposal
	context.subscriptions.push({
		dispose: () => {
			disposeJobQueueManagerInstance();
		}
	});

	// Watch for ANY file ending in .hexcore_job.json (not just the dot-prefixed one).
	// This lets agents create named jobs like sotr-strings.hexcore_job.json and
	// have them auto-detected without manual "Queue Job" intervention.
	const jobWatcher = vscode.workspace.createFileSystemWatcher('**/*.hexcore_job.json');
	context.subscriptions.push(jobWatcher);
	context.subscriptions.push(
		jobWatcher.onDidCreate(uri => scheduleJobRun(uri.fsPath)),
		jobWatcher.onDidChange(uri => scheduleJobRun(uri.fsPath))
	);
	context.subscriptions.push({
		dispose: () => {
			for (const timeoutHandle of pendingJobRuns.values()) {
				clearTimeout(timeoutHandle);
			}
			pendingJobRuns.clear();
		}
	});

	autoRunExistingJobs();

	// Register Commands
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.openFile', async () => {
			const uris = await vscode.window.showOpenDialog({
				canSelectMany: false,
				openLabel: 'Open Binary',
				filters: {
					'Windows Executables': ['exe', 'dll', 'sys', 'ocx', 'scr', 'cpl'],
					'Linux Executables': ['elf', 'so', 'a', 'o'],
					'Raw Binary': ['bin', 'raw', 'dmp'],
					'All Files': ['*']
				}
			});
			if (uris && uris.length > 0) {
				// Open in Custom Editor
				await vscode.commands.executeCommand('vscode.openWith', uris[0], DisassemblyEditorProvider.viewType);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.open', async (uri?: vscode.Uri) => {
			if (uri) {
				await vscode.commands.executeCommand('vscode.openWith', uri, DisassemblyEditorProvider.viewType);
				return;
			}

			await vscode.commands.executeCommand('hexcore.disasm.openFile');
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzeFile', async (uri?: vscode.Uri) => {
			if (!uri) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					openLabel: 'Disassemble',
					filters: {
						'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
						'All Files': ['*']
					}
				});
				if (uris && uris.length > 0) {
					uri = uris[0];
				}
			}
			if (uri) {
				try {
					// Open in custom editor (main disassembly view)
					await vscode.commands.executeCommand('vscode.openWith', uri, DisassemblyEditorProvider.viewType);
				} catch (error: any) {
					vscode.window.showErrorMessage(`Failed to disassemble file: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.goToAddress', async (argAddress?: number) => {
			let addr: number | undefined = argAddress;

			if (addr === undefined) {
				const input = await vscode.window.showInputBox({
					prompt: 'Enter address (hex)',
					placeHolder: '0x401000',
					validateInput: (value) => {
						const val = parseInt(value.replace(/^0x/, ''), 16);
						return isNaN(val) ? 'Invalid hex address' : null;
					}
				});
				if (input) {
					addr = parseInt(input.replace(/^0x/, ''), 16);
				}
			}

			if (addr !== undefined) {
				const targetAddress = addr;
				disasmEditorProvider.navigateToAddress(targetAddress);

				// Sync Graph View if function exists - auto-focus graph
				let func = engine.getFunctionAt(targetAddress);
				if (!func) {
					// Try to find containing function
					const funcs = engine.getFunctions();
					func = funcs.find(f => targetAddress >= f.address && targetAddress < f.endAddress);
				}

				// A-lazy: materialize so a .pdata stub gets its body before the "has instructions"
				// gate; otherwise an unopened stub (empty instructions) would never auto-focus the graph.
				if (func) {
					await engine.materializeFunction(func.address);
				}

				if (func && func.instructions.length > 0) {
					await graphViewProvider.showFunction(func);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.goToFileOffset', async (arg?: { filePath?: string; offset?: number }) => {
			const loadedPath = engine.getFilePath();
			if (!loadedPath || !arg?.filePath || path.resolve(loadedPath) !== path.resolve(arg.filePath)) {
				vscode.window.showWarningMessage('Hex Viewer sync requires the same binary to be open in the Disassembler.');
				return false;
			}
			const address = engine.fileOffsetToAddress(arg.offset ?? Number.NaN);
			if (address === undefined) {
				vscode.window.showWarningMessage('The selected file offset is outside the loaded binary.');
				return false;
			}
			await vscode.commands.executeCommand('hexcore.disasm.goToAddress', address);
			return true;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.findXrefs', async () => {
			const input = await vscode.window.showInputBox({
				prompt: 'Find references to address',
				placeHolder: '0x401000'
			});
			if (input) {
				const addr = parseInt(input.replace(/^0x/, ''), 16);
				const xrefs = await engine.findCrossReferences(addr);
				disasmEditorProvider.showXrefs(xrefs);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.addComment', async () => {
			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No address selected');
				return;
			}
			const comment = await vscode.window.showInputBox({
				prompt: `Add comment at 0x${addr.toString(16)}`,
				placeHolder: 'Enter comment...'
			});
			if (comment) {
				engine.addComment(addr, comment);
				disasmEditorProvider.refresh();
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.renameFunction', async (item?: any) => {
			// Headless mode: { address: string|number, name: string }
			if (item && typeof item === 'object' && 'address' in item && 'name' in item) {
				const addr = typeof item.address === 'string' ? parseInt(item.address, 16) : item.address;
				engine.renameFunction(addr, item.name);
				return { success: true };
			}
			// Interactive mode
			const addr = item?.address || disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const currentName = engine.getFunctionName(addr) || `sub_${addr.toString(16).toUpperCase()}`;
			const newName = await vscode.window.showInputBox({
				prompt: 'Rename function',
				value: currentName
			});
			if (newName) {
				engine.renameFunction(addr, newName);
				functionProvider.refresh();
				disasmEditorProvider.refresh();
			}
		})
	);

	// v3.7.4: Rename variable (interactive)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.renameVariable', async (arg?: any) => {
			// Headless mode: { funcAddress|funcAddr: string|number, originalName: string, newName: string }
			if (arg && typeof arg === 'object' && ('funcAddress' in arg || 'funcAddr' in arg) && 'originalName' in arg && 'newName' in arg) {
				const rawAddr = arg.funcAddress ?? arg.funcAddr;
				const funcAddr = typeof rawAddr === 'string' ? parseInt(rawAddr, 16) : rawAddr;
				engine.renameVariable(funcAddr, arg.originalName, arg.newName);
				return { success: true };
			}
			// Interactive mode
			const addr = disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const originalName = await vscode.window.showInputBox({ prompt: 'Original variable name (e.g. param_1)' });
			if (!originalName) { return; }
			const newName = await vscode.window.showInputBox({ prompt: `Rename "${originalName}" to:`, value: originalName });
			if (newName && newName !== originalName) {
				engine.renameVariable(addr, originalName, newName);
				disasmEditorProvider.refresh();
				vscode.window.showInformationMessage(`Renamed "${originalName}" → "${newName}"`);
			}
		})
	);

	// v3.7.4: Retype variable (interactive)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.retypeVariable', async (arg?: any) => {
			if (arg && typeof arg === 'object' && ('funcAddress' in arg || 'funcAddr' in arg) && ('originalName' in arg || 'variableName' in arg) && 'newType' in arg) {
				const rawAddr = arg.funcAddress ?? arg.funcAddr;
				const funcAddr = typeof rawAddr === 'string' ? parseInt(rawAddr, 16) : rawAddr;
				const varName = arg.originalName ?? arg.variableName;
				engine.retypeVariable(funcAddr, varName, arg.newType);
				return { success: true };
			}
			const addr = disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const originalName = await vscode.window.showInputBox({ prompt: 'Variable name to retype' });
			if (!originalName) { return; }
			const newType = await vscode.window.showInputBox({ prompt: `New type for "${originalName}":`, value: 'int64_t' });
			if (newType) {
				engine.retypeVariable(addr, originalName, newType);
				disasmEditorProvider.refresh();
				vscode.window.showInformationMessage(`Retyped "${originalName}" → ${newType}`);
			}
		})
	);

	// v3.7.4: Retype function return type
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.retypeFunction', async (arg?: any) => {
			const applyLegacyFunctionRetype = (addr: number, returnType: string) => {
				if (!Number.isSafeInteger(addr) || addr < 0) {
					throw new Error('retypeFunction requires a non-negative safe virtual address.');
				}
				const session = engine.getSessionStore();
				if (!session) {
					throw new Error('HXDB semantic persistence is unavailable for the active binary.');
				}
				const functionIdentity = `0x${addr.toString(16)}`;
				const semanticStore = session.getSemanticStore();
				const previous = semanticStore.getPrototype(functionIdentity);
				const generationBefore = session.getAnalysisSession()?.generation;
				engine.retypeFunction(addr, returnType);
				const prototype = semanticStore.getPrototype(functionIdentity);
				if (!prototype) {
					throw new Error(`retypeFunction did not persist a semantic prototype for ${functionIdentity}.`);
				}
				const changed = previous?.prototypeHash !== prototype.prototypeHash;
				return decorateSemanticCommandResult({
					success: true,
					ok: true,
					command: 'retypeFunction',
					functionIdentity,
					changed,
					prototype,
					previousPrototypeHash: previous?.prototypeHash,
					prototypeHash: prototype.prototypeHash,
					generationBefore,
					generationAfter: session.getAnalysisSession()?.generation,
					storeHash: semanticStore.exportHash(),
					propagationComplete: !changed,
				});
			};
			if (arg && typeof arg === 'object' && 'address' in arg && 'returnType' in arg) {
				const addr = typeof arg.address === 'string' ? parseInt(arg.address, 16) : arg.address;
				return applyLegacyFunctionRetype(addr, arg.returnType);
			}
			const addr = arg?.address || disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const returnType = await vscode.window.showInputBox({ prompt: 'Function return type:', value: 'int' });
			if (returnType) {
				const result = applyLegacyFunctionRetype(addr, returnType);
				disasmEditorProvider.refresh();
				vscode.window.showInformationMessage(`Return type → ${returnType}`);
				return result;
			}
		})
	);

	// R32: complete semantic prototype/ABI commands. Headless calls receive the
	// pipeline target and output path; command-palette calls use the selected function.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.types.applyPrototype', async (arg?: unknown) => {
			const options = semanticInvocation(arg);
			const identity = semanticFunctionIdentity(options);
			let request: ApplyPrototypeRequest | undefined;
			if (options.returnType !== undefined || options.parameters !== undefined || options.callingConventionId !== undefined) {
				request = { ...options, functionIdentity: identity } as unknown as ApplyPrototypeRequest;
			} else if (!options.quiet) {
				request = await interactivePrototypeRequest(identity);
			}
			if (!request) {
				if (options.quiet) { throw new Error('applyPrototype requires a complete prototype request.'); }
				return undefined;
			}
			const prepared = await semanticService(options);
			const result = decorateSemanticCommandResult({ ...prepared.service.applyPrototype(request) });
			const outputPath = writeSemanticCommandOutput(options, result);
			refreshAfterSemanticCommand();
			announceSemanticCommand(options, result, 'Semantic prototype', outputPath);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.setCallingConvention', async (arg?: unknown) => {
			const options = semanticInvocation(arg);
			const identity = semanticFunctionIdentity(options);
			let callingConventionId = typeof options.callingConventionId === 'string'
				? options.callingConventionId
				: undefined;
			if (!callingConventionId && !options.quiet) {
				callingConventionId = await vscode.window.showQuickPick(
					['cdecl', 'stdcall', 'fastcall', 'thiscall', 'vectorcall', 'usercall', 'win64', 'sysv64', 'aapcs32', 'aapcs64'],
					{ placeHolder: 'Calling convention', ignoreFocusOut: true },
				);
			}
			if (!callingConventionId) {
				if (options.quiet) { throw new Error('setCallingConvention requires callingConventionId.'); }
				return undefined;
			}
			const request = {
				...options,
				functionIdentity: identity,
				callingConventionId,
			} as unknown as SetCallingConventionRequest;
			const prepared = await semanticService(options);
			const result = decorateSemanticCommandResult({ ...prepared.service.setCallingConvention(request) });
			const outputPath = writeSemanticCommandOutput(options, result);
			refreshAfterSemanticCommand();
			announceSemanticCommand(options, result, 'Calling convention', outputPath);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.setParameter', async (arg?: unknown) => {
			const options = semanticInvocation(arg);
			const identity = semanticFunctionIdentity(options);
			let ordinal = typeof options.ordinal === 'number' ? options.ordinal : undefined;
			let parameter = isRecord(options.parameter) ? options.parameter : undefined;
			if ((ordinal === undefined || !parameter) && !options.quiet) {
				const value = await vscode.window.showInputBox({
					prompt: 'Parameter patch as JSON',
					value: JSON.stringify({ ordinal: ordinal ?? 0, parameter: parameter ?? { name: 'arg0', type: 'uint64_t' } }),
					ignoreFocusOut: true,
				});
				if (value === undefined) { return undefined; }
				const parsed = JSON.parse(value) as { ordinal?: unknown; parameter?: unknown };
				ordinal = typeof parsed.ordinal === 'number' ? parsed.ordinal : undefined;
				parameter = isRecord(parsed.parameter) ? parsed.parameter : undefined;
			}
			if (ordinal === undefined || !parameter) {
				throw new Error('setParameter requires a numeric ordinal and a parameter patch.');
			}
			const request = {
				...options,
				functionIdentity: identity,
				ordinal,
				parameter,
			} as unknown as SetParameterRequest;
			const prepared = await semanticService(options);
			const result = decorateSemanticCommandResult({ ...prepared.service.setParameter(request) });
			const outputPath = writeSemanticCommandOutput(options, result);
			refreshAfterSemanticCommand();
			announceSemanticCommand(options, result, 'Semantic parameter', outputPath);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.clearOverride', async (arg?: unknown) => {
			const options = semanticInvocation(arg);
			const identity = semanticFunctionIdentity(options);
			const explicitIdentity = options.functionIdentity !== undefined || options.functionAddress !== undefined || options.address !== undefined;
			if (!options.quiet && !explicitIdentity) {
				const confirmation = await vscode.window.showWarningMessage(
					`Clear the analyst semantic override for ${identity}?`,
					{ modal: true },
					'Clear Override',
				);
				if (confirmation !== 'Clear Override') { return undefined; }
			}
			const request: ClearOverrideRequest = { functionIdentity: identity };
			const prepared = await semanticService(options);
			const result = decorateSemanticCommandResult({ ...prepared.service.clearOverride(request) });
			const outputPath = writeSemanticCommandOutput(options, result);
			if (result.changed === true) { refreshAfterSemanticCommand(); }
			announceSemanticCommand(options, result, 'Semantic override', outputPath);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.explainPrototype', async (arg?: unknown) => {
			const options = semanticInvocation(arg);
			const request: ExplainPrototypeRequest = { functionIdentity: semanticFunctionIdentity(options) };
			const prepared = await semanticService(options);
			const result = { ...prepared.service.explainPrototype(request), semanticStatus: 'ok' as const };
			const outputPath = writeSemanticCommandOutput(options, result);
			if (!options.quiet && !outputPath) {
				const document = await vscode.workspace.openTextDocument({
					language: 'json',
					content: `${JSON.stringify(result, null, 2)}\n`,
				});
				await vscode.window.showTextDocument(document, { preview: true });
			}
			announceSemanticCommand(options, result, 'Prototype explanation', outputPath);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.export', async (arg?: unknown) => {
			let options = semanticInvocation(arg);
			const prepared = await semanticService(options);
			if (!resolveSemanticOutputPath(options.output) && !options.quiet) {
				const target = engine.getFilePath();
				const uri = await vscode.window.showSaveDialog({
					defaultUri: target ? vscode.Uri.file(`${target}.hexcore-semantics.json`) : undefined,
					filters: { 'HexCore Semantic Export': ['json'] },
				});
				if (!uri) { return undefined; }
				options = { ...options, output: uri.fsPath };
			}
			const result = prepared.service.export();
			const outputPath = writeSemanticCommandOutput(options, result, prepared.service.exportCanonical());
			if (!options.quiet) {
				vscode.window.showInformationMessage(`Semantic model exported${outputPath ? `: ${outputPath}` : '.'}`);
			}
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.import', async (arg?: unknown) => {
			let options = semanticInvocation(arg) as Record<string, unknown> & SemanticImportCommandOptions;
			if (options.input === undefined && options.inputPath === undefined && !options.quiet) {
				const uris = await vscode.window.showOpenDialog({
					canSelectMany: false,
					canSelectFiles: true,
					canSelectFolders: false,
					filters: { 'HexCore Semantic Export': ['json'] },
				});
				if (!uris?.[0]) { return undefined; }
				options = { ...options, inputPath: uris[0].fsPath };
			}
			const prepared = await semanticService(options);
			const input = readSemanticImportInput(options);
			const result = decorateSemanticCommandResult({
				...prepared.service.import(input as string | SemanticCommandExportEnvelope),
			});
			const outputPath = writeSemanticCommandOutput(options, result);
			if (result.changedPrototypeCount > 0) { refreshAfterSemanticCommand(); }
			announceSemanticCommand(options, result, 'Semantic import', outputPath);
			return result;
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.references.query', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as ReferenceGraphCommandInvocationOptions & ReferenceGraphQueryCommandOptions;
			await prepareReferenceGraphTarget(options);
			const result = runReferenceGraphQuery(engine, options);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.references.export', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as ReferenceGraphCommandInvocationOptions & ReferenceGraphExportCommandOptions;
			await prepareReferenceGraphTarget(options);
			const result = runReferenceGraphExport(engine, options);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.propagation.solve', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as PropagationCommandOptions;
			await prepareReferenceGraphTarget(options);
			const result = await runPropagationSolve(engine, options);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.propagation.status', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as PropagationCommandOptions;
			await prepareReferenceGraphTarget(options);
			const result = runPropagationStatus(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.propagation.export', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as PropagationCommandOptions;
			await prepareReferenceGraphTarget(options);
			const result = runPropagationExport(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.list', async (arg?: unknown) => {
			const options = (isRecord(arg) ? arg : {}) as ReferenceGraphCommandInvocationOptions;
			await prepareReferenceGraphTarget(options);
			const result = runTypeList(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.create', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			if (!isRecord(options.spec)) { throw new Error('typeManager.create requires spec.'); }
			const result = runTypeCreate(engine, options.spec as never, typeof options.generation === 'number' ? options.generation : undefined);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.update', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			if (typeof options.typeId !== 'string' || !isRecord(options.patch)) { throw new Error('typeManager.update requires typeId and patch.'); }
			const result = runTypeUpdate(engine, options.typeId, options.patch as never, typeof options.generation === 'number' ? options.generation : undefined);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.rename', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			if (typeof options.typeId !== 'string' || typeof options.name !== 'string') { throw new Error('typeManager.rename requires typeId and name.'); }
			const result = runTypeRename(engine, options.typeId, options.name, typeof options.generation === 'number' ? options.generation : undefined);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.delete', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			if (typeof options.typeId !== 'string') { throw new Error('typeManager.delete requires typeId.'); }
			const result = runTypeDelete(engine, options.typeId, typeof options.generation === 'number' ? options.generation : undefined);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.undo', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			if (typeof options.typeId !== 'string') { throw new Error('typeManager.undo requires typeId.'); }
			const result = runTypeUndo(engine, options.typeId, typeof options.generation === 'number' ? options.generation : undefined);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.export', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			const result = runTypeExport(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.typeManager.import', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			let input = options.input;
			if (input === undefined && typeof options.inputPath === 'string') {
				input = JSON.parse(fs.readFileSync(path.resolve(options.inputPath), 'utf8'));
			}
			if (!isRecord(input)) { throw new Error('typeManager.import requires input or inputPath.'); }
			const result = runTypeImport(engine, input as unknown as TypeManagerExport);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.types.ingestDebug', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			const result = await runDebugTypeIngest(engine, isRecord(options.input) ? options.input as never : undefined, options as never);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.records.recover', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			const result = await runRecordRecovery(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.pdb.importSemantics', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			const result = await importPdbSemantics(engine, {
				...(typeof options.pdbPath === 'string' ? { pdbPath: options.pdbPath } : {}),
				...(typeof options.maxFunctions === 'number' ? { maxFunctions: options.maxFunctions } : {}),
			});
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.pdb.resolveSymbols', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			if (typeof options.pdbName !== 'string' || typeof options.guid !== 'string' || typeof options.age !== 'number' || typeof options.cacheDirectory !== 'string') {
				throw new Error('pdb.resolveSymbols requires pdbName, guid, age and cacheDirectory.');
			}
			const resolvedPath = await resolvePdbFromSymbolServers({
				pdbName: options.pdbName, guid: options.guid, age: options.age, cacheDirectory: options.cacheDirectory,
				...(Array.isArray(options.symbolServers) ? { symbolServers: options.symbolServers.filter((item): item is string => typeof item === 'string') } : {}),
			});
			const result = { ok: resolvedPath !== undefined, command: 'hexcore.pdb.resolveSymbols', resolvedPath: resolvedPath ?? null };
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.signatures.apply', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			const result = applyImportSignatureProvider(engine);
			writeReferenceGraphOutput(options, result);
			return result;
		}),
		vscode.commands.registerCommand('hexcore.semanticExplorer.open', async (arg?: unknown) => {
			const options = isRecord(arg) ? arg : {};
			await prepareReferenceGraphTarget(options);
			SemanticExplorerPanel.show(context.extensionUri, engine);
			return { ok: true, command: 'hexcore.semanticExplorer.open' };
		}),
	);

	// v3.7.4: Set/remove bookmark
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.setBookmark', async (arg?: any) => {
			if (arg && typeof arg === 'object' && 'address' in arg && 'label' in arg) {
				const addr = typeof arg.address === 'string' ? parseInt(arg.address, 16) : arg.address;
				engine.setBookmark(addr, arg.label);
				return { success: true };
			}
			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No address selected');
				return;
			}
			const label = await vscode.window.showInputBox({ prompt: 'Bookmark label:', value: `0x${addr.toString(16).toUpperCase()}` });
			if (label) {
				engine.setBookmark(addr, label);
				vscode.window.showInformationMessage(`Bookmark set: ${label}`);
			}
		})
	);

	// v3.7.4: Get session DB path (for HQL integration + pipeline headless)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.getSessionDbPath', (arg?: unknown) => {
			const store = engine.getSessionStore();
			const dbPath = store?.getDbPath() ?? null;
			const error = !store
				? (!engine.isFileLoaded()
					? 'No binary file loaded — session store not initialized'
					: 'Session store unavailable (hexcore-better-sqlite3 may not be installed)')
				: undefined;

			const result: Record<string, unknown> = { dbPath };
			if (error) {
				result.error = error;
			}

			// Headless pipeline support: write result to output file
			const options = (arg !== null && arg !== undefined && typeof arg === 'object') ? arg as Record<string, unknown> : {};
			if (options.output) {
				const outputPath = typeof options.output === 'string'
					? options.output
					: (options.output as { path: string }).path;
				fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
			}

			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.showCFG', async () => {
			const addr = disasmEditorProvider.getCurrentFunctionAddress()
				?? graphViewProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}

			const func = engine.getFunctionAt(addr);
			if (func) {
				await graphViewProvider.showFunctionInEditor(func);
			} else {
				vscode.window.showErrorMessage('Function data not found');
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.updateCFG', async () => {
			const addr = disasmEditorProvider.getCurrentFunctionAddress();
			const func = addr === undefined ? undefined : engine.getFunctionAt(addr);
			if (func) {
				await graphViewProvider.showFunction(func);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.searchString', async () => {
			const query = await vscode.window.showInputBox({
				prompt: 'Search string references',
				placeHolder: 'Enter string to search...'
			});
			if (query) {
				const results = await engine.searchStringReferences(query);
				stringRefProvider.setResults(results);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.constraints.solveHeadless', async (arg?: ConstraintSolverOptions) => {
			const options = arg ?? {};
			const result = await solveConstraints(options);
			if (!options.quiet) {
				vscode.window.showInformationMessage(
					`Z3 ${result.status}: ${result.modelCount} model(s) in ${result.metrics.elapsedMs}ms`
				);
			}
			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.buildFormula', async (arg?: BuildFormulaCommandOptions) => {
			const options = normalizeBuildFormulaCommandOptions(arg);
			const targetFilePath = await resolveAnalyzeAllTargetFilePath(undefined, options, engine);
			if (!targetFilePath) {
				throw new Error('No binary file is selected for formula extraction.');
			}

			const currentFile = engine.getFilePath();
			if (currentFile !== targetFilePath) {
				const loaded = await engine.loadFile(targetFilePath);
				if (!loaded) {
					throw new Error(`Failed to load file: ${targetFilePath}`);
				}
				await engine.analyzeAll();
			}

			const instructions = await resolveFormulaInstructions(engine, disasmEditorProvider, options);
			if (instructions.length === 0) {
				throw new Error('No instructions were resolved for formula extraction.');
			}

			const formula = buildInstructionFormula(instructions, options.targetRegister);
			const result = createBuildFormulaResult(targetFilePath, instructions, formula);
			if (options.output) {
				writeBuildFormulaOutput(result, options.output);
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					`Formula extracted (${result.targetRegister}): ${result.expression}`
				);
			}

			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.checkConstants', async (arg?: CheckConstantsCommandOptions) => {
			const options = normalizeCheckConstantsCommandOptions(arg);
			const targetFilePath = await resolveAnalyzeAllTargetFilePath(undefined, options, engine);
			if (!targetFilePath) {
				throw new Error('No binary file is selected for constant sanity check.');
			}

			const currentFile = engine.getFilePath();
			if (currentFile !== targetFilePath) {
				const loaded = await engine.loadFile(targetFilePath);
				if (!loaded) {
					throw new Error(`Failed to load file: ${targetFilePath}`);
				}
			}

			if (engine.getFunctions().length === 0 || currentFile !== targetFilePath) {
				await engine.analyzeAll();
			}

			const notesFilePath = resolveOptionalNotesFilePath(options.notesFile, targetFilePath);
			const instructions = collectAnalyzedInstructions(engine);
			const analysis = analyzeConstantSanity(instructions, {
				notesFilePath,
				maxFindings: options.maxFindings
			});

			const result: ConstantSanityResult = {
				filePath: targetFilePath,
				fileName: path.basename(targetFilePath),
				generatedAt: new Date().toISOString(),
				...analysis
			};

			if (options.output) {
				writeConstantSanityOutput(result, options.output);
			}

			if (!options.quiet) {
				if (result.mismatchedAnnotations > 0) {
					vscode.window.showWarningMessage(
						`Constant sanity checker found ${result.mismatchedAnnotations} mismatches.`
					);
				} else {
					vscode.window.showInformationMessage('Constant sanity checker found no mismatches.');
				}
			}

			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.exportASM', async () => {
			const uri = await vscode.window.showSaveDialog({
				filters: { 'Assembly': ['asm', 's'], 'Text': ['txt'] }
			});
			if (uri) {
				const result = await engine.exportAssembly(uri.fsPath);
				if (result.status === 'partial') {
					vscode.window.showWarningMessage(
						`Assembly exported with ${result.functionsWithoutInstructions}/${result.totalFunctions} empty function bodies: ${uri.fsPath}`
					);
				} else {
					vscode.window.showInformationMessage(`Assembly exported to ${uri.fsPath}`);
				}
			}
		})
	);

	// ============================================================================
	// Assembly & Patching Commands (LLVM MC)
	// ============================================================================

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.patchInstruction', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No instruction selected');
				return;
			}

			const newCode = await vscode.window.showInputBox({
				prompt: `Patch instruction at 0x${addr.toString(16)}`,
				placeHolder: 'mov rax, rbx'
			});

			if (newCode) {
				try {
					const result = await engine.patchInstruction(addr, newCode);
					if (result.success) {
						engine.applyPatch(addr, result.bytes);
						disasmEditorProvider.refresh();
						const msg = result.nopPadding > 0
							? `Patched with ${result.nopPadding} NOP padding`
							: 'Instruction patched successfully';
						vscode.window.showInformationMessage(msg);
					} else {
						vscode.window.showErrorMessage(`Patch failed: ${result.error}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Patch error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.nopInstruction', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const addr = disasmEditorProvider.getCurrentAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No instruction selected');
				return;
			}

			const confirm = await vscode.window.showQuickPick(['Yes', 'No'], {
				placeHolder: `NOP instruction at 0x${addr.toString(16)}?`
			});

			if (confirm === 'Yes') {
				try {
					const success = await engine.nopInstruction(addr);
					if (success) {
						disasmEditorProvider.refresh();
						vscode.window.showInformationMessage('Instruction replaced with NOPs');
					} else {
						vscode.window.showErrorMessage('Failed to NOP instruction');
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`NOP error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.assemble', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const code = await vscode.window.showInputBox({
				prompt: 'Assemble instruction',
				placeHolder: 'mov rax, 0x1234'
			});

			if (code) {
				try {
					const result = await engine.assemble(code);
					if (result.success) {
						const hex = result.bytes.toString('hex').toUpperCase().match(/.{2}/g)?.join(' ');
						vscode.window.showInformationMessage(`${result.size} bytes: ${hex}`);
					} else {
						vscode.window.showErrorMessage(`Assembly error: ${result.error}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Assembly error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.assembleMultiple', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const input = await vscode.window.showInputBox({
				prompt: 'Assemble multiple instructions (separate with ;)',
				placeHolder: 'push rbp; mov rbp, rsp; sub rsp, 0x20'
			});

			if (input) {
				const instructions = input.split(';').map(s => s.trim()).filter(s => s.length > 0);
				try {
					const results = await engine.assembleMultiple(instructions);
					const allBytes: Buffer[] = [];
					let hasError = false;

					for (const r of results) {
						if (r.success) {
							allBytes.push(r.bytes);
						} else {
							vscode.window.showErrorMessage(`Error in "${r.statement}": ${r.error}`);
							hasError = true;
							break;
						}
					}

					if (!hasError) {
						const combined = Buffer.concat(allBytes);
						const hex = combined.toString('hex').toUpperCase().match(/.{2}/g)?.join(' ');
						vscode.window.showInformationMessage(`${combined.length} bytes: ${hex}`);
					}
				} catch (error: any) {
					vscode.window.showErrorMessage(`Assembly error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.savePatchedFile', async () => {
			const uri = await vscode.window.showSaveDialog({
				filters: {
					'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
					'All Files': ['*']
				},
				saveLabel: 'Save Patched File'
			});

			if (uri) {
				try {
					engine.savePatched(uri.fsPath);
					vscode.window.showInformationMessage(`Patched file saved to ${uri.fsPath}`);
				} catch (error: any) {
					vscode.window.showErrorMessage(`Save error: ${error.message}`);
				}
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.setSyntax', async () => {
			if (!(await ensureAssemblerAvailable())) {
				return;
			}

			const syntax = await vscode.window.showQuickPick(['Intel', 'AT&T'], {
				placeHolder: 'Select assembly syntax'
			});

			if (syntax) {
				engine.setAssemblySyntax(syntax === 'Intel' ? 'intel' : 'att');
				vscode.window.showInformationMessage(`Syntax set to ${syntax}`);
			}
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.showLlvmVersion', () => {
			engine.getAssemblerAvailability().then((availability) => {
				if (!availability.available) {
					const detail = availability.error ? ` ${availability.error}` : '';
					vscode.window.showErrorMessage(
						vscode.l10n.t('LLVM MC engine is not available.{0}', detail)
					);
					return;
				}
				const version = engine.getLlvmVersion();
				vscode.window.showInformationMessage(`LLVM MC Version: ${version}`);
			});
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.nativeStatus', async () => {
			await showNativeStatus();
		})
	);

	// -----------------------------------------------------------------------
	// Live-memory disassembly — raw bytes supplied by the Debugger.
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.disassembleBufferHeadless', async (arg?: Record<string, unknown>) => {
			const bytesBase64 = typeof arg?.bytesBase64 === 'string' ? arg.bytesBase64 : undefined;
			const addressText = typeof arg?.address === 'string' ? arg.address : undefined;
			const archText = typeof arg?.arch === 'string' ? arg.arch : undefined;
			if (!bytesBase64 || !addressText || !archText) {
				throw new Error('disassembleBufferHeadless requires "bytesBase64", "address", and "arch".');
			}
			if (!['x86', 'x64', 'arm', 'arm64', 'mips', 'mips64'].includes(archText)) {
				throw new Error(`disassembleBufferHeadless does not support architecture "${archText}".`);
			}
			const bytes = Buffer.from(bytesBase64, 'base64');
			if (bytes.length === 0 || bytes.length > 4 * 1024 * 1024) {
				throw new Error('disassembleBufferHeadless requires between 1 byte and 4 MiB.');
			}
			const address = BigInt(addressText);
			if (address < 0n || address > BigInt(Number.MAX_SAFE_INTEGER)) {
				throw new Error('disassembleBufferHeadless address is outside the exact JavaScript integer range.');
			}

			const memoryEngine = new DisassemblerEngine();
			try {
				memoryEngine.loadBuffer(bytes, Number(address), archText as ReturnType<typeof engine.getArchitecture>);
				const instructions = await memoryEngine.disassembleRange(Number(address), bytes.length);
				const result = {
					success: instructions.length > 0,
					source: 'debugger-live-memory',
					address: `0x${address.toString(16)}`,
					size: bytes.length,
					architecture: archText,
					instructions: instructions.map(i => ({
						address: `0x${i.address.toString(16)}`,
						bytes: Buffer.from(i.bytes).toString('hex'),
						mnemonic: i.mnemonic,
						opStr: i.opStr,
						size: i.size,
					})),
				};
				const outputPath = typeof arg?.output === 'string'
					? arg.output
					: (arg?.output as { path?: string } | undefined)?.path;
				if (outputPath) {
					fs.mkdirSync(path.dirname(outputPath), { recursive: true });
					fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
				}
				return result;
			} finally {
				memoryEngine.dispose();
			}
		})
	);

	// -----------------------------------------------------------------------
	// Live-memory lifting — bytes supplied by the Debugger, never materialized
	// as a derived executable on disk.
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.liftMemoryHeadless', async (arg?: Record<string, unknown>) => {
			const bytesBase64 = typeof arg?.bytesBase64 === 'string' ? arg.bytesBase64 : undefined;
			const addressText = typeof arg?.address === 'string' ? arg.address : undefined;
			const archText = typeof arg?.arch === 'string' ? arg.arch : undefined;
			const targetOs = typeof arg?.targetOs === 'string' ? arg.targetOs : undefined;
			if (!bytesBase64 || !addressText || !archText) {
				throw new Error('liftMemoryHeadless requires "bytesBase64", "address", and "arch".');
			}
			if (!['x86', 'x64', 'arm', 'arm64'].includes(archText)) {
				throw new Error(`liftMemoryHeadless does not support architecture "${archText}".`);
			}
			if (!remillWrapper.isAvailable()) {
				return { success: false, ir: '', error: 'hexcore-remill is not available.', bytesConsumed: 0 };
			}

			const bytes = Buffer.from(bytesBase64, 'base64');
			if (bytes.length === 0 || bytes.length > 4 * 1024 * 1024) {
				throw new Error('liftMemoryHeadless requires between 1 byte and 4 MiB of live memory.');
			}
			const address = BigInt(addressText);
			if (address < 0n || address > BigInt(Number.MAX_SAFE_INTEGER)) {
				throw new Error('liftMemoryHeadless address is outside the exact JavaScript integer range.');
			}
			const maxInstructions = typeof arg?.maxInstructions === 'number'
				? Math.min(Math.max(Math.trunc(arg.maxInstructions), 1), 256_000)
				: Math.min(Math.max(Math.ceil(bytes.length / 2) + 4096, 8000), 256_000);
			const maxBasicBlocks = typeof arg?.maxBasicBlocks === 'number'
				? Math.min(Math.max(Math.trunc(arg.maxBasicBlocks), 1), 64_000)
				: Math.min(Math.max(Math.ceil(bytes.length / 4) + 1024, 4096), 64_000);
			const liftOptions: RemillLiftOptions = {
				maxBytes: bytes.length,
				maxInstructions,
				maxBasicBlocks,
				optimizeIR: arg?.optimizeIR !== false,
				inlineSemantics: arg?.inlineSemantics !== false,
				splitAtCalls: arg?.splitAtCalls !== false,
			};
			const result = await remillWrapper.liftBytes(
				bytes,
				Number(address),
				archText as ReturnType<typeof engine.getArchitecture>,
				targetOs,
				liftOptions,
			);
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (arg?.output as { path?: string } | undefined)?.path;
			if (outputPath && result.success) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, result.ir, 'utf8');
			}
			return {
				...result,
				address: `0x${address.toString(16)}`,
				architecture: archText,
				source: 'debugger-live-memory',
				requestedBytes: bytes.length,
			};
		})
	);

	// -----------------------------------------------------------------------
	// [Experimental] Lift to LLVM IR
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.liftToIR', async (arg?: unknown) => {
			// Headless mode: arg is an options object with file/address/startAddress/size
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'startAddress' in (arg as Record<string, unknown>) || 'address' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;

			if (!remillWrapper.isAvailable()) {
				const errorMsg = 'hexcore-remill is not available. Install the prebuild or build from source.';
				if (quiet) {
					return { success: false, ir: '', address: 0, bytesConsumed: 0, architecture: '', error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			const requestedArch = typeof options.architecture === 'string'
				? options.architecture
				: typeof options.arch === 'string' ? options.arch : undefined;
			const arch = requestedArch && ['x86', 'x64', 'arm', 'arm64'].includes(requestedArch)
				? requestedArch as ReturnType<typeof engine.getArchitecture>
				: engine.getArchitecture();
			const mapping = mapCapstoneToRemill(arch);
			if (!mapping.supported) {
				const errorMsg = `Architecture '${arch}' is not supported by Remill. Supported: x86, x64.`;
				if (quiet) {
					return { success: false, ir: '', address: 0, bytesConsumed: 0, architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			let startAddress: number;
			let size: number;
			let functionName: string | undefined;
			let didBacktrack = false;
			let backtrackOriginalAddress: number | undefined;
			const liftTransformations: LiftPreambleTransformation[] = [];
			const requestedInstructionLimit = coercePositiveInt(options.count);
			let explicitScopeLimited = false;
			let liftWindow: ResolvedLiftByteSize | undefined;
			// v3.8.0-nightly: trampoline follow metadata (Milestone 4.1). Populated
			// when the resolved entry turns out to be a single unconditional JMP.
			let trampolineOriginalAddress: number | undefined;
			let trampolineChain: Array<{ from: number; to: number; mnemonic: string }> = [];

			// Resolve bytes: from headless options, selected function, or user input
			if (isHeadless && options.file) {
				// Headless: load file if needed
				const filePath = String(options.file);
				if (!engine.isFileLoaded() || engine.getFilePath() !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						const errorMsg = `Failed to load file: ${filePath}`;
						if (quiet) {
							return { success: false, ir: '', address: 0, bytesConsumed: 0, architecture: '', error: errorMsg };
						}
						vscode.window.showErrorMessage(errorMsg);
						return undefined;
					}
				}
				// Issue #32 (HONESTY): a managed .NET (CIL) assembly carries a CLR Runtime
				// Header and CIL (not native x86) in .text. Lifting it as x86 yields the
				// _CorExeMain thunk + mis-decoded metadata, which the decompiler then dresses
				// up as a confident "stub function". Refuse the native lift with a structured
				// honest error rather than emitting garbage IR (use a .NET/IL decompiler).
				if (engine.getPEDataDirectories().clr) {
					const errorMsg = 'managed .NET (CIL) assembly — native x86 lift not applicable; use a .NET/IL decompiler';
					if (quiet) {
						return { success: false, ir: '', address: 0, bytesConsumed: 0, architecture: arch, error: errorMsg, managed: true };
					}
					vscode.window.showWarningMessage(
						'Managed .NET (CIL) assembly: native x86 lift is not applicable. Use a .NET/IL decompiler (ILSpy / dnSpyEx).'
					);
					return undefined;
				}
				// v0.9.1 (G-001): when `symbolName:` is given, resolve via
				// the ELF `.symtab` to pick the right section's bytes —
				// every ET_REL code section starts at VA 0, so
				// `address: "0x0"` alone always picks `.text` (collides
				// with `init_module` at `.init.text:0x0`). The symbol
				// lookup returns the exact bytes from the file, which
				// we feed straight to the lifter; the address-table
				// lookup below is then skipped.
				const symbolNameArg = typeof options.symbolName === 'string'
					? options.symbolName : undefined;
				if (symbolNameArg) {
					const sym = engine.findFunctionSymbolByName(symbolNameArg);
					if (!sym) {
						const candidates = engine.getElfFunctionSymbols()
							.map(s => `${s.name} (${s.section}@+0x${s.offsetInSection.toString(16)})`)
							.slice(0, 20).join(', ');
						const errorMsg =
							`Symbol "${symbolNameArg}" not found in ${filePath}'s symbol table. ` +
							(candidates ? `Candidates: ${candidates}` : 'No function symbols found.');
						if (quiet) {
							return { success: false, ir: '', address: 0, bytesConsumed: 0, architecture: arch, error: errorMsg };
						}
						vscode.window.showErrorMessage(errorMsg);
						return undefined;
					}
					// Lift directly from the symbol's exact bytes,
					// bypassing the address-based byte resolution.
					const liftBuf = sym.bytes;
					const liftAddr = sym.address;
					functionName = symbolNameArg;
					console.log(
						`[HexCore] liftToIR G-001: resolved symbol "${symbolNameArg}" -> ` +
						`section ${sym.section} @+0x${liftAddr.toString(16)}, ${sym.size} bytes`
					);
					try {
						const liftResult = await remillWrapper.liftBytes(
							liftBuf, liftAddr, arch, 'linux',
							{ maxBytes: liftBuf.length },
						);
						if (!liftResult.success) {
							return { success: false, ir: '', address: liftAddr, bytesConsumed: 0, architecture: arch, error: liftResult.error || 'remill lift failed' };
						}
						const irHeader = buildIRHeader({
							fileName: path.basename(filePath),
							functionName,
							address: liftAddr,
							size: sym.size,
							architecture: arch,
						});
						const fullIR = irHeader + liftResult.ir;
						if (typeof options.output === 'object' && options.output && 'path' in (options.output as any)) {
							const outPath = (options.output as any).path;
							const resolved = path.isAbsolute(outPath)
								? outPath : path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', outPath);
							fs.writeFileSync(resolved, fullIR, 'utf-8');
						}
						return {
							success: true,
							ir: fullIR,
							address: liftAddr,
							bytesConsumed: liftResult.bytesConsumed ?? sym.size,
							architecture: arch,
							functionName,
							section: sym.section,
						};
					} catch (e: any) {
						return { success: false, ir: '', address: liftAddr, bytesConsumed: 0, architecture: arch, error: `lift threw: ${e?.message ?? e}` };
					}
				}

				// FIX (HEXCORE_DEFEAT FAIL 3): use resolveAddressArg so symbolic
				// keywords like "entry", "first", "main" resolve properly. The
				// previous parseAddressValue chain returned undefined for "entry"
				// and fell through to baseAddress (e.g. 0x140000000 / DOS header),
				// causing Helix to decompile garbage from the MZ header.
				startAddress = resolveAddressArg(options.address as string | number | undefined, engine)
					?? resolveAddressArg(options.startAddress as string | number | undefined, engine)
					?? engine.getBaseAddress();
				// Auto-backtrack: if address is mid-function, find the real start (FEAT-DISASM-004 / BUG-HELIX-002)
				backtrackOriginalAddress = startAddress;
				if (options.autoBacktrack !== false) {
					const backtrack = await resolveAutoBacktrack(engine, startAddress);
					if (backtrack) {
						console.log(
							`[HexCore] liftToIR auto-backtrack (${backtrack.source}): ` +
							`0x${startAddress.toString(16)} -> 0x${backtrack.start.toString(16)}`
						);
						startAddress = backtrack.start;
						didBacktrack = true;
					}
				}
				// v3.8.0-nightly — Trampoline follow (Milestone 4.1). After
				// backtrack resolved, check if the current start is a single
				// unconditional JMP (packer stub, VMP/Themida wrap, vgk.sys
				// entry). Follow the chain and re-point startAddress at the
				// real function so Remill lifts real code instead of emitting
				// `void { return; }` for the trampoline.
				if (options.followTrampoline !== false) {
					const trampoline = await followTrampolineChain(engine, startAddress);
					if (trampoline.hops.length > 0) {
						trampolineOriginalAddress = startAddress;
						trampolineChain = trampoline.hops;
						console.log(`[HexCore] liftToIR trampoline: 0x${startAddress.toString(16)} -> 0x${trampoline.target.toString(16)} (${trampoline.hops.length} hops)`);
						startAddress = trampoline.target;
					}
				}
				// FIX-027c: loadFile alone does not run analyzeAll's .pdata
				// reconciliation. Without this barrier, a chained-unwind function
				// is sized from its first raw RUNTIME_FUNCTION fragment and that
				// short end is passed to Remill as knownFunctionEnds. The PE64 scan
				// then stops before the remaining fragments (SOTTR HealthData:
				// 137/701 bytes). The engine method is one-shot per loaded file.
				await engine.ensurePdataFunctionsReconciled();
				// FIX-QUALITY-002 / 002d: coerce stringy job args + clamp using
				// AUTHORITATIVE extent (.pdata preferred over prologue-scan size).
				// Log proof: knownSize=4800 from table but pdata end=0x140027e85
				// (6761). Clamping to the short size permanently under-lifts.
				{
					const extent = getAuthoritativeFunctionExtent(engine, startAddress);
					// Heal undersized table entries so later primaryEnd matches.
					const knownFn = engine.getFunctionAt(startAddress);
					if (knownFn && extent.size > knownFn.size) {
						knownFn.size = extent.size;
						knownFn.endAddress = extent.end;
						console.log(
							`[HexCore] liftToIR FIX-QUALITY-002d: healed fn table size ` +
							`${knownFn.size} → ${extent.size} via ${extent.source} ` +
							`end=0x${extent.end.toString(16)}`
						);
					}
					const resolved = resolveLiftByteSize({
						startAddress,
						endExclusive: options.endExclusive,
						stopAtFunctionBoundary: options.stopAtFunctionBoundary === true,
						size: options.size,
						count: options.count,
						knownFunctionSize: extent.size,
						bufferSize: engine.getBufferSize(),
						// FIX-QUALITY-002e: ET_REL symbol/analyzeAll sizes may cover
						// only a hot fragment. Preserve an explicit job byte window;
						// PE keeps the authoritative `.pdata` clamp.
						allowOversizedLift: shouldHonorExplicitLiftWindow(
							options, engine.getFileInfo()?.isRelocatable === true),
					});
					size = resolved.size;
					explicitScopeLimited = resolved.scopeLimited === true;
					liftWindow = resolved;
					console.log(
						`[HexCore] liftToIR FIX-QUALITY-002: size=${size} reason=${resolved.reason}` +
						(resolved.clampedFrom !== undefined ? ` (was ${resolved.clampedFrom})` : '') +
						` knownSize=${extent.size} src=${extent.source} @0x${startAddress.toString(16)}`
					);
				}
			} else if (isHeadless && options.functionAddress !== undefined) {
				startAddress = typeof options.functionAddress === 'number' ? options.functionAddress : 0;
				// Auto-backtrack: find real function start if address is mid-function
				backtrackOriginalAddress = startAddress;
				if (options.autoBacktrack !== false) {
					const backtrack = await resolveAutoBacktrack(engine, startAddress);
					if (backtrack) {
						console.log(
							`[HexCore] liftToIR auto-backtrack (${backtrack.source}): ` +
							`0x${startAddress.toString(16)} -> 0x${backtrack.start.toString(16)}`
						);
						startAddress = backtrack.start;
						didBacktrack = true;
					}
				}
				const func = engine.getFunctionAt(startAddress);
				if (func) {
					const resolved = resolveLiftByteSize({
						startAddress,
						endExclusive: options.endExclusive,
						stopAtFunctionBoundary: options.stopAtFunctionBoundary === true,
						size: options.size,
						count: options.count,
						knownFunctionSize: func.endAddress - func.address,
						bufferSize: engine.getBufferSize(),
						allowOversizedLift: shouldHonorExplicitLiftWindow(
							options, engine.getFileInfo()?.isRelocatable === true),
					});
					size = resolved.size;
					explicitScopeLimited = resolved.scopeLimited === true;
					liftWindow = resolved;
					functionName = func.name;
				} else {
					// v3.7.5 FIX: Smart sizing — symbol table → count → 4096 (was 256)
					const resolved = resolveLiftByteSize({
						startAddress,
						endExclusive: options.endExclusive,
						stopAtFunctionBoundary: options.stopAtFunctionBoundary === true,
						size: options.size,
						count: options.count,
						knownFunctionSize: 0,
						bufferSize: engine.getRecommendedLiftSize(startAddress, 4096),
					});
					size = resolved.size;
					explicitScopeLimited = resolved.scopeLimited === true;
					liftWindow = resolved;
				}

				// (Symtab lookup moved to shared code below, before IR rename)
			} else {
				// Interactive: ask user for address and size
				const addrInput = await vscode.window.showInputBox({
					prompt: 'Start address (hex, e.g. 0x401000)',
					placeHolder: '0x401000',
				});
				if (!addrInput) {
					return undefined;
				}
				startAddress = parseInt(addrInput, 16);
				if (isNaN(startAddress)) {
					vscode.window.showErrorMessage(`Invalid address: ${addrInput}`);
					return undefined;
				}

				const sizeInput = await vscode.window.showInputBox({
					prompt: 'Size in bytes',
					placeHolder: '256',
					value: '256',
				});
				if (!sizeInput) {
					return undefined;
				}
				size = parseInt(sizeInput, 10);
				if (isNaN(size) || size <= 0) {
					vscode.window.showErrorMessage(`Invalid size: ${sizeInput}`);
					return undefined;
				}
				liftWindow = {
					size,
					reason: 'interactive-byte-size',
					countingDomain: 'byte-range',
				};
			}

			const effectiveInstructionLimit = liftWindow?.countingDomain === 'instruction-count-heuristic'
				? requestedInstructionLimit
				: undefined;

			// Extract bytes from engine buffer (addressToOffset handles VA→file offset)
			if (!engine.isFileLoaded()) {
				const errorMsg = 'No binary file is loaded. Open a file in the disassembler first.';
				// Bug #36/2: missing-input -> structured error for headless/pipeline runs.
				if (quiet || isHeadless) {
					return { success: false, ir: '', address: startAddress, bytesConsumed: 0, architecture: mapping.remillArch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// v3.8.0: Section-aware lifting for ELF kernel modules
			// When allExecutableSections is true, lift all executable sections separately
			if (isHeadless && options.allExecutableSections === true) {
				return liftAllExecutableSections({
					engine,
					remillWrapper,
					quiet,
					options,
					mapping
				});
			}

			let bytes = engine.getBytes(startAddress, size); // let: FIX-011 may reassign with patched buffer
			if (!bytes || bytes.length === 0) {
				const loadedFile = engine.getFilePath() ? path.basename(engine.getFilePath()!) : 'unknown';
				const base = engine.getBaseAddress();
				const bufSize = engine.getBufferSize();
				const errorMsg = `Address 0x${startAddress.toString(16)} is outside the loaded binary "${loadedFile}" (base=0x${base.toString(16)}, size=0x${bufSize.toString(16)}).`;
				// Bug #36/2: no code at the requested address -> structured error for the
				// pipeline runner, never undefined + modal in a headless auto-run.
				if (quiet || isHeadless) {
					return { success: false, ir: '', address: startAddress, bytesConsumed: 0, architecture: mapping.remillArch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// v3.7.5 FIX-017: Skip CET endbr64 + ftrace __fentry__ preamble.
			// Remill's amd64 semantics may not support endbr64 (F3 0F 1E FA),
			// causing it to decode every byte as a 1-byte instruction (ADD/OR/XOR).
			// Also skip `call __fentry__` (E8 00 00 00 00) which is a NOP sled
			// patched by ftrace at runtime. Both appear at the start of Linux
			// kernel module functions compiled with -fcf-protection and -pg.
			{
				const fileInfo = engine.getFileInfo();
				const isRelocatableElf = fileInfo?.isRelocatable === true;
				const firstBytes = Array.from(bytes.subarray(0, Math.min(16, bytes.length))).map(b => b.toString(16).padStart(2, '0')).join(' ');
				console.log(`[HexCore] liftToIR FIX-017 probe: addr=0x${startAddress.toString(16)} first16=[${firstBytes}] len=${bytes.length}`);
				const preamblePlan = planLiftPreamble(bytes, startAddress, isRelocatableElf);
				const skip = preamblePlan.skipBytes;
				liftTransformations.push(...preamblePlan.transformations);

				if (skip > 0) {
					console.log(`[HexCore] liftToIR FIX-017: Skipping ${skip}-byte CET/ftrace preamble at 0x${startAddress.toString(16)} (endbr64+__fentry__)`);
					bytes = bytes.subarray(skip);
					startAddress += skip;
				}
			}

			// Update size to actual bytes extracted (may be truncated at file boundary)
			size = bytes.length;

			// FIX-011: For ET_REL (relocatable ELF), pre-patch call displacements
			// so the Remill lifter sees real call targets instead of `call +5` (NOP).
			// Without patching, unresolved relocations have displacement=0, which
			// makes calls disappear from the IR (fall-through optimization).
			// Strategy: patch bytes → Remill emits `call @sub_<fakeAddr>` →
			// post-process IR to replace `@sub_<fakeAddr>` with `@mutex_lock` etc.
			let symbolMap: Map<number, string> | undefined; // fakeAddr → symbolName
			// FIX-097: relocated data sections (fake base VA → raw section bytes)
			// carried from the byte-patch step to the post-lift metadata emit.
			let dataSectionFakes: Array<{ vaStart: number; bytes: Buffer }> | undefined;
			const fileInfo = engine.getFileInfo();
			const textRelocs = engine.getTextRelocations();

			console.log(`[HexCore] liftToIR FIX-011: isRelocatable=${fileInfo?.isRelocatable}, textRelocs.size=${textRelocs.size}`);
			if (fileInfo?.isRelocatable && textRelocs.size > 0) {
				const patchedBytes = Buffer.from(bytes);
				symbolMap = new Map();
				let fakeAddr = 0x7FFF0000; // fake address space for external symbols
				const symbolAddrs = new Map<string, number>(); // dedup: name → fakeAddr

				const textSection = engine.getSections().find(s => s.name === '.text');
				const textSectionVA = textSection?.virtualAddress ?? 0;
				const liftOffsetInText = startAddress - textSectionVA;
				let patchCount = 0;

				// Kernel infrastructure — NOPs at runtime, skip patching.
				// FIX-098: do NOT skip __x86_return_thunk. Spectre/retbleed-mitigated
				// kernel modules (e.g. mali_kbase.ko = 2641 of them) compile EVERY
				// `ret` as `jmp __x86_return_thunk` (e9 00000000 + PLT32 reloc, no c3
				// byte). Skipping the reloc left the displacement 0, so Remill decoded
				// the jmp as `jmp PC+5` = a forward branch into the body, NOT a return
				// -> the lifted IR had ZERO `ret` edges -> every early return orphaned
				// the rest of the body = the "N unreachable statements after return"
				// premature-return defect. By PATCHING it like a normal symbol (below),
				// the jmp target lands in externalSymbols_ and the native Remill FIX-019
				// (remill_wrapper.cpp ~915/1224) recognizes the name and emits a RET in
				// Phase 4. (The __x86_indirect_thunk_* retpolines stay skipped — those
				// are indirect call/jump trampolines, not returns.)
				const infraSymbols = new Set([
					'__fentry__', '__cfi_check',
					'__x86_indirect_thunk_rax', '__x86_indirect_thunk_rbx',
					'__x86_indirect_thunk_rcx', '__x86_indirect_thunk_rdx',
					'__x86_indirect_thunk_rsi', '__x86_indirect_thunk_rdi',
					'__x86_indirect_thunk_rbp', '__x86_indirect_thunk_r8',
					'__x86_indirect_thunk_r9', '__x86_indirect_thunk_r10',
					'__x86_indirect_thunk_r11', '__x86_indirect_thunk_r12',
					'__x86_indirect_thunk_r13', '__x86_indirect_thunk_r14',
					'__x86_indirect_thunk_r15',
				]);

				for (const [textOffset, reloc] of textRelocs) {
					// Only patch relocations within our lift range
					const patchOffset = textOffset - liftOffsetInText;
					if (patchOffset < 0 || patchOffset + 4 > patchedBytes.length) {
						continue;
					}
					if (infraSymbols.has(reloc.name)) {
						continue;
					}
					// R_X86_64_PLT32(4) and PC32(2) are direct call/jump relocations
					if (reloc.type !== 2 && reloc.type !== 4) {
						continue;
					}

					// Allocate or reuse fake address for this symbol
					let targetAddr = symbolAddrs.get(reloc.name);
					if (targetAddr === undefined) {
						targetAddr = fakeAddr;
						fakeAddr += 0x10; // 16-byte spacing
						symbolAddrs.set(reloc.name, targetAddr);
					}

					// Patch the 32-bit displacement: S + A - P
					// P = virtual address of the relocation site
					const relocVA = textSectionVA + textOffset;
					const displacement = (targetAddr + reloc.addend - relocVA) | 0;
					patchedBytes.writeInt32LE(displacement, patchOffset);

					// Record the RESOLVED target that Remill will actually see:
					// target = PC_after_call + displacement = (relocVA + 4) + displacement
					// This accounts for the addend (typically -4 for R_X86_64_PLT32)
					const resolvedTarget = ((relocVA + 4) + displacement) >>> 0;
					if (!symbolMap.has(resolvedTarget)) {
						symbolMap.set(resolvedTarget, reloc.name);
					}
					patchCount++;
				}

				console.log(`[HexCore] liftToIR FIX-011: Patched ${patchCount} call displacements, ` +
					`${symbolMap.size} unique external symbols (fakeAddr range 0x7FFF0000–0x${(fakeAddr - 0x10).toString(16)})`);

				// Use patched buffer for lifting
				bytes = patchedBytes;
			}

			// FIX-097: patch DATA relocations (string/constant loads). The engine
			// collected R_X86_64_32/32S relocs against SECTION symbols (e.g.
			// `mov rdi, .rodata.str1.1+OFF`) that FIX-011 dropped, leaving the
			// operand `i64 0` => `printk(0, ...)`. We assign each referenced data
			// section a non-overlapping fake base VA (well below the 0x7FFF0000 call
			// range), patch the absolute 32-bit operand to base+offset, and carry the
			// section bytes out as `dataSectionFakes`. The post-lift step embeds them
			// as `!helix.strings` metadata so the decompiler can readCString(base+OFF)
			// and render the real string literal.
			const dataRelocs = engine.getDataRelocations();
			if (fileInfo?.isRelocatable && dataRelocs.size > 0) {
				const patchedBytes = Buffer.from(bytes); // may already carry FIX-011 patches
				const textSection = engine.getSections().find(s => s.name === '.text');
				const textSectionVA = textSection?.virtualAddress ?? 0;
				const liftOffsetInText = startAddress - textSectionVA;
				const sectionFakeBase = new Map<string, number>(); // section → fake base VA
				let nextBase = 0x7F000000;
				let dataPatchCount = 0;

				for (const [textOffset, dreloc] of dataRelocs) {
					const patchOffset = textOffset - liftOffsetInText;
					if (patchOffset < 0 || patchOffset + 4 > patchedBytes.length) {
						continue; // outside our lift window
					}
					// String literals live in .rodata*; skip .data/.text/module
					// pointer relocs so we don't mis-render real data pointers as
					// strings (and don't disturb their existing `i64 0` semantics).
					if (!dreloc.sectionName.startsWith('.rodata')) {
						continue;
					}
					let base = sectionFakeBase.get(dreloc.sectionName);
					if (base === undefined) {
						base = nextBase;
						nextBase += 0x00100000; // 1 MiB spacing per section
						sectionFakeBase.set(dreloc.sectionName, base);
					}
					const targetAddress = base + dreloc.addend;
					if (dreloc.type === 2) {
						// R_X86_64_PC32 is consumed by a RIP-relative operand.
						// Encode from the end of its four-byte displacement so
						// Remill observes the synthetic .rodata address exactly.
						const relocVA = textSectionVA + textOffset;
						const displacement = encodeX86PcRelativeDataDisplacement(
							targetAddress,
							relocVA,
						);
						patchedBytes.writeInt32LE(displacement, patchOffset);
					} else {
						// R_X86_64_32/32S store an absolute 32-bit value.
						patchedBytes.writeInt32LE(targetAddress | 0, patchOffset);
					}
					dataPatchCount++;
				}

				if (dataPatchCount > 0) {
					dataSectionFakes = [];
					for (const [name, base] of sectionFakeBase) {
						const secBytes = engine.getSectionBytesByName(name);
						if (secBytes && secBytes.length > 0) {
							dataSectionFakes.push({ vaStart: base, bytes: secBytes });
						}
					}
					bytes = patchedBytes;
				}
				console.log(`[HexCore] liftToIR FIX-097: patched ${dataPatchCount} data relocs across ` +
					`${sectionFakeBase.size} section(s); ${dataSectionFakes?.length ?? 0} fake data section(s) ` +
					`carried (bases from 0x7F000000): ${[...sectionFakeBase].map(([n, b]) => `${n}@0x${b.toString(16)}`).join(', ')}`);
			}

			// Note: callfuscation deflattening (call-as-jmp) is applied centrally in
			// RemillWrapper.liftBytes() so every lift path (liftToIR, helix.decompile,
			// rellic) benefits uniformly. See deflattenCallfuscation() in pathfinder.ts.

			// FIX-011: Pass external symbol map to Remill C++ Phase 5.6
			if (symbolMap && symbolMap.size > 0) {
				remillWrapper.setExternalSymbols(symbolMap);
			}

			// Build format-specific lift options (Item 2 + Item 3)
			const fmt = fileInfo?.format ?? '';
			const targetOs = fmt.startsWith('ELF') ? 'linux'
				: (fmt === 'PE' || fmt === 'PE64') ? 'windows'
					: undefined;

			const liftOpts: RemillLiftOptions = {};
			let liftBufferAddress = startAddress;
			const callfuscationEvidence = engine.detectCallfuscation();
			if (callfuscationEvidence.detected && options.deflattenCallfuscation !== false) {
				if (effectiveInstructionLimit !== undefined) {
					liftOpts.deflattenCallfuscation = true;
					liftOpts.entryAddress = startAddress;
					liftOpts.reachableOnly = true;
					console.log(
						`[HexCore] callfuscation lift: preserving explicit count=${effectiveInstructionLimit} ` +
						`within bounded window @0x${startAddress.toString(16)}+${bytes.length}`
					);
				} else {
					const section = engine.getSections().find(candidate => {
						const end = candidate.virtualAddress + Math.max(candidate.virtualSize, candidate.rawSize);
						return (candidate.isCode || candidate.isExecutable) &&
							startAddress >= candidate.virtualAddress && startAddress < end;
					});
					const sectionBytes = section
						? engine.getBytes(section.virtualAddress, section.rawSize)
						: undefined;
					if (section && sectionBytes && sectionBytes.length > 0) {
						bytes = sectionBytes;
						liftBufferAddress = section.virtualAddress;
						liftOpts.deflattenCallfuscation = true;
						liftOpts.entryAddress = startAddress;
						liftOpts.reachableOnly = true;
						console.log(
							`[HexCore] callfuscation lift: entry=0x${startAddress.toString(16)}, ` +
							`window=${section.name}@0x${section.virtualAddress.toString(16)}+${sectionBytes.length}`
						);
					} else {
						console.warn('[HexCore] callfuscation detected, but no containing executable section was available; using the bounded lift window');
					}
				}
			}

			// FIX-QUALITY-002 / 002c / 002d: single-function lift scope.
			// Primary end MUST come from .pdata when larger than the function
			// table (prologue-scan undersize = 4800 vs pdata 6761).
			// Do NOT flood additionalLeaders — Remill discovers BBs itself.
			const extent = getAuthoritativeFunctionExtent(engine, startAddress);
			const primaryFn = engine.getFunctionAt(startAddress);
			if (primaryFn && extent.size > primaryFn.size) {
				primaryFn.size = extent.size;
				primaryFn.endAddress = extent.end;
			}
			const primaryEnd = extent.end > startAddress
				? extent.end
				: (startAddress + bytes.length);
			const knownFnSize = extent.size > 0
				? extent.size
				: (primaryEnd - startAddress);

			if (fmt === 'PE' || fmt === 'PE64') {
				liftOpts.liftMode = 'pe64';
				// Only the primary function end (absolute VA).
				liftOpts.knownFunctionEnds = [primaryEnd];
			} else if (fileInfo?.isRelocatable) {
				liftOpts.liftMode = 'elf_relocatable';
			}

			// Pathfinder: #51 inject ONLY jump-table case targets as Remill
			// additionalLeaders (not the full BB leader flood — that races
			// maxBasicBlocks and under-lifts). Full leader injection remains
			// opt-in via allowOversizedLift.
			let pathfinderOwnershipEnd: number | undefined;
			try {
				const cfgHints = await runPathfinder(engine, startAddress, bytes);
				pathfinderOwnershipEnd = cfgHints.ownershipEnd;
				const rangeHi = Math.min(primaryEnd, startAddress + bytes.length);
				const jtTargets = (cfgHints.indirectJumps ?? [])
					.filter(j => j.type === 'jump_table')
					.flatMap(j => j.targets ?? [])
					.filter(t => t > startAddress && t < rangeHi);
				const uniqueJt = [...new Set(jtTargets)].sort((a, b) => a - b);

				if (uniqueJt.length > 0) {
					// Selective injection: case bodies only (#51)
					liftOpts.additionalLeaders = uniqueJt;
					console.log(
						`[HexCore] liftToIR #51: injecting ${uniqueJt.length} jump-table case leaders ` +
						`(sample: [${uniqueJt.slice(0, 8).map(t => '0x' + t.toString(16)).join(', ')}${uniqueJt.length > 8 ? '...' : ''}])`
					);
				}

				if (cfgHints.confidence > 0 && !quiet) {
					const pdataCount = getPdataFunctionCount(engine);
					const inFn = (cfgHints.leaders ?? []).filter(
						(a: number) => a > startAddress && a < primaryEnd
					).length;
					console.log(
						`[pathfinder] CFG hints: ${inFn}/${cfgHints.leaders.length} leaders in-fn, ` +
						`jtCases=${uniqueJt.length}, primaryEnd=0x${primaryEnd.toString(16)}, ` +
						`tail-calls=${cfgHints.tailCalls.length}, insns=${cfgHints.instructionsDecoded}, ` +
						`confidence=${cfgHints.confidence}% (.pdata: ${pdataCount} functions)`
					);
				}
				// Oversized multi-fn experimental window: full leader injection.
				if (options.allowOversizedLift === true && cfgHints.confidence > 0) {
					const pfLeaders = (cfgHints.leaders ?? []).filter(
						(a: number) => a >= startAddress && a < startAddress + bytes.length
					);
					liftOpts.additionalLeaders = [...new Set([
						startAddress,
						...pfLeaders,
						...uniqueJt,
					])].sort((a, b) => a - b);
				}
			} catch (pfErr) {
				console.warn('[pathfinder] CFG analysis failed, continuing without hints:', pfErr);
			}

			// FIX-052 + FIX-QUALITY-002c: caps MUST leave headroom above any
			// pre-injected leaders. Floor is intentionally high so a future
			// leader injection cannot re-introduce silent max_blocks truncates.
			{
				const leaderCount = liftOpts.additionalLeaders?.length ?? 0;
				if (liftOpts.maxBytes === undefined) {
					liftOpts.maxBytes = Math.min(
						explicitScopeLimited ? bytes.length : Math.max(bytes.length, knownFnSize + 64, 32768),
						4 * 1024 * 1024,
					);
				}
				if (liftOpts.maxInstructions === undefined) {
					if (effectiveInstructionLimit !== undefined) {
						liftOpts.maxInstructions = Math.min(effectiveInstructionLimit, 256_000);
					} else {
						const est = Math.ceil(bytes.length / 2) + leaderCount + 4096;
						liftOpts.maxInstructions = Math.min(Math.max(est, 8000), 256_000);
					}
				}
				if (liftOpts.maxBasicBlocks === undefined) {
					// CRITICAL: floor well above pre-injected leaders (leaderCount+2048).
					const est = Math.max(
						Math.ceil(leaderCount * 1.5) + 2048,
						Math.ceil(bytes.length / 4) + 1024,
						4096,
					);
					liftOpts.maxBasicBlocks = Math.min(est, 64_000);
				}
			}

			// Perform lifting with progress indicator
			let liftResult = await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: '[Experimental] Lifting to LLVM IR...',
					cancellable: false,
				},
				async () => {
					return remillWrapper.liftBytes(bytes, liftBufferAddress, arch, targetOs, liftOpts);
				}
			);

			// FIX-QUALITY-002c: silent under-lift detector + engine-direct retry.
			// If Remill consumed << known function size, retry once with harness
			// opts (no leader flood, generous caps). Closes the 4800/6761 gap.
			if (
				liftResult.success &&
				knownFnSize > 256 &&
				typeof liftResult.bytesConsumed === 'number' &&
				liftResult.bytesConsumed > 0 &&
				liftResult.bytesConsumed < knownFnSize * 0.85 &&
				!explicitScopeLimited &&
				options.noLiftRetry !== true
			) {
				const short = liftResult.bytesConsumed;
				console.warn(
					`[HexCore] liftToIR FIX-QUALITY-002c: under-lift detected ` +
					`bytesConsumed=${short} < 85% of knownSize=${knownFnSize} — retrying engine-direct style`
				);
				const retryOpts: RemillLiftOptions = {
					...(fmt === 'PE' || fmt === 'PE64'
						? { liftMode: 'pe64' as const, knownFunctionEnds: [primaryEnd] }
						: fileInfo?.isRelocatable
							? { liftMode: 'elf_relocatable' as const }
							: {}),
					maxBytes: Math.max(knownFnSize + 64, bytes.length, 32768),
					maxInstructions: 256_000,
					maxBasicBlocks: 64_000,
				};
				const retryBuf = bytes.length >= knownFnSize
					? bytes
					: (engine.getBytes(startAddress, knownFnSize + 64) ?? bytes);
				const retry = await remillWrapper.liftBytes(
					retryBuf, startAddress, arch, targetOs, retryOpts
				);
				if (
					retry.success &&
					typeof retry.bytesConsumed === 'number' &&
					retry.bytesConsumed > short
				) {
					console.log(
						`[HexCore] liftToIR FIX-QUALITY-002c: retry improved ` +
						`${short} → ${retry.bytesConsumed} bytes, ir ${(retry.ir || '').split('\n').length} lines`
					);
					liftResult = retry;
				} else {
					console.warn(
						`[HexCore] liftToIR FIX-QUALITY-002c: retry did not improve ` +
						`(kept ${short} bytes)`
					);
				}
			}

			// Clear after lift
			if (symbolMap && symbolMap.size > 0) {
				remillWrapper.clearExternalSymbols();
			}

			if (!liftResult.success) {
				const errorMsg = `Lift failed: ${liftResult.error}`;
				if (quiet) {
					return { success: false, ir: '', address: startAddress, bytesConsumed: liftResult.bytesConsumed, architecture: mapping.remillArch, error: liftResult.error };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// FIX-011 post-processing: Inject external symbol declarations into IR.
			//
			// The Remill Phase 4.5 (calliTargets) is supposed to replace CALLI
			// arguments with concrete target addresses, but the LLVM CallInst
			// pointers can become stale after block construction. Instead, we use
			// TWO complementary strategies:
			//
			// Strategy A: Use liftResult.callTargets (populated by Phase 3 in C++)
			//   to map fakeAddr → symbolName, then replace any `i64 <decimal>` or
			//   `@sub_<hex>` patterns that match.
			//
			// Strategy B: Inject `@__hxreloc__` declarations so the Helix engine's
			//   resolveCallTargets() can map call instruction addresses → symbols.
			//   This works even when Strategy A finds no text matches.
			let processedIR = liftResult.ir;
			if (symbolMap && symbolMap.size > 0) {
				let replaceCount = 0;
				const declares = new Set<string>();

				// Strategy A: Direct IR text replacement
				const sortedEntries = [...symbolMap.entries()].sort((a, b) => b[0] - a[0]);
				for (const [addr, name] of sortedEntries) {
					const fakeHex = addr.toString(16);
					const before = processedIR;

					// Replace @sub_<hex> and @lifted_<hex> patterns
					processedIR = processedIR
						.replace(new RegExp(`@sub_${fakeHex}\\b`, 'gi'), `@${name}`)
						.replace(new RegExp(`@lifted_${fakeHex}\\b`, 'gi'), `@${name}`);

					// Replace i64 <decimal> in CALLI arguments
					const decPattern = `i64 ${addr}`;
					if (processedIR.includes(decPattern)) {
						processedIR = processedIR.split(decPattern).join(`i64 ptrtoint (ptr @${name} to i64)`);
					}

					if (processedIR !== before) {
						replaceCount++;
						declares.add(name);
					}
				}

				// Strategy B: Inject @__hxreloc__ declarations for Helix resolveCallTargets()
				// Also builds the full symbol set from callTargets array (more reliable than text matching)
				const callTargets: number[] = liftResult.callTargets ?? [];
				console.log(`[HexCore] liftToIR FIX-011 Strategy B: callTargets=[${callTargets.slice(0, 10).map(t => '0x' + t.toString(16)).join(', ')}${callTargets.length > 10 ? '...' : ''}] (${callTargets.length} total), symbolMap keys=[${[...symbolMap.keys()].slice(0, 10).map(k => '0x' + k.toString(16)).join(', ')}${symbolMap.size > 10 ? '...' : ''}] (${symbolMap.size} total)`);
				let matchedTargets = 0;
				for (const target of callTargets) {
					const name = symbolMap.get(target);
					if (name) {
						declares.add(name);
						matchedTargets++;
					}
				}
				console.log(`[HexCore] liftToIR FIX-011 Strategy B: ${matchedTargets}/${callTargets.length} callTargets matched symbolMap`);

				// Clean up orphaned fake-address references
				processedIR = processedIR.replace(/^(define|declare) [^\n]*@sub_7ff[0-9a-f]+[^\n]*\n/gmi, '');
				processedIR = processedIR.replace(/^(define|declare) [^\n]*@lifted_7ff[0-9a-f]+[^\n]*\n/gmi, '');

				// Build annotation block with declares + hxreloc metadata
				if (declares.size > 0) {
					// v3.7.5 FIX: Deduplicate — skip symbols already declared inline
					// by the Remill lifter (C++ side emits declare during lift).
					const alreadyDeclared = new Set<string>();
					for (const match of processedIR.matchAll(/^declare\s+\S+\s+@(\w+)\s*\(/gm)) {
						alreadyDeclared.add(match[1]);
					}
					const newDeclares = [...declares].filter(n => !alreadyDeclared.has(n));
					const declareLines = newDeclares.map(n => `declare ptr @${n}(...)`);

					// Machine-readable relocation declarations for Helix
					const relocDeclares: string[] = [];
					const relocEntries = [...symbolMap.entries()]
						.filter(([, name]) => declares.has(name))
						.sort((a, b) => a[0] - b[0]);
					for (const [addr, name] of relocEntries) {
						const hexAddr = addr.toString(16).padStart(16, '0');
						relocDeclares.push(`declare void @__hxreloc__${hexAddr}__${name}()`);
					}

					// Only build block if there are new declares or reloc metadata to inject
					const blockParts: string[] = [];
					if (declareLines.length > 0) { blockParts.push(declareLines.join('\n')); }
					if (relocDeclares.length > 0) { blockParts.push(relocDeclares.join('\n')); }

					const declareBlock = blockParts.length > 0
						? '\n; --- External symbols (resolved from .rela.text, ' + declares.size + ' symbols) ---\n' + blockParts.join('\n') + '\n'
						: '';

					if (declareBlock.length > 0) {
						const lastDeclareIdx = processedIR.lastIndexOf('\ndeclare ');
						if (lastDeclareIdx >= 0) {
							const lineEnd = processedIR.indexOf('\n', lastDeclareIdx + 1);
							processedIR = processedIR.slice(0, lineEnd) + '\n' + declareBlock + processedIR.slice(lineEnd);
						} else {
							const firstDefine = processedIR.indexOf('\ndefine ');
							if (firstDefine >= 0) {
								processedIR = processedIR.slice(0, firstDefine) + '\n' + declareBlock + processedIR.slice(firstDefine);
							} else {
								processedIR = declareBlock + processedIR;
							}
						}
					}

					console.log(`[HexCore] liftToIR FIX-011: ${replaceCount} text replacements, ` +
						`${declares.size} external declares (${newDeclares.length} new, ${alreadyDeclared.size} deduped), ${callTargets.length} callTargets from Remill`);
				}
			}

			// v3.8.0: Resolve real symbol name from ELF symtab.
			// This runs AFTER all branches (file, address, functionAddress, interactive)
			// so it catches every code path. Must check multiple address candidates
			// because CET/ftrace preamble skip changes startAddress (e.g. 0x3a20→0x3a29).
			if (!functionName || functionName.startsWith('sub_')) {
				const elfAnalysisRef = engine.getELFAnalysis();
				const elfSym = elfAnalysisRef?.symbols;

				const addrCandidates = [startAddress];
				if (backtrackOriginalAddress && backtrackOriginalAddress !== startAddress) {
					addrCandidates.push(backtrackOriginalAddress);
				}
				const userAddr = parseAddressValue(options.address as string | number | undefined)
					?? parseAddressValue(options.startAddress as string | number | undefined);
				if (userAddr && !addrCandidates.includes(userAddr)) {
					addrCandidates.push(userAddr);
				}

				console.log(`[HexCore] liftToIR symtab-lookup: functionName=${functionName ?? 'null'}, elfAnalysis=${!!elfAnalysisRef}, symbols=${elfSym?.length ?? 'N/A'}, candidates=[${addrCandidates.map(a => '0x' + a.toString(16)).join(',')}]`);

				if (elfSym && elfSym.length > 0) {
					for (const candidate of addrCandidates) {
						const sym = elfSym.find(s =>
							s.type === 'FUNC' && s.value === candidate && s.name && !s.name.startsWith('$')
						);
						if (sym) {
							functionName = sym.name;
							console.log(`[HexCore] liftToIR: Resolved symtab name: ${sym.name} at 0x${candidate.toString(16)} (startAddress=0x${startAddress.toString(16)})`);
							break;
						}
					}
				} else {
					const fallbackName = engine.getFunctionName(startAddress)
						?? (userAddr ? engine.getFunctionName(userAddr) : undefined);
					if (fallbackName && !fallbackName.startsWith('sub_')) {
						functionName = fallbackName;
						console.log(`[HexCore] liftToIR: Resolved via getFunctionName: ${fallbackName}`);
					}
				}
			}

			// v3.8.0: Inject real function name into IR (replaces lifted_<decimal>)
			// Remill names the function "lifted_<decimal_address>", but we have the real
			// name from .symtab. Rename it so Helix picks up the real name for output.
			if (functionName && !functionName.startsWith('sub_')) {
				const liftedName = `lifted_${startAddress}`;
				// Replace all occurrences: define, call, references
				const nameRegex = new RegExp(`\\b${liftedName}\\b`, 'g');
				if (processedIR.includes(liftedName)) {
					processedIR = processedIR.replace(nameRegex, functionName);
					console.log(`[HexCore] liftToIR: Renamed ${liftedName} → ${functionName} in IR`);
				}
			}

			// FIX-054: the lifted_<addr> -> functionName rename above can collide with a
			// spurious `declare ptr @functionName(...)` that the native Remill Phase 5.6
			// external-symbol injector emits when a callfuscated function takes its OWN
			// address (its symbol lands in externalSymbols_, e.g. fh_install_hook in
			// malware.ko). The resulting `define @X` + `declare @X` is an invalid LLVM
			// redefinition that aborts the Helix parser -> 8-line stub. Strip the
			// redundant self-declare (safe: only fires when an in-module `define @X(`
			// exists). No-op once the native getOrCreateExtern self-address guard ships.
			processedIR = RemillWrapper.dedupSelfDeclares(processedIR);

				// FIX-099 (Defect 2): name in-module direct/tail calls that the
				// compiler resolved internally (no .rela.text reloc — real PC-relative
				// displacement baked in), using the ELF .symtab. Without this a CALLI
				// to another module function (e.g. csf_queue_register_internal@0x63150,
				// trace_jit_stats@0xB90) lifts as a bare numeric target -> Helix renders
				// (*(code*)0xADDR)() and the out-of-table-call honesty cap pins
				// confidence at 50%. We map each lifted callTarget that equals a known
				// .text function offset to its name and rewrite ONLY the CALLI-target
				// operand (line-scoped, so a coincidental i64 immediate elsewhere is
				// never touched).
				if (fileInfo?.isRelocatable && Array.isArray(liftResult.callTargets) && liftResult.callTargets.length > 0) {
					const textFnByOffset = new Map<number, string>();
					for (const s of engine.getElfFunctionSymbols()) {
						if (s.section === '.text') { textFnByOffset.set(s.offsetInSection, s.name); }
					}
					const named = new Set<string>();
					const irLines = processedIR.split('\n');
					for (let i = 0; i < irLines.length; i++) {
						if (!irLines[i].includes('CALLI')) { continue; }
						for (const t of liftResult.callTargets) {
							const nm = textFnByOffset.get(t);
							if (!nm || nm === functionName) { continue; }
							const tok = `i64 ${t},`;
							if (irLines[i].includes(tok)) {
								irLines[i] = irLines[i].split(tok).join(`i64 ptrtoint (ptr @${nm} to i64),`);
								named.add(nm);
							}
						}
					}
					if (named.size > 0) {
						processedIR = irLines.join('\n');
						const declared099 = new Set([...processedIR.matchAll(/^declare\s+\S+\s+@([\w.$]+)\s*\(/gm)].map(m => m[1]));
						const newDecls099 = [...named]
							.filter(n => !declared099.has(n) && !processedIR.includes(`define ptr @${n}(`))
							.map(n => `declare ptr @${n}(...)`);
						if (newDecls099.length > 0) {
							const block099 = '\n' + newDecls099.join('\n') + '\n';
							const lastDecl099 = processedIR.lastIndexOf('\ndeclare ');
							if (lastDecl099 >= 0) {
								const e099 = processedIR.indexOf('\n', lastDecl099 + 1);
								processedIR = processedIR.slice(0, e099) + block099 + processedIR.slice(e099);
							} else {
								const fd099 = processedIR.indexOf('\ndefine ');
								processedIR = fd099 >= 0 ? processedIR.slice(0, fd099) + block099 + processedIR.slice(fd099) : block099 + processedIR;
							}
						}
						console.log(`[HexCore] liftToIR FIX-099: named ${named.size} in-module .symtab call target(s): ${[...named].slice(0, 8).join(', ')}`);
					}
				}

			// FIX-097: embed the relocated data-section bytes as module metadata
			// so the Helix decompiler can resolve a patched `mov rdi, <base+OFF>`
			// back to the original string literal — turning printk(0, ...) into
			// printk("DMESG: unresolved symbol: %s\n", ...). One !helix.strings
			// node per fake data section: !{ i64 baseVA, !"<raw section bytes>" }.
			if (dataSectionFakes && dataSectionFakes.length > 0) {
				let maxMdId = -1;
				for (const m of processedIR.matchAll(/^!(\d+)\s*=/gm)) {
					const id = parseInt(m[1], 10);
					if (id > maxMdId) { maxMdId = id; }
				}
				let mdId = Math.max(maxMdId + 1, 90000);
				const nodeRefs: string[] = [];
				const nodeDefs: string[] = [];
				for (const ds of dataSectionFakes) {
					// LLVM .ll string escaping: \HH (upper hex) for ", \ and non-printable.
					let esc = '';
					for (const b of ds.bytes) {
						if (b === 0x22 || b === 0x5c || b < 0x20 || b > 0x7e) {
							esc += '\\' + b.toString(16).padStart(2, '0').toUpperCase();
						} else {
							esc += String.fromCharCode(b);
						}
					}
					const nid = mdId++;
					nodeRefs.push(`!${nid}`);
					nodeDefs.push(`!${nid} = !{i64 ${ds.vaStart}, !"${esc}"}`);
				}
				processedIR = processedIR.replace(/\s*$/, '\n') +
					'\n; --- FIX-097: relocated data sections for string recovery ---\n' +
					`!helix.strings = !{${nodeRefs.join(', ')}}\n` +
					nodeDefs.join('\n') + '\n';
				const totalBytes = dataSectionFakes.reduce((n, d) => n + d.bytes.length, 0);
				console.log(`[HexCore] liftToIR FIX-097: embedded ${dataSectionFakes.length} data section(s) ` +
					`as !helix.strings metadata (${totalBytes} bytes)`);
			}

			const fileName = engine.getFilePath() ? path.basename(engine.getFilePath()!) : 'unknown';
			const header = buildIRHeader({
				fileName,
				address: startAddress,
				size,
				architecture: mapping.remillArch,
				functionName,
			});

			const minimumSemanticCoverage = typeof options.minimumSemanticCoverage === 'number'
				? options.minimumSemanticCoverage
				: 1;
			const liftSemantics = assessLiftSemanticCoverage(
				processedIR,
				liftResult,
				minimumSemanticCoverage,
			);
			if (explicitScopeLimited) {
				liftSemantics.status = 'partial';
				const scopeReason = `explicit instruction scope limited to ${effectiveInstructionLimit} instruction(s)`;
				liftSemantics.reason = liftSemantics.reason
					? `${liftSemantics.reason}; ${scopeReason}`
					: scopeReason;
			}
			const coverageExtent = getAuthoritativeFunctionExtent(engine, startAddress);
			const decodedBytes = Math.max(0, Number(liftResult.bytesConsumed ?? 0));
			const requestedWindowCoverage = Math.max(0, Math.min(1, decodedBytes / Math.max(1, size)));
			const decodedByteCoverage = coverageExtent.size > 0
				? Math.max(0, Math.min(1, decodedBytes / coverageExtent.size))
				: undefined;
			const requestedEndExclusive = startAddress + size;
			const functionEndExclusive = liftWindow?.endExclusive
				?? (coverageExtent.source !== 'none' ? coverageExtent.end : undefined);
			const functionRangeSize = functionEndExclusive !== undefined
				? Math.max(0, functionEndExclusive - startAddress)
				: undefined;
			const functionRangeSource = liftWindow?.endExclusive !== undefined
				? liftWindow.reason
				: coverageExtent.source;
			const semanticInstructionEnd = primaryFn?.instructions?.reduce(
				(maximum, instruction) => Math.max(
					maximum,
					Number(instruction.address) + Number(instruction.size),
				),
				startAddress,
			);
			const boundaryCompletion = functionEndExclusive !== undefined
				? assessLiftRangeCompletion({
					startAddress,
					endExclusive: functionEndExclusive,
					semanticEndExclusive: semanticInstructionEnd,
					pathfinderOwnershipEnd,
					nativeTruncated: liftResult.truncated,
				})
				: undefined;
			if (boundaryCompletion?.status === 'partial') {
				liftSemantics.status = 'partial';
				liftSemantics.reason = liftSemantics.reason
					? `${liftSemantics.reason}; ${boundaryCompletion.reason}`
					: boundaryCompletion.reason;
			}
			const semanticEndExclusive = semanticInstructionEnd !== undefined
				? (functionEndExclusive !== undefined
					? Math.min(functionEndExclusive, semanticInstructionEnd)
					: semanticInstructionEnd)
				: startAddress;
			const rangeContract = {
				requestedByteRange: {
					start: toHexAddress(startAddress),
					endExclusive: toHexAddress(requestedEndExclusive),
					size,
					countingDomain: liftWindow?.countingDomain ?? 'byte-range',
					reason: liftWindow?.reason ?? 'resolved-lift-window',
				},
				...(functionEndExclusive !== undefined ? {
					functionByteRange: {
						start: toHexAddress(startAddress),
						endExclusive: toHexAddress(functionEndExclusive),
						size: functionRangeSize,
						source: functionRangeSource,
					},
				} : {}),
				semanticBodyRange: {
					start: toHexAddress(startAddress),
					endExclusive: toHexAddress(semanticEndExclusive),
					size: Math.max(0, semanticEndExclusive - startAddress),
					boundaryReached: boundaryCompletion?.reached ?? false,
					boundaryCrossed: boundaryCompletion?.crossed ?? false,
					byteCoverage: boundaryCompletion?.coverage,
					source: semanticInstructionEnd !== undefined
						? 'function-table-instructions' as const
						: 'unavailable' as const,
				},
				remillDecodedByteSet: {
					bytes: decodedBytes,
					coverage: functionRangeSize !== undefined
						? Math.max(0, Math.min(1, decodedBytes / Math.max(1, functionRangeSize)))
						: undefined,
					representation: 'union-of-decoded-intervals' as const,
					nativeTruncated: liftResult.truncated === true,
					...(liftResult.nextAddress ? { nextAddress: toHexAddress(liftResult.nextAddress) } : {}),
					...(liftResult.truncationReason ? { truncationReason: liftResult.truncationReason } : {}),
				},
			};
			const coverageHeader =
				`; RequestedByteRange: [${toHexAddress(startAddress)}, ${toHexAddress(requestedEndExclusive)}) ` +
				`domain=${rangeContract.requestedByteRange.countingDomain} reason=${rangeContract.requestedByteRange.reason}\n` +
				(functionEndExclusive !== undefined
					? `; FunctionByteRange: [${toHexAddress(startAddress)}, ${toHexAddress(functionEndExclusive)}) source=${functionRangeSource}\n`
					: '; FunctionByteRange: unknown\n') +
				`; SemanticBodyRange: [${toHexAddress(startAddress)}, ${toHexAddress(semanticEndExclusive)}) ` +
				`boundaryReached=${rangeContract.semanticBodyRange.boundaryReached} ` +
				`boundaryCrossed=${rangeContract.semanticBodyRange.boundaryCrossed} ` +
				`source=${rangeContract.semanticBodyRange.source}\n` +
				`; RemillDecodedByteSet: ${(requestedWindowCoverage * 100).toFixed(2)}% ` +
				`(${decodedBytes}/${size} bytes) representation=union-of-decoded-intervals ` +
				`nativeTruncated=${liftResult.truncated === true}\n` +
				`; DecodedByteCoverage: ${decodedByteCoverage === undefined
					? 'unknown (function boundary unavailable)'
					: `${(decodedByteCoverage * 100).toFixed(2)}% (${decodedBytes}/${coverageExtent.size} bytes, ${coverageExtent.source})`}\n\n`;
			const fullIR = header + formatLiftSemanticHeader(liftSemantics) + coverageHeader + processedIR;
			if (liftSemantics.status === 'partial') {
				console.warn(
					`[HexCore] liftToIR semantic partial: ${liftSemantics.reason ?? 'incomplete semantics'}; ` +
					`decoded=${liftSemantics.decodedInstructions} lifted=${liftSemantics.liftedInstructions} ` +
					`unsupported=${liftSemantics.unsupportedInstructions} decodeFailures=${liftSemantics.decodeFailureInstructions}`,
				);
			}

			// v3.7.5 FIX-021: Separate internal vs external call targets.
			// Internal targets are within the .ko/.text range — can be lifted recursively.
			// External targets are resolved via symbolMap (already handled above).
			const allCallTargets: number[] = liftResult.callTargets ?? [];
			const textSection = engine.getSections().find(s => s.name === '.text');
			const textStart = textSection?.virtualAddress ?? 0;
			const textEnd = textStart + (textSection?.virtualSize ?? 0);
			const internalCallTargets = allCallTargets.filter(t =>
				t >= textStart && t < textEnd && !(symbolMap?.has(t))
			);
			const externalCallTargets = allCallTargets.filter(t =>
				symbolMap?.has(t)
			);

			if (internalCallTargets.length > 0) {
				console.log(`[HexCore] liftToIR FIX-021: ${internalCallTargets.length} internal call targets: [${internalCallTargets.slice(0, 10).map(t => '0x' + t.toString(16)).join(', ')}${internalCallTargets.length > 10 ? '...' : ''}]`);
			}

			// Headless: write to file if output specified
			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string'
					? options.output
					: (options.output as { path: string }).path;
				// Bug #36/2: ensure the output directory exists before writing.
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, fullIR, 'utf-8');
				return {
					success: true,
					ir: fullIR,
					address: startAddress,
					bytesConsumed: liftResult.bytesConsumed,
					architecture: mapping.remillArch,
					functionName,
					backtracked: didBacktrack,
					requestedAddress: backtrackOriginalAddress,
					liftTransformations,
					// FIX-QUALITY-001: surface Remill callTargets so helix.decompile
					// can enrich the D2 functionStarts registry (plus IR parse).
					callTargets: liftResult.callTargets,
					scopeLimited: explicitScopeLimited,
					requestedInstructionLimit: effectiveInstructionLimit,
					...(didBacktrack ? { originalAddress: backtrackOriginalAddress } : {}),
					...(trampolineChain.length > 0 ? {
						trampolineFollowed: true,
						trampolineOriginalAddress,
						trampolineTarget: startAddress,
						trampolineHops: trampolineChain.map(h => ({
							from: '0x' + h.from.toString(16),
							to: '0x' + h.to.toString(16),
							mnemonic: h.mnemonic,
						})),
					} : {}),
					internalCallTargets,
					...liftSemantics,
					requestedWindowCoverage,
					decodedByteCoverage,
					functionBoundaryKnown: coverageExtent.source !== 'none',
					semanticWarning: liftSemantics.reason ?? '',
					...rangeContract,
				};
			}

			if (quiet) {
				return {
					success: true,
					ir: fullIR,
					address: startAddress,
					bytesConsumed: liftResult.bytesConsumed,
					architecture: mapping.remillArch,
					functionName,
					backtracked: didBacktrack,
					requestedAddress: backtrackOriginalAddress,
					liftTransformations,
					// FIX-QUALITY-001: see headless return above.
					callTargets: liftResult.callTargets,
					scopeLimited: explicitScopeLimited,
					requestedInstructionLimit: effectiveInstructionLimit,
					...(didBacktrack ? { originalAddress: backtrackOriginalAddress } : {}),
					...(trampolineChain.length > 0 ? {
						trampolineFollowed: true,
						trampolineOriginalAddress,
						trampolineTarget: startAddress,
						trampolineHops: trampolineChain.map(h => ({
							from: '0x' + h.from.toString(16),
							to: '0x' + h.to.toString(16),
							mnemonic: h.mnemonic,
						})),
					} : {}),
					internalCallTargets,
					...liftSemantics,
					requestedWindowCoverage,
					decodedByteCoverage,
					functionBoundaryKnown: coverageExtent.source !== 'none',
					semanticWarning: liftSemantics.reason ?? '',
					...rangeContract,
				};
			}

			// Interactive: open IR in a new editor tab (readonly)
			const doc = await vscode.workspace.openTextDocument({
				content: fullIR,
				language: 'llvm',
			});
			await vscode.window.showTextDocument(doc, { preview: false });

			// Mark the editor as readonly for this session
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			// Show experimental notice once per session
			if (!shownExperimentalNotice) {
				shownExperimentalNotice = true;
				vscode.window.showInformationMessage(
					'[Experimental] LLVM IR lifting is experimental. Output may be incomplete or inaccurate.'
				);
			}

			return {
				success: true,
				ir: fullIR,
				address: startAddress,
				bytesConsumed: liftResult.bytesConsumed,
				architecture: mapping.remillArch,
				functionName,
				backtracked: didBacktrack,
				requestedAddress: backtrackOriginalAddress,
				liftTransformations,
				callTargets: liftResult.callTargets,
				scopeLimited: explicitScopeLimited,
				requestedInstructionLimit: effectiveInstructionLimit,
				internalCallTargets,
				...liftSemantics,
				requestedWindowCoverage,
				decodedByteCoverage,
				functionBoundaryKnown: coverageExtent.source !== 'none',
				semanticWarning: liftSemantics.reason ?? '',
				...rangeContract,
				...(didBacktrack ? { originalAddress: backtrackOriginalAddress } : {}),
			};
		})
	);

	// -----------------------------------------------------------------------
	// [Experimental] Decompile to pseudo-C (Lifting + Rellic)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.rellic.decompile', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'startAddress' in (arg as Record<string, unknown>) || 'address' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;

			if (!remillWrapper.isAvailable()) {
				const errorMsg = 'hexcore-remill is not available. Cannot lift machine code to IR.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			if (!rellicWrapper.isAvailable()) {
				const errorMsg = 'hexcore-rellic is not available. Install the prebuild or build from source.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			const arch = engine.getArchitecture();
			const mapping = mapCapstoneToRemill(arch);
			if (!mapping.supported) {
				const errorMsg = `Architecture '${arch}' is not supported by Remill.`;
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: String(arch), error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			let startAddress: number;
			let size: number;
			let functionName: string | undefined;

			if (isHeadless && options.file) {
				const filePath = String(options.file);
				if (!engine.isFileLoaded() || engine.getFilePath() !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						const errorMsg = `Failed to load file: ${filePath}`;
						if (quiet) {
							return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: errorMsg };
						}
						vscode.window.showErrorMessage(errorMsg);
						return undefined;
					}
				}
				startAddress = parseAddressValue(options.address as string | number | undefined)
					?? parseAddressValue(options.startAddress as string | number | undefined)
					?? engine.getBaseAddress();
				// FIX-QUALITY-002: same sizing policy as liftToIR (rellic path).
				{
					const knownFn = engine.getFunctionAt(startAddress);
					const knownSize = (knownFn && knownFn.size > 0)
						? knownFn.size
						: engine.getRecommendedLiftSize(startAddress, 0);
					const resolved = resolveLiftByteSize({
						size: options.size,
						count: options.count,
						knownFunctionSize: knownSize,
						bufferSize: engine.getBufferSize(),
						allowOversizedLift: options.allowOversizedLift === true,
					});
					size = resolved.size;
				}
			} else if (isHeadless && options.functionAddress !== undefined) {
				startAddress = typeof options.functionAddress === 'number' ? options.functionAddress : 0;
				const func = engine.getFunctionAt(startAddress);
				if (func) {
					size = func.endAddress - func.address;
					functionName = func.name;
				} else {
					const resolved = resolveLiftByteSize({
						size: options.size,
						count: options.count,
						knownFunctionSize: engine.getRecommendedLiftSize(startAddress, 0),
						bufferSize: 4096,
						allowOversizedLift: options.allowOversizedLift === true,
					});
					size = resolved.size;
				}
			} else {
				const addrInput = await vscode.window.showInputBox({
					prompt: 'Start address (hex, e.g. 0x401000)',
					placeHolder: '0x401000',
				});
				if (!addrInput) {
					return undefined;
				}
				startAddress = parseInt(addrInput, 16);
				if (isNaN(startAddress)) {
					vscode.window.showErrorMessage(`Invalid address: ${addrInput}`);
					return undefined;
				}

				const sizeInput = await vscode.window.showInputBox({
					prompt: 'Size in bytes',
					placeHolder: '256',
					value: '256',
				});
				if (!sizeInput) {
					return undefined;
				}
				size = parseInt(sizeInput, 10);
				if (isNaN(size) || size <= 0) {
					vscode.window.showErrorMessage(`Invalid size: ${sizeInput}`);
					return undefined;
				}
			}

			if (!engine.isFileLoaded()) {
				const errorMsg = 'No binary file is loaded.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: `0x${startAddress.toString(16)}`, architecture: mapping.remillArch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// D-scanrange: auto-backtrack a mid-function hit to the real prologue
			// BEFORE fetching bytes, so the lift buffer starts at the function entry
			// and Remill sees the full CFG (no use-before-def from a mid-function
			// lift). Authoritative AMD64 .pdata containment wins even when the
			// requested address is mid-instruction. Heuristic candidates retain
			// FIX-022c's distance and exact-continuity guards. ET_REL remains
			// excluded so this path never re-fetches an unpatched .ko window.
			if (options.autoBacktrack !== false) {
				const originalEnd = startAddress + size;
				const backtrack = await resolveAutoBacktrack(engine, startAddress);
				if (backtrack) {
					startAddress = backtrack.start;
					size = Math.max(
						originalEnd - startAddress,
						(backtrack.end ?? startAddress) - startAddress
					);
					console.log(
						`[HexCore] rellic.decompile D-scanrange (${backtrack.source}): ` +
						`re-anchored to 0x${startAddress.toString(16)} (size now ${size})`
					);
				}
			}

			let bytes = engine.getBytes(startAddress, size);
			if (!bytes || bytes.length === 0) {
				const errorMsg = `Address 0x${startAddress.toString(16)} is outside the loaded binary.`;
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: `0x${startAddress.toString(16)}`, architecture: mapping.remillArch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Step 1: Lift to IR — with format-specific options (Item 2 + Item 3)
			const fmtForOs = engine.getFileInfo()?.format ?? '';
			const fileInfoDecomp = engine.getFileInfo();
			const targetOsForLift = fmtForOs.startsWith('ELF') ? 'linux'
				: (fmtForOs === 'PE' || fmtForOs === 'PE64') ? 'windows'
					: undefined;

			// FIX-QUALITY-002: same single-function scope as liftToIR
			const decompLiftOpts: RemillLiftOptions = {};
			let decompLiftBufferAddress = startAddress;
			const callfuscationEvidence = engine.detectCallfuscation();
			if (callfuscationEvidence.detected && options.deflattenCallfuscation !== false) {
				const section = engine.getSections().find(candidate => {
					const end = candidate.virtualAddress + Math.max(candidate.virtualSize, candidate.rawSize);
					return (candidate.isCode || candidate.isExecutable) &&
						startAddress >= candidate.virtualAddress && startAddress < end;
				});
				const sectionBytes = section
					? engine.getBytes(section.virtualAddress, section.rawSize)
					: undefined;
				if (section && sectionBytes && sectionBytes.length > 0) {
					bytes = sectionBytes;
					decompLiftBufferAddress = section.virtualAddress;
					decompLiftOpts.deflattenCallfuscation = true;
					decompLiftOpts.entryAddress = startAddress;
					decompLiftOpts.reachableOnly = true;
				} else {
					console.warn('[HexCore] callfuscation detected, but no containing executable section was available; using the bounded lift window');
				}
			}
			const primaryFnDecomp = engine.getFunctionAt(startAddress);
			const primaryEndDecomp = (primaryFnDecomp && primaryFnDecomp.endAddress > startAddress)
				? primaryFnDecomp.endAddress
				: (startAddress + bytes.length);
			const withinPrimaryDecomp = (a: number): boolean =>
				a > startAddress && a < primaryEndDecomp;

			if (fmtForOs === 'PE' || fmtForOs === 'PE64') {
				decompLiftOpts.liftMode = 'pe64';
				decompLiftOpts.knownFunctionEnds = [primaryEndDecomp];
			} else if (fileInfoDecomp?.isRelocatable) {
				decompLiftOpts.liftMode = 'elf_relocatable';
				const symLeaders: number[] = [];
				for (const fn of engine.getFunctions()) {
					if (withinPrimaryDecomp(fn.address)) {
						symLeaders.push(fn.address);
					}
				}
				if (symLeaders.length > 0) { decompLiftOpts.additionalLeaders = symLeaders; }
			}

			// v3.8.0 Pathfinder: BB leaders inside primary only (mirror liftToIR)
			try {
				const cfgHints = await runPathfinder(engine, startAddress, bytes);
				if (cfgHints.confidence > 0) {
					const existingLeaders = (decompLiftOpts.additionalLeaders ?? []).filter(withinPrimaryDecomp);
					const pfLeaders = (cfgHints.leaders ?? []).filter(withinPrimaryDecomp);
					const mergedLeaders = new Set([...existingLeaders, ...pfLeaders, startAddress]);
					decompLiftOpts.additionalLeaders = [...mergedLeaders].sort((a, b) => a - b);
					decompLiftOpts.knownFunctionEnds = [primaryEndDecomp];
				}
			} catch {
				// Non-fatal
			}

			// FIX-052: Adaptive lift caps (mirror of the liftToIR path) so the
			// decompile path also lifts large intra-function chains whole and
			// does not truncate callfuscation-deflattened bodies.
			{
				const leaderCount = decompLiftOpts.additionalLeaders?.length ?? 0;
				if (decompLiftOpts.maxBytes === undefined) {
					decompLiftOpts.maxBytes = Math.min(Math.max(bytes.length, 32768), 4 * 1024 * 1024);
				}
				if (decompLiftOpts.maxInstructions === undefined) {
					const est = Math.ceil(bytes.length / 2) + leaderCount;
					decompLiftOpts.maxInstructions = Math.min(Math.max(est, 2000), 256_000);
				}
				if (decompLiftOpts.maxBasicBlocks === undefined) {
					const est = Math.max(Math.ceil(leaderCount * 1.5) + 512,
					                     Math.ceil(bytes.length / 8));
					decompLiftOpts.maxBasicBlocks = Math.min(Math.max(est, 2048), 64_000);
				}
			}

			const liftResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: '[Experimental] Lifting to LLVM IR...', cancellable: false },
				async () => remillWrapper.liftBytes(bytes, decompLiftBufferAddress, arch, targetOsForLift, decompLiftOpts)
			);

			if (!liftResult.success) {
				const errorMsg = `Lift failed: ${liftResult.error}`;
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: `0x${startAddress.toString(16)}`, architecture: mapping.remillArch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Step 2: Decompile IR to pseudo-C
			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: '[Experimental] Decompiling to pseudo-C...', cancellable: false },
				async () => rellicWrapper.decompile(liftResult.ir)
			);

			if (!decompileResult.success) {
				const errorMsg = `Decompilation failed: ${decompileResult.error}`;
				if (!quiet) {
					const action = await vscode.window.showErrorMessage(errorMsg, 'View IR');
					if (action === 'View IR') {
						const doc = await vscode.workspace.openTextDocument({ content: liftResult.ir, language: 'llvm' });
						await vscode.window.showTextDocument(doc, { preview: false });
					}
				}
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: `0x${startAddress.toString(16)}`, architecture: mapping.remillArch, error: decompileResult.error };
				}
				return undefined;
			}

			const fileName = engine.getFilePath() ? path.basename(engine.getFilePath()!) : 'unknown';
			const addressStr = `0x${startAddress.toString(16).padStart(8, '0')}`;
			const header = buildPseudoCHeader({
				fileName,
				address: addressStr,
				architecture: mapping.remillArch,
				functionName,
			});

			const fullCode = header + decompileResult.code;

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			if (quiet) {
				return {
					success: true,
					code: fullCode,
					functionCount: decompileResult.functionCount,
					address: addressStr,
					architecture: mapping.remillArch,
					error: '',
				};
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return {
				success: true,
				code: fullCode,
				functionCount: decompileResult.functionCount,
				address: addressStr,
				architecture: mapping.remillArch,
				error: '',
			};
		})
	);

	// -----------------------------------------------------------------------
	// [Experimental] Decompile IR to pseudo-C (direct IR input)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.rellic.decompileIR', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'irText' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;

			if (!rellicWrapper.isAvailable()) {
				const errorMsg = 'hexcore-rellic is not available.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			let irText: string;

			if (isHeadless && typeof options.irText === 'string') {
				irText = options.irText;
			} else if (isHeadless && typeof options.file === 'string') {
				if (!fs.existsSync(options.file)) {
					const errorMsg = `File not found: ${options.file}`;
					if (quiet) {
						return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: errorMsg };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(options.file, 'utf-8');
			} else {
				const activeEditor = vscode.window.activeTextEditor;
				if (!activeEditor) {
					vscode.window.showErrorMessage('No active editor with LLVM IR content.');
					return undefined;
				}
				irText = activeEditor.document.getText();
			}

			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: '[Experimental] Decompiling IR to pseudo-C...', cancellable: false },
				async () => rellicWrapper.decompile(irText)
			);

			if (!decompileResult.success) {
				const errorMsg = `Decompilation failed: ${decompileResult.error}`;
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: '', error: decompileResult.error };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			const fullCode = decompileResult.code;

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			if (quiet) {
				return {
					success: true,
					code: fullCode,
					functionCount: decompileResult.functionCount,
					address: '',
					architecture: '',
					error: '',
				};
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return {
				success: true,
				code: fullCode,
				functionCount: decompileResult.functionCount,
				address: '',
				architecture: '',
				error: '',
			};
		})
	);

	// -----------------------------------------------------------------------
	// Helper: Apply Session DB renames/retypes to decompiled pseudo-C
	// -----------------------------------------------------------------------
	/**
	 * v3.8.0: Extract struct field info from BTF or DWARF for a given function.
	 * Priority: BTF (fast, compact) → DWARF (full debug info).
	 * Both are pre-loaded by the engine during analyzeELF, so this is fully sync.
	 */
	function extractStructInfoForFunction(
		eng: DisassemblerEngine,
		functionAddress?: number,
		functionName?: string,
		irText?: string,
	): { structInfo: StructInfoJson; functionName: string } | null {
		// Resolve function name from address if not provided
		let funcName = functionName;
		if (!funcName && functionAddress) {
			const func = eng.getFunctionAt(functionAddress);
			funcName = func?.name;
		}
		// v3.8.1: If we only got a generic sub_<addr> back (or nothing),
		// try the ELF symtab — it typically carries the real symbol for
		// .ko files. Without this, DWARF lookups would always fail on
		// kernel modules because analyzeAll tags every function as sub_N.
		const elfAnalysis = eng.getELFAnalysis();
		if (!elfAnalysis) { return null; }

		if ((!funcName || funcName.startsWith('sub_')) && functionAddress) {
			// Range-aware: the address passed in is often after the
			// endbr64 + __fentry__ preamble (offset +9), so match the
			// containing symbol (value <= addr < value+size) rather
			// than exact-start. Prefer the innermost match if several
			// symbols nest.
			let best: { value: number; name: string } | undefined;
			for (const sym of (elfAnalysis.symbols ?? []) as any[]) {
				if (sym.type !== 'FUNC' || !sym.name) { continue; }
				if (sym.value > functionAddress) { continue; }
				if (sym.size > 0 && sym.value + sym.size <= functionAddress) { continue; }
				if (!best || sym.value > best.value) {
					best = { value: sym.value, name: sym.name };
				}
			}
			if (best?.name) {
				funcName = best.name;
			}
		}
		if (!funcName) { return null; }

		// Strip sub_ prefix — debug info stores real symbol names
		if (funcName.startsWith('sub_')) { return null; }

		const fullInfo = elfAnalysis.btfData
			? exportStructInfoJson(elfAnalysis.btfData)
			: elfAnalysis.dwarfStructInfo;
		if (!fullInfo || !fullInfo.functions[funcName]) { return null; }

		// FIX-121: include signatures for callees present in this lifted IR so
		// the MLIR type lattice can seed call results (for example
		// find_reasonable_region -> struct kbase_va_region*). Keep the database
		// scoped; serializing every DWARF struct for every function is wasteful.
		const functionNames = new Set<string>([funcName]);
		if (irText) {
			// Remill passes the real callee as `ptr @symbol` to a semantic
			// helper, so it is not necessarily the direct LLVM call target.
			// Filtering through DWARF/BTF keeps LLVM globals out of the scope.
			const symbolPattern = /@([A-Za-z_.$][\w.$]*)/g;
			for (const match of irText.matchAll(symbolPattern)) {
				if (fullInfo.functions[match[1]]) { functionNames.add(match[1]); }
			}
		}
		const scoped = scopeStructInfoForFunctions(fullInfo, functionNames);
		return { structInfo: scoped, functionName: funcName };
	}

	// -----------------------------------------------------------------------
	/**
	 * v3.7.5 P3: Collect variable renames from the session DB for a given function.
	 * Returns an array of {oldName, newName} pairs to pass to the Helix engine.
	 * The engine will walk the C AST and apply renames surgically on CVarRefExpr nodes.
	 */
	function collectSessionVariableRenames(
		options: Record<string, unknown>,
		eng: DisassemblerEngine
	): Array<{ oldName: string; newName: string }> {
		if (!eng.isFileLoaded()) { return []; }
		const store = eng.getSessionStore();
		if (!store) { return []; }

		// Determine function address from options (handle both number and hex string)
		const funcAddress = parseAddressValue(options.functionAddress as string | number | undefined)
			?? parseAddressValue(options.address as string | number | undefined)
			?? parseAddressValue(options.startAddress as string | number | undefined);
		if (!funcAddress) { return []; }

		// Try the address and nearby offsets (same logic as applySessionRenames)
		const hexAddr = `0x${funcAddress.toString(16)}`;
		let variables = store.getVariables(hexAddr);

		// Try nearby addresses (±16 bytes for patchable entry)
		if ((!variables || variables.length === 0)) {
			for (let delta = 1; delta <= 16; delta++) {
				variables = store.getVariables(`0x${(funcAddress + delta).toString(16)}`);
				if (variables && variables.length > 0) { break; }
				variables = store.getVariables(`0x${(funcAddress - delta).toString(16)}`);
				if (variables && variables.length > 0) { break; }
			}
		}

		if (!variables || variables.length === 0) { return []; }

		const result: Array<{ oldName: string; newName: string }> = [];
		for (const v of variables) {
			if (v.new_name && v.new_name !== v.original_name) {
				result.push({ oldName: v.original_name, newName: v.new_name });
			}
		}
		return result;
	}

	// #52 (option a): post-process Helix C with engine import/PLT map.
	// Pure logic lives in importSymbolNames.ts — see regression tests there.
	function applyImportSymbolNames(source: string, semanticContext?: HelixAnalysisContext): string {
		if (semanticContext) {
			const snapshotSymbols = new Map<number, string>();
			for (const symbol of semanticContext.symbols) {
				snapshotSymbols.set(Number.parseInt(symbol.address, 16), symbol.name);
			}
			for (const imported of semanticContext.imports) {
				snapshotSymbols.set(Number.parseInt(imported.address, 16), imported.name);
			}
			const { source: out, renamed } = applyImportSymbolNamesToSource(source, snapshotSymbols);
			if (renamed > 0) {
				console.log(`[HexCore] helix.decompile: named ${renamed} call target(s) via immutable context`);
			}
			return out;
		}
		if (!engine.isFileLoaded()) { return source; }
		let functions: Array<{ address: number; name?: string }> = [];
		let imports: Array<{ functions?: Array<{ address: number; name?: string }> }> = [];
		try { functions = engine.getFunctions(); } catch { /* engine too old */ }
		try { imports = engine.getImports(); } catch { /* engine too old */ }
		const symMap = buildImportSymbolMap(functions, imports);
		const { source: out, renamed } = applyImportSymbolNamesToSource(source, symMap);
		if (renamed > 0) {
			console.log(`[HexCore] helix.decompile: named ${renamed} sub_/g_ call target(s) via engine symbol map (#52)`);
		}
		return out;
	}

	/** #31: cap Confidence when body still shows damning defects (packaging safety net). */
	function applyHonestyCap(source: string, evidence: HonestyEvidence = {}): string {
		const r = applyHonestyConfidenceCap(source, evidence);
		if (r.capped) {
			console.log(
				`[HexCore] helix.decompile #31 honesty cap: ${r.originalScore}% → ${r.newScore}% ` +
				`(${r.reasons.join('; ')})`,
			);
		}
		return r.source;
	}

	function applySessionRenames(source: string, funcAddress: number | undefined, originalAddress?: number): string {
		if (!engine.isFileLoaded()) return source;
		if (!funcAddress && !originalAddress) return source;

		const store = engine.getSessionStore();
		if (!store) return source;

		let result = source;

		// Try both the lift address and the original (pre-backtrack) address,
		// since renames may be registered against either.
		const candidates: string[] = [];
		if (funcAddress) candidates.push(`0x${funcAddress.toString(16)}`);
		if (originalAddress && originalAddress !== funcAddress)
			candidates.push(`0x${originalAddress.toString(16)}`);

		// Find first address that has a Session DB entry
		let hexAddr = candidates[0] ?? '';
		let funcEntry = store.getFunction(hexAddr);
		if (!funcEntry && candidates[1]) {
			hexAddr = candidates[1];
			funcEntry = store.getFunction(hexAddr);
		}

		// Also try the function table for nearby addresses (±16 bytes for patchable entry)
		if (!funcEntry && funcAddress) {
			for (let delta = 1; delta <= 16; delta++) {
				const tryAddr = `0x${(funcAddress + delta).toString(16)}`;
				funcEntry = store.getFunction(tryAddr);
				if (funcEntry) { hexAddr = tryAddr; break; }
				const tryAddr2 = `0x${(funcAddress - delta).toString(16)}`;
				funcEntry = store.getFunction(tryAddr2);
				if (funcEntry) { hexAddr = tryAddr2; break; }
			}
		}
		if (funcEntry?.name) {
			// Replace sub_<hex> with the user-defined name (word boundary)
			// Try both lift address and original address patterns
			for (const addr of [funcAddress, originalAddress].filter(Boolean) as number[]) {
				const subName = `sub_${addr.toString(16)}`;
				const regex = new RegExp(`\\b${escapeRegex(subName)}\\b`, 'g');
				result = result.replace(regex, funcEntry.name);
			}
		}

		// 2. Apply variable renames and retypes
		// v3.7.5 P3: Variable renames are ALSO passed to the Helix C AST walker
		// (via addVariableRename) for surgical node-level replacement. The string-based
		// regex here runs as a safety net — if the engine already renamed the variable,
		// the regex won't find the old name and is a no-op. If the engine didn't rename
		// (C AST layer off, name mismatch, older .node), the regex catches it.
		const variables = store.getVariables(hexAddr) ?? [];
		for (const v of variables) {
			if (v.new_name && v.new_name !== v.original_name) {
				const regex = new RegExp(`\\b${escapeRegex(v.original_name)}\\b`, 'g');
				result = result.replace(regex, v.new_name);
			}
			if (v.new_type) {
				// Replace type declarations: int32_t param_1 → MyType param_1
				// Look for "old_type var_name" pattern and replace the type part
				const varName = v.new_name || v.original_name;
				// Common C type patterns that appear before variable names
				const typePattern = new RegExp(
					`(\\b(?:u?int(?:8|16|32|64)_t|void|char|short|int|long|float|double|bool|unsigned|struct\\s+\\w+)\\s*\\*?)\\s+(${escapeRegex(varName)}\\b)`,
					'g'
				);
				result = result.replace(typePattern, `${v.new_type} $2`);
			}
		}

		// 3. Apply function return type rename
		if (funcEntry?.return_type) {
			const funcName = funcEntry.name || `sub_${(funcAddress ?? 0).toString(16)}`;
			// Replace return type in function signature: "int32_t funcName(" → "RetType funcName("
			const sigRegex = new RegExp(
				`(\\b(?:u?int(?:8|16|32|64)_t|void|char|short|int|long|float|double|bool|unsigned|struct\\s+\\w+)\\s*\\*?)\\s+(${escapeRegex(funcName)}\\s*\\()`,
				'g'
			);
			result = result.replace(sigRegex, `${funcEntry.return_type} $2`);
		}

		return result;
	}

	/**
	 * v3.7.5 FIX-022c: Validate a backtrack candidate by Capstone linear sweep.
	 *
	 * Decodes instructions from `candidate` to `original`. If we encounter a RET,
	 * INT3 padding (CC CC), unconditional JMP to outside the range, or a decode
	 * failure before reaching `original`, the candidate is a different function
	 * and the backtrack is invalid.
	 *
	 * Cost: ~30-50 Capstone decode calls (submillisecond).
	 */
	async function validateBacktrackCandidate(
		eng: DisassemblerEngine,
		candidate: number,
		original: number
	): Promise<boolean> {
		const dist = original - candidate;
		if (dist <= 0 || dist > 4096) { return false; }

		const bytes = eng.getBytes(candidate, dist + 64); // extra margin
		if (!bytes || bytes.length < dist) { return false; }

		try {
			const capstone = eng.getCapstone();
			if (!capstone) { return false; }

			const insns = await capstone.disassemble(bytes, candidate, 512);
			return isBacktrackContinuityValid(insns ?? [], bytes, candidate, original);
		} catch {
			// Capstone error — can't validate, be conservative and reject
			return false;
		}
	}

	interface AutoBacktrackResolution {
		start: number;
		end?: number;
		source: 'pdata' | 'heuristic';
	}

	/**
	 * Resolve a mid-function request without conflating unwind metadata with
	 * prologue heuristics. AMD64 .pdata is authoritative containment data and
	 * remains valid for a request in the middle of an instruction. Heuristic
	 * candidates must still land exactly on the requested instruction boundary.
	 */
	async function resolveAutoBacktrack(
		eng: DisassemblerEngine,
		original: number
	): Promise<AutoBacktrackResolution | undefined> {
		if (eng.getFileInfo()?.isRelocatable === true) {
			return undefined;
		}

		await eng.ensurePdataFunctionsReconciled();
		const pdataRange = eng.findAuthoritativePdataRangeContaining(original);
		if (pdataRange && pdataRange.begin < original) {
			if (!isBacktrackWithinSection(eng.getSections(), pdataRange.begin, original)) {
				console.log(
					`[HexCore] auto-backtrack: rejected cross-section pdata range ` +
					`0x${original.toString(16)} -> 0x${pdataRange.begin.toString(16)}`
				);
				return undefined;
			}
			return {
				start: pdataRange.begin,
				end: pdataRange.end,
				source: 'pdata'
			};
		}

		const candidate = await eng.findFunctionStartForAddress(original, false);
		if (candidate === undefined || candidate >= original) {
			return undefined;
		}
		if (!isBacktrackWithinSection(eng.getSections(), candidate, original)) {
			console.log(
				`[HexCore] auto-backtrack: rejected cross-section heuristic ` +
				`0x${original.toString(16)} -> 0x${candidate.toString(16)}`
			);
			return undefined;
		}

		const distance = original - candidate;
		if (distance > 4096) {
			console.log(
				`[HexCore] auto-backtrack: discarding heuristic 0x${original.toString(16)} -> ` +
				`0x${candidate.toString(16)} (${distance} bytes > 4096 limit)`
			);
			return undefined;
		}
		if (!await validateBacktrackCandidate(eng, candidate, original)) {
			console.log(
				`[HexCore] auto-backtrack: heuristic 0x${original.toString(16)} -> ` +
				`0x${candidate.toString(16)} rejected by continuity check`
			);
			return undefined;
		}

		return {
			start: candidate,
			end: eng.getFunctionAt(candidate)?.endAddress,
			source: 'heuristic'
		};
	}

	function escapeRegex(s: string): string {
		return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
	}

	// -----------------------------------------------------------------------
	// Souper — Superoptimize LLVM IR via Z3 SMT solving (v3.8.0)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.souper.optimize', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'irText' in (arg as Record<string, unknown>) || 'irPath' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;

			if (!souperWrapper.isAvailable()) {
				const errorMsg = 'hexcore-souper is not available. Souper optimization will be skipped.';
				if (quiet) {
					return { success: false, ir: '', candidatesFound: 0, candidatesReplaced: 0, optimizationTimeMs: 0, error: errorMsg };
				}
				vscode.window.showWarningMessage(errorMsg);
				return undefined;
			}

			// Resolve IR text from various sources
			let irText: string;

			if (isHeadless && typeof options.irText === 'string') {
				irText = options.irText;
			} else if (isHeadless && typeof options.irPath === 'string') {
				const resolved = path.isAbsolute(options.irPath)
					? options.irPath
					: path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', options.irPath);
				if (!fs.existsSync(resolved)) {
					const errorMsg = `IR file not found: ${resolved}`;
					if (quiet) {
						return { success: false, ir: '', candidatesFound: 0, candidatesReplaced: 0, optimizationTimeMs: 0, error: errorMsg };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(resolved, 'utf-8');
			} else if (isHeadless && typeof options.file === 'string') {
				if (!fs.existsSync(options.file)) {
					const errorMsg = `File not found: ${options.file}`;
					if (quiet) {
						return { success: false, ir: '', candidatesFound: 0, candidatesReplaced: 0, optimizationTimeMs: 0, error: errorMsg };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(options.file, 'utf-8');
			} else {
				const activeEditor = vscode.window.activeTextEditor;
				if (!activeEditor) {
					vscode.window.showErrorMessage('No active editor with LLVM IR content.');
					return undefined;
				}
				irText = activeEditor.document.getText();
			}

			// Run Souper optimization
			const souperOpts = {
				maxCandidates: typeof options.maxCandidates === 'number' ? options.maxCandidates : undefined,
				timeoutMs: typeof options.timeoutMs === 'number' ? options.timeoutMs : undefined,
				aggressiveMode: options.aggressiveMode === true,
			};

			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Souper: Optimizing IR...', cancellable: false },
				async () => souperWrapper.optimize(irText, souperOpts)
			);

			if (!quiet) {
				if (result.success) {
					console.log(`[souper] Optimized: applied=${result.candidatesReplaced} inferred=${result.candidatesInferred} attempted=${result.candidatesAttempted}/${result.candidatesFound} timeouts=${result.solverTimeouts} in ${result.optimizationTimeMs.toFixed(0)}ms`);
				} else {
					console.warn(`[souper] Optimization failed: ${result.error}`);
				}
			}

			// Save output if requested (pipeline passes { path, format } object)
			const outputPath = typeof options.output === 'string'
				? options.output
				: (options.output && typeof (options.output as any).path === 'string')
					? (options.output as any).path
					: undefined;
			if (result.success && result.ir && outputPath) {
				const outPath = path.isAbsolute(outputPath)
					? outputPath
					: path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', outputPath);
				fs.mkdirSync(path.dirname(outPath), { recursive: true });
				fs.writeFileSync(outPath, result.ir, 'utf-8');
			}

			return {
				success: result.success,
				ir: result.ir,
				candidatesFound: result.candidatesFound,
				candidatesAttempted: result.candidatesAttempted,
				candidatesInferred: result.candidatesInferred,
				candidatesReplaced: result.candidatesReplaced,
				solverTimeouts: result.solverTimeouts,
				optimizationTimeMs: result.optimizationTimeMs,
				diagnostics: result.diagnostics || '',
				error: result.error || '',
			};
		})
	);

	// -----------------------------------------------------------------------
	// Helix — Decompile IR to pseudo-C (direct IR input)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.helix.cancelActiveLiveDecompile', () => ({
			success: true,
			cancelledWorkers: helixWrapper.cancelActiveDecompiles('debugger-live-memory'),
		}))
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.helix.decompileIR', async (arg?: unknown) => {
			const isHeadless = !((arg as any) instanceof vscode.Uri)
				&& hasHeadlessHelixIrInput(arg);

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;
			const sourceTargetFile = typeof options.sourceTargetFile === 'string'
				? options.sourceTargetFile
				: typeof options.file === 'string' ? options.file : undefined;
			const analysisContext = decideAnalysisContextOwnership(
				sourceTargetFile,
				engine.getFilePath(),
			);
			const useActiveEngineContext = analysisContext.activeEngineEvidenceUsed;
			const requestedArch = typeof options.architecture === 'string'
				? options.architecture
				: typeof options.arch === 'string' ? options.arch : undefined;
			const arch = requestedArch && ['x86', 'x64', 'arm', 'arm64'].includes(requestedArch)
				? requestedArch as ReturnType<typeof engine.getArchitecture>
				: useActiveEngineContext ? engine.getArchitecture() : 'x64';
			if (!useActiveEngineContext) {
				console.log(
					`[hexcore-helix] active engine context denied for decompileIR ` +
					`(ownership=${analysisContext.ownership}, source=${analysisContext.sourceTargetFile ?? 'unbound'}, ` +
					`active=${analysisContext.activeTargetFile ?? 'none'})`
				);
			}

			if (!helixWrapper.isAvailable()) {
				const errorMsg = 'hexcore-helix is not available.';
				// Bug #36/2: headless/pipeline runs get the structured error, not undefined + modal.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg, analysisContext };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			let irText: string;

			// irPath: explicit .ll file path for pipeline use (options.file is always the binary).
			const irFilePath = typeof options.irPath === 'string' ? options.irPath : undefined;

			if (isHeadless && typeof options.irText === 'string') {
				irText = options.irText;
			} else if (irFilePath) {
				const resolved = path.isAbsolute(irFilePath)
					? irFilePath
					: path.resolve(vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '', irFilePath);
				if (!fs.existsSync(resolved)) {
					const errorMsg = `IR file not found: ${resolved}`;
					// Bug #36/2: in headless/pipeline runs ALWAYS return the structured
					// {success:false,error} so the runner surfaces the real cause; never
					// return undefined or pop a modal during a headless auto-run (the
					// file-watcher path is headless but has quiet:false).
					if (quiet || isHeadless) {
						return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg, analysisContext };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(resolved, 'utf-8');
			} else if (isHeadless && typeof options.file === 'string') {
				if (!fs.existsSync(options.file)) {
					const errorMsg = `File not found: ${options.file}`;
					// Bug #36/2: headless callers must get the structured error, not a modal.
					if (quiet || isHeadless) {
						return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg, analysisContext };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(options.file, 'utf-8');
			} else {
				const activeEditor = vscode.window.activeTextEditor;
				if (!activeEditor) {
					vscode.window.showErrorMessage('No active editor with LLVM IR content.');
					return undefined;
				}
				irText = activeEditor.document.getText();
			}

			// FIX-QUALITY-001: cast layer ON by default; functionStarts enriched below.
			// NOTE: must be `let` — sessionRenames and structInfo may promote fields.
			let helixIROptions: {
				optimizeIR?: boolean; useCastLayer?: boolean;
				variableRenames?: Array<{ oldName: string; newName: string }>;
				structInfo?: StructInfoJson; functionName?: string;
				dataSections?: Array<{ vaStart: bigint; bytes: Buffer }>;
				functionStarts?: number[];
				semanticContext?: HelixAnalysisContext;
			} = { ...resolveHelixBaseOptions(options) };

			// v3.7.5 P3: Collect session variable renames for this function and pass
			// them to the Helix engine so the C AST walker can apply them surgically.
			const sessionRenames = useActiveEngineContext
				? collectSessionVariableRenames(options, engine)
				: [];
			if (sessionRenames.length > 0) {
				helixIROptions = helixIROptions ?? {};
				helixIROptions.variableRenames = sessionRenames;
			}

			// v3.8.0: Extract struct field info from BTF for struct field naming
			const funcAddr = parseAddressValue(options.functionAddress as string | number | undefined)
				?? parseAddressValue(options.address as string | number | undefined)
				?? parseAddressValue(options.startAddress as string | number | undefined)
				?? parseAddressValue(options.targetAddress as string | number | undefined);
			const semanticContext = useActiveEngineContext && funcAddr !== undefined
				? await createHelixAnalysisContext(engine, funcAddr)
				: undefined;
			if (semanticContext) {
				helixIROptions.semanticContext = semanticContext;
			}
			// v3.8.1: If neither address nor name was provided in options,
			// extract the function name directly from the LLVM IR text.
			// Remill/Pathfinder names it during lift (e.g.
			// "define ... @kbase_jit_allocate(...)"), which is the
			// definitive source for struct-scoping on decompileIR calls
			// that don't carry metadata.
			let explicitFuncName = typeof options.functionName === 'string' ? options.functionName : undefined;
			if (!explicitFuncName && funcAddr === undefined && typeof irText === 'string') {
				const defMatch = irText.match(/^\s*define\s+(?:[^@\n]*)@([A-Za-z_][\w.]*)/m);
				if (defMatch) {
					explicitFuncName = defMatch[1];
					console.log(`[helix-struct] Extracted function name from IR: ${explicitFuncName}`);
				}
			}
			const structResult = useActiveEngineContext && options.structInfo !== false
				? extractStructInfoForFunction(engine, funcAddr, explicitFuncName, irText)
				: null;
			if (structResult) {
				helixIROptions = helixIROptions ?? {};
				helixIROptions.structInfo = structResult.structInfo;
				helixIROptions.functionName = structResult.functionName;
				if (!quiet) {
					const sc = Object.keys(structResult.structInfo.structs).length;
					console.log(`[helix-struct] Auto-extracted ${sc} struct(s) from BTF for ${structResult.functionName}`);
				}
			}
			// Also accept explicit structInfo JSON from headless callers
			if (isHeadless && options.structInfoJson && typeof options.structInfoJson === 'string') {
				try {
					const parsed = JSON.parse(options.structInfoJson) as StructInfoJson;
					helixIROptions = helixIROptions ?? {};
					helixIROptions.structInfo = parsed;
					if (typeof options.functionName === 'string') {
						helixIROptions.functionName = options.functionName;
					}
				} catch { /* invalid JSON — ignore */ }
			}

			// v3.8.0: Souper superoptimization — optimize IR before Helix decompilation
			let irForHelix = irText;
			// v3.8.3: tri-state Souper gate -- absent/'auto' runs Souper only on
			// crypto/MBA-dense IR; true is explicit force-on; false is off.
			const souperGate = decideSouperGate(options.souper, irText, {
				threshold: typeof options.souperAutoThreshold === 'number' ? options.souperAutoThreshold : undefined,
				minSignalOps: typeof options.souperAutoMinOps === 'number' ? options.souperAutoMinOps : undefined,
			});
			if (souperWrapper.isAvailable() && souperGate.mode === 'auto-skip' && !quiet) {
				console.log(`[souper] auto-skip (${souperGate.reason})`);
			}
			if (souperWrapper.isAvailable() && souperGate.run) {
				const souperResult = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Souper: Optimizing IR...', cancellable: false },
					async () => souperWrapper.optimize(irText, {
						timeoutMs: typeof options.souperTimeout === 'number' ? options.souperTimeout : undefined,
					})
				);
				if (souperResult.success && souperResult.ir) {
					irForHelix = souperResult.ir;
					if (!quiet) {
						console.log(`[souper] Optimized: ${souperResult.candidatesReplaced}/${souperResult.candidatesFound} candidates in ${souperResult.optimizationTimeMs.toFixed(0)}ms`);
					}
				} else if (souperResult.error) {
					console.warn(`[souper] Optimization skipped: ${souperResult.error}`);
				}
			}

			// v3.9.0: Feed the binary's data sections so Helix's
			// RecoverSwitchTables pass can read jump-table entries.  Without
			// this the pass auto-skips and every `switch (...)` in the source
			// binary collapses to `goto default` in the decompiled output.
			const binaryForSections = isHeadless && typeof options.file === 'string'
				? options.file : undefined;
			const peSections = await getDataSectionsFor(binaryForSections);
			if (peSections && peSections.length > 0) {
				helixIROptions = helixIROptions ?? {};
				helixIROptions.dataSections = peSections.map(s => ({
					vaStart: s.vaStart, bytes: s.bytes
				}));
			}

			// A completed immutable context owns the function-start table. Older or
			// incomplete contexts retain the explicit honesty-mode fallback.
			if (semanticContext?.analysis.functionStartsAuthoritative && options.functionStarts !== false) {
				helixIROptions.functionStarts = [...semanticContext.functionStarts];
				if (!quiet) {
					console.log(
						`[helix] immutable context ${semanticContext.contextSha256.slice(0, 12)}: ` +
						`${semanticContext.functionStarts.length} authoritative function starts`
					);
				}
			} else if (useActiveEngineContext && wantsHelixFunctionStarts(options)) {
				const starts = buildHelixFunctionStarts(engine, {
					irText: irForHelix,
					entryAddress: funcAddr,
				});
				if (starts && starts.length > 0) {
					helixIROptions.functionStarts = starts;
					if (!quiet) {
						console.log(
							`[helix] functionStarts: ${starts.length} entries ` +
							`(honesty mode: analyzeAll+IR CALLI+imports/exports)`
						);
					}
				}
			} else if (!quiet) {
				console.log('[helix] functionStarts: omitted (default quality path; set functionStarts:true for D2 honesty)');
			}

			const forceWorker = options.forceWorker === true;
			const forceProcess = options.forceProcess === true;
			const workerTimeoutMs = typeof options.workerTimeoutMs === 'number'
				? options.workerTimeoutMs
				: undefined;
			const workerGroup = typeof options.workerGroup === 'string'
				? options.workerGroup
				: undefined;
			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Helix: Decompiling IR...', cancellable: false },
				// Live-memory callers explicitly force an isolated process so native work
				// can be killed without terminating the Extension Host.
				async () => helixWrapper.decompileIr(irForHelix, arch, {
					...helixIROptions,
					forceWorker,
					forceProcess,
					workerTimeoutMs,
					workerGroup,
					forceSync: !forceWorker && !forceProcess && (quiet || isHeadless || options.forceSync === true),
				})
			);

			if (!decompileResult.success) {
				const errorMsg = `Helix decompilation failed: ${decompileResult.error}`;
				console.error(`[hexcore-helix] decompileIR failed:`, decompileResult.error);
				// Bug #36/2: a Helix failure in a pipeline step must reach the runner as a
				// structured error, not undefined + modal, so the recorded step error is
				// the real Helix cause rather than 'output file was not created'.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: decompileResult.error, analysisContext };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Apply Session DB renames/retypes (funcAddress from options if available)
			const decompileAddr = parseAddressValue(options.functionAddress as string | number | undefined)
				?? parseAddressValue(options.address as string | number | undefined);
			let fullCode = decompileResult.source;
			if (useActiveEngineContext) {
				fullCode = applySessionRenames(fullCode, decompileAddr);
				// #52: name imported/PLT call targets (sub_<pltVA> → dlopen, …) via the engine symbol map.
				fullCode = applyImportSymbolNames(fullCode, semanticContext);
				fullCode = applyHonestyCap(fullCode, {
					callfuscation: engine.detectCallfuscation(),
				});
			}

			// v3.8.0: Replace Helix-generated sub_<hex> with real function name.
			// Helix ignores the IR function name and generates sub_<hex> from the
			// entry address. We extract the real name from the IR text (define @<name>)
			// or from the ; Function: header, then replace in C output.
			{
				let irFuncName = typeof options.functionName === 'string' ? options.functionName : undefined;

				// Extract name from IR if not in options
				if (!irFuncName || irFuncName.startsWith('sub_')) {
					// Try "define ... @<name>(" pattern in IR
					const defineMatch = irForHelix.match(/define\s+\S+\s+@(\w+)\s*\(/);
					if (defineMatch && !defineMatch[1].startsWith('lifted_') && !defineMatch[1].startsWith('sub_')) {
						irFuncName = defineMatch[1];
					}
					// Try "; Function: <name>" header
					if (!irFuncName || irFuncName.startsWith('sub_')) {
						const headerMatch = irForHelix.match(/^;\s*Function:\s*(.+)$/m);
						if (headerMatch && !headerMatch[1].startsWith('sub_')) {
							irFuncName = headerMatch[1].trim();
						}
					}
				}

				if (irFuncName && !irFuncName.startsWith('sub_')) {
					// Extract the function's own sub_<hex> name from the Helix output.
					// It appears in the signature line: "int64_t sub_3a29(...)"
					// Only replace THIS specific sub_<hex>, not other sub_<hex> calls.
					const sigMatch = fullCode.match(/^\w[\w\s*]+\b(sub_[0-9a-fA-F]+)\s*\(/m);
					if (sigMatch) {
						const subName = sigMatch[1];
						fullCode = fullCode.replace(new RegExp(`\\b${subName}\\b`, 'g'), irFuncName);
						console.log(`[HexCore] helix.decompileIR: Renamed ${subName} → ${irFuncName} in C output`);
					}
				}
			}
			const outputQuality = inspectHelixOutputQuality(fullCode);
			fullCode = stampHelixConfidenceAxes(fullCode, outputQuality.confidenceAxes);

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				// Bug #36/2: ensure the output directory exists before writing so a job
				// whose reportsDir/outDir was never created does not silently fail the
				// write and then trip the 'output file was not created' mask.
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			const commandResult = {
				success: true,
				status: outputQuality.status,
				code: fullCode,
				functionCount: decompileResult.instructionCount,
				address: decompileResult.entryAddress,
				architecture: arch,
				confidence: outputQuality.confidence,
				confidenceAxes: outputQuality.confidenceAxes,
				qualityIssues: outputQuality.qualityIssues,
				qualityIssueMessages: outputQuality.issues,
				securityEvidenceUsable: outputQuality.securityEvidenceUsable,
				warning: outputQuality.reason ?? '',
				error: '',
				analysisContext,
				semanticContext: semanticContext ? {
					contextVersion: semanticContext.contextVersion,
					contextSha256: semanticContext.contextSha256,
					function: semanticContext.function,
					analysis: semanticContext.analysis,
				} : undefined,
				// HQL: expose the raw HAST FlatBuffer so headless callers
				// (hexcore.hql.scanHeadless) can run scanHAST() over the decompiled
				// function. In-process executeCommand returns the literal object so
				// the Buffer survives uncopied. Additive: existing callers ignore it.
				astBuffer: decompileResult.astBuffer,
			};

			if (quiet) {
				return commandResult;
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return commandResult;
		})
	);

	// -----------------------------------------------------------------------
	// Helix — Lift + Decompile (binary → IR → pseudo-C)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.helix.decompile', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'startAddress' in (arg as Record<string, unknown>) || 'address' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;
			const arch = engine.getArchitecture();

			if (!remillWrapper.isAvailable()) {
				const errorMsg = 'hexcore-remill is not available. Cannot lift machine code to IR.';
				// Bug #36/2: headless/pipeline runs get the structured error, not undefined + modal.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			if (!helixWrapper.isAvailable()) {
				const errorMsg = 'hexcore-helix is not available. Install the prebuild or build from source.';
				// Bug #36/2: headless/pipeline runs get the structured error, not undefined + modal.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Issue #32 (HONESTY): if the target is a managed .NET (CIL) assembly, do NOT
			// lift its CIL .text as native x86 — that produces the _CorExeMain thunk + a run
			// of mis-decoded zero padding and a confident 85% "stub function". Short-circuit
			// with an honest marker (managed:true, confidence 0) so the analyze/decompile
			// output reads as "can't, use IL tooling" instead of a fake success (D4).
			const managedTarget = await detectManagedDotNet(options);
			if (managedTarget) {
				const markerCode = buildManagedDotNetMarker(managedTarget);
				if (isHeadless && options.output) {
					const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
					fs.mkdirSync(path.dirname(outputPath), { recursive: true });
					fs.writeFileSync(outputPath, markerCode, 'utf-8');
				}
				const reqAddr = parseAddressValue(options.address as string | number | undefined)
					?? parseAddressValue(options.startAddress as string | number | undefined);
				const managedResult = {
					success: true,
					managed: true,
					managedFormat: managedTarget.kind === 'clr' ? 'dotnet-cil' : 'dotnet-single-file',
					confidence: 0,
					code: markerCode,
					functionCount: 0,
					address: reqAddr !== undefined ? `0x${reqAddr.toString(16).toUpperCase()}` : '',
					architecture: arch,
					error: 'managed .NET (CIL) assembly — native x86 decompile not applicable; use a .NET/IL decompiler',
				};
				if (quiet || isHeadless) {
					return managedResult;
				}
				const mdoc = await vscode.workspace.openTextDocument({ content: markerCode, language: 'c' });
				await vscode.window.showTextDocument(mdoc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
				// Issue #32 "Better" tier: offer to recover the real C# / IL via the
				// Revenant managed decompiler (hexcore-revenant) rather than only pointing
				// at external tooling. The user clicks the action; nothing auto-runs.
				const REVENANT_ACTION = 'Decompile with Revenant';
				const dotnetFile = (typeof options.file === 'string' ? options.file : undefined) || engine.getFilePath();
				void vscode.window.showWarningMessage(
					'Managed .NET (CIL) assembly: native x86 decompile is not applicable. Recover the C# / IL with Revenant.',
					REVENANT_ACTION
				).then(async action => {
					if (action !== REVENANT_ACTION) { return; }
					const cmds = await vscode.commands.getCommands(true);
					if (!cmds.includes('hexcore.revenant.decompile')) {
						void vscode.window.showErrorMessage('HexCore Revenant extension is not available. Decompile manually with ilspycmd / ILSpy (ICSharpCode.Decompiler).');
						return;
					}
					void vscode.commands.executeCommand('hexcore.revenant.decompile', dotnetFile ? { file: dotnetFile } : undefined);
				});
				return managedResult;
			}

			// Lift machine code to LLVM IR via liftToIR command
			const liftResult: LiftResult | undefined = await vscode.commands.executeCommand(
				'hexcore.disasm.liftToIR', { ...options, quiet: true, output: undefined }
			);

			if (!liftResult || !liftResult.success) {
				const errorMsg = liftResult?.error ?? 'Lift failed.';
				// Bug #36/2: a failed lift (no function/code at address) must propagate as
				// a structured error in headless/pipeline runs, not undefined + modal.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// FIX-QUALITY-001: cast layer ON by default (engine-direct parity).
			// NOTE: must be `let` — sessionRenames and structInfo may promote fields.
			let helixOptions: {
				optimizeIR?: boolean; useCastLayer?: boolean;
				variableRenames?: Array<{ oldName: string; newName: string }>;
				structInfo?: StructInfoJson; functionName?: string;
				dataSections?: Array<{ vaStart: bigint; bytes: Buffer }>;
				functionStarts?: number[];
				semanticContext?: HelixAnalysisContext;
			} = { ...resolveHelixBaseOptions(options) };

			// v3.7.5 P3: Collect session variable renames and pass to Helix engine
			const sessionRenames2 = collectSessionVariableRenames(options, engine);
			if (sessionRenames2.length > 0) {
				helixOptions = helixOptions ?? {};
				helixOptions.variableRenames = sessionRenames2;
			}

			// v3.8.0: Extract struct field info from BTF for struct field naming
			const funcAddr2 = (typeof liftResult.address === 'number' ? liftResult.address : undefined)
				?? parseAddressValue(options.address as string | number | undefined)
				?? parseAddressValue(options.startAddress as string | number | undefined);
			const semanticContext2 = funcAddr2 !== undefined
				? await createHelixAnalysisContext(engine, funcAddr2)
				: undefined;
			if (semanticContext2) {
				helixOptions.semanticContext = semanticContext2;
			}
			const structResult2 = options.structInfo !== false
				? extractStructInfoForFunction(engine, funcAddr2, typeof options.functionName === 'string' ? options.functionName : undefined, liftResult.ir)
				: null;
			if (structResult2) {
				helixOptions = helixOptions ?? {};
				helixOptions.structInfo = structResult2.structInfo;
				helixOptions.functionName = structResult2.functionName;
				if (!quiet) {
					const sc = Object.keys(structResult2.structInfo.structs).length;
					console.log(`[helix-struct] Auto-extracted ${sc} struct(s) from BTF for ${structResult2.functionName}`);
				}
			}
			if (isHeadless && options.structInfoJson && typeof options.structInfoJson === 'string') {
				try {
					const parsed = JSON.parse(options.structInfoJson) as StructInfoJson;
					helixOptions = helixOptions ?? {};
					helixOptions.structInfo = parsed;
					if (typeof options.functionName === 'string') {
						helixOptions.functionName = options.functionName;
					}
				} catch { /* invalid JSON — ignore */ }
			}

			// v3.8.0: Souper superoptimization — optimize lifted IR before Helix
			let irForHelix2 = liftResult.ir;
			// v3.8.3: tri-state Souper gate -- absent/'auto' runs Souper only on
			// crypto/MBA-dense IR; true is explicit force-on; false is off.
			const souperGate2 = decideSouperGate(options.souper, liftResult.ir, {
				threshold: typeof options.souperAutoThreshold === 'number' ? options.souperAutoThreshold : undefined,
				minSignalOps: typeof options.souperAutoMinOps === 'number' ? options.souperAutoMinOps : undefined,
			});
			if (souperWrapper.isAvailable() && souperGate2.mode === 'auto-skip' && !quiet) {
				console.log(`[souper] auto-skip (${souperGate2.reason})`);
			}
			if (souperWrapper.isAvailable() && souperGate2.run) {
				const souperResult = await vscode.window.withProgress(
					{ location: vscode.ProgressLocation.Notification, title: 'Souper: Optimizing IR...', cancellable: false },
					async () => souperWrapper.optimize(liftResult.ir, {
						timeoutMs: typeof options.souperTimeout === 'number' ? options.souperTimeout : undefined,
					})
				);
				if (souperResult.success && souperResult.ir) {
					irForHelix2 = souperResult.ir;
					if (!quiet) {
						console.log(`[souper] Optimized: ${souperResult.candidatesReplaced}/${souperResult.candidatesFound} candidates in ${souperResult.optimizationTimeMs.toFixed(0)}ms`);
					}
				} else if (souperResult.error) {
					console.warn(`[souper] Optimization skipped: ${souperResult.error}`);
				}
			}

			// v3.9.0: Feed data sections so RecoverSwitchTables can resolve
			// jump tables in the source binary (see decompileIR command).
			const peSections2 = await getDataSectionsFor(
				typeof options.file === 'string' ? options.file : undefined
			);
			if (peSections2 && peSections2.length > 0) {
				helixOptions = helixOptions ?? {};
				helixOptions.dataSections = peSections2.map(s => ({
					vaStart: s.vaStart, bytes: s.bytes
				}));
			}

			if (semanticContext2?.analysis.functionStartsAuthoritative && options.functionStarts !== false) {
				helixOptions.functionStarts = [...semanticContext2.functionStarts];
				if (!quiet) {
					console.log(
						`[helix] immutable context ${semanticContext2.contextSha256.slice(0, 12)}: ` +
						`${semanticContext2.functionStarts.length} authoritative function starts`
					);
				}
			} else if (wantsHelixFunctionStarts(options)) {
				const lrAny = liftResult as LiftResult & { internalCallTargets?: number[] };
				const starts = buildHelixFunctionStarts(engine, {
					callTargets: Array.isArray(lrAny.callTargets) ? lrAny.callTargets : undefined,
					internalCallTargets: Array.isArray(lrAny.internalCallTargets)
						? lrAny.internalCallTargets : undefined,
					irText: irForHelix2,
					entryAddress: typeof liftResult.address === 'number' ? liftResult.address : funcAddr2,
				});
				if (starts && starts.length > 0) {
					helixOptions.functionStarts = starts;
					if (!quiet) {
						console.log(
							`[helix] functionStarts: ${starts.length} entries ` +
							`(honesty mode: analyzeAll+IR CALLI+imports/exports)`
						);
					}
				}
			} else if (!quiet) {
				console.log('[helix] functionStarts: omitted (default quality path; set functionStarts:true for D2 honesty)');
			}

			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Helix: Decompiling...', cancellable: false },
				// FIX-QUALITY-002b: headless/quiet → forceSync (engine-direct parity;
				// avoids Electron worker_threads + native .node double-load quirks)
				async () => helixWrapper.decompileIr(irForHelix2, arch, {
					...helixOptions,
					forceSync: quiet || isHeadless || options.forceSync === true,
				})
			);

			if (!decompileResult.success) {
				const errorMsg = `Helix decompilation failed: ${decompileResult.error}`;
				console.error(`[hexcore-helix] decompile failed:`, decompileResult.error);
				// Bug #36/2: surface the real Helix failure to the pipeline runner.
				if (quiet || isHeadless) {
					return { success: false, code: '', functionCount: 0, address: String(liftResult.address ?? ''), architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Apply Session DB renames/retypes to the decompiled output
			// liftResult.address = post-backtrack (e.g. 0x3A10)
			// options.address / options.startAddress = original user address (e.g. 0x3A20)
			const funcAddr = typeof liftResult.address === 'number' ? liftResult.address : undefined;
			const origAddr = parseAddressValue(options.address as string | number | undefined)
				?? parseAddressValue(options.startAddress as string | number | undefined)
				?? parseAddressValue(options.functionAddress as string | number | undefined);
			let fullCode = applySessionRenames(decompileResult.source, funcAddr, origAddr);
				// #52: name imported/PLT call targets (sub_<pltVA> → dlopen, …) via the engine symbol map.
				fullCode = applyImportSymbolNames(fullCode, semanticContext2);

			// FIX-QUALITY-002: stamp lift diagnostics into the C header so job
			// outputs self-describe whether Remill under-lifted (silent gap).
			{
				const irLines = (liftResult.ir || '').split('\n').length;
				const cLines = fullCode.split('\n').length;
				const consumed = typeof liftResult.bytesConsumed === 'number' ? liftResult.bytesConsumed : -1;
				const knownSz = (() => {
					const a = typeof liftResult.address === 'number'
						? liftResult.address
						: (funcAddr ?? origAddr ?? 0);
					if (!a) { return 0; }
					return getAuthoritativeFunctionExtent(engine, a).size;
				})();
				const under = knownSz > 0 && consumed > 0 && consumed < knownSz * 0.85;
				const scopeLimited = liftResult.scopeLimited === true;
				// #56: apply the honesty gate while lift coverage is still
				// structured data. Parsing the later LiftDiag comment is both late
				// and fragile, and previously made UNDERLIFT invisible to the cap.
				fullCode = applyHonestyCap(fullCode, {
					bytesConsumed: consumed,
					knownFunctionSize: knownSz,
					cLines,
					callfuscation: engine.detectCallfuscation(),
					semanticCoverage: liftResult.semanticCoverage,
					unsupportedInstructions: liftResult.unsupportedInstructions,
					decodeFailureInstructions: liftResult.decodeFailureInstructions,
					scopeLimited: scopeLimited ? {
						instructionLimit: liftResult.requestedInstructionLimit,
					} : undefined,
				});
				const requestedLiftAddress = typeof liftResult.requestedAddress === 'number'
					? liftResult.requestedAddress : (origAddr ?? funcAddr ?? 0);
				const effectiveLiftAddress = typeof liftResult.address === 'number'
					? liftResult.address : 0;
				const transformations = Array.isArray(liftResult.liftTransformations)
					? liftResult.liftTransformations as Array<{ kind: string; address: number; bytes: number }>
					: [];
				const diag =
					`// LiftDiag: addr=0x${effectiveLiftAddress.toString(16)} ` +
					`requested=0x${requestedLiftAddress.toString(16)} effective=0x${effectiveLiftAddress.toString(16)} ` +
					`range=${knownSz > 0 ? `0x${effectiveLiftAddress.toString(16)}-0x${(effectiveLiftAddress + knownSz).toString(16)}` : '?'} ` +
					`bytesConsumed=${consumed}/${knownSz || '?'} irLines=${irLines} cLines=${cLines} ` +
					`cast=${helixOptions.useCastLayer !== false} ` +
					`fnStarts=${helixOptions.functionStarts?.length ?? 0} ` +
					`semanticCoverage=${typeof liftResult.semanticCoverage === 'number' ? (liftResult.semanticCoverage * 100).toFixed(1) + '%' : '?'} ` +
					`unsupported=${liftResult.unsupportedInstructions ?? '?'} ` +
					`decodeFailures=${liftResult.decodeFailureInstructions ?? '?'}` +
					(under ? ' UNDERLIFT' : '') +
					(scopeLimited ? ` SCOPED(count=${liftResult.requestedInstructionLimit ?? '?'})` : '') +
					(transformations.length > 0
						? ` transforms=${transformations.map(item => `${item.kind}@0x${item.address.toString(16)}+${item.bytes}`).join(',')}`
						: ' transforms=none');
				console.log(`[HexCore] ${diag}`);
				// Insert after the Confidence header line when present, else prepend.
				if (/Confidence:\s*[\d.]+%/.test(fullCode)) {
					fullCode = fullCode.replace(
						/(Confidence:\s*[\d.]+%[^\n]*\n)/,
						`$1${diag}\n`,
					);
				} else {
					fullCode = diag + '\n' + fullCode;
				}
			}
			const outputQuality = inspectHelixOutputQuality(fullCode);
			fullCode = stampHelixConfidenceAxes(fullCode, outputQuality.confidenceAxes);

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				// Bug #36/2: ensure the output directory exists before writing.
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			const commandResult = {
				success: true,
				status: liftResult.status === 'partial' ? 'partial' as const : outputQuality.status,
				code: fullCode,
				functionCount: decompileResult.instructionCount,
				address: decompileResult.entryAddress || String(liftResult.address || ''),
				architecture: arch,
				confidence: outputQuality.confidence,
				confidenceAxes: outputQuality.confidenceAxes,
				qualityIssues: outputQuality.qualityIssues,
				qualityIssueMessages: outputQuality.issues,
				securityEvidenceUsable: outputQuality.securityEvidenceUsable,
				warning: liftResult.semanticWarning || outputQuality.reason || '',
				liftSemantics: {
					decodedInstructions: liftResult.decodedInstructions,
					liftedInstructions: liftResult.liftedInstructions,
					unsupportedInstructions: liftResult.unsupportedInstructions,
					decodeFailureInstructions: liftResult.decodeFailureInstructions,
					semanticCoverage: liftResult.semanticCoverage,
					unsupportedOpcodes: liftResult.unsupportedOpcodes,
					requestedWindowCoverage: liftResult.requestedWindowCoverage,
					decodedByteCoverage: liftResult.decodedByteCoverage,
					functionBoundaryKnown: liftResult.functionBoundaryKnown,
				},
				semanticContext: semanticContext2 ? {
					contextVersion: semanticContext2.contextVersion,
					contextSha256: semanticContext2.contextSha256,
					function: semanticContext2.function,
					analysis: semanticContext2.analysis,
				} : undefined,
				error: '',
				// HQL: raw HAST FlatBuffer for headless scanHAST() callers (additive).
				astBuffer: decompileResult.astBuffer,
			};

			if (quiet) {
				return commandResult;
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return commandResult;
		})
	);

	// -----------------------------------------------------------------------
	// HQL (Helix Query Language) -- semantic signature scanner.
	// Decompiles the target function (reusing the helix.decompile* commands,
	// which now expose the raw HAST FlatBuffer) and evaluates the built-in HQL
	// signature library over its AST. See ./hqlScanner.ts.
	// -----------------------------------------------------------------------

	// Adapter: turn an HqlScanTarget into the right Helix decompile command
	// invocation and return the quiet result (which carries astBuffer). Binary
	// targets -> helix.decompile (lift+decompile); IR targets -> helix.decompileIR.
	const hqlDecompile = async (target: HqlScanTarget): Promise<HelixDecompileQuietResult | undefined> => {
		if (target.irPath !== undefined || target.irText !== undefined) {
			return vscode.commands.executeCommand<HelixDecompileQuietResult>(
				'hexcore.helix.decompileIR',
				{
					...(target.irPath !== undefined ? { irPath: target.irPath } : {}),
					...(target.irText !== undefined ? { irText: target.irText } : {}),
					quiet: true,
					output: undefined,
				}
			);
		}
		return vscode.commands.executeCommand<HelixDecompileQuietResult>(
			'hexcore.helix.decompile',
			{
				...(target.file !== undefined ? { file: target.file } : {}),
				...(target.address !== undefined ? { address: target.address } : {}),
				quiet: true,
				output: undefined,
			}
		);
	};
	const hqlSessionBinding = () => {
		const session = engine.getSessionStore();
		if (!session) { return undefined; }
		return createLiveHqlSessionReader(session);
	};

	// Interactive: scan the current/selected function for HQL signature matches.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hql.scanFunction', async (arg?: unknown) => {
			if (!loadHql()) {
				vscode.window.showErrorMessage(`HexCore HQL is unavailable: ${getHqlLoadError() ?? 'hexcore-hql not loaded'}`);
				return;
			}

			// Resolve the function address: explicit arg, then the current function
			// in the active disassembler editor.
			const explicit = (arg && typeof arg === 'object' && !(arg instanceof vscode.Uri))
				? (arg as Record<string, unknown>).address
				: undefined;
			const addr = parseAddressValue(explicit as string | number | undefined)
				?? disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('HQL: no function selected. Open a function in the disassembler first.');
				return;
			}

			const target: HqlScanTarget = { file: engine.getFilePath(), address: addr };
			const result = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'HQL: Scanning function...', cancellable: false },
				async () => scanOneTarget(target, hqlDecompile, { session: hqlSessionBinding })
			);

			const channel = hqlOutputChannel();
			const label = result.function || result.address || `0x${addr.toString(16)}`;
			if (result.error && result.findings.length === 0) {
				channel.appendLine(`[HQL] ${label}: ${result.error}`);
				vscode.window.showInformationMessage(`HQL: ${result.error}`);
				return result;
			}
			channel.appendLine(`[HQL] ${label} -- ${result.findings.length} signature(s) matched`);
			for (const f of result.findings) {
				const calibrated = f.confidence !== undefined ? `, calibrated confidence ${f.confidence.toFixed(2)}` : '';
				channel.appendLine(`         ${f.signatureId} (${f.evidenceLevel}, structural ${f.structuralCompleteness.toFixed(2)}${calibrated}, ${f.matchCount} node(s))`);
			}
			channel.show(true);
			vscode.window.showInformationMessage(`HQL: ${result.findings.length} signature(s) matched in ${label}`);
			return result;
		})
	);

	// Headless: batch HQL scan for the automation pipeline.
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.hql.scanHeadless', async (arg?: Record<string, unknown>) => {
			const file = typeof arg?.file === 'string' ? arg.file : undefined;
			const irPath = typeof arg?.irPath === 'string' ? arg.irPath : undefined;
			const irText = typeof arg?.irText === 'string' ? arg.irText : undefined;
			const address = (typeof arg?.address === 'string' || typeof arg?.address === 'number')
				? arg.address : undefined;
			const addresses = Array.isArray(arg?.addresses)
				? (arg!.addresses as Array<unknown>).filter(
					(a): a is string | number => typeof a === 'string' || typeof a === 'number')
				: undefined;
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as { path?: unknown })?.path === 'string'
					? (arg!.output as { path: string }).path : undefined);
			const positiveIntegerArg = (name: string): number | undefined => {
				const value = arg?.[name];
				return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 ? value : undefined;
			};

			const targets = buildScanTargets({ file, address, addresses, irPath, irText });
			if (targets.length === 0) {
				const report = {
					success: false,
					status: 'failed' as const,
					command: 'hexcore.hql.scanHeadless' as const,
					file,
					targetCount: 0,
					completedTargetCount: 0,
					failedTargetCount: 0,
					partialTargetCount: 0,
					matchedFunctionCount: 0,
					totalFindings: 0,
					results: [],
					budget: { ...DEFAULT_HQL_BATCH_BUDGET },
					error: 'hexcore.hql.scanHeadless requires an "address", "addresses", "irPath", or "irText".',
				};
				if (outputPath) {
					fs.mkdirSync(path.dirname(outputPath), { recursive: true });
					fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
				}
				return report;
			}

			const report = await runHqlScanBatch(file, targets, hqlDecompile, {
				maxTargets: positiveIntegerArg('maxTargets'),
				maxConcurrency: positiveIntegerArg('maxConcurrency'),
				maxFunctionsPerHast: positiveIntegerArg('maxFunctionsPerHast'),
				maxNodesPerFunction: positiveIntegerArg('maxNodesPerFunction'),
				maxFindingsPerFunction: positiveIntegerArg('maxFindingsPerFunction'),
				session: hqlSessionBinding,
			});

			if (outputPath) {
				// Bug #36/2: create the parent dir so the write never silently fails
				// and trips the runner's "output file not created" mask.
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf-8');
			}
			return report;
		})
	);

	// -----------------------------------------------------------------------
	// Extract Struct Info — dump BTF/debug struct layouts to JSON
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.extractStructInfo', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri);
			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;

			const elfAnalysis = engine.getELFAnalysis();
			const hasBtf = !!elfAnalysis?.btfData;
			const hasDwarf = !!elfAnalysis?.dwarfStructInfo;

			if (!hasBtf && !hasDwarf) {
				const errorMsg = 'No debug info available. Load a .ko or vmlinux with .BTF or .debug_info sections.';
				if (quiet) {
					return { success: false, error: errorMsg };
				}
				vscode.window.showWarningMessage(errorMsg);
				return undefined;
			}

			// If a specific function is requested, export only that function's structs
			const functionName = typeof options.functionName === 'string' ? options.functionName : undefined;
			let result: StructInfoJson;

			if (hasBtf) {
				if (functionName) {
					const scoped = getStructInfoForFunction(functionName, elfAnalysis!.btfData!);
					result = scoped ?? exportStructInfoJson(elfAnalysis!.btfData!);
				} else {
					result = exportStructInfoJson(elfAnalysis!.btfData!);
				}
			} else {
				// DWARF path — already pre-parsed into StructInfoJson
				result = elfAnalysis!.dwarfStructInfo!;
				// If function-scoped, filter it
				if (functionName && result.functions[functionName]) {
					const scoped = extractStructInfoForFunction(engine, undefined, functionName);
					if (scoped) {
						result = scoped.structInfo;
					}
				}
			}

			const jsonText = JSON.stringify(result, null, 2);

			// The pipeline injects output as { path, format }; direct callers may
			// still pass a string. Honour both forms under the same contract.
			const outputPath = resolveOptionalOutputPath(options.output as string | { path?: string } | undefined);
			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, jsonText, 'utf-8');
				if (!quiet) {
					vscode.window.showInformationMessage(
						`Struct info exported: ${Object.keys(result.structs).length} structs, ${Object.keys(result.functions).length} functions → ${outputPath}`
					);
				}
				return { success: true, path: outputPath, structCount: Object.keys(result.structs).length, functionCount: Object.keys(result.functions).length };
			}

			if (quiet) {
				return { success: true, json: result, structCount: Object.keys(result.structs).length, functionCount: Object.keys(result.functions).length };
			}

			// Open as JSON in editor
			const doc = await vscode.workspace.openTextDocument({ content: jsonText, language: 'json' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });

			vscode.window.showInformationMessage(
				`Struct info: ${Object.keys(result.structs).length} structs, ${Object.keys(result.functions).length} functions`
			);

			return { success: true, structCount: Object.keys(result.structs).length, functionCount: Object.keys(result.functions).length };
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzeAll', async (arg?: vscode.Uri | AnalyzeAllCommandOptions) => {
			const options = normalizeAnalyzeAllCommandOptions(arg);
			const targetFilePath = await resolveAnalyzeAllTargetFilePath(arg, options, engine);
			if (!targetFilePath) {
				const errorMessage = 'No binary file is selected for analysis.';
				if (options.quiet) {
					throw new Error(errorMessage);
				}
				vscode.window.showWarningMessage(errorMessage);
				return undefined;
			}

			let nativeExecution: NativeAnalyzeExecution | undefined;
			const runAnalysis = async (progress?: vscode.Progress<{ message?: string }>): Promise<number> => {
				engine.reloadConfig();
				const defaultLimits = engine.getAnalysisLimits();
				const requestedLimits = resolveAnalyzeAllLimits(options);
				const maxFunctions = requestedLimits.maxFunctions ?? defaultLimits.maxFunctions;
				const maxFunctionSize = requestedLimits.maxFunctionSize ?? defaultLimits.maxFunctionSize;
				const requestedBase = parseOptionalRawBaseAddress(options.baseAddress);
				const pipelineTimeout = Number.isFinite(options.pipelineTimeoutMs)
					? Math.max(1_000, Math.trunc(options.pipelineTimeoutMs!))
					: 600_000;
				const nativeTimeout = Math.max(1_000, pipelineTimeout - 5_000);
				const executionId = crypto.randomUUID();
				const metaRoot = options.output?.path
					? path.join(path.dirname(options.output.path), '.hexcore-meta')
					: path.join(os.tmpdir(), 'hexcore-analyze-all');
				const snapshotPath = path.join(metaRoot, `analyze-${executionId}.snapshot.bin`);
				const heartbeatPath = path.join(metaRoot, `analyze-${executionId}.heartbeat.json`);
				progress?.report({ message: `Starting isolated analysis (maxFunctions=${maxFunctions}, maxFunctionSize=${maxFunctionSize})...` });
				const isolated = await analyzeAllProcessController.run({
					filePath: targetFilePath,
					raw: { architecture: options.arch, ...(requestedBase !== undefined ? { baseAddress: requestedBase } : {}) },
					limits: { maxFunctions, maxFunctionSize },
					options: { filterJunk: options.filterJunk, detectVM: options.detectVM, detectPRNG: options.detectPRNG },
					snapshotPath,
					heartbeatPath,
					timeoutMs: nativeTimeout,
				});
				nativeExecution = isolated.nativeExecution;
				progress?.report({ message: 'Importing isolated analysis snapshot...' });
				try {
					const snapshot = v8.deserialize(zlib.gunzipSync(fs.readFileSync(isolated.snapshotPath)));
					await engine.loadAnalysisSnapshot(targetFilePath, snapshot);
				} finally {
					try { fs.unlinkSync(isolated.snapshotPath); } catch { /* heartbeat retains execution evidence */ }
				}
				return isolated.functionNetChange;
			};

			const functionNetChange = options.quiet
				? await runAnalysis()
				: await vscode.window.withProgress(
					{
						location: vscode.ProgressLocation.Notification,
						title: 'Analyzing binary...',
						cancellable: false
					},
					async progress => runAnalysis(progress)
				);

			functionProvider.refresh();
			stringRefProvider.refresh();
			sectionProvider.refresh();
			importProvider.refresh();
			exportProvider.refresh();

			const result = createAnalyzeAllResult(engine, targetFilePath, functionNetChange, options.includeInstructions === true, {
				filterJunk: options.filterJunk,
				detectVM: options.detectVM,
				detectPRNG: options.detectPRNG,
				allowLazy: options.allowLazy,
				allowDecodeEmpty: options.allowDecodeEmpty,
				minMaterializedRatio: options.minMaterializedRatio,
			});
			if (nativeExecution) { result.nativeExecution = nativeExecution; }
			if (options.output) {
				writeAnalyzeAllOutput(result, options.output);
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					`Analysis complete: ${result.newFunctions} added, ${result.removedFunctions} pruned (${result.totalFunctions} total)`
				);
			}

			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.cancelAnalyzeAll', () => ({
			cancelled: analyzeAllProcessController.cancelActive(),
		}))
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.windowsFilesystemAuditHeadless', async (arg?: WindowsFilesystemAuditCommandOptions) => {
			const options = arg ?? {};
			const requestedFile = typeof options.file === 'string' && options.file.length > 0
				? path.resolve(options.file)
				: engine.getFilePath();
			if (!requestedFile) {
				throw new Error('windowsFilesystemAuditHeadless requires a PE file or an active analyzed target.');
			}
			if (!Number.isInteger(options.maxStringSignals ?? 200) || (options.maxStringSignals ?? 200) <= 0) {
				throw new Error('maxStringSignals must be a positive integer.');
			}
			const currentFile = engine.getFilePath();
			if (!currentFile || path.resolve(currentFile).toLowerCase() !== requestedFile.toLowerCase()) {
				const loaded = await engine.loadFile(requestedFile);
				if (!loaded) { throw new Error(`Failed to load PE file: ${requestedFile}`); }
			}
			if (engine.getFunctions().length === 0) {
				await engine.analyzeAll();
			}
			if (engine.getFileInfo()?.format.startsWith('PE') !== true) {
				throw new Error('windowsFilesystemAuditHeadless is PE-only.');
			}

			let peAnalysis: any;
			try {
				peAnalysis = await vscode.commands.executeCommand('hexcore.peanalyzer.analyze', {
					file: requestedFile,
					quiet: true,
				});
			} catch (error) {
				console.warn('[HexCore] PE Analyzer context unavailable for filesystem audit:', error);
			}
			const functions = engine.getFunctions();
			const lazyFunctions = functions.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'lazy').length;
			const materializedFunctions = functions.filter(fn => engine.getFunctionBodyStatus(fn.address) === 'materialized').length;
			const persistedSession = engine.getSessionStore()?.getAnalysisSession();
			const universeManifest = engine.getSessionStore()?.getAnalysisUniverseManifest();
			const result = buildWindowsFilesystemAudit({
				principal: peAnalysis?.executionManifest,
				imports: engine.getImports(),
				functions,
				strings: engine.getStrings(),
				lazyFunctions,
				maxStringSignals: options.maxStringSignals,
				architecture: engine.getArchitecture(),
			});
			const outputBase = {
				...result,
				target: requestedFile,
				analysisContext: {
					engineGeneration: engine.getAnalysisGeneration(),
					...(persistedSession ? {
						sessionId: persistedSession.id,
						sessionGeneration: persistedSession.generation,
						...(persistedSession.parentGeneration !== undefined ? { parentGeneration: persistedSession.parentGeneration } : {}),
					} : {}),
					materializedFunctions,
					lazyFunctions,
					closureRestoration: engine.getAnalysisClosureRestoration(),
					...(universeManifest ? {
						universeSha256: universeManifest.universeSha256,
						persistedMaterializedFunctions: universeManifest.materializedFunctions.length,
					} : {}),
				},
				auditConfiguration: {
					maxStringSignals: options.maxStringSignals ?? 200,
				},
				mitigations: peAnalysis?.mitigations ?? [],
				peCapabilitySummary: peAnalysis?.windowsSecuritySummary ?? null,
				semanticWarning: result.chain
					.filter(edge => edge.status === 'blocked' || edge.status === 'missing')
					.map(edge => `${edge.kind}: ${edge.blockers[0] ?? edge.summary}`)
					.join('; '),
			};
			const output = {
				...outputBase,
				normalization: describeCanonicalArtifactIdentity(outputBase),
			};
			if (options.output?.path) {
				fs.mkdirSync(path.dirname(options.output.path), { recursive: true });
				fs.writeFileSync(options.output.path, JSON.stringify(output, null, 2), 'utf8');
			}
			return output;
		})
	);

	// ============================================================================
	// Headless Commands (Pipeline-safe, no UI prompts)
	// ============================================================================

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.disassembleAtHeadless', async (arg?: Record<string, unknown>) => {
			// 1. Parse and validate args
			const params = parseDisassembleAtAddress(arg);

			// 2. Load file if needed (reuse engine if same file)
			if (params.file) {
				const currentFile = engine.getFilePath();
				if (currentFile !== params.file) {
					const loaded = await engine.loadFile(params.file);
					if (!loaded) {
						throw new Error(`Failed to load file: ${params.file}`);
					}
					await engine.analyzeAll();
				}
			}

			// 3. Validate address is within binary range
			const testBytes = engine.getBytes(params.address, 1);
			if (!testBytes || testBytes.length === 0) {
				throw new Error(`Address 0x${params.address.toString(16).toUpperCase()} is outside the binary range.`);
			}

			// 3b. v3.7.4: IMP-001 — Verify instruction alignment
			const alignmentCheck = await engine.verifyInstructionAlignment(params.address);
			const alignmentWarning = alignmentCheck.aligned ? undefined
				: `Address 0x${params.address.toString(16).toUpperCase()} is mid-instruction. ` +
				`Nearest boundary: 0x${alignmentCheck.suggestedAddress!.toString(16).toUpperCase()}`;

			// 3c. Auto-backtrack: if address is mid-function, find the real start
			//     Uses native function boundary detection (FEAT-DISASM-004)
			let effectiveAddress = params.address;
			const autoBacktrack = (arg as any)?.autoBacktrack !== false; // enabled by default
			if (autoBacktrack) {
				const backtrack = await resolveAutoBacktrack(engine, params.address);
				if (backtrack) {
					effectiveAddress = backtrack.start;
				}
			}

			// 4. Determine max instruction size from architecture
			const arch = engine.getArchitecture();
			const maxInstructionSize = (arch === 'arm' || arch === 'arm64')
				? MAX_INSTRUCTION_SIZE_ARM
				: MAX_INSTRUCTION_SIZE_X86;

			// 5. Compute context instructions (before target address)
			const contextRecovery = await computeContextRecovery(
				engine, effectiveAddress, params.context, maxInstructionSize
			);
			const contextInstructions = contextRecovery.instructions;

			// 6. Disassemble main instructions (use effectiveAddress for backtrack).
			// Clamp the byte window before decoding so a known function end is a
			// terminal boundary, not metadata reported after a linear sweep crossed it.
			const extent = getAuthoritativeFunctionExtent(engine, effectiveAddress);
			if (params.stopAtFunctionBoundary && params.endExclusive === undefined && extent.source === 'none') {
				throw new Error('disassembleAtHeadless: stopAtFunctionBoundary requires a known function extent.');
			}
			const requestedEndExclusive = params.endExclusive ??
				(params.stopAtFunctionBoundary && extent.source !== 'none' ? extent.end : undefined);
			if (requestedEndExclusive !== undefined && requestedEndExclusive <= effectiveAddress) {
				throw new Error('disassembleAtHeadless: resolved endExclusive must be greater than the effective address.');
			}
			if (requestedEndExclusive !== undefined) {
				const lastRequestedByte = engine.getBytes(requestedEndExclusive - 1, 1);
				if (!lastRequestedByte || lastRequestedByte.length === 0) {
					throw new Error(`Requested endExclusive 0x${requestedEndExclusive.toString(16).toUpperCase()} is outside the binary range.`);
				}
			}
			const estimatedSize = params.effectiveCount * maxInstructionSize;
			const automaticFunctionEnd = extent.source !== 'none' && effectiveAddress >= extent.start && effectiveAddress < extent.end
				? extent.end
				: undefined;
			const decodeEndExclusive = requestedEndExclusive ?? automaticFunctionEnd;
			const boundedSize = decodeEndExclusive !== undefined
				? decodeEndExclusive - effectiveAddress
				: estimatedSize;
			const extentFunction = extent.source !== 'none' ? engine.getFunctionAt(extent.start) : undefined;
			if (extentFunction && extent.source !== 'pdata' && extent.end > extent.start &&
				extent.end < extentFunction.endAddress) {
				extentFunction.endAddress = extent.end;
				extentFunction.size = extent.end - extent.start;
			}
			const knownFunctionAddress = extentFunction
				? extent.start
				: undefined;
			const closureResult = knownFunctionAddress !== undefined
				? await engine.materializeFunctionForAnalysis(knownFunctionAddress)
				: undefined;
			const rawMainInstructions = await engine.disassembleRange(effectiveAddress, boundedSize, params.effectiveCount);
			const mainInstructions = rawMainInstructions
				.filter(instruction => instruction.address >= effectiveAddress &&
					(decodeEndExclusive === undefined || instruction.address + instruction.size <= decodeEndExclusive))
				.slice(0, params.effectiveCount);
			const lastMainInstruction = mainInstructions[mainInstructions.length - 1];
			const candidateNextAddress = lastMainInstruction
				? lastMainInstruction.address + lastMainInstruction.size
				: effectiveAddress;
			const nextByteAvailable = (engine.getBytes(candidateNextAddress, 1)?.length ?? 0) > 0;
			const stop = classifyDisassemblyStop({
				startAddress: effectiveAddress,
				requestedCount: params.count,
				effectiveCount: params.effectiveCount,
				returnedCount: mainInstructions.length,
				lastInstruction: lastMainInstruction,
				functionExtent: extent.source !== 'none' ? extent : undefined,
				requestedEndExclusive,
				nextByteAvailable,
			});
			const decodedEndExclusive = lastMainInstruction
				? lastMainInstruction.address + lastMainInstruction.size
				: effectiveAddress;
			const requestedByteCoverage = requestedEndExclusive !== undefined
				? assessByteRangeCompletion(
					decodedEndExclusive - effectiveAddress,
					requestedEndExclusive - effectiveAddress,
				)
				: undefined;
			const owningFunction = extent.source !== 'none' ? engine.getFunctionAt(extent.start) : undefined;
			const semanticAddresses = new Set(
				(owningFunction?.instructions ?? []).map(instruction => Number(instruction.address)),
			);
			const lastSemanticInstruction = owningFunction?.instructions.at(-1);
			const semanticEnd = lastSemanticInstruction
				? Number(lastSemanticInstruction.address) + Number(lastSemanticInstruction.size)
				: undefined;
			const instructionRole = (instruction: { address: number; mnemonic: string }, isContext: boolean) =>
				classifyDisassemblyInstructionRole({
					address: instruction.address,
					mnemonic: instruction.mnemonic,
					isContext,
					semanticAddresses,
					semanticEnd,
					boundaryEndExclusive: extent.source !== 'none' ? extent.end : undefined,
				});

			// 7. Prepare reference maps for comment resolution
			const stringsMap = engine.getStringsMap();
			const functionsMap = engine.getFunctionsMap();
			const importsArray = engine.getImports();
			const commentsMap = engine.getComments();
			// v3.8.5: PE-gate for IAT indirect-call naming in resolveInstructionComment (no-op for ELF).
			const isPE = engine.getFileInfo()?.format.startsWith('PE') === true;

			// 8. Format all instructions (context + main)
			const allEntries: DisassembleAtInstructionEntry[] = [];

			for (const instr of contextInstructions) {
				const comment = resolveInstructionComment(
					instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address, isPE
				);
				allEntries.push({
					address: `0x${instr.address.toString(16).toUpperCase()}`,
					bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
					mnemonic: instr.mnemonic,
					operands: instr.opStr,
					comment,
					size: instr.size,
					isContext: true,
					role: instructionRole(instr, true),
				});
			}

			for (const instr of mainInstructions) {
				const comment = resolveInstructionComment(
					instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address, isPE
				);
				allEntries.push({
					address: `0x${instr.address.toString(16).toUpperCase()}`,
					bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
					mnemonic: instr.mnemonic,
					operands: instr.opStr,
					comment,
					size: instr.size,
					isContext: false,
					role: instructionRole(instr, false),
				});
			}

			// 8b. v3.7: Apply junk instruction filtering if requested
			const filterJunk = arg?.filterJunk === true;
			let junkAnalysis: { junkCount: number; junkRatio: number } | undefined;
			if (filterJunk && mainInstructions.length > 0) {
				const { filtered, junkCount, junkRatio } = engine.filterJunkInstructions(mainInstructions);
				junkAnalysis = { junkCount, junkRatio };
				// Re-format filtered instructions
				const filteredEntries: DisassembleAtInstructionEntry[] = [];
				for (const instr of filtered) {
					const comment = resolveInstructionComment(
						instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address, isPE
					);
					filteredEntries.push({
						address: `0x${instr.address.toString(16).toUpperCase()}`,
						bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
						mnemonic: instr.mnemonic,
						operands: instr.opStr,
						comment,
						size: instr.size,
						isContext: false,
						role: instructionRole(instr, false),
					});
				}
				// Append filtered result (context + filtered main)
				const allFiltered = [...allEntries.filter(e => e.isContext), ...filteredEntries];
				(allEntries as any)._filtered = allFiltered;
			}

			// 8c. v3.7.1: VM detection if requested
			const detectVMFlag = arg?.detectVM === true;
			let vmDetection: { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number } | undefined;
			if (detectVMFlag) {
				vmDetection = engine.detectVM();
			}

			// 8d. v3.7.1: PRNG detection if requested
			const detectPRNGFlag = arg?.detectPRNG === true;
			let prngDetection: { prngDetected: boolean; seedSource: string | null; seedValue: number | null; randCallCount: number; callSites: Array<{ address: string; function: string; context: string }> } | undefined;
			if (detectPRNGFlag) {
				prngDetection = engine.detectPRNG();
			}
			const semanticInstructionCount = allEntries.filter(entry => entry.role === 'semantic-body').length;
			const paddingInstructionCount = allEntries.filter(entry => entry.role === 'alignment-padding').length;
			const unclassifiedInstructionCount = allEntries.filter(entry => entry.role === 'unclassified').length;
			const bodyStatus = knownFunctionAddress !== undefined
				? engine.getFunctionBodyStatus(knownFunctionAddress)
				: 'decode-empty';
			const displayOnly = !closureResult || closureResult.status === 'unknown-function' ||
				closureResult.status === 'decode-empty' || closureResult.status === 'partial';
			const closureReason = closureResult?.status === 'committed'
				? 'Function body was classified and committed to the downstream analysis universe.'
				: closureResult?.status === 'already-current'
					? 'Function body was already present in the current analysis universe.'
					: closureResult?.status === 'partial'
						? 'Function body decoded incompletely and remains retryable display-only evidence; downstream audits are unchanged.'
					: semanticInstructionCount === 0
						? 'Decoded bytes were not committed as a classified function body; downstream audits are unchanged.'
						: 'No authoritative function body was available for an analysis-context commit.';
			const coverageStatus = requestedByteCoverage?.status ?? 'ok';
			const semanticStatus = coverageStatus === 'partial' || semanticInstructionCount === 0 || displayOnly
				? 'partial' as const
				: 'ok' as const;
			const warnings = [
				requestedByteCoverage?.reason,
				semanticInstructionCount === 0 ? 'Decoded window contains zero classified semantic instructions.' : undefined,
				displayOnly ? closureReason : undefined,
			].filter((warning): warning is string => Boolean(warning));

			// 9. Build result JSON
			const result: DisassembleAtResult & { filteredInstructions?: DisassembleAtInstructionEntry[]; junkAnalysis?: { junkCount: number; junkRatio: number }; junkCount?: number; junkRatio?: number; vmDetection?: typeof vmDetection; prngDetection?: typeof prngDetection } = {
				status: semanticStatus,
				...(warnings.length > 0 ? { semanticWarning: warnings.join(' ') } : {}),
				address: `0x${params.address.toString(16).toUpperCase()}`,
				effectiveAddress: `0x${effectiveAddress.toString(16).toUpperCase()}`,
				addressMapping: engine.getAddressMapping(params.address),
				effectiveAddressMapping: engine.getAddressMapping(effectiveAddress),
				count: params.count,
				effectiveCount: params.effectiveCount,
				countingDomain: params.countingDomain,
				context: params.context,
				contextRecovery: contextRecovery.summary,
				actualCount: allEntries.length,
				returnedMainCount: mainInstructions.length,
				semanticInstructionCount,
				paddingInstructionCount,
				unclassifiedInstructionCount,
				analysisClosure: {
					status: closureResult?.status ?? 'display-only',
					...(knownFunctionAddress !== undefined ? { functionAddress: `0x${knownFunctionAddress.toString(16).toUpperCase()}` } : {}),
					bodyStatus,
					...(closureResult?.bodyCompleteness ? { bodyCompleteness: closureResult.bodyCompleteness } : {}),
					changed: closureResult?.changed === true,
					auditUniverseChanged: closureResult?.changed === true && semanticInstructionCount > 0,
					instructionsAdded: closureResult?.instructionsAdded ?? 0,
					engineGenerationBefore: closureResult?.engineGenerationBefore ?? engine.getAnalysisGeneration(),
					engineGenerationAfter: closureResult?.engineGenerationAfter ?? engine.getAnalysisGeneration(),
					...(closureResult?.sessionGenerationBefore !== undefined ? { sessionGenerationBefore: closureResult.sessionGenerationBefore } : {}),
					...(closureResult?.sessionGenerationAfter !== undefined ? { sessionGenerationAfter: closureResult.sessionGenerationAfter } : {}),
					reason: closureReason,
				},
				truncated: stop.truncated,
				...(stop.truncated && (stop.stopReason === 'count-limit' || stop.stopReason === 'decode-failure')
					? { truncationReason: stop.stopReason }
					: {}),
				stopReason: stop.stopReason,
				pageFillRatio: stop.pageFillRatio,
				requestedWindowCoverage: requestedByteCoverage?.coverage ?? (params.count > 0
					? Math.min(1, mainInstructions.length / params.count)
					: 0),
				...(requestedEndExclusive !== undefined && requestedByteCoverage !== undefined ? {
					requestedByteRange: {
						start: `0x${effectiveAddress.toString(16).toUpperCase()}`,
						endExclusive: `0x${requestedEndExclusive.toString(16).toUpperCase()}`,
						size: requestedEndExclusive - effectiveAddress,
						reached: requestedByteCoverage.reached,
						byteCoverage: requestedByteCoverage.coverage,
						source: params.endExclusive !== undefined
							? 'explicit-endExclusive' as const
							: 'function-boundary' as const,
					},
				} : {}),
				...(stop.functionBoundary ? { decodedByteCoverage: stop.functionBoundary.byteCoverage } : {}),
				...(stop.functionBoundary ? { functionBoundary: {
					start: `0x${stop.functionBoundary.start.toString(16).toUpperCase()}`,
					endExclusive: `0x${stop.functionBoundary.end.toString(16).toUpperCase()}`,
					end: `0x${stop.functionBoundary.end.toString(16).toUpperCase()}`,
					...(semanticEnd !== undefined ? {
						semanticEnd: `0x${semanticEnd.toString(16).toUpperCase()}`,
						paddingBytes: Math.max(0, stop.functionBoundary.end - semanticEnd),
					} : {}),
					size: stop.functionBoundary.size,
					source: stop.functionBoundary.source,
					reached: stop.functionBoundary.reached,
					crossed: stop.functionBoundary.crossed,
					byteCoverage: stop.functionBoundary.byteCoverage,
				} } : {}),
				maxCount: MAX_DISASSEMBLE_AT_COUNT,
				...(stop.nextAddress !== undefined ? { nextAddress: `0x${stop.nextAddress.toString(16).toUpperCase()}` } : {}),
				instructions: allEntries,
				generatedAt: new Date().toISOString(),
			};

			if (filterJunk && junkAnalysis) {
				result.filteredInstructions = (allEntries as any)._filtered;
				result.junkAnalysis = junkAnalysis;
				result.junkCount = junkAnalysis.junkCount;
				result.junkRatio = junkAnalysis.junkRatio;
			}

			if (detectVMFlag && vmDetection) {
				result.vmDetection = vmDetection;
			}

			if (detectPRNGFlag && prngDetection) {
				result.prngDetection = prngDetection;
			}

			// v3.7.4: Include alignment warning if address was mid-instruction
			if (alignmentWarning) {
				(result as any).alignmentWarning = alignmentWarning;
				(result as any).suggestedAddress = `0x${alignmentCheck.suggestedAddress!.toString(16).toUpperCase()}`;
			}

			// v3.7.4: Include ELF ET_REL warning if applicable
			const fileInfo = engine.getFileInfo();
			if (fileInfo?.isRelocatable) {
				(result as any).elfWarning = 'Target is ET_REL (relocatable). External calls are unresolved relocations.';
			}

			// 10. Write to file if output.path specified
			if (params.output?.path) {
				fs.mkdirSync(path.dirname(params.output.path), { recursive: true });
				fs.writeFileSync(params.output.path, JSON.stringify(result, null, 2), 'utf8');
			}

			// 11. Show notification unless quiet
			if (!params.quiet) {
				vscode.window.showInformationMessage(
					`Disassemble At: ${allEntries.length} instructions from 0x${params.address.toString(16).toUpperCase()}`
				);
			}

			return result;
		})
	);

	context.subscriptions.push(
		/**
		 * Issue #55 — detect packer (UPX/etc.). MIT-only, no external PATH tools.
		 * args: { file?, output?, quiet? }
		 * Does NOT unpack (no bundled UPX / no user PATH dependency).
		 */
		vscode.commands.registerCommand('hexcore.disasm.detectPacker', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : engine.getFilePath();
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as AnalyzeAllOutputOptions | undefined;

			if (!filePath || !fs.existsSync(filePath)) {
				throw new Error('detectPacker requires a readable args.file (or a loaded engine file).');
			}

			// Prefer engine tables when this file is already loaded (richer section/string signals).
			let sections: Array<{ name: string; isCode?: boolean; permissions?: string; rawAddress?: number; rawSize?: number; virtualSize?: number }> = [];
			let strings: Array<{ string?: string }> = [];
			try {
				if (engine.getFilePath() === filePath) {
					sections = engine.getSections().map(s => ({
						name: s.name, isCode: s.isCode, permissions: s.permissions,
						rawAddress: s.rawAddress, rawSize: s.rawSize, virtualSize: s.virtualSize,
					}));
					strings = engine.getStrings().map(s => ({ string: s.string }));
				}
			} catch { /* engine empty */ }

			const bytes = fs.readFileSync(filePath);
			const detect = detectPacker(bytes, { sections, strings });

			const exportData = {
				...detect,
				capabilities: packerCapabilityTags(detect),
				file: filePath,
				fileSize: bytes.length,
				// Flat fields for onResult
				ok: true,
				generatedAt: new Date().toISOString(),
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}
			if (!quietMode) {
				const msg = detect.packed
					? `Packer: ${detect.family} (conf ${detect.confidence}%) — ${detect.recommendation.slice(0, 120)}`
					: 'No packer markers detected.';
				vscode.window.showInformationMessage(msg);
			}
			return exportData;
		}),
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.searchStringHeadless', async (arg?: Record<string, unknown>) => {
			const singleQuery = typeof arg?.query === 'string' ? arg.query : undefined;
			const batchQueries = Array.isArray(arg?.queries)
				? (arg!.queries as unknown[]).filter((q): q is string => typeof q === 'string')
				: undefined;

			if (!singleQuery && (!batchQueries || batchQueries.length === 0)) {
				throw new Error('searchStringHeadless requires a "query" (string) or "queries" (string[]) argument.');
			}

			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const outputOptions = arg?.output as AnalyzeAllOutputOptions | undefined;
			const minConfidence = typeof arg?.minConfidence === 'number' && Number.isFinite(arg.minConfidence)
				? Math.max(0, Math.min(1, arg.minConfidence))
				: 0;

			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			// Batch mode: queries[] takes precedence when provided
			if (batchQueries && batchQueries.length > 0) {
				const batchResults: Array<{
					query: string;
					totalMatches: number;
					discardedLowConfidence: number;
					matches: Array<{
						address: string;
						string: string;
						encoding: string;
						references: string[];
						literalConfidence?: number;
						evidenceClass?: string;
						evidenceReasons?: string[];
					}>;
				}> = [];

				// Deduplicate queries to avoid redundant searches
				const uniqueQueries = [...new Set(batchQueries)];

				for (const q of uniqueQueries) {
					const allResults = await engine.searchStringReferences(q);
					const results = allResults.filter(result => (result.literalConfidence ?? 0) >= minConfidence);
					batchResults.push({
						query: q,
						totalMatches: results.length,
						discardedLowConfidence: allResults.length - results.length,
						matches: results.map((sr: any) => ({
							address: toHexAddress(sr.address),
							string: sr.string,
							encoding: sr.encoding,
							references: sr.references.map((addr: number) => toHexAddress(addr)),
							literalConfidence: sr.literalConfidence,
							evidenceClass: sr.evidenceClass,
							evidenceReasons: sr.evidenceReasons,
							query: q
						}))
					});
				}

				const totalMatches = batchResults.reduce((sum, r) => sum + r.totalMatches, 0);

				const exportData = {
					mode: 'batch' as const,
					queriesCount: uniqueQueries.length,
					totalMatches,
					minConfidence,
					discardedLowConfidence: batchResults.reduce((sum, result) => sum + result.discardedLowConfidence, 0),
					results: batchResults,
					generatedAt: new Date().toISOString()
				};

				if (outputOptions?.path) {
					fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
					fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
				}

				if (!quietMode) {
					vscode.window.showInformationMessage(
						`Batch string search: ${totalMatches} total matches across ${uniqueQueries.length} queries`
					);
				}

				return exportData;
			}

			// Single query mode (backward compatible)
			const allResults = await engine.searchStringReferences(singleQuery!);
			const results = allResults.filter(result => (result.literalConfidence ?? 0) >= minConfidence);

			const exportData = {
				query: singleQuery,
				totalMatches: results.length,
				minConfidence,
				discardedLowConfidence: allResults.length - results.length,
				matches: results.map((sr: any) => ({
					address: toHexAddress(sr.address),
					string: sr.string,
					encoding: sr.encoding,
					references: sr.references.map((addr: number) => toHexAddress(addr)),
					literalConfidence: sr.literalConfidence,
					evidenceClass: sr.evidenceClass,
					evidenceReasons: sr.evidenceReasons,
				})),
				generatedAt: new Date().toISOString()
			};

			if (outputOptions?.path) {
				fs.mkdirSync(path.dirname(outputOptions.path), { recursive: true });
				fs.writeFileSync(outputOptions.path, JSON.stringify(exportData, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(`String search: ${results.length} matches for "${singleQuery}"`);
			}

			return exportData;
		})
	);

	// v3.7.4: Extract strings filtered by PE section (FIX-003)
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.extractStrings', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const sections = Array.isArray(arg?.sections) ? arg.sections as string[] : undefined;
			const minLength = typeof arg?.minLength === 'number' ? arg.minLength : 4;
			const maxStrings = typeof arg?.maxStrings === 'number' ? arg.maxStrings : 10000;
			const quietMode = arg?.quiet === true;
			const rawOutput = arg?.output;
			const outputPath = typeof (rawOutput as any)?.path === 'string' ? (rawOutput as any).path : undefined;

			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
				}
			}

			// Clear existing strings and re-extract with section filter
			await engine.findStrings(sections, minLength);

			const allStrings = engine.getStrings();
			const limited = allStrings.slice(0, maxStrings);

			const result = {
				totalFound: allStrings.length,
				returned: limited.length,
				sections: sections ?? ['(all)'],
				minLength,
				strings: limited.map(s => ({
					address: `0x${s.address.toString(16)}`,
					string: s.string,
					encoding: s.encoding,
					references: s.references.map(r => `0x${r.toString(16)}`)
				})),
				generatedAt: new Date().toISOString()
			};

			if (outputPath) {
				fs.writeFileSync(outputPath, JSON.stringify(result, null, '\t'), 'utf-8');
				if (!quietMode) {
					vscode.window.showInformationMessage(`Extracted ${result.returned} strings → ${outputPath}`);
				}
			}

			return result;
		})
	);

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.exportASMHeadless', async (arg?: Record<string, unknown>) => {
			const rawOutput = arg?.output;
			const outputObject = typeof rawOutput === 'object' && rawOutput !== null
				? rawOutput as { path?: unknown }
				: undefined;
			const outputPath = typeof outputObject?.path === 'string'
				? outputObject.path
				: undefined;
			if (!outputPath) {
				throw new Error('exportASMHeadless requires an "output.path" argument.');
			}

			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const functionAddress = typeof arg?.functionAddress === 'string'
				? parseInt(arg.functionAddress.replace(/^0x/i, ''), 16)
				: undefined;

			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			fs.mkdirSync(path.dirname(outputPath), { recursive: true });
			let exportResult: AssemblyExportResult;

			if (functionAddress !== undefined && !isNaN(functionAddress)) {
				// Export single function. A-lazy: materialize so an unopened .pdata stub's body is
				// disassembled before we emit its instruction listing (this is a display/export read).
				await engine.materializeFunction(functionAddress);
				const func = engine.getFunctionAt(functionAddress);
				if (!func) {
					throw new Error(`No function found at address 0x${functionAddress.toString(16).toUpperCase()}`);
				}
				let asmContent = `; Function: ${func.name} @ 0x${func.address.toString(16).toUpperCase()}\n`;
				asmContent += `; Size: ${func.size} bytes, ${func.instructions.length} instructions\n\n`;
				for (const inst of func.instructions) {
					const hex = inst.bytes.toString('hex').toUpperCase().padEnd(16, ' ');
					const comment = inst.comment ? `  ; ${inst.comment}` : '';
					asmContent += `0x${inst.address.toString(16).toUpperCase()}  ${hex}  ${inst.mnemonic} ${inst.opStr}${comment}\n`;
				}
				fs.writeFileSync(outputPath, asmContent, 'utf8');
				const completeness = engine.getFunctionBodyCompleteness(func.address);
				const incompleteFunctions: AssemblyExportResult['incompleteFunctions'] = completeness?.state === 'partial' ? [{
					address: func.address,
					name: func.name,
					reason: 'partial-decode',
					byteCoverage: completeness.byteCoverage,
					stopReason: completeness.stopReason,
				}] : [];
				exportResult = {
					status: func.instructions.length > 0 && incompleteFunctions.length === 0 ? 'ok' : 'partial',
					totalFunctions: 1,
					functionsWithInstructions: func.instructions.length > 0 ? 1 : 0,
					functionsWithoutInstructions: func.instructions.length > 0 ? 0 : 1,
					decodedInstructions: func.instructions.length,
					emptyFunctions: func.instructions.length > 0 ? [] : [{
						address: func.address,
						name: func.name,
						reason: 'decode-empty'
					}],
					incompleteFunctions,
				};
			} else {
				// Export all functions
				exportResult = await engine.exportAssembly(outputPath);
			}

			if (!quietMode) {
				const label = functionAddress !== undefined
					? `function at 0x${functionAddress.toString(16).toUpperCase()}`
					: 'all functions';
				vscode.window.showInformationMessage(`Assembly exported (${label}) to ${outputPath}`);
			}

			return {
				outputPath,
				generatedAt: new Date().toISOString(),
				...exportResult,
				...(exportResult.status === 'partial' ? {
					semanticWarning: `${exportResult.functionsWithoutInstructions}/${exportResult.totalFunctions} function body or bodies decoded no instructions`
				} : {})
			};
		})
	);

	// =========================================================================
	// =========================================================================
	// MILESTONE 2.1 — Refcount Audit Scanner (hexcore.audit.refcountScan)
	// Automates detection of the 4 vulnerability patterns (A, B, C, E) that
	// produced all 4 bounty bugs on Mali / Qualcomm. Input: a file containing
	// decompiled C (Helix output or raw source). Output: JSON report with
	// RefcountAuditFinding[] + summary. Headless-safe.
	// =========================================================================
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.audit.refcountScan', async (arg?: Record<string, unknown>) => {
			const rawInput = typeof arg?.input === 'string'
				? arg.input
				: (typeof arg?.file === 'string' ? arg.file : undefined);
			if (!rawInput) {
				throw new Error('refcountScan requires an "input" or "file" argument pointing to decompiled C output (.c / .helix.c).');
			}
			const quietMode = arg?.quiet === true;
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as any)?.path === 'string' ? (arg!.output as any).path : undefined);

			// CWE-22 path containment + DoS size guard: this command is reachable
			// from the auto-run *.hexcore_job.json pipeline, so caller-supplied
			// input/output paths must stay inside the workspace and the input must be
			// bounded. With a workspace, the path must resolve inside a folder (blocks
			// both ".." escape and absolute escape); with none, refuse absolute.
			const MAX_AUDIT_INPUT_BYTES = 16 * 1024 * 1024;
			const assertContainedPath = (p: string, kind: 'input' | 'output'): string => {
				const resolved = path.resolve(p);
				const roots = (vscode.workspace.workspaceFolders ?? []).map(f => path.resolve(f.uri.fsPath));
				const containedPath = roots.length === 0
					? (!path.isAbsolute(p) ? resolved : undefined)
					: resolvePathWithinRoots(resolved, roots);
				if (!containedPath) {
					throw new Error(`refcountScan: ${kind} path "${p}" is outside the workspace; refusing (CWE-22 path containment).`);
				}
				return containedPath;
			};
			const safeInput = assertContainedPath(rawInput, 'input');
			const safeOutput = outputPath ? assertContainedPath(outputPath, 'output') : undefined;

			let sourceBytes: Buffer;
			try {
				const stat = fs.statSync(safeInput);
				if (stat.size > MAX_AUDIT_INPUT_BYTES) {
					throw new Error(`input is ${stat.size} bytes (cap ${MAX_AUDIT_INPUT_BYTES}); decompiled C is expected, refusing to avoid a DoS`);
				}
				sourceBytes = fs.readFileSync(safeInput);
			} catch (err: unknown) {
				const message = err instanceof Error ? err.message : String(err);
				throw new Error(`refcountScan: failed to read ${safeInput}: ${message}`);
			}

			const scan = auditRefcount(sourceBytes.toString('utf8'), safeInput);
			const inputQuality = readAuditInputQuality(safeInput, sourceBytes,
				(vscode.workspace.workspaceFolders ?? []).map(folder => folder.uri.fsPath),
				safeOutput ? path.join(path.dirname(safeOutput), '.hexcore-meta', 'inputs') : undefined);
			if (scan.scanCoverage.status !== 'ok') {
				inputQuality.status = 'partial';
				inputQuality.negativeEvidenceUsable = false;
				inputQuality.reasons.push(...scan.scanCoverage.reasons.map(reason => `scanner:${reason}`));
			}
			const report = {
				...scan, command: 'hexcore.audit.refcountScan', status: inputQuality.status,
				negativeEvidenceUsable: inputQuality.negativeEvidenceUsable, inputQuality,
				conclusion: scan.findings.length ? 'pattern-signals' : inputQuality.negativeEvidenceUsable
					? 'no-matches-in-accepted-input' : 'inconclusive',
			};

			if (safeOutput) {
				fs.mkdirSync(path.dirname(safeOutput), { recursive: true });
				fs.writeFileSync(safeOutput, JSON.stringify(report, null, 2), 'utf8');
			}

			if (!quietMode) {
				const badge = report.summary.total > 0
					? `${report.summary.total} unproven pattern signal(s)` : report.negativeEvidenceUsable
						? 'No matches in accepted input' : 'Inconclusive: input quality not accepted';
				vscode.window.showInformationMessage(
					`${badge} | ${report.observations.length} diagnostic observation(s) | ${report.functionsScanned} fn scanned | ${report.scanTimeMs}ms`,
				);
			}

			return report;
		})
	);

	// FEAT-DISASM-002 — rttiScanHeadless
	// Scans a PE binary for MSVC RTTI Type Descriptors (.?AV pattern)
	// =========================================================================
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.rttiScanHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as any)?.path === 'string' ? (arg!.output as any).path : undefined);

			// Load file into engine if a path is provided and differs from current
			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			// Read the raw file buffer — we need direct byte access for pattern scanning
			const targetPath = filePath ?? engine.getFilePath();
			if (!targetPath) {
				throw new Error('rttiScanHeadless requires a "file" argument or a previously loaded file.');
			}
			const fileBuffer = fs.readFileSync(targetPath);

			// Search for .?AV pattern (MSVC RTTI Type Descriptor decorated name)
			const marker = Buffer.from('.?AV', 'ascii');
			const classes: Array<{ className: string; offset: number; fullName: string }> = [];

			for (let i = 0; i <= fileBuffer.length - marker.length; i++) {
				if (fileBuffer[i] === marker[0] &&
					fileBuffer[i + 1] === marker[1] &&
					fileBuffer[i + 2] === marker[2] &&
					fileBuffer[i + 3] === marker[3]) {
					// Found .?AV — extract the full decorated name until @@ or null byte
					let end = i + 4;
					const maxLen = Math.min(i + 512, fileBuffer.length); // cap at 512 chars
					let foundTerminator = false;
					while (end < maxLen) {
						const byte = fileBuffer[end];
						if (byte === 0) {
							foundTerminator = true;
							break;
						}
						// Check for @@ terminator (two consecutive @)
						if (byte === 0x40 && end + 1 < maxLen && fileBuffer[end + 1] === 0x40) {
							end += 2; // include the @@
							foundTerminator = true;
							break;
						}
						// Only accept printable ASCII in class names
						if (byte < 0x20 || byte > 0x7E) {
							foundTerminator = true;
							break;
						}
						end++;
					}

					if (!foundTerminator) {
						continue;
					}

					const fullName = fileBuffer.subarray(i, end).toString('ascii');
					// Validate: must be a reasonable RTTI name (at least .?AV + one char)
					if (fullName.length < 5) {
						continue;
					}

					// Undecorate: strip .?AV prefix and @@ suffix
					let className = fullName.slice(4); // remove ".?AV"
					if (className.endsWith('@@')) {
						className = className.slice(0, -2);
					}
					// Strip any remaining trailing @ and namespace qualifiers for the short name
					// e.g., ".?AVFoo@Bar@@" -> className = "Foo@Bar", we keep it as-is
					// Only strip the final @@ which we already did

					classes.push({
						className,
						offset: i,
						fullName,
					});
				}
			}

			const result = {
				success: true as const,
				classes: classes.map(c => ({
					className: c.className,
					offset: c.offset,
					fullName: c.fullName,
				})),
				totalClasses: classes.length,
				generatedAt: new Date().toISOString(),
			};

			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`RTTI Scan: found ${classes.length} class type descriptors`
				);
			}

			return result;
		})
	);

	// =========================================================================
	// FEAT-DISASM-003 — searchBytesHeadless (AOB scan)
	// Searches for byte patterns with wildcards in the loaded binary
	// =========================================================================
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.searchBytesHeadless', async (arg?: Record<string, unknown>) => {
			const rawPattern = typeof arg?.pattern === 'string' ? arg.pattern : undefined;
			if (!rawPattern) {
				throw new Error('searchBytesHeadless requires a "pattern" argument (e.g. "48 8B ?? ?? 0F 84").');
			}
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const maxResults = typeof arg?.maxResults === 'number' && Number.isInteger(arg.maxResults) && arg.maxResults > 0
				? arg.maxResults
				: 100;
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as any)?.path === 'string' ? (arg!.output as any).path : undefined);

			// Load file into engine if a path is provided and differs from current
			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			const targetPath = filePath ?? engine.getFilePath();
			if (!targetPath) {
				throw new Error('searchBytesHeadless requires a "file" argument or a previously loaded file.');
			}
			const fileBuffer = fs.readFileSync(targetPath);

			// Parse the pattern string into bytes and mask
			// Supports: "48 8B ?? ?? 0F 84" or "488B????0F84" or mixed
			const normalizedPattern = rawPattern.trim();
			const patternBytes: Array<{ value: number; wildcard: boolean }> = [];

			if (normalizedPattern.includes(' ')) {
				// Space-separated format: "48 8B ?? ?? 0F 84"
				const tokens = normalizedPattern.split(/\s+/);
				for (const token of tokens) {
					if (token === '??' || token === '?') {
						patternBytes.push({ value: 0, wildcard: true });
					} else if (/^[0-9a-fA-F]{2}$/.test(token)) {
						patternBytes.push({ value: parseInt(token, 16), wildcard: false });
					} else {
						throw new Error(`Invalid pattern token: "${token}". Expected two hex digits or "??".`);
					}
				}
			} else {
				// Compact format: "488B????0F84"
				if (normalizedPattern.length % 2 !== 0) {
					throw new Error('Compact pattern must have an even number of characters.');
				}
				for (let i = 0; i < normalizedPattern.length; i += 2) {
					const pair = normalizedPattern.slice(i, i + 2);
					if (pair === '??' || pair === '??') {
						patternBytes.push({ value: 0, wildcard: true });
					} else if (/^[0-9a-fA-F]{2}$/.test(pair)) {
						patternBytes.push({ value: parseInt(pair, 16), wildcard: false });
					} else {
						throw new Error(`Invalid pattern pair: "${pair}". Expected two hex digits or "??".`);
					}
				}
			}

			if (patternBytes.length === 0) {
				throw new Error('Pattern must contain at least one byte.');
			}

			// Build section lookup for offset-to-VA conversion
			const sections = engine.getSections();
			const baseAddress = engine.getBaseAddress();

			const offsetToVA = (offset: number): number => {
				for (const section of sections) {
					if (offset >= section.rawAddress && offset < section.rawAddress + section.rawSize) {
						return section.virtualAddress + (offset - section.rawAddress);
					}
				}
				// Fallback: raw offset + base
				return offset + baseAddress;
			};

			// Linear scan
			const matches: Array<{ address: string; offset: number }> = [];
			const patternLen = patternBytes.length;
			const scanLimit = fileBuffer.length - patternLen;

			for (let i = 0; i <= scanLimit && matches.length < maxResults; i++) {
				let matched = true;
				for (let j = 0; j < patternLen; j++) {
					const entry = patternBytes[j];
					if (!entry.wildcard && fileBuffer[i + j] !== entry.value) {
						matched = false;
						break;
					}
				}
				if (matched) {
					const va = offsetToVA(i);
					matches.push({
						address: `0x${va.toString(16).toUpperCase()}`,
						offset: i,
					});
				}
			}

			// Normalize the pattern for display (space-separated)
			const displayPattern = patternBytes
				.map(b => b.wildcard ? '??' : b.value.toString(16).toUpperCase().padStart(2, '0'))
				.join(' ');

			const result = {
				success: true as const,
				pattern: displayPattern,
				matches,
				totalMatches: matches.length,
				generatedAt: new Date().toISOString(),
			};

			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				vscode.window.showInformationMessage(
					`AOB Scan: ${matches.length} match(es) for pattern "${displayPattern}"`
				);
			}

			return result;
		})
	);

	// =========================================================================
	// FEAT-PE-001 — analyzePEHeadless (Deep PE Analysis with Typed Imports)
	// v3.7.5: Comprehensive PE analysis with Windows API signatures,
	// category-based security summary, TLS/Debug/CLR parsing
	// =========================================================================
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzePEHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const forceReload = arg?.forceReload !== false; // default true in headless — stale cache costs more than reanalysis
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as any)?.path === 'string' ? (arg!.output as any).path : undefined);

			// FIX-102 (issue #37 Bug 1): concurrent headless jobs all shared the one
			// global DisassemblerEngine, so two pipeline jobs analyzing DIFFERENT
			// binaries at the same time stomped each other's analysis state -- e.g.
			// a 3 MB Speed.exe job reporting a 465 MB Hogwarts imageSize because the
			// concurrent Hogwarts job had loaded into the shared engine between this
			// job's load and its reads. Resolve a PER-FILE engine from the factory
			// (keyed by normalized path) so each distinct binary gets an isolated
			// engine and concurrent jobs can no longer interleave. Shadows the global
			// `engine` for this command only; falls back to the global engine when no
			// path is given (UI / generic callers).
			const engineLease = filePath ? await factory.acquireEngine(filePath) : undefined;
			const engine = engineLease?.engine ?? factory.getEngine();
			try {

			// Load file into engine if a path is provided.
			// Cache-poison guard: previous sessions in the same workspace can leave
			// the shared DisassemblerEngine with stale analysis state for a different
			// binary. Normalize paths (Windows is case-insensitive, different drive
			// letter casing / separator combinations compare unequal) AND force a
			// reload by default in headless mode so automation never silently reads
			// another binary's cached analysis.
			if (filePath) {
				const normalize = (p: string) => path.resolve(p).toLowerCase();
				const currentFile = engine.getFilePath();
				const samePath = currentFile !== undefined && normalize(currentFile) === normalize(filePath);
				if (forceReload || !samePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			const fileInfo = engine.getFileInfo();
			if (!fileInfo || (fileInfo.format !== 'PE' && fileInfo.format !== 'PE64')) {
				throw new Error('analyzePEHeadless requires a PE/PE64 binary.');
			}

			const sections = engine.getSections();
			const typedImports = engine.getTypedImports();
			const exports = engine.getExports();
			const categorySummary = engine.getImportCategorySummary();
			const dataDirectories = engine.getPEDataDirectories();

			// Count resolved vs unresolved imports
			let totalImported = 0;
			let totalResolved = 0;
			for (const lib of typedImports) {
				for (const func of lib.functions) {
					totalImported++;
					if (func.signature) { totalResolved++; }
				}
			}

			// Build typed imports output
			const importsOutput = typedImports.map(lib => ({
				dll: lib.name,
				functionCount: lib.functions.length,
				functions: lib.functions.map(func => {
					const base: Record<string, unknown> = {
						name: func.name,
						address: `0x${func.address.toString(16).toUpperCase()}`,
					};
					if (func.ordinal !== undefined) { base.ordinal = func.ordinal; }
					if (func.hint !== undefined) { base.hint = func.hint; }
					if (func.signature) {
						base.prototype = formatApiSignatureCompact(func.signature);
						base.returnType = func.signature.returnType;
						base.paramCount = func.signature.parameters.length;
						base.category = func.signature.category;
						base.tags = func.signature.tags;
					}
					return base;
				})
			}));

			// Build exports output
			const exportsOutput = exports.map(exp => {
				const base: Record<string, unknown> = {
					name: exp.name,
					ordinal: exp.ordinal,
					address: `0x${exp.address.toString(16).toUpperCase()}`,
				};
				if (exp.isForwarder) {
					base.isForwarder = true;
					base.forwarderName = exp.forwarderName;
				}
				return base;
			});

			// Build security tags summary
			const allTags = new Set<string>();
			for (const cat of categorySummary) {
				for (const tag of cat.tags) {
					allTags.add(tag);
				}
			}

			// Build data directories output
			const dataDirectoriesOutput: Record<string, unknown> = {};

			if (dataDirectories.tls) {
				const tls = dataDirectories.tls;
				dataDirectoriesOutput.tls = {
					startAddress: `0x${tls.startAddressOfRawData.toString(16).toUpperCase()}`,
					endAddress: `0x${tls.endAddressOfRawData.toString(16).toUpperCase()}`,
					indexAddress: `0x${tls.addressOfIndex.toString(16).toUpperCase()}`,
					callbacksAddress: `0x${tls.addressOfCallBacks.toString(16).toUpperCase()}`,
					callbackCount: tls.callbackAddresses.length,
					callbacks: tls.callbackAddresses.map(a => `0x${a.toString(16).toUpperCase()}`),
					warning: tls.callbackAddresses.length > 0 ? 'TLS callbacks detected — common anti-debug technique' : undefined
				};
			}

			if (dataDirectories.debug && dataDirectories.debug.length > 0) {
				dataDirectoriesOutput.debug = dataDirectories.debug.map(d => {
					const entry: Record<string, unknown> = {
						type: d.typeName,
						timestamp: d.timestamp.toISOString(),
						size: d.size
					};
					if (d.pdbPath) { entry.pdbPath = d.pdbPath; }
					if (d.pdbGuid) { entry.pdbGuid = d.pdbGuid; }
					return entry;
				});
			}

			if (dataDirectories.delayImport && dataDirectories.delayImport.length > 0) {
				dataDirectoriesOutput.delayImport = dataDirectories.delayImport.map(lib => ({
					dll: lib.name,
					functionCount: lib.functions.length,
					functions: lib.functions.map(f => f.name)
				}));
			}

			if (dataDirectories.clr) {
				const clr = dataDirectories.clr;
				dataDirectoriesOutput.clr = {
					runtimeVersion: `${clr.majorRuntimeVersion}.${clr.minorRuntimeVersion}`,
					metadataSize: clr.metadataSize,
					entryPointToken: `0x${clr.entryPointToken.toString(16).toUpperCase()}`,
					ilOnly: clr.ilOnly,
					isNative: clr.isNative,
					is32BitRequired: clr.is32BitRequired,
					warning: '.NET (managed/CIL) assembly detected — native decompile not applicable; use a .NET/IL decompiler'
				};
			}

			if (dataDirectories.resourceSize) {
				dataDirectoriesOutput.resourceSize = dataDirectories.resourceSize;
			}
			if (dataDirectories.securitySize) {
				dataDirectoriesOutput.securitySize = dataDirectories.securitySize;
				dataDirectoriesOutput.isSigned = true;
			}
			if (dataDirectories.relocSize) {
				dataDirectoriesOutput.relocSize = dataDirectories.relocSize;
			}

			const result = {
				fileInfo: {
					format: fileInfo.format,
					architecture: fileInfo.architecture,
					entryPoint: `0x${fileInfo.entryPoint.toString(16).toUpperCase()}`,
					baseAddress: `0x${fileInfo.baseAddress.toString(16).toUpperCase()}`,
					imageSize: fileInfo.imageSize,
					timestamp: fileInfo.timestamp?.toISOString(),
					subsystem: fileInfo.subsystem,
					isRelocatable: fileInfo.isRelocatable,
				},
				sections: sections.map(s => ({
					name: s.name,
					virtualAddress: `0x${s.virtualAddress.toString(16).toUpperCase()}`,
					virtualSize: s.virtualSize,
					rawSize: s.rawSize,
					permissions: s.permissions,
					isCode: s.isCode,
					isData: s.isData,
				})),
				imports: {
					totalLibraries: typedImports.length,
					totalFunctions: totalImported,
					resolvedSignatures: totalResolved,
					unresolvedCount: totalImported - totalResolved,
					libraries: importsOutput,
				},
				exports: {
					totalFunctions: exports.length,
					functions: exportsOutput,
				},
				categorySummary: categorySummary.map(cat => ({
					category: cat.category,
					label: cat.label,
					count: cat.count,
					tags: cat.tags,
					functions: cat.functions,
				})),
				securityIndicators: {
					tags: Array.from(allTags).sort(),
					hasNetworkAPIs: categorySummary.some(c => c.category === 'network'),
					hasCryptoAPIs: categorySummary.some(c => c.category === 'crypto'),
					hasInjectionAPIs: categorySummary.some(c => c.category === 'injection'),
					hasAntiDebug: allTags.has('anti_debug'),
					hasKeylogger: allTags.has('keylogger'),
					hasProcessEnum: allTags.has('enumeration'),
					hasDynamicLoading: allTags.has('dynamic_loading'),
					hasPersistence: allTags.has('persistence'),
					isSigned: !!dataDirectories.securitySize,
					isDotNet: !!dataDirectories.clr,
					hasTLSCallbacks: (dataDirectories.tls?.callbackAddresses.length ?? 0) > 0,
				},
				dataDirectories: dataDirectoriesOutput,
				generatedAt: new Date().toISOString(),
			};

			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				const resolvedPct = totalImported > 0 ? Math.round(totalResolved / totalImported * 100) : 0;
				vscode.window.showInformationMessage(
					`PE Analysis: ${typedImports.length} DLLs, ${totalImported} imports (${resolvedPct}% typed), ${exports.length} exports`
				);
			}

				return result;
			} finally {
				engineLease?.dispose();
			}
		})
	);

	// =========================================================================
	// FEAT-ELF-001 — analyzeELFHeadless (Deep ELF Analysis)
	// v3.7.5 P4: Comprehensive ELF analysis with symbols, relocations,
	// program headers, dynamic entries, and .ko module info
	// =========================================================================
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.disasm.analyzeELFHeadless', async (arg?: Record<string, unknown>) => {
			const filePath = typeof arg?.file === 'string' ? arg.file : undefined;
			const quietMode = arg?.quiet === true;
			const outputPath = typeof arg?.output === 'string'
				? arg.output
				: (typeof (arg?.output as any)?.path === 'string' ? (arg!.output as any).path : undefined);

			if (filePath) {
				const currentFile = engine.getFilePath();
				if (currentFile !== filePath) {
					const loaded = await engine.loadFile(filePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${filePath}`);
					}
					await engine.analyzeAll();
				}
			}

			const fileInfo = engine.getFileInfo();
			if (!fileInfo || (fileInfo.format !== 'ELF32' && fileInfo.format !== 'ELF64')) {
				throw new Error('analyzeELFHeadless requires an ELF binary.');
			}

			const elfData = engine.getELFAnalysis();
			if (!elfData) {
				throw new Error('ELF analysis data not available.');
			}

			// v3.8.0: Compute confidence score for ELF analysis quality
			const confidenceScore = await engine.computeELFConfidenceScore();

			const sections = engine.getSections();
			const imports = engine.getImports();
			const exports = engine.getExports();

			// Build structured output
			const symbolStats = {
				total: elfData.symbols.length,
				functions: elfData.symbols.filter(s => s.type === 'FUNC').length,
				objects: elfData.symbols.filter(s => s.type === 'OBJECT').length,
				imports: elfData.symbols.filter(s => s.isImport).length,
				exports: elfData.symbols.filter(s => s.isExport).length,
				local: elfData.symbols.filter(s => s.binding === 'LOCAL').length,
				global: elfData.symbols.filter(s => s.binding === 'GLOBAL').length,
				weak: elfData.symbols.filter(s => s.binding === 'WEAK').length,
			};

			const result = {
				fileInfo: {
					format: fileInfo.format,
					architecture: fileInfo.architecture,
					entryPoint: `0x${fileInfo.entryPoint.toString(16).toUpperCase()}`,
					baseAddress: `0x${fileInfo.baseAddress.toString(16).toUpperCase()}`,
					imageSize: fileInfo.imageSize,
					elfType: elfData.elfType,
					isRelocatable: fileInfo.isRelocatable,
					interpreter: elfData.interpreter,
					soname: elfData.soname,
				},
				sections: sections.map(s => ({
					name: s.name,
					virtualAddress: `0x${s.virtualAddress.toString(16).toUpperCase()}`,
					virtualSize: s.virtualSize,
					rawSize: s.rawSize,
					permissions: s.permissions,
					isCode: s.isCode,
					isData: s.isData,
				})),
				programHeaders: elfData.programHeaders.map(ph => ({
					type: ph.typeName,
					permissions: ph.permissions,
					offset: `0x${ph.offset.toString(16)}`,
					vaddr: `0x${ph.vaddr.toString(16).toUpperCase()}`,
					filesz: ph.filesz,
					memsz: ph.memsz,
					align: ph.align,
					...(ph.interpreter ? { interpreter: ph.interpreter } : {}),
				})),
				symbolStats,
				symbols: elfData.symbols.map(s => ({
					name: s.name,
					value: `0x${s.value.toString(16).toUpperCase()}`,
					size: s.size,
					binding: s.binding,
					type: s.type,
					visibility: s.visibility,
					section: s.sectionName,
					isImport: s.isImport,
					isExport: s.isExport,
				})),
				relocations: {
					total: elfData.relocations.length,
					bySectionCount: (() => {
						const map = new Map<string, number>();
						for (const r of elfData.relocations) {
							map.set(r.sectionName, (map.get(r.sectionName) || 0) + 1);
						}
						return Object.fromEntries(map);
					})(),
					entries: elfData.relocations.slice(0, 5000).map(r => ({
						offset: `0x${r.offset.toString(16).toUpperCase()}`,
						type: r.typeName,
						symbol: r.symbolName,
						addend: r.addend,
						section: r.sectionName,
					})),
					truncated: elfData.relocations.length > 5000,
				},
				dynamicEntries: elfData.dynamicEntries.map(d => ({
					tag: d.tagName,
					value: `0x${d.value.toString(16).toUpperCase()}`,
					...(d.stringValue ? { string: d.stringValue } : {}),
				})),
				neededLibraries: elfData.neededLibraries,
				...(elfData.moduleInfo ? {
					moduleInfo: {
						name: elfData.moduleInfo.name,
						version: elfData.moduleInfo.version,
						description: elfData.moduleInfo.description,
						author: elfData.moduleInfo.author,
						license: elfData.moduleInfo.license,
						vermagic: elfData.moduleInfo.vermagic,
						srcversion: elfData.moduleInfo.srcversion,
						depends: elfData.moduleInfo.depends,
						intree: elfData.moduleInfo.intree,
						retpoline: elfData.moduleInfo.retpoline,
						parameters: elfData.moduleInfo.parmDescriptions,
					}
				} : {}),
				...(confidenceScore ? {
					confidenceScore: {
						overall: confidenceScore.overall,
						symbolResolution: confidenceScore.symbolResolution,
						cfgComplexity: confidenceScore.cfgComplexity,
						patternRecognition: confidenceScore.patternRecognition,
						externalCallCoverage: confidenceScore.externalCallCoverage,
						symtabCompleteness: confidenceScore.symtabCompleteness,
						detectedPatterns: confidenceScore.detectedPatterns,
					}
				} : {}),
				// v3.8.2: surface parsed BTF type data. The parser (elfBtfLoader) is
				// real and is populated by ensureDebugInfoLoaded() (called above via
				// computeELFConfidenceScore) when a .BTF section is present. Previously
				// dropped from the result even though docs promise the btfData field
				// (same serializer-drop archetype as the analyzeAll vm/prng/junk bug).
				// The internal shape uses Maps; serialize types to a plain array.
				...(elfData.btfData ? {
					btfData: {
						version: elfData.btfData.version,
						typeCount: elfData.btfData.typeCount,
						hasBTF: true,
						types: Array.from(elfData.btfData.types.values()).slice(0, 5000),
						strings: elfData.btfData.strings.slice(0, 5000),
					}
				} : {}),
				generatedAt: new Date().toISOString(),
			};

			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
			}

			if (!quietMode) {
				const modLabel = elfData.moduleInfo?.name ? ` (module: ${elfData.moduleInfo.name})` : '';
				vscode.window.showInformationMessage(
					`ELF Analysis: ${elfData.elfType}, ${symbolStats.total} symbols, ${elfData.relocations.length} relocs, ${elfData.neededLibraries.length} libs${modLabel}`
				);
			}

			return result;
		})
	);

	console.log('HexCore Disassembler extension activated');
}

/**
 * v3.8.0: Section-aware lifting for ELF kernel modules.
 * Lifts all executable sections (.text, .init.text, .exit.text, etc.) separately
 * and returns structured output with per-section function groups.
 */
interface LiftAllExecutableSectionsOptions {
	engine: DisassemblerEngine;
	remillWrapper: RemillWrapper;
	quiet: boolean;
	options: Record<string, unknown>;
	mapping: { remillArch: string; supported: boolean };
}

interface LiftedSection {
	name: string;
	purpose: ELFExecutableSection['purpose'];
	functions: Array<{
		address: string;
		size: number;
		ir: string;
		bytesConsumed: number;
	}>;
	functionCount: number;
	bytesConsumed: number;
}

async function liftAllExecutableSections(
	params: LiftAllExecutableSectionsOptions
): Promise<unknown> {
	const { engine, remillWrapper, quiet, options, mapping } = params;

	const fileInfo = engine.getFileInfo();
	const elfData = engine.getELFAnalysis();

	// FIX BUG#2: Support PE binaries by enumerating executable sections from the engine.
	// elfData?.executableSections only exists for ELF. For PE, use engine.getSections()
	// and filter by isExecutable flag.
	let execSections = elfData?.executableSections;

	if (!execSections || execSections.length === 0) {
		// Fallback: try generic section enumeration (works for PE and any format)
		const allSections = engine.getSections();
		const exeSections = allSections.filter(s => s.isExecutable && s.rawSize > 0);

		if (exeSections.length > 0) {
			// Convert generic Section → ELFExecutableSection-compatible shape
			execSections = exeSections.map(s => ({
				name: s.name,
				offset: s.rawAddress,
				size: s.rawSize,
				virtualAddress: s.virtualAddress,
				purpose: s.name === '.text' ? 'runtime' as const
					: s.name === '.init' ? 'module_init' as const
					: 'runtime' as const,
				permissions: s.permissions,
				flags: s.characteristics,
			}));
			console.log(`[HexCore] allExecutableSections: PE/generic fallback found ${execSections.length} executable sections: ${execSections.map(s => s.name).join(', ')}`);
		} else {
			const format = fileInfo?.format ?? 'unknown';
			const errorMsg = `No executable sections found in ${format} binary. Sections: ${allSections.map(s => s.name).join(', ')}`;
			console.error(`[HexCore] allExecutableSections: ${errorMsg}`);
			return {
				success: false,
				ir: '',
				address: 0,
				bytesConsumed: 0,
				architecture: mapping.remillArch,
				error: errorMsg,
				sections: []
			};
		}
	}

	// Get all relocations for per-section filtering
	const allRelocations = engine.getTextRelocations();
	const isRelocatable = fileInfo?.isRelocatable === true;

	const liftedSections: LiftedSection[] = [];
	const allFunctions: Array<{
		address: string;
		size: number;
		ir: string;
		bytesConsumed: number;
		sectionName: string;
		purpose: string;
	}> = [];

	console.log(`[HexCore] Section-aware lifting: ${execSections.length} executable sections found`);

	// Process each executable section
	for (const execSec of execSections) {
		// Skip trampoline sections for now (PLT handling is different)
		if (execSec.purpose === 'trampoline') {
			console.log(`[HexCore] Skipping trampoline section: ${execSec.name}`);
			continue;
		}

		console.log(`[HexCore] Lifting section: ${execSec.name} (purpose: ${execSec.purpose}, offset: 0x${execSec.offset.toString(16)}, size: ${execSec.size})`);

		// Extract bytes for this section
		// For ET_REL, virtualAddress is 0; use baseAddress + offset to create a valid VA.
		// For PE, virtualAddress is an RVA — must add the image base.
		// For non-relocatable ELF, virtualAddress is already absolute.
		let sectionStartAddress: number;
		if (isRelocatable) {
			sectionStartAddress = engine.getBaseAddress() + execSec.offset;
		} else {
			const va = execSec.virtualAddress || execSec.offset;
			// If VA looks like an RVA (small value, PE typically has base > 0x10000),
			// add the image base address
			const base = engine.getBaseAddress();
			sectionStartAddress = (va < base && base > 0x10000) ? base + va : va;
		}
		const sectionBytes = engine.getBytes(sectionStartAddress, execSec.size);
		if (!sectionBytes || sectionBytes.length === 0) {
			console.warn(`[HexCore] Could not extract bytes for section: ${execSec.name}`);
			continue;
		}

		// Get section-specific relocations
		// Relocation section naming convention: .rela.<section_name>
		const sectionRelocs = new Map<number, { name: string; type: number; addend: number }>();
		if (isRelocatable && allRelocations.size > 0) {
			// Find the relocation section for this executable section
			const relaSectionName = `.rela${execSec.name}`;
			const relSectionName = `.rel${execSec.name}`;

			// textRelocations uses global file offsets (relative to .text start);
			// convert to per-section offsets
			const sectionFileStart = execSec.offset;
			const sectionFileEnd = execSec.offset + execSec.size;
			const mainText = engine.getSections().find(s => s.name === '.text');
			const textFileStart = mainText?.rawAddress ?? 0;

			for (const [globalOffset, reloc] of allRelocations) {
				// globalOffset is (targetSec.offset - textFileStart) + rOffset
				// Convert to actual file offset by adding textFileStart
				const actualFileOffset = globalOffset + textFileStart;
				if (actualFileOffset >= sectionFileStart && actualFileOffset < sectionFileEnd) {
					const sectionRelativeOffset = actualFileOffset - sectionFileStart;
					sectionRelocs.set(sectionRelativeOffset, reloc);
				}
			}

			console.log(`[HexCore] Section ${execSec.name}: ${sectionRelocs.size} relocations`);
		}

		// Apply relocations if present
		let bytesToLift = sectionBytes;
		let symbolMap: Map<number, string> | undefined;

		if (isRelocatable && sectionRelocs.size > 0) {
			const patchedBytes = Buffer.from(sectionBytes);
			symbolMap = new Map();
			let fakeAddr = 0x7FFF0000;
			const symbolAddrs = new Map<string, number>();

			// Kernel infrastructure symbols to skip
			const infraSymbols = new Set([
				'__fentry__', '__cfi_check', // FIX-098: __x86_return_thunk removed -> patch it so native FIX-019 emits RET (retbleed `jmp __x86_return_thunk` == ret)
				'__x86_indirect_thunk_rax', '__x86_indirect_thunk_rbx',
				'__x86_indirect_thunk_rcx', '__x86_indirect_thunk_rdx',
				'__x86_indirect_thunk_rsi', '__x86_indirect_thunk_rdi',
				'__x86_indirect_thunk_rbp', '__x86_indirect_thunk_r8',
				'__x86_indirect_thunk_r9', '__x86_indirect_thunk_r10',
				'__x86_indirect_thunk_r11', '__x86_indirect_thunk_r12',
				'__x86_indirect_thunk_r13', '__x86_indirect_thunk_r14',
				'__x86_indirect_thunk_r15',
			]);

			for (const [secOffset, reloc] of sectionRelocs) {
				if (infraSymbols.has(reloc.name)) {
					continue;
				}
				if (reloc.type !== 2 && reloc.type !== 4) {
					continue;
				}

				let targetAddr = symbolAddrs.get(reloc.name);
				if (targetAddr === undefined) {
					targetAddr = fakeAddr;
					fakeAddr += 0x10;
					symbolAddrs.set(reloc.name, targetAddr);
				}

				// Patch the displacement at the relocation offset
				if (secOffset + 4 <= patchedBytes.length) {
					const relocVA = (execSec.virtualAddress || execSec.offset) + secOffset;
					const displacement = (targetAddr + reloc.addend - relocVA) | 0;
					patchedBytes.writeInt32LE(displacement, secOffset);

					const resolvedTarget = ((relocVA + 4) + displacement) >>> 0;
					if (!symbolMap.has(resolvedTarget)) {
						symbolMap.set(resolvedTarget, reloc.name);
					}
				}
			}

			bytesToLift = patchedBytes;
		}

		// Skip CET/ftrace preamble
		const skipBytes = planLiftPreamble(
			bytesToLift,
			execSec.virtualAddress || execSec.offset,
			true,
		).skipBytes;

		if (skipBytes > 0) {
			bytesToLift = bytesToLift.subarray(skipBytes);
		}

		// Build lift options
		const liftOpts: RemillLiftOptions = {
			liftMode: 'elf_relocatable'
		};

		// Add function leaders from symbols in this section
		const sectionFuncs = engine.getFunctions().filter(fn => {
			const fnOffset = engine['addressToOffset'](fn.address);
			return fnOffset >= execSec.offset && fnOffset < execSec.offset + execSec.size;
		});

		if (sectionFuncs.length > 0) {
			liftOpts.additionalLeaders = sectionFuncs.map(fn => fn.address);
		}

		// Set external symbols for this section
		if (symbolMap && symbolMap.size > 0) {
			remillWrapper.setExternalSymbols(symbolMap);
		}

		// Perform the lift
		const liftResult = await remillWrapper.liftBytes(
			bytesToLift,
			(execSec.virtualAddress || execSec.offset) + skipBytes,
			engine.getArchitecture() as 'x86' | 'x64' | 'arm64',
			'linux',
			liftOpts
		);

		// Clear external symbols after lift
		if (symbolMap && symbolMap.size > 0) {
			remillWrapper.clearExternalSymbols();
		}

		if (!liftResult.success) {
			console.warn(`[HexCore] Failed to lift section ${execSec.name}: ${liftResult.error}`);
			continue;
		}

		// FIX BUG#3: Detect HandleUnsupported in IR and report diagnostic info.
		// When Remill can't lift an instruction, it generates a HandleUnsupported call
		// and stops. We detect this, Capstone-decode the failing bytes for diagnostics,
		// and report the unsupported instruction(s) to the user.
		const handleUnsupportedCount = (liftResult.ir.match(/HandleUnsupported/g) || []).length;
		if (handleUnsupportedCount > 0) {
			const isARM = engine.getArchitecture() === 'arm64' || engine.getArchitecture() === 'arm';
			const instrSize = isARM ? 4 : 1; // ARM64 is fixed-width 4 bytes
			const liftAddr = (execSec.virtualAddress || execSec.offset) + skipBytes;

			// Try to Capstone-decode the failing instruction for diagnostic
			const failBytes = bytesToLift.subarray(0, Math.min(16, bytesToLift.length));
			const failHex = Array.from(failBytes.subarray(0, instrSize)).map(b => b.toString(16).padStart(2, '0')).join(' ');

			console.warn(`[HexCore] Section ${execSec.name}: ${handleUnsupportedCount} HandleUnsupported call(s) in IR. ` +
				`First unsupported bytes at 0x${liftAddr.toString(16)}: [${failHex}] ` +
				`(${liftResult.bytesConsumed}/${bytesToLift.length} bytes consumed, ` +
				`${((liftResult.bytesConsumed / bytesToLift.length) * 100).toFixed(1)}% coverage)`);

			// If coverage is very low (<5%) and ARM64, warn about ISA support
			if (liftResult.bytesConsumed < bytesToLift.length * 0.05 && isARM) {
				console.warn(`[HexCore] ARM64 coverage <5%. Remill may not support this ISA extension. ` +
					`Bytes at entry: [${Array.from(failBytes).map(b => b.toString(16).padStart(2, '0')).join(' ')}]. ` +
					`Consider reporting to Remill upstream with the instruction encoding.`);
			}
		}

		// Post-process IR to inject external symbol declarations
		let processedIR = liftResult.ir;
		if (symbolMap && symbolMap.size > 0) {
			const declares = new Set<string>();
			for (const [addr, name] of symbolMap) {
				const addrHex = addr.toString(16);
				const declare = `declare void @${name}(...) ; external symbol`;
				declares.add(declare);

				// Replace fake address references with symbol name
				const fakeAddrPattern = new RegExp(`@sub_${addrHex}\\b`, 'g');
				processedIR = processedIR.replace(fakeAddrPattern, `@${name}`);
			}

			if (declares.size > 0) {
				const declareBlock = '\n; --- External symbols for ' + execSec.name + ' ---\n' +
					Array.from(declares).join('\n') + '\n';
				processedIR = declareBlock + processedIR;
			}
		}

		// Build section result
		const sectionFunction = {
			address: `0x${(execSec.virtualAddress || execSec.offset).toString(16).toUpperCase()}`,
			size: bytesToLift.length,
			ir: processedIR,
			bytesConsumed: liftResult.bytesConsumed
		};

		liftedSections.push({
			name: execSec.name,
			purpose: execSec.purpose,
			functions: [sectionFunction],
			functionCount: 1,
			bytesConsumed: liftResult.bytesConsumed
		});

		allFunctions.push({
			...sectionFunction,
			sectionName: execSec.name,
			purpose: execSec.purpose
		});

		console.log(`[HexCore] Section ${execSec.name}: lifted ${liftResult.bytesConsumed} bytes`);
	}

	// Build combined IR with section markers
	const fileName = engine.getFilePath() ? path.basename(engine.getFilePath()!) : 'unknown';
	const header = buildIRHeader({
		fileName,
		address: 0,
		size: 0,
		architecture: mapping.remillArch,
		functionName: 'section_aware_lift',
	});

	let combinedIR = header;
	for (const section of liftedSections) {
		combinedIR += `\n; === Section: ${section.name} (purpose: ${section.purpose}) ===\n`;
		combinedIR += section.functions[0]?.ir || '';
	}

	// Handle output file if specified
	if (options.output) {
		const outputPath = typeof options.output === 'string'
			? options.output
			: (options.output as { path: string }).path;

		const result = {
			success: true,
			ir: combinedIR,
			architecture: mapping.remillArch,
			sections: liftedSections.map(s => ({
				name: s.name,
				purpose: s.purpose,
				functions: s.functions,
				functionCount: s.functionCount
			})),
			functions: allFunctions,
			totalSections: liftedSections.length,
			totalFunctions: allFunctions.length,
			generatedAt: new Date().toISOString()
		};

		// FIX BUG#1: Write raw IR for .ll files, JSON envelope for everything else.
		// .ll files must be valid LLVM IR text consumable by llvm-dis, llvm-as, opt.
		const isRawIR = outputPath.endsWith('.ll') || outputPath.endsWith('.bc');
		if (isRawIR) {
			fs.writeFileSync(outputPath, combinedIR, 'utf-8');
			console.log(`[HexCore] allExecutableSections: wrote raw IR to ${outputPath} (${combinedIR.length} bytes)`);
		} else {
			fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf-8');
		}
		return result;
	}

	// Return structured result
	return {
		success: true,
		ir: combinedIR,
		architecture: mapping.remillArch,
		sections: liftedSections.map(s => ({
			name: s.name,
			purpose: s.purpose,
			functions: s.functions,
			functionCount: s.functionCount
		})),
		functions: allFunctions,
		totalSections: liftedSections.length,
		totalFunctions: allFunctions.length,
		generatedAt: new Date().toISOString()
	};
}

export function deactivate(): void {
	DisassemblerFactory.getInstance().disposeAll();
}

interface EmulatorChoice {
	readonly label: string;
	readonly description: string;
	readonly detail: string;
	readonly value: 'azoth' | 'debugger' | 'both';
}

const EMULATOR_CHOICES: readonly EmulatorChoice[] = [
	{
		label: '$(debug-alt) Both (Azoth + Debugger)',
		description: 'recommended — all pipeline steps run',
		detail: 'Activate both Azoth and the legacy TypeScript debugger side-by-side. Each uses its own native module.',
		value: 'both'
	},
	{
		label: '$(rocket) Azoth only',
		description: 'clean-room C++/Rust emulator',
		detail: 'Project Azoth. Faster activation, lower memory. hexcore.debug.* pipeline steps are skipped.',
		value: 'azoth'
	},
	{
		label: '$(bug) Legacy Debugger only',
		description: 'TypeScript debugger — regression comparison',
		detail: 'Legacy hexcore-debugger. hexcore.elixir.* pipeline steps are skipped.',
		value: 'debugger'
	}
];

function readCurrentEmulator(): 'azoth' | 'debugger' | 'both' {
	const raw = vscode.workspace.getConfiguration('hexcore').get<string>('emulator', 'both');
	return raw === 'azoth' || raw === 'debugger' || raw === 'both' ? raw : 'both';
}

function emulatorStatusBarLabel(value: 'azoth' | 'debugger' | 'both'): string {
	switch (value) {
		case 'both': return '$(debug-alt) Emulator: Both';
		case 'azoth': return '$(rocket) Emulator: Azoth';
		case 'debugger': return '$(bug) Emulator: Debugger';
	}
}

function setupEmulatorSwitcher(context: vscode.ExtensionContext): void {
	const statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 95);
	statusBarItem.command = 'hexcore.emulator.switch';
	statusBarItem.tooltip = 'Click to switch HexCore emulator (Azoth / Debugger / Both). Requires window reload.';

	const refreshStatusBar = (): void => {
		const current = readCurrentEmulator();
		statusBarItem.text = emulatorStatusBarLabel(current);
		statusBarItem.show();
	};
	refreshStatusBar();

	context.subscriptions.push(
		statusBarItem,
		vscode.workspace.onDidChangeConfiguration((e) => {
			if (e.affectsConfiguration('hexcore.emulator')) {
				refreshStatusBar();
			}
		}),
		vscode.commands.registerCommand('hexcore.emulator.switch', async () => {
			const current = readCurrentEmulator();
			const picks = EMULATOR_CHOICES.map(c => ({
				...c,
				label: c.value === current ? `${c.label}  $(check)` : c.label
			}));
			const pick = await vscode.window.showQuickPick(picks, {
				title: 'HexCore — Switch Emulator',
				placeHolder: `Current: ${current}. Pick an emulator to activate (reload required).`,
				matchOnDescription: true,
				matchOnDetail: true
			});
			if (!pick || pick.value === current) { return; }

			// Prefer workspace-level setting when a workspace is open so
			// the choice travels with the project; fall back to user-global.
			const target = vscode.workspace.workspaceFolders && vscode.workspace.workspaceFolders.length > 0
				? vscode.ConfigurationTarget.Workspace
				: vscode.ConfigurationTarget.Global;
			try {
				await vscode.workspace.getConfiguration('hexcore').update('emulator', pick.value, target);
			} catch (err: unknown) {
				const msg = err instanceof Error ? err.message : String(err);
				vscode.window.showErrorMessage(vscode.l10n.t('Failed to update hexcore.emulator: {0}', msg));
				return;
			}

			const choice = await vscode.window.showInformationMessage(
				vscode.l10n.t('Emulator set to "{0}". Reload the window to apply.', pick.value),
				vscode.l10n.t('Reload Window'),
				vscode.l10n.t('Later')
			);
			if (choice === vscode.l10n.t('Reload Window')) {
				vscode.commands.executeCommand('workbench.action.reloadWindow');
			}
		})
	);
}

function normalizeAnalyzeAllCommandOptions(arg?: vscode.Uri | AnalyzeAllCommandOptions): AnalyzeAllCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}

	const raw = arg as AnalyzeAllCommandOptions;
	const normalized: AnalyzeAllCommandOptions = {};

	if (typeof raw.file === 'string') {
		normalized.file = raw.file;
	}
	if (raw.output) {
		normalized.output = raw.output;
	}
	if (typeof raw.quiet === 'boolean') {
		normalized.quiet = raw.quiet;
	}
	if (raw.maxFunctions !== undefined) {
		normalized.maxFunctions = parsePositiveIntegerOption(raw.maxFunctions, 'maxFunctions');
	}
	if (raw.maxFunctionSize !== undefined) {
		normalized.maxFunctionSize = parsePositiveIntegerOption(raw.maxFunctionSize, 'maxFunctionSize');
	}
	if (raw.forceReload !== undefined) {
		if (typeof raw.forceReload !== 'boolean') {
			throw new Error('Invalid "forceReload" option: expected boolean.');
		}
		normalized.forceReload = raw.forceReload;
	}
	if (raw.includeInstructions !== undefined) {
		normalized.includeInstructions = raw.includeInstructions === true;
	}
	if (raw.arch !== undefined) {
		if (!['x86', 'x64', 'arm', 'arm64', 'mips', 'mips64'].includes(raw.arch)) {
			throw new Error(`Invalid "arch" option: ${String(raw.arch)}`);
		}
		normalized.arch = raw.arch;
	}
	if (raw.baseAddress !== undefined) {
		parseOptionalRawBaseAddress(raw.baseAddress);
		normalized.baseAddress = raw.baseAddress;
	}
	if (raw.pipelineTimeoutMs !== undefined) {
		if (!Number.isFinite(raw.pipelineTimeoutMs) || raw.pipelineTimeoutMs <= 0) {
			throw new Error('Invalid "pipelineTimeoutMs" option: expected a positive finite number.');
		}
		normalized.pipelineTimeoutMs = Math.trunc(raw.pipelineTimeoutMs);
	}

	// v3.7 options
	if (raw.filterJunk === true) { normalized.filterJunk = true; }
	if (raw.detectVM === true) { normalized.detectVM = true; }
	if (raw.detectPRNG === true) { normalized.detectPRNG = true; }
	Object.assign(
		normalized,
		normalizeFunctionMaterializationPolicy(raw as unknown as Record<string, unknown>),
	);

	return normalized;
}

function parseOptionalRawBaseAddress(value: string | number | undefined): number | undefined {
	if (value === undefined) { return undefined; }
	const parsed = typeof value === 'number'
		? value
		: /^0x[\da-f]+$/i.test(value.trim())
			? Number.parseInt(value.trim().slice(2), 16)
			: Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 0) {
		throw new Error('Invalid "baseAddress" option: expected a non-negative safe integer or 0x-prefixed address.');
	}
	return parsed;
}

async function resolveAnalyzeAllTargetFilePath(
	arg: vscode.Uri | AnalyzeAllCommandOptions | undefined,
	options: AnalyzeAllCommandOptions,
	engine: DisassemblerEngine
): Promise<string | undefined> {
	if (arg instanceof vscode.Uri && arg.scheme === 'file') {
		return arg.fsPath;
	}

	if (typeof options.file === 'string' && options.file.length > 0) {
		return path.resolve(options.file);
	}

	const activeFilePath = getActiveFilePath();
	if (activeFilePath) {
		return activeFilePath;
	}

	const loadedFilePath = engine.getFilePath();
	if (loadedFilePath) {
		return loadedFilePath;
	}

	if (options.quiet) {
		return undefined;
	}

	const uris = await vscode.window.showOpenDialog({
		canSelectMany: false,
		openLabel: 'Analyze',
		filters: {
			'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
			'All Files': ['*']
		}
	});
	return uris?.[0]?.fsPath;
}

function getActiveFilePath(): string | undefined {
	const uri = vscode.window.activeTextEditor?.document.uri;
	if (!uri || uri.scheme !== 'file') {
		return undefined;
	}
	return uri.fsPath;
}

function shouldForceReloadAnalyzeAll(options: AnalyzeAllCommandOptions): boolean {
	if (typeof options.forceReload === 'boolean') {
		return options.forceReload;
	}
	return options.quiet === true;
}

function resolveAnalyzeAllLimits(options: AnalyzeAllCommandOptions): { maxFunctions?: number; maxFunctionSize?: number } {
	return {
		maxFunctions: options.maxFunctions,
		maxFunctionSize: options.maxFunctionSize
	};
}

function parsePositiveIntegerOption(value: number, optionName: string): number {
	if (typeof value !== 'number' || !Number.isFinite(value)) {
		throw new Error(`Invalid "${optionName}" option: expected finite number.`);
	}
	const normalized = Math.floor(value);
	if (normalized < 1) {
		throw new Error(`Invalid "${optionName}" option: expected value >= 1.`);
	}
	return normalized;
}

function normalizeBuildFormulaCommandOptions(arg?: BuildFormulaCommandOptions): BuildFormulaCommandOptions {
	if (arg === undefined) {
		return {};
	}

	const normalized: BuildFormulaCommandOptions = {
		file: arg.file,
		targetRegister: typeof arg.targetRegister === 'string' ? arg.targetRegister : undefined,
		output: arg.output,
		quiet: arg.quiet === true
	};

	if (arg.startAddress !== undefined) {
		normalized.startAddress = arg.startAddress;
	}
	if (arg.endAddress !== undefined) {
		normalized.endAddress = arg.endAddress;
	}
	if (Array.isArray(arg.addresses)) {
		normalized.addresses = [...arg.addresses];
	}

	return normalized;
}

function normalizeCheckConstantsCommandOptions(arg?: CheckConstantsCommandOptions): CheckConstantsCommandOptions {
	if (arg === undefined) {
		return {};
	}

	const normalized: CheckConstantsCommandOptions = {
		file: arg.file,
		notesFile: arg.notesFile,
		output: arg.output,
		quiet: arg.quiet === true
	};

	if (arg.maxFindings !== undefined) {
		normalized.maxFindings = parsePositiveIntegerOption(arg.maxFindings, 'maxFindings');
	}

	return normalized;
}

function normalizeValidateJobCommandOptions(arg?: vscode.Uri | string | ValidateJobCommandOptions): ValidateJobCommandOptions {
	if (arg === undefined) {
		return {};
	}
	if (arg instanceof vscode.Uri) {
		return { jobFile: arg.fsPath };
	}
	if (typeof arg === 'string') {
		return { jobFile: arg };
	}
	return arg;
}

function normalizeValidateWorkspaceCommandOptions(arg?: ValidateWorkspaceCommandOptions): ValidateWorkspaceCommandOptions {
	if (arg === undefined) {
		return {};
	}
	return arg;
}

function normalizeRunJobCommandOptions(arg?: vscode.Uri | string | RunJobCommandOptions): RunJobCommandOptions {
	if (arg === undefined) {
		return {};
	}
	if (arg instanceof vscode.Uri) {
		return { jobFile: arg.fsPath };
	}
	if (typeof arg === 'string') {
		return { jobFile: arg };
	}
	return arg;
}

function normalizeCreatePresetJobCommandOptions(arg?: CreatePresetJobCommandOptions): CreatePresetJobCommandOptions {
	if (arg === undefined) {
		return {};
	}
	return arg;
}

function normalizeSaveJobAsProfileCommandOptions(arg?: SaveJobAsProfileCommandOptions): SaveJobAsProfileCommandOptions {
	if (arg === undefined) {
		return {};
	}
	return arg;
}

function resolvePipelinePreset(presets: PipelinePreset[], hint?: string): PipelinePreset | undefined {
	if (!hint) {
		return undefined;
	}
	const normalizedHint = hint.trim().toLowerCase();
	return presets.find(preset =>
		preset.id.toLowerCase() === normalizedHint ||
		preset.name.toLowerCase() === normalizedHint
	);
}

async function resolvePresetTargetFilePath(
	options: CreatePresetJobCommandOptions,
	quiet: boolean,
	workspaceRoot: string
): Promise<string | undefined> {
	if (typeof options.file === 'string' && options.file.length > 0) {
		return resolveRelativeOrAbsolutePath(workspaceRoot, options.file);
	}

	const activeFilePath = getActiveFilePath();
	if (activeFilePath) {
		return activeFilePath;
	}

	if (quiet) {
		return undefined;
	}

	const uris = await vscode.window.showOpenDialog({
		canSelectMany: false,
		openLabel: 'Select Target Binary for Preset Job',
		filters: {
			'Executables': ['exe', 'dll', 'elf', 'so', 'bin'],
			'All Files': ['*']
		}
	});

	return uris?.[0]?.fsPath;
}

function resolvePresetOutDirPath(
	options: CreatePresetJobCommandOptions,
	workspaceRoot: string,
	presetId: string
): string {
	if (typeof options.outDir === 'string' && options.outDir.length > 0) {
		return resolveRelativeOrAbsolutePath(workspaceRoot, options.outDir);
	}
	const safePreset = sanitizeFileName(presetId);
	return path.join(workspaceRoot, 'hexcore-reports', safePreset);
}

function resolvePresetJobFilePath(options: CreatePresetJobCommandOptions, workspaceRoot: string): string {
	if (typeof options.jobPath === 'string' && options.jobPath.length > 0) {
		return resolveRelativeOrAbsolutePath(workspaceRoot, options.jobPath);
	}
	return path.join(workspaceRoot, '.hexcore_job.json');
}

function resolveSaveProfileJobFilePath(options: SaveJobAsProfileCommandOptions, workspaceRoot: string): string {
	if (typeof options.jobFile === 'string' && options.jobFile.length > 0) {
		return resolveRelativeOrAbsolutePath(workspaceRoot, options.jobFile);
	}
	return path.join(workspaceRoot, '.hexcore_job.json');
}

function validatePipelineJobTemplate(template: unknown, jobFilePath: string): asserts template is PipelineJobTemplate {
	if (!isRecord(template)) {
		throw new Error(`Invalid job format in ${jobFilePath}: expected JSON object`);
	}
	if (typeof template.file !== 'string' || template.file.trim().length === 0) {
		throw new Error(`Invalid job format in ${jobFilePath}: missing "file"`);
	}
	if (typeof template.outDir !== 'string' || template.outDir.trim().length === 0) {
		throw new Error(`Invalid job format in ${jobFilePath}: missing "outDir"`);
	}
	if (!Array.isArray(template.steps) || template.steps.length === 0) {
		throw new Error(`Invalid job format in ${jobFilePath}: "steps" must be a non-empty array`);
	}
}

function resolveRelativeOrAbsolutePath(baseDir: string, candidate: string): string {
	return path.isAbsolute(candidate)
		? candidate
		: path.resolve(baseDir, candidate);
}

function getWorkspaceRootPath(): string | undefined {
	return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

function resolveOptionalOutputPath(output?: string | { path?: string }): string | undefined {
	if (typeof output === 'string' && output.length > 0) {
		return path.resolve(output);
	}
	if (typeof output === 'object' && output !== null && typeof output.path === 'string' && output.path.length > 0) {
		return path.resolve(output.path);
	}
	return undefined;
}

const JOB_FILE_SUFFIX = '.hexcore_job.json';
// Directories not worth walking when hunting for job files. Keeps the bounded
// recursive scan (used ONLY to populate the interactive picker) fast.
const JOB_SCAN_SKIP_DIRS = new Set([
	'node_modules', '.git', '.hg', '.svn', 'out', 'dist', 'build',
	'target', 'bin', 'obj', '.vscode-test', 'coverage', '__pycache__'
]);
const JOB_SCAN_MAX_DEPTH = 6;

// Recursively collect *.hexcore_job.json under rootDir, bounded by depth and
// skipping heavy dirs. Used to build the interactive job picker — NEVER to
// silently auto-pick a job (see resolveJobFilePath).
function findJobFilesRecursive(rootDir: string): string[] {
	const found: string[] = [];
	const walk = (dir: string, depth: number): void => {
		let entries: fs.Dirent[];
		try {
			entries = fs.readdirSync(dir, { withFileTypes: true });
		} catch {
			return; // unreadable dir is non-fatal
		}
		for (const entry of entries) {
			if (entry.isFile() && entry.name.endsWith(JOB_FILE_SUFFIX)) {
				found.push(path.join(dir, entry.name));
			}
		}
		if (depth >= JOB_SCAN_MAX_DEPTH) {
			return;
		}
		for (const entry of entries) {
			if (entry.isDirectory() && !JOB_SCAN_SKIP_DIRS.has(entry.name) && !entry.name.startsWith('.')) {
				walk(path.join(dir, entry.name), depth + 1);
			}
		}
	};
	walk(rootDir, 0);
	return found;
}

// Resolve which job file a manual Run Job / Validate Job command should act on.
// Order of intent (strongest first); it NEVER silently guesses among several jobs:
//   1. an explicit path / URI / string arg (right-click, programmatic);
//   2. the *.hexcore_job.json open in the active editor ("run the one I'm viewing");
//   3. the canonical .hexcore_job.json (then the first named job) at a workspace root;
//   4. interactive only: if jobs exist solely in subfolders, ONE is used directly,
//      but SEVERAL trigger a QuickPick so the user chooses — no auto-pick.
// Non-interactive (quiet) callers never prompt; they get undefined and the caller
// reports an honest "not found". The recursive FileSystemWatcher (on save) is a
// separate path (executePipelineJob with an explicit path) and is unaffected.
async function resolveJobFilePath(
	arg: vscode.Uri | string | RunJobCommandOptions | undefined,
	explicitPath?: string,
	options?: { interactive?: boolean }
): Promise<string | undefined> {
	if (typeof explicitPath === 'string' && explicitPath.length > 0) {
		return path.resolve(explicitPath);
	}
	if (arg instanceof vscode.Uri) {
		return arg.fsPath;
	}
	if (typeof arg === 'string' && arg.length > 0) {
		return path.resolve(arg);
	}

	// The job file currently open in the editor wins — "run the job I'm viewing".
	const activeDoc = vscode.window.activeTextEditor?.document;
	if (activeDoc && !activeDoc.isUntitled && activeDoc.uri.scheme === 'file'
		&& activeDoc.uri.fsPath.endsWith(JOB_FILE_SUFFIX)) {
		return activeDoc.uri.fsPath;
	}

	const folders = vscode.workspace.workspaceFolders ?? [];
	for (const folder of folders) {
		// Canonical .hexcore_job.json at the workspace root.
		const candidate = path.join(folder.uri.fsPath, JOB_FILE_SUFFIX);
		if (fs.existsSync(candidate)) {
			return candidate;
		}
		// First *.hexcore_job.json directly in the workspace root.
		try {
			const files = fs.readdirSync(folder.uri.fsPath);
			const namedJob = files.find(f => f.endsWith(JOB_FILE_SUFFIX));
			if (namedJob) {
				return path.join(folder.uri.fsPath, namedJob);
			}
		} catch {
			// Non-fatal
		}
	}

	// Nothing at any workspace root. Only an INTERACTIVE command may look into
	// subfolders, and only by asking the user when there is more than one match.
	if (options?.interactive) {
		const candidates: string[] = [];
		for (const folder of folders) {
			candidates.push(...findJobFilesRecursive(folder.uri.fsPath));
		}
		const unique = Array.from(new Set(candidates)).sort((a, b) => a.localeCompare(b));
		if (unique.length === 1) {
			return unique[0];
		}
		if (unique.length > 1) {
			const root = folders[0]?.uri.fsPath;
			const picked = await vscode.window.showQuickPick(
				unique.map(p => ({
					label: path.basename(p),
					description: root ? path.relative(root, p) : p,
					jobPath: p
				})),
				{
					title: 'HexCore: select a job to run',
					placeHolder: `${unique.length} .hexcore_job.json files found (none at the workspace root)`,
					matchOnDescription: true
				}
			);
			return picked?.jobPath;
		}
	}

	return undefined;
}

function writeJsonFile(outputPath: string, data: unknown): void {
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(outputPath, JSON.stringify(data, null, 2), 'utf8');
}

function showCapabilitiesInOutputChannel(capabilities: ReturnType<typeof listCapabilities>): void {
	const outputChannel = vscode.window.createOutputChannel('HexCore Pipeline');
	outputChannel.clear();
	outputChannel.appendLine('HexCore Pipeline - Command Capabilities');
	outputChannel.appendLine('='.repeat(50));
	outputChannel.appendLine('');
	for (const cap of capabilities) {
		const status = cap.headless ? 'HEADLESS' : 'INTERACTIVE';
		outputChannel.appendLine(`[${status}] ${cap.command}`);
		if (cap.aliases.length > 0) {
			outputChannel.appendLine(`  Aliases:    ${cap.aliases.join(', ')}`);
		}
		outputChannel.appendLine(`  Timeout:    ${cap.defaultTimeoutMs}ms`);
		outputChannel.appendLine(`  Validates:  ${cap.validateOutput}`);
		outputChannel.appendLine(`  Extension:  ${cap.requiredExtension.join(', ')}`);
		if (cap.reason) {
			outputChannel.appendLine(`  Note:       ${cap.reason}`);
		}
		outputChannel.appendLine('');
	}
	outputChannel.show();
}

function showValidationReportInOutputChannel(report: PipelineJobValidationReport): void {
	const outputChannel = vscode.window.createOutputChannel('HexCore Pipeline');
	outputChannel.clear();
	outputChannel.appendLine('HexCore Pipeline - Job Validation');
	outputChannel.appendLine('='.repeat(50));
	outputChannel.appendLine(`Job file:   ${report.jobFile}`);
	outputChannel.appendLine(`Target:     ${report.file}`);
	outputChannel.appendLine(`Output dir: ${report.outDir}`);
	outputChannel.appendLine(`Steps:      ${report.totalSteps}`);
	outputChannel.appendLine(`Result:     ${report.ok ? 'OK' : 'ISSUES FOUND'}`);
	outputChannel.appendLine('');

	if (report.issues.length > 0) {
		outputChannel.appendLine('Issues:');
		for (const issue of report.issues) {
			const stepInfo = issue.stepIndex ? ` (step ${issue.stepIndex})` : '';
			outputChannel.appendLine(`- [${issue.level.toUpperCase()}] ${issue.code}${stepInfo}: ${issue.message}`);
		}
		outputChannel.appendLine('');
	}

	outputChannel.appendLine('Step Matrix:');
	for (const step of report.steps) {
		outputChannel.appendLine(
			`- #${step.index} ${step.cmd} -> ${step.resolvedCmd} | declared=${step.declared} | headless=${step.headless} | registered=${step.registered} | output=${step.outputPath ?? '(none)'}`
		);
	}
	outputChannel.show();
}

function showWorkspaceValidationInOutputChannel(report: WorkspaceValidationReport): void {
	const outputChannel = vscode.window.createOutputChannel('HexCore Pipeline');
	outputChannel.clear();
	outputChannel.appendLine('HexCore Pipeline - Workspace Validation');
	outputChannel.appendLine('='.repeat(50));
	outputChannel.appendLine(`Generated: ${report.generatedAt}`);
	outputChannel.appendLine(`Workspaces: ${report.workspaceRoots.length > 0 ? report.workspaceRoots.join(' | ') : '(none)'}`);
	outputChannel.appendLine(`Jobs: ${report.totalJobs} | Passed: ${report.passedJobs} | Failed: ${report.failedJobs}`);
	outputChannel.appendLine('');

	for (const entry of report.entries) {
		const status = entry.ok ? 'OK' : 'FAIL';
		outputChannel.appendLine(`[${status}] ${entry.jobFile}`);
		outputChannel.appendLine(`  Steps: ${entry.totalSteps} | Errors: ${entry.errors} | Warnings: ${entry.warnings}`);
		if (entry.error) {
			outputChannel.appendLine(`  Error: ${entry.error}`);
		}
		outputChannel.appendLine('');
	}

	outputChannel.show();
}

function showDoctorReportInOutputChannel(report: PipelineDoctorReport): void {
	const outputChannel = vscode.window.createOutputChannel('HexCore Pipeline');
	outputChannel.clear();
	outputChannel.appendLine('HexCore Pipeline - Doctor');
	outputChannel.appendLine('='.repeat(50));
	outputChannel.appendLine(`Workspace:            ${report.workspaceRoot}`);
	outputChannel.appendLine(`Capabilities:         ${report.totalCapabilities}`);
	outputChannel.appendLine(`Ready:                ${report.readyCommands}`);
	outputChannel.appendLine(`Degraded:             ${report.degradedCommands}`);
	outputChannel.appendLine(`Missing:              ${report.missingCommands}`);
	outputChannel.appendLine(`Gated (emulator):     ${report.gatedCommands}`);
	outputChannel.appendLine(`Registered hexcore.*: ${report.registeredHexcoreCommands}`);
	outputChannel.appendLine('');

	if (report.undeclaredHexcoreCommands.length > 0) {
		outputChannel.appendLine('Undeclared registered commands (hexcore.*):');
		for (const command of report.undeclaredHexcoreCommands) {
			outputChannel.appendLine(`- ${command}`);
		}
		outputChannel.appendLine('');
	}

	for (const entry of report.entries) {
		outputChannel.appendLine(`[${entry.readiness.toUpperCase()}] ${entry.command}`);
		if (entry.aliases.length > 0) {
			outputChannel.appendLine(`  Aliases:    ${entry.aliases.join(', ')}`);
		}
		outputChannel.appendLine(`  Headless:   ${entry.headless}`);
		outputChannel.appendLine(`  Registered: ${entry.registered}`);
		outputChannel.appendLine(`  Timeout:    ${entry.defaultTimeoutMs}ms`);
		outputChannel.appendLine(`  Validate:   ${entry.validateOutput}`);
		if (entry.reason) {
			outputChannel.appendLine(`  Note:       ${entry.reason}`);
		}
		if (entry.ownerExtensions.length > 0) {
			outputChannel.appendLine(
				`  Owners:     ${entry.ownerExtensions.map(owner => `${owner.id} (installed=${owner.installed}, active=${owner.active})`).join('; ')}`
			);
		}
		outputChannel.appendLine('');
	}

	outputChannel.show();
}

/**
 * v3.8.3: derive high-signal capability tags from the import table, section flags, and CLR
 * header. Best-effort and import/section based (dynamically-resolved APIs via PEB-walk/CRC32
 * are intentionally not covered here). Gives the orchestrator a behavior summary the raw
 * function map lacked (e.g. an injector's CreateRemoteThread set was previously invisible).
 */
function computeAnalyzeAllCapabilities(engine: DisassemblerEngine): string[] {
	const caps: string[] = [];
	const apiNames = new Set<string>();
	for (const lib of engine.getImports()) {
		for (const fn of lib.functions) {
			const n = fn.name.toLowerCase();
			apiNames.add(n);
			apiNames.add(n.replace(/[aw]$/, '')); // also index without an A/W suffix
		}
	}
	const has = (...names: string[]): number => names.filter(n => apiNames.has(n.toLowerCase())).length;

	if (engine.getPEDataDirectories().clr) {
		caps.push('managed-dotnet (native decompile N/A; use IL tooling)');
	}
	if (has('openprocess', 'virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex', 'queueuserapc', 'setthreadcontext', 'ntmapviewofsection') >= 2) {
		caps.push('process-injection');
	}
	const rwxSection = engine.getSections().some(s => s.permissions.includes('w') && s.permissions.includes('x'));
	if (rwxSection || (has('virtualprotect') >= 1 && has('virtualalloc') >= 1)) {
		caps.push('self-modifying-or-rwx');
	}
	// Issue #55: structured packer detect (UPX magic/banner + section heuristics).
	// Keeps legacy tag `packed` and adds `packed:upx` when family is UPX.
	try {
		const filePath = engine.getFilePath?.();
		const raw = filePath && fs.existsSync(filePath)
			? fs.readFileSync(filePath)
			: undefined;
		const packer = detectPacker(raw, {
			sections: engine.getSections().map(s => ({
				name: s.name,
				isCode: s.isCode,
				permissions: s.permissions,
				rawAddress: s.rawAddress,
				rawSize: s.rawSize,
				virtualSize: s.virtualSize,
			})),
			strings: engine.getStrings().map(s => ({ string: s.string })),
		});
		for (const t of packerCapabilityTags(packer)) {
			caps.push(t);
		}
	} catch {
		// fall through — capabilities stay without packer tags
	}
	if (has('socket', 'connect', 'wsastartup', 'internetopen', 'internetconnect', 'winhttpopen', 'httpsendrequest', 'urldownloadtofile', 'send', 'recv') >= 1) {
		caps.push('networking');
	}
	if (has('cryptacquirecontext', 'cryptencrypt', 'cryptdecrypt', 'cryptderivekey', 'bcryptencrypt', 'bcryptdecrypt') >= 1) {
		caps.push('crypto-api');
	}
	// Gap J: crypto via AES/SHA hardware opcodes. partialencryption's custom cipher was
	// built from AESKEYGENASSIST + AESDECLAST; surfacing the opcode usage points the analyst
	// straight at the crypto without reading every function. Scan the decoded stream.
	const cryptoOpcode = /^(aes|sha1|sha256|sha1rnds|sha256rnds|vaes|pclmulqdq)/;
	let hasCryptoNi = false;
	for (const fn of engine.getFunctions()) {
		for (const inst of fn.instructions) {
			if (cryptoOpcode.test(inst.mnemonic.toLowerCase())) { hasCryptoNi = true; break; }
		}
		if (hasCryptoNi) { break; }
	}
	if (hasCryptoNi) {
		caps.push('crypto-aes-sha-ni');
	}
	if (has('isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess', 'outputdebugstring') >= 1) {
		caps.push('anti-debug-or-debugstring');
	}
	if (has('createtoolhelp32snapshot', 'process32first', 'process32next') >= 2) {
		caps.push('process-enumeration');
	}
	if (has('regsetvalueex', 'regcreatekeyex', 'createservice', 'schtasks') >= 1) {
		caps.push('persistence-api');
	}
	// Gap H: toolchain/runtime fingerprint from section names (reliable, no string scan).
	// Knowing the language up front (e.g. D + std BigInt, or Go) is often the whole triage.
	const secNames = new Set(engine.getSections().map(s => s.name.toLowerCase()));
	if (secNames.has('.minfo') || secNames.has('._deh') || secNames.has('.dp') || secNames.has('.fptable') || secNames.has('.tp')) {
		caps.push('lang-dlang');
	}
	if (secNames.has('.gopclntab') || secNames.has('.go.buildinfo') || secNames.has('.gosymtab')) {
		caps.push('lang-go');
	}
	return caps;
}

function createAnalyzeAllResult(engine: DisassemblerEngine, targetFilePath: string, _legacyNetChange: number, includeInstructions: boolean = false, v37Options?: {
	filterJunk?: boolean;
	detectVM?: boolean;
	detectPRNG?: boolean;
	allowLazy?: boolean;
	allowDecodeEmpty?: boolean;
	minMaterializedRatio?: number;
}): AnalyzeAllResult {
	const functions = engine.getFunctions();
	const analysisDelta = engine.getLastAnalysisDelta();
	const MAX_INSTRUCTIONS_PER_FUNCTION = 200;

	const functionSummaries: AnalyzeAllFunctionSummary[] = functions.map(func => {
		const bodyStatus = engine.getFunctionBodyStatus(func.address);
		const discoveryEvidence = engine.getFunctionDiscoveryEvidence(func.address);
		const summary: AnalyzeAllFunctionSummary = {
			address: toHexAddress(func.address),
			name: func.name,
			size: func.size,
			instructionCount: func.instructions.length,
			bodyStatus,
			...(bodyStatus === 'lazy'
				? { bodyReason: 'deferred-until-requested' as const }
				: bodyStatus === 'decode-empty'
					? { bodyReason: 'decoder-returned-no-instructions' as const }
					: {}),
			callers: func.callers.length,
			callees: func.callees.length,
			...(discoveryEvidence.length > 0 ? {
				discoveryEvidence: discoveryEvidence.map(evidence => ({
					kind: evidence.kind,
					...(evidence.sourceAddress !== undefined
						? { sourceAddress: toHexAddress(evidence.sourceAddress) }
						: {}),
					...(evidence.consumerAddress !== undefined
						? { consumerAddress: toHexAddress(evidence.consumerAddress) }
						: {}),
					...(evidence.confidence !== undefined ? { confidence: evidence.confidence } : {}),
				})),
			} : {}),
		};

		if (includeInstructions) {
			summary.instructions = func.instructions.slice(0, MAX_INSTRUCTIONS_PER_FUNCTION).map(inst => ({
				address: toHexAddress(inst.address),
				mnemonic: inst.mnemonic,
				operands: inst.opStr,
				bytes: inst.bytes.toString('hex').toUpperCase()
			}));
			summary.xrefsTo = func.callers.map(addr => toHexAddress(addr));
			summary.xrefsFrom = func.callees.map(addr => toHexAddress(addr));
		}

		return summary;
	});
	const functionsWithInstructions = functionSummaries.filter(func => func.instructionCount > 0).length;
	const functionsMaterialized = functionSummaries.filter(func => func.bodyStatus === 'materialized').length;
	const partialFunctions = functionSummaries.filter(func => func.bodyStatus === 'partial').length;
	const lazyFunctions = functionSummaries.filter(func => func.bodyStatus === 'lazy').length;
	const decodeEmptyFunctions = functionSummaries.filter(func => func.bodyStatus === 'decode-empty').length;
	const totalFunctionInstructions = functionSummaries.reduce((total, func) => total + func.instructionCount, 0);
	const materialization = assessFunctionMaterialization({
		totalFunctions: functions.length,
		materializedFunctions: functionsMaterialized,
		partialFunctions,
		lazyFunctions,
		decodeEmptyFunctions,
		allowLazy: v37Options?.allowLazy,
		allowDecodeEmpty: v37Options?.allowDecodeEmpty,
		minMaterializedRatio: v37Options?.minMaterializedRatio,
	});
	const closureRestoration = engine.getAnalysisClosureRestoration();
	const restorationWarning = closureRestoration.status === 'partial' || closureRestoration.status === 'reset'
		? `Persisted closure restoration incomplete: ${closureRestoration.restored}/${closureRestoration.requested}; ${closureRestoration.failed[0] ?? 'unknown failure'}`
		: undefined;

	const result: AnalyzeAllResult = {
		status: closureRestoration.status === 'partial' || closureRestoration.status === 'reset' ? 'partial' : materialization.status,
		...(materialization.reason || restorationWarning ? { warning: [materialization.reason, restorationWarning].filter(Boolean).join(' ') } : {}),
		filePath: targetFilePath,
		fileName: path.basename(targetFilePath),
		newFunctions: analysisDelta.added,
		removedFunctions: analysisDelta.removed,
		functionNetChange: analysisDelta.netChange,
		totalFunctions: functions.length,
		functionsWithInstructions,
		functionsWithoutInstructions: functions.length - functionsWithInstructions,
		lazyFunctions,
		decodeEmptyFunctions,
		materializedFunctionRatio: materialization.materializedFunctionRatio,
		analysisDepth: materialization.analysisDepth,
		negativeEvidenceUsable: false,
		functionsMaterialized,
		partialFunctions,
		materializationPolicy: materialization.policy,
		closureRestoration,
		totalFunctionInstructions,
		totalStrings: engine.getStrings().length,
		architecture: engine.getArchitecture(),
		baseAddress: toHexAddress(engine.getBaseAddress()),
		sections: engine.getSections().length,
		imports: engine.getImports().length,
		importedFunctions: engine.getImports().reduce((n, lib) => n + lib.functions.length, 0),
		exports: engine.getExports().length,
		sectionDetails: engine.getSections().map(s => ({
			name: s.name,
			virtualAddress: toHexAddress(s.virtualAddress),
			virtualSize: s.virtualSize,
			rawSize: s.rawSize,
			permissions: s.permissions,
			isCode: s.isCode
		})),
		importDetails: engine.getImports().map(lib => ({
			dll: lib.name,
			functionCount: lib.functions.length,
			functions: lib.functions.map(fn => ({ name: fn.name, address: toHexAddress(fn.address), ordinal: fn.ordinal }))
		})),
		exportDetails: engine.getExports().map(e => ({
			name: e.name,
			address: toHexAddress(e.address),
			ordinal: e.ordinal,
			isForwarder: e.isForwarder
		})),
		capabilities: computeAnalyzeAllCapabilities(engine),
		functions: functionSummaries,
		reportMarkdown: ''
	};

	if (includeInstructions) {
		const stringRefs = engine.getStrings();
		result.strings = stringRefs.slice(0, 5000).map(sr => ({
			address: toHexAddress(sr.address),
			value: sr.string,
			encoding: sr.encoding,
			referencedBy: sr.references.map(addr => toHexAddress(addr))
		}));
	}

	// v3.7: Junk analysis
	if (v37Options?.filterJunk) {
		let totalInstr = 0;
		let totalJunk = 0;
		for (const func of functions) {
			const { junkCount } = engine.filterJunkInstructions(func.instructions);
			totalInstr += func.instructions.length;
			totalJunk += junkCount;
		}
		result.junkAnalysis = {
			totalInstructions: totalInstr,
			junkCount: totalJunk,
			junkRatio: totalInstr > 0 ? totalJunk / totalInstr : 0
		};
	}

	// v3.7: VM detection
	if (v37Options?.detectVM) {
		result.vmDetection = engine.detectVM();
	}

	// v3.7: PRNG detection
	if (v37Options?.detectPRNG) {
		result.prngDetection = engine.detectPRNG();
	}

	// v3.8.1: callfuscation detection — always run. It is a cheap byte scan and,
	// unlike the passes above, does NOT depend on function discovery (which the
	// obfuscation defeats), so it is the one reliable obfuscation signal here.
	const cf = engine.detectCallfuscation();
	if (cf.callCount > 0) {
		result.callfuscation = cf;
	}

	result.reportMarkdown = generateAnalyzeAllReport(result);
	return result;
}

function generateAnalyzeAllReport(result: AnalyzeAllResult): string {
	let report = `# HexCore Disassembly Analysis Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${result.fileName} |
| **File Path** | ${result.filePath} |
| **Architecture** | ${result.architecture} |
| **Base Address** | ${result.baseAddress} |

---

## Analysis Summary

| Metric | Value |
|--------|-------|
| **Functions Added** | ${result.newFunctions} |
| **Functions Pruned** | ${result.removedFunctions} |
| **Net Function Change** | ${result.functionNetChange} |
| **Total Functions** | ${result.totalFunctions} |
| **Functions With Decoded Instructions** | ${result.functionsWithInstructions} |
| **Complete Materialized Functions** | ${result.functionsMaterialized} |
| **Partial Function Bodies** | ${result.partialFunctions} |
| **Analysis Depth** | ${result.analysisDepth} |
| **Negative Evidence Usable** | false (discovery is not a behavioral audit) |
| **Functions Without Decoded Instructions** | ${result.functionsWithoutInstructions} |
| **Lazy Function Bodies** | ${result.lazyFunctions} |
| **Decode-Empty Function Bodies** | ${result.decodeEmptyFunctions} |
| **Materialized Function Ratio** | ${(result.materializedFunctionRatio * 100).toFixed(2)}% |
| **Materialization Status** | ${result.status}${result.warning ? ` - ${result.warning}` : ''} |
| **Materialization Policy** | allowLazy=${result.materializationPolicy.allowLazy}, allowDecodeEmpty=${result.materializationPolicy.allowDecodeEmpty}, minRatio=${(result.materializationPolicy.minMaterializedRatio * 100).toFixed(2)}% |
| **Indexed Function Instructions** | ${result.totalFunctionInstructions} |
| **Total Strings** | ${result.totalStrings} |
| **Sections** | ${result.sections} |
| **Imports** | ${result.imports} |
| **Exports** | ${result.exports} |

---

## Function Index Preview (First 100 by Address)

Showing ${Math.min(result.functions.length, 100)} of ${result.functions.length} discovered functions.
JSON output retains the full discovered-function index. Lazy bodies are indexed but not decoded;
zero known references does not establish that a function has no callers or callees.

| Address | Name | Size | Body | Instructions | Known Callers | Known Callees |
|---------|------|------|------|--------------|---------|---------|
`;

	for (const func of result.functions.slice(0, 100)) {
		report += `| ${func.address} | ${func.name} | ${func.size} | ${func.bodyStatus} | ${func.instructionCount} | ${func.callers} | ${func.callees} |\n`;
	}

	if (result.functions.length > 100) {
		report += `| ... | ... | ... | ... | ... | ... | ... |\n`;
	}

	report += `
---
*Generated by HexCore Disassembler*
`;

	return report;
}

function writeAnalyzeAllOutput(result: AnalyzeAllResult, output: AnalyzeAllOutputOptions): void {
	const format = normalizeOutputFormat(output.path, output.format);
	fs.mkdirSync(path.dirname(output.path), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(output.path, result.reportMarkdown, 'utf8');
		return;
	}

	// NOTE: Build the headless payload explicitly (not the whole result) to keep
	// the reportMarkdown blob out of the JSON. The v3.7 analysis fields
	// (junkAnalysis / vmDetection / prngDetection) are OPTIONAL and only present
	// when the caller passed filterJunk / detectVM / detectPRNG. They were
	// previously dropped here even when populated — callfuscation/VM/PRNG
	// telemetry never reached pipeline consumers. Include them when present.
	const payload: Record<string, unknown> = {
		filePath: result.filePath,
		fileName: result.fileName,
		newFunctions: result.newFunctions,
		removedFunctions: result.removedFunctions,
		functionNetChange: result.functionNetChange,
		totalFunctions: result.totalFunctions,
		functionsWithInstructions: result.functionsWithInstructions,
		functionsWithoutInstructions: result.functionsWithoutInstructions,
		lazyFunctions: result.lazyFunctions,
		decodeEmptyFunctions: result.decodeEmptyFunctions,
		materializedFunctionRatio: result.materializedFunctionRatio,
		analysisDepth: result.analysisDepth,
		negativeEvidenceUsable: result.negativeEvidenceUsable,
		functionsMaterialized: result.functionsMaterialized,
		partialFunctions: result.partialFunctions,
		materializationPolicy: result.materializationPolicy,
		closureRestoration: result.closureRestoration,
		nativeExecution: result.nativeExecution,
		status: result.status,
		warning: result.warning,
		totalFunctionInstructions: result.totalFunctionInstructions,
		totalStrings: result.totalStrings,
		architecture: result.architecture,
		baseAddress: result.baseAddress,
		sections: result.sections,
		sectionDetails: result.sectionDetails,
		imports: result.imports,
		importedFunctions: result.importedFunctions,
		importDetails: result.importDetails,
		exports: result.exports,
		exportDetails: result.exportDetails,
		capabilities: result.capabilities,
		functions: result.functions,
		generatedAt: new Date().toISOString()
	};
	if (result.junkAnalysis) { payload.junkAnalysis = result.junkAnalysis; }
	if (result.vmDetection) { payload.vmDetection = result.vmDetection; }
	if (result.prngDetection) { payload.prngDetection = result.prngDetection; }
	if (result.callfuscation) { payload.callfuscation = result.callfuscation; }

	fs.writeFileSync(output.path, JSON.stringify(payload, null, 2), 'utf8');
}

async function resolveFormulaInstructions(
	engine: DisassemblerEngine,
	disasmEditorProvider: DisassemblyEditorProvider,
	options: BuildFormulaCommandOptions
): Promise<Instruction[]> {
	if (options.addresses && options.addresses.length > 0) {
		const parsedAddresses = options.addresses
			.map(address => parseAddressValue(address))
			.filter((address): address is number => address !== undefined);
		if (parsedAddresses.length === 0) {
			throw new Error('No valid instruction addresses were provided.');
		}

		const instructions: Instruction[] = [];
		for (const address of parsedAddresses) {
			const instruction = await findInstructionByAddress(engine, address);
			if (!instruction) {
				throw new Error(`Instruction not found at ${toHexAddress(address)}.`);
			}
			instructions.push(instruction);
		}
		return instructions.sort((left, right) => left.address - right.address);
	}

	let startAddress = parseAddressValue(options.startAddress);
	let endAddress = parseAddressValue(options.endAddress);
	if (startAddress === undefined && !options.quiet) {
		const defaultStart = disasmEditorProvider.getCurrentAddress();
		const input = await vscode.window.showInputBox({
			prompt: 'Formula Start Address (hex or decimal)',
			placeHolder: defaultStart !== undefined ? toHexAddress(defaultStart) : '0x401000',
			value: defaultStart !== undefined ? toHexAddress(defaultStart) : undefined,
			validateInput: value => parseAddressValue(value) === undefined ? 'Invalid address' : null
		});
		if (input) {
			startAddress = parseAddressValue(input);
		}
	}

	if (startAddress === undefined) {
		startAddress = disasmEditorProvider.getCurrentAddress();
	}
	if (startAddress === undefined) {
		throw new Error('Formula extraction requires a start address.');
	}

	if (endAddress === undefined && !options.quiet) {
		const startHex = toHexAddress(startAddress);
		const input = await vscode.window.showInputBox({
			prompt: 'Formula End Address (hex or decimal)',
			placeHolder: startHex,
			value: startHex,
			validateInput: value => parseAddressValue(value) === undefined ? 'Invalid address' : null
		});
		if (input) {
			endAddress = parseAddressValue(input);
		}
	}

	if (endAddress === undefined) {
		endAddress = startAddress;
	}

	return collectInstructionsInRange(engine, startAddress, endAddress);
}

async function collectInstructionsInRange(engine: DisassemblerEngine, startAddress: number, endAddress: number): Promise<Instruction[]> {
	const from = Math.min(startAddress, endAddress);
	const to = Math.max(startAddress, endAddress);

	const containing = engine.getFunctions().find(func =>
		from >= func.address && from < func.endAddress
	);
	if (!containing) {
		throw new Error(`No containing function found for ${toHexAddress(from)}.`);
	}

	// A-lazy: materialize the containing function so a .pdata stub's body exists before we read it.
	await engine.materializeFunction(containing.address);

	const instructions = containing.instructions
		.filter(instruction => instruction.address >= from && instruction.address <= to)
		.sort((left, right) => left.address - right.address);
	if (instructions.length === 0) {
		throw new Error(`No instructions found in range ${toHexAddress(from)}..${toHexAddress(to)}.`);
	}
	return instructions;
}

async function findInstructionByAddress(engine: DisassemblerEngine, address: number): Promise<Instruction | undefined> {
	// A-lazy: the target instruction lives in some function's body. Materialize the containing
	// function (if the address falls inside one) so a .pdata stub is disassembled before the search.
	const containing = engine.getFunctions().find(func => address >= func.address && address < func.endAddress);
	if (containing) {
		await engine.materializeFunction(containing.address);
	}
	for (const func of engine.getFunctions()) {
		const instruction = func.instructions.find(item => item.address === address);
		if (instruction) {
			return instruction;
		}
	}
	return undefined;
}

function createBuildFormulaResult(
	filePath: string,
	instructions: Instruction[],
	formula: FormulaBuildResult
): BuildFormulaResult {
	const sorted = [...instructions].sort((left, right) => left.address - right.address);
	const startAddress = sorted[0]?.address ?? 0;
	const endAddress = sorted[sorted.length - 1]?.address ?? 0;

	return {
		filePath,
		fileName: path.basename(filePath),
		startAddress: toHexAddress(startAddress),
		endAddress: toHexAddress(endAddress),
		instructionCount: formula.instructionCount,
		targetRegister: formula.targetRegister,
		expression: formula.expression,
		registerExpressions: formula.registerExpressions,
		steps: formula.steps,
		unsupportedInstructions: formula.unsupportedInstructions,
		reportMarkdown: formula.reportMarkdown,
		generatedAt: new Date().toISOString()
	};
}

function writeBuildFormulaOutput(result: BuildFormulaResult, output: AnalyzeAllOutputOptions): void {
	const outputPath = path.resolve(output.path);
	const format = normalizeOutputFormat(outputPath, output.format);
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(outputPath, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
}

function writeConstantSanityOutput(result: ConstantSanityResult, output: AnalyzeAllOutputOptions): void {
	const outputPath = path.resolve(output.path);
	const format = normalizeOutputFormat(outputPath, output.format);
	fs.mkdirSync(path.dirname(outputPath), { recursive: true });

	if (format === 'md') {
		fs.writeFileSync(outputPath, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(outputPath, JSON.stringify(result, null, 2), 'utf8');
}

function collectAnalyzedInstructions(engine: DisassemblerEngine): Instruction[] {
	const byAddress = new Map<number, Instruction>();
	for (const func of engine.getFunctions()) {
		for (const instruction of func.instructions) {
			if (!byAddress.has(instruction.address)) {
				byAddress.set(instruction.address, instruction);
			}
		}
	}
	return Array.from(byAddress.values()).sort((left, right) => left.address - right.address);
}

function resolveOptionalNotesFilePath(candidate: string | undefined, targetFilePath: string): string | undefined {
	if (typeof candidate !== 'string' || candidate.trim().length === 0) {
		return undefined;
	}

	const normalizedCandidate = candidate.trim();
	if (path.isAbsolute(normalizedCandidate)) {
		return normalizedCandidate;
	}

	const workspaceRoot = getWorkspaceRootPath();
	if (workspaceRoot) {
		return path.resolve(workspaceRoot, normalizedCandidate);
	}

	return path.resolve(path.dirname(targetFilePath), normalizedCandidate);
}

function parseAddressValue(value: string | number | undefined): number | undefined {
	if (typeof value === 'number' && Number.isFinite(value)) {
		const normalized = Math.floor(value);
		return normalized >= 0 ? normalized : undefined;
	}
	if (typeof value !== 'string') {
		return undefined;
	}

	const text = value.trim();
	if (text.length === 0) {
		return undefined;
	}
	if (/^-?0x[0-9a-f]+$/i.test(text)) {
		return parseInt(text, 16);
	}
	if (/^[0-9]+$/i.test(text)) {
		return parseInt(text, 10);
	}
	return undefined;
}

/**
 * Resolve symbolic address keywords (`"entry"`, `"first"`, `"main"`) against
 * the engine state. Returns `undefined` if the keyword can't be resolved or
 * the input isn't a known keyword.
 *
 * FIX (HEXCORE_DEFEAT FAIL 3): `"address": "entry"` previously fell through to
 * `engine.getBaseAddress()` which is the PE/ELF base (e.g. 0x140000000), not
 * the actual entry point. Helix would then try to decompile the MZ header and
 * produce garbage like `void sub_140000000(void) { *v1 = v1 + v2; }`.
 */
function resolveSymbolicAddress(value: string | number | undefined, eng: DisassemblerEngine): number | undefined {
	if (typeof value !== 'string') {
		return undefined;
	}
	const keyword = value.trim().toLowerCase();
	if (keyword === 'entry' || keyword === 'entrypoint' || keyword === 'entry_point') {
		// Prefer the entry point from file info (PE OptionalHeader, ELF e_entry).
		const fileInfo = eng.getFileInfo();
		const entry = fileInfo?.entryPoint;
		if (typeof entry === 'number' && entry > 0) {
			return entry;
		}
	}
	if (keyword === 'first' || keyword === 'first_function') {
		const funcs = eng.getFunctions();
		if (funcs.length > 0) {
			// Sort by address ascending and return the lowest.
			const sorted = [...funcs].sort((a, b) => a.address - b.address);
			return sorted[0].address;
		}
	}
	if (keyword === 'main') {
		const funcs = eng.getFunctions();
		const main = funcs.find(f => f.name === 'main' || f.name === '_main' || f.name === 'WinMain');
		if (main) {
			return main.address;
		}
	}
	return undefined;
}

/**
 * Combined address resolver — tries numeric/hex parsing first, then symbolic
 * keywords. Use this anywhere the user can pass `"entry"`, `"main"`, etc.
 */
function resolveAddressArg(value: string | number | undefined, eng: DisassemblerEngine): number | undefined {
	const numeric = parseAddressValue(value);
	if (numeric !== undefined) {
		return numeric;
	}
	return resolveSymbolicAddress(value, eng);
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

function toHexAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

function sanitizeFileName(value: string): string {
	return value
		.replace(/[^a-zA-Z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '')
		.toLowerCase() || 'default';
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

/**
 * Shows a file picker for selecting a .hexcore_job.json file.
 */
async function pickJobFile(): Promise<string | undefined> {
	const folders = vscode.workspace.workspaceFolders;
	if (!folders || folders.length === 0) {
		const picked = await vscode.window.showOpenDialog({
			canSelectFiles: true,
			canSelectFolders: false,
			canSelectMany: false,
			openLabel: 'Select Job File',
			filters: { 'HexCore Jobs': ['hexcore_job.json'], 'JSON': ['json'] }
		});
		return picked?.[0]?.fsPath;
	}

	// Search for ALL job files in workspace (canonical + named)
	const jobFiles = await vscode.workspace.findFiles(
		'**/*.hexcore_job.json',
		'**/{node_modules,.git,out,dist}/**'
	);

	if (jobFiles.length === 0) {
		const picked = await vscode.window.showOpenDialog({
			canSelectFiles: true,
			canSelectFolders: false,
			canSelectMany: false,
			openLabel: 'Select Job File',
			filters: { 'HexCore Jobs': ['hexcore_job.json'], 'JSON': ['json'] }
		});
		return picked?.[0]?.fsPath;
	}

	if (jobFiles.length === 1) {
		return jobFiles[0].fsPath;
	}

	const picked = await vscode.window.showQuickPick(
		jobFiles.map(uri => ({
			label: path.basename(uri.fsPath),
			description: path.dirname(uri.fsPath),
			uri
		})),
		{ placeHolder: 'Select a job file to queue' }
	);

	return picked?.uri.fsPath;
}

/**
 * Displays job status in an output channel.
 */
function showJobStatusInOutputChannel(job: JobStatusReport): void {
	const channel = vscode.window.createOutputChannel('HexCore Job Status');
	channel.clear();
	channel.appendLine(`Job ID: ${job.jobId}`);
	channel.appendLine(`Status: ${job.status}`);
	channel.appendLine(`Priority: ${job.priority}`);
	if (job.position !== null && job.position !== undefined) {
		channel.appendLine(`Queue Position: ${job.position}`);
	}
	if (job.sessionId) {
		channel.appendLine(`Session: ${job.sessionId}`);
	}
	if (job.workerId !== undefined) {
		channel.appendLine(`Worker: ${job.workerId}`);
	}
	channel.appendLine(`File: ${job.filePath}`);
	channel.appendLine(`Submitted: ${new Date(job.submittedAt).toLocaleString()}`);
	if (job.startedAt) {
		channel.appendLine(`Started: ${new Date(job.startedAt).toLocaleString()}`);
	}
	if (job.completedAt) {
		channel.appendLine(`Completed: ${new Date(job.completedAt).toLocaleString()}`);
	}
	if (job.error) {
		channel.appendLine(`Error: ${job.error}`);
	}
	if (job.result) {
		channel.appendLine('Result:');
		channel.appendLine(JSON.stringify(job.result, null, 2));
	}
	channel.show();
}

/**
 * Displays queue status in an output channel.
 */
function showQueueStatusInOutputChannel(jobs: QueuedJob[], stats: QueueStats): void {
	const channel = vscode.window.createOutputChannel('HexCore Job Queue');
	channel.clear();
	channel.appendLine('Job Queue Status');
	channel.appendLine('='.repeat(50));
	channel.appendLine(`Queued: ${stats.queued} | Running: ${stats.running} | Done: ${stats.done} | Failed: ${stats.failed} | Cancelled: ${stats.cancelled}`);
	channel.appendLine('');

	if (jobs.length === 0) {
		channel.appendLine('No jobs in queue.');
	} else {
		channel.appendLine('Jobs:');
		channel.appendLine('-'.repeat(50));
		for (const job of jobs) {
			const shortId = job.jobId.substring(0, 8);
			const fileName = path.basename(job.filePath);
			channel.appendLine(`${shortId}... | ${job.status.padEnd(10)} | ${job.priority.padEnd(7)} | ${fileName}`);
		}
	}
	channel.show();
}
