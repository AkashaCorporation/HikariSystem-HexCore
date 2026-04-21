/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { DisassemblyEditorProvider } from './disassemblyEditor';
import { FunctionTreeProvider } from './functionTree';
import { StringRefProvider } from './stringRefTree';
import { SectionTreeProvider } from './sectionTree';
import { ImportTreeProvider } from './importTree';
import { ExportTreeProvider } from './exportTree';
import { DisassemblerEngine, ImportLibrary, Instruction, TypedImportLibrary, TypedImportFunction, ImportCategorySummary, PEDataDirectories, ELFAnalysis, ELFExecutableSection } from './disassemblerEngine';
import { formatApiSignatureCompact, CATEGORY_LABELS } from './peApiDatabase';
import { DisassemblerFactory } from './disassemblerFactory';
import { GraphViewProvider } from './graphViewProvider';
import {
	AutomationPipelineRunner,
	PipelineDoctorReport,
	PipelineJobValidationReport,
	PipelineRunStatus,
	listCapabilities,
	runPipelineDoctor,
	getJobQueueManagerInstance,
	disposeJobQueueManagerInstance,
	JobPriority
} from './automationPipelineRunner';
import { QueuedJob, QueueStats } from './jobQueueManager';
import { buildInstructionFormula, FormulaBuildResult } from './formulaBuilder';
import { analyzeConstantSanity, ConstantSanityAnalysis } from './constantSanityChecker';
import { RemillWrapper, buildIRHeader, type LiftResult, type RemillLiftOptions } from './remillWrapper';
import { runPathfinder, getPdataFunctionCount } from './pathfinder';
import { RellicWrapper, buildPseudoCHeader } from './rellicWrapper';
import { HelixWrapper } from './helixWrapper';
import { SouperWrapper } from './souperWrapper';
import { getStructInfoForFunction, exportStructInfoJson, type StructInfoJson, type StructInfo } from './elfBtfLoader';
import { auditRefcount, type RefcountAuditReport } from './refcountAuditScanner';
import { mapCapstoneToRemill } from './archMapper';
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

type OutputFormat = 'json' | 'md';

interface AnalyzeAllOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface AnalyzeAllCommandOptions {
	file?: string;
	output?: AnalyzeAllOutputOptions;
	quiet?: boolean;
	maxFunctions?: number;
	maxFunctionSize?: number;
	forceReload?: boolean;
	includeInstructions?: boolean;
	// v3.7 options
	filterJunk?: boolean;
	detectVM?: boolean;
	detectPRNG?: boolean;
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
	callers: number;
	callees: number;
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
	filePath: string;
	fileName: string;
	newFunctions: number;
	totalFunctions: number;
	totalStrings: number;
	architecture: string;
	baseAddress: string;
	sections: number;
	imports: number;
	exports: number;
	functions: AnalyzeAllFunctionSummary[];
	strings?: AnalyzeAllStringEntry[];
	reportMarkdown: string;
	// v3.7 analysis data
	junkAnalysis?: { totalInstructions: number; junkCount: number; junkRatio: number };
	vmDetection?: { vmDetected: boolean; vmType: string; dispatcher: string | null; opcodeCount: number; stackArrays: Array<{ base: string; type: string }>; junkRatio: number };
	prngDetection?: { prngDetected: boolean; seedSource: string | null; seedValue: number | null; randCallCount: number; callSites: Array<{ address: string; function: string; context: string }> };
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
}

export interface DisassembleAtResult {
	address: string;         // VA requested in hex
	count: number;           // Requested count
	context: number;         // Requested context
	actualCount: number;     // Total instructions returned (context + main)
	instructions: DisassembleAtInstructionEntry[];
	generatedAt: string;     // ISO 8601 timestamp
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
 * Priority (descending): string > import > function > raw address > empty.
 * User comments are prepended with " | " separator when a reference also exists.
 */
export function resolveInstructionComment(
	instruction: { targetAddress?: number; comment?: string },
	strings: Map<number, { string: string; address: number }>,
	functions: Map<number, { name: string; address: number }>,
	imports: { name: string; functions: { name: string; address: number }[] }[],
	userComments: Map<number, string>,
	instructionAddress: number
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

export function parseDisassembleAtAddress(args: any): { address: number; count: number; context: number; file?: string; output?: { path: string }; quiet?: boolean } {
	// --- address (required, hex string) ---
	const rawAddress: unknown = args?.address;
	if (rawAddress === undefined || rawAddress === null || rawAddress === '') {
		throw new Error("disassembleAtHeadless requires a valid hex 'address' argument (e.g. '0x401000').");
	}
	if (typeof rawAddress !== 'string') {
		throw new Error("disassembleAtHeadless requires a valid hex 'address' argument (e.g. '0x401000').");
	}
	let hexStr = rawAddress;
	if (hexStr.startsWith('0x') || hexStr.startsWith('0X')) {
		hexStr = hexStr.slice(2);
	}
	if (hexStr.length === 0 || !/^[0-9a-fA-F]+$/.test(hexStr)) {
		throw new Error("disassembleAtHeadless requires a valid hex 'address' argument (e.g. '0x401000').");
	}
	const address = parseInt(hexStr, 16);
	if (Number.isNaN(address)) {
		throw new Error("disassembleAtHeadless requires a valid hex 'address' argument (e.g. '0x401000').");
	}

	// --- count (optional, positive integer, default 30) ---
	let count = DEFAULT_COUNT;
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
	if (contextCount <= 0) {
		return [];
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
		return [];
	}

	const allInstructions = await engine.disassembleRange(startAddr, rangeSize);

	// Keep only instructions strictly before the target address
	const beforeTarget = allInstructions.filter(instr => instr.address < targetAddress);

	// Return the last contextCount instructions
	if (beforeTarget.length <= contextCount) {
		return beforeTarget;
	}
	return beforeTarget.slice(beforeTarget.length - contextCount);
}


export function activate(context: vscode.ExtensionContext): void {
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

	const souperWrapper = new SouperWrapper();
	context.subscriptions.push({ dispose: () => souperWrapper.dispose() });
	vscode.commands.executeCommand('setContext', 'hexcore:helixAvailable', helixWrapper.isAvailable());

	let shownExperimentalNotice = false;

	const showNativeStatus = async (): Promise<void> => {
		const disassembler = await engine.getDisassemblerAvailability();
		const assembler = await engine.getAssemblerAvailability();
		const remillAvailable = remillWrapper.isAvailable();
		const rellicAvailable = rellicWrapper.isAvailable();
		const helixAvailable = helixWrapper.isAvailable();

		if (disassembler.available && assembler.available && remillAvailable && rellicAvailable && helixAvailable) {
			vscode.window.showInformationMessage(
				vscode.l10n.t('Native engines are available for this session (Capstone + LLVM MC + Remill + Rellic + Helix).')
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
		if (!rellicAvailable) {
			parts.push(
				vscode.l10n.t('Rellic: {0}', rellicWrapper.getLastError() ?? vscode.l10n.t('Unavailable'))
			);
		}
		if (!helixAvailable) {
			parts.push(
				vscode.l10n.t('Helix: {0}', helixWrapper.getLastError() ?? vscode.l10n.t('Unavailable'))
			);
		}

		vscode.window.showWarningMessage(
			vscode.l10n.t('Native engine status: {0}', parts.join(' | '))
		);
	};

	const pipelineRunner = new AutomationPipelineRunner();
	const pendingJobRuns = new Map<string, NodeJS.Timeout>();
	const activeJobRuns = new Set<string>();
	const queuedAutoRuns = new Set<string>();

	const executePipelineJob = async (
		jobFilePath: string,
		quiet: boolean,
		autoTriggered: boolean
	): Promise<PipelineRunStatus | undefined> => {
		const normalizedPath = path.resolve(jobFilePath);
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

	const runPipelineJob = async (arg?: vscode.Uri | string | RunJobCommandOptions): Promise<PipelineRunStatus | undefined> => {
		const options = normalizeRunJobCommandOptions(arg);
		const quiet = options.quiet ?? false;
		const jobFilePath = resolveJobFilePath(arg, options.jobFile);
		if (!jobFilePath) {
			if (!quiet) {
				vscode.window.showWarningMessage('No .hexcore_job.json file was found.');
			}
			return undefined;
		}

		return executePipelineJob(jobFilePath, quiet, false);
	};

	const scheduleJobRun = (jobFilePath: string): void => {
		const normalizedPath = path.resolve(jobFilePath);
		const existing = pendingJobRuns.get(normalizedPath);
		if (existing) {
			clearTimeout(existing);
		}
		if (activeJobRuns.has(normalizedPath)) {
			queuedAutoRuns.add(normalizedPath);
			return;
		}

		const timeoutHandle = setTimeout(() => {
			pendingJobRuns.delete(normalizedPath);
			executePipelineJob(normalizedPath, true, true).catch(error => {
				console.error('HexCore pipeline auto-run failed:', error);
			});
		}, 350);
		pendingJobRuns.set(normalizedPath, timeoutHandle);
	};

	const autoRunExistingJobs = (): void => {
		const folders = vscode.workspace.workspaceFolders ?? [];
		for (const folder of folders) {
			// Primary: check for .hexcore_job.json (the canonical name)
			const jobFilePath = path.join(folder.uri.fsPath, '.hexcore_job.json');
			if (fs.existsSync(jobFilePath)) {
				scheduleJobRun(jobFilePath);
			}
			// Also scan for named jobs (*.hexcore_job.json) in workspace root
			try {
				const files = fs.readdirSync(folder.uri.fsPath);
				for (const file of files) {
					if (file.endsWith('.hexcore_job.json') && file !== '.hexcore_job.json') {
						const namedJobPath = path.join(folder.uri.fsPath, file);
						scheduleJobRun(namedJobPath);
					}
				}
			} catch {
				// Non-fatal
			}
		}
	};

	// Sync tree views when editor changes
	onDidChangeActiveEditor.event(() => {
		functionProvider.refresh();
		stringRefProvider.refresh();
		sectionProvider.refresh();
		importProvider.refresh();
		exportProvider.refresh();
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
				return capabilities;
			}
			showCapabilitiesInOutputChannel(capabilities);
			return capabilities;
		}),
		vscode.commands.registerCommand('hexcore.pipeline.validateJob', async (arg?: vscode.Uri | string | ValidateJobCommandOptions) => {
			const options = normalizeValidateJobCommandOptions(arg);
			const quiet = options.quiet ?? false;
			const jobFilePath = resolveJobFilePath(arg, options.jobFile);
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

			return report;
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
		vscode.commands.registerCommand('hexcore.pipeline.queueJob', async (arg?: { jobFile?: string; priority?: JobPriority; quiet?: boolean }) => {
			const jobFilePath = arg?.jobFile
				? path.resolve(arg.jobFile)
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
			const manager = getJobQueueManagerInstance();
			const jobId = manager.queueJob(jobFilePath, priority);

			if (!arg?.quiet) {
				vscode.window.showInformationMessage(`Job queued with ID: ${jobId} (priority: ${priority})`);
			}

			return { jobId, filePath: jobFilePath, priority };
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
		vscode.commands.registerCommand('hexcore.pipeline.jobStatus', async (arg?: { jobId?: string; quiet?: boolean }) => {
			const manager = getJobQueueManagerInstance();

			if (arg?.jobId) {
				const job = manager.getJobStatus(arg.jobId);
				if (!arg.quiet) {
					if (job) {
						showJobStatusInOutputChannel(job);
					} else {
						vscode.window.showWarningMessage(`Job not found: ${arg.jobId}`);
					}
				}
				return job;
			}

			const allJobs = manager.getAllJobs();
			const stats = manager.getQueueStats();

			if (!arg?.quiet) {
				showQueueStatusInOutputChannel(allJobs, stats);
			}

			return { jobs: allJobs, stats };
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

				if (func && func.instructions.length > 0) {
					// Auto-focus the graph view and show CFG
					try {
						await vscode.commands.executeCommand('hexcore.disassembler.graphView.focus');
					} catch {
						// View may not be visible yet, that's ok
					}
					graphViewProvider.showFunction(func);
				}
			}
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
			if (arg && typeof arg === 'object' && 'address' in arg && 'returnType' in arg) {
				const addr = typeof arg.address === 'string' ? parseInt(arg.address, 16) : arg.address;
				engine.retypeFunction(addr, arg.returnType);
				return { success: true };
			}
			const addr = arg?.address || disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}
			const returnType = await vscode.window.showInputBox({ prompt: 'Function return type:', value: 'int' });
			if (returnType) {
				engine.retypeFunction(addr, returnType);
				disasmEditorProvider.refresh();
				vscode.window.showInformationMessage(`Return type → ${returnType}`);
			}
		})
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
			const addr = disasmEditorProvider.getCurrentFunctionAddress();
			if (addr === undefined) {
				vscode.window.showWarningMessage('No function selected');
				return;
			}

			const func = engine.getFunctionAt(addr);
			if (func) {
				// Focus the graph view
				await vscode.commands.executeCommand('hexcore.disassembler.graphView.focus');
				// Render the graph
				graphViewProvider.showFunction(func);
			} else {
				vscode.window.showErrorMessage('Function data not found');
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
				await engine.exportAssembly(uri.fsPath);
				vscode.window.showInformationMessage(`Assembly exported to ${uri.fsPath}`);
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

			const arch = engine.getArchitecture();
			const mapping = mapCapstoneToRemill(arch);
			if (!mapping.supported) {
				const errorMsg = `Architecture '${arch}' is not supported by Remill. Supported: x86, x64, arm64.`;
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
					// v3.7.5 FIX-022: For PE files, try function table FIRST (forceProbe=false).
					// Only fall back to byte-level probe for ET_REL (.ko) where the function
					// table may have incorrect entries. forceProbe=true was causing regressions
					// on PE64 (ROTTR) by backtracking into adjacent functions' prologues.
					const isRelocatable = engine.getFileInfo()?.isRelocatable === true;
					const funcStart = await engine.findFunctionStartForAddress(startAddress, isRelocatable);
					if (funcStart !== undefined && funcStart !== startAddress) {
						// FIX-022c: Validate backtrack with Capstone linear sweep.
						// Decode instructions from candidate to original address. If we hit
						// a RET, INT3 padding, or decode failure before reaching the original,
						// the candidate is a DIFFERENT function — discard the backtrack.
						const dist = startAddress - funcStart;
						if (dist > 0 && dist <= 4096) {
							const valid = await validateBacktrackCandidate(engine, funcStart, startAddress);
							if (valid) {
								startAddress = funcStart;
								didBacktrack = true;
							} else {
								console.log(`[HexCore] liftToIR FIX-022c: Backtrack 0x${startAddress.toString(16)} -> 0x${funcStart.toString(16)} REJECTED (linear sweep found function boundary in ${dist}-byte gap)`);
							}
						} else if (dist > 4096) {
							console.log(`[HexCore] liftToIR FIX-022c: Discarding backtrack 0x${startAddress.toString(16)} -> 0x${funcStart.toString(16)} (${dist} bytes > 4096 limit)`);
						}
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
				if (typeof options.size === 'number') {
					size = options.size;
				} else if (typeof options.count === 'number') {
					// v3.7.5 FIX: Use the larger of count*15 and the actual symbol size.
					const countEstimate = options.count * 15;
					const symbolSize = engine.getRecommendedLiftSize(startAddress, 0);
					size = symbolSize > 0 ? Math.max(countEstimate, symbolSize) : countEstimate;
				} else {
					size = engine.getBufferSize();
				}
			} else if (isHeadless && options.functionAddress !== undefined) {
				startAddress = typeof options.functionAddress === 'number' ? options.functionAddress : 0;
				// Auto-backtrack: find real function start if address is mid-function
				backtrackOriginalAddress = startAddress;
				if (options.autoBacktrack !== false) {
					// v3.7.5 FIX-022: forceProbe only for ET_REL (see address path above)
					const isRelocatable2 = engine.getFileInfo()?.isRelocatable === true;
					const funcStart = await engine.findFunctionStartForAddress(startAddress, isRelocatable2);
					if (funcStart !== undefined && funcStart !== startAddress) {
						const dist2 = startAddress - funcStart;
						if (dist2 > 0 && dist2 <= 4096) {
							const valid2 = await validateBacktrackCandidate(engine, funcStart, startAddress);
							if (valid2) {
								startAddress = funcStart;
								didBacktrack = true;
							} else {
								console.log(`[HexCore] liftToIR FIX-022c: Backtrack 0x${startAddress.toString(16)} -> 0x${funcStart.toString(16)} REJECTED (linear sweep found boundary in ${dist2}-byte gap)`);
							}
						} else if (dist2 > 4096) {
							console.log(`[HexCore] liftToIR FIX-022c: Discarding backtrack (${dist2} bytes > 4096 limit)`);
						}
					}
				}
				const func = engine.getFunctionAt(startAddress);
				if (func) {
					size = func.endAddress - func.address;
					functionName = func.name;
				} else {
					// v3.7.5 FIX: Smart sizing — symbol table → count → 4096 (was 256)
					if (typeof options.size === 'number') {
						size = options.size;
					} else if (typeof options.count === 'number') {
						size = options.count * 15;
					} else {
						size = engine.getRecommendedLiftSize(startAddress, 4096);
					}
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
			}

			// Extract bytes from engine buffer (addressToOffset handles VA→file offset)
			if (!engine.isFileLoaded()) {
				const errorMsg = 'No binary file is loaded. Open a file in the disassembler first.';
				if (quiet) {
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
				if (quiet) {
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
				const firstBytes = Array.from(bytes.subarray(0, Math.min(16, bytes.length))).map(b => b.toString(16).padStart(2, '0')).join(' ');
				console.log(`[HexCore] liftToIR FIX-017 probe: addr=0x${startAddress.toString(16)} first16=[${firstBytes}] len=${bytes.length}`);
				let skip = 0;
				// endbr64: F3 0F 1E FA (4 bytes)
				if (bytes.length >= skip + 4 &&
					bytes[skip] === 0xF3 && bytes[skip + 1] === 0x0F &&
					bytes[skip + 2] === 0x1E && bytes[skip + 3] === 0xFA) {
					skip += 4;
				}
				// endbr32: F3 0F 1E FB (4 bytes)
				else if (bytes.length >= skip + 4 &&
					bytes[skip] === 0xF3 && bytes[skip + 1] === 0x0F &&
					bytes[skip + 2] === 0x1E && bytes[skip + 3] === 0xFB) {
					skip += 4;
				}
				// call __fentry__ / call +0 (ftrace NOP): E8 00 00 00 00 (5 bytes)
				if (bytes.length >= skip + 5 &&
					bytes[skip] === 0xE8 &&
					bytes[skip + 1] === 0x00 && bytes[skip + 2] === 0x00 &&
					bytes[skip + 3] === 0x00 && bytes[skip + 4] === 0x00) {
					skip += 5;
				}
				// Multi-byte NOP sled (66 0F 1F 84 00 00 00 00 00 = 9-byte NOP)
				if (bytes.length >= skip + 2 && bytes[skip] === 0x66 && bytes[skip + 1] === 0x0F) {
					// Skip the NOP (variable length: 2-9 bytes)
					const nopLens = [2, 3, 4, 5, 6, 7, 8, 9];
					for (const len of nopLens) {
						if (bytes.length >= skip + len && bytes[skip] === 0x66 && bytes[skip + 1] === 0x0F && bytes[skip + 2] === 0x1F) {
							skip += len;
							break;
						}
					}
				}

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

				// Kernel infrastructure — NOPs at runtime, skip patching
				const infraSymbols = new Set([
					'__fentry__', '__x86_return_thunk', '__cfi_check',
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

			if (fmt === 'PE' || fmt === 'PE64') {
				liftOpts.liftMode = 'pe64';
				// Collect function end addresses from .pdata for the lifted range
				const allFuncs = engine.getFunctions();
				const endAddr = startAddress + bytes.length;
				const knownEnds: number[] = [];
				const nearbyLeaders: number[] = [];
				for (const fn of allFuncs) {
					if (fn.endAddress > startAddress && fn.address < endAddr) {
						if (fn.endAddress > startAddress && fn.endAddress <= endAddr) {
							knownEnds.push(fn.endAddress);
						}
						// Function starts within our range are additional leaders
						if (fn.address > startAddress && fn.address < endAddr) {
							nearbyLeaders.push(fn.address);
						}
					}
				}
				if (knownEnds.length > 0) { liftOpts.knownFunctionEnds = knownEnds; }
				if (nearbyLeaders.length > 0) { liftOpts.additionalLeaders = nearbyLeaders; }
			} else if (fileInfo?.isRelocatable) {
				liftOpts.liftMode = 'elf_relocatable';
				// ELF symtab: function addresses within lift range as additional leaders
				const allFuncs = engine.getFunctions();
				const endAddr = startAddress + bytes.length;
				const symLeaders: number[] = [];
				for (const fn of allFuncs) {
					if (fn.address > startAddress && fn.address < endAddr) {
						symLeaders.push(fn.address);
					}
				}
				if (symLeaders.length > 0) { liftOpts.additionalLeaders = symLeaders; }
			}

			// v3.8.0 Pathfinder: inject .pdata function boundaries as CFG hints
			// This gives the Remill lifter EXACT function boundaries from PE64 metadata,
			// dramatically improving basic block discovery and tail call detection.
			try {
				const cfgHints = await runPathfinder(engine, startAddress, bytes);
				if (cfgHints.confidence > 0) {
					// Merge Pathfinder hints with existing leaders
					const existingLeaders = liftOpts.additionalLeaders ?? [];
					const existingEnds = liftOpts.knownFunctionEnds ?? [];

					// Add Pathfinder leaders (other function starts near our target)
					const mergedLeaders = new Set([...existingLeaders, ...cfgHints.leaders]);
					liftOpts.additionalLeaders = [...mergedLeaders].sort((a, b) => a - b);

					// Add function end boundaries from .pdata
					if (cfgHints.functionEnds.length > 0) {
						const mergedEnds = new Set([...existingEnds, ...cfgHints.functionEnds]);
						liftOpts.knownFunctionEnds = [...mergedEnds].sort((a, b) => a - b);
					}

					if (!quiet) {
						const pdataCount = getPdataFunctionCount(engine);
						console.log(`[pathfinder] CFG hints: ${cfgHints.leaders.length} leaders, ${cfgHints.functionEnds.length} ends, ${cfgHints.tailCalls.length} tail-calls, ${cfgHints.instructionsDecoded} insns decoded, confidence=${cfgHints.confidence}% (.pdata: ${pdataCount} functions)`);
					}
				}
			} catch (pfErr) {
				// Non-fatal: Pathfinder failure doesn't block lifting
				console.warn('[pathfinder] CFG analysis failed, continuing without hints:', pfErr);
			}

			// Perform lifting with progress indicator
			const liftResult = await vscode.window.withProgress(
				{
					location: vscode.ProgressLocation.Notification,
					title: '[Experimental] Lifting to LLVM IR...',
					cancellable: false,
				},
				async () => {
					return remillWrapper.liftBytes(bytes, startAddress, arch, targetOs, liftOpts);
				}
			);

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

			const fileName = engine.getFilePath() ? path.basename(engine.getFilePath()!) : 'unknown';
			const header = buildIRHeader({
				fileName,
				address: startAddress,
				size,
				architecture: mapping.remillArch,
				functionName,
			});

			const fullIR = header + processedIR;

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
				fs.writeFileSync(outputPath, fullIR, 'utf-8');
				return {
					success: true,
					ir: fullIR,
					address: startAddress,
					bytesConsumed: liftResult.bytesConsumed,
					architecture: mapping.remillArch,
					functionName,
					backtracked: didBacktrack,
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
				if (typeof options.size === 'number') {
					size = options.size;
				} else if (typeof options.count === 'number') {
					// v3.7.5 FIX: Use the larger of count*15 and the actual symbol size.
					const countEstimate = options.count * 15;
					const symbolSize = engine.getRecommendedLiftSize(startAddress, 0);
					size = symbolSize > 0 ? Math.max(countEstimate, symbolSize) : countEstimate;
				} else {
					size = engine.getBufferSize();
				}
			} else if (isHeadless && options.functionAddress !== undefined) {
				startAddress = typeof options.functionAddress === 'number' ? options.functionAddress : 0;
				const func = engine.getFunctionAt(startAddress);
				if (func) {
					size = func.endAddress - func.address;
					functionName = func.name;
				} else {
					// v3.7.5 FIX: Smart sizing — symbol table → count → 4096 (was 256)
					if (typeof options.size === 'number') {
						size = options.size;
					} else if (typeof options.count === 'number') {
						size = options.count * 15;
					} else {
						size = engine.getRecommendedLiftSize(startAddress, 4096);
					}
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

			const bytes = engine.getBytes(startAddress, size);
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

			const decompLiftOpts: RemillLiftOptions = {};
			if (fmtForOs === 'PE' || fmtForOs === 'PE64') {
				decompLiftOpts.liftMode = 'pe64';
				const allFuncs = engine.getFunctions();
				const endAddr = startAddress + bytes.length;
				const knownEnds: number[] = [];
				const nearbyLeaders: number[] = [];
				for (const fn of allFuncs) {
					if (fn.endAddress > startAddress && fn.address < endAddr) {
						if (fn.endAddress > startAddress && fn.endAddress <= endAddr) {
							knownEnds.push(fn.endAddress);
						}
						if (fn.address > startAddress && fn.address < endAddr) {
							nearbyLeaders.push(fn.address);
						}
					}
				}
				if (knownEnds.length > 0) { decompLiftOpts.knownFunctionEnds = knownEnds; }
				if (nearbyLeaders.length > 0) { decompLiftOpts.additionalLeaders = nearbyLeaders; }
			} else if (fileInfoDecomp?.isRelocatable) {
				decompLiftOpts.liftMode = 'elf_relocatable';
				const allFuncs = engine.getFunctions();
				const endAddr = startAddress + bytes.length;
				const symLeaders: number[] = [];
				for (const fn of allFuncs) {
					if (fn.address > startAddress && fn.address < endAddr) {
						symLeaders.push(fn.address);
					}
				}
				if (symLeaders.length > 0) { decompLiftOpts.additionalLeaders = symLeaders; }
			}

			// v3.8.0 Pathfinder: inject .pdata CFG hints (same as liftToIR path)
			try {
				const cfgHints = await runPathfinder(engine, startAddress, bytes);
				if (cfgHints.confidence > 0) {
					const existingLeaders = decompLiftOpts.additionalLeaders ?? [];
					const existingEnds = decompLiftOpts.knownFunctionEnds ?? [];
					const mergedLeaders = new Set([...existingLeaders, ...cfgHints.leaders]);
					decompLiftOpts.additionalLeaders = [...mergedLeaders].sort((a, b) => a - b);
					if (cfgHints.functionEnds.length > 0) {
						const mergedEnds = new Set([...existingEnds, ...cfgHints.functionEnds]);
						decompLiftOpts.knownFunctionEnds = [...mergedEnds].sort((a, b) => a - b);
					}
				}
			} catch {
				// Non-fatal
			}

			const liftResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: '[Experimental] Lifting to LLVM IR...', cancellable: false },
				async () => remillWrapper.liftBytes(bytes, startAddress, arch, targetOsForLift, decompLiftOpts)
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

		// 1. Try BTF first (fast, compact)
		if (elfAnalysis.btfData) {
			const scoped = getStructInfoForFunction(funcName, elfAnalysis.btfData);
			if (scoped && Object.keys(scoped.structs).length > 0) {
				return { structInfo: scoped, functionName: funcName };
			}
		}

		// 2. Fallback to DWARF (pre-loaded by engine during analyzeELF)
		if (elfAnalysis.dwarfStructInfo) {
			const cache = elfAnalysis.dwarfStructInfo;
			const funcSig = cache.functions[funcName];
			if (!funcSig) { return null; }

			const relevantStructs: Record<string, StructInfo> = {};
			for (const param of funcSig.params) {
				if (param.structName && cache.structs[param.structName]) {
					relevantStructs[param.structName] = cache.structs[param.structName];
					// One level of nested structs
					for (const field of cache.structs[param.structName].fields) {
						const nestedMatch = field.type.match(/^struct\s+(\w+)$/);
						if (nestedMatch && cache.structs[nestedMatch[1]]) {
							relevantStructs[nestedMatch[1]] = cache.structs[nestedMatch[1]];
						}
					}
				}
			}

			if (Object.keys(relevantStructs).length === 0) { return null; }

			return {
				structInfo: { structs: relevantStructs, functions: { [funcName]: funcSig } },
				functionName: funcName,
			};
		}

		return null;
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
			if (!capstone) { return true; } // can't validate, assume ok

			const insns = await capstone.disassemble(bytes, candidate, 512);
			if (!insns || insns.length === 0) { return false; }

			for (const insn of insns) {
				const insnEnd = insn.address + insn.size;

				// Reached or passed the original address — valid backtrack
				if (insnEnd >= original) { return true; }

				// RET instruction — function ended before reaching original
				if (insn.mnemonic === 'ret' || insn.mnemonic === 'retf' ||
					insn.mnemonic === 'retfq') {
					return false;
				}

				// INT3 (0xCC) — padding between functions
				if (insn.mnemonic === 'int3') {
					// Check if next byte is also INT3 (CC CC = inter-function padding)
					const nextOff = insnEnd - candidate;
					if (nextOff < bytes.length && bytes[nextOff] === 0xCC) {
						return false;
					}
				}

				// Unconditional JMP to outside the [candidate, original] range
				if (insn.mnemonic === 'jmp') {
					// If it's a short/near jump, check target
					const target = insn.targetAddress;
					if (target !== undefined && (target < candidate || target > original + 64)) {
						return false;
					}
				}
			}

			// Ran out of instructions without reaching original — suspicious
			return false;
		} catch {
			// Capstone error — can't validate, be conservative and reject
			return false;
		}
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
					console.log(`[souper] Optimized: ${result.candidatesReplaced}/${result.candidatesFound} candidates in ${result.optimizationTimeMs.toFixed(0)}ms`);
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
				candidatesReplaced: result.candidatesReplaced,
				optimizationTimeMs: result.optimizationTimeMs,
				error: result.error || '',
			};
		})
	);

	// -----------------------------------------------------------------------
	// Helix — Decompile IR to pseudo-C (direct IR input)
	// -----------------------------------------------------------------------
	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.helix.decompileIR', async (arg?: unknown) => {
			const isHeadless = arg !== null && arg !== undefined && typeof arg === 'object'
				&& !((arg as any) instanceof vscode.Uri)
				&& ('file' in (arg as Record<string, unknown>) || 'irText' in (arg as Record<string, unknown>));

			const options = isHeadless ? arg as Record<string, unknown> : {};
			const quiet = options.quiet === true;
			const arch = engine.getArchitecture();

			if (!helixWrapper.isAvailable()) {
				const errorMsg = 'hexcore-helix is not available.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
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
					if (quiet) {
						return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
					}
					vscode.window.showErrorMessage(errorMsg);
					return undefined;
				}
				irText = fs.readFileSync(resolved, 'utf-8');
			} else if (isHeadless && typeof options.file === 'string') {
				if (!fs.existsSync(options.file)) {
					const errorMsg = `File not found: ${options.file}`;
					if (quiet) {
						return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
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

			// Pass optimizeIR + useCastLayer options to Helix (v3.7.4)
			// NOTE: must be `let` — sessionRenames and structInfo may promote it from undefined → {}
			let helixIROptions: {
				optimizeIR?: boolean; useCastLayer?: boolean;
				variableRenames?: Array<{ oldName: string; newName: string }>;
				structInfo?: StructInfoJson; functionName?: string;
			} | undefined =
				isHeadless && (options.optimizeIR !== undefined || options.useCastLayer !== undefined)
					? {
						...(options.optimizeIR !== undefined ? { optimizeIR: options.optimizeIR !== false } : {}),
						...(options.useCastLayer !== undefined ? { useCastLayer: options.useCastLayer === true } : {}),
					}
					: undefined;

			// v3.7.5 P3: Collect session variable renames for this function and pass
			// them to the Helix engine so the C AST walker can apply them surgically.
			const sessionRenames = collectSessionVariableRenames(options, engine);
			if (sessionRenames.length > 0) {
				helixIROptions = helixIROptions ?? {};
				helixIROptions.variableRenames = sessionRenames;
			}

			// v3.8.0: Extract struct field info from BTF for struct field naming
			const funcAddr = parseAddressValue(options.functionAddress as string | number | undefined)
				?? parseAddressValue(options.address as string | number | undefined)
				?? parseAddressValue(options.startAddress as string | number | undefined)
				?? parseAddressValue(options.targetAddress as string | number | undefined);
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
			const structResult = options.structInfo !== false
				? extractStructInfoForFunction(engine, funcAddr, explicitFuncName)
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
			if (souperWrapper.isAvailable() && options.souper !== false) {
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

			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Helix: Decompiling IR...', cancellable: false },
				async () => helixWrapper.decompileIr(irForHelix, arch, helixIROptions ?? (sessionRenames.length > 0 ? { variableRenames: sessionRenames } : undefined))
			);

			if (!decompileResult.success) {
				const errorMsg = `Helix decompilation failed: ${decompileResult.error}`;
				console.error(`[hexcore-helix] decompileIR failed:`, decompileResult.error);
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: decompileResult.error };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Apply Session DB renames/retypes (funcAddress from options if available)
			const decompileAddr = parseAddressValue(options.functionAddress as string | number | undefined)
				?? parseAddressValue(options.address as string | number | undefined);
			let fullCode = applySessionRenames(decompileResult.source, decompileAddr);

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

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			if (quiet) {
				return {
					success: true,
					code: fullCode,
					functionCount: decompileResult.instructionCount,
					address: decompileResult.entryAddress,
					architecture: arch,
					error: '',
				};
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return {
				success: true,
				code: fullCode,
				functionCount: decompileResult.instructionCount,
				address: decompileResult.entryAddress,
				architecture: arch,
				error: '',
			};
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
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			if (!helixWrapper.isAvailable()) {
				const errorMsg = 'hexcore-helix is not available. Install the prebuild or build from source.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Lift machine code to LLVM IR via liftToIR command
			const liftResult: LiftResult | undefined = await vscode.commands.executeCommand(
				'hexcore.disasm.liftToIR', { ...options, quiet: true, output: undefined }
			);

			if (!liftResult || !liftResult.success) {
				const errorMsg = liftResult?.error ?? 'Lift failed.';
				if (quiet) {
					return { success: false, code: '', functionCount: 0, address: '', architecture: arch, error: errorMsg };
				}
				vscode.window.showErrorMessage(errorMsg);
				return undefined;
			}

			// Pass optimizeIR + useCastLayer options to Helix
			// NOTE: must be `let` — sessionRenames and structInfo may promote it from undefined → {}
			let helixOptions: {
				optimizeIR?: boolean; useCastLayer?: boolean;
				variableRenames?: Array<{ oldName: string; newName: string }>;
				structInfo?: StructInfoJson; functionName?: string;
			} | undefined =
				isHeadless && (options.optimizeIR !== undefined || options.useCastLayer !== undefined)
					? {
						...(options.optimizeIR !== undefined ? { optimizeIR: options.optimizeIR !== false } : {}),
						...(options.useCastLayer !== undefined ? { useCastLayer: options.useCastLayer === true } : {}),
					}
					: undefined;

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
			const structResult2 = options.structInfo !== false
				? extractStructInfoForFunction(engine, funcAddr2, typeof options.functionName === 'string' ? options.functionName : undefined)
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
			if (souperWrapper.isAvailable() && options.souper !== false) {
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

			const decompileResult = await vscode.window.withProgress(
				{ location: vscode.ProgressLocation.Notification, title: 'Helix: Decompiling...', cancellable: false },
				async () => helixWrapper.decompileIr(irForHelix2, arch, helixOptions ?? (sessionRenames2.length > 0 ? { variableRenames: sessionRenames2 } : undefined))
			);

			if (!decompileResult.success) {
				const errorMsg = `Helix decompilation failed: ${decompileResult.error}`;
				console.error(`[hexcore-helix] decompile failed:`, decompileResult.error);
				if (quiet) {
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
			const fullCode = applySessionRenames(decompileResult.source, funcAddr, origAddr);

			if (isHeadless && options.output) {
				const outputPath = typeof options.output === 'string' ? options.output : (options.output as { path: string }).path;
				fs.writeFileSync(outputPath, fullCode, 'utf-8');
			}

			if (quiet) {
				return {
					success: true,
					code: fullCode,
					functionCount: decompileResult.instructionCount,
					address: decompileResult.entryAddress || String(liftResult.address || ''),
					architecture: arch,
					error: '',
				};
			}

			const doc = await vscode.workspace.openTextDocument({ content: fullCode, language: 'c' });
			await vscode.window.showTextDocument(doc, { preview: false, viewColumn: vscode.ViewColumn.Beside });
			await vscode.commands.executeCommand('workbench.action.files.setActiveEditorReadonlyInSession');

			return {
				success: true,
				code: fullCode,
				functionCount: decompileResult.instructionCount,
				address: decompileResult.entryAddress || String(liftResult.address || ''),
				architecture: arch,
				error: '',
			};
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

			// Output to file if path specified
			if (typeof options.output === 'string') {
				fs.writeFileSync(options.output, jsonText, 'utf-8');
				if (!quiet) {
					vscode.window.showInformationMessage(
						`Struct info exported: ${Object.keys(result.structs).length} structs, ${Object.keys(result.functions).length} functions → ${options.output}`
					);
				}
				return { success: true, path: options.output, structCount: Object.keys(result.structs).length, functionCount: Object.keys(result.functions).length };
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

			const runAnalysis = async (progress?: vscode.Progress<{ message?: string }>): Promise<number> => {
				engine.reloadConfig();
				const currentFile = engine.getFilePath();
				const forceReload = shouldForceReloadAnalyzeAll(options);
				if (forceReload || currentFile !== targetFilePath) {
					progress?.report({ message: `Loading ${path.basename(targetFilePath)}...` });
					const loaded = await engine.loadFile(targetFilePath);
					if (!loaded) {
						throw new Error(`Failed to load file: ${targetFilePath}`);
					}
				}

				const defaultLimits = engine.getAnalysisLimits();
				const requestedLimits = resolveAnalyzeAllLimits(options);
				const overrideMaxFunctions = requestedLimits.maxFunctions ?? defaultLimits.maxFunctions;
				const overrideMaxFunctionSize = requestedLimits.maxFunctionSize ?? defaultLimits.maxFunctionSize;
				const hasOverride = overrideMaxFunctions !== defaultLimits.maxFunctions
					|| overrideMaxFunctionSize !== defaultLimits.maxFunctionSize;

				if (hasOverride) {
					engine.setAnalysisLimits(overrideMaxFunctions, overrideMaxFunctionSize);
					progress?.report({
						message: `Applying limits (maxFunctions=${overrideMaxFunctions}, maxFunctionSize=${overrideMaxFunctionSize})...`
					});
				}

				try {
					progress?.report({ message: 'Scanning for function prologs and references...' });
					return engine.analyzeAll({ filterJunk: options.filterJunk, detectVM: options.detectVM });
				} finally {
					if (hasOverride) {
						engine.setAnalysisLimits(defaultLimits.maxFunctions, defaultLimits.maxFunctionSize);
					}
				}
			};

			const newFunctions = options.quiet
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

			const result = createAnalyzeAllResult(engine, targetFilePath, newFunctions, options.includeInstructions === true, {
				filterJunk: options.filterJunk,
				detectVM: options.detectVM,
				detectPRNG: options.detectPRNG
			});
			if (options.output) {
				writeAnalyzeAllOutput(result, options.output);
			}

			if (!options.quiet) {
				vscode.window.showInformationMessage(
					`Analysis complete: ${result.newFunctions} new functions found (${result.totalFunctions} total)`
				);
			}

			return result;
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
				const existingFunc = engine.getFunctionAt(params.address);
				if (!existingFunc) {
					// Address not recognized as a function start — try to find one
					const funcStart = await engine.findFunctionStartForAddress(params.address);
					if (funcStart !== undefined && funcStart !== params.address) {
						effectiveAddress = funcStart;
					}
				}
			}

			// 4. Determine max instruction size from architecture
			const arch = engine.getArchitecture();
			const maxInstructionSize = (arch === 'arm' || arch === 'arm64')
				? MAX_INSTRUCTION_SIZE_ARM
				: MAX_INSTRUCTION_SIZE_X86;

			// 5. Compute context instructions (before target address)
			let contextInstructions: Instruction[] = [];
			if (params.context > 0) {
				contextInstructions = await computeContextInstructions(
					engine, params.address, params.context, maxInstructionSize
				);
			}

			// 6. Disassemble main instructions (use effectiveAddress for backtrack)
			const estimatedSize = params.count * maxInstructionSize;
			const rawMainInstructions = await engine.disassembleRange(effectiveAddress, estimatedSize);
			const mainInstructions = rawMainInstructions.slice(0, params.count);

			// 7. Prepare reference maps for comment resolution
			const stringsMap = engine.getStringsMap();
			const functionsMap = engine.getFunctionsMap();
			const importsArray = engine.getImports();
			const commentsMap = engine.getComments();

			// 8. Format all instructions (context + main)
			const allEntries: DisassembleAtInstructionEntry[] = [];

			for (const instr of contextInstructions) {
				const comment = resolveInstructionComment(
					instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address
				);
				allEntries.push({
					address: `0x${instr.address.toString(16).toUpperCase()}`,
					bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
					mnemonic: instr.mnemonic,
					operands: instr.opStr,
					comment,
					size: instr.size,
					isContext: true,
				});
			}

			for (const instr of mainInstructions) {
				const comment = resolveInstructionComment(
					instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address
				);
				allEntries.push({
					address: `0x${instr.address.toString(16).toUpperCase()}`,
					bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
					mnemonic: instr.mnemonic,
					operands: instr.opStr,
					comment,
					size: instr.size,
					isContext: false,
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
						instr, stringsMap, functionsMap, importsArray, commentsMap, instr.address
					);
					filteredEntries.push({
						address: `0x${instr.address.toString(16).toUpperCase()}`,
						bytes: Array.from(instr.bytes).map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' '),
						mnemonic: instr.mnemonic,
						operands: instr.opStr,
						comment,
						size: instr.size,
						isContext: false,
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

			// 9. Build result JSON
			const result: DisassembleAtResult & { filteredInstructions?: DisassembleAtInstructionEntry[]; junkAnalysis?: { junkCount: number; junkRatio: number }; junkCount?: number; junkRatio?: number; vmDetection?: typeof vmDetection; prngDetection?: typeof prngDetection } = {
				address: `0x${params.address.toString(16).toUpperCase()}`,
				count: params.count,
				context: params.context,
				actualCount: allEntries.length,
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
					matches: Array<{
						address: string;
						string: string;
						encoding: string;
						references: string[];
					}>;
				}> = [];

				// Deduplicate queries to avoid redundant searches
				const uniqueQueries = [...new Set(batchQueries)];

				for (const q of uniqueQueries) {
					const results = await engine.searchStringReferences(q);
					batchResults.push({
						query: q,
						totalMatches: results.length,
						matches: results.map((sr: any) => ({
							address: toHexAddress(sr.address),
							string: sr.string,
							encoding: sr.encoding,
							references: sr.references.map((addr: number) => toHexAddress(addr)),
							query: q
						}))
					});
				}

				const totalMatches = batchResults.reduce((sum, r) => sum + r.totalMatches, 0);

				const exportData = {
					mode: 'batch' as const,
					queriesCount: uniqueQueries.length,
					totalMatches,
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
			const results = await engine.searchStringReferences(singleQuery!);

			const exportData = {
				query: singleQuery,
				totalMatches: results.length,
				matches: results.map((sr: any) => ({
					address: toHexAddress(sr.address),
					string: sr.string,
					encoding: sr.encoding,
					references: sr.references.map((addr: number) => toHexAddress(addr))
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

			if (functionAddress !== undefined && !isNaN(functionAddress)) {
				// Export single function
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
			} else {
				// Export all functions
				await engine.exportAssembly(outputPath);
			}

			if (!quietMode) {
				const label = functionAddress !== undefined
					? `function at 0x${functionAddress.toString(16).toUpperCase()}`
					: 'all functions';
				vscode.window.showInformationMessage(`Assembly exported (${label}) to ${outputPath}`);
			}

			return { outputPath, generatedAt: new Date().toISOString() };
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

			let source: string;
			try {
				source = fs.readFileSync(rawInput, 'utf8');
			} catch (err: unknown) {
				const message = err instanceof Error ? err.message : String(err);
				throw new Error(`refcountScan: failed to read ${rawInput}: ${message}`);
			}

			const report: RefcountAuditReport = auditRefcount(source, rawInput);

			if (outputPath) {
				fs.mkdirSync(path.dirname(outputPath), { recursive: true });
				fs.writeFileSync(outputPath, JSON.stringify(report, null, 2), 'utf8');
			}

			if (!quietMode) {
				const critical = report.findings.filter(f => f.severity === 'high').length;
				const badge = critical > 0 ? `🔴 ${critical} high-severity` : report.summary.total > 0 ? `🟡 ${report.summary.total} finding(s)` : '🟢 Clean';
				vscode.window.showInformationMessage(
					`${badge} | ${report.functionsScanned} fn scanned | ${report.scanTimeMs}ms`,
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
					isNative: clr.isNative,
					is32BitRequired: clr.is32BitRequired,
					warning: '.NET assembly detected'
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
				'__fentry__', '__x86_return_thunk', '__cfi_check',
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
		let skipBytes = 0;
		if (bytesToLift.length >= 4 &&
			bytesToLift[0] === 0xF3 && bytesToLift[1] === 0x0F &&
			bytesToLift[2] === 0x1E && (bytesToLift[3] === 0xFA || bytesToLift[3] === 0xFB)) {
			skipBytes += 4; // endbr64/endbr32
		}
		if (bytesToLift.length >= skipBytes + 5 &&
			bytesToLift[skipBytes] === 0xE8 &&
			bytesToLift[skipBytes + 1] === 0x00 && bytesToLift[skipBytes + 2] === 0x00 &&
			bytesToLift[skipBytes + 3] === 0x00 && bytesToLift[skipBytes + 4] === 0x00) {
			skipBytes += 5; // call __fentry__
		}

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

	// v3.7 options
	if (raw.filterJunk === true) { normalized.filterJunk = true; }
	if (raw.detectVM === true) { normalized.detectVM = true; }
	if (raw.detectPRNG === true) { normalized.detectPRNG = true; }

	return normalized;
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

function resolveJobFilePath(arg: vscode.Uri | string | RunJobCommandOptions | undefined, explicitPath?: string): string | undefined {
	if (typeof explicitPath === 'string' && explicitPath.length > 0) {
		return path.resolve(explicitPath);
	}

	if (arg instanceof vscode.Uri) {
		return arg.fsPath;
	}

	if (typeof arg === 'string' && arg.length > 0) {
		return path.resolve(arg);
	}

	const folders = vscode.workspace.workspaceFolders ?? [];
	for (const folder of folders) {
		// Primary: canonical .hexcore_job.json
		const candidate = path.join(folder.uri.fsPath, '.hexcore_job.json');
		if (fs.existsSync(candidate)) {
			return candidate;
		}
		// Fallback: first *.hexcore_job.json in workspace root
		try {
			const files = fs.readdirSync(folder.uri.fsPath);
			const namedJob = files.find(f => f.endsWith('.hexcore_job.json'));
			if (namedJob) {
				return path.join(folder.uri.fsPath, namedJob);
			}
		} catch {
			// Non-fatal
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

function createAnalyzeAllResult(engine: DisassemblerEngine, targetFilePath: string, newFunctions: number, includeInstructions: boolean = false, v37Options?: { filterJunk?: boolean; detectVM?: boolean; detectPRNG?: boolean }): AnalyzeAllResult {
	const functions = engine.getFunctions();
	const MAX_INSTRUCTIONS_PER_FUNCTION = 200;

	const functionSummaries: AnalyzeAllFunctionSummary[] = functions.map(func => {
		const summary: AnalyzeAllFunctionSummary = {
			address: toHexAddress(func.address),
			name: func.name,
			size: func.size,
			instructionCount: func.instructions.length,
			callers: func.callers.length,
			callees: func.callees.length
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

	const result: AnalyzeAllResult = {
		filePath: targetFilePath,
		fileName: path.basename(targetFilePath),
		newFunctions,
		totalFunctions: functions.length,
		totalStrings: engine.getStrings().length,
		architecture: engine.getArchitecture(),
		baseAddress: toHexAddress(engine.getBaseAddress()),
		sections: engine.getSections().length,
		imports: engine.getImports().length,
		exports: engine.getExports().length,
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
| **New Functions** | ${result.newFunctions} |
| **Total Functions** | ${result.totalFunctions} |
| **Total Strings** | ${result.totalStrings} |
| **Sections** | ${result.sections} |
| **Imports** | ${result.imports} |
| **Exports** | ${result.exports} |

---

## Functions (Top 100)

| Address | Name | Size | Instructions | Callers | Callees |
|---------|------|------|--------------|---------|---------|
`;

	for (const func of result.functions.slice(0, 100)) {
		report += `| ${func.address} | ${func.name} | ${func.size} | ${func.instructionCount} | ${func.callers} | ${func.callees} |\n`;
	}

	if (result.functions.length > 100) {
		report += `| ... | ... | ... | ... | ... | ... |\n`;
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

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				filePath: result.filePath,
				fileName: result.fileName,
				newFunctions: result.newFunctions,
				totalFunctions: result.totalFunctions,
				totalStrings: result.totalStrings,
				architecture: result.architecture,
				baseAddress: result.baseAddress,
				sections: result.sections,
				imports: result.imports,
				exports: result.exports,
				functions: result.functions,
				generatedAt: new Date().toISOString()
			},
			null,
			2
		),
		'utf8'
	);
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
			const instruction = findInstructionByAddress(engine, address);
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

function collectInstructionsInRange(engine: DisassemblerEngine, startAddress: number, endAddress: number): Instruction[] {
	const from = Math.min(startAddress, endAddress);
	const to = Math.max(startAddress, endAddress);

	const containing = engine.getFunctions().find(func =>
		from >= func.address && from < func.endAddress
	);
	if (!containing) {
		throw new Error(`No containing function found for ${toHexAddress(from)}.`);
	}

	const instructions = containing.instructions
		.filter(instruction => instruction.address >= from && instruction.address <= to)
		.sort((left, right) => left.address - right.address);
	if (instructions.length === 0) {
		throw new Error(`No instructions found in range ${toHexAddress(from)}..${toHexAddress(to)}.`);
	}
	return instructions;
}

function findInstructionByAddress(engine: DisassemblerEngine, address: number): Instruction | undefined {
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
function showJobStatusInOutputChannel(job: QueuedJob): void {
	const channel = vscode.window.createOutputChannel('HexCore Job Status');
	channel.clear();
	channel.appendLine(`Job ID: ${job.jobId}`);
	channel.appendLine(`Status: ${job.status}`);
	channel.appendLine(`Priority: ${job.priority}`);
	channel.appendLine(`File: ${job.filePath}`);
	channel.appendLine(`Created: ${new Date(job.createdAt).toLocaleString()}`);
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
