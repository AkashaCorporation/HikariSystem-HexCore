/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';
import { JobQueueManager, getJobQueueManager, JobPriority } from './jobQueueManager';

export type PipelineOutputFormat = 'json' | 'md';
export { JobQueueManager, getJobQueueManager, JobPriority } from './jobQueueManager';

export type OnResultOperator = 'contains' | 'equals' | 'not' | 'gt' | 'lt' | 'regex';
export type OnResultAction = 'skip' | 'goto' | 'abort' | 'log';

export interface OnResultRule {
	field: string;
	operator: OnResultOperator;
	value: string | number;
	action: OnResultAction;
	actionValue?: string | number;
}

export interface PipelineOutputOptions {
	path?: string;
	format?: PipelineOutputFormat;
}

export interface PipelineStep {
	cmd: string;
	args?: Record<string, unknown>;
	output?: PipelineOutputOptions;
	continueOnError?: boolean;
	timeoutMs?: number;
	expectOutput?: boolean;
	retryCount?: number;
	retryDelayMs?: number;
	onResult?: OnResultRule;
}

export interface PipelineJobFile {
	file: string;
	outDir: string;
	steps: PipelineStep[];
	quiet?: boolean;
	priority?: JobPriority;
	/**
	 * When true, this acts as the default for every step that doesn't set its
	 * own `continueOnError`. v3.8.0-nightly: previously the top-level flag
	 * was silently ignored; now it propagates to all steps without a step-level
	 * override. Intuition: "keep going through failures across the whole job".
	 */
	continueOnError?: boolean;
}

export interface PipelineCommandOptions {
	file?: string;
	output?: {
		path: string;
		format?: PipelineOutputFormat;
	};
	quiet?: boolean;
	[key: string]: unknown;
}

export interface PipelineStepStatus {
	cmd: string;
	resolvedCmd: string;
	status: 'ok' | 'error' | 'skipped';
	startedAt: string;
	finishedAt: string;
	durationMs: number;
	attemptCount: number;
	outputPath?: string;
	/**
	 * v3.8.0 observability: size of the output artifact written by this step,
	 * in bytes. `undefined` when the step did not produce an output file or
	 * the probe failed. Backward compatible — older consumers simply ignore
	 * this field.
	 */
	outputBytes?: number;
	error?: string;
}

/**
 * v3.8.0 observability: run-level aggregate summary written at job finish.
 * Populated alongside `status`/`finishedAt` so one-shot consumers can read a
 * single file to get headline numbers without walking the `steps` array.
 * Backward compatible — missing on mid-run snapshots and legacy status files.
 */
export interface PipelineRunSummary {
	totalSteps: number;
	okCount: number;
	errorCount: number;
	skippedCount: number;
	totalDurationMs: number;
	slowestStepCmd?: string;
	slowestStepMs?: number;
	// Queue snapshot at the moment this job finished, if a queue was running.
	queueSnapshot?: {
		queued: number;
		running: number;
		done: number;
		failed: number;
		cancelled: number;
	};
}

export interface PipelineRunStatus {
	jobFile: string;
	file: string;
	outDir: string;
	status: 'running' | 'ok' | 'error' | 'partial';
	startedAt: string;
	finishedAt?: string;
	steps: PipelineStepStatus[];
	/**
	 * v3.8.0: populated when the job transitions to a terminal status
	 * (`ok` / `error` / `partial`). Absent while `status === 'running'`.
	 */
	summary?: PipelineRunSummary;
}

export interface PipelineValidationIssue {
	level: 'error' | 'warning';
	code: string;
	message: string;
	stepIndex?: number;
	command?: string;
}

export interface PipelineValidationStep {
	index: number;
	cmd: string;
	resolvedCmd: string;
	declared: boolean;
	headless: boolean;
	registered: boolean;
	timeoutMs: number;
	retryCount: number;
	retryDelayMs: number;
	continueOnError: boolean;
	expectOutput: boolean;
	provideOutput: boolean;
	outputPath?: string;
	ownerExtensions: PipelineDoctorExtensionState[];
}

export interface PipelineJobValidationReport {
	jobFile: string;
	file: string;
	outDir: string;
	quiet: boolean;
	ok: boolean;
	generatedAt: string;
	totalSteps: number;
	issues: PipelineValidationIssue[];
	steps: PipelineValidationStep[];
}

export interface PipelineDoctorExtensionState {
	id: string;
	installed: boolean;
	active: boolean;
}

export interface PipelineDoctorEntry {
	command: string;
	aliases: string[];
	headless: boolean;
	validateOutput: boolean;
	defaultTimeoutMs: number;
	registered: boolean;
	// `gated` (v3.8.2): the command's owner emulator is deselected via the
	// hexcore.emulator setting, so it is intentionally not registered. This is
	// expected, not a fault — distinct from `degraded` (owner installed but
	// command failed to register for an unknown reason).
	readiness: 'ready' | 'degraded' | 'missing' | 'gated';
	reason?: string;
	ownerExtensions: PipelineDoctorExtensionState[];
}

export interface PipelineDoctorReport {
	generatedAt: string;
	workspaceRoot: string;
	totalCapabilities: number;
	registeredHexcoreCommands: number;
	readyCommands: number;
	degradedCommands: number;
	missingCommands: number;
	gatedCommands: number;
	undeclaredHexcoreCommands: string[];
	entries: PipelineDoctorEntry[];
}

interface NormalizedPipelineJob {
	file: string;
	outDir: string;
	steps: PipelineStep[];
	quiet: boolean;
	/**
	 * H1 fix (v3.8.0-beta): the job-file `priority` field is now honoured by
	 * `normalizeJob`. Defaults to `'normal'` when absent; invalid values fall
	 * back to `'normal'` with a console warning. Consumed by the queueJob
	 * command path when no explicit priority arg is provided.
	 */
	priority: JobPriority;
}

interface StepOutputPath {
	path: string;
	format: PipelineOutputFormat;
}

/**
 * Recorded result for a completed pipeline step, used for $step[N] interpolation.
 *
 * - `outputPath` — the file path written by the step (maps to `$step[N].output`)
 * - `result`     — the parsed JSON content of that file (maps to `$step[N].result.X`)
 */
interface StepRecord {
	outputPath: string | undefined;
	result: Record<string, unknown> | undefined;
}

interface CommandCapability {
	headless: boolean;
	defaultTimeoutMs: number;
	validateOutput: boolean;
	reason?: string;
	cancelCommand?: string;
}

export const JOB_STATUS_FILENAME = 'hexcore-pipeline.status.json';
export const JOB_LOG_FILENAME = 'hexcore-pipeline.log';
const DEFAULT_TIMEOUT_MS = 60000;
const DEFAULT_RETRY_COUNT = 0;
const DEFAULT_RETRY_DELAY_MS = 1000;
const COMMAND_ALIASES = new Map<string, string>([
	['hexcore.hash.file', 'hexcore.hashcalc.calculate'],
	['hexcore.hash.calculate', 'hexcore.hashcalc.calculate'],
	['hexcore.disasm.open', 'hexcore.disasm.openFile'],
	['hexcore.pe.analyze', 'hexcore.peanalyzer.analyze'],
	['hexcore.elf.analyze', 'hexcore.elfanalyzer.analyze'],
	['hexcore.hex.dump', 'hexcore.hexview.dumpHeadless'],
	['hexcore.hex.search', 'hexcore.hexview.searchHeadless'],
	['hexcore.debug.emulate.full', 'hexcore.debug.emulateFullHeadless'],
	['hexcore.debug.run', 'hexcore.debug.emulateFullHeadless'],
	// v3.8.2: repoint to Helix. Rellic is deprecated (superseded by the Helix
	// MLIR pipeline in v3.7.0); the docs already describe these aliases as
	// resolving to Helix, so the map was the lie. The rellic.* commands remain
	// directly addressable for backward compatibility.
	['hexcore.decompile', 'hexcore.helix.decompile'],
	['hexcore.decompile.ir', 'hexcore.helix.decompileIR'],
	['hexcore.liftir', 'hexcore.disasm.liftToIR'],
	['hexcore.souper', 'hexcore.souper.optimize'],
	['hexcore.optimize', 'hexcore.souper.optimize'],
	['hexcore.superoptimize', 'hexcore.souper.optimize'],
	// Revenant (.NET / CIL) decompiler — doc-friendly short forms. The bare
	// `hexcore.decompile` alias is already claimed by Helix (native targets),
	// so managed aliases are namespaced under `dotnet`/`revenant` to avoid the
	// collision and make the managed-vs-native split explicit in job files.
	['hexcore.dotnet.decompile', 'hexcore.revenant.decompile'],
	['hexcore.decompile.dotnet', 'hexcore.revenant.decompile'],
	['hexcore.revenant.decompileCSharp', 'hexcore.revenant.decompile'],
	['hexcore.dotnet.decompileIL', 'hexcore.revenant.decompileIL'],
	['hexcore.decompile.il', 'hexcore.revenant.decompileIL'],
	['hexcore.disasm.disassembleAt', 'hexcore.disasm.disassembleAtHeadless'],
	['hexcore.disasm.rttiScan', 'hexcore.disasm.rttiScanHeadless'],
	['hexcore.disasm.scanRtti', 'hexcore.disasm.rttiScanHeadless'],
	['hexcore.disasm.searchBytes', 'hexcore.disasm.searchBytesHeadless'],
	['hexcore.disasm.aobScan', 'hexcore.disasm.searchBytesHeadless'],
	// HQL semantic scanner aliases (doc-friendly short forms).
	['hexcore.hql.scan', 'hexcore.hql.scanHeadless'],
	['hexcore.hql.scanFunctions', 'hexcore.hql.scanHeadless'],
	['hexcore.debug.searchMemory', 'hexcore.debug.searchMemoryHeadless'],
	['hexcore.unicorn.searchMemory', 'hexcore.debug.searchMemoryHeadless'],
	['hexcore.unicorn.searchMemoryHeadless', 'hexcore.debug.searchMemoryHeadless'],
	['hexcore.struct', 'hexcore.extractStructInfo'],
	['hexcore.structInfo', 'hexcore.extractStructInfo'],
	// v3.8.2: session-annotation aliases documented in HEXCORE_AUTOMATION.md
	// but previously absent from the map AND the capability map, so a job
	// copied from the docs died with "not declared in capability map".
	['hexcore.disasm.rename', 'hexcore.disasm.renameFunction'],
	['hexcore.disasm.retype', 'hexcore.disasm.retypeVariable'],
	['hexcore.disasm.bookmark', 'hexcore.disasm.setBookmark'],
	['hexcore.disasm.sessionPath', 'hexcore.disasm.getSessionDbPath'],
]);

/**
 * COMMAND_CAPABILITIES — Registry of all pipeline-supported commands.
 *
 * Each entry maps a command identifier to its capability metadata:
 *   - `headless`          — Whether the command supports headless (non-interactive) execution.
 *   - `defaultTimeoutMs`  — Default timeout in milliseconds for the command.
 *   - `validateOutput`    — Whether the runner should validate the output file after execution.
 *   - `reason`            — (Optional) Why a command is not headless-capable.
 *   - `cancelCommand`     — (Optional) Command to invoke if the step times out.
 *
 * ## Conditional Branching with `onResult` (v3.7.1 — Issue #16)
 *
 * Any {@link PipelineStep} may include an optional `onResult` field of type
 * {@link OnResultRule} to enable conditional branching based on step output.
 * When a step completes and has an `onResult` rule, the runner evaluates the
 * rule against the step's output JSON and executes the specified action.
 * Steps without `onResult` proceed sequentially (backward compatible).
 *
 * ### Available Operators ({@link OnResultOperator})
 *   - `contains` — Checks if the string representation of the output field
 *                   contains the specified value as a substring.
 *   - `equals`   — Checks strict equality (string or numeric).
 *   - `not`      — Checks inequality (inverse of `equals`).
 *   - `gt`       — Checks if the numeric output field is greater than the value.
 *   - `lt`       — Checks if the numeric output field is less than the value.
 *   - `regex`    — Compiles the value as a RegExp and tests against the field.
 *
 * ### Available Actions ({@link OnResultAction})
 *   - `skip`  — Skip the next N steps (N = `actionValue`, default 1).
 *               Next executed step: `currentIndex + N + 1`.
 *   - `goto`  — Jump to the step at index `actionValue` (0-based).
 *               Target must be within `[0, steps.length - 1]`.
 *   - `abort` — Stop the pipeline immediately with an error.
 *               `actionValue` is used as the abort reason message.
 *   - `log`   — Log a message (`actionValue`) and continue to the next step.
 *
 * ### Loop Protection
 * The runner enforces a maximum of {@link MAX_LOOP_ITERATIONS} (100) non-sequential
 * jumps per pipeline run. If exceeded, the pipeline aborts with a descriptive error
 * indicating the loop location. This prevents infinite loops from `goto` actions.
 *
 * ### Example `.hexcore_job.json` with `onResult`
 * ```json
 * {
 *   "file": "challenge.exe",
 *   "outDir": "./reports",
 *   "steps": [
 *     {
 *       "cmd": "hexcore.entropy.analyze",
 *       "onResult": {
 *         "field": "maxEntropy",
 *         "operator": "gt",
 *         "value": 7.5,
 *         "action": "goto",
 *         "actionValue": 3
 *       }
 *     },
 *     { "cmd": "hexcore.strings.extract" },
 *     { "cmd": "hexcore.disasm.analyzeAll" },
 *     { "cmd": "hexcore.yara.scan" }
 *   ]
 * }
 * ```
 *
 * @see {@link OnResultRule} for the rule schema
 * @see {@link evaluateOnResult} for operator evaluation logic
 * @see {@link applyOnResultAction} for action execution logic
 */
const COMMAND_CAPABILITIES = new Map<string, CommandCapability>([
	['hexcore.filetype.detect', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.hashcalc.calculate', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.entropy.analyze', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.strings.extract', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.peanalyzer.analyze', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.analyzePEHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.analyzeELFHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.analyzeAll', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.yara.scan', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.ioc.extract', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.strings.extractAdvanced', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.minidump.parse', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.minidump.threads', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.minidump.modules', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.minidump.memory', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.pipeline.listCapabilities', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.validateJob', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.validateWorkspace', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.createPresetJob', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.pipeline.saveJobAsProfile', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.pipeline.doctor', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	// Project Pythia — Oracle Hook commands (v3.9.0-preview.oracle, Issue #17).
	// Gated by hexcore.oracle.enabled setting; commands return early without
	// invoking Pythia when disabled. validateOutput is false because the
	// Oracle commands write to a shared Output Channel + optional files in
	// outDir, not a canonical per-command output file.
	['hexcore.oracle.inspectConfig', { headless: true, defaultTimeoutMs: 10000, validateOutput: false }],
	['hexcore.oracle.listSessions', { headless: true, defaultTimeoutMs: 10000, validateOutput: false }],
	['hexcore.oracle.demoHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.disasm.buildFormula', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.disasm.checkConstants', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.disasm.searchStringHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.exportASMHeadless', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.rellic.decompile', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.rellic.decompileIR', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.liftToIR', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.helix.decompile', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.helix.decompileIR', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	// Revenant — managed (.NET / CIL) decompiler. The native Remill->Helix
	// pipeline lifts CIL .text as x86 and emits a fake stub; Revenant recovers
	// the real C# / IL via the bundled self-contained engine (ICSharpCode.
	// Decompiler). Consumes a managed PE (`file`), writes C#/IL source to
	// `output`, honours `quiet`. validateOutput:true — both modes emit a real
	// source file the runner validates, exactly like helix.decompile.
	['hexcore.revenant.decompile', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.revenant.decompileIL', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	// HQL (Helix Query Language) semantic scanner. Decompiles the target
	// function(s) via the helix pipeline then evaluates the built-in signature
	// library over the HAST. Writes a JSON report ({ results: [...] }) to output.
	['hexcore.hql.scanHeadless', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.hql.scanFunction', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command scans the function in the active disassembler editor and shows notifications.' }],
	['hexcore.souper.optimize', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.extractStructInfo', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.disasm.disassembleAtHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.rttiScanHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	// v3.8.0-nightly Wave 3.2 — Milestone 2.1 refcount audit scanner.
	// Input: decompiled C file. Output: JSON report with RefcountAuditFinding[].
	['hexcore.audit.refcountScan', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.disasm.searchBytesHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.extractStrings', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.getSessionDbPath', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.disasm.renameFunction', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.disasm.renameVariable', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.disasm.retypeFunction', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.disasm.retypeVariable', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.disasm.setBookmark', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.yara.quickScan', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command shows notifications and threat report UI.' }],
	['hexcore.yara.scanWorkspace', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command depends on workspace UI flow.' }],
	['hexcore.yara.loadDefender', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens folder picker.' }],
	['hexcore.yara.loadCategory', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command prompts with quick-pick UI.' }],
	['hexcore.yara.updateRules', { headless: true, defaultTimeoutMs: 60000, validateOutput: false }],
	['hexcore.yara.createRule', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command depends on active selection and editor UI.' }],
	['hexcore.yara.threatReport', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command renders output from prior UI scan context.' }],
	['hexcore.disasm.analyzeFile', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens editor UI.' }],
	['hexcore.disasm.openFile', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens file picker.' }],
	['hexcore.disasm.searchString', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command prompts for input.' }],
	['hexcore.disasm.exportASM', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens save dialog.' }],
	['hexcore.debug.emulate', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive debugger command opens file picker and UI.' }],
	['hexcore.debug.emulateWithArch', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive debugger command opens prompts and UI.' }],
	['hexcore.debug.emulateHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.continueHeadless', { headless: true, defaultTimeoutMs: 300000, validateOutput: true }],
	['hexcore.debug.stepHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.debug.readMemoryHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.getRegistersHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.debug.setBreakpointHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.debug.getStateHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.snapshotHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.restoreSnapshotHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.exportTraceHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.debug.emulateFullHeadless', { headless: true, defaultTimeoutMs: 300000, validateOutput: true }],
	['hexcore.debug.writeMemoryHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.debug.setRegisterHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.debug.setStdinHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.debug.searchMemoryHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.debug.disposeHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.elixir.emulateHeadless', { headless: true, defaultTimeoutMs: 300000, validateOutput: true }],
	['hexcore.elixir.stalkerDrcovHeadless', { headless: true, defaultTimeoutMs: 300000, validateOutput: true }],
	['hexcore.elixir.snapshotRoundTripHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.elixir.smokeTestHeadless', { headless: true, defaultTimeoutMs: 30000, validateOutput: false }],
	['hexcore.elfanalyzer.analyze', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.elfanalyzer.analyzeActive', { headless: false, defaultTimeoutMs: 60000, validateOutput: false, reason: 'Interactive command analyzes active editor file.' }],
	['hexcore.base64.decodeHeadless', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.hexview.dumpHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.hexview.searchHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.pipeline.composeReport', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.pipeline.queueJob', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.cancelJob', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.jobStatus', { headless: true, defaultTimeoutMs: 30000, validateOutput: true }],
	['hexcore.pipeline.runJob', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Recursive pipeline invocation is not supported from a step.' }]
]);

const COMMAND_OWNERS = new Map<string, readonly string[]>([
	['hexcore.filetype.detect', ['hikarisystem.hexcore-filetype']],
	['hexcore.hashcalc.calculate', ['hikarisystem.hexcore-hashcalc']],
	['hexcore.entropy.analyze', ['hikarisystem.hexcore-entropy']],
	['hexcore.strings.extract', ['hikarisystem.hexcore-strings']],
	['hexcore.peanalyzer.analyze', ['hikarisystem.hexcore-peanalyzer']],
	['hexcore.disasm.analyzeAll', ['hikarisystem.hexcore-disassembler']],
	['hexcore.yara.scan', ['hikarisystem.hexcore-yara']],
	['hexcore.ioc.extract', ['hikarisystem.hexcore-ioc']],
	['hexcore.pipeline.listCapabilities', ['hikarisystem.hexcore-disassembler']],
	['hexcore.yara.quickScan', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.scanWorkspace', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.loadDefender', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.loadCategory', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.updateRules', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.createRule', ['hikarisystem.hexcore-yara']],
	['hexcore.yara.threatReport', ['hikarisystem.hexcore-yara']],
	['hexcore.disasm.analyzeFile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.openFile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.searchString', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.exportASM', ['hikarisystem.hexcore-disassembler']],
	['hexcore.debug.emulate', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.emulateWithArch', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.emulateHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.continueHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.stepHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.readMemoryHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.getRegistersHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.setBreakpointHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.getStateHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.pipeline.runJob', ['hikarisystem.hexcore-disassembler']],
	['hexcore.strings.extractAdvanced', ['hikarisystem.hexcore-strings']],
	['hexcore.minidump.parse', ['hikarisystem.hexcore-minidump']],
	['hexcore.minidump.threads', ['hikarisystem.hexcore-minidump']],
	['hexcore.minidump.modules', ['hikarisystem.hexcore-minidump']],
	['hexcore.minidump.memory', ['hikarisystem.hexcore-minidump']],
	['hexcore.disasm.searchStringHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.exportASMHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.buildFormula', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.checkConstants', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.validateJob', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.validateWorkspace', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.createPresetJob', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.saveJobAsProfile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.doctor', ['hikarisystem.hexcore-disassembler']],
	['hexcore.debug.snapshotHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.restoreSnapshotHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.exportTraceHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.emulateFullHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.writeMemoryHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.setRegisterHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.setStdinHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.searchMemoryHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.disposeHeadless', ['hikarisystem.hexcore-debugger']],
	['hexcore.elixir.emulateHeadless', ['hikarisystem.hexcore-elixir']],
	['hexcore.elixir.stalkerDrcovHeadless', ['hikarisystem.hexcore-elixir']],
	['hexcore.elixir.snapshotRoundTripHeadless', ['hikarisystem.hexcore-elixir']],
	['hexcore.elixir.smokeTestHeadless', ['hikarisystem.hexcore-elixir']],
	['hexcore.elfanalyzer.analyze', ['hikarisystem.hexcore-elfanalyzer']],
	['hexcore.elfanalyzer.analyzeActive', ['hikarisystem.hexcore-elfanalyzer']],
	['hexcore.base64.decodeHeadless', ['hikarisystem.hexcore-base64']],
	['hexcore.hexview.dumpHeadless', ['hikarisystem.hexcore-hexviewer']],
	['hexcore.hexview.searchHeadless', ['hikarisystem.hexcore-hexviewer']],
	['hexcore.pipeline.composeReport', ['hikarisystem.hexcore-report-composer']],
	['hexcore.rellic.decompile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.rellic.decompileIR', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.liftToIR', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.disassembleAtHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.rttiScanHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.audit.refcountScan', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.searchBytesHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.helix.decompile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.helix.decompileIR', ['hikarisystem.hexcore-disassembler']],
	['hexcore.revenant.decompile', ['hikarisystem.hexcore-revenant']],
	['hexcore.revenant.decompileIL', ['hikarisystem.hexcore-revenant']],
	['hexcore.hql.scanHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.hql.scanFunction', ['hikarisystem.hexcore-disassembler']],
	['hexcore.souper.optimize', ['hikarisystem.hexcore-disassembler']],
	['hexcore.extractStructInfo', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.extractStrings', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.analyzePEHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.analyzeELFHeadless', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.getSessionDbPath', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.renameFunction', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.renameVariable', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.retypeFunction', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.retypeVariable', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.setBookmark', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.queueJob', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.cancelJob', ['hikarisystem.hexcore-disassembler']],
	['hexcore.pipeline.jobStatus', ['hikarisystem.hexcore-disassembler']],
]);

// v3.8.0: Emulator-gated commands. The `hexcore.emulator` setting selects
// which emulator activates its commands — hexcore-debugger skips activation
// when emulator != "debugger", and symmetrically hexcore-elixir when
// emulator != "azoth". Steps targeting the inactive emulator are marked
// `skipped` by the pipeline runner instead of failing the job.
const EMULATOR_GATED_COMMANDS = new Map<string, 'debugger' | 'azoth'>([
	// hexcore-debugger (legacy TypeScript debugger)
	['hexcore.debug.emulate', 'debugger'],
	['hexcore.debug.emulateWithArch', 'debugger'],
	['hexcore.debug.emulateHeadless', 'debugger'],
	['hexcore.debug.continueHeadless', 'debugger'],
	['hexcore.debug.stepHeadless', 'debugger'],
	['hexcore.debug.readMemoryHeadless', 'debugger'],
	['hexcore.debug.getRegistersHeadless', 'debugger'],
	['hexcore.debug.setBreakpointHeadless', 'debugger'],
	['hexcore.debug.getStateHeadless', 'debugger'],
	['hexcore.debug.snapshotHeadless', 'debugger'],
	['hexcore.debug.restoreSnapshotHeadless', 'debugger'],
	['hexcore.debug.exportTraceHeadless', 'debugger'],
	['hexcore.debug.emulateFullHeadless', 'debugger'],
	['hexcore.debug.writeMemoryHeadless', 'debugger'],
	['hexcore.debug.setRegisterHeadless', 'debugger'],
	['hexcore.debug.setStdinHeadless', 'debugger'],
	['hexcore.debug.searchMemoryHeadless', 'debugger'],
	['hexcore.debug.disposeHeadless', 'debugger'],
	// hexcore-elixir (Project Azoth — default emulator in v3.8.0)
	['hexcore.elixir.emulateHeadless', 'azoth'],
	['hexcore.elixir.stalkerDrcovHeadless', 'azoth'],
	['hexcore.elixir.snapshotRoundTripHeadless', 'azoth'],
	['hexcore.elixir.smokeTestHeadless', 'azoth'],
]);

function checkEmulatorGate(command: string): { skip: true; reason: string } | { skip: false } {
	const required = EMULATOR_GATED_COMMANDS.get(command);
	if (!required) { return { skip: false }; }
	const active = vscode.workspace.getConfiguration('hexcore').get<string>('emulator', 'both');
	// "both" activates debugger and elixir side-by-side, so gates always pass.
	if (active === required || active === 'both') { return { skip: false }; }
	return {
		skip: true,
		reason: `hexcore.emulator="${active}" selects a different emulator; run "HexCore: Switch Emulator…" (Command Palette) or click the emulator indicator in the status bar to change this.`
	};
}

// Elixir commands that require PE32+ (x86_64). Running them against a PE32
// (x86) binary produces a legitimate but noisy "error" status; arch mismatch
// is better modelled as `skipped` so pipelines targeting mixed-arch corpora
// don't halt on `continueOnError: false` and don't pollute partial-status
// reports with predictable incompatibilities.
const ELIXIR_X64_ONLY_COMMANDS = new Set<string>([
	'hexcore.elixir.emulateHeadless',
	'hexcore.elixir.stalkerDrcovHeadless',
	'hexcore.elixir.snapshotRoundTripHeadless'
]);

function checkBinaryArchGate(command: string, targetPath: string): { skip: true; reason: string } | { skip: false } {
	if (!ELIXIR_X64_ONLY_COMMANDS.has(command)) { return { skip: false }; }
	try {
		if (!fs.existsSync(targetPath)) { return { skip: false }; }
		const fd = fs.openSync(targetPath, 'r');
		try {
			const head = Buffer.alloc(0x400);
			const n = fs.readSync(fd, head, 0, head.length, 0);
			if (n < 0x40) { return { skip: false }; }
			if (head[0] !== 0x4d || head[1] !== 0x5a) { return { skip: false }; } // not PE, let the command handle it
			const lfanew = head.readUInt32LE(0x3c);
			if (lfanew + 6 > n) { return { skip: false }; }
			if (head.readUInt32LE(lfanew) !== 0x00004550) { return { skip: false }; }
			const machine = head.readUInt16LE(lfanew + 4);
			if (machine === 0x8664) { return { skip: false }; }
			const archLabel = machine === 0x014c ? 'x86 (PE32)'
				: machine === 0xaa64 ? 'ARM64'
				: machine === 0x01c0 ? 'ARM'
				: `machine=0x${machine.toString(16)}`;
			return {
				skip: true,
				reason: `${command} requires x86_64 (PE32+); ${path.basename(targetPath)} is ${archLabel}. Use hexcore.emulator="debugger" for PE32 targets, or run "HexCore: Switch Emulator…".`
			};
		} finally {
			fs.closeSync(fd);
		}
	} catch {
		return { skip: false }; // on probe failure, let the command throw the real error
	}
}

export interface PipelineCapabilityEntry {
	command: string;
	aliases: string[];
	headless: boolean;
	defaultTimeoutMs: number;
	validateOutput: boolean;
	reason?: string;
	requiredExtension: string[];
}

export function listCapabilities(): PipelineCapabilityEntry[] {
	const entries: PipelineCapabilityEntry[] = [];
	for (const [cmd, cap] of COMMAND_CAPABILITIES.entries()) {
		const aliases: string[] = [];
		for (const [alias, target] of COMMAND_ALIASES.entries()) {
			if (target === cmd) {
				aliases.push(alias);
			}
		}
		entries.push({
			command: cmd,
			aliases,
			headless: cap.headless,
			defaultTimeoutMs: cap.defaultTimeoutMs,
			validateOutput: cap.validateOutput,
			reason: cap.reason,
			requiredExtension: [...(COMMAND_OWNERS.get(cmd) ?? [])]
		});
	}
	return entries;
}

export async function runPipelineDoctor(): Promise<PipelineDoctorReport> {
	const commands = new Set(await vscode.commands.getCommands(true));
	const knownCommands = new Set<string>([
		...COMMAND_CAPABILITIES.keys(),
		...COMMAND_ALIASES.keys()
	]);

	// A command whose owner emulator is deselected by the hexcore.emulator
	// setting is intentionally unregistered — report it as `gated`, not
	// `degraded`, so a healthy "azoth" or "debugger" config doesn't look broken.
	const activeEmulator = vscode.workspace.getConfiguration('hexcore').get<string>('emulator', 'both');

	const capabilities = listCapabilities();
	const entries: PipelineDoctorEntry[] = capabilities.map(capability => {
		const ownerExtensions = getExtensionStates(capability.requiredExtension);
		const registered = commands.has(capability.command);
		const hasMissingOwner = ownerExtensions.some(owner => !owner.installed);
		const requiredEmulator = EMULATOR_GATED_COMMANDS.get(capability.command);
		const isGated = requiredEmulator !== undefined
			&& activeEmulator !== 'both'
			&& activeEmulator !== requiredEmulator;
		const readiness: PipelineDoctorEntry['readiness'] = hasMissingOwner
			? 'missing'
			: (registered ? 'ready' : (isGated ? 'gated' : 'degraded'));
		const reason = (!registered && isGated && !capability.reason)
			? `Emulator-gated: hexcore.emulator="${activeEmulator}" deselects this command's engine ("${requiredEmulator}"). This is expected, not a fault.`
			: capability.reason;

		return {
			command: capability.command,
			aliases: capability.aliases,
			headless: capability.headless,
			validateOutput: capability.validateOutput,
			defaultTimeoutMs: capability.defaultTimeoutMs,
			registered,
			readiness,
			reason,
			ownerExtensions
		};
	});

	const registeredHexcoreCommands = [...commands].filter(command => command.startsWith('hexcore.'));
	const undeclaredHexcoreCommands = registeredHexcoreCommands
		.filter(command => !knownCommands.has(command))
		.sort();
	const readyCommands = entries.filter(entry => entry.readiness === 'ready').length;
	const degradedCommands = entries.filter(entry => entry.readiness === 'degraded').length;
	const missingCommands = entries.filter(entry => entry.readiness === 'missing').length;
	const gatedCommands = entries.filter(entry => entry.readiness === 'gated').length;
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '(no workspace)';

	return {
		generatedAt: new Date().toISOString(),
		workspaceRoot,
		totalCapabilities: entries.length,
		registeredHexcoreCommands: registeredHexcoreCommands.length,
		readyCommands,
		degradedCommands,
		missingCommands,
		gatedCommands,
		undeclaredHexcoreCommands,
		entries
	};
}

export const MAX_LOOP_ITERATIONS = 100;

/**
 * Resolves a (possibly dotted) field path against a step's output object.
 * `"maxEntropy"` reads a top-level field; `"summary.maxEntropy"` walks nested
 * objects. A flat key that contains a literal dot is tried first so existing
 * jobs whose field name happens to contain a dot keep working. Returns
 * `undefined` if any segment is missing or a non-object is traversed.
 */
export function resolveFieldPath(stepOutput: Record<string, unknown>, field: string): unknown {
	// Fast path / backward compat: exact top-level key (covers keys with dots).
	if (Object.prototype.hasOwnProperty.call(stepOutput, field)) {
		return stepOutput[field];
	}
	if (!field.includes('.')) {
		return undefined;
	}
	let current: unknown = stepOutput;
	for (const segment of field.split('.')) {
		if (!isRecord(current) || !Object.prototype.hasOwnProperty.call(current, segment)) {
			return undefined;
		}
		current = current[segment];
	}
	return current;
}

export function evaluateOnResult(rule: OnResultRule, stepOutput: Record<string, unknown>): boolean {
	const fieldValue = resolveFieldPath(stepOutput, rule.field);
	if (fieldValue === undefined) {
		return false;
	}

	switch (rule.operator) {
		case 'contains':
			return String(fieldValue).includes(String(rule.value));
		case 'equals':
			return fieldValue === rule.value || String(fieldValue) === String(rule.value);
		case 'not':
			return fieldValue !== rule.value && String(fieldValue) !== String(rule.value);
		case 'gt':
			return Number(fieldValue) > Number(rule.value);
		case 'lt':
			return Number(fieldValue) < Number(rule.value);
		case 'regex':
			return new RegExp(String(rule.value)).test(String(fieldValue));
		default:
			return false;
	}
}

export function applyOnResultAction(rule: OnResultRule, currentIndex: number, totalSteps: number, logPath: string): number {
	switch (rule.action) {
		case 'skip': {
			// Validate actionValue is a non-negative integer. A non-numeric value
			// (Number(...) -> NaN) previously produced a NaN next-index, so the main
			// loop's `while (NaN < steps.length)` fell through and the job silently
			// ended reporting 'ok' while dropping every remaining step. Fail loud.
			const n = Number(rule.actionValue ?? 1);
			if (!Number.isInteger(n) || n < 0) {
				throw new Error(`onResult skip actionValue must be a non-negative integer, got ${JSON.stringify(rule.actionValue)}`);
			}
			return currentIndex + 1 + n;
		}
		case 'goto': {
			// Require an integer in range. The previous `target < 0 || target >= totalSteps`
			// check let NaN through (both comparisons false -> returned NaN -> the loop
			// silently exited as 'ok') and let a fractional in-range value through (e.g.
			// 1.5 -> job.steps[1.5] === undefined -> undefined.cmd TypeError). Reject both.
			const target = Number(rule.actionValue);
			if (!Number.isInteger(target) || target < 0 || target >= totalSteps) {
				throw new Error(`onResult goto target ${JSON.stringify(rule.actionValue)} must be an integer step index in [0, ${totalSteps - 1}]`);
			}
			return target;
		}
		case 'abort':
			appendLog(logPath, `[onResult] ABORT: ${rule.actionValue ?? 'condition matched'}`);
			return -1;
		case 'log':
			appendLog(logPath, `[onResult] LOG: ${rule.actionValue ?? 'condition matched'}`);
			return currentIndex + 1;
		default:
			return currentIndex + 1;
	}
}

export class AutomationPipelineRunner {
	public async runJobFile(jobFilePath: string, quietOverride?: boolean, abortSignal?: AbortSignal): Promise<PipelineRunStatus> {
		const absoluteJobPath = path.resolve(jobFilePath);
		if (!fs.existsSync(absoluteJobPath)) {
			throw new Error(`Job file not found: ${absoluteJobPath}`);
		}

		const rawContent = fs.readFileSync(absoluteJobPath, 'utf8');
		const parsed = parseJsonFile(rawContent, absoluteJobPath);
		const normalized = normalizeJob(parsed, absoluteJobPath, quietOverride);

		return this.run(normalized, absoluteJobPath, abortSignal);
	}

	public async validateJobFile(jobFilePath: string, quietOverride?: boolean): Promise<PipelineJobValidationReport> {
		const absoluteJobPath = path.resolve(jobFilePath);
		if (!fs.existsSync(absoluteJobPath)) {
			throw new Error(`Job file not found: ${absoluteJobPath}`);
		}

		const rawContent = fs.readFileSync(absoluteJobPath, 'utf8');
		const parsed = parseJsonFile(rawContent, absoluteJobPath);
		const normalized = normalizeJob(parsed, absoluteJobPath, quietOverride);
		return createValidationReport(normalized, absoluteJobPath);
	}

	private async run(job: NormalizedPipelineJob, jobFilePath: string, abortSignal?: AbortSignal): Promise<PipelineRunStatus> {
		try {
			fs.mkdirSync(job.outDir, { recursive: true });
		} catch (mkdirError: unknown) {
			// outDir is job-file-controlled; if it resolves onto an existing file or
			// an ENOTDIR path, surface a clear, contextual error instead of a raw fs
			// throw. status.json lives inside outDir, so it cannot be written for this
			// failure - the labelled rejection is the most we can do.
			throw new Error(`Cannot create job output directory '${job.outDir}': ${toErrorMessage(mkdirError)}`);
		}

		const logPath = path.join(job.outDir, JOB_LOG_FILENAME);
		const statusPath = path.join(job.outDir, JOB_STATUS_FILENAME);

		const status: PipelineRunStatus = {
			jobFile: jobFilePath,
			file: job.file,
			outDir: job.outDir,
			status: 'running',
			startedAt: new Date().toISOString(),
			steps: []
		};

		writeJson(statusPath, status);

		// Workspace-Aware Pipeline Banner
		const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '(no workspace)';
		appendLog(logPath, '='.repeat(60));
		appendLog(logPath, `HexCore Pipeline Runner`);
		appendLog(logPath, `Workspace: ${workspaceRoot}`);
		appendLog(logPath, `Job file:  ${jobFilePath}`);
		appendLog(logPath, `Target:    ${job.file}`);
		appendLog(logPath, `Output:    ${job.outDir}`);
		appendLog(logPath, `Steps:     ${job.steps.length}`);
		appendLog(logPath, `Started:   ${status.startedAt}`);
		appendLog(logPath, '='.repeat(60));

		let failed = false;
		let halted = false;
		let index = 0;
		let loopCounter = 0;
		// Accumulates one record per completed step for $step[N] interpolation.
		const stepRecords: StepRecord[] = [];

		while (index < job.steps.length) {
			// Check if job was aborted
			if (abortSignal?.aborted) {
				appendLog(logPath, '[CANCELLED] Job aborted by user.');
				status.status = 'error';
				status.finishedAt = new Date().toISOString();
				writeJson(statusPath, status);
				return status;
			}

			const step = job.steps[index];
			const resolvedCommand = resolveCommand(step.cmd);
			const capability = COMMAND_CAPABILITIES.get(resolvedCommand);
			const validateOutput = shouldValidateOutput(step, capability);
			const provideOutput = shouldProvideOutput(step, capability);
			let output: StepOutputPath | undefined;
			try {
				output = provideOutput ? resolveStepOutput(job.outDir, step, index) : undefined;
			} catch (outputError: unknown) {
				// resolveStepOutput enforces CWE-22 containment and rejects an output.path
				// that escapes outDir, is absolute, or resolves to the directory itself.
				// That throw sits before the per-step try blocks, so it previously unwound
				// run() and froze status.json on 'running'. Record a clean step error and
				// honour continueOnError instead.
				const errorMessage = `Invalid step output path: ${toErrorMessage(outputError)}`;
				const stepStatus = createStepStatus(step, resolvedCommand, new Date(), 1, undefined, 'error', errorMessage);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: undefined, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					halted = true;
					break;
				}
				index++;
				continue;
			}
			const timeoutMs = resolveStepTimeout(step, capability);
			const retryCount = resolveRetryCount(step);
			const retryDelayMs = resolveRetryDelayMs(step);
			const maxAttempts = retryCount + 1;
			const startedAt = new Date();

			appendLog(logPath, `[Step ${index + 1}] ${step.cmd} -> ${resolvedCommand}`);
			appendLog(logPath, `[Step ${index + 1}] Timeout: ${timeoutMs}ms`);
			appendLog(logPath, `[Step ${index + 1}] Retries: ${retryCount} (delay=${retryDelayMs}ms)`);

			if (!capability) {
				const errorMessage = `Command is not declared in pipeline capability map: ${resolvedCommand}`;
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					1,
					output?.path,
					'error',
					errorMessage
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					halted = true;
					break;
				}
				index++;
				continue;
			}

			if (!capability.headless) {
				const reason = capability.reason ?? 'Command requires UI interaction.';
				const errorMessage = `Command is not headless-safe for pipeline: ${resolvedCommand}. ${reason}`;
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					1,
					output?.path,
					'error',
					errorMessage
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					halted = true;
					break;
				}
				index++;
				continue;
			}

			// Emulator gate: hexcore-debugger and hexcore-elixir register
			// mutually-exclusive commands based on the hexcore.emulator
			// setting. Mark the inactive-emulator step as `skipped` instead
			// of letting ensureCommandReady fail with "not registered".
			const emulatorGate = checkEmulatorGate(resolvedCommand);
			if (emulatorGate.skip) {
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					0,
					output?.path,
					'skipped',
					emulatorGate.reason
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] SKIPPED: ${emulatorGate.reason}`);
				writeJson(statusPath, status);
				index++;
				continue;
			}

			// Arch gate: Elixir is x86_64-only. Running an emulate/stalker/snapshot
			// step against a PE32 (x86) binary is a predictable incompatibility,
			// not a runtime failure — mark it `skipped` so the pipeline stays green
			// and reports the real reason instead of surfacing it as `error`.
			const archGate = checkBinaryArchGate(resolvedCommand, job.file);
			if (archGate.skip) {
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					0,
					output?.path,
					'skipped',
					archGate.reason
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] SKIPPED: ${archGate.reason}`);
				writeJson(statusPath, status);
				index++;
				continue;
			}

			try {
				await ensureCommandReady(resolvedCommand, logPath, index);
			} catch (error: unknown) {
				const errorMessage = normalizeExecutionError(error, resolvedCommand);
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					1,
					output?.path,
					'error',
					errorMessage
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					halted = true;
					break;
				}
				index++;
				continue;
			}

			let commandOptions: PipelineCommandOptions;
			try {
				commandOptions = buildCommandOptions(job.file, step, output, job.quiet, stepRecords, index, resolvedCommand);
			} catch (error: unknown) {
				const errorMessage = `Step arg interpolation failed: ${toErrorMessage(error)}`;
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					1,
					output?.path,
					'error',
					errorMessage
				);
				status.steps.push(stepStatus);
				stepRecords.push({ outputPath: output?.path, result: undefined });
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					halted = true;
					break;
				}
				index++;
				continue;
			}

			let attemptCount = 0;
			let executionError: unknown;
			let completed = false;
			// Captures the command's return value so onResult / $step[N].result
			// can read it even when the step defines no `output` file (the marquee
			// adaptive-triage templates put onResult on a step with no output).
			let commandReturn: unknown;

			while (attemptCount < maxAttempts) {
				attemptCount++;
				appendLog(logPath, `[Step ${index + 1}] Attempt ${attemptCount}/${maxAttempts}`);

				try {
					commandReturn = await withTimeout(
						vscode.commands.executeCommand(resolvedCommand, commandOptions),
						timeoutMs,
						`Step ${index + 1} (${resolvedCommand}) timed out after ${timeoutMs}ms`
					);

					if (validateOutput) {
						if (!output) {
							throw new Error(`Expected output validation for ${resolvedCommand}, but no output path was assigned.`);
						}
						// Bug #36/2: surface the command's REAL failure instead of the
						// generic "Expected output file was not created" mask. Scope this
						// to validateOutput steps only — a future step may legitimately
						// return success:false under continueOnError, and we must not
						// blanket-throw on that. Both the quiet:false auto-run path
						// (handler returns undefined) and the quiet:true path (handler
						// returns {success:false,error}) are covered. This throw flows
						// through the SAME continueOnError try/catch below, so behavior
						// is unchanged except the recorded message is now the true cause.
						if (commandReturn === undefined) {
							throw new Error('command returned no result (likely missing or invalid input - see the Extension Host console for the real error)');
						} else if (isRecord(commandReturn) && commandReturn.success === false) {
							throw new Error(String(commandReturn.error ?? 'command reported success:false'));
						}
						validateStepOutput(output.path);
					}

					const stepStatus = createStepStatus(
						step,
						resolvedCommand,
						startedAt,
						attemptCount,
						output?.path,
						'ok'
					);
					status.steps.push(stepStatus);
					appendLog(logPath, `[Step ${index + 1}] OK (${stepStatus.durationMs}ms, attempts=${attemptCount})`);
					writeJson(statusPath, status);
					completed = true;
					break;
				} catch (error: unknown) {
					executionError = error;
					let errorMessage = normalizeExecutionError(error, resolvedCommand);
					if (error instanceof TimeoutError) {
						const cancelled = await tryCancelOnTimeout(capability, logPath, index);
						// Be honest in the recorded status: a timed-out step is
						// only abandoned, not killed, unless a real cancelCommand ran.
						if (!cancelled) {
							errorMessage += ' (step abandoned on timeout; the underlying operation may still be running in the Extension Host)';
						}
					}

					if (attemptCount < maxAttempts) {
						appendLog(logPath, `[Step ${index + 1}] Attempt ${attemptCount} failed: ${errorMessage}`);
						appendLog(logPath, `[Step ${index + 1}] Retrying after ${retryDelayMs}ms...`);
						if (retryDelayMs > 0) {
							await delay(retryDelayMs);
						}
						continue;
					}

					const stepStatus = createStepStatus(
						step,
						resolvedCommand,
						startedAt,
						attemptCount,
						output?.path,
						'error',
						errorMessage
					);
					status.steps.push(stepStatus);
					appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
					writeJson(statusPath, status);
					failed = true;
					if (!step.continueOnError) {
						halted = true;
						break;
					}
				}
			}

			if (!completed && executionError && !step.continueOnError) {
				halted = true;
				break;
			}

			// Step output capture — used for both onResult evaluation and
			// $step[N] interpolation. Prefer the written output file (it is the
			// canonical, post-serialization artifact); fall back to the command's
			// in-memory return value so steps WITHOUT an `output` block can still
			// feed onResult / $step[N].result (e.g. the adaptive-triage templates
			// branch on `hexcore.entropy.analyze` with no output file).
			let stepOutputData: Record<string, unknown> | undefined;
			if (completed && output?.path) {
				try {
					const content = fs.readFileSync(output.path, 'utf8');
					const parsed: unknown = JSON.parse(content);
					if (isRecord(parsed)) {
						stepOutputData = parsed;
					}
				} catch (readErr) {
					appendLog(logPath, `[Step ${index + 1}] WARNING: Could not read output for step result capture: ${toErrorMessage(readErr)} (path=${output?.path ?? '<none>'})`);
				}
			}
			if (completed && stepOutputData === undefined && isRecord(commandReturn)) {
				stepOutputData = commandReturn;
			}

			// Record the completed step result so later steps can reference it via $step[N].
			stepRecords.push({ outputPath: output?.path, result: stepOutputData });

			// Evaluate onResult conditional branching. evaluateOnResult can throw on a
			// bad RegExp ('regex' operator) and applyOnResultAction throws on an invalid
			// goto/skip target. This branch was the only step phase with no try/catch, so
			// such a throw unwound run() and left status.json frozen on 'running'. Catch
			// it, record a clean step error, and halt to a terminal status instead.
			if (completed && step.onResult && stepOutputData) {
				let matched = false;
				let nextIndex = index + 1;
				try {
					matched = evaluateOnResult(step.onResult, stepOutputData);
					if (matched) {
						nextIndex = applyOnResultAction(step.onResult, index, job.steps.length, logPath);
					}
				} catch (onResultError: unknown) {
					const errorMessage = `onResult evaluation failed: ${toErrorMessage(onResultError)}`;
					status.steps.push(createStepStatus(step, resolvedCommand, startedAt, 1, output?.path, 'error', errorMessage));
					appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
					writeJson(statusPath, status);
					failed = true;
					halted = true;
					break;
				}
				if (matched) {
					if (nextIndex === -1) {
						// 'abort' - stop with an error. Set halted so the terminal
						// status is 'error' (documented), not 'partial'.
						failed = true;
						halted = true;
						break;
					}
					// Only BACKWARD jumps form a loop. A forward `skip N` or a
					// forward `goto` advances the pipeline and must NOT consume
					// the loop budget (previously `nextIndex !== index + 1` also
					// counted forward skips, so a pipeline with many skips could
					// falsely trip the 100-iteration cap).
					if (nextIndex <= index) {
						loopCounter++;
						if (loopCounter > MAX_LOOP_ITERATIONS) {
							appendLog(logPath, `[Step ${index + 1}] ERROR: Maximum loop iterations (${MAX_LOOP_ITERATIONS}) exceeded`);
							failed = true;
							break;
						}
					}
					index = nextIndex;
					continue;
				}
			}

			index++;
		}

		status.finishedAt = new Date().toISOString();
		// 'error' = pipeline halted on a step failure; 'partial' = some steps
		// failed but continueOnError kept the job running to completion.
		if (!failed) {
			status.status = 'ok';
		} else if (halted) {
			status.status = 'error';
		} else {
			status.status = 'partial';
		}

		// v3.8.0 observability: build run-level summary (headline metrics +
		// queue snapshot) so dashboards and report composers can read a
		// single file instead of walking `steps`. Best-effort queue probe —
		// missing queue singleton is not an error.
		const summary: PipelineRunSummary = {
			totalSteps: status.steps.length,
			okCount: status.steps.filter(s => s.status === 'ok').length,
			errorCount: status.steps.filter(s => s.status === 'error').length,
			skippedCount: status.steps.filter(s => s.status === 'skipped').length,
			totalDurationMs: new Date(status.finishedAt).getTime() - new Date(status.startedAt).getTime()
		};
		let slowest: PipelineStepStatus | undefined;
		for (const s of status.steps) {
			if (s.status === 'ok' && (!slowest || s.durationMs > slowest.durationMs)) {
				slowest = s;
			}
		}
		if (slowest) {
			summary.slowestStepCmd = slowest.resolvedCmd;
			summary.slowestStepMs = slowest.durationMs;
		}
		try {
			if (jobQueueManagerInstance) {
				summary.queueSnapshot = jobQueueManagerInstance.getQueueStats();
			}
		} catch { /* singleton not initialised or getter threw — skip */ }
		status.summary = summary;

		writeJson(statusPath, status);
		appendLog(logPath, `Job finished with status: ${status.status}`);
		appendLog(logPath, `Summary: ok=${summary.okCount} error=${summary.errorCount} skipped=${summary.skippedCount} totalMs=${summary.totalDurationMs}${summary.slowestStepCmd ? ` slowest=${summary.slowestStepCmd}(${summary.slowestStepMs}ms)` : ''}`);

		return status;
	}
}

async function createValidationReport(job: NormalizedPipelineJob, jobFilePath: string): Promise<PipelineJobValidationReport> {
	const issues: PipelineValidationIssue[] = [];
	const steps: PipelineValidationStep[] = [];
	const registeredCommands = new Set(await vscode.commands.getCommands(true));

	if (!fs.existsSync(job.file)) {
		issues.push({
			level: 'error',
			code: 'TARGET_FILE_NOT_FOUND',
			message: `Target file does not exist: ${job.file}`
		});
	}

	for (let index = 0; index < job.steps.length; index++) {
		const step = job.steps[index];
		const resolvedCmd = resolveCommand(step.cmd);
		const capability = COMMAND_CAPABILITIES.get(resolvedCmd);
		const declared = capability !== undefined;
		const ownerIds = COMMAND_OWNERS.get(resolvedCmd) ?? [];
		const ownerExtensions = getExtensionStates(ownerIds);
		const registered = registeredCommands.has(resolvedCmd);
		const expectOutput = shouldValidateOutput(step, capability);
		const provideOutput = shouldProvideOutput(step, capability);
		const timeoutMs = resolveStepTimeout(step, capability);
		const retryCount = resolveRetryCount(step);
		const retryDelayMs = resolveRetryDelayMs(step);
		const output = provideOutput ? resolveStepOutput(job.outDir, step, index) : undefined;

		steps.push({
			index: index + 1,
			cmd: step.cmd,
			resolvedCmd,
			declared,
			headless: capability?.headless ?? false,
			registered,
			timeoutMs,
			retryCount,
			retryDelayMs,
			continueOnError: step.continueOnError === true,
			expectOutput,
			provideOutput,
			outputPath: output?.path,
			ownerExtensions
		});

		if (!declared) {
			issues.push({
				level: 'error',
				code: 'COMMAND_NOT_DECLARED',
				message: `Command is not declared in pipeline capability map: ${resolvedCmd}`,
				stepIndex: index + 1,
				command: resolvedCmd
			});
			continue;
		}

		if (!capability.headless) {
			const reason = capability.reason ?? 'Command requires UI interaction.';
			issues.push({
				level: 'error',
				code: 'COMMAND_NOT_HEADLESS',
				message: `Command is not headless-safe for pipeline: ${resolvedCmd}. ${reason}`,
				stepIndex: index + 1,
				command: resolvedCmd
			});
		}

		if (ownerIds.length === 0) {
			issues.push({
				level: 'warning',
				code: 'OWNER_NOT_MAPPED',
				message: `No owner extension mapping found for command: ${resolvedCmd}`,
				stepIndex: index + 1,
				command: resolvedCmd
			});
		}

		const missingOwners = ownerExtensions.filter(extension => !extension.installed);
		if (missingOwners.length > 0) {
			issues.push({
				level: 'error',
				code: 'OWNER_EXTENSION_MISSING',
				message: `Owner extension is not installed for ${resolvedCmd}: ${missingOwners.map(extension => extension.id).join(', ')}`,
				stepIndex: index + 1,
				command: resolvedCmd
			});
		}

		if (!registered && ownerExtensions.length > 0 && missingOwners.length === 0) {
			issues.push({
				level: 'warning',
				code: 'COMMAND_NOT_REGISTERED_YET',
				message: `Command is currently not registered in Extension Host: ${resolvedCmd}. It may register after extension activation.`,
				stepIndex: index + 1,
				command: resolvedCmd
			});
		}

		// $step[N] reference validation (static). The runtime resolver throws on
		// forward/out-of-range references, but validation previously never parsed
		// the tokens, so a forward-ref job was greenlit. Catch them here.
		if (step.args) {
			for (const ref of collectStepReferences(step.args)) {
				const refIndex = ref.token === 'prev' ? index - 1 : parseInt(ref.token, 10);
				if (Number.isNaN(refIndex)) {
					issues.push({
						level: 'error',
						code: 'STEP_REF_INVALID',
						message: `Invalid step reference $step[${ref.token}] in step ${index + 1} (${step.cmd})`,
						stepIndex: index + 1,
						command: resolvedCmd
					});
				} else if (refIndex < 0) {
					issues.push({
						level: 'error',
						code: 'STEP_REF_OUT_OF_RANGE',
						message: `$step[${ref.token}] in step ${index + 1} resolves to index ${refIndex}, which is out of bounds (a $step[prev] on step 1 has no predecessor)`,
						stepIndex: index + 1,
						command: resolvedCmd
					});
				} else if (refIndex >= index) {
					issues.push({
						level: 'error',
						code: 'STEP_REF_FORWARD',
						message: `Forward reference $step[${ref.token}] in step ${index + 1} (${step.cmd}) targets step ${refIndex + 1}, which has not run yet (references must point to an earlier step)`,
						stepIndex: index + 1,
						command: resolvedCmd
					});
				}
			}
		}
	}

	const hasErrors = issues.some(issue => issue.level === 'error');
	return {
		jobFile: jobFilePath,
		file: job.file,
		outDir: job.outDir,
		quiet: job.quiet,
		ok: !hasErrors,
		generatedAt: new Date().toISOString(),
		totalSteps: job.steps.length,
		issues,
		steps
	};
}

function parseJsonFile(content: string, jobFilePath: string): unknown {
	try {
		return JSON.parse(content);
	} catch (error: unknown) {
		throw new Error(`Invalid JSON in ${jobFilePath}: ${toErrorMessage(error)}`);
	}
}

function normalizeJob(data: unknown, jobFilePath: string, quietOverride?: boolean): NormalizedPipelineJob {
	if (!isRecord(data)) {
		throw new Error(`Invalid job format in ${jobFilePath}: expected JSON object`);
	}

	const baseDir = path.dirname(jobFilePath);
	const file = toAbsolutePath(baseDir, getStringField(data, 'file'));
	const outDir = toAbsolutePath(baseDir, getStringField(data, 'outDir'));
	const rawSteps = data.steps;

	if (!Array.isArray(rawSteps) || rawSteps.length === 0) {
		throw new Error(`Invalid job format in ${jobFilePath}: "steps" must be a non-empty array`);
	}

	// v3.8.0-nightly: honour top-level `continueOnError: true` as a default
	// for every step that doesn't explicitly set its own value. Without this
	// fallback, users who set the flag at the job root (the natural intuition
	// for "continue through failures on this whole job") would see the first
	// step-failure halt everything, because only step-level flags were read.
	const jobDefaultContinueOnError = data.continueOnError === true;

	const steps: PipelineStep[] = rawSteps.map((step, index) => {
		const normalized = normalizeStep(step, index, jobFilePath);
		if (jobDefaultContinueOnError && isRecord(step) && typeof step.continueOnError !== 'boolean') {
			normalized.continueOnError = true;
		}
		return normalized;
	});
	const quiet = typeof quietOverride === 'boolean'
		? quietOverride
		: (typeof data.quiet === 'boolean' ? data.quiet : true);

	// H1 fix (v3.8.0-beta): parse top-level `priority` from the job file.
	// Previously this field was declared in the TS interface + JSON schema
	// but silently dropped here, so user-configured priorities were ignored
	// at runtime. Invalid values warn and fall back to 'normal'.
	let priority: JobPriority = 'normal';
	if (data.priority !== undefined) {
		if (data.priority === 'high' || data.priority === 'normal' || data.priority === 'low') {
			priority = data.priority;
		} else {
			console.warn(
				`[hexcore.pipeline] Invalid "priority" in ${jobFilePath}: ` +
				`expected 'high' | 'normal' | 'low', got ${JSON.stringify(data.priority)}. ` +
				`Falling back to 'normal'.`
			);
		}
	}

	return {
		file,
		outDir,
		steps,
		quiet,
		priority
	};
}

export function normalizeStep(step: unknown, index: number, jobFilePath: string): PipelineStep {
	if (!isRecord(step)) {
		throw new Error(`Invalid step at index ${index} in ${jobFilePath}: expected object`);
	}

	const cmd = getStringField(step, 'cmd');
	const args = isRecord(step.args) ? step.args : undefined;
	const continueOnError = typeof step.continueOnError === 'boolean' ? step.continueOnError : false;
	const timeoutMs = parseTimeoutMs(step.timeoutMs, index, cmd, jobFilePath);
	const retryCount = parseRetryCount(step.retryCount, index, cmd, jobFilePath);
	const retryDelayMs = parseRetryDelayMs(step.retryDelayMs, index, cmd, jobFilePath);
	const expectOutput = typeof step.expectOutput === 'boolean' ? step.expectOutput : undefined;

	let output: PipelineOutputOptions | undefined;
	if (step.output !== undefined) {
		if (!isRecord(step.output)) {
			throw new Error(`Invalid "output" in step ${index} (${cmd})`);
		}
		output = {
			path: typeof step.output.path === 'string' ? step.output.path : undefined,
			format: step.output.format === 'md' || step.output.format === 'json'
				? step.output.format
				: undefined
		};
	}

	let onResult: OnResultRule | undefined;
	if (step.onResult !== undefined) {
		if (!isRecord(step.onResult)) {
			throw new Error(`Step ${index}: onResult must be an object`);
		}
		const or = step.onResult as Record<string, unknown>;
		const validOperators: readonly string[] = ['contains', 'equals', 'not', 'gt', 'lt', 'regex'];
		const validActions: readonly string[] = ['skip', 'goto', 'abort', 'log'];

		if (typeof or.field !== 'string' || !or.field) {
			throw new Error(`Step ${index}: onResult.field must be a non-empty string`);
		}
		if (!validOperators.includes(String(or.operator))) {
			throw new Error(`Step ${index}: onResult.operator must be one of: ${validOperators.join(', ')}`);
		}
		if (or.value === undefined) {
			throw new Error(`Step ${index}: onResult.value is required`);
		}
		if (!validActions.includes(String(or.action))) {
			throw new Error(`Step ${index}: onResult.action must be one of: ${validActions.join(', ')}`);
		}

		onResult = {
			field: or.field,
			operator: or.operator as OnResultOperator,
			value: or.value as string | number,
			action: or.action as OnResultAction,
			actionValue: or.actionValue as string | number | undefined
		};
	}

	return {
		cmd,
		args,
		output,
		continueOnError,
		timeoutMs,
		expectOutput,
		retryCount,
		retryDelayMs,
		onResult
	};
}

function resolveCommand(cmd: string): string {
	return COMMAND_ALIASES.get(cmd) ?? cmd;
}

function parseTimeoutMs(
	rawValue: unknown,
	index: number,
	cmd: string,
	jobFilePath: string
): number | undefined {
	if (rawValue === undefined) {
		return undefined;
	}
	if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
		throw new Error(`Invalid "timeoutMs" in step ${index} (${cmd}) of ${jobFilePath}: expected finite number`);
	}
	const normalized = Math.floor(rawValue);
	if (normalized < 1) {
		throw new Error(`Invalid "timeoutMs" in step ${index} (${cmd}) of ${jobFilePath}: expected value >= 1`);
	}
	return normalized;
}

function parseRetryCount(
	rawValue: unknown,
	index: number,
	cmd: string,
	jobFilePath: string
): number | undefined {
	if (rawValue === undefined) {
		return undefined;
	}
	if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
		throw new Error(`Invalid "retryCount" in step ${index} (${cmd}) of ${jobFilePath}: expected finite number`);
	}
	const normalized = Math.floor(rawValue);
	if (normalized < 0) {
		throw new Error(`Invalid "retryCount" in step ${index} (${cmd}) of ${jobFilePath}: expected value >= 0`);
	}
	return normalized;
}

function parseRetryDelayMs(
	rawValue: unknown,
	index: number,
	cmd: string,
	jobFilePath: string
): number | undefined {
	if (rawValue === undefined) {
		return undefined;
	}
	if (typeof rawValue !== 'number' || !Number.isFinite(rawValue)) {
		throw new Error(`Invalid "retryDelayMs" in step ${index} (${cmd}) of ${jobFilePath}: expected finite number`);
	}
	const normalized = Math.floor(rawValue);
	if (normalized < 0) {
		throw new Error(`Invalid "retryDelayMs" in step ${index} (${cmd}) of ${jobFilePath}: expected value >= 0`);
	}
	return normalized;
}

function resolveStepOutput(outDir: string, step: PipelineStep, index: number): StepOutputPath {
	const explicitPath = step.output?.path;
	let outputPath: string;
	if (typeof explicitPath === 'string' && explicitPath.length > 0) {
		// CWE-22 containment: a *.hexcore_job.json is attacker-controllable and
		// AUTO-RUN, so an explicit output path MUST resolve INSIDE outDir — reject
		// absolute paths and any "../" escape (an unconstrained path here is an
		// arbitrary-file-write primitive).
		const root = path.resolve(outDir);
		const resolved = path.resolve(outDir, explicitPath);
		// Must name a FILE strictly inside outDir: reject absolute paths, ".." escapes,
		// AND a path that resolves to the outDir directory itself (".", "./", "sub/"),
		// which would otherwise be handed to the command as a directory and then
		// mis-recorded as an empty-output failure.
		const contained = !path.isAbsolute(explicitPath) &&
			resolved !== root &&
			resolved.startsWith(root + path.sep);
		if (!contained) {
			throw new Error(`Invalid "output.path" in step ${index} (${step.cmd}): must be a relative file path inside the job output directory (no absolute paths, no ".." escape, and not the directory itself). Got: ${explicitPath}`);
		}
		outputPath = resolved;
	} else {
		const safeName = sanitizeFileName(step.cmd);
		outputPath = path.join(outDir, `${String(index + 1).padStart(2, '0')}-${safeName}.json`);
	}

	const format = resolveOutputFormat(outputPath, step.output?.format);
	return { path: outputPath, format };
}

function resolveOutputFormat(outputPath: string, format?: PipelineOutputFormat): PipelineOutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

/**
 * Resolves `$step[N]` and `$step[prev]` variable references inside step args.
 *
 * Supported token forms:
 *   - `$step[N].output`          — the output file path written by step N (0-based)
 *   - `$step[prev].output`       — the output file path of the immediately preceding step
 *   - `$step[N].result.fieldName` — a top-level field from the parsed JSON output of step N
 *   - `$step[prev].result.fieldName` — same, for the previous step
 *
 * Rules enforced:
 *   - Forward references (referencing a step >= currentIndex) throw an error.
 *   - Out-of-range indices throw an error.
 *   - Only string-typed values are interpolated; non-string values pass through unchanged.
 *   - Nested objects/arrays in args are traversed recursively.
 *
 * @param args         - The raw args record from the pipeline step definition.
 * @param stepRecords  - Array of records for all steps that have already completed.
 * @param currentIndex - The 0-based index of the step currently being executed.
 */
export function resolveStepReferences(
	args: Record<string, unknown>,
	stepRecords: StepRecord[],
	currentIndex: number
): Record<string, unknown> {
	return resolveObject(args, stepRecords, currentIndex) as Record<string, unknown>;
}

/**
 * Statically extracts every `$step[N]` / `$step[prev]` reference inside an args
 * object (recursing into nested objects/arrays/strings). Used by validateJob to
 * reject forward / out-of-range references BEFORE the job runs, instead of only
 * throwing at the offending step's dispatch time.
 */
export function collectStepReferences(value: unknown): Array<{ token: string; accessor: string }> {
	const found: Array<{ token: string; accessor: string }> = [];
	const TOKEN_RE = /\$step\[(\d+|prev)\]\.(?:output|result\.[a-zA-Z0-9_]+)/g;
	const walk = (v: unknown): void => {
		if (typeof v === 'string') {
			let m: RegExpExecArray | null;
			TOKEN_RE.lastIndex = 0;
			while ((m = TOKEN_RE.exec(v)) !== null) {
				const full = m[0];
				const dotPos = full.indexOf('.', full.indexOf(']'));
				found.push({ token: m[1], accessor: full.slice(dotPos + 1) });
			}
		} else if (Array.isArray(v)) {
			for (const item of v) { walk(item); }
		} else if (isRecord(v)) {
			for (const item of Object.values(v)) { walk(item); }
		}
	};
	walk(value);
	return found;
}

function resolveValue(
	value: unknown,
	stepRecords: StepRecord[],
	currentIndex: number
): unknown {
	if (typeof value === 'string') {
		return interpolateString(value, stepRecords, currentIndex);
	}
	if (Array.isArray(value)) {
		return value.map(item => resolveValue(item, stepRecords, currentIndex));
	}
	if (isRecord(value)) {
		return resolveObject(value, stepRecords, currentIndex);
	}
	return value;
}

function resolveObject(
	obj: Record<string, unknown>,
	stepRecords: StepRecord[],
	currentIndex: number
): Record<string, unknown> {
	const result: Record<string, unknown> = {};
	for (const [key, val] of Object.entries(obj)) {
		result[key] = resolveValue(val, stepRecords, currentIndex);
	}
	return result;
}

/**
 * Interpolates all `$step[N]` tokens found inside a single string value.
 * A token may be the entire string or embedded within a larger string.
 * When a token is the entire string content, the resolved value is returned
 * as-is (preserving its original type when accessed via result.X lookup).
 * When embedded among other text the resolved value is always coerced to string.
 */
function interpolateString(
	raw: string,
	stepRecords: StepRecord[],
	currentIndex: number
): unknown {
	// Pattern: $step[N].output  or  $step[N].result.fieldName
	//          $step[prev].output or $step[prev].result.fieldName
	const TOKEN_RE = /\$step\[(\d+|prev)\]\.(?:output|result\.[a-zA-Z0-9_]+)/g;

	// Fast-path: nothing to interpolate
	if (!TOKEN_RE.test(raw)) {
		return raw;
	}

	// Reset lastIndex after the test() call consumed it
	TOKEN_RE.lastIndex = 0;

	// Collect all tokens to determine if the entire string is a single token
	const tokens: Array<{ full: string; index: string; accessor: string }> = [];
	let match: RegExpExecArray | null;
	while ((match = TOKEN_RE.exec(raw)) !== null) {
		const full = match[0];
		// accessor is everything after $step[N].
		const dotPos = full.indexOf('.', full.indexOf(']'));
		const accessor = full.slice(dotPos + 1); // e.g. "output" or "result.fieldName"
		tokens.push({ full, index: match[1], accessor });
	}

	// Resolve each token to a concrete value
	const resolved = tokens.map(token => ({
		token,
		value: resolveToken(token.index, token.accessor, stepRecords, currentIndex)
	}));

	// If the raw string is exactly one token and nothing else, return the
	// resolved value directly (preserves non-string types from result fields).
	if (tokens.length === 1 && raw === tokens[0].full) {
		return resolved[0].value;
	}

	// Otherwise perform string substitution left-to-right.
	const allTokenRe = /\$step\[(\d+|prev)\]\.(?:output|result\.[a-zA-Z0-9_]+)/g;
	return raw.replace(allTokenRe, (_match, indexToken) => {
		const dotPos = _match.indexOf('.', _match.indexOf(']'));
		const accessor = _match.slice(dotPos + 1);
		const resolvedVal = resolveToken(indexToken, accessor, stepRecords, currentIndex);
		return resolvedVal === undefined || resolvedVal === null ? '' : String(resolvedVal);
	});
}

function resolveToken(
	indexToken: string,
	accessor: string,
	stepRecords: StepRecord[],
	currentIndex: number
): unknown {
	const stepIndex = indexToken === 'prev' ? currentIndex - 1 : parseInt(indexToken, 10);

	if (isNaN(stepIndex)) {
		throw new Error(`$step[${indexToken}]: invalid step index`);
	}

	if (stepIndex < 0) {
		throw new Error(`$step[${indexToken}]: index resolves to ${stepIndex}, which is out of bounds`);
	}

	if (stepIndex >= currentIndex) {
		throw new Error(
			`$step[${indexToken}]: forward reference detected — step ${stepIndex} has not completed yet ` +
			`(current step is ${currentIndex})`
		);
	}

	if (stepIndex >= stepRecords.length) {
		throw new Error(
			`$step[${indexToken}]: index ${stepIndex} is out of range ` +
			`(only ${stepRecords.length} step(s) have been recorded)`
		);
	}

	const record = stepRecords[stepIndex];

	if (accessor === 'output') {
		return record.outputPath ?? '';
	}

	// accessor is "result.<fieldName>"
	const fieldName = accessor.slice('result.'.length);
	if (!record.result) {
		throw new Error(
			`$step[${stepIndex}].result.${fieldName}: step ${stepIndex} produced no parseable output`
		);
	}
	return record.result[fieldName];
}

// Orchestration commands whose `file` arg is a *job file path*, not the
// pipeline target binary. For these, a step-level `file` must survive instead
// of being overwritten with `job.file`. We forward it as `jobFile` (the name
// the queue handler reads), so both `args.file` (documented) and `args.jobFile`
// work from a pipeline step.
const JOB_FILE_ARG_COMMANDS = new Set<string>([
	'hexcore.pipeline.queueJob'
]);

function buildCommandOptions(
	filePath: string,
	step: PipelineStep,
	output: StepOutputPath | undefined,
	quietMode: boolean,
	stepRecords: StepRecord[],
	currentIndex: number,
	resolvedCommand?: string
): PipelineCommandOptions {
	const merged: PipelineCommandOptions = {};
	const usesJobFileArg = resolvedCommand !== undefined && JOB_FILE_ARG_COMMANDS.has(resolvedCommand);
	if (step.args) {
		// Resolve $step[N] references before spreading args into the command options.
		const resolvedArgs = resolveStepReferences(step.args, stepRecords, currentIndex);
		for (const [key, value] of Object.entries(resolvedArgs)) {
			// For orchestration commands, preserve the documented `file`/`jobFile`
			// job-path arg by forwarding it as `jobFile` (it would otherwise be
			// clobbered by the pipeline target binary below).
			if (usesJobFileArg && (key === 'file' || key === 'jobFile')) {
				if (merged.jobFile === undefined && typeof value === 'string') {
					merged.jobFile = value;
				}
				continue;
			}
			// Pipeline controls these fields to guarantee consistent headless behavior.
			if (key === 'file' || key === 'quiet' || key === 'output') {
				continue;
			}
			merged[key] = value;
		}
	}
	merged.file = filePath;
	merged.quiet = quietMode;
	if (output) {
		merged.output = output;
	}

	return merged;
}

function shouldValidateOutput(step: PipelineStep, capability?: CommandCapability): boolean {
	if (typeof step.expectOutput === 'boolean') {
		return step.expectOutput;
	}
	if (step.output !== undefined) {
		return true;
	}
	return capability?.validateOutput ?? false;
}

function shouldProvideOutput(step: PipelineStep, capability: CommandCapability | undefined): boolean {
	if (step.output !== undefined) {
		return true;
	}
	if (typeof step.expectOutput === 'boolean') {
		return step.expectOutput;
	}
	return capability?.validateOutput ?? false;
}

function resolveStepTimeout(step: PipelineStep, capability?: CommandCapability): number {
	if (typeof step.timeoutMs === 'number') {
		return step.timeoutMs;
	}
	if (capability) {
		return capability.defaultTimeoutMs;
	}
	return DEFAULT_TIMEOUT_MS;
}

function resolveRetryCount(step: PipelineStep): number {
	if (typeof step.retryCount === 'number') {
		return step.retryCount;
	}
	return DEFAULT_RETRY_COUNT;
}

function resolveRetryDelayMs(step: PipelineStep): number {
	if (typeof step.retryDelayMs === 'number') {
		return step.retryDelayMs;
	}
	return DEFAULT_RETRY_DELAY_MS;
}

function validateStepOutput(outputPath: string): void {
	if (!fs.existsSync(outputPath)) {
		throw new Error(`Expected output file was not created: ${outputPath}`);
	}
	const stat = fs.statSync(outputPath);
	if (stat.size === 0) {
		throw new Error(`Output file was created but is empty: ${outputPath}`);
	}
}

async function withTimeout<T>(promise: PromiseLike<T>, timeoutMs: number, timeoutMessage: string): Promise<T> {
	let timeoutHandle: NodeJS.Timeout | undefined;
	const timeoutPromise = new Promise<T>((_resolve, reject) => {
		timeoutHandle = setTimeout(() => {
			reject(new TimeoutError(timeoutMessage));
		}, timeoutMs);
	});

	try {
		return await Promise.race([Promise.resolve(promise), timeoutPromise]);
	} finally {
		if (timeoutHandle) {
			clearTimeout(timeoutHandle);
		}
	}
}

function createStepStatus(
	step: PipelineStep,
	resolvedCmd: string,
	startedAt: Date,
	attemptCount: number,
	outputPath: string | undefined,
	status: 'ok' | 'error' | 'skipped',
	error?: string
): PipelineStepStatus {
	const finishedAt = new Date();
	// When a step errors and the command never wrote its output file,
	// leave an error stub so downstream consumers ({ $step[N].output.path })
	// can Read() it and see the failure reason instead of getting file-not-found.
	if (status === 'error' && outputPath && !fs.existsSync(outputPath)) {
		try {
			fs.mkdirSync(path.dirname(outputPath), { recursive: true });
			fs.writeFileSync(outputPath, JSON.stringify({
				ok: false,
				error: error ?? 'Step failed',
				cmd: step.cmd,
				resolvedCmd,
				attemptCount,
				stub: true
			}, null, 2));
		} catch { /* ignore — status is still reported via status.json */ }
	}
	// v3.8.0 observability: probe output size for `ok` + stubbed `error` cases.
	// Best-effort; never throws — missing files just omit the field.
	let outputBytes: number | undefined;
	if (outputPath) {
		try {
			const st = fs.statSync(outputPath);
			outputBytes = st.size;
		} catch { /* ignore — field stays undefined */ }
	}
	return {
		cmd: step.cmd,
		resolvedCmd,
		status,
		startedAt: startedAt.toISOString(),
		finishedAt: finishedAt.toISOString(),
		durationMs: finishedAt.getTime() - startedAt.getTime(),
		attemptCount,
		outputPath,
		outputBytes,
		error
	};
}

function normalizeExecutionError(error: unknown, resolvedCommand: string): string {
	const base = toErrorMessage(error);
	if (/command .*not found/i.test(base) || /command .* is not available/i.test(base)) {
		return `Command is not available: ${resolvedCommand}`;
	}
	return base;
}

function getExtensionStates(ownerIds: readonly string[]): PipelineDoctorExtensionState[] {
	return ownerIds.map(id => {
		const extension = vscode.extensions.getExtension(id);
		return {
			id,
			installed: extension !== undefined,
			active: extension?.isActive === true
		};
	});
}

async function ensureCommandReady(command: string, logPath: string, index: number): Promise<void> {
	if (await isCommandRegistered(command)) {
		return;
	}

	const ownerExtensions = COMMAND_OWNERS.get(command);
	if (!ownerExtensions || ownerExtensions.length === 0) {
		throw new Error(`Command is not registered in Extension Host and has no owner mapping: ${command}`);
	}

	appendLog(logPath, `[Step ${index + 1}] Command preflight: ${command} is not registered yet. Attempting extension activation.`);

	const ownerStates: string[] = [];
	for (const ownerId of ownerExtensions) {
		const extension = vscode.extensions.getExtension(ownerId);
		if (!extension) {
			ownerStates.push(`${ownerId}=missing`);
			continue;
		}

		if (extension.isActive) {
			ownerStates.push(`${ownerId}=active`);
			continue;
		}

		try {
			await extension.activate();
			ownerStates.push(`${ownerId}=activated`);
		} catch (error: unknown) {
			ownerStates.push(`${ownerId}=activate-failed(${toErrorMessage(error)})`);
		}
	}

	const registered = await waitForCommandRegistration(command, 1500);
	if (registered) {
		appendLog(logPath, `[Step ${index + 1}] Command preflight: ${command} registered after activation.`);
		return;
	}

	const ownerDetail = ownerStates.length > 0
		? ownerStates.join('; ')
		: 'no owner diagnostics';
	throw new Error(`Command is not available in Extension Host: ${command}. Owner state: ${ownerDetail}`);
}

async function isCommandRegistered(command: string): Promise<boolean> {
	const commands = await vscode.commands.getCommands(true);
	return commands.includes(command);
}

async function waitForCommandRegistration(command: string, timeoutMs: number): Promise<boolean> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await isCommandRegistered(command)) {
			return true;
		}
		await delay(50);
	}
	return isCommandRegistered(command);
}

function delay(ms: number): Promise<void> {
	return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Best-effort cancellation when a step exceeds its timeout.
 *
 * HONEST BEHAVIOUR: the pipeline cannot interrupt a `vscode.commands.executeCommand`
 * promise. We only race it against a timer (see {@link withTimeout}); when the
 * timer wins we ABANDON the command and move on, but the underlying operation
 * keeps running in the Extension Host until it finishes on its own. The only
 * real cancellation we can perform is invoking an explicit `cancelCommand` if a
 * capability declares one (none do today). We do NOT fake a cancel — when none
 * is configured we say so plainly in the log.
 *
 * @returns `true` only if a real cancel command was successfully executed.
 */
async function tryCancelOnTimeout(capability: CommandCapability, logPath: string, index: number): Promise<boolean> {
	if (!capability.cancelCommand) {
		appendLog(logPath, `[Step ${index + 1}] Timeout: no cancel command is wired for this command. The step is abandoned and marked timed-out, but the underlying operation may STILL BE RUNNING in the Extension Host until it completes on its own.`);
		return false;
	}
	try {
		await vscode.commands.executeCommand(capability.cancelCommand);
		appendLog(logPath, `[Step ${index + 1}] Timeout: cancellation command executed (${capability.cancelCommand}).`);
		return true;
	} catch (error: unknown) {
		appendLog(logPath, `[Step ${index + 1}] Timeout: cancellation command failed (${capability.cancelCommand}): ${toErrorMessage(error)}. Underlying operation may still be running.`);
		return false;
	}
}

class TimeoutError extends Error {
	constructor(message: string) {
		super(message);
		this.name = 'TimeoutError';
	}
}

function sanitizeFileName(value: string): string {
	return value
		.replace(/[^a-zA-Z0-9._-]+/g, '-')
		.replace(/-+/g, '-')
		.replace(/^-|-$/g, '')
		.toLowerCase() || 'step';
}

function getStringField(record: Record<string, unknown>, field: string): string {
	const value = record[field];
	if (typeof value !== 'string' || value.trim().length === 0) {
		throw new Error(`Missing or invalid "${field}" field`);
	}
	return value.trim();
}

function toAbsolutePath(baseDir: string, value: string): string {
	return path.isAbsolute(value)
		? value
		: path.resolve(baseDir, value);
}

function writeJson(filePath: string, data: unknown): void {
	fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

function appendLog(logPath: string, message: string): void {
	const timestamp = new Date().toISOString();
	fs.appendFileSync(logPath, `[${timestamp}] ${message}\n`, 'utf8');
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
 * Singleton instance of the JobQueueManager.
 */
let jobQueueManagerInstance: JobQueueManager | undefined;

/**
 * Gets or creates the singleton JobQueueManager instance.
 * @param concurrencyLimit Optional concurrency limit (default: 2)
 * @returns The JobQueueManager instance
 */
export function getJobQueueManagerInstance(concurrencyLimit?: number): JobQueueManager {
	if (!jobQueueManagerInstance) {
		// Pool size. Historically this defaulted to SEQUENTIAL (1) because the
		// emulation engine (DebugEngine) is a process-wide singleton holding ONE
		// shared x64-ELF worker, so two emulation/debug jobs corrupted each
		// other's session (a sibling's disposeHeadless / readMemory touched the
		// shared engine outside the per-session SessionLock and tore down the
		// in-flight worker). Issue #26 (sessionId-based sticky worker routing)
		// now lets same-session jobs pin to one worker, so a >1 pool is safe for
		// session-tagged and stateless work. The actual size is driven by the
		// hexcore.pipeline.queue.poolSize setting, which activate() reads and
		// passes here on first call (Issue #25). When a caller passes nothing we
		// stay conservative and sequential.
		jobQueueManagerInstance = getJobQueueManager(concurrencyLimit ?? 1);
		// Configure the job executor to use the AutomationPipelineRunner
		jobQueueManagerInstance.setJobExecutor(async (filePath: string, abortSignal: AbortSignal) => {
			const runner = new AutomationPipelineRunner();
			return runner.runJobFile(filePath, undefined, abortSignal);
		});
		jobQueueManagerInstance.start();
	}
	return jobQueueManagerInstance;
}

/**
 * Disposes the JobQueueManager singleton instance.
 */
export function disposeJobQueueManagerInstance(): void {
	if (jobQueueManagerInstance) {
		jobQueueManagerInstance.dispose();
		jobQueueManagerInstance = undefined;
	}
}
