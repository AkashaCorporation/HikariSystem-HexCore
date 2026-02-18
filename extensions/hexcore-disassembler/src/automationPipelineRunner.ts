/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import * as vscode from 'vscode';

export type PipelineOutputFormat = 'json' | 'md';

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
}

export interface PipelineJobFile {
	file: string;
	outDir: string;
	steps: PipelineStep[];
	quiet?: boolean;
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
	error?: string;
}

export interface PipelineRunStatus {
	jobFile: string;
	file: string;
	outDir: string;
	status: 'running' | 'ok' | 'error';
	startedAt: string;
	finishedAt?: string;
	steps: PipelineStepStatus[];
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
	readiness: 'ready' | 'degraded' | 'missing';
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
	undeclaredHexcoreCommands: string[];
	entries: PipelineDoctorEntry[];
}

interface NormalizedPipelineJob {
	file: string;
	outDir: string;
	steps: PipelineStep[];
	quiet: boolean;
}

interface StepOutputPath {
	path: string;
	format: PipelineOutputFormat;
}

interface CommandCapability {
	headless: boolean;
	defaultTimeoutMs: number;
	validateOutput: boolean;
	reason?: string;
	cancelCommand?: string;
}

const JOB_STATUS_FILENAME = 'hexcore-pipeline.status.json';
const JOB_LOG_FILENAME = 'hexcore-pipeline.log';
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
	['hexcore.hex.search', 'hexcore.hexview.searchHeadless']
]);

const COMMAND_CAPABILITIES = new Map<string, CommandCapability>([
	['hexcore.filetype.detect', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.hashcalc.calculate', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.entropy.analyze', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.strings.extract', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.peanalyzer.analyze', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
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
	['hexcore.disasm.buildFormula', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.disasm.checkConstants', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.disasm.searchStringHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.exportASMHeadless', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
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
	['hexcore.elfanalyzer.analyze', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.elfanalyzer.analyzeActive', { headless: false, defaultTimeoutMs: 60000, validateOutput: false, reason: 'Interactive command analyzes active editor file.' }],
	['hexcore.base64.decodeHeadless', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.hexview.dumpHeadless', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.hexview.searchHeadless', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.pipeline.composeReport', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
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
	['hexcore.elfanalyzer.analyze', ['hikarisystem.hexcore-elfanalyzer']],
	['hexcore.elfanalyzer.analyzeActive', ['hikarisystem.hexcore-elfanalyzer']],
	['hexcore.base64.decodeHeadless', ['hikarisystem.hexcore-base64']],
	['hexcore.hexview.dumpHeadless', ['hikarisystem.hexcore-hexviewer']],
	['hexcore.hexview.searchHeadless', ['hikarisystem.hexcore-hexviewer']],
	['hexcore.pipeline.composeReport', ['hikarisystem.hexcore-report-composer']]
]);

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

	const capabilities = listCapabilities();
	const entries: PipelineDoctorEntry[] = capabilities.map(capability => {
		const ownerExtensions = getExtensionStates(capability.requiredExtension);
		const registered = commands.has(capability.command);
		const hasMissingOwner = ownerExtensions.some(owner => !owner.installed);
		const readiness: PipelineDoctorEntry['readiness'] = hasMissingOwner
			? 'missing'
			: (registered ? 'ready' : 'degraded');

		return {
			command: capability.command,
			aliases: capability.aliases,
			headless: capability.headless,
			validateOutput: capability.validateOutput,
			defaultTimeoutMs: capability.defaultTimeoutMs,
			registered,
			readiness,
			reason: capability.reason,
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
	const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? '(no workspace)';

	return {
		generatedAt: new Date().toISOString(),
		workspaceRoot,
		totalCapabilities: entries.length,
		registeredHexcoreCommands: registeredHexcoreCommands.length,
		readyCommands,
		degradedCommands,
		missingCommands,
		undeclaredHexcoreCommands,
		entries
	};
}

export class AutomationPipelineRunner {
	public async runJobFile(jobFilePath: string, quietOverride?: boolean): Promise<PipelineRunStatus> {
		const absoluteJobPath = path.resolve(jobFilePath);
		if (!fs.existsSync(absoluteJobPath)) {
			throw new Error(`Job file not found: ${absoluteJobPath}`);
		}

		const rawContent = fs.readFileSync(absoluteJobPath, 'utf8');
		const parsed = parseJsonFile(rawContent, absoluteJobPath);
		const normalized = normalizeJob(parsed, absoluteJobPath, quietOverride);

		return this.run(normalized, absoluteJobPath);
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

	private async run(job: NormalizedPipelineJob, jobFilePath: string): Promise<PipelineRunStatus> {
		fs.mkdirSync(job.outDir, { recursive: true });

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

		for (let index = 0; index < job.steps.length; index++) {
			const step = job.steps[index];
			const resolvedCommand = resolveCommand(step.cmd);
			const capability = COMMAND_CAPABILITIES.get(resolvedCommand);
			const validateOutput = shouldValidateOutput(step, capability);
			const provideOutput = shouldProvideOutput(step, capability);
			const output = provideOutput ? resolveStepOutput(job.outDir, step, index) : undefined;
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
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					break;
				}
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
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					break;
				}
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
				appendLog(logPath, `[Step ${index + 1}] ERROR: ${errorMessage}`);
				writeJson(statusPath, status);
				failed = true;
				if (!step.continueOnError) {
					break;
				}
				continue;
			}

			const commandOptions = buildCommandOptions(job.file, step, output, job.quiet);

			let attemptCount = 0;
			let executionError: unknown;
			let completed = false;

			while (attemptCount < maxAttempts) {
				attemptCount++;
				appendLog(logPath, `[Step ${index + 1}] Attempt ${attemptCount}/${maxAttempts}`);

				try {
					await withTimeout(
						vscode.commands.executeCommand(resolvedCommand, commandOptions),
						timeoutMs,
						`Step ${index + 1} (${resolvedCommand}) timed out after ${timeoutMs}ms`
					);

					if (validateOutput) {
						if (!output) {
							throw new Error(`Expected output validation for ${resolvedCommand}, but no output path was assigned.`);
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
					const errorMessage = normalizeExecutionError(error, resolvedCommand);
					if (error instanceof TimeoutError) {
						await tryCancelOnTimeout(capability, logPath, index);
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
						break;
					}
				}
			}

			if (!completed && executionError && !step.continueOnError) {
				break;
			}
		}

		status.finishedAt = new Date().toISOString();
		status.status = failed ? 'error' : 'ok';
		writeJson(statusPath, status);
		appendLog(logPath, `Job finished with status: ${status.status}`);

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

	const steps: PipelineStep[] = rawSteps.map((step, index) => normalizeStep(step, index, jobFilePath));
	const quiet = typeof quietOverride === 'boolean'
		? quietOverride
		: (typeof data.quiet === 'boolean' ? data.quiet : true);

	return {
		file,
		outDir,
		steps,
		quiet
	};
}

function normalizeStep(step: unknown, index: number, jobFilePath: string): PipelineStep {
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

	return {
		cmd,
		args,
		output,
		continueOnError,
		timeoutMs,
		expectOutput,
		retryCount,
		retryDelayMs
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
		outputPath = path.isAbsolute(explicitPath)
			? explicitPath
			: path.resolve(outDir, explicitPath);
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

function buildCommandOptions(filePath: string, step: PipelineStep, output: StepOutputPath | undefined, quietMode: boolean): PipelineCommandOptions {
	const merged: PipelineCommandOptions = {};
	if (step.args) {
		for (const [key, value] of Object.entries(step.args)) {
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
	return {
		cmd: step.cmd,
		resolvedCmd,
		status,
		startedAt: startedAt.toISOString(),
		finishedAt: finishedAt.toISOString(),
		durationMs: finishedAt.getTime() - startedAt.getTime(),
		attemptCount,
		outputPath,
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

async function tryCancelOnTimeout(capability: CommandCapability, logPath: string, index: number): Promise<void> {
	if (!capability.cancelCommand) {
		appendLog(logPath, `[Step ${index + 1}] Timeout: no cancel command configured.`);
		return;
	}
	try {
		await vscode.commands.executeCommand(capability.cancelCommand);
		appendLog(logPath, `[Step ${index + 1}] Timeout: cancellation command executed (${capability.cancelCommand}).`);
	} catch (error: unknown) {
		appendLog(logPath, `[Step ${index + 1}] Timeout: cancellation command failed (${capability.cancelCommand}): ${toErrorMessage(error)}`);
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
