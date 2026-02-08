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
const COMMAND_ALIASES = new Map<string, string>([
	['hexcore.hash.file', 'hexcore.hashcalc.calculate'],
	['hexcore.hash.calculate', 'hexcore.hashcalc.calculate'],
	['hexcore.disasm.open', 'hexcore.disasm.openFile'],
	['hexcore.pe.analyze', 'hexcore.peanalyzer.analyze']
]);

const COMMAND_CAPABILITIES = new Map<string, CommandCapability>([
	['hexcore.filetype.detect', { headless: true, defaultTimeoutMs: 60000, validateOutput: true }],
	['hexcore.hashcalc.calculate', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.entropy.analyze', { headless: true, defaultTimeoutMs: 90000, validateOutput: true }],
	['hexcore.strings.extract', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.peanalyzer.analyze', { headless: true, defaultTimeoutMs: 120000, validateOutput: true }],
	['hexcore.disasm.analyzeAll', { headless: true, defaultTimeoutMs: 180000, validateOutput: true }],
	['hexcore.disasm.analyzeFile', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens editor UI.' }],
	['hexcore.disasm.openFile', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens file picker.' }],
	['hexcore.disasm.searchString', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command prompts for input.' }],
	['hexcore.disasm.exportASM', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive command opens save dialog.' }],
	['hexcore.debug.emulate', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive debugger command opens file picker and UI.' }],
	['hexcore.debug.emulateWithArch', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Interactive debugger command opens prompts and UI.' }],
	['hexcore.pipeline.runJob', { headless: false, defaultTimeoutMs: DEFAULT_TIMEOUT_MS, validateOutput: false, reason: 'Recursive pipeline invocation is not supported from a step.' }]
]);

const COMMAND_OWNERS = new Map<string, readonly string[]>([
	['hexcore.filetype.detect', ['hikarisystem.hexcore-filetype']],
	['hexcore.hashcalc.calculate', ['hikarisystem.hexcore-hashcalc']],
	['hexcore.entropy.analyze', ['hikarisystem.hexcore-entropy']],
	['hexcore.strings.extract', ['hikarisystem.hexcore-strings']],
	['hexcore.peanalyzer.analyze', ['hikarisystem.hexcore-peanalyzer']],
	['hexcore.disasm.analyzeAll', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.analyzeFile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.openFile', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.searchString', ['hikarisystem.hexcore-disassembler']],
	['hexcore.disasm.exportASM', ['hikarisystem.hexcore-disassembler']],
	['hexcore.debug.emulate', ['hikarisystem.hexcore-debugger']],
	['hexcore.debug.emulateWithArch', ['hikarisystem.hexcore-debugger']],
	['hexcore.pipeline.runJob', ['hikarisystem.hexcore-disassembler']]
]);

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
		appendLog(logPath, `Job started for file: ${job.file}`);
		let failed = false;

		for (let index = 0; index < job.steps.length; index++) {
			const step = job.steps[index];
			const resolvedCommand = resolveCommand(step.cmd);
			const capability = COMMAND_CAPABILITIES.get(resolvedCommand);
			const output = resolveStepOutput(job.outDir, step, index);
			const validateOutput = shouldValidateOutput(step, capability);
			const timeoutMs = resolveStepTimeout(step, capability);
			const startedAt = new Date();

			appendLog(logPath, `[Step ${index + 1}] ${step.cmd} -> ${resolvedCommand}`);
			appendLog(logPath, `[Step ${index + 1}] Timeout: ${timeoutMs}ms`);

			if (!capability) {
				const errorMessage = `Command is not declared in pipeline capability map: ${resolvedCommand}`;
				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					output.path,
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
					output.path,
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
					output.path,
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

			try {
				await withTimeout(
					vscode.commands.executeCommand(resolvedCommand, commandOptions),
					timeoutMs,
					`Step ${index + 1} (${resolvedCommand}) timed out after ${timeoutMs}ms`
				);

				if (validateOutput) {
					validateStepOutput(output.path);
				}

				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					output.path,
					'ok'
				);
				status.steps.push(stepStatus);
				appendLog(logPath, `[Step ${index + 1}] OK (${stepStatus.durationMs}ms)`);
				writeJson(statusPath, status);
			} catch (error: unknown) {
				const errorMessage = normalizeExecutionError(error, resolvedCommand);
				if (error instanceof TimeoutError) {
					await tryCancelOnTimeout(capability, logPath, index);
				}

				const stepStatus = createStepStatus(
					step,
					resolvedCommand,
					startedAt,
					output.path,
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

		status.finishedAt = new Date().toISOString();
		status.status = failed ? 'error' : 'ok';
		writeJson(statusPath, status);
		appendLog(logPath, `Job finished with status: ${status.status}`);

		return status;
	}
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
		expectOutput
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

function buildCommandOptions(filePath: string, step: PipelineStep, output: StepOutputPath, quietMode: boolean): PipelineCommandOptions {
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
	merged.output = output;

	return merged;
}

function shouldValidateOutput(step: PipelineStep, capability?: CommandCapability): boolean {
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
