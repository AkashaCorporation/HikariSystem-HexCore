/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as path from 'path';
import { AgentBridgeClientError, requestAgentBridge, streamAgentBridgeEvents } from './agentBridgeClient';
import { isRecord } from './agentBridgeProtocol';

interface CliIo {
	stdout(value: string): void;
	stderr(value: string): void;
}

interface ParsedArguments {
	command: string;
	positionals: string[];
	flags: Map<string, string | boolean>;
}

const defaultIo: CliIo = {
	stdout: value => process.stdout.write(`${value}\n`),
	stderr: value => process.stderr.write(`${value}\n`),
};

export async function main(argv = process.argv.slice(2), io: CliIo = defaultIo): Promise<number> {
	try {
		const parsed = parseArguments(argv);
		if (parsed.command === 'help' || parsed.command === '--help' || parsed.command === '-h') {
			io.stdout(helpText());
			return 0;
		}
		const workspace = path.resolve(stringFlag(parsed.flags, 'workspace') ?? process.cwd());
		switch (parsed.command) {
			case 'validate': {
				const result = await requestAgentBridge(workspace, 'validate', {
					jobFile: requiredPositional(parsed, 0, 'validate requires a job file path.'),
				});
				io.stdout(JSON.stringify(result));
				return isRecord(result) && result.valid === false ? 3 : 0;
			}
			case 'submit': {
				const jobFile = requiredPositional(parsed, 0, 'submit requires a job file path.');
				const params: Record<string, unknown> = { jobFile };
				const priority = stringFlag(parsed.flags, 'priority');
				const sessionId = stringFlag(parsed.flags, 'session');
				if (priority) { params.priority = priority; }
				if (sessionId) { params.sessionId = sessionId; }
				const submitted = await requestAgentBridge(workspace, 'submit', params);
				if (parsed.flags.get('wait') === true) {
					if (!isRecord(submitted) || typeof submitted.jobId !== 'string') {
						throw new AgentBridgeClientError('invalid-submit-response', 'Submit response did not contain jobId.');
					}
					const terminal = await requestAgentBridge(workspace, 'wait', {
						jobId: submitted.jobId,
						...timeoutParam(parsed.flags),
					});
					io.stdout(JSON.stringify({ submit: submitted, terminal }));
					return terminalExitCode(terminal);
				}
				io.stdout(JSON.stringify(submitted));
				return 0;
			}
			case 'status': {
				const result = await requestAgentBridge(workspace, 'status', { jobId: requiredPositional(parsed, 0, 'status requires a job ID.') });
				io.stdout(JSON.stringify(result));
				return 0;
			}
			case 'wait': {
				const result = await requestAgentBridge(workspace, 'wait', {
					jobId: requiredPositional(parsed, 0, 'wait requires a job ID.'),
					...timeoutParam(parsed.flags),
				});
				io.stdout(JSON.stringify(result));
				return terminalExitCode(result);
			}
			case 'events': {
				const params: Record<string, unknown> = { jobId: requiredPositional(parsed, 0, 'events requires a job ID.') };
				const since = integerFlag(parsed.flags, 'since-sequence');
				if (since !== undefined) { params.sinceSequence = since; }
				const streamed = await streamAgentBridgeEvents(workspace, params, message => io.stdout(JSON.stringify(message)));
				return streamed.terminalEvent ? terminalExitCode(streamed.terminalEvent.event.payload) : 0;
			}
			case 'cancel': {
				const result = await requestAgentBridge(workspace, 'cancel', { jobId: requiredPositional(parsed, 0, 'cancel requires a job ID.') });
				io.stdout(JSON.stringify(result));
				return 0;
			}
			case 'capabilities': {
				const result = await requestAgentBridge(workspace, 'capabilities');
				io.stdout(JSON.stringify(parsed.flags.get('summary') === true ? summarizeCapabilities(result) : result));
				return 0;
			}
			case 'schema': {
				const result = await requestAgentBridge(workspace, 'capabilities');
				if (!isRecord(result) || result.jobSchema === undefined) {
					throw new AgentBridgeClientError('schema-unavailable', 'The running HexCore bridge did not provide a job schema.');
				}
				io.stdout(JSON.stringify({ protocolVersion: result.protocolVersion, jobSchema: result.jobSchema }));
				return 0;
			}
			case 'doctor': {
				const result = await requestAgentBridge(workspace, 'doctor');
				io.stdout(JSON.stringify(parsed.flags.get('summary') === true ? summarizeDoctor(result) : result));
				return 0;
			}
			default:
				throw new AgentBridgeClientError('unknown-command', `Unknown command: ${parsed.command}. Run hexcore-agent help.`);
		}
	} catch (error) {
		const normalized = error instanceof AgentBridgeClientError
			? error
			: new AgentBridgeClientError('cli-error', error instanceof Error ? error.message : String(error));
		io.stderr(JSON.stringify({ ok: false, error: { code: normalized.code, message: normalized.message, ...(normalized.details === undefined ? {} : { details: normalized.details }) } }));
		return 1;
	}
}

function parseArguments(argv: string[]): ParsedArguments {
	if (argv.length === 0) {
		return { command: 'help', positionals: [], flags: new Map() };
	}
	const command = argv[0];
	const positionals: string[] = [];
	const flags = new Map<string, string | boolean>();
	for (let index = 1; index < argv.length; index++) {
		const value = argv[index];
		if (!value.startsWith('--')) {
			positionals.push(value);
			continue;
		}
		const name = value.slice(2);
		if (name === 'wait' || name === 'summary') {
			flags.set(name, true);
			continue;
		}
		const next = argv[index + 1];
		if (next === undefined || next.startsWith('--')) {
			throw new AgentBridgeClientError('invalid-arguments', `Flag --${name} requires a value.`);
		}
		flags.set(name, next);
		index++;
	}
	return { command, positionals, flags };
}

function requiredPositional(parsed: ParsedArguments, index: number, message: string): string {
	const value = parsed.positionals[index];
	if (!value) {
		throw new AgentBridgeClientError('invalid-arguments', message);
	}
	return value;
}

function stringFlag(flags: Map<string, string | boolean>, name: string): string | undefined {
	const value = flags.get(name);
	return typeof value === 'string' ? value : undefined;
}

function integerFlag(flags: Map<string, string | boolean>, name: string): number | undefined {
	const raw = stringFlag(flags, name);
	if (raw === undefined) {
		return undefined;
	}
	const value = Number(raw);
	if (!Number.isSafeInteger(value) || value < 0) {
		throw new AgentBridgeClientError('invalid-arguments', `--${name} must be a non-negative integer.`);
	}
	return value;
}

function timeoutParam(flags: Map<string, string | boolean>): Record<string, unknown> {
	const timeoutMs = integerFlag(flags, 'timeout-ms');
	return timeoutMs === undefined ? {} : { timeoutMs };
}

function terminalExitCode(value: unknown): number {
	if (!isRecord(value)) {
		return 0;
	}
	if (value.queueStatus === 'failed' || value.queueStatus === 'cancelled') {
		return 2;
	}
	if (isRecord(value.pipeline) && value.pipeline.status === 'error') {
		return 2;
	}
	return 0;
}

function helpText(): string {
	return [
		'HexCore Agent Bridge CLI v1',
		'',
		'HexCore must be open with the same trusted workspace before this CLI is used.',
		'',
		'Usage:',
		'  hexcore-agent validate <job.hexcore_job.json>',
		'  hexcore-agent submit <job.hexcore_job.json> [--priority high|normal|low] [--session ID] [--wait] [--timeout-ms N]',
		'  hexcore-agent status <jobId>',
		'  hexcore-agent wait <jobId> [--timeout-ms N]',
		'  hexcore-agent events <jobId> [--since-sequence N]',
		'  hexcore-agent cancel <jobId>',
		'  hexcore-agent capabilities',
		'  hexcore-agent schema',
		'  hexcore-agent doctor',
		'',
		'Common:',
		'  --workspace PATH   Workspace authenticated by the running HexCore instance (default: cwd)',
		'  --summary          Compact capabilities/doctor output for agent context',
	].join('\n');
}

function summarizeCapabilities(value: unknown): unknown {
	if (!isRecord(value)) { return value; }
	return {
		protocolVersion: value.protocolVersion,
		transport: value.transport,
		workspace: value.workspace,
		methods: isRecord(value.methods) ? Object.keys(value.methods).sort() : [],
		limits: value.limits,
		pipelineCapabilityCount: Array.isArray(value.pipelineCapabilities) ? value.pipelineCapabilities.length : 0,
		jobSchemaTitle: isRecord(value.jobSchema) ? value.jobSchema.title : undefined,
	};
}

function summarizeDoctor(value: unknown): unknown {
	if (!isRecord(value)) { return value; }
	return {
		generatedAt: value.generatedAt,
		workspaceRoot: value.workspaceRoot,
		totalCapabilities: value.totalCapabilities,
		registeredHexcoreCommands: value.registeredHexcoreCommands,
		readyCommands: value.readyCommands,
		degradedCommands: value.degradedCommands,
		missingCommands: value.missingCommands,
		gatedCommands: value.gatedCommands,
		undeclaredHexcoreCommandCount: Array.isArray(value.undeclaredHexcoreCommands) ? value.undeclaredHexcoreCommands.length : 0,
	};
}

if (require.main === module) {
	void main().then(code => { process.exitCode = code; });
}
