/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import * as os from 'os';
import * as path from 'path';

export const AGENT_BRIDGE_PROTOCOL_VERSION = 1 as const;
export const AGENT_BRIDGE_MAX_REQUEST_BYTES = 1024 * 1024;
export const AGENT_BRIDGE_MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
export const AGENT_BRIDGE_DEFAULT_WAIT_TIMEOUT_MS = 30 * 60 * 1000;
export const AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS = 24 * 60 * 60 * 1000;

export type AgentBridgeMethod =
	| 'validate'
	| 'submit'
	| 'status'
	| 'wait'
	| 'events'
	| 'cancel'
	| 'capabilities'
	| 'doctor';

export interface AgentBridgeRequest {
	protocolVersion: typeof AGENT_BRIDGE_PROTOCOL_VERSION;
	requestId: string;
	token: string;
	method: AgentBridgeMethod;
	params?: Record<string, unknown>;
}

export interface AgentBridgeErrorPayload {
	code: string;
	message: string;
	details?: unknown;
}

export interface AgentBridgeResponse {
	protocolVersion: typeof AGENT_BRIDGE_PROTOCOL_VERSION;
	type: 'response';
	requestId: string;
	ok: boolean;
	result?: unknown;
	error?: AgentBridgeErrorPayload;
}

export interface AgentBridgeEvent {
	protocolVersion: typeof AGENT_BRIDGE_PROTOCOL_VERSION;
	type: 'event';
	event: {
		sequence: number;
		timestamp: string;
		eventType: 'submitted' | 'submission-deduped' | 'running' | 'terminal';
		jobId: string;
		payload: unknown;
	};
}

export interface AgentBridgeDiscovery {
	schemaVersion: 1;
	protocolVersion: typeof AGENT_BRIDGE_PROTOCOL_VERSION;
	instanceId: string;
	workspace: string;
	workspaceSha256: string;
	endpoint: string;
	token: string;
	pid: number;
	createdAt: string;
	extensionVersion: string;
}

export class AgentBridgeProtocolError extends Error {
	constructor(
		public readonly code: string,
		message: string,
		public readonly details?: unknown,
	) {
		super(message);
		this.name = 'AgentBridgeProtocolError';
	}
}

export const AGENT_BRIDGE_METHOD_SCHEMAS: Readonly<Record<AgentBridgeMethod, unknown>> = Object.freeze({
	validate: {
		type: 'object',
		required: ['jobFile'],
		additionalProperties: false,
		properties: {
			jobFile: { type: 'string', description: 'Workspace-contained *.hexcore_job.json path.' },
		},
	},
	submit: {
		type: 'object',
		required: ['jobFile'],
		additionalProperties: false,
		properties: {
			jobFile: { type: 'string', description: 'Workspace-contained *.hexcore_job.json path.' },
			priority: { enum: ['high', 'normal', 'low'] },
			sessionId: { type: 'string', minLength: 1, maxLength: 128 },
		},
	},
	status: jobIdSchema(),
	wait: {
		type: 'object',
		required: ['jobId'],
		additionalProperties: false,
		properties: {
			jobId: { type: 'string', minLength: 1 },
			timeoutMs: { type: 'integer', minimum: 1, maximum: AGENT_BRIDGE_MAX_WAIT_TIMEOUT_MS },
		},
	},
	events: {
		type: 'object',
		required: ['jobId'],
		additionalProperties: false,
		properties: {
			jobId: { type: 'string', minLength: 1 },
			sinceSequence: { type: 'integer', minimum: 0 },
		},
	},
	cancel: jobIdSchema(),
	capabilities: emptySchema(),
	doctor: emptySchema(),
});

function jobIdSchema(): unknown {
	return {
		type: 'object',
		required: ['jobId'],
		additionalProperties: false,
		properties: { jobId: { type: 'string', minLength: 1 } },
	};
}

function emptySchema(): unknown {
	return { type: 'object', additionalProperties: false, properties: {} };
}

export function canonicalWorkspacePath(workspaceRoot: string): string {
	const resolved = path.resolve(workspaceRoot);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

export function workspaceSha256(workspaceRoot: string): string {
	return sha256Text(canonicalWorkspacePath(workspaceRoot));
}

export function agentBridgeDiscoveryPath(workspaceRoot: string): string {
	return path.join(os.tmpdir(), 'hexcore-agent', workspaceSha256(workspaceRoot), 'bridge.json');
}

export function createAgentBridgeEndpoint(workspaceRoot: string, instanceId: string): string {
	const suffix = `${workspaceSha256(workspaceRoot).slice(0, 16)}-${instanceId.replace(/-/g, '').slice(0, 12)}`;
	if (process.platform === 'win32') {
		return `\\\\.\\pipe\\hexcore-agent-v1-${suffix}`;
	}
	return path.join(os.tmpdir(), `hexcore-agent-v1-${suffix}.sock`);
}

export function parseAgentBridgeRequest(line: string): AgentBridgeRequest {
	if (Buffer.byteLength(line, 'utf8') > AGENT_BRIDGE_MAX_REQUEST_BYTES) {
		throw new AgentBridgeProtocolError('request-too-large', `Request exceeds ${AGENT_BRIDGE_MAX_REQUEST_BYTES} bytes.`);
	}
	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch {
		throw new AgentBridgeProtocolError('invalid-json', 'Request is not valid JSON.');
	}
	if (!isRecord(parsed)) {
		throw new AgentBridgeProtocolError('invalid-request', 'Request must be a JSON object.');
	}
	if (parsed.protocolVersion !== AGENT_BRIDGE_PROTOCOL_VERSION) {
		throw new AgentBridgeProtocolError(
			'unsupported-protocol',
			`Expected protocolVersion=${AGENT_BRIDGE_PROTOCOL_VERSION}.`,
			{ received: parsed.protocolVersion },
		);
	}
	const requestId = requiredString(parsed, 'requestId', 128);
	const token = requiredString(parsed, 'token', 512);
	const method = requiredString(parsed, 'method', 64);
	if (!isAgentBridgeMethod(method)) {
		throw new AgentBridgeProtocolError('unknown-method', `Unknown Agent Bridge method: ${method}`);
	}
	if (parsed.params !== undefined && !isRecord(parsed.params)) {
		throw new AgentBridgeProtocolError('invalid-params', 'params must be a JSON object when present.');
	}
	return {
		protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
		requestId,
		token,
		method,
		...(parsed.params ? { params: parsed.params } : {}),
	};
}

export function makeAgentBridgeResponse(requestId: string, result: unknown): AgentBridgeResponse {
	return {
		protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
		type: 'response',
		requestId,
		ok: true,
		result,
	};
}

export function makeAgentBridgeErrorResponse(requestId: string, error: unknown): AgentBridgeResponse {
	const payload = error instanceof AgentBridgeProtocolError
		? { code: error.code, message: error.message, ...(error.details === undefined ? {} : { details: error.details }) }
		: { code: 'internal-error', message: error instanceof Error ? error.message : String(error) };
	return {
		protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
		type: 'response',
		requestId,
		ok: false,
		error: payload,
	};
}

export function serializeAgentBridgeMessage(message: AgentBridgeResponse | AgentBridgeEvent): string {
	const serialized = JSON.stringify(message);
	if (Buffer.byteLength(serialized, 'utf8') > AGENT_BRIDGE_MAX_RESPONSE_BYTES) {
		throw new AgentBridgeProtocolError('response-too-large', `Response exceeds ${AGENT_BRIDGE_MAX_RESPONSE_BYTES} bytes.`);
	}
	return `${serialized}\n`;
}

export function canonicalJson(value: unknown): string {
	return JSON.stringify(sortCanonicalValue(value));
}

export function sha256Canonical(value: unknown): string {
	return sha256Text(canonicalJson(value));
}

export function sha256Text(value: string): string {
	return crypto.createHash('sha256').update(value, 'utf8').digest('hex');
}

export function timingSafeTokenEqual(left: string, right: string): boolean {
	const leftBuffer = Buffer.from(left, 'utf8');
	const rightBuffer = Buffer.from(right, 'utf8');
	return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isAgentBridgeMethod(value: string): value is AgentBridgeMethod {
	return value === 'validate'
		|| value === 'submit'
		|| value === 'status'
		|| value === 'wait'
		|| value === 'events'
		|| value === 'cancel'
		|| value === 'capabilities'
		|| value === 'doctor';
}

function requiredString(record: Record<string, unknown>, key: string, maxLength: number): string {
	const value = record[key];
	if (typeof value !== 'string' || value.trim().length === 0 || value.length > maxLength) {
		throw new AgentBridgeProtocolError('invalid-request', `${key} must be a non-empty string of at most ${maxLength} characters.`);
	}
	return value;
}

function sortCanonicalValue(value: unknown): unknown {
	if (Array.isArray(value)) {
		return value.map(entry => entry === undefined ? null : sortCanonicalValue(entry));
	}
	if (isRecord(value)) {
		const output: Record<string, unknown> = {};
		for (const key of Object.keys(value).sort()) {
			if (value[key] !== undefined) {
				output[key] = sortCanonicalValue(value[key]);
			}
		}
		return output;
	}
	if (typeof value === 'number' && !Number.isFinite(value)) {
		return null;
	}
	return value;
}
