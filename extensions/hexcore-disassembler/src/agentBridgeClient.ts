/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as net from 'net';
import * as path from 'path';
import {
	AGENT_BRIDGE_MAX_RESPONSE_BYTES,
	AGENT_BRIDGE_PROTOCOL_VERSION,
	AgentBridgeProtocolError,
	agentBridgeDiscoveryPath,
	canonicalWorkspacePath,
	isRecord,
	workspaceSha256,
	type AgentBridgeDiscovery,
	type AgentBridgeEvent,
	type AgentBridgeMethod,
	type AgentBridgeRequest,
	type AgentBridgeResponse,
} from './agentBridgeProtocol';

const DEFAULT_CONNECT_TIMEOUT_MS = 5000;

export class AgentBridgeClientError extends Error {
	constructor(
		public readonly code: string,
		message: string,
		public readonly details?: unknown,
	) {
		super(message);
		this.name = 'AgentBridgeClientError';
	}
}

export interface StreamAgentBridgeResult {
	response: AgentBridgeResponse;
	terminalEvent?: AgentBridgeEvent;
}

export function readAgentBridgeDiscovery(workspaceRoot: string): AgentBridgeDiscovery {
	const resolvedWorkspace = path.resolve(workspaceRoot);
	const discoveryPath = agentBridgeDiscoveryPath(resolvedWorkspace);
	let parsed: unknown;
	try {
		parsed = JSON.parse(fs.readFileSync(discoveryPath, 'utf8')) as unknown;
	} catch {
		throw new AgentBridgeClientError(
			'bridge-unavailable',
			`No active HexCore Agent Bridge was found for ${resolvedWorkspace}. Open and trust this workspace in HexCore first.`,
			{ discoveryPath },
		);
	}
	if (!isRecord(parsed)
		|| parsed.schemaVersion !== 1
		|| parsed.protocolVersion !== AGENT_BRIDGE_PROTOCOL_VERSION
		|| typeof parsed.endpoint !== 'string'
		|| typeof parsed.token !== 'string'
		|| typeof parsed.instanceId !== 'string'
		|| typeof parsed.workspace !== 'string'
		|| typeof parsed.workspaceSha256 !== 'string'
		|| typeof parsed.pid !== 'number'
		|| typeof parsed.createdAt !== 'string'
		|| typeof parsed.extensionVersion !== 'string') {
		throw new AgentBridgeClientError('invalid-discovery', `Invalid Agent Bridge discovery document: ${discoveryPath}`);
	}
	if (parsed.workspaceSha256 !== workspaceSha256(resolvedWorkspace)
		|| canonicalWorkspacePath(parsed.workspace) !== canonicalWorkspacePath(resolvedWorkspace)) {
		throw new AgentBridgeClientError('workspace-mismatch', 'Agent Bridge discovery document belongs to another workspace.');
	}
	const discovery = parsed as unknown as AgentBridgeDiscovery;
	if (!isProcessAlive(discovery.pid)) {
		removeStaleDiscovery(discoveryPath, discovery.instanceId);
		throw new AgentBridgeClientError(
			'bridge-stale',
			'HexCore Agent Bridge discovery is stale because its Extension Host process is no longer running.',
			{ pid: discovery.pid, discoveryPath },
		);
	}
	return discovery;
}

export async function requestAgentBridge(
	workspaceRoot: string,
	method: Exclude<AgentBridgeMethod, 'events'>,
	params: Record<string, unknown> = {},
): Promise<unknown> {
	const discovery = readAgentBridgeDiscovery(workspaceRoot);
	const request = createRequest(discovery, method, params);
	return new Promise<unknown>((resolve, reject) => {
		const socket = net.createConnection(discovery.endpoint);
		let settled = false;
		let buffer = '';
		let receivedBytes = 0;
		const timeout = setTimeout(() => {
			if (!settled) {
				settled = true;
				socket.destroy();
				reject(new AgentBridgeClientError('connect-timeout', 'Timed out connecting to the HexCore Agent Bridge.'));
			}
		}, DEFAULT_CONNECT_TIMEOUT_MS);
		const fail = (error: unknown): void => {
			if (settled) { return; }
			settled = true;
			clearTimeout(timeout);
			reject(normalizeClientError(error));
		};
		socket.once('connect', () => {
			clearTimeout(timeout);
			socket.write(`${JSON.stringify(request)}\n`);
		});
		socket.on('data', chunk => {
			receivedBytes += chunk.length;
			if (receivedBytes > AGENT_BRIDGE_MAX_RESPONSE_BYTES) {
				fail(new AgentBridgeClientError('response-too-large', 'Agent Bridge response exceeded the byte limit.'));
				socket.destroy();
				return;
			}
			buffer += chunk.toString('utf8');
			const newline = buffer.indexOf('\n');
			if (newline < 0 || settled) { return; }
			try {
				const response = parseResponse(buffer.slice(0, newline));
				settled = true;
				clearTimeout(timeout);
				socket.end();
				if (!response.ok) {
					reject(new AgentBridgeClientError(response.error?.code ?? 'bridge-error', response.error?.message ?? 'Agent Bridge request failed.', response.error?.details));
				} else {
					resolve(response.result);
				}
			} catch (error) {
				fail(error);
			}
		});
		socket.once('error', fail);
		socket.once('end', () => {
			if (!settled) {
				fail(new AgentBridgeClientError('connection-closed', 'Agent Bridge closed the connection without a response.'));
			}
		});
	});
}

export async function streamAgentBridgeEvents(
	workspaceRoot: string,
	params: Record<string, unknown>,
	onMessage: (message: AgentBridgeResponse | AgentBridgeEvent) => void,
): Promise<StreamAgentBridgeResult> {
	const discovery = readAgentBridgeDiscovery(workspaceRoot);
	const request = createRequest(discovery, 'events', params);
	return new Promise<StreamAgentBridgeResult>((resolve, reject) => {
		const socket = net.createConnection(discovery.endpoint);
		let response: AgentBridgeResponse | undefined;
		let terminalEvent: AgentBridgeEvent | undefined;
		let buffer = '';
		let currentLineBytes = 0;
		let settled = false;
		const timeout = setTimeout(() => {
			if (!settled) {
				settled = true;
				socket.destroy();
				reject(new AgentBridgeClientError('connect-timeout', 'Timed out connecting to the HexCore Agent Bridge.'));
			}
		}, DEFAULT_CONNECT_TIMEOUT_MS);
		const fail = (error: unknown): void => {
			if (settled) { return; }
			settled = true;
			clearTimeout(timeout);
			reject(normalizeClientError(error));
		};
		socket.once('connect', () => {
			clearTimeout(timeout);
			socket.write(`${JSON.stringify(request)}\n`);
		});
		socket.on('data', chunk => {
			currentLineBytes += chunk.length;
			if (currentLineBytes > AGENT_BRIDGE_MAX_RESPONSE_BYTES) {
				fail(new AgentBridgeClientError('response-too-large', 'Agent Bridge event line exceeded the byte limit.'));
				socket.destroy();
				return;
			}
			buffer += chunk.toString('utf8');
			let newline = buffer.indexOf('\n');
			while (newline >= 0) {
				const line = buffer.slice(0, newline);
				buffer = buffer.slice(newline + 1);
				currentLineBytes = Buffer.byteLength(buffer, 'utf8');
				try {
					const message = parseMessage(line);
					if (message.type === 'response') {
						response = message;
						if (!message.ok) {
							fail(new AgentBridgeClientError(message.error?.code ?? 'bridge-error', message.error?.message ?? 'Agent Bridge event subscription failed.', message.error?.details));
							return;
						}
					} else if (message.event.eventType === 'terminal') {
						terminalEvent = message;
					}
					onMessage(message);
				} catch (error) {
					fail(error);
					return;
				}
				newline = buffer.indexOf('\n');
			}
		});
		socket.once('error', fail);
		socket.once('end', () => {
			if (settled) { return; }
			settled = true;
			clearTimeout(timeout);
			if (!response) {
				reject(new AgentBridgeClientError('connection-closed', 'Agent Bridge closed the event stream before acknowledging it.'));
				return;
			}
			resolve({ response, ...(terminalEvent ? { terminalEvent } : {}) });
		});
	});
}

function createRequest(
	discovery: AgentBridgeDiscovery,
	method: AgentBridgeMethod,
	params: Record<string, unknown>,
): AgentBridgeRequest {
	return {
		protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
		requestId: crypto.randomUUID(),
		token: discovery.token,
		method,
		params,
	};
}

function parseResponse(line: string): AgentBridgeResponse {
	const message = parseMessage(line);
	if (message.type !== 'response') {
		throw new AgentBridgeClientError('invalid-response', 'Expected a response envelope.');
	}
	return message;
}

function parseMessage(line: string): AgentBridgeResponse | AgentBridgeEvent {
	let parsed: unknown;
	try {
		parsed = JSON.parse(line);
	} catch {
		throw new AgentBridgeClientError('invalid-response-json', 'Agent Bridge returned invalid JSON.');
	}
	if (!isRecord(parsed) || parsed.protocolVersion !== AGENT_BRIDGE_PROTOCOL_VERSION) {
		throw new AgentBridgeClientError('invalid-response', 'Agent Bridge returned an incompatible envelope.');
	}
	if (parsed.type === 'response' && typeof parsed.requestId === 'string' && typeof parsed.ok === 'boolean') {
		return parsed as unknown as AgentBridgeResponse;
	}
	if (parsed.type === 'event' && isRecord(parsed.event) && typeof parsed.event.jobId === 'string') {
		return parsed as unknown as AgentBridgeEvent;
	}
	throw new AgentBridgeClientError('invalid-response', 'Agent Bridge returned an unrecognized envelope.');
}

function normalizeClientError(error: unknown): AgentBridgeClientError {
	if (error instanceof AgentBridgeClientError) {
		return error;
	}
	if (error instanceof AgentBridgeProtocolError) {
		return new AgentBridgeClientError(error.code, error.message, error.details);
	}
	const nodeError = error as NodeJS.ErrnoException;
	if (nodeError?.code === 'ENOENT' || nodeError?.code === 'ECONNREFUSED') {
		return new AgentBridgeClientError('bridge-unavailable', 'HexCore Agent Bridge is not accepting connections. Reload or reopen the workspace.', { code: nodeError.code });
	}
	return new AgentBridgeClientError('client-error', error instanceof Error ? error.message : String(error));
}

function isProcessAlive(pid: number): boolean {
	if (!Number.isSafeInteger(pid) || pid <= 0) {
		return false;
	}
	try {
		process.kill(pid, 0);
		return true;
	} catch (error) {
		const code = (error as NodeJS.ErrnoException)?.code;
		return code !== 'ESRCH';
	}
}

function removeStaleDiscovery(discoveryPath: string, instanceId: string): void {
	try {
		const current = JSON.parse(fs.readFileSync(discoveryPath, 'utf8')) as unknown;
		if (isRecord(current) && current.instanceId === instanceId) {
			fs.unlinkSync(discoveryPath);
		}
	} catch {
		// Another instance may have replaced or removed the discovery document.
	}
}
