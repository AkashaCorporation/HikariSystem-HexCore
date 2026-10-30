/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import {
	AGENT_BRIDGE_PROTOCOL_VERSION,
	AgentBridgeProtocolError,
	canonicalJson,
	parseAgentBridgeRequest,
	sha256Canonical,
	timingSafeTokenEqual,
} from './agentBridgeProtocol';

suite('Agent Bridge protocol', () => {
	test('canonicalizes object keys before hashing', () => {
		const left = { z: 2, a: { y: 1, x: true } };
		const right = { a: { x: true, y: 1 }, z: 2 };
		assert.strictEqual(canonicalJson(left), canonicalJson(right));
		assert.strictEqual(sha256Canonical(left), sha256Canonical(right));
	});

	test('parses a valid versioned request', () => {
		const request = parseAgentBridgeRequest(JSON.stringify({
			protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
			requestId: 'request-1',
			token: 'token',
			method: 'status',
			params: { jobId: 'job-1' },
		}));
		assert.strictEqual(request.method, 'status');
		assert.deepStrictEqual(request.params, { jobId: 'job-1' });
	});

	test('accepts the non-mutating validate method', () => {
		const request = parseAgentBridgeRequest(JSON.stringify({
			protocolVersion: 1,
			requestId: 'request-validate',
			token: 'token',
			method: 'validate',
			params: { jobFile: '.hexcore_job.json' },
		}));
		assert.strictEqual(request.method, 'validate');
	});

	test('rejects unsupported protocol versions and unknown methods', () => {
		assert.throws(() => parseAgentBridgeRequest(JSON.stringify({
			protocolVersion: 2,
			requestId: 'request-1',
			token: 'token',
			method: 'status',
		})), (error: unknown) => error instanceof AgentBridgeProtocolError && error.code === 'unsupported-protocol');
		assert.throws(() => parseAgentBridgeRequest(JSON.stringify({
			protocolVersion: 1,
			requestId: 'request-1',
			token: 'token',
			method: 'execute-arbitrary-command',
		})), (error: unknown) => error instanceof AgentBridgeProtocolError && error.code === 'unknown-method');
	});

	test('uses length-safe constant-time token comparison', () => {
		assert.strictEqual(timingSafeTokenEqual('same-token', 'same-token'), true);
		assert.strictEqual(timingSafeTokenEqual('same-token', 'different-token'), false);
		assert.strictEqual(timingSafeTokenEqual('short', 'much-longer'), false);
	});
});
