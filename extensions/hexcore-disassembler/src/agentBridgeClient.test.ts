/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { AgentBridgeClientError, readAgentBridgeDiscovery } from './agentBridgeClient';
import {
	AGENT_BRIDGE_PROTOCOL_VERSION,
	agentBridgeDiscoveryPath,
	workspaceSha256,
	type AgentBridgeDiscovery,
} from './agentBridgeProtocol';

suite('Agent Bridge client discovery', () => {
	test('removes only a discovery document whose Extension Host PID is stale', () => {
		const root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-agent-stale-'));
		const discoveryPath = agentBridgeDiscoveryPath(root);
		const discovery: AgentBridgeDiscovery = {
			schemaVersion: 1,
			protocolVersion: AGENT_BRIDGE_PROTOCOL_VERSION,
			instanceId: 'stale-instance',
			workspace: root,
			workspaceSha256: workspaceSha256(root),
			endpoint: '\\\\.\\pipe\\hexcore-agent-stale-test',
			token: 'stale-token',
			pid: 2147483647,
			createdAt: '2026-10-28T00:00:00.000Z',
			extensionVersion: 'test',
		};
		fs.mkdirSync(path.dirname(discoveryPath), { recursive: true });
		fs.writeFileSync(discoveryPath, JSON.stringify(discovery));
		try {
			assert.throws(
				() => readAgentBridgeDiscovery(root),
				(error: unknown) => error instanceof AgentBridgeClientError && error.code === 'bridge-stale',
			);
			assert.strictEqual(fs.existsSync(discoveryPath), false);
		} finally {
			fs.rmSync(root, { recursive: true, force: true });
		}
	});
});
