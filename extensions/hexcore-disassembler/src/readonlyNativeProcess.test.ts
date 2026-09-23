/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as path from 'path';
import { fork } from 'child_process';
import { ReadonlyNativeProcess } from './readonlyNativeProcess';
import { nativeBytesSha256, nativeRequestSha256, validateNativeFunctionIdentity, validateReadonlyNativeRequest, type ReadonlyNativeRequest } from './readonlyNativeProtocol';
import type { HelixAnalysisContext } from './helixAnalysisContext';

function request(): ReadonlyNativeRequest {
	const context: any = { contextVersion: 1, target: { id: 'target:fixture', architecture: 'x64' }, analysis: { generation: 2 }, queryIdentity: { targetIdentity: 'target:fixture', sessionId: 'session:fixture', generation: 0, engineGeneration: 2, snapshotSha256: 'b'.repeat(64), universeSha256: 'c'.repeat(64) }, abi: { platform: 'unknown' }, function: { entry: '0x1000', end: '0x1001' } };
	context.contextSha256 = nativeBytesSha256(JSON.stringify(context));
	return { version: 1, context: context as HelixAnalysisContext, architecture: 'x64', targetOs: 'linux', input: { kind: 'bytes', bytesBase64: 'ww==', byteSha256: nativeBytesSha256(Buffer.from([0xc3])), address: 0x1000, options: { maxBytes: 1, maxInstructions: 10, maxBasicBlocks: 10 } }, dataSections: [], externalSymbols: [], preparationIssues: [], maxOutputBytes: 4096 };
}

suite('terminable read-only native producer', () => {
	const controller = (mode: string) => new ReadonlyNativeProcess(() => fork(path.join(__dirname, 'readonlyNativeTestChild.js'), [mode], {
		env: { ...process.env, HEXCORE_READONLY_NATIVE_TEST: '1', ELECTRON_RUN_AS_NODE: '1' }, execArgv: [], serialization: 'advanced', stdio: ['ignore', 'ignore', 'ignore', 'ipc'],
	}));
	test('request digests are stable and altered context/bytes are rejected', () => {
		const value = request(); validateReadonlyNativeRequest(value);
		assert.strictEqual(nativeRequestSha256(value), nativeRequestSha256(JSON.parse(JSON.stringify(value))));
		value.context.function.entry = '0x2000'; assert.throws(() => validateReadonlyNativeRequest(value), /digest/);
		const bytes = request(); if (bytes.input.kind === 'bytes') { bytes.input.bytesBase64 = 'kA=='; }
		assert.throws(() => validateReadonlyNativeRequest(bytes), /byte identity/);
	});
	test('decompile identity must agree with the captured function', () => {
		const value = request(); value.context.function.name = 'expected';
		assert.doesNotThrow(() => validateNativeFunctionIdentity(value.context, { functionName: 'expected', entryAddress: '0x01000' }));
		assert.throws(() => validateNativeFunctionIdentity(value.context, { functionName: 'other', entryAddress: '0x1000' }), /function identity/);
		assert.throws(() => validateNativeFunctionIdentity(value.context, { functionName: 'expected', entryAddress: '' }), /entry identity/);
		assert.throws(() => validateNativeFunctionIdentity(value.context, { functionName: 'expected', entryAddress: '0x2000' }), /entry identity/);
	});
	test('watchdog ends a blocked process and the parent keeps heartbeats', async () => {
		const events: any[] = [];
		const result = await controller('hang').run(request(), { timeoutMs: 350, onHeartbeat: event => events.push(event) });
		assert.strictEqual(result.status, 'error'); assert.match(result.error!, /timeout/);
		assert.ok(events.some(event => event.phase === 'lifting')); assert.ok(events.length >= 3);
		assert.strictEqual(result.execution.exited, true); assert.ok(result.execution.elapsedMs < 4000);
		assert.throws(() => process.kill(result.execution.pid!, 0));
	});
	test('cancel waits for actual process exit and does not affect the next job', async () => {
		const abort = new AbortController();
		const running = controller('hang').run(request(), { timeoutMs: 10000, signal: abort.signal, onHeartbeat: event => { if (event.phase === 'lifting') { abort.abort(); } } });
		const result = await running;
		assert.match(result.error!, /cancelled/); assert.throws(() => process.kill(result.execution.pid!, 0));
		const next = await controller('error').run(request(), { timeoutMs: 5000 });
		assert.strictEqual(next.error, 'fixture'); assert.strictEqual(next.execution.exited, true);
	});
	test('crash and foreign response cannot become a successful artifact', async () => {
		const crashed = await controller('crash').run(request(), { timeoutMs: 5000 });
		assert.strictEqual(crashed.status, 'error'); assert.strictEqual(crashed.execution.exitCode, 17);
		const foreign = await controller('wrong-id').run(request(), { timeoutMs: 5000 });
		assert.match(foreign.error!, /identity mismatch/); assert.strictEqual(foreign.semanticEligible, false);
	});
	test('pre-cancelled work never launches a native process', async () => {
		const abort = new AbortController(); abort.abort();
		const result = await new ReadonlyNativeProcess(() => { throw new Error('must not launch'); }).run(request(), { signal: abort.signal });
		assert.match(result.error!, /cancelled/); assert.strictEqual(result.execution.pid, undefined);
	});
});
