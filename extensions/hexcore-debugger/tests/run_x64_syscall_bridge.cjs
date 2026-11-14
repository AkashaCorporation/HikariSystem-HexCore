/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const assert = require('assert');
const path = require('path');
const { DebugEngine } = require('../out/debugEngine');

const fixturePath = process.argv[2];
if (!fixturePath) {
	throw new Error('Usage: node tests/run_x64_syscall_bridge.cjs <fixture.elf>');
}

(async () => {
	const engine = new DebugEngine();
	try {
		await engine.startEmulation(path.resolve(fixturePath), 'x64');
		await engine.emulationRunCounted(500);

		const calls = engine.getApiCallLog();
		assert.deepStrictEqual(calls.map(call => call.name), [
			'sys_12', 'sys_9', 'sys_158', 'sys_1', 'sys_999', 'sys_60',
		]);
		assert.deepStrictEqual(calls.map(call => call.returnValue), [
			0x06000000n, 0x20000000n, 0n, 2n, -38n, 0n,
		]);
		assert.strictEqual(engine.getStdoutBuffer(), 'OK');
		assert.strictEqual(calls[4].pcAddress > 0n, true);
		console.log(JSON.stringify({
			status: 'pass',
			backend: engine.getExecutionBackend(),
			calls: calls.map(call => ({
				name: call.name,
				returnValue: call.returnValue.toString(),
				pcAddress: '0x' + call.pcAddress.toString(16),
			})),
			stdout: engine.getStdoutBuffer(),
		}, null, 2));
	} finally {
		engine.disposeEmulation();
	}
})().catch(error => {
	console.error(error);
	process.exitCode = 1;
});
