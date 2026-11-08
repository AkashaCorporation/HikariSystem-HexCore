/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as path from 'path';
import { DebugEngine, EmulationNotReadyError } from './debugEngine';

suite('DebugEngine emulation lifecycle', () => {
	test('failed startup cannot be reused by execution commands', async () => {
		const engine = new DebugEngine();
		const missing = path.join(__dirname, 'fixture-does-not-exist.exe');

		await assert.rejects(engine.startEmulation(missing), (error: Error) => {
			assert.ok(error instanceof EmulationNotReadyError);
			assert.strictEqual((error as EmulationNotReadyError).code, 'HEXCORE_DEBUGGER_NOT_READY');
			return true;
		});
		assert.strictEqual(engine.getEmulationLifecycle().status, 'failed');
		assert.strictEqual(engine.getEmulationState(), null);
		assert.strictEqual(engine.isEmulationSessionActive(), false);

		for (const operation of [
			() => engine.emulationStep(),
			() => engine.emulationContinue(),
			() => engine.saveSnapshot(),
			() => engine.restoreSnapshot(),
		]) {
			await assert.rejects(operation(), (error: Error) => {
				assert.ok(error instanceof EmulationNotReadyError);
				assert.strictEqual((error as EmulationNotReadyError).lifecycle, 'failed');
				return true;
			});
		}
		assert.throws(
			() => engine.emulationSetBreakpoint(0x401000n),
			(error: Error) => error instanceof EmulationNotReadyError && error.lifecycle === 'failed',
		);
	});
});
