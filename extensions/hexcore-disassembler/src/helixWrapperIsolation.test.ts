/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { HelixWrapper } from './helixWrapper';

interface MutableWrapper {
	available: boolean;
	modulePaths: string[];
	module: {
		HelixEngine: new () => {
			isDisposed: boolean;
			decompileIr(): never;
			dispose(): void;
		};
		Architecture: Record<string, number>;
	};
}

function installHangingEngine(wrapper: HelixWrapper): string {
	const fixtureDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-helix-worker-'));
	fs.writeFileSync(path.join(fixtureDir, 'index.js'), `
		class HelixEngine {
			constructor() { this.isDisposed = false; }
			decompileIr() { while (true) {} }
			dispose() { this.isDisposed = true; }
		}
		module.exports = { HelixEngine, Architecture: {} };
	`);
	class MainThreadEngine {
		isDisposed = false;
		decompileIr(): never { throw new Error('main-thread engine must not run'); }
		dispose(): void { this.isDisposed = true; }
	}
	const mutable = wrapper as unknown as MutableWrapper;
	mutable.available = true;
	mutable.modulePaths = [fixtureDir];
	mutable.module = { HelixEngine: MainThreadEngine, Architecture: {} };
	return fixtureDir;
}

suite('Helix isolated-worker lifecycle', () => {
	test('process timeout settles a blocked native-style call', async () => {
		const wrapper = new HelixWrapper();
		const fixtureDir = installHangingEngine(wrapper);
		const started = Date.now();
		try {
			const result = await wrapper.decompileIr('define i64 @sub_1000() { ret i64 0 }', 'x64', {
				forceProcess: true,
				workerTimeoutMs: 50,
				workerGroup: 'debugger-live-memory',
				cleanup: false,
			});
			assert.strictEqual(result.success, false);
			assert.match(result.error, /timed out after 50ms/);
			assert.ok(Date.now() - started < 2_000, 'blocked process must not hold the caller');
		} finally {
			wrapper.dispose();
			fs.rmSync(fixtureDir, { recursive: true, force: true });
		}
	});

	test('group cancellation leaves unrelated workers running', async () => {
		const wrapper = new HelixWrapper();
		const fixtureDir = installHangingEngine(wrapper);
		try {
			const live = wrapper.decompileIr('define i64 @live() { ret i64 0 }', 'x64', {
				forceProcess: true, workerGroup: 'debugger-live-memory', cleanup: false,
			});
			const interactive = wrapper.decompileIr('define i64 @interactive() { ret i64 0 }', 'x64', {
				forceWorker: true, workerGroup: 'interactive', cleanup: false,
			});
			await new Promise(resolve => setTimeout(resolve, 50));
			assert.strictEqual(wrapper.cancelActiveDecompiles('debugger-live-memory'), 1);
			await live;
			assert.strictEqual(wrapper.cancelActiveDecompiles('debugger-live-memory'), 0);
			assert.strictEqual(wrapper.cancelActiveDecompiles('interactive'), 1);
			await interactive;
		} finally {
			wrapper.dispose();
			fs.rmSync(fixtureDir, { recursive: true, force: true });
		}
	});
});
