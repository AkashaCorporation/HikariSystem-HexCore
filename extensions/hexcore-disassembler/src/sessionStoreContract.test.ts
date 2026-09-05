/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { SessionStore } from './sessionStore';

suite('SessionStore analysis contract', () => {
	let tempDir = '';

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-session-contract-'));
	});

	teardown(() => {
		const resolved = path.resolve(tempDir);
		const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempRoot)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('persists a session for the same target and replaces it when binary identity changes', () => {
		const binaryPath = path.join(tempDir, 'sample.bin');
		fs.writeFileSync(binaryPath, Buffer.from([1, 2, 3, 4]));

		const first = new SessionStore(binaryPath);
		const target1 = first.bindAnalysisTarget({
			filePath: binaryPath,
			fileSize: 4,
			format: 'raw',
			architecture: 'x64',
			imageBase: '0x400000',
		});
		const session1 = first.getAnalysisSession();
		assert.ok(session1);
		assert.strictEqual(session1.targetId, target1.id);
		assert.strictEqual(first.getMeta('analysis_contract_version'), '1');
		first.dispose();

		const reopened = new SessionStore(binaryPath);
		reopened.bindAnalysisTarget({
			filePath: binaryPath,
			fileSize: 4,
			format: 'raw',
			architecture: 'x64',
			imageBase: '0x400000',
		});
		assert.strictEqual(reopened.getAnalysisSession()?.id, session1.id);
		reopened.dispose();

		fs.writeFileSync(binaryPath, Buffer.from([5, 6, 7, 8]));
		const replaced = new SessionStore(binaryPath);
		const target2 = replaced.bindAnalysisTarget({
			filePath: binaryPath,
			fileSize: 4,
			format: 'raw',
			architecture: 'x64',
			imageBase: '0x400000',
		});
		assert.notStrictEqual(target2.id, target1.id);
		assert.notStrictEqual(replaced.getAnalysisSession()?.id, session1.id);
		replaced.dispose();
	});
});
