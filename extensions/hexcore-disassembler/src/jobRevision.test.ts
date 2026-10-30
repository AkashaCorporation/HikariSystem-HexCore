/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { jobRevisionSha256 } from './jobRevision';

suite('job revision identity', () => {
	test('uses the same SHA-256 for watcher bytes and bridge UTF-8 text', () => {
		const text = '{"autoRun":false,"steps":[]}\n';
		assert.strictEqual(jobRevisionSha256(text), jobRevisionSha256(Buffer.from(text, 'utf8')));
		assert.match(jobRevisionSha256(text), /^[0-9a-f]{64}$/);
	});

	test('changes when the job revision changes', () => {
		assert.notStrictEqual(jobRevisionSha256('{"name":"A"}'), jobRevisionSha256('{"name":"B"}'));
	});
});
