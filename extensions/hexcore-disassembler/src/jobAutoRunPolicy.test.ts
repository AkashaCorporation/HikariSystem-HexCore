/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { inspectJobAutoRunPolicyText } from './jobAutoRunPolicy';

suite('job auto-run policy', () => {
	test('autoRun false disables watcher execution only', () => {
		assert.deepStrictEqual(inspectJobAutoRunPolicyText('{"autoRun":false}'), {
			autoRun: false,
			authority: 'job-file',
			reason: 'autoRun:false',
		});
	});

	test('true and omission preserve legacy watcher behavior', () => {
		assert.strictEqual(inspectJobAutoRunPolicyText('{"autoRun":true}').autoRun, true);
		assert.strictEqual(inspectJobAutoRunPolicyText('{"steps":[]}').autoRun, true);
	});

	test('malformed or invalid policy remains runner-visible', () => {
		assert.strictEqual(inspectJobAutoRunPolicyText('{').authority, 'unreadable');
		assert.strictEqual(inspectJobAutoRunPolicyText('{"autoRun":"no"}').autoRun, true);
	});
});
