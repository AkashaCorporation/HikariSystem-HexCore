/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { createInvestigationJob, sanitizeInvestigationJobName } from './investigationJob';

suite('Investigation job builder', () => {
	test('uses the analyst name for the job and every retained artifact', () => {
		const definition = createInvestigationJob({
			targetPath: 'C:\\cases\\game.exe',
			outputDirectory: 'C:\\cases\\hexcore-reports\\health-points',
			name: 'Health Points',
			query: 'health_percent',
			functionAddress: '0X000000014000E620',
		});

		assert.strictEqual(definition.slug, 'health-points');
		assert.strictEqual(definition.fileName, 'health-points.hexcore_job.json');
		assert.strictEqual(definition.job.steps[1].output?.path, 'health-points.references.json');
		assert.strictEqual(definition.job.steps[0].expectOutput, false);
		assert.strictEqual(definition.job.steps[2].output?.path, 'health-points.ll');
		assert.strictEqual(definition.job.steps[3].output?.path, 'health-points.helix.c');
		assert.strictEqual(definition.job.steps[2].args?.address, '0x14000e620');
		assert.strictEqual(definition.job.steps[3].args?.irPath, '$step[2].output');
		assert.strictEqual(definition.job.steps[3].allowPartial, true);
	});

	test('sanitizes names and rejects empty identifiers', () => {
		assert.strictEqual(sanitizeInvestigationJobName('  Anti Debug / Check  '), 'anti-debug-check');
		assert.throws(() => sanitizeInvestigationJobName('***'), /letter or number/);
	});

	test('rejects invalid addresses and instruction budgets', () => {
		const base = {
			targetPath: 'target.exe',
			outputDirectory: 'reports',
			name: 'health',
			query: 'health',
		};
		assert.throws(() => createInvestigationJob({ ...base, functionAddress: 'not-an-address' }), /Invalid address/);
		assert.throws(() => createInvestigationJob({ ...base, functionAddress: '0x401000', instructionCount: 0 }), /between 1 and 10000/);
	});
});
