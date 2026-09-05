/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { analysisPathIdentity, decideAnalysisContextOwnership } from './analysisContextOwnership';

suite('decompileIR analysis-context ownership', () => {
	test('allows active-engine evidence only for the producing target', () => {
		const decision = decideAnalysisContextOwnership(
			'C:\\samples\\ffmodule.exe',
			'C:\\samples\\ffmodule.exe',
			'win32',
		);
		assert.strictEqual(decision.ownership, 'matched');
		assert.strictEqual(decision.activeEngineEvidenceUsed, true);
	});

	test('rejects evidence from a different active target', () => {
		const decision = decideAnalysisContextOwnership(
			'C:\\samples\\ffmodule.exe',
			'C:\\samples\\callfuscated',
			'win32',
		);
		assert.strictEqual(decision.ownership, 'mismatched');
		assert.strictEqual(decision.activeEngineEvidenceUsed, false);
	});

	test('treats inline IR without a producer binding as unbound', () => {
		const decision = decideAnalysisContextOwnership(undefined, 'C:\\samples\\callfuscated', 'win32');
		assert.strictEqual(decision.ownership, 'unbound');
		assert.strictEqual(decision.activeEngineEvidenceUsed, false);
	});

	test('normalizes Windows drive-letter and path casing', () => {
		assert.strictEqual(
			analysisPathIdentity('C:\\Samples\\Target.exe', 'win32'),
			analysisPathIdentity('c:\\samples\\target.exe', 'win32'),
		);
	});
});
