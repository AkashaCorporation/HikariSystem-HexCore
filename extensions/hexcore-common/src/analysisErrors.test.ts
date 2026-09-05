/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { isAnalysisResult } from './analysisContract';
import {
	ANALYSIS_ERROR_CODES,
	ANALYSIS_ERROR_SPECS,
	analysisError,
	failedResult,
	isAnalysisErrorCode,
	okResult,
	partialResult,
	skippedResult,
} from './analysisErrors';

// Every registered code has exactly one spec, and vice versa.
assert.strictEqual(ANALYSIS_ERROR_CODES.length, Object.keys(ANALYSIS_ERROR_SPECS).length);
for (const code of ANALYSIS_ERROR_CODES) {
	assert.ok(ANALYSIS_ERROR_SPECS[code], `missing spec for ${code}`);
	assert.strictEqual(typeof ANALYSIS_ERROR_SPECS[code].retryable, 'boolean');
	assert.ok(ANALYSIS_ERROR_SPECS[code].description.length > 0);
}

assert.strictEqual(isAnalysisErrorCode('wrong-target'), true);
assert.strictEqual(isAnalysisErrorCode('nope'), false);
assert.strictEqual(isAnalysisErrorCode(42), false);

// Registry-driven retryability default + per-call override.
const wrongTarget = analysisError('wrong-target', 'finding belongs to another binary');
assert.strictEqual(wrongTarget.severity, 'error');
assert.strictEqual(wrongTarget.retryable, false);
assert.strictEqual(analysisError('timeout', 'slow', { retryable: false }).retryable, false);
assert.strictEqual(analysisError('engine-fault', 'x').retryable, true);

// ok result: no error diagnostics allowed, data/artifacts optional.
const ok = okResult({ value: 1 });
assert.strictEqual(isAnalysisResult(ok), true);
assert.strictEqual(ok.status, 'ok');
assert.deepStrictEqual(ok.diagnostics, []);
assert.strictEqual(ok.data?.value, 1);

// partial result: keeps data and carries explanatory diagnostics.
const partial = partialResult(
	{ recovered: 9 },
	[{ code: 'partial-result', severity: 'warning', message: 'confidence capped', retryable: true }],
);
assert.strictEqual(partial.status, 'partial');
assert.strictEqual(partial.diagnostics.length, 1);

// failed result: typed code, always at least one error diagnostic.
const failed = failedResult('engine-unavailable', 'capstone missing');
assert.strictEqual(failed.status, 'failed');
assert.strictEqual(failed.diagnostics[0].severity, 'error');
assert.strictEqual(failed.diagnostics[0].code, 'engine-unavailable');
assert.strictEqual(failed.diagnostics[0].retryable, false);
assert.strictEqual(isAnalysisResult(failed), true);

// skipped result: informational diagnostic, no error.
const skipped = skippedResult('binary header gate: not a PE', 'parse-failed');
assert.strictEqual(skipped.status, 'skipped');
assert.strictEqual(skipped.diagnostics[0].severity, 'info');
assert.strictEqual(skipped.diagnostics[0].code, 'parse-failed');

console.log('analysisErrors: 58/58 passing');
