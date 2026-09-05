/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { inspectHelixOutputQuality, stampHelixConfidenceAxes } from './helixOutputQuality';

suite('Helix output quality', () => {
	test('marks a damning honesty defect as partial', () => {
		const quality = inspectHelixOutputQuality([
			'// Confidence: 50.0% (Low)  |  win64',
			"// Issues: damning honesty defect (uninitialized return value 'result') - confidence capped at 50%",
		].join('\n'));
		assert.strictEqual(quality.status, 'partial');
		assert.strictEqual(quality.confidence, 50);
		assert.match(quality.reason ?? '', /uninitialized return value/);
	});

	test('marks low confidence as partial without inventing an error', () => {
		const quality = inspectHelixOutputQuality('// Confidence: 55% (Low)  |  win64');
		assert.strictEqual(quality.status, 'partial');
		assert.deepStrictEqual(quality.issues, []);
	});

	test('keeps a high-confidence output semantically ok', () => {
		const quality = inspectHelixOutputQuality([
			'// Confidence: 91.5% (High)  |  win64',
			'// LiftDiag: semanticCoverage=98.2% unsupported=1',
		].join('\n'));
		assert.strictEqual(quality.status, 'ok');
		assert.strictEqual(quality.confidence, 91.5);
		assert.deepStrictEqual(quality.confidenceAxes, {
			translation: 91.5,
			liftCoverage: 98.2,
			semanticType: null,
			semanticTypeStatus: 'not-assessed',
		});
	});

	test('marks Backblaze-style placeholders and self-references partial regardless of aggregate confidence', () => {
		const quality = inspectHelixOutputQuality([
			'// Confidence: 71.5% (Medium)  |  win64',
			'// Issues: 4 auto-declared placeholder variable(s) - lift-quality concern, 32 suspicious self-referencing assignment(s)',
			'int64_t f(void) {',
			'    int64_t result;',
			'    return result;',
			'}',
		].join('\n'));

		assert.strictEqual(quality.status, 'partial');
		assert.strictEqual(quality.securityEvidenceUsable, false);
		assert.deepStrictEqual(quality.qualityIssues.map(issue => [issue.kind, issue.count]), [
			['placeholder-variable', 4],
			['self-reference', 32],
		]);
	});

	test('detects duplicate local definitions as an independent partial gate', () => {
		const quality = inspectHelixOutputQuality([
			'// Confidence: 92% (High)',
			'int64_t f(void) {',
			'    void* var_68;',
			'    void* var_68; /* stack[104] */',
			'    return 0;',
			'}',
		].join('\n'));

		assert.strictEqual(quality.status, 'partial');
		assert.deepStrictEqual(quality.qualityIssues, [{
			kind: 'duplicate-local',
			severity: 'damning',
			count: 1,
			detail: 'duplicate local definition(s): var_68',
		}]);
	});

	test('persists independently auditable confidence axes in C output', () => {
		const source = '// Confidence: 91.5% (High)\n// LiftDiag: semanticCoverage=98.2% unsupported=1\nint f(void);';
		const axes = inspectHelixOutputQuality(source).confidenceAxes;
		const stamped = stampHelixConfidenceAxes(source, axes);

		assert.match(stamped, /^\/\/ ConfidenceAxes: \{"translation":91.5,"liftCoverage":98.2,"semanticType":null,"semanticTypeStatus":"not-assessed"\}$/m);
		assert.strictEqual((stamped.match(/ConfidenceAxes:/g) ?? []).length, 1);
	});
});
