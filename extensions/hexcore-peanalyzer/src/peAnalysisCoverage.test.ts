import * as assert from 'assert';
import { assessPEAnalysisCoverage } from './peAnalysisCoverage';

suite('PE analysis coverage', () => {
	test('distinguishes an absent directory from an unsupported parser', () => {
		assert.strictEqual(assessPEAnalysisCoverage(undefined, false, 0).status, 'not-present');
		assert.strictEqual(
			assessPEAnalysisCoverage({ virtualAddress: 0x3000, size: 0x100 }, false, 0).status,
			'not-assessed',
		);
	});

	test('does not call a present-but-empty directory clean', () => {
		const result = assessPEAnalysisCoverage({ virtualAddress: 0x3000, size: 0x100 }, true, 0);
		assert.strictEqual(result.status, 'partial');
		assert.match(result.reason ?? '', /returned no records/);
	});

	test('reports parsed records with directory identity', () => {
		assert.deepStrictEqual(
			assessPEAnalysisCoverage({ virtualAddress: 0x3000, size: 0x100 }, true, 37),
			{ status: 'parsed', directoryRva: 0x3000, directorySize: 0x100, recordCount: 37 },
		);
	});
});
