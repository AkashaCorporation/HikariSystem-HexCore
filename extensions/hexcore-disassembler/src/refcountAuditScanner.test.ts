import * as assert from 'assert';
import { auditRefcount } from './refcountAuditScanner';

suite('Refcount evidence contract', () => {
	test('assertions, warnings and termination are observations, never reachable bugs', () => {
		const report = auditRefcount('void check(void *p) {\nif (!p) {\nBUG_ON(!p); WARN_ON(!p);\npanic("stop");\n}\n}', 'check.c');
		assert.strictEqual(report.findings.length, 0);
		assert.strictEqual(report.summary.byPattern.E, 0);
		assert.deepStrictEqual(report.observations.map(o => o.kind), ['assertion', 'warning', 'termination']);
		assert.ok(report.observations.every(o => o.reachability === 'not-assessed' && o.vulnerabilityStatus === 'not-assessed'));
		assert.strictEqual(report.observations[0].line, 3);
		assert.strictEqual(report.scanCoverage.status, 'ok');
	});
	test('unreachable or compile-time diagnostics cannot become findings', () => {
		const report = auditRefcount('void check(void) {\nBUILD_BUG_ON(0);\nif (0) { BUG(); }\nassert(1);\n}', 'check.c');
		assert.strictEqual(report.findings.length, 0);
		assert.deepStrictEqual(report.observations.map(o => o.symbol), ['BUG', 'assert']);
	});
	test('comments, escaped quotes and literal braces cannot invent calls or functions', () => {
		const report = auditRefcount('/* void fake_force() { BUG(); } */\nvoid check(void) {\n// kref_get(obj);\nchar *s = "\\\" } BUG_ON(x); kref_get(obj);";\nchar c = \'}\';\n/* WARN_ON(x);\n kref_get(obj); */\nreturn;\n}', 'check.c');
		assert.strictEqual(report.functionsScanned, 1);
		assert.strictEqual(report.findings.length, 0);
		assert.strictEqual(report.observations.length, 0);
		assert.strictEqual(report.scanCoverage.status, 'ok');
	});
	test('force naming alone does not prove refcount bypass or UAF', () => {
		const report = auditRefcount('void refresh_force(void) {\nrefresh();\n}', 'check.c');
		assert.ok(report.findings.length > 0);
		for (const finding of report.findings) {
			assert.strictEqual(finding.evidenceLevel, 'signal');
			assert.strictEqual(finding.proofStatus, 'unproven');
			assert.strictEqual(finding.confidenceKind, 'heuristic-pattern-score');
			assert.strictEqual(finding.severityKind, 'review-priority');
			assert.strictEqual(finding.referenceBug, undefined);
			assert.ok(!finding.description.includes('which bypasses'));
		}
	});
	test('no-match scan never claims program safety', () => {
		const report = auditRefcount('int id(int v) {\nreturn v;\n}', 'check.c');
		assert.strictEqual(report.scanCoverage.status, 'ok');
		assert.strictEqual(report.proofStatus, 'unproven');
		assert.ok(report.limitations.some(l => l.includes('No matches does not prove')));
	});
	test('long-line omissions are explicit', () => {
		const report = auditRefcount(`void check(void) {\n${'a'.repeat(2001)}\n}`, 'check.c');
		assert.strictEqual(report.scanCoverage.status, 'partial');
		assert.deepStrictEqual(report.scanCoverage.skippedLines, [2]);
	});
	test('truncated functions cannot be complete', () => {
		const report = auditRefcount('void check(void) {\nreturn;', 'check.c');
		assert.ok(report.scanCoverage.reasons.includes('incomplete-function'));
	});
	test('function scan cap is explicit', () => {
		const report = auditRefcount(`void check(void) {\n${'a();\n'.repeat(5003)}}`, 'check.c');
		assert.ok(report.scanCoverage.reasons.includes('incomplete-function'));
	});
	test('unsupported signatures remain partial', () => {
		const report = auditRefcount('void\ncheck\n(void)\n{\nreturn;\n}', 'check.c');
		assert.ok(report.scanCoverage.reasons.includes('no-functions-scanned'));
	});
	test('preprocessor alternatives and line splicing remain unassessed', () => {
		const report = auditRefcount('#if 0\nvoid check(void) {\n// comment \\\nBUG();\n}\n#endif', 'check.c');
		assert.ok(report.scanCoverage.reasons.includes('preprocessor-not-evaluated'));
		assert.ok(report.scanCoverage.reasons.includes('line-splicing-not-supported'));
	});
	test('unterminated literals and comments are explicit', () => {
		for (const suffix of ['/* unfinished', '"unfinished']) {
			const report = auditRefcount(`void check(void) {\n${suffix}`, 'check.c');
			assert.ok(report.scanCoverage.reasons.includes('unterminated-comment-or-literal'));
		}
	});
	test('invalid input stays partial and byte size uses UTF-8', () => {
		assert.strictEqual(auditRefcount(undefined as unknown as string, 'bad.c').scanCoverage.status, 'partial');
		const source = 'void check(void) {\n/* \u00e9 */\n}';
		assert.strictEqual(auditRefcount(source, 'check.c').fileSize, Buffer.byteLength(source, 'utf8'));
	});
});
