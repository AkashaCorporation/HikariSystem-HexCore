import * as assert from 'assert';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { canonicalJson } from '../../src/atlas/canonical.js';
import type { AtlasBenchmarkRecord } from '../../src/atlas/types.js';
import {
	assertAtlasBenchmarkRecords,
	confusionMatrix,
	executeWithWatchdog,
	policySha256,
	preserveBaselineRuntime,
	readJson,
	writeExecutionArtifact,
} from '../lib/contract.js';

let assertions = 0;
const check = (condition: unknown, message: string): void => {
	assert.ok(condition, message);
	assertions++;
};

const metrics = confusionMatrix(['a', 'b', 'c', 'd'], ['a', 'b'], ['a', 'c']);
assert.deepStrictEqual(metrics, {
	truePositive: 1,
	falsePositive: 1,
	trueNegative: 1,
	falseNegative: 1,
	precision: 0.5,
	recall: 0.5,
});
assertions++;
assert.throws(() => confusionMatrix(['a'], ['outside'], []), /outside the declared universe/);
assertions++;
assert.throws(() => confusionMatrix(['a', 'a'], [], []), /duplicate identities/);
assertions++;

const timed = executeWithWatchdog(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], 100);
check(timed.status === 'timeout', 'watchdog must classify a terminated process as timeout');
check(timed.code === 'WATCHDOG_TIMEOUT', 'watchdog must expose a typed terminal code');
check(timed.runtimeMs < 10_000, 'watchdog must bound runtime');

const temporaryRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-benchmark-contract-'));
try {
	const executionPath = path.join(temporaryRoot, 'execution.json');
	writeExecutionArtifact(executionPath, 'test', 'fixture', 100, timed);
	const execution = readJson<any>(executionPath);
	check(execution.status === 'timeout' && execution.code === 'WATCHDOG_TIMEOUT', 'timeout artifact must remain machine-readable');
	check(/^[a-f0-9]{64}$/.test(execution.stdoutSha256) && /^[a-f0-9]{64}$/.test(execution.stderrSha256), 'execution artifact must hash partial output');

	const baselinePath = path.join(temporaryRoot, 'baseline.json');
	const record: AtlasBenchmarkRecord = {
		recordType: 'benchmark', id: 'capa-1.0.0.fixture.rule', ruleId: 'rule', ruleVersion: '1.0.0',
		corpus: 'fixture', corpusSha256: 'a'.repeat(64), truePositive: 1, falsePositive: 0,
		trueNegative: 1, falseNegative: 0, precision: 1, recall: 1, runtimeMs: 12.5,
		engineVersion: 'capa-1.0.0', signatureSetSha256: 'b'.repeat(64),
	};
	fs.writeFileSync(baselinePath, `${JSON.stringify([record], null, 2)}\n`, 'utf8');
	const preserved = preserveBaselineRuntime([{ ...record, runtimeMs: 99.5 }], baselinePath);
	check(preserved[0].runtimeMs === 12.5, 'semantically identical Atlas records must retain the measured baseline runtime');
	const changed = preserveBaselineRuntime([{ ...record, truePositive: 0, falseNegative: 1, precision: 0, recall: 0, runtimeMs: 99.5 }], baselinePath);
	check(changed[0].runtimeMs === 99.5, 'changed benchmark semantics must create a new runtime baseline');
} finally {
	fs.rmSync(temporaryRoot, { recursive: true, force: true });
}

const packageRoot = path.resolve(__dirname, '..', '..');
const policyFiles = [
	path.join(packageRoot, 'benchmarks', 'capa', 'normalization-policy.json'),
	path.join(packageRoot, 'benchmarks', 'floss', 'normalization-policy.json'),
];
for (const policyFile of policyFiles) {
	check(/^[a-f0-9]{64}$/.test(policySha256(policyFile)), `${path.basename(path.dirname(policyFile))} policy must have a canonical identity`);
}

const groundTruth = readJson<{ functions: Record<string, string[]> }>(path.join(packageRoot, 'benchmarks', 'corpus', 'ground_truth.json'));
const resultRoot = path.join(packageRoot, 'benchmarks', 'results');
for (const filename of fs.readdirSync(resultRoot).filter(name => name.endsWith('.json')).sort()) {
	const records = readJson<AtlasBenchmarkRecord[]>(path.join(resultRoot, filename));
	assertAtlasBenchmarkRecords(records, Object.keys(groundTruth.functions).length);
	assertions += records.length;
	const canonical = canonicalJson(records);
	check(!/bench_|0x[0-9a-f]+|semantic_benchmark\.dll|[A-Za-z]:\\/i.test(canonical), `${filename} must contain aggregate Atlas metrics, not target-specific facts`);
}

const regressionRoot = path.join(packageRoot, 'benchmarks', 'function-atlas', 'regressions');
const x86Metadata = readJson<{
	status: string;
	irSha256: string;
	irBytes: number;
	originalFailures: string[];
	expected: { pipeline: string; hastSchema: number; semanticEligible: boolean; adapterCoverage: number };
	acceptedBy: { functionCount: number; binaryCount: number; functionAtlasArtifactSha256: string };
}>(path.join(regressionRoot, 'x86-width-and-unary-regression.json'));
const x86Ir = fs.readFileSync(path.join(regressionRoot, 'x86-width-and-unary-regression.ll'));
check(x86Metadata.irSha256 === createHash('sha256').update(x86Ir).digest('hex'), 'x86 Function Atlas regression IR must match its pinned identity');
check(x86Metadata.status === 'resolved'
	&& x86Metadata.irBytes === x86Ir.length
	&& x86Metadata.originalFailures.length === 2
	&& x86Metadata.expected.pipeline === 'mlir'
	&& x86Metadata.expected.hastSchema === 1
	&& x86Metadata.expected.semanticEligible
	&& x86Metadata.expected.adapterCoverage === 1
	&& x86Metadata.acceptedBy.functionCount === 224
	&& x86Metadata.acceptedBy.binaryCount === 16,
'x86 Function Atlas regression must retain the resolved HAST contract');
const adapterLosses = readJson<{
	status: string;
	failures: unknown[];
	acceptedFunctions: number;
	expectedFunctions: number;
}>(path.join(regressionRoot, 'adapter-losses.resolved.json'));
check(adapterLosses.status === 'resolved'
	&& adapterLosses.failures.length === 0
	&& adapterLosses.acceptedFunctions === 224
	&& adapterLosses.expectedFunctions === 224,
'adapter-loss regression gate must remain resolved across the complete corpus');

console.log(`Benchmark contract tests: ${assertions} assertions passed`);
