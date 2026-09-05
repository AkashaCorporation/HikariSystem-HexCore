/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as path from 'path';
import {
	ANALYSIS_CONTRACT_VERSION,
	createAnalysisAddress,
	createAnalysisArtifactProvenance,
	createAnalysisResult,
	createAnalysisSession,
	createAnalysisTarget,
	isAnalysisResult,
	normalizeAddressValue,
} from './analysisContract';

const HASH_A = 'A'.repeat(64);
const HASH_B = 'b'.repeat(64);

assert.strictEqual(normalizeAddressValue('0X140000000'), '0x140000000');
assert.strictEqual(normalizeAddressValue(0x140000000n), '0x140000000');
assert.throws(() => normalizeAddressValue(Number.MAX_SAFE_INTEGER + 1), /safe integers/);
assert.throws(() => normalizeAddressValue(-1n), /cannot be negative/);

const address = createAnalysisAddress('runtime-va', '0x7ff600001000', {
	architecture: 'x86_64',
	overlayId: 'main',
});
assert.deepStrictEqual(address, {
	space: 'runtime-va',
	value: '0x7ff600001000',
	architecture: 'x86_64',
	overlayId: 'main',
});

const target = createAnalysisTarget({
	binarySha256: HASH_A,
	filePath: path.join('.', 'fixtures', 'sample.exe'),
	fileSize: 4096,
	format: 'pe',
	architecture: 'x86_64',
	imageBase: '0x140000000',
});
const sameTargetElsewhere = createAnalysisTarget({
	binarySha256: HASH_A.toLowerCase(),
	filePath: path.join('.', 'copies', 'sample.exe'),
	fileSize: 4096,
	format: 'pe',
	architecture: 'x86_64',
	imageBase: 0x140000000n,
});
assert.strictEqual(target.contractVersion, ANALYSIS_CONTRACT_VERSION);
assert.strictEqual(target.binarySha256, HASH_A.toLowerCase());
assert.strictEqual(target.id, sameTargetElsewhere.id);
assert.strictEqual(target.imageBase?.value, '0x140000000');

const session = createAnalysisSession({
	id: 'session-1',
	targetId: target.id,
	generation: 3,
	parentGeneration: 2,
	createdAt: '2026-08-05T00:00:00.000Z',
	engines: [{ id: 'hikarisystem.hexcore-disassembler', version: '1.4.29' }],
});
assert.strictEqual(session.targetId, target.id);
assert.throws(() => createAnalysisSession({
	id: 'session-1', targetId: target.id, generation: 2, parentGeneration: 2,
}), /before the current generation/);

const partial = createAnalysisResult({
	status: 'partial',
	data: { recoveredFunctions: 9 },
	diagnostics: [{ code: 'E_OPCODE_UNSUPPORTED', severity: 'error', message: 'One opcode was not modeled' }],
});
assert.strictEqual(isAnalysisResult(partial), true);
assert.strictEqual(partial.status, 'partial');
assert.throws(() => createAnalysisResult({
	status: 'ok',
	diagnostics: [{ code: 'E_HIDDEN', severity: 'error', message: 'Hidden failure' }],
}), /ok analysis result/);
assert.throws(() => createAnalysisResult({ status: 'failed' }), /at least one error diagnostic/);

const artifact = {
	id: `artifact:sha256:${HASH_B}`,
	path: path.join('.', 'reports', 'sample.json'),
	sha256: HASH_B,
	mediaType: 'application/json',
};
const provenance = createAnalysisArtifactProvenance({
	target,
	session,
	producer: [{ id: 'hikarisystem.hexcore-disassembler', version: '1.4.29' }],
	artifact,
	status: 'partial',
	generatedAt: '2026-08-05T00:00:01.000Z',
});
assert.strictEqual(provenance.target.id, target.id);
assert.strictEqual(provenance.session.generation, 3);
assert.strictEqual(provenance.artifact.sha256, HASH_B);
assert.throws(() => createAnalysisArtifactProvenance({
	target,
	session: { ...session, targetId: 'target:sha256:other' },
	producer: [],
	artifact,
	status: 'ok',
}), /does not belong/);

console.log('analysisContract: 18/18 passing');
