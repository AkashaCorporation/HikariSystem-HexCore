/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as path from 'path';
import { createAnalysisTarget } from './analysisContract';
import {
	analysisObjectIdTargetId,
	createArtifactId,
	createBasicBlockId,
	createDataObjectId,
	createFindingId,
	createFunctionId,
	createInstructionId,
	createStringId,
	createTypeId,
	createVariableId,
	createXrefId,
	isAnalysisObjectId,
	parseAnalysisObjectId,
} from './analysisIds';

const HASH_A = 'A'.repeat(64);
const HASH_B = 'b'.repeat(64);
const DIGEST_A = HASH_A.toLowerCase();

const target = createAnalysisTarget({
	binarySha256: HASH_A,
	filePath: path.join('.', 'fixtures', 'sample.exe'),
	fileSize: 4096,
	format: 'pe',
	architecture: 'x86_64',
	imageBase: '0x140000000',
});
const otherTarget = createAnalysisTarget({
	binarySha256: HASH_B,
	filePath: path.join('.', 'fixtures', 'sample.exe'),
	fileSize: 4096,
	format: 'pe',
});

const fnId = createFunctionId({ target, space: 'va', address: '0X140001000' });
assert.strictEqual(fnId, `fn:sha256:${DIGEST_A}:va:0x140001000`);
assert.strictEqual(fnId, createFunctionId({ target, space: 'va', address: 0x140001000n }));
assert.notStrictEqual(fnId, createFunctionId({ target: otherTarget, space: 'va', address: '0x140001000' }));

const blkId = createBasicBlockId({ target, space: 'va', functionEntry: '0x140001000', blockStart: '0X140001040' });
assert.strictEqual(blkId, `blk:sha256:${DIGEST_A}:va:0x140001000:0x140001040`);

assert.strictEqual(
	createInstructionId({ target, space: 'rva', address: 0x1010 }),
	`insn:sha256:${DIGEST_A}:rva:0x1010`,
);
assert.strictEqual(
	createDataObjectId({ target, space: 'va', address: '0x140003000' }),
	`data:sha256:${DIGEST_A}:va:0x140003000`,
);
assert.strictEqual(
	createStringId({ target, fileOffset: 0x2400n }),
	`str:sha256:${DIGEST_A}:file-offset:0x2400`,
);
assert.strictEqual(createTypeId({ target, name: 'struct _PEB' }), `type:sha256:${DIGEST_A}:struct-peb`);
assert.strictEqual(
	createVariableId({ target, name: 'arg_8', owner: { space: 'va', functionEntry: '0x140001000' } }),
	`var:sha256:${DIGEST_A}:va:0x140001000:arg-8`,
);
assert.strictEqual(
	createVariableId({ target, name: 'g_Config', owner: 'global' }),
	`var:sha256:${DIGEST_A}:global:g-config`,
);
assert.strictEqual(
	createXrefId({
		target,
		from: { space: 'va', address: '0x140001000' },
		to: { space: 'rva', address: '0x2000' },
		kind: 'CALL',
	}),
	`xref:sha256:${DIGEST_A}:va:0x140001000:rva:0x2000:call`,
);
assert.strictEqual(
	createFindingId({ target, category: 'anti-debug', subject: { space: 'va', address: '0x140002000' } }),
	`finding:sha256:${DIGEST_A}:anti-debug:va:0x140002000`,
);
assert.strictEqual(
	createFindingId({ target, category: 'YARA hit', subject: { token: 'ruleset 42' } }),
	`finding:sha256:${DIGEST_A}:yara-hit:token:ruleset-42`,
);

const artifactId = createArtifactId(HASH_B.toUpperCase());
assert.strictEqual(artifactId, `artifact:sha256:${HASH_B}`);

const parsedFn = parseAnalysisObjectId(fnId);
assert.strictEqual(parsedFn.kind, 'function');
assert.strictEqual(parsedFn.targetId, target.id);
assert.strictEqual(parsedFn.digest, DIGEST_A);
assert.deepStrictEqual(parsedFn.parts, ['va', '0x140001000']);

const parsedArtifact = parseAnalysisObjectId(artifactId);
assert.strictEqual(parsedArtifact.kind, 'artifact');
assert.strictEqual(parsedArtifact.targetId, undefined);
assert.deepStrictEqual(parsedArtifact.parts, []);

assert.strictEqual(analysisObjectIdTargetId(fnId), target.id);
assert.strictEqual(analysisObjectIdTargetId(artifactId), undefined);

assert.strictEqual(isAnalysisObjectId(fnId), true);
assert.strictEqual(isAnalysisObjectId('hello'), false);
assert.strictEqual(isAnalysisObjectId(42), false);

assert.throws(() => createFunctionId({ target, space: 'va', address: Number.MAX_SAFE_INTEGER + 1 }), /safe integers/);
assert.throws(() => createFunctionId({ target, space: 'va', address: -1n }), /cannot be negative/);
assert.throws(() => createTypeId({ target, name: '!!!' }), /cannot be empty/);
assert.throws(() => createTypeId({ target, name: 'x'.repeat(200) }), /128 characters/);
assert.throws(() => parseAnalysisObjectId(`fn:md5:${HASH_A}:va:0x1`), /sha256/);
assert.throws(() => parseAnalysisObjectId(`bogus:sha256:${DIGEST_A}:va:0x1`), /Unknown analysis object ID prefix/);
assert.throws(() => parseAnalysisObjectId(`fn:sha256:${DIGEST_A}`), /discriminator/);
assert.throws(() => parseAnalysisObjectId('artifact:sha256:nothex'), /64 hexadecimal/);

console.log('analysisIds: 34/34 passing');
