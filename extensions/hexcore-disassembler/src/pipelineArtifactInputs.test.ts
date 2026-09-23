/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { validatePipelineArtifactInputs } from './pipelineArtifactInputs';

suite('pipeline artifact input contracts', () => {
	let root: string;
	let file: string;
	setup(() => {
		root = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-artifact-contract-'));
		fs.mkdirSync(path.join(root, 'nested'));
		file = path.join(root, 'nested', 'input.ll');
		fs.writeFileSync(file, 'target triple = "x86_64-linux-gnu"\ndefine void @f() { ret void }');
	});
	teardown(() => { fs.rmSync(root, { recursive: true, force: true }); });
	function provenance(status: string): void {
		fs.mkdirSync(path.join(root, '.hexcore-meta'), { recursive: true });
		fs.writeFileSync(path.join(root, '.hexcore-meta', 'provenance.json'), JSON.stringify({ artifacts: [{
			artifact: { path: file, sha256: crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex') },
			step: { resolvedCmd: 'hexcore.disasm.liftToIR', semanticStatus: status, artifactKind: 'llvm-ir' },
		}] }));
	}
	test('rejects a failed persisted producer even if its file contains valid IR', async () => {
		provenance('error');
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [], true, root), /upstream-artifact-unavailable/);
	});
	test('rejects stale provenance hashes', async () => {
		provenance('ok'); fs.appendFileSync(file, '\n; changed');
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [], true, root), /hash-mismatch/);
	});
	test('requires partial opt-in and retains the reason', async () => {
		provenance('partial');
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [], false, root), /allowPartial/);
		assert.ok((await validatePipelineArtifactInputs({ irPath: file }, [], true, root)).length);
	});
	test('rejects incompatible artifact kinds despite an ll extension', async () => {
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [{ outputPath: file, status: 'ok', artifactKind: 'c-source' }], true, root), /artifact-kind/);
	});
	test('validates relative IR paths against the command workspace', async () => {
		fs.writeFileSync(file, '{"ok":false,"stub":true}');
		await assert.rejects(validatePipelineArtifactInputs({ irPath: path.relative(root, file) }, [], true, root), /error-contract/);
	});
	test('rejects JSON arrays and inline error contracts as IR', async () => {
		await assert.rejects(validatePipelineArtifactInputs({ irText: '[]' }, [], true), /artifact-kind/);
		await assert.rejects(validatePipelineArtifactInputs({ irText: '{"status":"error"}' }, [], true), /error-contract/);
	});
	test('does not downgrade an unknown producer state to ok', async () => {
		provenance('unknown');
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [], true, root), /producer state/);
	});
	test('uses execution order, not array order, for literal-path producer state', async () => {
		assert.deepStrictEqual(await validatePipelineArtifactInputs({ irPath: file }, [
			{ outputPath: file, status: 'ok', artifactKind: 'llvm-ir', executionOrdinal: 3 },
			{ outputPath: file, status: 'error', executionOrdinal: 2 },
		], false, root), []);
	});
	test('allows clean retained IR without requiring a historical manifest', async () => {
		assert.deepStrictEqual(await validatePipelineArtifactInputs({ irPath: file }, [], false, root), []);
	});
	test('does not mistake arbitrary JSON business state for a HexCore error contract', async () => {
		fs.writeFileSync(file, '{"status":"failed","error":"business record"}');
		assert.deepStrictEqual(await validatePipelineArtifactInputs({ input: file }, [], false, root), []);
		await assert.rejects(validatePipelineArtifactInputs({ irPath: file }, [], false, root), /upstream-artifact/);
	});
});
