/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { inspectHelixIrInput } from './helixIrInputContract';

suite('Helix IR input identity and quality', () => {
	test('uses AArch64 IR without an active target', () => {
		assert.deepStrictEqual(inspectHelixIrInput('target triple = "aarch64-pc-linux-gnu-elf"'), {
			architecture: 'arm64', architectureSource: 'ir', status: 'ok', reasons: [],
		});
	});
	test('does not permit explicit or bound architectures to contradict the IR', () => {
		const ir = 'target triple = "aarch64-linux-gnu"';
		assert.throws(() => inspectHelixIrInput(ir, 'x64'), /architecture-mismatch/);
		assert.throws(() => inspectHelixIrInput(ir, undefined, 'x64'), /architecture-mismatch/);
		assert.strictEqual(inspectHelixIrInput(ir, 'aarch64', 'arm64').architecture, 'arm64');
	});
	test('rejects unsupported triples rather than interpreting them as x64', () => {
		assert.throws(() => inspectHelixIrInput('target triple = "riscv64-linux-gnu"'), /unsupported-architecture/);
	});
	test('keeps partial lift status despite full decoded coverage', () => {
		const result = inspectHelixIrInput('; Architecture: aarch64\n; SemanticStatus: partial\n; SemanticCoverage: 100.00%\n; SemanticWarning: boundary not reached\ntarget triple = "aarch64-linux-gnu"');
		assert.strictEqual(result.status, 'partial');
		assert.ok(result.reasons.includes('boundary not reached'));
	});
	test('keeps partial provenance even when retained IR has no warning header', () => {
		const result = inspectHelixIrInput('target triple = "aarch64-linux-gnu"', undefined, undefined, ['Partial persisted input']);
		assert.strictEqual(result.status, 'partial');
		assert.deepStrictEqual(result.reasons, ['Partial persisted input']);
	});
	test('retains exact requested and decoded byte coverage from Remill headers', () => {
		const result = inspectHelixIrInput([
			'; Architecture: amd64_avx',
			'; SemanticStatus: ok',
			'; SemanticCoverage: 100.00% (decoded=26, lifted=26, unsupported=0, failures=0)',
			'; RequestedByteRange: [0x1400013C0, 0x140001404) domain=byte-range',
			'; RemillDecodedByteSet: 100.00% (68/68 bytes)',
			'target triple = "x86_64-unknown-windows-msvc-coff"',
		].join('\n'));
		assert.strictEqual(result.status, 'ok');
		assert.deepStrictEqual(result.liftEvidence, {
			requestedByteRange: { startAddress: 0x1400013C0, endExclusive: 0x140001404, size: 68 },
			decodedByteCoverage: { decodedBytes: 68, requestedBytes: 68, coverage: 1 },
			semanticInstructionCoverage: 1,
		});
	});
	test('marks a retained under-lift partial even when decoded instructions are semantically complete', () => {
		const result = inspectHelixIrInput([
			'; Architecture: amd64_avx',
			'; SemanticStatus: ok',
			'; SemanticCoverage: 100.00%',
			'; RequestedByteRange: [0x140000000, 0x140001000)',
			'; RemillDecodedByteSet: 9.38% (384/4096 bytes)',
			'target triple = "x86_64-unknown-windows-msvc-coff"',
		].join('\n'));
		assert.strictEqual(result.status, 'partial');
		assert.match(result.reasons.join('; '), /9\.4% \(384\/4096\)/);
	});
	test('marks missing architecture as non-authoritative and preserves explicit raw-IR usage', () => {
		assert.strictEqual(inspectHelixIrInput('define void @f() { ret void }').status, 'partial');
		assert.strictEqual(inspectHelixIrInput('define void @f() { ret void }', 'x86').architecture, 'x86');
	});
	test('rejects JSON error artifacts before LLVM parsing', () => {
		assert.throws(() => inspectHelixIrInput('{"stub":true,"ok":false}'), /upstream-error-artifact/);
		assert.throws(() => inspectHelixIrInput('{"rows":[]}'), /incompatible-artifact/);
		assert.throws(() => inspectHelixIrInput('[]'), /incompatible-artifact/);
		assert.throws(() => inspectHelixIrInput('; SemanticStatus: error\ndefine void @f() { ret void }'), /upstream-error-artifact/);
	});
});
