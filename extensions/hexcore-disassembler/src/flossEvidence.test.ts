import * as assert from 'assert';
import { importFlossEvidence } from './flossEvidence';

suite('FLOSS evidence contract', () => {
	const context = {
		binarySha256: 'a'.repeat(64), toolVersion: '3.1.1', toolSha256: 'b'.repeat(64), configurationSha256: 'c'.repeat(64),
		normalizationPolicyId: 'hexcore.floss-evidence-projection.v1', normalizationPolicySha256: 'd'.repeat(64),
	};
	const document = {
		metadata: { version: '3.1.1', imagebase: 0x140000000, min_length: 4, file_path: 'volatile.exe', runtime: { start_date: 'volatile' } },
		analysis: {},
		strings: {
			static_strings: [{ string: 'hello', offset: 0x20, encoding: 'ASCII' }],
			language_strings: [], language_strings_missed: [],
			stack_strings: [{ string: 'stack', encoding: 'UTF-8', function: 0x140001000, program_counter: 0x140001020, stack_pointer: 0x1000, original_stack_pointer: 0x1100, offset: 16, frame_offset: -240 }],
			tight_strings: [],
			decoded_strings: [{ string: 'decoded', encoding: 'UTF-16LE', address: 0x140003000, address_type: 'HEAP', decoded_at: 0x140002010, decoding_routine: 0x140002000 }],
		},
	};

	test('imports exact provenance facts without behavioral promotion', () => {
		const json = JSON.stringify(document);
		const first = importFlossEvidence(json, context);
		const second = importFlossEvidence(json, context);
		assert.deepStrictEqual(second, first);
		assert.strictEqual(first.facts.length, 3);
		assert.ok(first.facts.every(fact => fact.evidenceLevel === 'signal' && fact.promotionAllowed === false));
		const staticFact = first.facts.find(fact => fact.kind === 'static-string')!;
		assert.strictEqual(staticFact.fileOffset, '0x20');
		assert.strictEqual(staticFact.address, undefined, 'file offset must not be converted to VA');
		const stackFact = first.facts.find(fact => fact.kind === 'stack-string')!;
		assert.strictEqual(stackFact.functionAddress, '0x140001000');
		assert.strictEqual(stackFact.frameOffset, '-240');
		assert.match(first.normalizedSha256, /^[a-f0-9]{64}$/);
		const rerunDocument = structuredClone(document);
		rerunDocument.metadata.runtime.start_date = 'different-runtime-timestamp';
		const rerun = importFlossEvidence(JSON.stringify(rerunDocument), context);
		assert.notStrictEqual(rerun.sourceJsonSha256, first.sourceJsonSha256);
		assert.strictEqual(rerun.normalizedSha256, first.normalizedSha256, 'volatile FLOSS runtime metadata must not change semantic identity');
		const changedEvidence = structuredClone(document);
		changedEvidence.strings.static_strings[0].string = 'changed';
		assert.notStrictEqual(importFlossEvidence(JSON.stringify(changedEvidence), context).normalizedSha256, first.normalizedSha256, 'evidence changes must change semantic identity');
		assert.notStrictEqual(importFlossEvidence(json, { ...context, normalizationPolicySha256: 'e'.repeat(64) }).normalizedSha256, first.normalizedSha256, 'policy changes must change semantic identity');
	});

	test('fails closed on malformed, unknown-version, and unsafe integer input', () => {
		assert.throws(() => importFlossEvidence('{', context), /Malformed FLOSS JSON/);
		assert.throws(() => importFlossEvidence(JSON.stringify({ ...document, metadata: { ...document.metadata, version: '4.0.0' } }), context), /Unsupported FLOSS result version/);
		const unsafe = structuredClone(document);
		unsafe.strings.static_strings[0].offset = Number.MAX_SAFE_INTEGER + 1;
		assert.throws(() => importFlossEvidence(JSON.stringify(unsafe), context), /safe integer/);
	});
});
