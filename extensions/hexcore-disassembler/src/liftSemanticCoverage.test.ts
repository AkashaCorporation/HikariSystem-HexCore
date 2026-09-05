import * as assert from 'assert';
import { assessLiftSemanticCoverage, countHandleUnsupportedCalls, formatLiftSemanticHeader } from './liftSemanticCoverage';

suite('lift semantic coverage', () => {
	test('does not count the HandleUnsupported declaration', () => {
		const ir = [
			'declare ptr @HandleUnsupported(ptr, ptr)',
			'%v1 = call ptr @HandleUnsupported(ptr %m, ptr %s)',
			'%v2 = call ptr @HandleUnsupported(ptr %v1, ptr %s)',
		].join('\n');
		assert.strictEqual(countHandleUnsupportedCalls(ir), 2);
	});

	test('marks a successful transport with unsupported semantics partial', () => {
		const result = assessLiftSemanticCoverage('', {
			decodedInstructions: 100,
			liftedInstructions: 79,
			unsupportedInstructions: 21,
			semanticCoverage: 0.79,
			unsupportedOpcodes: { VPMADD52LUQZ128rm: 21 },
		});
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.semanticCoverage, 0.79);
		assert.match(result.reason ?? '', /21 decoded instruction/);
	});

	test('keeps a fully semantic lift ok', () => {
		const result = assessLiftSemanticCoverage('', {
			decodedInstructions: 42,
			liftedInstructions: 42,
			unsupportedInstructions: 0,
			decodeFailureInstructions: 0,
			semanticCoverage: 1,
		});
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.reason, undefined);
	});

	test('retains coverage and the dominant opcode histogram in the IR header', () => {
		const assessment = assessLiftSemanticCoverage('', {
			decodedInstructions: 260,
			liftedInstructions: 30,
			unsupportedInstructions: 230,
			semanticCoverage: 30 / 260,
			unsupportedOpcodes: { VPCOMPRESSQ: 36, KMOVB: 94, VPBROADCASTQ: 54 },
		});
		const header = formatLiftSemanticHeader(assessment);
		assert.match(header, /SemanticStatus: partial/);
		assert.match(header, /SemanticCoverage: 11\.54%/);
		assert.match(header, /KMOVB=94, VPBROADCASTQ=54, VPCOMPRESSQ=36/);
	});
});
