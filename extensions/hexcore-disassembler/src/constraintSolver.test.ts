import * as assert from 'assert';
import { buildSolverScript, classifySolverSemanticResult, parseSolverOutput } from './constraintSolver';

suite('constraint solver', () => {
	test('renders bounded integers and bitvector operations', () => {
		const built = buildSolverScript({
			variables: [
				{ name: 'digit', type: 'int', domain: [0, 9] },
				{ name: 'x', type: 'bv', bits: 32 },
			],
			constraints: [
				{ op: 'eq', args: [{ op: 'add', args: ['digit', 3] }, 7] },
				{ op: 'eq', args: [{ op: 'xor', args: ['x', { value: 0x5a, bits: 32 }] }, { value: 0x41, bits: 32 }] },
			],
		});
		assert.match(built.script, /\(declare-const digit Int\)/);
		assert.match(built.script, /\(assert \(>= digit 0\)\)/);
		assert.match(built.script, /\(bvand|bvxor/);
		assert.match(built.script, /\(get-value \(digit x\)\)/);
	});

	test('preserves large integer literals provided as strings', () => {
		const built = buildSolverScript({
			variables: [{ name: 'x', type: 'int' }],
			constraints: [{ op: 'eq', args: ['x', { type: 'int', value: '847851805715481601' }] }],
		});
		assert.match(built.script, /\(= x 847851805715481601\)/);
	});

	test('parses decimal, hexadecimal and bitvector model values', () => {
		const parsed = parseSolverOutput('sat\n((a 7) (b #x0000000f) (c (_ bv9 8)))\n', ['a', 'b', 'c']);
		assert.strictEqual(parsed.status, 'sat');
		assert.deepStrictEqual(parsed.model, { a: '7', b: '15', c: '9' });
	});

	test('parses unsat even when Z3 also reports that no model is available', () => {
		const parsed = parseSolverOutput('unsat\n(error "model is not available")\n', ['a']);
		assert.strictEqual(parsed.status, 'unsat');
		assert.strictEqual(parsed.model, undefined);
	});

	test('rejects solver control commands in raw SMT input', () => {
		assert.throws(() => buildSolverScript({ smt2: '(check-sat)' }), /control commands/);
	});

	test('rejects malformed sorts before invoking Z3', () => {
		assert.throws(() => buildSolverScript({
			variables: [{ name: 'x', type: 'int' }],
			constraints: [{ op: 'and', args: ['x', 1] }],
		}), /and requires bitvectors/);
		assert.throws(() => buildSolverScript({
			variables: [{ name: 'x', type: 'bv', bits: 32 }],
			constraints: [{ op: 'eq', args: ['x', { value: 1, bits: 64 }] }],
		}), /identical sorts/);
		assert.throws(() => buildSolverScript({
			variables: [{ name: 'x', type: 'int' }],
			constraints: [{ op: 'not', args: ['x'] }],
		}), /boolean argument/);
	});

	test('never classifies unknown or timeout as ok by default', () => {
		assert.strictEqual(classifySolverSemanticResult('unknown', false).semanticStatus, 'error');
		assert.strictEqual(classifySolverSemanticResult('sat', true).semanticStatus, 'error');
		assert.strictEqual(classifySolverSemanticResult('unsat', false).semanticStatus, 'ok');
	});

	test('explicit tolerance produces partial rather than ok', () => {
		assert.strictEqual(
			classifySolverSemanticResult('unknown', false, { allowUnknown: true }).semanticStatus,
			'partial',
		);
		assert.strictEqual(
			classifySolverSemanticResult('sat', true, { allowTimeout: true }).semanticStatus,
			'partial',
		);
	});
});
