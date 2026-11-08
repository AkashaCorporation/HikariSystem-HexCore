import * as assert from 'assert';
import { formatAssemblyExportSemanticWarning } from './assemblyExportResult';
import type { AssemblyExportResult } from './disassemblerEngine';

function result(overrides: Partial<AssemblyExportResult>): AssemblyExportResult {
	return {
		status: 'partial',
		totalFunctions: 526,
		functionsWithInstructions: 526,
		functionsWithoutInstructions: 0,
		decodedInstructions: 28_000,
		emptyFunctions: [],
		incompleteFunctions: [],
		...overrides,
	};
}

suite('assembly export semantic result', () => {
	test('reports incomplete bodies instead of claiming zero decoded bodies', () => {
		const warning = formatAssemblyExportSemanticWarning(result({
			incompleteFunctions: [
				{ address: 0x140007630, name: 'sub_140007630', reason: 'partial-decode', byteCoverage: 0.9989754098360656, stopReason: 'decode-failure' },
				{ address: 0x140013080, name: 'sub_140013080', reason: 'partial-decode', byteCoverage: 0.8025210084033614, stopReason: 'decode-failure' },
			],
		}));
		assert.match(warning ?? '', /2\/526 function bodies are incomplete/);
		assert.match(warning ?? '', /0x140007630 \(99\.90%, decode-failure\)/);
		assert.match(warning ?? '', /0x140013080 \(80\.25%, decode-failure\)/);
		assert.doesNotMatch(warning ?? '', /decoded no instructions/);
	});

	test('retains decode-empty wording only for truly empty bodies', () => {
		const warning = formatAssemblyExportSemanticWarning(result({
			functionsWithInstructions: 524,
			functionsWithoutInstructions: 2,
			emptyFunctions: [
				{ address: 0x140001000, name: 'sub_140001000', reason: 'decode-empty' },
				{ address: 0x140001100, name: 'sub_140001100', reason: 'decode-empty' },
			],
		}));
		assert.strictEqual(warning, '2/526 function bodies decoded no instructions');
	});

	test('returns no warning for a complete export', () => {
		assert.strictEqual(formatAssemblyExportSemanticWarning(result({ status: 'ok' })), undefined);
	});
});
