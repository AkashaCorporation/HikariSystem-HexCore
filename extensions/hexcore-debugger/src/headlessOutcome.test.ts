import * as assert from 'assert';
import { classifyHeadlessOutcome, isInvalidInstructionError, parseTerminalAddresses } from './headlessOutcome';

suite('Headless terminal outcome', () => {
	test('never reports a null PC as success', () => {
		const result = classifyHeadlessOutcome({ crashed: false, currentAddress: 0n, instructionsRan: 11, instructionBudget: 10_000 });
		assert.strictEqual(result.status, 'failed');
		assert.strictEqual(result.stopReason.kind, 'unexpected-zero-pc');
	});

	test('reports a requested breakpoint as a successful stop', () => {
		const result = classifyHeadlessOutcome({
			crashed: false, currentAddress: 0x40178en, breakpoints: [0x40178en], instructionsRan: 212, instructionBudget: 10_000,
		});
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.stopReason.kind, 'breakpoint');
	});

	test('reports an exhausted instruction budget as partial', () => {
		const result = classifyHeadlessOutcome({ crashed: false, currentAddress: 0x401050n, instructionsRan: 1000, instructionBudget: 1000 });
		assert.strictEqual(result.status, 'partial');
		assert.strictEqual(result.stopReason.kind, 'instruction-budget');
	});

	test('an expected return sentinel takes precedence over its fetch fault', () => {
		const result = classifyHeadlessOutcome({
			crashed: true, error: 'invalid memory read', currentAddress: 0xdeaddeadn, instructionsRan: 4, instructionBudget: 100,
		});
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.stopReason.kind, 'sentinel-return');
	});

	test('recognizes a caller-provided terminal address and kind', () => {
		const result = classifyHeadlessOutcome({
			crashed: true,
			error: 'Invalid memory fetch',
			currentAddress: 0xfeedfacen,
			terminalAddresses: [0xfeedfacen],
			terminalKind: 'table_return',
			instructionsRan: 42,
			instructionBudget: 100,
		});
		assert.strictEqual(result.status, 'ok');
		assert.strictEqual(result.stopReason.kind, 'configured-terminal');
		assert.strictEqual(result.stopReason.terminalKind, 'table_return');
	});

	test('classifies Unicorn invalid-instruction errors as an explicit capability failure', () => {
		const result = classifyHeadlessOutcome({
			crashed: false,
			error: 'Unicorn error: Invalid instruction (UC_ERR_INSN_INVALID)',
			currentAddress: 0x4018aan,
			instructionsRan: 27,
			instructionBudget: 1000,
			backend: 'unicorn',
			architecture: 'x64',
			unsupportedInstruction: {
				address: '0x4018aa',
				mnemonic: 'vpbroadcastq',
				opStr: 'zmm0, qword ptr [rax]',
				bytes: '62f2fd487800',
			},
		});
		assert.strictEqual(result.status, 'failed');
		assert.strictEqual(result.stopReason.kind, 'unsupported-instruction');
		assert.strictEqual(result.stopReason.capability?.requiredFeature, 'avx512');
		assert.strictEqual(result.stopReason.capability?.fallbackAvailable, false);
		assert.match(result.stopReason.message, /no fallback/i);
	});

	test('recognizes both Unicorn invalid-instruction spellings', () => {
		assert.strictEqual(isInvalidInstructionError('UC_ERR_INSN_INVALID'), true);
		assert.strictEqual(isInvalidInstructionError('Invalid instruction'), true);
		assert.strictEqual(isInvalidInstructionError('invalid memory read'), false);
	});

	test('parses 64-bit terminal strings without Number precision loss', () => {
		assert.deepStrictEqual(parseTerminalAddresses(['0xDEADDEADDEADDEAD']), [0xDEADDEADDEADDEADn]);
		assert.throws(() => parseTerminalAddresses([Number.MAX_SAFE_INTEGER + 1]), /string/);
	});
});
