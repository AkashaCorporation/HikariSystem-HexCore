import * as assert from 'assert';
import { planElf64RelaDyn } from './elfRelocations';

function rela(offset: bigint, symbol: bigint, type: bigint, addend: bigint): Buffer {
	const entry = Buffer.alloc(24);
	entry.writeBigUInt64LE(offset, 0);
	entry.writeBigUInt64LE((symbol << 32n) | type, 8);
	entry.writeBigInt64LE(addend, 16);
	return entry;
}

suite('ELF64 PIE base relocations', () => {
	test('plans R_X86_64_RELATIVE using the load bias for target and value', () => {
		const buffer = Buffer.concat([
			rela(0x3000n, 0n, 8n, 0x1234n),
			rela(0x3010n, 2n, 6n, 0n),
			rela(0x3020n, 0n, 37n, 0n),
		]);
		const plan = planElf64RelaDyn(buffer, { offset: 0, size: buffer.length }, 0x555555554000n);

		assert.deepStrictEqual(plan.relocations, [{
			targetAddress: 0x555555557000n,
			value: 0x555555555234n,
		}]);
		assert.deepStrictEqual(plan.coverage, {
			total: 3, relative: 1, appliedRelative: 0, deferredImports: 1, unsupported: 1, failed: 0,
		});
	});

	test('reports truncated entries instead of reading past the file', () => {
		const plan = planElf64RelaDyn(Buffer.alloc(25), { offset: 0, size: 48 }, 0n);
		assert.strictEqual(plan.coverage.total, 1);
		assert.strictEqual(plan.coverage.failed, 1);
	});
});
