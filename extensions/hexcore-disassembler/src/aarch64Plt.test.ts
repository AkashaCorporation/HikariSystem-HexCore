/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { CapstoneWrapper } from './capstoneWrapper';
import { resolveAarch64PltBindings } from './aarch64Plt';

suite('AArch64 PLT instruction/GOT binding', () => {
	const base = 0x555555555000;
	const got = base + 0x1000 + 0x268;
	const core = Buffer.from('100000b0113641f910a2099120021fd6', 'hex');
	let capstone: CapstoneWrapper;
	suiteSetup(async () => { capstone = new CapstoneWrapper(); await capstone.initialize('arm64', { detail: true }); });
	suiteTeardown(() => capstone.dispose());
	async function resolve(bytes: Buffer, symbols = new Map([[got, 'first'], [got + 8, 'second']])) {
		const decoded = await capstone.disassemble(bytes, base, bytes.length / 4);
		return resolveAarch64PltBindings(decoded, symbols, id => capstone.getRegisterName(id));
	}
	test('resolves a standard 16-byte stub above 4 GiB', async () => {
		assert.deepStrictEqual(await resolve(core), [{ address: base, endExclusive: base + 16, gotAddress: got, symbol: 'first' }]);
	});
	test('resolves padded entries in GOT order rather than relocation order', async () => {
		const second = Buffer.from(core);
		second.writeUInt32LE(0xf9413a11, 4); // ldr x17, [x16, #0x270]
		second.writeUInt32LE(0x9109c210, 8); // add x16, x16, #0x270
		const padding = Buffer.from('1f2003d51f2003d5', 'hex');
		const result = await resolve(Buffer.concat([second, padding, core, padding]));
		assert.deepStrictEqual(result.map(item => [item.address, item.symbol]), [[base, 'second'], [base + 24, 'first']]);
	});
	test('retains a BTI entry address without naming its interior twice', async () => {
		const result = await resolve(Buffer.concat([Buffer.from('5f2403d5', 'hex'), core]));
		assert.strictEqual(result.length, 1);
		assert.strictEqual(result[0].address, base);
	});
	test('supports authenticated PLT branches with a proven GOT modifier', async () => {
		// PAC encodings generated with LLVM MC, not inferred from instruction text.
		const signed = Buffer.concat([core.subarray(0, 12), Buffer.from('9f2103d5', 'hex'), core.subarray(12)]);
		assert.strictEqual((await resolve(signed))[0].symbol, 'first');
		for (const branch of ['300a1fd7', '300e1fd7']) {
			assert.strictEqual((await resolve(Buffer.concat([core.subarray(0, 12), Buffer.from(branch, 'hex')])))[0].symbol, 'first');
		}
		assert.deepStrictEqual(await resolve(Buffer.concat([core.subarray(0, 8), Buffer.from('9f2103d5', 'hex'), core.subarray(12)])), []);
	});
	test('does not invent a symbol for an unmapped GOT slot', async () => {
		assert.deepStrictEqual(await resolve(core, new Map()), []);
	});
	test('rejects clobbered address setup and the wrong branch register', async () => {
		const clobbered = Buffer.from(core); clobbered.writeUInt32LE(0xd2800010, 8); // mov x16, #0
		assert.deepStrictEqual(await resolve(clobbered), []);
		const branch = Buffer.from(core); branch.writeUInt32LE(0xd61f0200, 12); // br x16
		assert.deepStrictEqual(await resolve(branch), []);
	});
	test('requires complete contiguous structured instructions', async () => {
		assert.deepStrictEqual(await resolve(core.subarray(0, 12)), []);
		const decoded = await capstone.disassemble(core, base, 4);
		decoded[1].detail = undefined;
		assert.deepStrictEqual(resolveAarch64PltBindings(decoded, new Map([[got, 'first']]), id => capstone.getRegisterName(id)), []);
	});
});
