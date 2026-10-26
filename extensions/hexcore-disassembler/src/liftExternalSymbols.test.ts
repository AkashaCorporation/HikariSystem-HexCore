/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { resolveLiftExternalSymbols, renameLiftedEntry } from './liftExternalSymbols';
const callee = '_ZN12_GLOBAL__N_14CALLI2InImEEEP6MemoryS4_R5StateT_3RnWImES2_S9_';
const address = 0x7fff0000;
const symbols = new Map([[address, 'external_fixture']]);
const call = `%v = call ptr @${callee}(ptr %memory, ptr %state, i64 ${address}, ptr %next, i64 12, ptr %return)`;

suite('scoped lifted external symbol resolution', () => {
	test('entry renaming stamps identity and does not rename string data', () => {
		const ir = 'define ptr @lifted_4096(ptr %s, i64 %pc, ptr %m) {\n ret ptr %m\n}\n; lifted_4096\n@data = constant [11 x i8] c"lifted_4096"\n';
		const renamed = renameLiftedEntry(ir, 4096, 'named_fixture');
		assert.ok(renamed.includes('@named_fixture('));
		assert.ok(renamed.includes('"hexcore.entry_address"="0x1000"'));
		assert.ok(renamed.includes('; lifted_4096')); assert.ok(renamed.includes('c"lifted_4096"'));
		assert.throws(() => renameLiftedEntry(ir, 8192, 'other'), /definition required/);
		assert.throws(() => renameLiftedEntry(ir + 'define ptr @other() { ret ptr null }', 4096, 'other'), /conflicts/);
	});
	test('rewrites only the native CALLI target slot, not data or return PC', () => {
		const ir = [`%x = add i64 ${address}, 1`, `%long = add i64 ${address}0, 1`, `; ${call}`, call.replace('i64 12', `i64 ${address}`)].join('\n');
		const result = resolveLiftExternalSymbols(ir, symbols, [address]);
		assert.strictEqual(result.rewrittenTargets, 1); assert.deepStrictEqual(result.issues, []);
		assert.ok(result.ir.includes(`%x = add i64 ${address}, 1`)); assert.ok(result.ir.includes(`i64 ${address}0`));
		assert.ok(result.ir.includes(`ptr %next, i64 ${address}, ptr %return`));
		assert.ok(result.ir.includes('i64 ptrtoint (ptr @external_fixture to i64)'));
		assert.strictEqual((result.ir.match(/declare ptr @external_fixture/g) ?? []).length, 1);
	});
	test('handles the remill intrinsic argument position and remains idempotent', () => {
		const ir = `%v = call fastcc ptr @__remill_function_call(ptr %state, i64 ${address}, ptr %memory)`;
		const first = resolveLiftExternalSymbols(ir, symbols, [address]);
		const second = resolveLiftExternalSymbols(first.ir, symbols, [address]);
		assert.strictEqual(second.ir, first.ir); assert.strictEqual(second.rewrittenTargets, 0); assert.deepStrictEqual(second.issues, []);
	});
	test('resolves immediate tail-jump targets without touching return helpers', () => {
		const jump = `%v = call ptr @_ZN12_GLOBAL__N_13JMPI2InImE(ptr %memory, ptr %state, i64 ${address}, ptr %next)`;
		const result = resolveLiftExternalSymbols(jump, symbols, [address]);
		assert.strictEqual(result.rewrittenTargets, 1); assert.deepStrictEqual(result.issues, []);
		const returned = `%v = call ptr @__remill_function_return(ptr %state, i64 ${address}, ptr %memory)`;
		assert.strictEqual(resolveLiftExternalSymbols(returned, symbols).ir, returned);
	});
	test('does not reinterpret strings, similar callee names or indirect calls', () => {
		const ir = [`@text = constant [64 x i8] c"${call}"`, call.replace(callee, 'application_CALLI'), `%v = call ptr %fp(ptr @__remill_function_call, i64 ${address})`].join('\n');
		const result = resolveLiftExternalSymbols(ir, symbols, [address]);
		assert.strictEqual(result.ir, ir); assert.strictEqual(result.rewrittenTargets, 0); assert.ok(result.issues.length);
	});
	test('renames declared synthetic global tokens without touching embedded strings', () => {
		const ir = ['declare ptr @sub_7fff0000(...)', '%v = call ptr @sub_7fff0000()', '; @sub_7fff0000', '@text = constant [16 x i8] c"@sub_7fff0000"'].join('\n');
		const result = resolveLiftExternalSymbols(ir, symbols, [address]);
		assert.ok(result.ir.includes('declare ptr @external_fixture(...)')); assert.ok(result.ir.includes('%v = call ptr @external_fixture()'));
		assert.ok(result.ir.includes('; @sub_7fff0000')); assert.ok(result.ir.includes('c"@sub_7fff0000"'));
	});
	test('preserves defined bodies and rejects non-function symbol conflicts', () => {
		const defined = 'define ptr @sub_7fff0000() {\nentry:\n ret ptr null\n}\n';
		const result = resolveLiftExternalSymbols(defined, symbols, [address]);
		assert.strictEqual(result.ir, defined); assert.ok(result.issues.some(issue => issue.includes('Preserved conflicting')));
		assert.strictEqual(resolveLiftExternalSymbols(defined + call, symbols, [address]).ir, defined + call);
		const unrelated = defined.replace('sub_7fff0000', 'sub_7ff01234');
		assert.strictEqual(resolveLiftExternalSymbols(unrelated, symbols).ir, unrelated);
		const global = `@external_fixture = global i64 0\n${call}`;
		const conflict = resolveLiftExternalSymbols(global, symbols, [address]);
		assert.strictEqual(conflict.ir, global); assert.ok(conflict.issues.length);
	});
	test('does not create duplicate declarations when synthetic aliases collide', () => {
		const ir = `declare ptr @sub_7fff0000(...)\ndeclare ptr @lifted_7fff0000(...)\n${call}`;
		const result = resolveLiftExternalSymbols(ir, symbols, [address]);
		assert.strictEqual(result.ir, ir); assert.ok(result.issues.length);
	});
	test('existing declarations are retained and unusual LLVM names are escaped', () => {
		const existing = `declare ptr @external_fixture(...)\n${call}`;
		const result = resolveLiftExternalSymbols(existing, symbols);
		assert.strictEqual((result.ir.match(/declare ptr @external_fixture/g) ?? []).length, 1);
		const weird = resolveLiftExternalSymbols(call, new Map([[address, 'name"with\\quotes']]), [address]);
		assert.ok(weird.ir.includes('@"name\\22with\\5Cquotes"'));
		assert.strictEqual(resolveLiftExternalSymbols(weird.ir, new Map([[address, 'name"with\\quotes']]), [address]).ir, weird.ir);
	});
});
