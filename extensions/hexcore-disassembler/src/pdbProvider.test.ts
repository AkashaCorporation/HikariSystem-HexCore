/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as path from 'path';
import { loadPdbProvider, parsePdbSummary } from './pdbProvider';

suite('R36 PDB provider', function () {
	this.timeout(180_000);

	test('parses and validates real RSDS identity, prototypes, locals, records, lines and compilands deterministically', () => {
		const hql = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const root = path.join(hql, 'benchmarks', 'corpus', 'build', 'msvc-x64-O2-debug');
		const pdbPath = path.join(root, 'semantic_benchmark.pdb');
		assert.ok(fs.existsSync(pdbPath));
		const identity = parsePdbSummary(`GUID: {041FF2AD-D378-E9B4-124B-0EF2C3B15DCB}\nAge: 1\n`)!;
		const first = loadPdbProvider({ pdbPath, imageBase: 0x180000000, expectedGuid: identity.guid, expectedAge: identity.age });
		assert.notStrictEqual(first.status, 'error', JSON.stringify(first.diagnostics));
		assert.strictEqual(first.identityValidated, true);
		assert.strictEqual(first.identity?.guid, identity.guid);
		const xor = first.functions.find(fn => fn.name === 'bench_xor_buffer');
		assert.ok(xor?.prototype, 'bench_xor_buffer prototype must be decoded');
		assert.deepStrictEqual(xor?.prototype?.parameterTypes, ['unsigned char*', 'unsigned __int64', 'unsigned char']);
		assert.ok(xor?.locals.some(local => local.name === 'data' && local.parameter && local.locations.some(location => location.register === 'RCX')));
		assert.ok(first.lines.some(line => line.sourceFile.endsWith('semantic_benchmark.c')));
		assert.ok(first.inlineFrames.length > 0);
		assert.ok(first.enumTypes.some(type => type.name === '_PROCESSINFOCLASS' && type.values.length >= 5));
		assert.ok(first.typeAliases.length > 0);
		assert.ok(Object.values(first.debugTypes.structs).some(record => record.fields.some(field => field.bitfield === true)));
		assert.ok(first.compilands.some(compiland => compiland.endsWith('semantic_benchmark.obj')));
		const object = first.debugTypes.structs.BenchObject;
		assert.ok(object);
		assert.deepStrictEqual(object.fields.map(field => [field.name, field.offset]), [
			['refcount', '0x0'], ['buffer', '0x8'], ['length', '0x10'],
		]);
		const repeated = loadPdbProvider({ pdbPath, imageBase: 0x180000000, expectedGuid: identity.guid, expectedAge: identity.age });
		assert.strictEqual(repeated.contentHash, first.contentHash);
		assert.deepStrictEqual(repeated.functions, first.functions);
	});

	test('fails closed on a PE/PDB GUID or age mismatch', () => {
		const pdbPath = path.resolve(__dirname, '..', '..', 'hexcore-hql', 'benchmarks', 'corpus', 'build', 'msvc-x64-O0-debug', 'semantic_benchmark.pdb');
		const result = loadPdbProvider({ pdbPath, imageBase: 0x180000000, expectedGuid: '00000000-0000-0000-0000-000000000000', expectedAge: 99 });
		assert.strictEqual(result.status, 'error');
		assert.strictEqual(result.identityValidated, false);
		assert.ok(result.diagnostics.some(item => item.code === 'PDB_GUID_MISMATCH'));
		assert.ok(result.diagnostics.some(item => item.code === 'PDB_AGE_MISMATCH'));
	});
});
