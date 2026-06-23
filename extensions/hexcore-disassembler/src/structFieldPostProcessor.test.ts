/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.8.0 Struct Field Post-Processor
// Target: structFieldPostProcessor.ts (param rename + offset-based field rename with
// param-struct disambiguation for offsets shared by multiple structs).

import * as assert from 'assert';
import 'mocha';
import { applyStructFieldNames } from './structFieldPostProcessor';

// Two structs SHARE offset 0x10 with DIFFERENT field names (ambiguous by offset
// alone); offset 0x20 is unique to structB. `myfunc`'s first param is typed as
// structA, which is what disambiguates the 0x10 access.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const structInfo: any = {
	structs: {
		structA: { size: 64, fields: [{ offset: 0x10, name: 'aaa_field', type: 'int', size: 4 }] },
		structB: {
			size: 64,
			fields: [
				{ offset: 0x10, name: 'bbb_field', type: 'int', size: 4 },
				{ offset: 0x20, name: 'unique_in_b', type: 'int', size: 4 },
			],
		},
	},
	functions: {
		myfunc: { params: [{ index: 0, name: 'kctx', type: 'struct kbase_context *', structName: 'structA' }] },
	},
};

suite('structFieldPostProcessor', () => {

	suite('param-struct field disambiguation', () => {

		test('disambiguates an ambiguous offset via the param struct (-> access)', () => {
			// 0x10 exists in BOTH structA and structB with different names, so it is
			// ambiguous by offset alone. param_1 is structA, so kctx->field_0x10 must
			// resolve to structA's field. (Regression: this was dead code -- the
			// var-name match expected the accessor that FIELD_PATTERN had consumed.)
			const r = applyStructFieldNames('void myfunc() {\n  x = param_1->field_0x10;\n}', structInfo, 'myfunc', { includeTypedefs: false });
			assert.ok(r.source.includes('kctx->aaa_field'), `got: ${r.source}`);
			assert.ok(!r.source.includes('field_0x10'));
			assert.strictEqual(r.fieldRenames.length, 1);
		});

		test('disambiguates via the param struct (. access)', () => {
			const r = applyStructFieldNames('void myfunc() {\n  x = param_1.field_0x10;\n}', structInfo, 'myfunc', { includeTypedefs: false });
			assert.ok(r.source.includes('kctx.aaa_field'), `got: ${r.source}`);
			assert.strictEqual(r.fieldRenames.length, 1);
		});

		test('renames an unambiguous offset without needing disambiguation', () => {
			// 0x20 is unique to structB -- renamed even with no known struct.
			const r = applyStructFieldNames('void g() {\n  y = obj->field_0x20;\n}', structInfo, undefined, { includeTypedefs: false });
			assert.ok(r.source.includes('obj->unique_in_b'), `got: ${r.source}`);
			assert.strictEqual(r.fieldRenames.length, 1);
		});

		test('leaves an ambiguous offset unrenamed when no struct is known', () => {
			// 0x10 is ambiguous and `unknown` has no param-struct mapping -> keep as is.
			const r = applyStructFieldNames('void h() {\n  z = unknown->field_0x10;\n}', structInfo, undefined, { includeTypedefs: false });
			assert.ok(r.source.includes('field_0x10'), `got: ${r.source}`);
			assert.strictEqual(r.fieldRenames.length, 0);
		});
	});
});
