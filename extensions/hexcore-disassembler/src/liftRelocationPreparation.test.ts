/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { prepareLiftRelocations, type LiftRelocationInput } from './liftRelocationPreparation';

suite('shared lift relocation preparation', () => {
	const input = (): LiftRelocationInput => ({ bytes: Buffer.alloc(32), startAddress: 0x1000, textSectionAddress: 0x1000, relocatable: true, architecture: 'x64', textRelocations: new Map(), dataRelocations: new Map(), readDataSection: () => Buffer.from('example\0') });
	test('patches call/return-thunk symbols using S+A-P and preserves source bytes', () => {
		const spec = input(); spec.textRelocations = new Map([[1, { name: 'callee', type: 4, addend: -4 }], [6, { name: '__x86_return_thunk', type: 4, addend: -4 }], [11, { name: 'callee', type: 2, addend: -4 }]]);
		const result = prepareLiftRelocations(spec);
		assert.deepStrictEqual(result.issues, []); assert.strictEqual(result.patches.length, 3);
		assert.strictEqual(0x1005 + result.bytes.readInt32LE(1), 0x7fff0000);
		assert.strictEqual(0x100a + result.bytes.readInt32LE(6), 0x7fff0010);
		assert.strictEqual(0x100f + result.bytes.readInt32LE(11), 0x7fff0000);
		assert.deepStrictEqual([...result.symbolMap], [[0x7fff0000, 'callee'], [0x7fff0010, '__x86_return_thunk']]);
		assert.deepStrictEqual(spec.bytes, Buffer.alloc(32)); assert.notStrictEqual(result.sourceSha256, result.preparedSha256);
	});
	test('patches rodata PC32 and absolute 32/32S with detached data buffers', () => {
		const spec = input(); const data = Buffer.from('example\0'); spec.readDataSection = () => data;
		spec.dataRelocations = new Map([[2, { sectionName: '.rodata', type: 2, addend: 1 }], [10, { sectionName: '.rodata', type: 10, addend: 0 }], [20, { sectionName: '.rodata', type: 11, addend: 8 }]]);
		const result = prepareLiftRelocations(spec);
		assert.deepStrictEqual(result.issues, []);
		assert.strictEqual(0x1006 + result.bytes.readInt32LE(2), 0x7f000001);
		assert.strictEqual(result.bytes.readUInt32LE(10), 0x7f000000);
		assert.strictEqual(result.bytes.readUInt32LE(20), 0x7f000008);
		result.dataSections[0].bytes[0] = 0; assert.strictEqual(data[0], 'e'.charCodeAt(0));
	});
	test('resolves fentry identity without erasing the call or qualifying its effects', () => {
		const spec = input(); spec.bytes = Buffer.from('f30f1efae800000000c3', 'hex');
		spec.textRelocations = new Map([[5, { name: '__fentry__', type: 4, addend: -4 }]]);
		const result = prepareLiftRelocations(spec);
		assert.strictEqual(result.bytes[4], 0xe8);
		assert.strictEqual(result.bytes[9], 0xc3);
		assert.strictEqual(result.patches.length, 1);
		const target = 0x1009 + result.bytes.readInt32LE(5);
		assert.notStrictEqual(target, 0x1009, 'not a fabricated call to the next instruction');
		assert.strictEqual(result.symbolMap.get(target), '__fentry__');
		assert.deepStrictEqual(result.issues, ['Unqualified instrumentation semantics: __fentry__']);
		assert.strictEqual(spec.bytes.toString('hex'), 'f30f1efae800000000c3');
		spec.textRelocations = new Map([[5, { name: '__fentry__', type: 999, addend: -4 }]]);
		const unsupported = prepareLiftRelocations(spec);
		assert.strictEqual(unsupported.patches.length, 0);
		assert.strictEqual(unsupported.symbolMap.size, 0);
		assert.ok(unsupported.issues.some(issue => issue.includes('Unsupported symbol relocation')));
	});
	test('reports unsupported/deferred relocations rather than claiming complete fixups', () => {
		const spec = input(); spec.textRelocations = new Map([[1, { name: '__x86_indirect_thunk_rax', type: 4, addend: -4 }], [9, { name: 'unsupported', type: 999, addend: 0 }]]);
		spec.dataRelocations = new Map([[20, { sectionName: '.data', type: 10, addend: 0 }]]);
		const result = prepareLiftRelocations(spec);
		assert.strictEqual(result.issues.length, 3); assert.strictEqual(result.patches.length, 0);
		assert.strictEqual(result.sourceSha256, result.preparedSha256);
	});
	test('boundary and overlap checks prevent partial operand writes', () => {
		const spec = input(); spec.textRelocations = new Map([[1, { name: 'a', type: 4, addend: -4 }], [2, { name: 'b', type: 4, addend: -4 }], [31, { name: 'c', type: 4, addend: -4 }], [40, { name: 'outside', type: 4, addend: -4 }]]);
		const result = prepareLiftRelocations(spec);
		assert.strictEqual(result.patches.length, 1); assert.strictEqual(result.issues.length, 2); assert.strictEqual(result.bytes[31], 0);
		const cut = input(); cut.startAddress += 2; cut.textRelocations = new Map([[1, { name: 'left-cut', type: 4, addend: -4 }]]);
		assert.match(prepareLiftRelocations(cut).issues.join(), /crosses the lift boundary/);
	});
	test('does not patch missing/out-of-budget data or wrap unreachable displacements', () => {
		const spec = input(); spec.dataRelocations = new Map([[1, { sectionName: '.rodata', type: 2, addend: 0 }]]); spec.maxDataBytes = 0;
		assert.strictEqual(prepareLiftRelocations(spec).patches.length, 0);
		spec.maxDataBytes = 64; spec.readDataSection = () => undefined;
		assert.match(prepareLiftRelocations(spec).issues.join(), /unavailable/);
		const far = input(); far.startAddress = 0x100000000; far.textSectionAddress = far.startAddress; far.textRelocations = new Map([[1, { name: 'far', type: 4, addend: -4 }]]);
		assert.match(prepareLiftRelocations(far).issues.join(), /out of signed/);
	});
	test('large sections receive non-overlapping synthetic ranges', () => {
		const spec = input(); spec.dataRelocations = new Map([[1, { sectionName: '.rodata.large', type: 10, addend: 0 }], [8, { sectionName: '.rodata.small', type: 10, addend: 0 }]]);
		spec.readDataSection = name => Buffer.alloc(name.endsWith('large') ? 0x100001 : 4);
		const result = prepareLiftRelocations(spec); assert.deepStrictEqual(result.issues, []);
		assert.deepStrictEqual(result.dataSections.map(section => section.vaStart), [0x7f000000, 0x7f200000]);
	});
	test('non-relocatable inputs are a detached no-op; other architectures remain explicit', () => {
		const spec = input(); spec.relocatable = false;
		const result = prepareLiftRelocations(spec); assert.strictEqual(result.sourceSha256, result.preparedSha256); assert.notStrictEqual(result.bytes, spec.bytes);
		spec.relocatable = true; spec.architecture = 'arm64'; assert.match(prepareLiftRelocations(spec).issues.join(), /not implemented/);
	});
});
