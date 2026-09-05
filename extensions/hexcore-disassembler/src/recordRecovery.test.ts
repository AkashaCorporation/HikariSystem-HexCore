/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { ingestDebugTypeInfo } from './debugTypeIngestion';
import { recoverRecordsFromPropagation } from './recordRecovery';
import { canonicalizeSemanticType, type SemanticEvidence } from './semanticModel';
import { SemanticStore, type SemanticSqliteFactory } from './semanticStore';
import { TypeManager } from './typeManager';
import { WholeProgramPropagationEngine, type FunctionSummaryInput, type PropagationValueRef } from './wholeProgramPropagation';

function sqlite(): SemanticSqliteFactory {
	return require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')) as SemanticSqliteFactory;
}

const targetIdentity = `target:sha256:${'7'.repeat(64)}`;
const evidence: SemanticEvidence = { strength: 'debug', source: 'debug-info', producer: 'fixture', generation: 1 };

function hash(value: string): string { return crypto.createHash('sha256').update(value).digest('hex'); }
function value(kind: PropagationValueRef['kind'], identity: string, functionIdentity: string, widthBits?: number): PropagationValueRef {
	return { kind, identity, functionIdentity, ...(widthBits ? { widthBits } : {}) };
}

suite('R35 debug types, type manager and record recovery', () => {
	test('declares every R35 command once across manifest, extension and pipeline ownership', () => {
		const root = path.resolve(__dirname, '..');
		const manifest = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8')) as {
			activationEvents: string[]; contributes: { commands: Array<{ command: string }> };
		};
		const extension = fs.readFileSync(path.join(root, 'src', 'extension.ts'), 'utf8');
		const runner = fs.readFileSync(path.join(root, 'src', 'automationPipelineRunner.ts'), 'utf8');
		for (const command of [
			'hexcore.typeManager.list', 'hexcore.typeManager.create', 'hexcore.typeManager.update',
			'hexcore.typeManager.rename', 'hexcore.typeManager.delete', 'hexcore.typeManager.export',
			'hexcore.typeManager.undo', 'hexcore.typeManager.import', 'hexcore.types.ingestDebug', 'hexcore.records.recover',
		]) {
			assert.strictEqual(manifest.activationEvents.filter(item => item === `onCommand:${command}`).length, 1);
			assert.strictEqual(manifest.contributes.commands.filter(item => item.command === command).length, 1);
			assert.strictEqual(extension.split(`registerCommand('${command}'`).length - 1, 1);
			assert.strictEqual(runner.split(`['${command}'`).length - 1, 2);
		}
	});

	test('ingests nested records, unions, arrays and bitfields with typed provenance', () => {
		const store = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		try {
			const result = ingestDebugTypeInfo(store, {
				structs: {
					Child: { kind: 'struct', size: 4, align: 4, fields: [{ name: 'value', offset: '0x0', size: 4, type: 'uint32_t' }] },
					Container: { kind: 'struct', size: 24, align: 8, fields: [
						{ name: 'child', offset: '0x0', size: 8, type: 'struct Child *', nested: true },
						{ name: 'items', offset: '0x8', size: 12, type: 'uint32_t[3]', arrayStrideBits: 32 },
						{ name: 'flags', offset: '0x14', size: 1, type: 'uint8_t', bitOffset: 160, bitSize: 3, bitfield: true },
					] },
					Payload: { kind: 'union', size: 8, fields: [
						{ name: 'word', offset: '0x0', size: 8, type: 'uint64_t' },
						{ name: 'bytes', offset: '0x0', size: 8, type: 'uint8_t[8]' },
					] },
				},
				functions: {},
			}, { provider: 'dwarf', unitIdentity: 'fixture-cu', generation: 1 });
			assert.strictEqual(result.status, 'ok');
			assert.strictEqual(result.recordCount, 3);
			const container = store.listTypes().find(type => type.name === 'Container' && type.kind === 'struct')!;
			assert.strictEqual(container.members?.find(member => member.name === 'items')?.arrayStrideBits, 32);
			assert.strictEqual(container.members?.find(member => member.name === 'flags')?.bitfield, true);
			assert.ok(store.listTypes().some(type => type.name === 'Payload' && type.kind === 'union'));
		} finally { store.dispose(); }
	});

	test('edits stable analyst types transactionally and blocks deletion while dependencies remain', () => {
		const store = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		const manager = new TypeManager(store);
		try {
			const integer = manager.create({ kind: 'integer', name: 'uint32_t', sizeBits: 32, alignBits: 32, signed: false }, 1);
			const record = manager.create({
				kind: 'struct', name: 'Context', sizeBits: 32, alignBits: 32,
				members: [{ name: 'value', typeId: integer.typeId, bitOffset: 0, bitSize: 32 }], dependencies: [integer.typeId],
			}, 2);
			const renamed = manager.rename(record.typeId, 'RenamedContext', 3);
			assert.strictEqual(renamed.typeId, record.typeId);
			const undone = manager.undo(record.typeId, 4);
			assert.strictEqual(undone.name, 'Context');
			const restoredRename = manager.rename(record.typeId, 'RenamedContext', 5);
			assert.strictEqual(manager.delete(integer.typeId, 4).status, 'blocked');
			const exported = manager.export();
			const clone = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
			try {
				const imported = new TypeManager(clone).import(exported);
				assert.strictEqual(imported.changed, exported.payload.types.length);
				assert.strictEqual(new TypeManager(clone).export().contentHash, exported.contentHash);
			} finally { clone.dispose(); }
			assert.strictEqual(manager.delete(record.typeId, 6).status, 'removed');
			assert.strictEqual(manager.delete(integer.typeId, 7).status, 'removed');
			assert.ok(store.listHistory('type', record.typeId).some(item => item.canonicalHash === restoredRename.canonicalHash));
			assert.ok(store.listGenerations().some(item => item.factKey === record.typeId && item.status === 'removed'));
		} finally { store.dispose(); }
	});

	test('promotes only same-object non-overlapping layouts and retains overlaps as union candidates', () => {
		const store = new SemanticStore(sqlite().openDatabase(':memory:'), targetIdentity);
		try {
			const engine = new WholeProgramPropagationEngine(store);
			const functionIdentity = 'function:0x140001000';
			const base = value('parameter', 'context', functionIdentity, 64);
			const good: FunctionSummaryInput = {
				analysisTargetIdentity: targetIdentity, functionIdentity, functionBodySha256: hash('good'), generation: 1, materialized: true,
				fieldAccesses: [
					{ fieldIdentity: 'Context.a', base, offsetBytes: 0, access: 'read', value: value('memory-region', 'a', functionIdentity, 32) },
					{ fieldIdentity: 'Context.b', base, offsetBytes: 8, access: 'write', value: value('memory-region', 'b', functionIdentity, 64) },
				], constraints: [],
			};
			assert.strictEqual(engine.solve([good], { generation: 1 }).status, 'committed');
			const recovered = recoverRecordsFromPropagation(store, 1);
			assert.strictEqual(recovered.promotedCount, 1);
			const inferred = store.getType(recovered.groups[0].recoveredTypeId!);
			assert.deepStrictEqual(inferred?.members?.map(member => member.bitOffset), [0, 64]);

			const overlapFunction = 'function:0x140002000';
			const overlapBase = value('parameter', 'context', overlapFunction, 64);
			const overlap: FunctionSummaryInput = {
				analysisTargetIdentity: targetIdentity, functionIdentity: overlapFunction, functionBodySha256: hash('overlap'), generation: 2, materialized: true,
				fieldAccesses: [
					{ fieldIdentity: 'Overlap.a', base: overlapBase, offsetBytes: 0, access: 'read', value: value('memory-region', 'oa', overlapFunction, 32) },
					{ fieldIdentity: 'Overlap.b', base: overlapBase, offsetBytes: 2, access: 'read', value: value('memory-region', 'ob', overlapFunction, 32) },
				], constraints: [],
			};
			assert.strictEqual(engine.solve([good, overlap], { generation: 2, changedFunctions: [overlapFunction] }).status, 'committed');
			const second = recoverRecordsFromPropagation(store, 2);
			const blocked = second.groups.find(group => group.objectIdentity.includes(overlapFunction))!;
			assert.strictEqual(blocked.status, 'blocked-overlap');
			assert.strictEqual(blocked.overlapCandidates.length, 1);
			assert.strictEqual(blocked.recoveredTypeId, undefined);
		} finally { store.dispose(); }
	});
});
