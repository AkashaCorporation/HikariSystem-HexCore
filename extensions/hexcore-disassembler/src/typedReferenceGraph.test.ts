/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { SemanticEvidence } from './semanticModel';
import { SemanticStore, type SemanticSqliteDatabase, type SemanticSqliteFactory } from './semanticStore';
import { SessionStore } from './sessionStore';
import {
	REFERENCE_GRAPH_SCHEMA_VERSION,
	TypedReferenceGraph,
	canonicalizeReferenceEdge,
	type ReferenceEdgeSpec,
	type ReferenceRelationKind,
	type ReferenceTarget,
} from './typedReferenceGraph';

const targetIdentity = `target:sha256:${'a'.repeat(64)}`;

function loadNativeSqlite(): SemanticSqliteFactory {
	// eslint-disable-next-line @typescript-eslint/no-var-requires
	return require(path.join(__dirname, '..', '..', 'hexcore-better-sqlite3')) as SemanticSqliteFactory;
}

function evidence(
	generation = 1,
	producer = 'capstone:fixture',
	strength: SemanticEvidence['strength'] = 'derived',
): SemanticEvidence {
	if (strength === 'definitive') {
		return { strength, source: 'analyst', producer, generation, userDefined: true };
	}
	return {
		strength,
		source: strength === 'debug' ? 'debug-info' : strength === 'signature' ? 'signature' : 'dataflow',
		producer,
		generation,
	};
}

function edge(overrides: Partial<ReferenceEdgeSpec> = {}): ReferenceEdgeSpec {
	return {
		analysisTargetIdentity: targetIdentity,
		relation: 'code-call-near',
		source: {
			address: '0x140001010',
			ownerFunctionIdentity: 'function:0x140001000',
			basicBlockIdentity: 'basic-block:0x140001000:0',
			operandIndex: 0,
		},
		target: { kind: 'function', identity: 'function:0x140002000', address: '0x140002000' },
		accessWidthBits: null,
		provenance: {
			sourceEngine: 'hexcore-capstone',
			sourceEngineVersion: '5.0.9',
			sourceArtifactSha256: 'b'.repeat(64),
			evidenceAddress: '0x140001010',
		},
		evidence: evidence(),
		invalidationDependencies: [
			{ kind: 'function-body', key: 'function:0x140001000', generation: 1, contentSha256: 'c'.repeat(64) },
		],
		...overrides,
	};
}

function targetFor(relation: ReferenceRelationKind): ReferenceTarget {
	switch (relation) {
		case 'string-reference':
			return { kind: 'string', identity: 'string:0x140050000', address: '0x140050000' };
		case 'type-reference':
			return { kind: 'type', identity: 'type:sha256:context' };
		case 'type-member-reference':
			return { kind: 'type-member', identity: 'member:context:flags', typeId: 'type:sha256:context', memberIdentity: 'member:context:flags' };
		case 'type-symbolic-constant-reference':
			return { kind: 'enum-member', identity: 'enum:flags:ready', typeId: 'type:sha256:flags' };
		case 'type-vtable-slot-reference':
			return { kind: 'vtable-slot', identity: 'vtable:context:slot:3', typeId: 'type:sha256:context' };
		case 'type-function-pointer-slot-reference':
			return { kind: 'function-pointer-slot', identity: 'callback-table:slot:2' };
		case 'import-relocation':
		case 'import-iat':
		case 'import-plt':
			return { kind: 'import', identity: 'import:kernel32!CreateFileW', address: '0x140060000' };
		case 'data-read':
		case 'data-write':
		case 'data-read-write':
		case 'data-address-taken':
		case 'data-offset-pointer-construction':
			return { kind: 'global', identity: 'global:0x140070000', address: '0x140070000' };
		default:
			return { kind: 'function', identity: 'function:0x140002000', address: '0x140002000' };
	}
}

function relationSpec(relation: ReferenceRelationKind, index: number): ReferenceEdgeSpec {
	const indirect = relation === 'code-indirect-candidate' || relation === 'code-indirect-resolved';
	return edge({
		relation,
		source: {
			address: `0x${(0x140001010n + BigInt(index)).toString(16)}`,
			ownerFunctionIdentity: 'function:0x140001000',
			basicBlockIdentity: 'basic-block:0x140001000:0',
			operandIndex: index,
		},
		target: targetFor(relation),
		accessWidthBits: ['data-read', 'data-write', 'data-read-write'].includes(relation) ? 64 : null,
		provenance: {
			sourceEngine: 'hexcore-capstone',
			evidenceAddress: `0x${(0x140001010n + BigInt(index)).toString(16)}`,
		},
		...(indirect ? {
			indirectResolution: {
				status: relation === 'code-indirect-candidate' ? 'candidate' as const : 'resolved' as const,
				candidateSetId: `candidate-set:${index}`,
				source: 'address-taken-function' as const,
				reason: 'target address is materialized and address-taken',
			},
		} : {}),
	});
}

suite('HXDB persistent typed reference graph R33', function () {
	this.timeout(30_000);
	let tempDir = '';

	setup(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-reference-graph-'));
	});

	teardown(() => {
		const resolved = path.resolve(tempDir);
		const tempRoot = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempRoot)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('canonicalizes the complete R33 relation vocabulary with stable IDs and exact addresses', () => {
		const relations: ReferenceRelationKind[] = [
			'code-call-near', 'code-call-far', 'code-tail-call', 'code-jump', 'code-flow',
			'code-exception', 'code-unwind', 'code-indirect-candidate', 'code-indirect-resolved',
			'data-read', 'data-write', 'data-read-write', 'data-address-taken',
			'data-offset-pointer-construction', 'type-reference', 'type-member-reference',
			'type-symbolic-constant-reference', 'type-vtable-slot-reference',
			'type-function-pointer-slot-reference', 'import-relocation', 'import-iat', 'import-plt',
			'string-reference',
		];
		const canonical = relations.map((relation, index) => canonicalizeReferenceEdge(relationSpec(relation, index)));
		assert.strictEqual(canonical.length, 23);
		assert.strictEqual(new Set(canonical.map(item => item.edgeId)).size, canonical.length);
		assert.deepStrictEqual([...new Set(canonical.map(item => item.family))].sort(), ['code', 'data', 'import', 'string', 'type']);
		assert.ok(canonical.every(item => item.schemaVersion === REFERENCE_GRAPH_SCHEMA_VERSION));
		assert.ok(canonical.every(item => /^reference-edge:sha256:[0-9a-f]{64}$/.test(item.edgeId)));

		const aboveSafeInteger = canonicalizeReferenceEdge(edge({
			source: { ...edge().source, address: '0xffffffffffffffff' },
			provenance: { ...edge().provenance, evidenceAddress: '0xffffffffffffffff' },
			target: { kind: 'function', identity: 'function:max', address: '0xfffffffffffffffe' },
		}));
		assert.strictEqual(aboveSafeInteger.source.address, '0xffffffffffffffff');
		assert.strictEqual(aboveSafeInteger.target.address, '0xfffffffffffffffe');

		const otherEvidence = canonicalizeReferenceEdge(edge({
			provenance: { sourceEngine: 'hexcore-remill', evidenceAddress: '0x140001010' },
			evidence: evidence(1, 'remill:fixture'),
		}));
		const original = canonicalizeReferenceEdge(edge());
		assert.strictEqual(otherEvidence.edgeId, original.edgeId, 'producer identity must not destabilize a logical edge ID');
		assert.strictEqual(otherEvidence.canonicalHash, original.canonicalHash, 'provenance is evidence, not relation semantics');
	});

	test('retains exact direct call addresses without pretending they are materialized functions', () => {
		const direct = canonicalizeReferenceEdge({
			...edge(), relation: 'code-call-near',
			target: { kind: 'address', identity: 'address:0x140009000', address: '0x140009000' },
		});
		assert.strictEqual(direct.target.kind, 'address');
		const candidate = canonicalizeReferenceEdge({
			...edge(), relation: 'code-indirect-candidate',
			target: { kind: 'address', identity: 'address:0x140009000', address: '0x140009000' },
			indirectResolution: { status: 'candidate', candidateSetId: 'set:address', source: 'constant-function-pointer', reason: 'fixture' },
		});
		assert.strictEqual(candidate.target.kind, 'address');
		assert.throws(() => canonicalizeReferenceEdge({
			...edge(), relation: 'code-indirect-resolved',
			target: { kind: 'address', identity: 'address:0x140009000', address: '0x140009000' },
			indirectResolution: { status: 'resolved', candidateSetId: 'set:bad', source: 'points-to-set', reason: 'fixture' },
		}), /must target a function/);
	});

	test('persists typed edges in HXDB and serves exact incoming/outgoing/type/member/data/call queries', () => {
		const sqlite = loadNativeSqlite();
		const db = sqlite.openDatabase(':memory:');
		const store = new SemanticStore(db, targetIdentity);
		const graph = store.getReferenceGraph();
		const direct = canonicalizeReferenceEdge(edge());
		const read = canonicalizeReferenceEdge(edge({
			relation: 'data-read',
			source: { ...edge().source, address: '0x140001020', operandIndex: 1 },
			target: { kind: 'global', identity: 'global:state', address: '0x140070000', typeId: 'type:uint32' },
			accessWidthBits: 32,
			provenance: { sourceEngine: 'hexcore-remill', evidenceAddress: '0x140001020' },
		}));
		const member = canonicalizeReferenceEdge(edge({
			relation: 'data-write',
			source: { ...edge().source, address: '0x140001030', operandIndex: 2 },
			target: { kind: 'type-member', identity: 'member:context:flags', typeId: 'type:context', memberIdentity: 'member:context:flags' },
			accessWidthBits: 64,
			provenance: { sourceEngine: 'hexcore-helix', evidenceAddress: '0x140001030' },
		}));
		const typeUse = canonicalizeReferenceEdge(edge({
			relation: 'type-reference',
			source: { ...edge().source, address: '0x140001040', operandIndex: 3 },
			target: { kind: 'type', identity: 'type:context' },
			provenance: { sourceEngine: 'hexcore-hast', evidenceAddress: '0x140001040' },
		}));
		const importUse = canonicalizeReferenceEdge(edge({
			relation: 'import-iat',
			source: { ...edge().source, address: '0x140001050', operandIndex: 4 },
			target: { kind: 'import', identity: 'import:kernel32!CreateFileW', address: '0x140060000' },
			provenance: { sourceEngine: 'hexcore-pe', evidenceAddress: '0x140001050' },
		}));
		const stringUse = canonicalizeReferenceEdge(edge({
			relation: 'string-reference',
			source: { ...edge().source, address: '0x140001060', operandIndex: 5 },
			target: { kind: 'string', identity: 'string:open-failed', address: '0x140080000' },
			provenance: { sourceEngine: 'hexcore-strings', evidenceAddress: '0x140001060' },
		}));
		const batch = graph.writeBatch([stringUse, direct, typeUse, member, importUse, read]);
		assert.strictEqual(batch.results.length, 6);
		assert.ok(batch.results.every(result => result.status === 'accepted-new'));
		assert.strictEqual(graph.query().length, 6);
		assert.deepStrictEqual(graph.getCallers(direct.target.identity).map(item => item.callsiteAddress), ['0x140001010']);
		assert.deepStrictEqual(graph.getCallees(direct.source.ownerFunctionIdentity).map(item => item.calleeIdentity), [direct.target.identity]);
		assert.deepStrictEqual(graph.findDataAccesses('global', 'global:state').map(item => item.relation), ['data-read']);
		assert.deepStrictEqual(graph.findDataAccesses('type-member', 'member:context:flags').map(item => item.relation), ['data-write']);
		assert.deepStrictEqual(graph.findTypeUses('type:context').map(item => item.edgeId).sort(), [member.edgeId, typeUse.edgeId].sort());
		assert.deepStrictEqual(graph.findMemberUses('member:context:flags').map(item => item.edgeId), [member.edgeId]);
		assert.deepStrictEqual(graph.query({ address: '0x140060000', direction: 'incoming' }).map(item => item.edgeId), [importUse.edgeId]);
		assert.strictEqual(graph.query({ families: ['string'] })[0].edgeId, stringUse.edgeId);
		assert.strictEqual(graph.query({ targetKind: 'import' })[0].edgeId, importUse.edgeId);
		assert.strictEqual(graph.exportSnapshot().analysisTargetIdentity, targetIdentity);
		assert.strictEqual(graph.exportHash().length, 64);

		const tables = db.prepare(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`).all()
			.map(row => String((row as { name: unknown }).name));
		for (const table of ['reference_edges', 'reference_edge_dependencies', 'reference_edge_versions', 'reference_edge_conflicts']) {
			assert.ok(tables.includes(table));
		}
		store.dispose();
	});

	test('keeps every indirect candidate qualified and exposes deterministic bounded path search', () => {
		const sqlite = loadNativeSqlite();
		const store = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const graph = store.getReferenceGraph();
		const candidateBase = {
			relation: 'code-indirect-candidate' as const,
			indirectResolution: {
				status: 'candidate' as const,
				candidateSetId: 'candidate-set:dispatch:0',
				source: 'vtable' as const,
				reason: 'slot 3 of the recovered Context vtable',
			},
		};
		const first = canonicalizeReferenceEdge(edge({
			...candidateBase,
			target: { kind: 'function', identity: 'function:B', address: '0x140002000' },
		}));
		const second = canonicalizeReferenceEdge(edge({
			...candidateBase,
			target: { kind: 'function', identity: 'function:C', address: '0x140003000' },
		}));
		const resolved = canonicalizeReferenceEdge(edge({
			relation: 'code-indirect-resolved',
			source: { ...edge().source, address: '0x140002010' },
			target: { kind: 'function', identity: 'function:D', address: '0x140004000' },
			provenance: { sourceEngine: 'hexcore-dataflow', evidenceAddress: '0x140002010' },
			indirectResolution: {
				status: 'resolved', candidateSetId: 'candidate-set:dispatch:1', source: 'points-to-set',
				reason: 'singleton points-to set after prototype propagation',
			},
		}));
		const bToD = canonicalizeReferenceEdge(edge({
			source: { address: '0x140002010', ownerFunctionIdentity: 'function:B', basicBlockIdentity: 'basic-block:B:0', operandIndex: 0 },
			target: { kind: 'function', identity: 'function:D', address: '0x140004000' },
			provenance: { sourceEngine: 'hexcore-capstone', evidenceAddress: '0x140002010' },
		}));
		const candidateWrite = graph.writeIndirectCandidateSet([second, first], 2);
		assert.strictEqual(candidateWrite.results.length, 2);
		graph.writeBatch([resolved, bToD]);
		assert.throws(() => graph.writeIndirectCandidateSet([first, second], 1), /exceeds its explicit budget/);
		const candidates = graph.listIndirectCandidates('candidate-set:dispatch:0');
		assert.strictEqual(candidates.length, 2, 'candidate alternatives must remain separate edges');
		assert.notStrictEqual(candidates[0].edgeId, candidates[1].edgeId);
		assert.ok(candidates.every(item => item.indirectResolution?.reason.includes('vtable')));
		assert.strictEqual(graph.getCallees('function:0x140001000').length, 1, 'unresolved candidates are excluded by default');
		assert.strictEqual(graph.getCallees('function:0x140001000', true).length, 3);

		const paths = graph.findPaths({
			startIdentity: 'function:0x140001000', goalIdentity: 'function:D', maxDepth: 3, maxPaths: 10,
			filter: { families: ['code'] },
		});
		assert.deepStrictEqual(paths.map(item => item.nodes), [
			['function:0x140001000', 'function:D'],
			['function:0x140001000', 'function:B', 'function:D'],
		]);
		assert.throws(() => graph.findPaths({
			startIdentity: 'a', goalIdentity: 'b', maxDepth: 65, maxPaths: 1,
		}), /between 1 and 64/);
		assert.throws(() => graph.findPaths({
			startIdentity: 'function:0x140001000', goalIdentity: 'missing', maxDepth: 3, maxPaths: 10,
			maxVisitedStates: 1,
		}), /exceeded its explicit state budget/);
		store.dispose();
	});

	test('merges corroborating provenance without false conflicts and retains real semantic conflicts', () => {
		const sqlite = loadNativeSqlite();
		const store = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const graph = store.getReferenceGraph();
		const first = graph.putEdge(edge());
		const corroborated = graph.putEdge(edge({
			provenance: { sourceEngine: 'hexcore-remill', sourceEngineVersion: '7', evidenceAddress: '0x140001010' },
			evidence: evidence(1, 'remill:fixture'),
		}));
		assert.strictEqual(corroborated.accepted.edgeId, first.accepted.edgeId);
		assert.strictEqual(corroborated.conflict, undefined);
		assert.strictEqual(corroborated.accepted.evidenceSet.length, 2);
		assert.strictEqual(corroborated.accepted.provenanceSet.length, 2);
		assert.strictEqual(graph.listConflicts().length, 0);

		const weakWidth = edge({
			relation: 'data-read',
			target: { kind: 'global', identity: 'global:width-test', address: '0x140070000' },
			accessWidthBits: 32,
		});
		const strongWidth = edge({
			...weakWidth,
			accessWidthBits: 64,
			evidence: evidence(2, 'pdb:fixture', 'debug'),
			provenance: { sourceEngine: 'hexcore-pdb', evidenceAddress: '0x140001010' },
		});
		const weak = graph.putEdge(weakWidth);
		const strong = graph.putEdge(strongWidth);
		assert.strictEqual(weak.accepted.edgeId, strong.accepted.edgeId);
		assert.strictEqual(strong.status, 'replaced-stronger');
		assert.strictEqual(strong.accepted.accessWidthBits, 64);
		assert.strictEqual(graph.listConflicts().length, 1);
		store.dispose();
	});

	test('re-observes one semantic edge across generations with one active dependency and version history', () => {
		const sqlite = loadNativeSqlite();
		const store = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const graph = store.getReferenceGraph();
		const first = canonicalizeReferenceEdge(edge({
			evidence: evidence(1, 'r33:generation-1'),
			invalidationDependencies: [
				{ kind: 'analysis-generation', key: 'disassembler-analysis', generation: 1 },
				{ kind: 'function-body', key: 'function:0x140001000', generation: 1, contentSha256: 'c'.repeat(64) },
			],
		}));
		graph.putEdge(first);
		const second = canonicalizeReferenceEdge(edge({
			evidence: evidence(2, 'r33:generation-2'),
			invalidationDependencies: [
				{ kind: 'analysis-generation', key: 'disassembler-analysis', generation: 2 },
				{ kind: 'function-body', key: 'function:0x140001000', generation: 2, contentSha256: 'd'.repeat(64) },
			],
		}));
		const updated = graph.putEdge(second);
		assert.strictEqual(updated.accepted.edgeId, first.edgeId);
		assert.strictEqual(updated.accepted.generation, 2);
		assert.deepStrictEqual(updated.accepted.invalidationDependencies, second.invalidationDependencies);
		assert.strictEqual(graph.listStoredEdges().filter(item => item.edge.edgeId === first.edgeId).length, 1);
		const versions = graph.listVersions().filter(item => item.edgeId === first.edgeId);
		assert.strictEqual(versions.length, 2);
		assert.deepStrictEqual(versions.map(item => item.generation), [1, 2]);
		store.dispose();
	});

	test('tracks dependency invalidation, analyst-owned survival, stale rejection, reactivation, and generation diffs', () => {
		const sqlite = loadNativeSqlite();
		const store = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const graph = store.getReferenceGraph();
		const derived = canonicalizeReferenceEdge(edge({
			relation: 'data-read',
			target: { kind: 'global', identity: 'global:state', address: '0x140070000' },
			accessWidthBits: 32,
			invalidationDependencies: [{ kind: 'function-body', key: 'function:0x140001000', generation: 1 }],
		}));
		const analyst = canonicalizeReferenceEdge(edge({
			source: { ...edge().source, address: '0x140001018', operandIndex: 1 },
			target: { kind: 'function', identity: 'function:analyst', address: '0x140009000' },
			evidence: evidence(1, 'analyst:manual-xref', 'definitive'),
			invalidationDependencies: [{ kind: 'user-override', key: 'xref:manual' }],
		}));
		graph.writeBatch([analyst, derived]);
		assert.strictEqual(graph.invalidateByDependency(
			'function-body', 'function:0x140001000', 2, 'function body changed',
		), 1);
		assert.strictEqual(graph.getEdge(derived.edgeId)?.active, false);
		assert.strictEqual(graph.getEdge(analyst.edgeId)?.active, true);
		assert.strictEqual(graph.invalidateAllDerived(2, 'whole target reanalysis'), 0);

		const addedAtTwo = canonicalizeReferenceEdge(edge({
			source: { ...edge().source, address: '0x140001020', operandIndex: 2 },
			target: { kind: 'function', identity: 'function:new', address: '0x14000a000' },
			evidence: evidence(2),
		}));
		graph.putEdge(addedAtTwo);
		const diff12 = graph.diffGenerations(1, 2);
		assert.deepStrictEqual(diff12.added.map(item => item.edgeId), [addedAtTwo.edgeId]);
		assert.deepStrictEqual(diff12.removed.map(item => item.edgeId), [derived.edgeId]);
		assert.strictEqual(diff12.changed.length, 0);
		assert.strictEqual(diff12.diffHash.length, 64);

		const stale = graph.putEdge(edge({
			...derived,
			evidence: evidence(2, 'stale:rerun'),
		}));
		assert.strictEqual(stale.status, 'rejected-stale');
		const reactivated = graph.putEdge(edge({
			...derived,
			evidence: evidence(3, 'fresh:reanalysis'),
			invalidationDependencies: [{ kind: 'function-body', key: 'function:0x140001000', generation: 3 }],
		}));
		assert.strictEqual(reactivated.status, 'reactivated');
		assert.strictEqual(graph.getEdge(derived.edgeId)?.active, true);
		assert.deepStrictEqual(graph.diffGenerations(2, 3).added.map(item => item.edgeId), [derived.edgeId]);
		assert.deepStrictEqual(graph.snapshotAtGeneration(1).map(item => item.edgeId).sort(), [analyst.edgeId, derived.edgeId].sort());
		store.dispose();
	});

	test('reopens with identical hashes and is independent of batch insertion order', () => {
		const sqlite = loadNativeSqlite();
		const dbPath = path.join(tempDir, 'reference-roundtrip.hxdb');
		const firstEdge = canonicalizeReferenceEdge(edge());
		const secondEdge = canonicalizeReferenceEdge(edge({
			source: { ...edge().source, address: '0x140001020', operandIndex: 1 },
			target: { kind: 'string', identity: 'string:hello', address: '0x140080000' },
			relation: 'string-reference',
			provenance: { sourceEngine: 'hexcore-strings', evidenceAddress: '0x140001020' },
		}));
		const persistent = SemanticStore.open(dbPath, targetIdentity, sqlite);
		persistent.getReferenceGraph().writeBatch([secondEdge, firstEdge]);
		const graphHash = persistent.getReferenceGraph().exportHash();
		const semanticHash = persistent.exportHash();
		persistent.dispose();

		const reopened = SemanticStore.open(dbPath, targetIdentity, sqlite);
		assert.strictEqual(reopened.getReferenceGraph().exportHash(), graphHash);
		assert.strictEqual(reopened.exportHash(), semanticHash);
		assert.strictEqual(reopened.getReferenceGraph().putEdge(firstEdge).changed, false);
		assert.strictEqual(reopened.getReferenceGraph().exportHash(), graphHash);
		reopened.dispose();

		const left = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const right = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const leftResult = left.getReferenceGraph().writeBatch([firstEdge, secondEdge]);
		const rightResult = right.getReferenceGraph().writeBatch([secondEdge, firstEdge]);
		assert.strictEqual(leftResult.transactionHash, rightResult.transactionHash);
		assert.strictEqual(left.getReferenceGraph().exportCanonical(), right.getReferenceGraph().exportCanonical());
		left.dispose();
		right.dispose();
	});

	test('fails closed on malformed relations, lossy widths, wrong targets, duplicate logical edges, and corrupt storage', () => {
		assert.throws(() => canonicalizeReferenceEdge(edge({
			relation: 'data-read', accessWidthBits: null,
		})), /requires a positive access width/);
		assert.throws(() => canonicalizeReferenceEdge(edge({
			relation: 'string-reference', target: { kind: 'global', identity: 'global:not-a-string' },
		})), /must target a string/);
		assert.throws(() => canonicalizeReferenceEdge(edge({
			relation: 'code-indirect-candidate',
		})), /requires explicit candidate provenance/);
		assert.throws(() => canonicalizeReferenceEdge(edge({
			source: { ...edge().source, operandIndex: Number.MAX_SAFE_INTEGER + 1 },
		})), /safe integer/);
		assert.throws(() => canonicalizeReferenceEdge(edge({
			relation: 'unknown-relation' as ReferenceRelationKind,
		})), /unknown reference relation/i);

		const sqlite = loadNativeSqlite();
		const store = new SemanticStore(sqlite.openDatabase(':memory:'), targetIdentity);
		const graph = store.getReferenceGraph();
		assert.throws(() => graph.putEdge(edge({
			analysisTargetIdentity: `target:sha256:${'f'.repeat(64)}`,
		})), /target mismatch/);
		assert.throws(() => graph.writeBatch([edge(), edge()]), /duplicate logical edges/);
		const stored = graph.putEdge(edge()).accepted;
		(store as unknown as { db: SemanticSqliteDatabase }).db.prepare(`
			UPDATE reference_edges SET record_json = '{}' WHERE analysis_target_identity = ? AND edge_id = ?
		`).run(targetIdentity, stored.edgeId);
		assert.throws(() => graph.getEdge(stored.edgeId), /record hash does not match/);
		store.dispose();

		const badDb = sqlite.openDatabase(':memory:');
		badDb.exec(`
			CREATE TABLE hxdb_meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);
			INSERT INTO hxdb_meta(key, value) VALUES ('target_identity', '${targetIdentity}');
			CREATE TABLE reference_edges(edge_id TEXT PRIMARY KEY);
		`);
		assert.throws(() => new TypedReferenceGraph(badDb, targetIdentity), /table reference_edges is incompatible/);
		badDb.close?.();
	});

	test('SessionStore invalidates derived graph state while preserving analyst references', () => {
		const binaryPath = path.join(tempDir, 'target.bin');
		fs.writeFileSync(binaryPath, Buffer.from([1, 2, 3, 4]));
		const session = new SessionStore(binaryPath);
		session.bindAnalysisTarget({
			filePath: binaryPath, fileSize: 4, format: 'raw', architecture: 'x64', imageBase: '0x400000',
		});
		const graph = session.getSemanticStore().getReferenceGraph();
		const currentGeneration = session.getAnalysisSession()!.generation;
		const derived = canonicalizeReferenceEdge(edge({
			analysisTargetIdentity: graph.analysisTargetIdentity,
			evidence: evidence(currentGeneration),
		}));
		const analyst = canonicalizeReferenceEdge(edge({
			analysisTargetIdentity: graph.analysisTargetIdentity,
			source: { ...edge().source, address: '0x140001018', operandIndex: 1 },
			target: { kind: 'function', identity: 'function:manual', address: '0x140009000' },
			evidence: evidence(currentGeneration, 'analyst:manual', 'definitive'),
		}));
		graph.writeBatch([analyst, derived]);
		const selective = session.invalidateFunction('0x140001000');
		assert.strictEqual(selective.invalidatedReferenceEdges, 1);
		assert.strictEqual(graph.getEdge(derived.edgeId)?.active, false);
		assert.strictEqual(graph.getEdge(analyst.edgeId)?.active, true);

		const newDerived = canonicalizeReferenceEdge(edge({
			analysisTargetIdentity: graph.analysisTargetIdentity,
			source: { ...edge().source, address: '0x140001020', operandIndex: 2 },
			target: { kind: 'function', identity: 'function:new-derived', address: '0x14000a000' },
			evidence: evidence(currentGeneration),
		}));
		graph.putEdge(newDerived);
		const next = session.startReanalysis();
		assert.strictEqual(next.generation, currentGeneration + 1);
		assert.strictEqual(graph.getEdge(newDerived.edgeId)?.active, false);
		assert.strictEqual(graph.getEdge(analyst.edgeId)?.active, true);
		session.dispose();
	});
});
