/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import { SessionStore } from './sessionStore';
import { canonicalSerialize, canonicalizeSemanticType } from './semanticModel';
import { openSemanticQueryView } from './semanticQueryView';
import { createHqlSnapshotReader, preserveHqlFunctionFindings } from './hqlScanner';
import { explainSemanticEntity, propagationEffectIdentity } from './semanticExplanation';
import { runSemanticExplainCommand } from './semanticExplainCommand';

suite('pinned semantic explanation contract', () => {
	let directory: string;
	let file: string;
	let session: SessionStore;
	let identities: { prototype: string; binding: string; reference: string; effect: string; conflict: string };
	setup(() => {
		directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-semantic-explain-'));
		file = path.join(directory, 'fixture.bin'); fs.writeFileSync(file, Buffer.from([0xc3]));
		session = new SessionStore(file); session.bindAnalysisTarget({ filePath: file, fileSize: 1, format: 'raw', architecture: 'x64', imageBase: '0x1000' });
		const store = session.getSemanticStore(); const target = store.targetIdentity;
		const debug = { strength: 'debug' as const, source: 'debug-info' as const, producer: 'dwarf-fixture', generation: 0 };
		const definitive = { strength: 'definitive' as const, source: 'analyst' as const, producer: 'analyst-fixture', generation: 0, userDefined: true };
		const derived = { strength: 'derived' as const, source: 'dataflow' as const, producer: 'propagation-fixture', generation: 0 };
		const i32 = canonicalizeSemanticType({ kind: 'integer', name: 'int32_t', sizeBits: 32, signed: true }, debug); store.putType(i32);
		const i64 = canonicalizeSemanticType({ kind: 'integer', name: 'int64_t', sizeBits: 64, signed: true }, definitive); store.putType(i64);
		const prototype = store.putPrototype({ targetIdentity: target, functionIdentity: 'function:0x1000', functionAddress: '0x1000', callingConventionId: 'win64', returnTypeId: i32.typeId, parameters: [], evidence: debug }).accepted;
		const first = store.putTypeBinding({ targetIdentity: target, scope: 'local', functionIdentity: 'function:0x1000', valueIdentity: 'value:counter', typeId: i32.typeId, invalidationDependencies: ['function-body:function:0x1000'], evidence: debug }).accepted;
		const binding = store.putTypeBinding({ targetIdentity: target, scope: 'local', functionIdentity: 'function:0x1000', valueIdentity: 'value:counter', typeId: i64.typeId, invalidationDependencies: ['function-body:function:0x1000'], evidence: definitive }).accepted;
		assert.strictEqual(binding.bindingId, first.bindingId);
		const reference = store.getReferenceGraph().putEdge({ analysisTargetIdentity: target, relation: 'data-write', source: { address: '0x1010', ownerFunctionIdentity: 'function:0x1000', basicBlockIdentity: 'block:0x1000:0x1010', operandIndex: 0 },
			target: { kind: 'global', identity: 'global:counter', address: '0x2000' }, accessWidthBits: 32,
			provenance: { sourceEngine: 'capstone-fixture', sourceEngineVersion: '5', sourceArtifactSha256: 'd'.repeat(64), evidenceAddress: '0x1010' }, evidence: derived,
			invalidationDependencies: [{ kind: 'function-body', key: 'function:0x1000', generation: 0, contentSha256: 'e'.repeat(64) }] }).accepted;
		const effect = { kind: 'free', value: { kind: 'register', identity: 'value:counter', functionIdentity: 'function:0x1000', evidence: derived }, objectIdentity: 'object:counter' };
		const summary = { schemaVersion: 1, analysisTargetIdentity: target, functionIdentity: 'function:0x1000', functionBodySha256: 'a'.repeat(64), generation: 0,
			parameterEffects: [], returnRelationships: [], calls: [], globalEffects: [], ownershipEffects: [effect, { ...effect, objectIdentity: 'object:second', value: { ...effect.value, identity: 'value:second' } }], fieldAccesses: [], functionPointerTargets: [],
			barriers: [{ identity: 'barrier:loss', reason: 'incomplete alias', lossy: true }], dependencies: ['function:0x2000'], referenceEdgeHashes: [reference.canonicalHash], valueFacts: [], conflicts: [], inputHash: 'b'.repeat(64), outputHash: 'c'.repeat(64) };
		(session as any).db.prepare('INSERT INTO propagation_summaries (analysis_target_identity,function_identity,generation,input_hash,output_hash,record_json) VALUES (?,?,?,?,?,?)').run(target, summary.functionIdentity, 0, summary.inputHash, summary.outputHash, JSON.stringify(summary));
		const view = openSemanticQueryView(session);
		identities = { prototype: prototype.prototypeId, binding: binding.bindingId, reference: reference.edgeId,
			effect: propagationEffectIdentity(summary.functionIdentity, summary.generation, 'ownership', effect), conflict: view.exportSnapshot().data.conflicts[0].conflictHash };
	});
	teardown(() => { session.dispose(); fs.rmSync(directory, { recursive: true, force: true }); });
	test('direct debug prototype explains function, type and evidence', () => {
		const result = explainSemanticEntity(openSemanticQueryView(session), { kind: 'prototype', identity: identities.prototype });
		assert.strictEqual(result.status, 'ok', JSON.stringify(result)); assert.strictEqual(result.claim?.proofStatus, 'proven');
		assert.ok(result.nodes.some(node => node.kind === 'evidence' && (node.data as any).producer === 'dwarf-fixture'));
		assert.ok(result.evidenceChain.some(item => item.producer === 'dwarf-fixture' && item.strength === 'debug'));
		assert.deepStrictEqual(result.navigation, [{ functionIdentity: 'function:0x1000', address: '0x1000' }]);
		assert.ok(result.edges.some(edge => edge.relation === 'returns'));
	});
	test('conflicting binding remains partial and exposes arbitration record', () => {
		const result = explainSemanticEntity(openSemanticQueryView(session), { kind: 'type-binding', identity: identities.binding });
		assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.claim?.proofStatus, 'proven');
		assert.strictEqual(result.conflicts.length, 1); assert.ok(result.missingLinks.some(item => item.includes('conflict')));
		assert.ok(result.nodes.some(node => node.kind === 'invalidation-dependency'));
	});
	test('typed reference keeps decoder provenance and source navigation', () => {
		const result = explainSemanticEntity(openSemanticQueryView(session), { kind: 'typed-reference', identity: identities.reference });
		assert.strictEqual(result.status, 'ok', JSON.stringify(result)); assert.strictEqual(result.claim?.proofStatus, 'candidate');
		assert.ok(result.nodes.some(node => node.kind === 'reference-origin' && (node.data as any).sourceEngine === 'capstone-fixture'));
		assert.ok(result.nodes.some(node => node.id === 'global:counter'));
		assert.deepStrictEqual(result.navigation, [{ functionIdentity: 'function:0x1000', address: '0x1010' }]);
	});
	test('derived ownership effect stops honestly at a lossy barrier', () => {
		const result = explainSemanticEntity(openSemanticQueryView(session), { kind: 'propagation-effect', identity: identities.effect });
		assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.claim?.proofStatus, 'candidate');
		assert.strictEqual(result.barriers.length, 1); assert.ok(result.missingLinks.some(item => item.includes('lossy propagation barrier')));
		assert.ok(result.nodes.some(node => node.id === identities.reference)); assert.ok(result.navigation.some(item => item.functionIdentity === 'function:0x2000'));
	});
	test('semantic conflict is an explicit signal, never a resolved proof', () => {
		const result = explainSemanticEntity(openSemanticQueryView(session), { kind: 'semantic-conflict', identity: identities.conflict });
		assert.strictEqual(result.status, 'partial'); assert.strictEqual(result.claim?.proofStatus, 'signal'); assert.strictEqual(result.conflicts.length, 1);
	});
	test('HQL semantic matches carry resolvable exact snapshot identities', () => {
		const view = openSemanticQueryView(session);
		const facts = createHqlSnapshotReader(view).getSemanticFacts('0x1000') as any[];
		const prototype = facts.find(fact => fact.kind === 'function-prototype'); assert.ok(prototype.explainIdentity);
		const explained = explainSemanticEntity(view, { kind: 'hql-semantic-match', identity: prototype.explainIdentity });
		assert.strictEqual(explained.status, 'ok'); assert.strictEqual(explained.request.kind, 'hql-semantic-match'); assert.strictEqual(explained.claim?.id, identities.prototype);
		const ownership = facts.find(fact => fact.kind === 'summary-ownership');
		const summary = explainSemanticEntity(view, { kind: 'hql-semantic-match', identity: ownership.explainIdentity });
		assert.strictEqual(summary.status, 'partial');
		assert.strictEqual(summary.claim?.proofStatus, 'candidate');
		assert.strictEqual((summary.claim?.data as any).objectIdentity, 'object:counter');
		assert.ok(summary.missingLinks.some(item => item.includes('lossy propagation barrier')));
		assert.ok(!summary.missingLinks.some(item => item.includes('match-specific')));
		const legacy = explainSemanticEntity(view, { kind: 'hql-semantic-match', identity: ownership.explainIdentity.split(':effect:')[0] });
		assert.strictEqual(legacy.status, 'partial');
		assert.ok(legacy.missingLinks.some(item => item.includes('match-specific')));
	});
	test('persisted HQL identities distinguish effects and reject fabricated suffixes', () => {
		const view = openSemanticQueryView(session);
		const facts = createHqlSnapshotReader(view).getSemanticFacts('0x1000') as any[];
		const ownership = facts.filter(fact => fact.kind === 'summary-ownership');
		assert.strictEqual(ownership.length, 2);
		assert.notStrictEqual(ownership[0].explainIdentity, ownership[1].explainIdentity);
		assert.strictEqual(ownership[0].origin.recordSha256, ownership[1].origin.recordSha256);
		const persisted = JSON.parse(JSON.stringify(ownership));
		const before = persisted.map((fact: any) => explainSemanticEntity(view, { kind: 'hql-semantic-match', identity: fact.explainIdentity }));
		assert.deepStrictEqual(before.map((item: any) => item.claim.data.objectIdentity).sort(), ['object:counter', 'object:second']);
		const forged = persisted[0].explainIdentity.replace(/[a-f0-9]{64}$/, '0'.repeat(64));
		const rejected = explainSemanticEntity(view, { kind: 'hql-semantic-match', identity: forged });
		assert.strictEqual(rejected.claim, null);
		assert.strictEqual(rejected.status, 'unknown');
		assert.ok(rejected.missingLinks.some(item => item.includes('selected summary')));
		session.dispose(); session = new SessionStore(file);
		session.bindAnalysisTarget({ filePath: file, fileSize: 1, format: 'raw', architecture: 'x64', imageBase: '0x1000' });
		const reopened = openSemanticQueryView(session);
		for (let i = 0; i < persisted.length; i++) {
			const after = explainSemanticEntity(reopened, { kind: 'hql-semantic-match', identity: persisted[i].explainIdentity });
			assert.strictEqual(after.explanationSha256, before[i].explanationSha256);
			assert.deepStrictEqual(after.claim, before[i].claim);
		}
	});
	test('wrong snapshot and missing entity are not fabricated', () => {
		const view = openSemanticQueryView(session);
		const wrong = explainSemanticEntity(view, { kind: 'prototype', identity: identities.prototype, expected: { snapshotSha256: '0'.repeat(64) } });
		assert.strictEqual(wrong.status, 'error'); assert.strictEqual(wrong.success, false);
		const missing = explainSemanticEntity(view, { kind: 'prototype', identity: 'prototype:missing' });
		assert.strictEqual(missing.status, 'unknown'); assert.strictEqual(missing.claim, null); assert.ok(missing.missingLinks.length);
	});
	test('real HQL scan artifact replays exact effects after database reopen', () => {
		const hqlRoot = path.resolve(__dirname, '..', '..', 'hexcore-hql');
		const hql = require(hqlRoot);
		const astBuffer = fs.readFileSync(path.join(hqlRoot, 'test', 'fixtures', 'semantic-quality-v1_1.fb'));
		const address = '0xfedcba9876543210';
		const scanDirectory = path.join(directory, 'scan');
		fs.mkdirSync(scanDirectory);
		const binary = path.join(scanDirectory, 'scan-fixture.bin');
		fs.writeFileSync(binary, Buffer.from([0]));
		let scanSession = new SessionStore(binary);
		const bind = () => scanSession.bindAnalysisTarget({ filePath: binary, fileSize: 1, format: 'raw', architecture: 'arm64', imageBase: address });
		try {
			bind();
			const target = scanSession.getSemanticStore().targetIdentity;
			const functionIdentity = `function:${address}`;
			const evidence = { strength: 'derived', source: 'dataflow', producer: 'scan-fixture', generation: 0 };
			const ownershipEffects = ['first', 'second'].map(name => ({ kind: 'free', objectIdentity: `object:${name}`,
				value: { kind: 'register', identity: `value:${name}`, functionIdentity, evidence } }));
			const summary = { schemaVersion: 1, analysisTargetIdentity: target, functionIdentity, functionBodySha256: 'a'.repeat(64), generation: 0,
				parameterEffects: [], returnRelationships: [], calls: [], globalEffects: [], ownershipEffects, fieldAccesses: [], functionPointerTargets: [],
				barriers: [], dependencies: [], referenceEdgeHashes: [], valueFacts: [], conflicts: [], inputHash: 'b'.repeat(64), outputHash: 'c'.repeat(64) };
			(scanSession as any).db.prepare('INSERT INTO propagation_summaries (analysis_target_identity,function_identity,generation,input_hash,output_hash,record_json) VALUES (?,?,?,?,?,?)')
				.run(target, functionIdentity, 0, summary.inputHash, summary.outputHash, JSON.stringify(summary));
			const view = openSemanticQueryView(scanSession);
			const revision = scanSession.getSemanticReadRevision();
			const signatures = [{ id: 'test.exact-summary-effect', name: 'Exact summary effect', description: 'Synthetic contract fixture', severity: 'info',
				condition: { query: { node: 'CFunctionDecl' } }, semanticCondition: { fact: { fact: 'summary-ownership' } } }];
			const scanned = hql.scanHAST(astBuffer, signatures, createHqlSnapshotReader(view), { semanticSnapshotSha256: view.identity.snapshotSha256 });
			const artifact = path.join(directory, 'saved-scan.json');
			const mapped = preserveHqlFunctionFindings(scanned, address, address);
			fs.writeFileSync(artifact, JSON.stringify(mapped));
			assert.strictEqual(scanSession.getSemanticReadRevision(), revision);
			scanSession.dispose(); scanSession = new SessionStore(binary); bind();
			const saved = JSON.parse(fs.readFileSync(artifact, 'utf8'));
			const findings = saved.flatMap((item: any) => item.findings).filter((item: any) => item.signatureId === signatures[0].id);
			assert.strictEqual(findings.length, 1, JSON.stringify(saved));
			const matches = findings[0].semanticMatches;
			assert.strictEqual(matches.length, 2);
			assert.notStrictEqual(matches[0].explainIdentity, matches[1].explainIdentity);
			const reopened = openSemanticQueryView(scanSession);
			const explanations = matches.map((match: any) => explainSemanticEntity(reopened, { kind: 'hql-semantic-match', identity: match.explainIdentity }));
			assert.deepStrictEqual(explanations.map((item: any) => item.claim?.data.objectIdentity).sort(), ['object:first', 'object:second']);
			assert.ok(explanations.every((item: any) => item.claim?.proofStatus === 'candidate'));
		} finally { scanSession.dispose(); }
	});
	test('logical hash is deterministic across reopen and ignores engine observation', () => {
		const first = explainSemanticEntity(openSemanticQueryView(session, { engineGeneration: 3 }), { kind: 'prototype', identity: identities.prototype });
		const second = explainSemanticEntity(openSemanticQueryView(session, { engineGeneration: 9 }), { kind: 'prototype', identity: identities.prototype });
		assert.strictEqual(first.explanationSha256, second.explanationSha256);
		session.dispose(); session = new SessionStore(file); session.bindAnalysisTarget({ filePath: file, fileSize: 1, format: 'raw', architecture: 'x64', imageBase: '0x1000' });
		const reopened = explainSemanticEntity(openSemanticQueryView(session), { kind: 'prototype', identity: identities.prototype });
		assert.strictEqual(reopened.explanationSha256, first.explanationSha256); assert.deepStrictEqual(reopened.nodes, first.nodes);
		const { explanationSha256: _hash, identity, ...rest } = first;
		const { engineGeneration: _engine, ...logicalIdentity } = identity;
		assert.strictEqual(crypto.createHash('sha256').update(canonicalSerialize({ ...rest, identity: logicalIdentity })).digest('hex'), first.explanationSha256);
	});
	test('node and byte budgets are explicit and deterministic', () => {
		const view = openSemanticQueryView(session);
		const limited = explainSemanticEntity(view, { kind: 'prototype', identity: identities.prototype, maxNodes: 1 });
		assert.strictEqual(limited.status, 'partial'); assert.strictEqual(limited.truncated, true); assert.ok(limited.missingLinks.some(item => item.includes('budget')));
		const bytes = explainSemanticEntity(view, { kind: 'prototype', identity: identities.prototype, maxBytes: 4096 });
		assert.ok(Buffer.byteLength(JSON.stringify(bytes)) <= 4096); assert.strictEqual(bytes.status, 'partial'); assert.strictEqual(bytes.truncated, true);
		assert.strictEqual(explainSemanticEntity(view, { kind: 'prototype', identity: identities.prototype, maxBytes: 1 }).status, 'error');
	});
	test('headless adapter exposes the exact same contract and pinned top-level identity', () => {
		const engine = { isFileLoaded: () => true, getSessionStore: () => session, getAnalysisGeneration: () => 4 } as any;
		const view = openSemanticQueryView(session, { engineGeneration: 4 });
		const direct = explainSemanticEntity(view, { kind: 'prototype', identity: identities.prototype, expected: { snapshotSha256: view.identity.snapshotSha256 } });
		const command: any = runSemanticExplainCommand(engine, { kind: 'prototype', identity: identities.prototype, expected: { snapshotSha256: view.identity.snapshotSha256 } });
		assert.deepStrictEqual(command.nodes, direct.nodes); assert.deepStrictEqual(command.edges, direct.edges);
		assert.strictEqual(command.explanationSha256, direct.explanationSha256);
		assert.strictEqual(command.targetIdentity, direct.identity.targetIdentity); assert.strictEqual(command.command, 'hexcore.semantic.explain');
		const stale: any = runSemanticExplainCommand(engine, { kind: 'prototype', identity: identities.prototype, snapshotSha256: '0'.repeat(64) });
		assert.strictEqual(stale.status, 'error'); assert.strictEqual(stale.success, false);
		const absent: any = runSemanticExplainCommand({ isFileLoaded: () => false, getSessionStore: () => undefined } as any, {});
		assert.strictEqual(absent.status, 'error'); assert.strictEqual(absent.success, false);
	});
});
