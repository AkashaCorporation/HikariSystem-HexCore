/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import {
	SEMANTIC_SCHEMA_VERSION,
	PrototypeRegistry,
	SemanticTypeCatalog,
	TypeBindingRegistry,
	assessPrototypeRecovery,
	arbitrateSemanticValue,
	canonicalSerialize,
	canonicalizeFunctionPrototype,
	canonicalizePrototypeRecoveryObservation,
	canonicalizeSemanticType,
	canonicalizeTypeBinding,
	createOpaqueCDeclaration,
	createUsercallABI,
	classifyAggregateReturn,
	getABIModel,
	listABIModels,
	normalizeSemanticEvidence,
	parseLegacyCType,
	resolveArchitectureDefaultABI,
	type CallingConventionId,
	type EvidenceStrength,
	type FunctionPrototypeSpec,
	type SemanticEvidence,
	type SemanticTypeKind,
} from './semanticModel';

function evidence(
	strength: EvidenceStrength = 'derived',
	generation = 1,
	producer = 'semantic-model-test',
): SemanticEvidence {
	return { strength, source: strength === 'definitive' ? 'analyst' : 'dataflow', producer, generation };
}

suite('HXDB semantic model R31/R32', () => {
	test('canonical JSON is key-order independent and preserves exact bigint values', () => {
		const left = canonicalSerialize({ z: 1, a: { y: 2n, x: -0 }, omitted: undefined });
		const right = canonicalSerialize({ a: { x: 0, y: '2' }, z: 1 });
		assert.strictEqual(left, right);
		assert.strictEqual(left, '{"a":{"x":0,"y":"2"},"z":1}');
	});

	test('evidence requires a producer, generation, and calibration before confidence', () => {
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'signature', source: 'signature', producer: 'rule', generation: 1, confidence: 0.9,
		}), /requires explicit calibration/);
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'derived', source: 'dataflow', producer: '', generation: 1,
		}), /must not be empty/);
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'derived', source: 'dataflow', producer: 'pass', generation: -1,
		}), /non-negative/);
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'derived', source: 'invented-source' as never, producer: 'pass', generation: 1,
		}), /Unknown evidence source/);
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'signature', source: 'signature', producer: 'empty-calibration', generation: 1, confidence: 1,
			calibration: { corpus: 'empty', positiveSamples: 0, negativeSamples: 0 },
		}), /at least one positive and one negative/);
		const calibrated = normalizeSemanticEvidence({
			strength: 'signature', source: 'signature', producer: 'atlas:test', generation: 7, confidence: 0.75,
			calibration: { corpus: 'fixture-v1', positiveSamples: 12, negativeSamples: 8 },
		});
		assert.strictEqual(calibrated.confidence, 0.75);
		assert.strictEqual(calibrated.calibration?.positiveSamples, 12);
	});

	test('canonicalizes every required type kind with explicit dependencies and qualifiers', () => {
		const catalog = new SemanticTypeCatalog('target:sha256:legacy-types', 'cu:legacy-types');
		const ev = evidence('debug', 3, 'dwarf:test');
		const unknown = catalog.intern({ kind: 'unknown' }, ev);
		const voidType = catalog.intern({ kind: 'void', sizeBits: 0 }, ev);
		const boolType = catalog.intern({ kind: 'bool', sizeBits: 8, alignBits: 8 }, ev);
		const intType = catalog.intern({ kind: 'integer', sizeBits: 32, alignBits: 32, signed: true }, ev);
		const floatType = catalog.intern({ kind: 'float', sizeBits: 64, alignBits: 64 }, ev);
		const pointer = catalog.intern({ kind: 'pointer', targetTypeId: intType.typeId, sizeBits: 64, alignBits: 64 }, ev);
		const array = catalog.intern({ kind: 'array', targetTypeId: intType.typeId, count: 4, sizeBits: 128, alignBits: 32 }, ev);
		const vector = catalog.intern({ kind: 'vector', targetTypeId: floatType.typeId, count: 2, sizeBits: 128, alignBits: 128 }, ev);
		const struct = catalog.intern({
			kind: 'struct', name: 'Pair', sizeBits: 64, alignBits: 32,
			members: [
				{ name: 'right', typeId: intType.typeId, bitOffset: 32, evidence: ev },
				{ name: 'left', typeId: intType.typeId, bitOffset: 0, evidence: ev },
			],
		}, ev);
		const union = catalog.intern({
			kind: 'union', name: 'Bits', sizeBits: 32, alignBits: 32,
			members: [{ name: 'u', typeId: intType.typeId, bitOffset: 0 }],
		}, ev);
		const enumType = catalog.intern({
			kind: 'enum', name: 'LargeEnum', sizeBits: 64, alignBits: 64, signed: false,
			enumMembers: [{ name: 'Huge', value: 18_446_744_073_709_551_615n }, { name: 'Zero', value: 0 }],
		}, ev);
		const typedef = catalog.intern({ kind: 'typedef', name: 'PAIR', targetTypeId: struct.typeId }, ev);
		const qualified = catalog.intern({ kind: 'qualified', targetTypeId: pointer.typeId, const: true, volatile: true, restrict: true }, ev);
		const functionType = catalog.intern({
			kind: 'function',
			functionType: { returnTypeId: intType.typeId, parameterTypeIds: [pointer.typeId], callingConventionId: 'win64' },
		}, ev);
		const opaque = catalog.intern({ kind: 'opaque-c-declaration', opaqueDeclaration: 'void (__declspec(foo) *x)(int)' }, ev);

		const expectedKinds: SemanticTypeKind[] = [
			'unknown', 'void', 'bool', 'integer', 'float', 'pointer', 'array', 'vector', 'function',
			'struct', 'union', 'enum', 'typedef', 'qualified', 'opaque-c-declaration',
		];
		assert.deepStrictEqual([...new Set(catalog.list().map(type => type.kind))].sort(), expectedKinds.sort());
		assert.strictEqual(struct.members?.[0].name, 'left');
		assert.ok(struct.dependencies.includes(intType.typeId));
		assert.strictEqual(enumType.enumMembers?.find(member => member.name === 'Huge')?.value, '18446744073709551615');
		assert.deepStrictEqual([qualified.const, qualified.volatile, qualified.restrict], [true, true, true]);
		assert.strictEqual(functionType.functionType?.callingConventionId, 'win64');
		assert.strictEqual(opaque.kind, 'opaque-c-declaration');
		assert.ok([unknown, voidType, boolType, array, vector, union, typedef].every(type => type.typeId.startsWith('type:sha256:')));
	});

	test('type IDs ignore evidence and input member order but change with semantic qualifiers', () => {
		const int32 = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, alignBits: 32, signed: true }, evidence('derived', 1));
		const first = canonicalizeSemanticType({
			kind: 'struct', name: 'Point', members: [
				{ name: 'y', typeId: int32.typeId, bitOffset: 32 },
				{ name: 'x', typeId: int32.typeId, bitOffset: 0 },
			],
		}, evidence('derived', 1));
		const repeat = canonicalizeSemanticType({
			kind: 'struct', name: 'Point', members: [
				{ name: 'x', typeId: int32.typeId, bitOffset: 0 },
				{ name: 'y', typeId: int32.typeId, bitOffset: 32 },
			],
		}, evidence('definitive', 99));
		assert.strictEqual(first.typeId, repeat.typeId);
		assert.strictEqual(first.canonicalSerialization, repeat.canonicalSerialization);

		const plainPointer = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: int32.typeId, sizeBits: 64 }, evidence());
		const constPointer = canonicalizeSemanticType({ kind: 'pointer', targetTypeId: int32.typeId, sizeBits: 64, const: true }, evidence());
		assert.notStrictEqual(plainPointer.typeId, constPointer.typeId);
	});

	test('member, enum, and alias facts retain independent corroborating provenance', () => {
		const catalog = new SemanticTypeCatalog();
		const first = catalog.intern({
			kind: 'struct', name: 'Record',
			members: [{
				name: 'value', typeId: 'type:int', bitOffset: 0,
				evidence: { strength: 'debug', source: 'debug-info', producer: 'pdb:member', generation: 1 },
			}],
			aliases: [{
				name: 'RECORD', targetTypeId: 'type:record',
				evidence: { strength: 'signature', source: 'signature', producer: 'header:alias', generation: 1 },
			}],
		}, evidence('debug', 1, 'pdb:type'));
		const merged = catalog.intern({
			kind: 'struct', name: 'Record',
			members: [{
				name: 'value', typeId: 'type:int', bitOffset: 0,
				evidence: { strength: 'derived', source: 'dataflow', producer: 'access:member', generation: 1 },
			}],
			aliases: [{
				name: 'RECORD', targetTypeId: 'type:record',
				evidence: { strength: 'derived', source: 'migration', producer: 'legacy:alias', generation: 1 },
			}],
		}, evidence('derived', 1, 'layout:record'));
		assert.strictEqual(first.typeId, merged.typeId);
		assert.strictEqual(merged.members?.[0].evidenceSet?.length, 2);
		assert.strictEqual(merged.aliases?.[0].evidenceSet?.length, 2);
		const reinserted = catalog.intern(merged, evidence('signature', 2, 'atlas:record'));
		assert.strictEqual(reinserted.evidenceSet.length, 3);
		assert.ok(reinserted.evidenceSet.some(item => item.producer === 'pdb:type'));
		assert.ok(reinserted.evidenceSet.some(item => item.producer === 'layout:record'));
		assert.ok(reinserted.evidenceSet.some(item => item.producer === 'atlas:record'));

		const enumFirst = catalog.intern({
			kind: 'enum', name: 'State', enumMembers: [{
				name: 'Ready', value: 1,
				evidence: { strength: 'debug', source: 'debug-info', producer: 'dwarf:enum', generation: 1 },
			}],
		}, evidence('debug', 1, 'dwarf:type'));
		const enumMerged = catalog.intern({
			kind: 'enum', name: 'State', enumMembers: [{
				name: 'Ready', value: 1,
				evidence: { strength: 'signature', source: 'signature', producer: 'header:enum', generation: 1 },
			}],
		}, evidence('signature', 1, 'header:type'));
		assert.strictEqual(enumFirst.typeId, enumMerged.typeId);
		assert.strictEqual(enumMerged.enumMembers?.[0].evidenceSet?.length, 2);
	});

	test('rejects malformed compound type shapes instead of inventing a type', () => {
		assert.throws(() => canonicalizeSemanticType({ kind: 'pointer' }, evidence()), /require targetTypeId/);
		assert.throws(() => canonicalizeSemanticType({ kind: 'array', targetTypeId: 'type:x', count: 0 }, evidence()), /positive/);
		assert.throws(() => canonicalizeSemanticType({ kind: 'function' }, evidence()), /functionType/);
		assert.throws(() => canonicalizeSemanticType({ kind: 'opaque-c-declaration' }, evidence()), /original declaration/);
		assert.throws(() => canonicalizeSemanticType({
			kind: 'integer', targetTypeId: 'type:unexpected', sizeBits: 32,
		}, evidence()), /targetTypeId is not valid/);
		assert.throws(() => canonicalizeSemanticType({
			kind: 'struct', members: [{ name: '', typeId: 'type:int', bitOffset: 0 }],
		}, evidence()), /must not have an empty name/);
		assert.doesNotThrow(() => canonicalizeSemanticType({
			kind: 'struct', members: [{ name: '', typeId: 'type:int', bitOffset: 0, anonymous: true }],
		}, evidence()));
	});

	test('parses representative legacy C types and retains qualifier placement', () => {
		const catalog = new SemanticTypeCatalog('target:sha256:legacy-tagged', 'dwarf-cu:0x20');
		const result = catalog.parseLegacyCType('const unsigned long * restrict [3][4]', evidence('derived', 2, 'migration:v1'));
		assert.strictEqual(result.status, 'parsed');
		assert.strictEqual(result.type.kind, 'array');
		assert.strictEqual(result.type.count, 3);
		const innerArray = catalog.get(result.type.targetTypeId ?? '');
		assert.strictEqual(innerArray?.kind, 'array');
		assert.strictEqual(innerArray?.count, 4);
		const pointer = catalog.get(innerArray?.targetTypeId ?? '');
		assert.strictEqual(pointer?.kind, 'pointer');
		assert.strictEqual(pointer?.restrict, true);
		const base = catalog.get(pointer?.targetTypeId ?? '');
		assert.strictEqual(base?.kind, 'integer');
		assert.strictEqual(base?.sizeBits, 32);
		assert.strictEqual(base?.const, true);

		const tagged = catalog.parseLegacyCType('struct Widget * const', evidence());
		assert.strictEqual(tagged.status, 'parsed');
		assert.strictEqual(tagged.type.kind, 'pointer');
		assert.strictEqual(tagged.type.const, true);
		assert.strictEqual(catalog.get(tagged.type.targetTypeId ?? '')?.name, 'Widget');
	});

	test('nominal IDs permit deterministic recursive and forward-declared aggregate types', () => {
		const buildNode = () => {
			const catalog = new SemanticTypeCatalog('target:sha256:recursive-fixture', 'dwarf-cu:0x10');
			const forward = catalog.forwardDeclare('struct', 'Node', evidence('debug', 1, 'pdb:forward'));
			const pointer = catalog.intern({
				kind: 'pointer', targetTypeId: forward.typeId, sizeBits: 64, alignBits: 64,
			}, evidence('debug', 1, 'pdb:pointer'));
			const complete = catalog.defineNominal({
				kind: 'struct', name: 'Node', sizeBits: 128, alignBits: 64,
				members: [
					{ name: 'value', typeId: 'type:fixture:int64', bitOffset: 0 },
					{ name: 'next', typeId: pointer.typeId, bitOffset: 64 },
				],
			}, evidence('debug', 2, 'pdb:definition'));
			return { catalog, forward, pointer, complete };
		};
		const first = buildNode();
		const repeat = buildNode();
		assert.strictEqual(first.forward.typeId, first.complete.typeId);
		assert.notStrictEqual(first.forward.canonicalHash, first.complete.canonicalHash);
		assert.strictEqual(first.pointer.targetTypeId, first.complete.typeId);
		assert.strictEqual(first.catalog.get(first.forward.typeId)?.incomplete, undefined);
		assert.strictEqual(first.complete.typeId, repeat.complete.typeId);
		assert.strictEqual(first.complete.canonicalHash, repeat.complete.canonicalHash);
		assert.notStrictEqual(
			first.complete.typeId,
			new SemanticTypeCatalog('target:sha256:other', 'dwarf-cu:0x10').forwardDeclare('struct', 'Node', evidence()).typeId,
		);
	});

	test('nominal IDs survive display-name edits when the stable identity is preserved', () => {
		const original = canonicalizeSemanticType({
			kind: 'struct', name: 'Before', nominalIdentity: 'pdb:tpi:0x1234', sizeBits: 32,
			members: [{ name: 'value', typeId: 'type:u32', bitOffset: 0, bitSize: 32 }],
		}, evidence('debug', 1, 'pdb:fixture'));
		const renamed = canonicalizeSemanticType({ ...original, name: 'After' }, evidence('definitive', 2, 'analyst:rename'));
		assert.strictEqual(renamed.typeId, original.typeId);
		assert.notStrictEqual(renamed.canonicalHash, original.canonicalHash);
	});

	test('conflicting complete nominal layouts retain the losing definition', () => {
		const catalog = new SemanticTypeCatalog('target:sha256:nominal-conflict', 'pdb:tpi');
		const debugLayout = catalog.defineNominal({
			kind: 'struct', name: 'Header', sizeBits: 64,
			members: [{ name: 'length', typeId: 'type:u64', bitOffset: 0 }],
		}, evidence('debug', 1, 'pdb:header'));
		const guessedLayout = catalog.defineNominal({
			kind: 'struct', name: 'Header', sizeBits: 128,
			members: [{ name: 'length', typeId: 'type:u64', bitOffset: 64 }],
		}, evidence('guessed', 9, 'heuristic:header'));
		assert.strictEqual(debugLayout.typeId, guessedLayout.typeId);
		assert.strictEqual(debugLayout.canonicalHash, guessedLayout.canonicalHash);
		assert.strictEqual(catalog.get(debugLayout.typeId)?.canonicalHash, debugLayout.canonicalHash);
		assert.strictEqual(catalog.conflicts(debugLayout.typeId).length, 1);
		assert.notStrictEqual(catalog.conflicts(debugLayout.typeId)[0].loser.canonicalHash, debugLayout.canonicalHash);
		assert.strictEqual(catalog.conflicts(debugLayout.typeId)[0].loser.evidence.producer, 'heuristic:header');
	});

	test('nominal IDs include type-unit scope and support anonymous recursive aggregates', () => {
		const firstCu = new SemanticTypeCatalog('target:sha256:same', 'dwarf-cu:0x10');
		const secondCu = new SemanticTypeCatalog('target:sha256:same', 'dwarf-cu:0x20');
		assert.notStrictEqual(
			firstCu.forwardDeclare('struct', 'Node', evidence()).typeId,
			secondCu.forwardDeclare('struct', 'Node', evidence()).typeId,
		);

		const anonymousForward = firstCu.forwardDeclareAnonymous('struct', 'dwarf-die:0x44', evidence());
		const anonymousPointer = firstCu.intern({
			kind: 'pointer', targetTypeId: anonymousForward.typeId, sizeBits: 64,
		}, evidence());
		const anonymousComplete = firstCu.defineNominal({
			kind: 'struct', sizeBits: 64,
			members: [{ name: 'next', typeId: anonymousPointer.typeId, bitOffset: 0 }],
		}, evidence('debug', 2), 'dwarf-die:0x44');
		assert.strictEqual(anonymousForward.typeId, anonymousComplete.typeId);
		assert.strictEqual(anonymousComplete.name, undefined);
	});

	test('standalone tagged legacy parsing requires and honors explicit target/scope identity', () => {
		const unsafe = parseLegacyCType('struct Node *', evidence());
		assert.strictEqual(unsafe.status, 'opaque');
		assert.match(unsafe.reason ?? '', /require a target identity/);

		const safe = parseLegacyCType('struct Node *', evidence(), {
			targetIdentity: 'target:sha256:legacy-node', nominalScope: 'pdb:tpi',
		});
		assert.strictEqual(safe.status, 'parsed');
		assert.strictEqual(safe.type.kind, 'pointer');
		assert.ok(safe.types.some(type => type.kind === 'struct' && type.name === 'Node'));

		const catalog = new SemanticTypeCatalog('target:sha256:bound', 'pdb:tpi');
		const before = catalog.list().length;
		assert.throws(() => catalog.parseLegacyCType('struct Wrong *', evidence(), {
			targetIdentity: 'target:sha256:other', nominalScope: 'pdb:tpi',
		}), /does not match the catalog/);
		assert.strictEqual(catalog.list().length, before);
	});

	test('parses data-model-sensitive and Windows aliases deterministically', () => {
		const llp64 = parseLegacyCType('unsigned long', evidence(), { pointerSizeBits: 64, longSizeBits: 32 });
		const lp64 = parseLegacyCType('unsigned long', evidence(), { pointerSizeBits: 64, longSizeBits: 64, wcharSizeBits: 32 });
		assert.strictEqual(llp64.type.sizeBits, 32);
		assert.strictEqual(lp64.type.sizeBits, 64);
		assert.notStrictEqual(llp64.type.typeId, lp64.type.typeId);
		assert.strictEqual(parseLegacyCType('long double', evidence()).type.sizeBits, 64);
		assert.strictEqual(parseLegacyCType('long double', evidence(), { longDoubleSizeBits: 80 }).type.sizeBits, 80);

		const handle = parseLegacyCType('HANDLE', evidence('signature', 1, 'win32-headers'));
		assert.strictEqual(handle.status, 'parsed');
		assert.strictEqual(handle.type.kind, 'typedef');
		assert.strictEqual(handle.type.name, 'HANDLE');
		assert.ok(handle.types.some(type => type.kind === 'pointer'));
	});

	test('unsupported legacy declarations become explicit opaque facts', () => {
		const functionPointer = parseLegacyCType('int (*callback)(void *)', evidence('derived', 1, 'migration'));
		assert.strictEqual(functionPointer.status, 'opaque');
		assert.strictEqual(functionPointer.type.kind, 'opaque-c-declaration');
		assert.match(functionPointer.reason ?? '', /unsupported/);
		assert.match(functionPointer.type.opaqueDeclaration ?? '', /callback/);

		const unknownTypedef = parseLegacyCType('ThirdPartyMysteryType *', evidence());
		assert.strictEqual(unknownTypedef.status, 'opaque');
		assert.match(unknownTypedef.reason ?? '', /unrecognized base type/);

		const explicit = createOpaqueCDeclaration('  void  (__vendor * x) [ 4 ] ', evidence('definitive'));
		assert.strictEqual(explicit.opaqueDeclaration, 'void (__vendor * x)[4]');
	});

	function buildPrototype(
		strength: EvidenceStrength,
		generation: number,
		overrides: Partial<FunctionPrototypeSpec> = {},
	): FunctionPrototypeSpec {
		const catalog = new SemanticTypeCatalog();
		const ev = evidence(strength, generation, `${strength}:${generation}`);
		const voidType = catalog.intern({ kind: 'void' }, ev);
		const sizeType = catalog.intern({ kind: 'integer', sizeBits: 64, alignBits: 64, signed: false }, ev);
		const byteType = catalog.intern({ kind: 'integer', sizeBits: 8, alignBits: 8, signed: false }, ev);
		const bytePointer = catalog.intern({ kind: 'pointer', targetTypeId: byteType.typeId, sizeBits: 64, alignBits: 64 }, ev);
		return {
			targetIdentity: 'target:sha256:abc',
			functionIdentity: 'function:0x140001000',
			functionAddress: '0x0000000140001000',
			returnTypeId: voidType.typeId,
			callingConventionId: 'win64',
			parameters: [
				{
					ordinal: 0, name: 'buffer', typeId: bytePointer.typeId,
					location: { kind: 'register', registers: ['RCX'] }, direction: 'inout', nullable: false,
					buffer: { kind: 'bytes', countParameterOrdinal: 1 }, ownership: 'borrow', lifetime: 'call',
				},
				{ ordinal: 1, name: 'size', typeId: sizeType.typeId, location: { kind: 'register', registers: ['RDX'] } },
			],
			evidence: ev,
			...overrides,
		};
	}

	test('canonical prototypes retain full parameter semantics and stable hashes', () => {
		const first = canonicalizeFunctionPrototype(buildPrototype('signature', 1));
		const reordered = buildPrototype('definitive', 9);
		reordered.parameters = [...reordered.parameters].reverse();
		const repeat = canonicalizeFunctionPrototype(reordered);
		assert.strictEqual(first.prototypeHash, repeat.prototypeHash);
		assert.strictEqual(first.prototypeId, repeat.prototypeId);
		assert.strictEqual(first.functionAddress, '0x140001000');
		assert.deepStrictEqual(first.parameters.map(parameter => parameter.ordinal), [0, 1]);
		assert.strictEqual(first.parameters[0].location.kind, 'register');
		if (first.parameters[0].location.kind !== 'register') {
			throw new Error('Expected register parameter location.');
		}
		assert.deepStrictEqual(first.parameters[0].location.registers, ['rcx']);
		assert.strictEqual(first.parameters[0].direction, 'inout');
		assert.strictEqual(first.parameters[0].buffer?.countParameterOrdinal, 1);
		assert.strictEqual(first.parameters[0].ownership, 'borrow');
		assert.strictEqual(first.parameters[0].lifetime, 'call');
		assert.strictEqual(first.evidence.generation, 1);
		assert.strictEqual(repeat.evidence.generation, 9);
	});

	test('parameter identity survives semantic edits while the prototype hash changes', () => {
		const original = canonicalizeFunctionPrototype(buildPrototype('derived', 1));
		const editSpec = buildPrototype('definitive', 2);
		editSpec.parameters = editSpec.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, name: 'destination', direction: 'out' as const, nullable: true }
			: parameter);
		const edited = canonicalizeFunctionPrototype(editSpec);
		assert.strictEqual(original.parameters[0].parameterId, edited.parameters[0].parameterId);
		assert.notStrictEqual(original.prototypeHash, edited.prototypeHash);
	});

	test('stable parameter anchors survive hidden-parameter discovery and ordinal shifts', () => {
		const originalSpec = buildPrototype('debug', 1);
		originalSpec.parameters = originalSpec.parameters.map(parameter => ({
			...parameter, stableIdentity: `pdb-param:${parameter.name}`,
		}));
		const original = canonicalizeFunctionPrototype(originalSpec);

		const recoveredSpec = buildPrototype('debug', 2, { method: false });
		recoveredSpec.parameters = [
			{
				ordinal: 0, stableIdentity: 'abi-hidden:sret', name: 'returnStorage',
				typeId: recoveredSpec.returnTypeId,
				location: { kind: 'implicit', role: 'sret', register: 'rcx' },
				hiddenSret: true, compilerGenerated: true,
			},
			...recoveredSpec.parameters.map(parameter => ({
				...parameter,
				ordinal: parameter.ordinal + 1,
				location: {
					kind: 'register' as const,
					registers: [parameter.ordinal === 0 ? 'rdx' : 'r8'],
				},
				stableIdentity: `pdb-param:${parameter.name}`,
				buffer: parameter.buffer?.countParameterOrdinal !== undefined
					? { ...parameter.buffer, countParameterOrdinal: parameter.buffer.countParameterOrdinal + 1 }
					: parameter.buffer,
			})),
		];
		recoveredSpec.hiddenStorage = { parameterOrdinal: 0, callerAllocated: true, calleeReturnsPointer: true };
		const recovered = canonicalizeFunctionPrototype(recoveredSpec);
		assert.strictEqual(original.parameters[0].parameterId, recovered.parameters[1].parameterId);
		assert.strictEqual(original.parameters[1].parameterId, recovered.parameters[2].parameterId);
		assert.notStrictEqual(original.prototypeHash, recovered.prototypeHash);
	});

	test('equivalent parameter anchors merge as aliases without rewriting the durable parameter ID', () => {
		const firstSpec = buildPrototype('debug', 1);
		firstSpec.parameters = firstSpec.parameters.map(parameter => ({ ...parameter, stableIdentity: `pdb:${parameter.ordinal}` }));
		const secondSpec = buildPrototype('debug', 1);
		secondSpec.parameters = secondSpec.parameters.map(parameter => ({ ...parameter, stableIdentity: `dwarf:${parameter.ordinal}` }));
		const first = canonicalizeFunctionPrototype(firstSpec);
		const second = canonicalizeFunctionPrototype(secondSpec);
		assert.strictEqual(first.prototypeHash, second.prototypeHash);
		const registry = new PrototypeRegistry();
		registry.apply(first);
		registry.apply(second);
		const accepted = registry.get(first.targetIdentity, first.functionIdentity);
		assert.strictEqual(registry.conflicts(first.targetIdentity, first.functionIdentity).length, 0);
		assert.deepStrictEqual(accepted?.parameters[0].stableIdentityAliases, ['dwarf:0']);
		assert.strictEqual(accepted?.parameters[0].stableIdentity, 'pdb:0');
		assert.strictEqual(accepted?.parameters[0].parameterId, first.parameters[0].parameterId);

		const reverse = new PrototypeRegistry();
		reverse.apply(second);
		reverse.apply(first);
		const reverseAccepted = reverse.get(first.targetIdentity, first.functionIdentity);
		assert.strictEqual(reverseAccepted?.parameters[0].parameterId, second.parameters[0].parameterId);
		assert.deepStrictEqual(reverseAccepted?.parameters[0].stableIdentityAliases, ['pdb:0']);
	});

	test('prototype semantic hashes are reusable while associations and parameter IDs remain target-scoped', () => {
		const first = canonicalizeFunctionPrototype(buildPrototype('debug', 1));
		const otherSpec = buildPrototype('debug', 1, { targetIdentity: 'target:sha256:def' });
		const other = canonicalizeFunctionPrototype(otherSpec);
		assert.strictEqual(first.prototypeHash, other.prototypeHash);
		assert.notStrictEqual(first.parameters[0].parameterId, other.parameters[0].parameterId);

		const registry = new PrototypeRegistry();
		registry.apply(first);
		registry.apply(other);
		assert.strictEqual(registry.get(first.targetIdentity, first.functionIdentity)?.targetIdentity, first.targetIdentity);
		assert.strictEqual(registry.get(other.targetIdentity, other.functionIdentity)?.targetIdentity, other.targetIdentity);
	});

	test('models hidden this/sret storage and split/stack locations', () => {
		const base = buildPrototype('definitive', 4);
		const returnType = base.returnTypeId;
		base.callingConventionId = 'thiscall';
		base.method = true;
		base.parameters = [
			{
				ordinal: 0, name: 'returnStorage', typeId: returnType,
				location: { kind: 'implicit', role: 'sret', stackOffsetBytes: 4 }, hiddenSret: true, compilerGenerated: true,
			},
			{
				ordinal: 1, name: 'this', typeId: returnType,
				location: { kind: 'implicit', role: 'this', register: 'ECX' }, hiddenThis: true, compilerGenerated: true,
			},
			{
				ordinal: 2, name: 'wide', typeId: returnType,
				location: { kind: 'stack', base: 'entry-sp', offsetBytes: 8, sizeBytes: 4 },
			},
		];
		base.hiddenReturn = { kind: 'sret-parameter', location: base.parameters[0].location };
		base.hiddenStorage = { parameterOrdinal: 0, callerAllocated: true, calleeReturnsPointer: true };
		const prototype = canonicalizeFunctionPrototype(base);
		assert.strictEqual(prototype.parameters[0].hiddenSret, true);
		assert.strictEqual(prototype.parameters[1].hiddenThis, true);
		assert.strictEqual(prototype.hiddenStorage?.parameterOrdinal, 0);
		assert.strictEqual(prototype.hiddenReturn?.kind, 'sret-parameter');
	});

	test('prototype validation rejects duplicate ordinals and dangling semantic relationships', () => {
		const duplicate = buildPrototype('derived', 1);
		duplicate.parameters = [duplicate.parameters[0], { ...duplicate.parameters[1], ordinal: 0 }];
		assert.throws(() => canonicalizeFunctionPrototype(duplicate), /Duplicate parameter ordinal/);

		const danglingCount = buildPrototype('derived', 1);
		danglingCount.parameters = [{ ...danglingCount.parameters[0], buffer: { kind: 'bytes', countParameterOrdinal: 99 } }];
		assert.throws(() => canonicalizeFunctionPrototype(danglingCount), /missing count parameter/);

		const danglingSret = buildPrototype('derived', 1);
		danglingSret.hiddenStorage = { parameterOrdinal: 0, callerAllocated: true, calleeReturnsPointer: false };
		assert.throws(() => canonicalizeFunctionPrototype(danglingSret), /hidden sret parameter/);

		const fractionalImplicit = buildPrototype('derived', 1);
		fractionalImplicit.parameters = [{
			...fractionalImplicit.parameters[0],
			location: { kind: 'implicit', role: 'compiler-generated', stackOffsetBytes: 1.5 },
		}];
		assert.throws(() => canonicalizeFunctionPrototype(fractionalImplicit), /safe integer/);

		const contradictoryHidden = buildPrototype('derived', 1, { method: false });
		contradictoryHidden.parameters = [{
			...contradictoryHidden.parameters[0], hiddenThis: true, hiddenSret: true,
		}];
		assert.throws(() => canonicalizeFunctionPrototype(contradictoryHidden), /both hidden this and hidden sret/);

		const invalidRuntimeEnum = buildPrototype('derived', 1);
		invalidRuntimeEnum.parameters = [{
			...invalidRuntimeEnum.parameters[0], direction: 'sideways' as never,
		}];
		assert.throws(() => canonicalizeFunctionPrototype(invalidRuntimeEnum), /Unknown direction/);
		const invalidRuntimeBoolean = buildPrototype('derived', 1);
		invalidRuntimeBoolean.variadic = 'yes' as never;
		assert.throws(() => canonicalizeFunctionPrototype(invalidRuntimeBoolean), /must be boolean/);

		const ambiguousBuffer = buildPrototype('derived', 1);
		ambiguousBuffer.parameters = ambiguousBuffer.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, buffer: { kind: 'bytes' as const, countParameterOrdinal: 1, fixedCount: 16 } }
			: parameter);
		assert.throws(() => canonicalizeFunctionPrototype(ambiguousBuffer), /cannot use both/);

		const selfSizedBuffer = buildPrototype('derived', 1);
		selfSizedBuffer.parameters = selfSizedBuffer.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, buffer: { kind: 'bytes' as const, countParameterOrdinal: 0 } }
			: parameter);
		assert.throws(() => canonicalizeFunctionPrototype(selfSizedBuffer), /own buffer count/);

		const unboundedBytes = buildPrototype('derived', 1);
		unboundedBytes.parameters = unboundedBytes.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, buffer: { kind: 'bytes' as const } }
			: parameter);
		assert.throws(() => canonicalizeFunctionPrototype(unboundedBytes), /requires a count relationship/);

		const duplicateAnchor = buildPrototype('derived', 1);
		duplicateAnchor.parameters = duplicateAnchor.parameters.map(parameter => ({
			...parameter, stableIdentity: 'same-anchor',
		}));
		assert.throws(() => canonicalizeFunctionPrototype(duplicateAnchor), /Duplicate stable parameter identity/);

		const invalidSplit = buildPrototype('derived', 1);
		invalidSplit.parameters = [{
			...invalidSplit.parameters[0],
			location: { kind: 'split', parts: [
				{ kind: 'register', registers: ['rcx'] },
				{ kind: 'implicit', role: 'compiler-generated' } as never,
			] },
		}];
		assert.throws(() => canonicalizeFunctionPrototype(invalidSplit), /only register or stack parts/);

		const invalidHiddenReturn = buildPrototype('derived', 1);
		invalidHiddenReturn.hiddenReturn = {
			kind: 'register', location: { kind: 'stack', base: 'entry-sp', offsetBytes: 8 },
		};
		assert.throws(() => canonicalizeFunctionPrototype(invalidHiddenReturn), /require a register location/);

		const missingSret = buildPrototype('derived', 1);
		missingSret.hiddenReturn = {
			kind: 'sret-parameter', location: { kind: 'implicit', role: 'sret', register: 'rcx' },
		};
		assert.throws(() => canonicalizeFunctionPrototype(missingSret), /require a hidden sret parameter/);

		const splitWithStack = buildPrototype('derived', 1);
		splitWithStack.hiddenReturn = {
			kind: 'split-registers',
			location: { kind: 'split', parts: [
				{ kind: 'register', registers: ['eax'] },
				{ kind: 'stack', base: 'entry-sp', offsetBytes: 4 },
			] },
		};
		assert.throws(() => canonicalizeFunctionPrototype(splitWithStack), /require a split location/);

		const twoRegisterSingle = buildPrototype('derived', 1);
		twoRegisterSingle.hiddenReturn = {
			kind: 'register', location: { kind: 'register', registers: ['eax', 'edx'] },
		};
		assert.throws(() => canonicalizeFunctionPrototype(twoRegisterSingle), /require a register location/);

		const dualImplicit = buildPrototype('derived', 1);
		dualImplicit.parameters = [{
			...dualImplicit.parameters[0],
			location: { kind: 'implicit', role: 'compiler-generated', register: 'rcx', stackOffsetBytes: 8 },
		}];
		assert.throws(() => canonicalizeFunctionPrototype(dualImplicit), /cannot specify both register and stack/);

		const duplicateSret = buildPrototype('derived', 1, { callingConventionId: 'cdecl' });
		duplicateSret.parameters = [0, 1].map(ordinal => ({
			ordinal, name: `sret${ordinal}`, typeId: duplicateSret.returnTypeId,
			location: { kind: 'implicit' as const, role: 'sret' as const, stackOffsetBytes: 4 + ordinal * 4 },
			hiddenSret: true,
		}));
		assert.throws(() => canonicalizeFunctionPrototype(duplicateSret), /at most one hidden sret/);

		const mismatchedSret = buildPrototype('derived', 1);
		mismatchedSret.parameters = [{
			ordinal: 0, name: 'sret', typeId: mismatchedSret.returnTypeId,
			location: { kind: 'implicit', role: 'sret', register: 'rcx' }, hiddenSret: true,
		}];
		mismatchedSret.hiddenReturn = {
			kind: 'sret-parameter', location: { kind: 'implicit', role: 'sret', register: 'rdx' },
		};
		assert.throws(() => canonicalizeFunctionPrototype(mismatchedSret), /must match the hidden sret/);

		const contradictoryStorage = buildPrototype('derived', 1);
		contradictoryStorage.parameters = [{
			ordinal: 0, name: 'sret', typeId: contradictoryStorage.returnTypeId,
			location: { kind: 'implicit', role: 'sret', register: 'rcx' }, hiddenSret: true,
		}];
		contradictoryStorage.hiddenReturn = {
			kind: 'register', location: { kind: 'register', registers: ['rax'] },
		};
		contradictoryStorage.hiddenStorage = {
			parameterOrdinal: 0, callerAllocated: 'yes' as never, calleeReturnsPointer: true,
		};
		assert.throws(() => canonicalizeFunctionPrototype(contradictoryStorage), /flags must be boolean/);
	});

	test('retains every R32 recovery observation and caller consensus deterministically', () => {
		const prototype = canonicalizeFunctionPrototype(buildPrototype('derived', 8));
		const common = {
			targetIdentity: prototype.targetIdentity,
			functionIdentity: prototype.functionIdentity,
			evidence: evidence('derived', 8, 'abi-recovery:test'),
		};
		const specs = [
			{ ...common, kind: 'register-read-before-definition' as const, atAddress: '0x140001001', register: 'RCX' },
			{ ...common, kind: 'entry-stack-read' as const, atAddress: '0x140001004', stackOffsetBytes: 40 },
			{ ...common, kind: 'ret-immediate' as const, atAddress: '0x140001080', byteCount: 8 },
			{ ...common, kind: 'caller-stack-adjustment' as const, callerIdentity: 'caller:1', callsiteAddress: '0x140002000', byteCount: 8 },
			{ ...common, kind: 'callsite-argument-write' as const, callerIdentity: 'caller:1', callsiteAddress: '0x140002000', register: 'RCX', parameterOrdinal: 0 },
			{ ...common, kind: 'callsite-argument-write' as const, callerIdentity: 'caller:2', callsiteAddress: '0x140003000', register: 'RCX', parameterOrdinal: 0 },
			{ ...common, kind: 'caller-return-register-use' as const, callerIdentity: 'caller:1', callsiteAddress: '0x140002000', register: 'RAX' },
			{ ...common, kind: 'this-pattern' as const, atAddress: '0x140001008', register: 'RCX' },
			{ ...common, kind: 'debug-prototype' as const, atAddress: '0x140001000' },
			{ ...common, kind: 'import-prototype' as const, atAddress: '0x140001000' },
			{ ...common, kind: 'signature-prototype' as const, atAddress: '0x140001000' },
		];
		const canonical = specs.map(canonicalizePrototypeRecoveryObservation);
		const consensus = canonicalizePrototypeRecoveryObservation({
			...common,
			kind: 'caller-consensus',
			callerIdentities: ['caller:2', 'caller:1', 'caller:2'],
			corroboratingObservationIds: [canonical[4].observationId, canonical[5].observationId],
		});
		const assessment = assessPrototypeRecovery(prototype, [...canonical, consensus]);
		const repeat = assessPrototypeRecovery(prototype, [consensus, ...canonical].reverse());
		assert.strictEqual(assessment.observations.length, 12);
		assert.strictEqual(new Set(assessment.observations.map(item => item.kind)).size, 11);
		assert.strictEqual(assessment.callerConsensusCount, 2);
		assert.strictEqual(assessment.canonicalHash, repeat.canonicalHash);
		assert.strictEqual(Object.isFrozen(assessment.observations), true);
	});

	test('recovery observations fail closed on incomplete or cross-target evidence', () => {
		const prototype = canonicalizeFunctionPrototype(buildPrototype('derived', 1));
		const common = {
			targetIdentity: prototype.targetIdentity,
			functionIdentity: prototype.functionIdentity,
			evidence: evidence(),
		};
		assert.throws(() => canonicalizePrototypeRecoveryObservation({
			...common, kind: 'register-read-before-definition',
		}), /requires an address and register/);
		assert.throws(() => canonicalizePrototypeRecoveryObservation({
			...common, kind: 'caller-consensus', callerIdentities: ['only-one'], corroboratingObservationIds: ['one'],
		}), /at least two callers/);
		const foreign = canonicalizePrototypeRecoveryObservation({
			...common, targetIdentity: 'target:sha256:foreign', kind: 'debug-prototype',
		});
		assert.throws(() => assessPrototypeRecovery(prototype, [foreign]), /different target or function/);
		assert.throws(() => canonicalizePrototypeRecoveryObservation({
			...common, kind: 'debug-prototype', callerIdentity: 'fake-caller',
		}), /does not allow callerIdentity/);

		const caller1 = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'callsite-argument-write', callerIdentity: 'caller:1',
			callsiteAddress: '0x140002000', register: 'rcx',
		});
		const caller2 = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'callsite-argument-write', callerIdentity: 'caller:2',
			callsiteAddress: '0x140003000', register: 'rcx',
		});
		const inflatedConsensus = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'caller-consensus', callerIdentities: ['caller:1', 'caller:2', 'caller:3'],
			corroboratingObservationIds: [caller1.observationId, caller2.observationId],
		});
		assert.throws(
			() => assessPrototypeRecovery(prototype, [caller1, caller2, inflatedConsensus]),
			/exactly match its supporting callers/,
		);

		const invalidOrdinal = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'callsite-argument-write', callerIdentity: 'caller:1',
			callsiteAddress: '0x140004000', register: 'rcx', parameterOrdinal: 99,
		});
		assert.throws(() => assessPrototypeRecovery(prototype, [invalidOrdinal]), /missing parameter 99/);

		const returnUse = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'caller-return-register-use', callerIdentity: 'caller:2',
			callsiteAddress: '0x140005000', register: 'rax',
		});
		const mixedConsensus = canonicalizePrototypeRecoveryObservation({
			...common, kind: 'caller-consensus', callerIdentities: ['caller:1', 'caller:2'],
			corroboratingObservationIds: [caller1.observationId, returnUse.observationId],
		});
		assert.throws(
			() => assessPrototypeRecovery(prototype, [caller1, returnUse, mixedConsensus]),
			/same semantic claim/,
		);
	});

	test('ABI registry defines every required convention and deterministic hashes', () => {
		const required: CallingConventionId[] = [
			'cdecl', 'stdcall', 'fastcall', 'thiscall', 'vectorcall', 'usercall',
			'win64', 'sysv64', 'aapcs32', 'aapcs64',
		];
		const models = listABIModels();
		assert.deepStrictEqual(models.map(model => model.id).sort(), required.sort());
		assert.strictEqual(new Set(models.map(model => model.canonicalHash)).size, required.length);
		for (const model of models) {
			assert.match(model.canonicalHash, /^[a-f0-9]{64}$/);
			assert.ok(model.stack.alignmentBytes > 0);
			assert.ok(model.stack.slotSizeBytes > 0);
			assert.ok(model.returns.integer.length > 0 || model.userDefined);
			assert.ok(model.callerSaved.length > 0 || model.userDefined);
			assert.ok(model.calleeSaved.length > 0 || model.userDefined);
		}
	});

	test('ABI models expose stack, cleanup, return, aggregate, variadic, saved and hidden contracts', () => {
		assert.strictEqual(getABIModel('cdecl').stack.cleanup, 'caller');
		assert.strictEqual(getABIModel('stdcall').stack.cleanup, 'callee');
		assert.deepStrictEqual(getABIModel('fastcall').argumentBanks[0].registers, ['ecx', 'edx']);
		assert.strictEqual(getABIModel('thiscall').hiddenParameters[0].register, 'ecx');
		assert.strictEqual(getABIModel('vectorcall').argumentBanks.find(bank => bank.kind === 'vector')?.registers.length, 6);
		assert.strictEqual(getABIModel('stdcall').variadic.fallbackConventionId, 'cdecl');

		const win64 = getABIModel('win64');
		assert.strictEqual(win64.argumentAllocation, 'shared-ordinal-slots');
		assert.strictEqual(win64.stack.shadowSpaceBytes, 32);
		assert.strictEqual(win64.stack.argumentBaseBytes, 40);
		assert.strictEqual(win64.stack.argumentOrder, 'right-to-left');
		assert.strictEqual(win64.aggregateReturn.hiddenPointerRegister, 'rcx');
		assert.ok(win64.calleeSaved.includes('xmm15'));

		const sysv = getABIModel('sysv64');
		assert.strictEqual(sysv.argumentAllocation, 'independent-register-banks');
		assert.strictEqual(sysv.stack.redZoneBytes, 128);
		assert.strictEqual(sysv.variadic.floatingRegisterCountRegister, 'al');
		assert.deepStrictEqual(sysv.returns.splitInteger, ['rax', 'rdx']);

		const aapcs32 = getABIModel('aapcs32');
		assert.strictEqual(aapcs32.stack.alignmentBytes, 8);
		assert.strictEqual(aapcs32.variadic.floatingArgumentsUseIntegerBank, true);
		assert.strictEqual(aapcs32.aggregateReturn.hiddenPointerRegister, 'r0');

		const aapcs64 = getABIModel('aapcs64');
		assert.strictEqual(aapcs64.stack.alignmentBytes, 16);
		assert.strictEqual(aapcs64.aggregateReturn.hiddenPointerRegister, 'x8');
		assert.strictEqual(aapcs64.aggregateReturn.hiddenPointerConsumesArgumentSlot, false);
		assert.strictEqual(aapcs64.variadic.requiresRegisterSaveArea, true);
		assert.deepStrictEqual(aapcs64.platformSpecificRegisters, ['x18']);
		assert.strictEqual(aapcs64.partialCalleeSaved?.[0].preservedLowBits, 64);
	});

	test('ABI registry models are deeply immutable so their hashes cannot become stale', () => {
		const win64 = getABIModel('win64');
		assert.strictEqual(Object.isFrozen(win64), true);
		assert.strictEqual(Object.isFrozen(win64.stack), true);
		assert.strictEqual(Object.isFrozen(win64.argumentBanks), true);
		assert.strictEqual(Object.isFrozen(win64.argumentBanks[0].registers), true);
		assert.throws(() => { (win64.stack as { shadowSpaceBytes: number }).shadowSpaceBytes = 0; }, TypeError);
		assert.strictEqual(getABIModel('win64').stack.shadowSpaceBytes, 32);
	});

	test('aggregate return classifiers are executable and conservative when evidence is missing', () => {
		assert.deepStrictEqual(classifyAggregateReturn('cdecl', {
			sizeBits: 64, trivial: true,
		}).registers, ['edx', 'eax']);
		assert.deepStrictEqual(classifyAggregateReturn('stdcall', {
			sizeBits: 32, trivial: true,
		}).registers, ['eax']);
		assert.strictEqual(classifyAggregateReturn('fastcall', {
			sizeBits: 128, trivial: true,
		}).kind, 'hidden-pointer');
		assert.deepStrictEqual(classifyAggregateReturn('win64', {
			sizeBits: 64, trivial: true,
		}).registers, ['rax']);
		assert.strictEqual(classifyAggregateReturn('win64', {
			sizeBits: 64,
		}).kind, 'hidden-pointer');
		assert.strictEqual(classifyAggregateReturn('win64', {
			sizeBits: 24, trivial: true,
		}).kind, 'hidden-pointer');

		const sysvMixed = classifyAggregateReturn('sysv64', {
			sizeBits: 128, eightByteClasses: ['integer', 'floating'],
		});
		assert.strictEqual(sysvMixed.kind, 'registers');
		assert.deepStrictEqual(sysvMixed.registers, ['rax', 'xmm0']);
		assert.strictEqual(classifyAggregateReturn('sysv64', { sizeBits: 64 }).kind, 'indeterminate');
		assert.strictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 64, eightByteClasses: ['integer', 'floating'],
		}).kind, 'indeterminate');
		assert.strictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 128, eightByteClasses: ['memory'],
		}).kind, 'hidden-pointer');
		assert.deepStrictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 128, eightByteClasses: ['sse', 'sseup'],
		}).registers, ['xmm0']);
		assert.deepStrictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 128, eightByteClasses: ['x87', 'x87up'],
		}).registers, ['st0']);
		assert.deepStrictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 256, eightByteClasses: ['complex-x87'],
		}).registers, ['st0', 'st1']);
		assert.strictEqual(classifyAggregateReturn('sysv64', {
			sizeBits: 128, eightByteClasses: ['sseup', 'integer'],
		}).kind, 'indeterminate');

		assert.deepStrictEqual(classifyAggregateReturn('aapcs64', {
			sizeBits: 128, homogeneousMemberClass: 'floating', homogeneousMemberCount: 4,
		}).registers, ['v0', 'v1', 'v2', 'v3']);
		assert.deepStrictEqual(classifyAggregateReturn('aapcs64', { sizeBits: 128 }).registers, ['x0', 'x1']);
		assert.deepStrictEqual(classifyAggregateReturn('vectorcall', {
			sizeBits: 64, trivial: true,
		}).registers, ['edx', 'eax']);
		assert.strictEqual(classifyAggregateReturn('vectorcall', {
			sizeBits: 8, homogeneousMemberClass: 'floating', homogeneousMemberCount: 4,
		}).kind, 'indeterminate');
		assert.deepStrictEqual(classifyAggregateReturn('vectorcall', {
			sizeBits: 512, homogeneousMemberClass: 'vector', homogeneousMemberCount: 2,
		}).registers, ['ymm0', 'ymm1']);
		assert.strictEqual(classifyAggregateReturn('usercall', { sizeBits: 64 }).kind, 'indeterminate');
		assert.throws(() => classifyAggregateReturn('aapcs64', {
			sizeBits: 64, homogeneousMemberClass: 'floating', homogeneousMemberCount: 1.5,
		}), /positive safe integer/);
		assert.strictEqual(classifyAggregateReturn('aapcs64', {
			sizeBits: 8, homogeneousMemberClass: 'floating', homogeneousMemberCount: 4,
		}).kind, 'indeterminate');
		assert.strictEqual(classifyAggregateReturn('aapcs64', {
			sizeBits: 100_000, homogeneousMemberClass: 'vector', homogeneousMemberCount: 4,
		}).kind, 'indeterminate');
		assert.throws(() => classifyAggregateReturn('aapcs64', {
			sizeBits: 64, homogeneousMemberClass: 'bogus' as never, homogeneousMemberCount: 1,
		}), /Unknown homogeneous aggregate class/);
	});

	test('ABI location validation handles hidden registers and allocation order', () => {
		const aapcs = buildPrototype('definitive', 1, { callingConventionId: 'aapcs64' });
		aapcs.parameters = [
			{
				ordinal: 0, name: 'returnStorage', typeId: aapcs.returnTypeId,
				location: { kind: 'implicit', role: 'sret', register: 'x8' }, hiddenSret: true,
			},
			{
				ordinal: 1, name: 'value', typeId: aapcs.returnTypeId,
				location: { kind: 'register', registers: ['x0'] },
			},
		];
		aapcs.hiddenReturn = { kind: 'sret-parameter', location: aapcs.parameters[0].location };
		aapcs.hiddenStorage = { parameterOrdinal: 0, callerAllocated: true, calleeReturnsPointer: false };
		assert.doesNotThrow(() => canonicalizeFunctionPrototype(aapcs));

		const reversedFastcall = buildPrototype('definitive', 1, { callingConventionId: 'fastcall' });
		reversedFastcall.parameters = reversedFastcall.parameters.map(parameter => ({
			...parameter,
			location: { kind: 'register' as const, registers: [parameter.ordinal === 0 ? 'edx' : 'ecx'] },
		}));
		assert.throws(() => canonicalizeFunctionPrototype(reversedFastcall), /register allocation order/);

		const duplicateFastcall = buildPrototype('definitive', 1, { callingConventionId: 'fastcall' });
		duplicateFastcall.parameters = duplicateFastcall.parameters.map(parameter => ({
			...parameter, location: { kind: 'register' as const, registers: ['ecx'] },
		}));
		assert.throws(() => canonicalizeFunctionPrototype(duplicateFastcall), /assigned to multiple parameters/);

		const alignedAapcs = buildPrototype('definitive', 1, { callingConventionId: 'aapcs32' });
		alignedAapcs.parameters = [
			{
				ordinal: 0, name: 'small', typeId: alignedAapcs.returnTypeId,
				location: { kind: 'register', registers: ['r0'] }, abiValueClass: 'integer', abiSizeBits: 32, abiAlignBits: 32,
			},
			{
				ordinal: 1, name: 'wide', typeId: alignedAapcs.returnTypeId,
				location: { kind: 'register', registers: ['r2', 'r3'] }, abiValueClass: 'integer', abiSizeBits: 64, abiAlignBits: 64,
			},
		];
		assert.doesNotThrow(() => canonicalizeFunctionPrototype(alignedAapcs));

		const aliasedVfp = buildPrototype('definitive', 1, { callingConventionId: 'aapcs32' });
		aliasedVfp.parameters = [
			{
				ordinal: 0, name: 'single', typeId: aliasedVfp.returnTypeId,
				location: { kind: 'register', registers: ['s0'] }, abiValueClass: 'floating', abiSizeBits: 32,
			},
			{
				ordinal: 1, name: 'double', typeId: aliasedVfp.returnTypeId,
				location: { kind: 'register', registers: ['d0'] }, abiValueClass: 'vector', abiSizeBits: 64,
			},
		];
		assert.throws(() => canonicalizeFunctionPrototype(aliasedVfp), /aliases another parameter/);

		const oversizedFastcall = buildPrototype('definitive', 1, { callingConventionId: 'fastcall' });
		oversizedFastcall.parameters = [{
			ordinal: 0, name: 'wide', typeId: oversizedFastcall.returnTypeId,
			location: { kind: 'register', registers: ['ecx'] }, abiValueClass: 'integer', abiSizeBits: 64,
		}];
		assert.throws(() => canonicalizeFunctionPrototype(oversizedFastcall), /exceeds the x86 integer register width/);

		const negativeStack = buildPrototype('definitive', 1, { callingConventionId: 'cdecl' });
		negativeStack.parameters = [{
			ordinal: 0, name: 'bad', typeId: negativeStack.returnTypeId,
			location: { kind: 'stack', base: 'entry-sp', offsetBytes: -4 },
		}];
		assert.throws(() => canonicalizeFunctionPrototype(negativeStack), /must not be negative/);
	});

	test('unsupported variadic x86 conventions canonicalize to their declared cdecl fallback', () => {
		for (const convention of ['stdcall', 'fastcall', 'thiscall', 'vectorcall'] as const) {
			const spec = buildPrototype('definitive', 1, { callingConventionId: convention, variadic: true });
			spec.parameters = spec.parameters.map((parameter, index) => ({
				...parameter,
				location: { kind: 'stack' as const, base: 'entry-sp' as const, offsetBytes: 4 + index * 4 },
			}));
			const prototype = canonicalizeFunctionPrototype(spec);
			assert.strictEqual(prototype.callingConventionId, 'cdecl');
			assert.strictEqual(prototype.variadic, true);
		}
		const incoherent = buildPrototype('definitive', 1, { callingConventionId: 'fastcall', variadic: true });
		assert.throws(() => canonicalizeFunctionPrototype(incoherent), /must use stack locations/);
		const variadicThis = buildPrototype('definitive', 1, { callingConventionId: 'thiscall', variadic: true, method: true });
		variadicThis.parameters = [{
			ordinal: 0, name: 'this', typeId: variadicThis.returnTypeId,
			location: { kind: 'implicit', role: 'this', register: 'ecx' }, hiddenThis: true,
		}];
		assert.throws(() => canonicalizeFunctionPrototype(variadicThis), /must use stack locations/);

		const wrongWin64Register = buildPrototype('definitive', 1);
		wrongWin64Register.parameters = wrongWin64Register.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, location: { kind: 'register' as const, registers: ['r0'] } }
			: parameter);
		assert.throws(() => canonicalizeFunctionPrototype(wrongWin64Register), /violates shared ordinal slots/);
	});

	test('architecture defaults are explicitly inferred and never definitive', () => {
		const windows = resolveArchitectureDefaultABI('x86_64', 'windows', 12);
		const linux = resolveArchitectureDefaultABI('x86_64', 'linux', 12);
		const arm = resolveArchitectureDefaultABI('arm', 'unknown', 12);
		assert.strictEqual(windows.model.id, 'win64');
		assert.strictEqual(linux.model.id, 'sysv64');
		assert.strictEqual(arm.model.id, 'aapcs32');
		assert.strictEqual(windows.inferred, true);
		assert.strictEqual(windows.evidence.strength, 'guessed');
		assert.strictEqual(windows.evidence.source, 'architecture-default');
		assert.strictEqual(windows.evidence.generation, 12);
		assert.throws(() => resolveArchitectureDefaultABI('x86_64', 'unknown'), /require a platform/);
	});

	test('usercall accepts explicit register and stack contracts with its own stable hash', () => {
		const custom = createUsercallABI({
			displayName: 'Malware custom usercall',
			architecture: 'x86',
			argumentBanks: [{ kind: 'integer', registers: ['EAX', 'EBX'], allocation: 'left-to-right' }],
			returns: { integer: ['EDI'], floating: [], vector: [] },
			stack: {
				direction: 'down', argumentOrder: 'left-to-right', argumentBaseBytes: 8,
				slotSizeBytes: 4, alignmentBytes: 4, cleanup: 'convention-specific', shadowSpaceBytes: 0, redZoneBytes: 0,
			},
		});
		assert.strictEqual(custom.id, 'usercall');
		assert.strictEqual(custom.userDefined, true);
		assert.deepStrictEqual(custom.argumentBanks[0].registers, ['eax', 'ebx']);
		assert.deepStrictEqual(custom.returns.integer, ['edi']);
		assert.notStrictEqual(custom.canonicalHash, getABIModel('usercall').canonicalHash);
	});

	test('weaker prototype evidence cannot overwrite stronger evidence and conflicts remain inspectable', () => {
		const registry = new PrototypeRegistry();
		const definitiveSpec = buildPrototype('definitive', 4);
		const accepted = registry.apply(definitiveSpec);
		assert.strictEqual(accepted.status, 'accepted-new');

		const guessedSpec = buildPrototype('guessed', 99);
		guessedSpec.parameters = guessedSpec.parameters.map(parameter => parameter.ordinal === 0
			? { ...parameter, direction: 'out' as const }
			: parameter);
		const rejected = registry.apply(guessedSpec);
		assert.strictEqual(rejected.status, 'rejected-weaker');
		assert.strictEqual(registry.get(definitiveSpec.targetIdentity, definitiveSpec.functionIdentity)?.prototypeHash, accepted.accepted.prototypeHash);
		assert.strictEqual(registry.conflicts(definitiveSpec.targetIdentity, definitiveSpec.functionIdentity).length, 1);
		assert.strictEqual(registry.conflicts(definitiveSpec.targetIdentity, definitiveSpec.functionIdentity)[0].loser.evidence.strength, 'guessed');
		registry.apply({
			...guessedSpec,
			corroboratingEvidence: [{
				strength: 'derived', source: 'abi-recovery', producer: 'caller:corroboration', generation: 99,
			}],
		});
		assert.strictEqual(registry.conflicts(definitiveSpec.targetIdentity, definitiveSpec.functionIdentity).length, 1);
		assert.ok(registry.conflicts(definitiveSpec.targetIdentity, definitiveSpec.functionIdentity)[0]
			.loser.evidenceSet.some(item => item.producer === 'caller:corroboration'));
	});

	test('a later automated peer cannot erase a definitive analyst-owned override', () => {
		const registry = new PrototypeRegistry();
		const analyst = buildPrototype('definitive', 1);
		analyst.evidence = {
			strength: 'definitive', source: 'analyst', producer: 'analyst:prototype-editor', generation: 1, userDefined: true,
		};
		const analystPrototype = registry.apply(analyst).accepted;
		const automated = buildPrototype('definitive', 99);
		automated.parameters = automated.parameters.map(parameter => ({ ...parameter, optional: true }));
		const result = registry.apply(automated);
		assert.strictEqual(result.status, 'rejected-peer');
		assert.strictEqual(result.conflict?.reason, 'user-defined-override');
		assert.strictEqual(result.accepted.prototypeHash, analystPrototype.prototypeHash);
		assert.strictEqual(result.accepted.evidence.userDefined, true);
		assert.throws(() => normalizeSemanticEvidence({
			strength: 'derived', source: 'analyst', producer: 'bad-edit', generation: 1, userDefined: true,
		}), /must be definitive analyst evidence/);
	});

	test('stronger and newer-peer evidence replaces a fact without dropping the loser', () => {
		const registry = new PrototypeRegistry();
		const guessed = buildPrototype('guessed', 1);
		registry.apply(guessed);
		const debug = buildPrototype('debug', 1);
		debug.parameters = debug.parameters.map(parameter => ({ ...parameter, optional: true }));
		assert.strictEqual(registry.apply(debug).status, 'replaced-stronger');

		const newerDebug = buildPrototype('debug', 2);
		newerDebug.parameters = newerDebug.parameters.map(parameter => ({ ...parameter, nullable: true }));
		assert.strictEqual(registry.apply(newerDebug).status, 'replaced-peer');
		assert.strictEqual(registry.get(guessed.targetIdentity, guessed.functionIdentity)?.evidence.generation, 2);
		assert.strictEqual(registry.conflicts(guessed.targetIdentity, guessed.functionIdentity).length, 2);
	});

	test('equivalent facts update provenance without manufacturing a semantic conflict', () => {
		const oldValue = canonicalizeFunctionPrototype(buildPrototype('derived', 1));
		const newValue = canonicalizeFunctionPrototype(buildPrototype('debug', 2));
		const result = arbitrateSemanticValue(oldValue, newValue);
		assert.strictEqual(result.status, 'equivalent-updated');
		assert.strictEqual(result.accepted.evidence.strength, 'debug');
		assert.strictEqual(result.accepted.evidenceSet.length, 2);
		assert.deepStrictEqual(result.accepted.evidenceSet.map(item => item.strength), ['debug', 'derived']);
		assert.strictEqual(result.conflict, undefined);
	});

	test('corroborating evidence is retained without changing canonical semantic hashes', () => {
		const base = buildPrototype('signature', 3);
		const withoutCorroboration = canonicalizeFunctionPrototype(base);
		const withCorroboration = canonicalizeFunctionPrototype({
			...base,
			corroboratingEvidence: [
				{ strength: 'derived', source: 'abi-recovery', producer: 'caller:0x1000', generation: 3 },
				{ strength: 'derived', source: 'abi-recovery', producer: 'caller:0x2000', generation: 3 },
			],
		});
		assert.strictEqual(withoutCorroboration.prototypeHash, withCorroboration.prototypeHash);
		assert.strictEqual(withCorroboration.evidenceSet.length, 3);
		assert.deepStrictEqual(
			withCorroboration.evidenceSet.map(item => item.producer).sort(),
			['caller:0x1000', 'caller:0x2000', 'signature:3'].sort(),
		);
	});

	test('otherwise identical conflicting peers select the same winner in either ingestion order', () => {
		const firstSpec = buildPrototype('derived', 5);
		const secondSpec = buildPrototype('derived', 5);
		secondSpec.parameters = secondSpec.parameters.map(parameter => ({ ...parameter, optional: true }));
		const first = canonicalizeFunctionPrototype(firstSpec);
		const second = canonicalizeFunctionPrototype(secondSpec);
		const forward = arbitrateSemanticValue(first, second);
		const reverse = arbitrateSemanticValue(second, first);
		assert.notStrictEqual(first.canonicalHash, second.canonicalHash);
		assert.strictEqual(forward.accepted.canonicalHash, reverse.accepted.canonicalHash);
		assert.strictEqual(forward.conflict?.reason, 'deterministic-peer');
		assert.strictEqual(reverse.conflict?.reason, 'deterministic-peer');
	});

	test('type binding IDs track storage identity while semantic hashes track the bound type', () => {
		const first = canonicalizeTypeBinding({
			targetIdentity: 'target:sha256:aaa', scope: 'stack-slot', functionIdentity: 'fn:1', valueIdentity: 'entry-sp:-32',
			typeId: 'type:sha256:one', invalidationDependencies: ['xref:2', 'xref:1', 'xref:1'], evidence: evidence('debug', 1),
		});
		const changed = canonicalizeTypeBinding({
			targetIdentity: 'target:sha256:aaa', scope: 'stack-slot', functionIdentity: 'fn:1', valueIdentity: 'entry-sp:-32',
			typeId: 'type:sha256:two', invalidationDependencies: ['xref:1', 'xref:2'], evidence: evidence('guessed', 9),
		});
		assert.strictEqual(first.bindingId, changed.bindingId);
		assert.notStrictEqual(first.canonicalHash, changed.canonicalHash);
		assert.deepStrictEqual(first.invalidationDependencies, ['xref:1', 'xref:2']);

		const registry = new TypeBindingRegistry();
		registry.apply(first);
		const rejected = registry.apply(changed);
		assert.strictEqual(rejected.status, 'rejected-weaker');
		assert.strictEqual(registry.get(first.bindingId)?.typeId, first.typeId);
		assert.strictEqual(registry.conflicts(first.bindingId).length, 1);
	});

	test('type bindings are target-scoped and function-local scopes cannot omit their function', () => {
		const common = {
			scope: 'stack-slot' as const, functionIdentity: 'fn:1', valueIdentity: 'entry-sp:-32',
			typeId: 'type:sha256:one', evidence: evidence('debug', 1),
		};
		const first = canonicalizeTypeBinding({ ...common, targetIdentity: 'target:sha256:aaa' });
		const otherTarget = canonicalizeTypeBinding({ ...common, targetIdentity: 'target:sha256:bbb' });
		assert.notStrictEqual(first.bindingId, otherTarget.bindingId);
		assert.throws(() => canonicalizeTypeBinding({
			...common, targetIdentity: 'target:sha256:aaa', functionIdentity: undefined,
		}), /require functionIdentity/);
		assert.throws(() => canonicalizeTypeBinding({
			...common, targetIdentity: 'target:sha256:aaa', scope: 'bogus' as never,
		}), /Unknown type binding scope/);
	});

	test('registries recanonicalize supplied records instead of trusting forged IDs and hashes', () => {
		const prototype = canonicalizeFunctionPrototype(buildPrototype('definitive', 1));
		const prototypeRegistry = new PrototypeRegistry();
		const forgedPrototype = { ...prototype, prototypeHash: '0'.repeat(64), canonicalHash: '0'.repeat(64), prototypeId: 'forged' };
		const appliedPrototype = prototypeRegistry.apply(forgedPrototype);
		assert.strictEqual(appliedPrototype.accepted.prototypeHash, prototype.prototypeHash);
		assert.strictEqual(appliedPrototype.accepted.prototypeId, prototype.prototypeId);

		const binding = canonicalizeTypeBinding({
			targetIdentity: 'target:sha256:aaa', scope: 'global', valueIdentity: '0x140010000',
			typeId: 'type:sha256:one', evidence: evidence('definitive', 1),
		});
		const bindingRegistry = new TypeBindingRegistry();
		const forgedBinding = { ...binding, bindingId: 'forged', canonicalHash: 'f'.repeat(64) };
		const appliedBinding = bindingRegistry.apply(forgedBinding);
		assert.strictEqual(appliedBinding.accepted.bindingId, binding.bindingId);
		assert.strictEqual(appliedBinding.accepted.canonicalHash, binding.canonicalHash);
	});

	test('canonical facts and registry views are deeply immutable', () => {
		const type = canonicalizeSemanticType({ kind: 'integer', sizeBits: 32, signed: true }, evidence());
		assert.strictEqual(Object.isFrozen(type), true);
		assert.strictEqual(Object.isFrozen(type.evidence), true);
		assert.throws(() => { (type as { sizeBits?: number }).sizeBits = 64; }, TypeError);

		const registry = new PrototypeRegistry();
		const prototype = registry.apply(buildPrototype('definitive', 1)).accepted;
		assert.strictEqual(Object.isFrozen(prototype), true);
		assert.strictEqual(Object.isFrozen(prototype.parameters), true);
		assert.strictEqual(Object.isFrozen(prototype.parameters[0]), true);
		assert.throws(() => { (prototype.parameters[0] as { name: string }).name = 'mutated'; }, TypeError);
		assert.strictEqual(registry.get(prototype.targetIdentity, prototype.functionIdentity)?.parameters[0].name, 'buffer');
	});

	test('schema and canonical IDs are byte-identical on independent reruns', () => {
		const firstType = parseLegacyCType('const uint8_t * restrict', evidence('signature', 5, 'headers'));
		const secondType = parseLegacyCType(' const   uint8_t*restrict ', evidence('definitive', 99, 'analyst'));
		assert.strictEqual(firstType.type.typeId, secondType.type.typeId);
		assert.strictEqual(firstType.type.canonicalSerialization, secondType.type.canonicalSerialization);
		assert.strictEqual(SEMANTIC_SCHEMA_VERSION, 2);
	});
});
