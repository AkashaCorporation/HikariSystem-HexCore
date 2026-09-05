/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
	SemanticTypeCatalog,
	canonicalSerialize,
	canonicalizeFunctionPrototype,
	canonicalizeSemanticType,
	type SemanticEvidence,
} from './semanticModel';
import {
	SemanticCommandService,
	type ApplyPrototypeRequest,
	type SemanticCommandChangeEvent,
} from './semanticCommandService';
import { SessionStore } from './sessionStore';

const functionIdentity = '0x1400f2fc0';

function derivedEvidence(): SemanticEvidence {
	return {
		strength: 'derived',
		source: 'abi-recovery',
		producer: 'r32-test:weaker-recovery',
		generation: 4,
	};
}

function makeBinary(directory: string): string {
	const binaryPath = path.join(directory, 'fixture.bin');
	fs.writeFileSync(binaryPath, Buffer.from('hexcore-semantic-command-r32-fixture', 'ascii'));
	return binaryPath;
}

function seedWeakerPrototype(session: SessionStore): void {
	const store = session.getSemanticStore();
	const evidence = derivedEvidence();
	const catalog = new SemanticTypeCatalog(store.targetIdentity, 'r32-test-weaker');
	const returnType = catalog.parseLegacyCType('int32_t', evidence, {
		targetIdentity: store.targetIdentity,
		nominalScope: 'r32-test-weaker',
	});
	const parameterType = catalog.parseLegacyCType('void *', evidence, {
		targetIdentity: store.targetIdentity,
		nominalScope: 'r32-test-weaker',
	});
	store.writeBatch({
		types: [...returnType.types, ...parameterType.types],
		prototypes: [canonicalizeFunctionPrototype({
			targetIdentity: store.targetIdentity,
			functionIdentity,
			functionAddress: functionIdentity,
			returnTypeId: returnType.rootTypeId,
			callingConventionId: 'win64',
			parameters: [{
				ordinal: 0,
				stableIdentity: 'legacy-buffer',
				name: 'unknown_buffer',
				typeId: parameterType.rootTypeId,
				location: { kind: 'register', registers: ['rcx'] },
			}],
			evidence,
		})],
	});
}

function analystPrototypeRequest(): ApplyPrototypeRequest {
	return {
		functionIdentity,
		functionAddress: functionIdentity,
		returnType: 'bool',
		callingConventionId: 'win64',
		parameters: [
			{
				ordinal: 0,
				stableIdentity: 'path-output',
				stableIdentityAliases: ['header:param:dst'],
				abiValueClass: 'integer',
				abiSizeBits: 64,
				abiAlignBits: 64,
				name: 'destination',
				type: 'wchar_t *',
				direction: 'inout',
				optional: false,
				nullable: false,
				buffer: { kind: 'elements', countParameterOrdinal: 1 },
				ownership: 'borrow',
				lifetime: 'call',
				hiddenThis: false,
				hiddenSret: false,
				compilerGenerated: false,
			},
			{
				ordinal: 1,
				stableIdentity: 'path-capacity',
				name: 'capacity',
				type: 'size_t',
				direction: 'in',
				optional: false,
				nullable: false,
				ownership: 'none',
				lifetime: 'call',
			},
		],
		variadic: false,
		noreturn: false,
		method: false,
		staticMethod: false,
	};
}

suite('R32 semantic command service', function () {
	this.timeout(20_000);
	let tempRoot = '';
	let firstDir = '';
	let secondDir = '';
	let firstSession: SessionStore | undefined;
	let secondSession: SessionStore | undefined;

	setup(() => {
		tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-semantic-command-'));
		firstDir = path.join(tempRoot, 'first');
		secondDir = path.join(tempRoot, 'second');
		fs.mkdirSync(firstDir);
		fs.mkdirSync(secondDir);
	});

	teardown(() => {
		try { secondSession?.dispose(); } catch { /* best-effort test cleanup */ }
		try { firstSession?.dispose(); } catch { /* best-effort test cleanup */ }
		secondSession = undefined;
		firstSession = undefined;
		const resolved = path.resolve(tempRoot);
		const tempPrefix = `${path.resolve(os.tmpdir())}${path.sep}`;
		if (resolved.startsWith(tempPrefix)) {
			fs.rmSync(resolved, { recursive: true, force: true });
		}
	});

	test('applies, edits, explains, exports and imports complete prototypes deterministically', () => {
		firstSession = new SessionStore(makeBinary(firstDir));
		seedWeakerPrototype(firstSession);
		const callbackTrace: string[] = [];
		const callbackEvents: SemanticCommandChangeEvent[] = [];
		const record = (name: string) => (event: SemanticCommandChangeEvent): void => {
			callbackTrace.push(`${name}:${event.command}:${event.functionIdentity}`);
			callbackEvents.push(event);
		};
		const service = new SemanticCommandService(firstSession, {
			producer: 'r32-test:analyst-command',
			callbacks: {
				onGeneration: record('generation'),
				onInvalidate: record('invalidate'),
				onPropagateConsumers: record('propagate'),
			},
		});

		const applied = service.applyPrototype(analystPrototypeRequest());
		assert.strictEqual(applied.ok, true);
		assert.strictEqual(applied.changed, true);
		assert.strictEqual(applied.propagationComplete, true);
		assert.deepStrictEqual(applied.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['rcx'] },
			{ kind: 'register', registers: ['rdx'] },
		]);
		assert.deepStrictEqual(applied.inferredLocations.map(item => item.ordinal), [0, 1]);
		const firstParameter = applied.prototype.parameters[0];
		assert.strictEqual(firstParameter.stableIdentity, 'path-output');
		assert.deepStrictEqual(firstParameter.stableIdentityAliases, ['header:param:dst']);
		assert.strictEqual(firstParameter.abiValueClass, 'integer');
		assert.strictEqual(firstParameter.abiSizeBits, 64);
		assert.strictEqual(firstParameter.abiAlignBits, 64);
		assert.strictEqual(firstParameter.name, 'destination');
		assert.strictEqual(firstParameter.direction, 'inout');
		assert.strictEqual(firstParameter.optional, false);
		assert.strictEqual(firstParameter.nullable, false);
		assert.deepStrictEqual(firstParameter.buffer, { kind: 'elements', countParameterOrdinal: 1 });
		assert.strictEqual(firstParameter.ownership, 'borrow');
		assert.strictEqual(firstParameter.lifetime, 'call');
		assert.strictEqual(firstParameter.hiddenThis, false);
		assert.strictEqual(firstParameter.hiddenSret, false);
		assert.strictEqual(firstParameter.compilerGenerated, false);
		assert.strictEqual(applied.prototype.evidence.userDefined, true);
		assert.strictEqual(
			firstSession.getSemanticStore().getType(applied.prototype.returnTypeId)?.evidence.generation,
			applied.prototype.evidence.generation,
			'new types and their prototype must share the command generation',
		);
		assert.ok(applied.prototype.evidenceSet.some(evidence => evidence.producer === 'r32-test:weaker-recovery'));
		assert.ok(applied.conflicts.some(conflict => conflict.reason === 'stronger-evidence'));
		assert.deepStrictEqual(callbackTrace, [
			`generation:applyPrototype:${functionIdentity}`,
			`invalidate:applyPrototype:${functionIdentity}`,
			`propagate:applyPrototype:${functionIdentity}`,
		]);

		const callbackCount = callbackTrace.length;
		const repeated = service.applyPrototype(analystPrototypeRequest());
		assert.strictEqual(repeated.changed, false);
		assert.strictEqual(repeated.prototype.prototypeHash, applied.prototype.prototypeHash);
		assert.strictEqual(callbackTrace.length, callbackCount, 'idempotent edits must not invalidate consumers');

		const convention = service.setCallingConvention({
			functionIdentity,
			callingConventionId: 'sysv64',
		});
		assert.strictEqual(convention.changed, true);
		assert.strictEqual(convention.prototype.callingConventionId, 'sysv64');
		assert.deepStrictEqual(convention.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['rdi'] },
			{ kind: 'register', registers: ['rsi'] },
		]);
		assert.strictEqual(convention.inferredLocations.length, 2);

		const wcharPointerId = convention.prototype.parameters[0].typeId;
		const parameterEdit = service.setParameter({
			functionIdentity,
			ordinal: 0,
			parameter: {
				stableIdentity: 'path-output',
				stableIdentityAliases: ['header:param:dst', 'analyst:param:output'],
				abiValueClass: 'integer',
				abiSizeBits: 64,
				abiAlignBits: 64,
				name: 'output_path',
				type: { typeId: wcharPointerId },
				location: { kind: 'register', registers: ['rdi'] },
				direction: 'out',
				optional: true,
				nullable: true,
				buffer: { kind: 'elements', countParameterOrdinal: 1 },
				ownership: 'transfer',
				lifetime: 'heap',
				hiddenThis: false,
				hiddenSret: false,
				compilerGenerated: true,
			},
		});
		const edited = parameterEdit.prototype.parameters[0];
		assert.strictEqual(edited.parameterId, convention.prototype.parameters[0].parameterId, 'stable parameter identity must survive edits');
		assert.strictEqual(edited.name, 'output_path');
		assert.deepStrictEqual(edited.stableIdentityAliases, ['analyst:param:output', 'header:param:dst']);
		assert.strictEqual(edited.typeId, wcharPointerId);
		assert.deepStrictEqual(edited.location, { kind: 'register', registers: ['rdi'] });
		assert.strictEqual(edited.direction, 'out');
		assert.strictEqual(edited.optional, true);
		assert.strictEqual(edited.nullable, true);
		assert.deepStrictEqual(edited.buffer, { kind: 'elements', countParameterOrdinal: 1 });
		assert.strictEqual(edited.ownership, 'transfer');
		assert.strictEqual(edited.lifetime, 'heap');
		assert.strictEqual(edited.compilerGenerated, true);

		const explanation = service.explainPrototype({ functionIdentity });
		assert.strictEqual(explanation.prototype.prototypeHash, parameterEdit.prototype.prototypeHash);
		assert.strictEqual(explanation.abi.id, 'sysv64');
		assert.strictEqual(explanation.returnType?.kind, 'bool');
		assert.strictEqual(explanation.parameters[0].type?.kind, 'pointer');
		assert.ok(explanation.conflicts.length >= 1);
		assert.ok(explanation.generations.length >= 3);
		assert.ok(explanation.dependencies.some(dependency => dependency.dependencyKey === wcharPointerId));

		const clear = service.clearOverride({ functionIdentity });
		assert.strictEqual(clear.ok, true);
		assert.strictEqual(clear.status, 'restored');
		if (!clear.changed) { throw new Error('clearOverride did not restore the inferred prototype'); }
		assert.strictEqual(clear.previousPrototype.prototypeHash, parameterEdit.prototype.prototypeHash);
		assert.strictEqual(clear.prototype?.evidence.producer, 'r32-test:weaker-recovery');
		assert.strictEqual(clear.prototype?.evidence.userDefined, undefined);
		assert.strictEqual(clear.propagationComplete, true);
		assert.ok(clear.conflicts.length >= 1);
		assert.ok(clear.generations.some(generation => generation.status === 'restored-after-override'));
		assert.strictEqual(
			service.explainPrototype({ functionIdentity }).prototype.prototypeHash,
			clear.prototype?.prototypeHash,
			'accepted state must expose the prior inferred prototype',
		);
		assert.deepStrictEqual(callbackTrace.slice(-3), [
			`generation:clearOverride:${functionIdentity}`,
			`invalidate:clearOverride:${functionIdentity}`,
			`propagate:clearOverride:${functionIdentity}`,
		]);
		assert.deepStrictEqual(service.clearOverride({ functionIdentity: '0x140000000' }), {
			ok: true,
			command: 'clearOverride',
			status: 'no-override',
			changed: false,
			reason: 'No accepted prototype exists.',
		});

		const exported = service.export();
		assert.strictEqual(exported.contentHash.length, 64);
		assert.strictEqual(service.exportCanonical(), service.exportCanonical());
		secondSession = new SessionStore(makeBinary(secondDir));
		const importTrace: string[] = [];
		const importedService = new SemanticCommandService(secondSession, {
			callbacks: {
				onGeneration: event => importTrace.push(`generation:${event.functionIdentity}`),
				onInvalidate: event => importTrace.push(`invalidate:${event.functionIdentity}`),
				onPropagateConsumers: event => importTrace.push(`propagate:${event.functionIdentity}`),
			},
		});
		const imported = importedService.import(service.exportCanonical());
		assert.strictEqual(imported.ok, true);
		assert.strictEqual(imported.contentHash, exported.contentHash);
		assert.strictEqual(imported.prototypeCount, 1);
		assert.strictEqual(imported.changedPrototypeCount, 1);
		assert.strictEqual(imported.propagationComplete, true);
		assert.deepStrictEqual(importTrace, [
			`generation:${functionIdentity}`,
			`invalidate:${functionIdentity}`,
			`propagate:${functionIdentity}`,
		]);
		assert.strictEqual(importedService.export().contentHash, exported.contentHash);
		assert.strictEqual(
			canonicalSerialize(importedService.explainPrototype({ functionIdentity }).prototype),
			canonicalSerialize(service.explainPrototype({ functionIdentity }).prototype),
		);
		const tampered = { ...exported, contentHash: '0'.repeat(64) };
		assert.throws(() => importedService.import(tampered), /content hash mismatch/);
		assert.ok(callbackEvents.every(event => event.transactionHash.length === 64));
	});

	test('clearOverride restores equivalent inferred semantics from record-coupled fact history', () => {
		firstSession = new SessionStore(makeBinary(firstDir));
		const service = new SemanticCommandService(firstSession, {
			producer: 'r32-test:equivalent-analyst',
		});
		const request: ApplyPrototypeRequest = {
			functionIdentity: '0x401002',
			returnType: 'int32_t',
			callingConventionId: 'cdecl',
			parameters: [],
		};
		const inferred = service.applyPrototype({ ...request, evidence: derivedEvidence() });
		assert.strictEqual(inferred.prototype.evidence.userDefined, undefined);
		const override = service.applyPrototype(request);
		assert.strictEqual(override.prototype.prototypeHash, inferred.prototype.prototypeHash);
		assert.strictEqual(override.prototype.evidence.userDefined, true);
		assert.ok(override.prototype.evidenceSet.some(evidence => evidence.producer === 'r32-test:weaker-recovery'));

		const cleared = service.clearOverride({ functionIdentity: request.functionIdentity });
		assert.strictEqual(cleared.status, 'restored');
		if (!cleared.changed || !cleared.prototype) {
			throw new Error('Equivalent inferred prototype was not restored');
		}
		assert.strictEqual(cleared.prototype.prototypeHash, inferred.prototype.prototypeHash);
		assert.strictEqual(cleared.prototype.evidence.producer, 'r32-test:weaker-recovery');
		assert.strictEqual(cleared.prototype.evidence.userDefined, undefined);
	});

	test('fails closed when an ABI location or semantic type cannot be inferred honestly', () => {
		firstSession = new SessionStore(makeBinary(firstDir));
		const service = new SemanticCommandService(firstSession);
		const analystOnly = service.applyPrototype({
			functionIdentity: '0x401001',
			returnType: 'void',
			callingConventionId: 'cdecl',
			parameters: [],
		});
		assert.strictEqual(analystOnly.prototype.evidence.userDefined, true);
		const removed = service.clearOverride({ functionIdentity: '0x401001' });
		assert.strictEqual(removed.ok, true);
		assert.strictEqual(removed.status, 'removed');
		assert.strictEqual(removed.changed, true);
		if (!removed.changed) { throw new Error('clearOverride did not remove an override without history'); }
		assert.strictEqual(removed.prototype, undefined);
		assert.strictEqual(removed.propagationComplete, false);
		assert.strictEqual(firstSession.getSemanticStore().getPrototype('0x401001'), undefined);
		assert.ok(removed.generations.some(generation => generation.status === 'removed-user-override'));
		assert.throws(() => service.applyPrototype({
			functionIdentity: '0x401000',
			returnType: 'void',
			callingConventionId: 'usercall',
			parameters: [{ ordinal: 0, name: 'value', type: 'uint32_t' }],
		}), /usercall parameter locations are explicit/);
		assert.throws(() => service.applyPrototype({
			functionIdentity: '0x401004',
			returnType: 'void',
			callingConventionId: 'win64',
			parameters: [{ ordinal: 0, name: 'opaque', type: 'struct NotDefined' }],
		}), /ABI location for .* parameter 0 is indeterminate/);
		assert.throws(() => service.applyPrototype({
			functionIdentity: '0x401008',
			returnType: { typeId: 'type:sha256:missing' },
			callingConventionId: 'cdecl',
			parameters: [],
		}), /Unknown semantic type ID/);

		const cdecl = service.applyPrototype({
			functionIdentity: '0x40100c',
			returnType: 'int32_t',
			callingConventionId: 'cdecl',
			parameters: [
				{ ordinal: 0, name: 'left', type: 'uint32_t' },
				{ ordinal: 1, name: 'right', type: 'uint64_t' },
			],
		});
		assert.deepStrictEqual(cdecl.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4 },
			{ kind: 'stack', base: 'entry-sp', offsetBytes: 8, sizeBytes: 8 },
		]);
		assert.strictEqual(cdecl.propagationComplete, false, 'missing consumer callbacks must remain explicit');

		const store = firstSession.getSemanticStore();
		const typeEvidence: SemanticEvidence = {
			strength: 'definitive', source: 'analyst', producer: 'r32-test:abi-types', generation: 1, userDefined: true,
		};
		const float64 = canonicalizeSemanticType({ kind: 'float', name: 'double', sizeBits: 64, alignBits: 64 }, typeEvidence);
		const vector128 = canonicalizeSemanticType({ kind: 'vector', targetTypeId: float64.typeId, count: 2, sizeBits: 128, alignBits: 128 }, typeEvidence);
		const uint32 = canonicalizeSemanticType({ kind: 'integer', name: 'uint32_t', sizeBits: 32, alignBits: 32, signed: false }, typeEvidence);
		const uint64 = canonicalizeSemanticType({ kind: 'integer', name: 'uint64_t', sizeBits: 64, alignBits: 64, signed: false }, typeEvidence);
		store.writeBatch({ types: [float64, vector128, uint32, uint64] });
		const sysvMixed = service.applyPrototype({
			functionIdentity: '0x401010',
			returnType: 'void',
			callingConventionId: 'sysv64',
			parameters: [
				{ ordinal: 0, name: 'scalar', type: { typeId: float64.typeId } },
				{ ordinal: 1, name: 'vector', type: { typeId: vector128.typeId } },
			],
		});
		assert.deepStrictEqual(sysvMixed.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['xmm0'] },
			{ kind: 'register', registers: ['xmm1'] },
		], 'floating and vector banks must not alias the same physical SIMD register');

		const aapcsAligned = service.applyPrototype({
			functionIdentity: '0x401014',
			returnType: 'void',
			callingConventionId: 'aapcs32',
			parameters: [
				{ ordinal: 0, name: 'word', type: { typeId: uint32.typeId } },
				{ ordinal: 1, name: 'wide', type: { typeId: uint64.typeId } },
			],
		});
		assert.deepStrictEqual(aapcsAligned.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['r0'] },
			{ kind: 'split', parts: [
				{ kind: 'register', registers: ['r2'] },
				{ kind: 'register', registers: ['r3'] },
			] },
		]);
	});

	test('allocates every required R32 ABI family without overstating architecture defaults', () => {
		firstSession = new SessionStore(makeBinary(firstDir));
		const service = new SemanticCommandService(firstSession);
		const apply = (
			identity: string,
			callingConventionId: ApplyPrototypeRequest['callingConventionId'],
			parameters: ApplyPrototypeRequest['parameters'],
			options: Partial<ApplyPrototypeRequest> = {},
		) => service.applyPrototype({
			functionIdentity: identity,
			returnType: 'uint32_t',
			callingConventionId,
			parameters,
			...options,
		});

		for (const [index, convention] of (['cdecl', 'stdcall'] as const).entries()) {
			const result = apply(`0x40200${index}`, convention, [
				{ ordinal: 0, name: 'first', type: 'uint32_t' },
				{ ordinal: 1, name: 'second', type: 'uint32_t' },
			]);
			assert.deepStrictEqual(result.prototype.parameters.map(parameter => parameter.location), [
				{ kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4 },
				{ kind: 'stack', base: 'entry-sp', offsetBytes: 8, sizeBytes: 4 },
			]);
		}

		const fastcall = apply('0x402010', 'fastcall', [
			{ ordinal: 0, name: 'first', type: 'uint32_t' },
			{ ordinal: 1, name: 'second', type: 'uint32_t' },
			{ ordinal: 2, name: 'third', type: 'uint32_t' },
		]);
		assert.deepStrictEqual(fastcall.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['ecx'] },
			{ kind: 'register', registers: ['edx'] },
			{ kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4 },
		]);

		const thiscall = apply('0x402020', 'thiscall', [
			{ ordinal: 0, stableIdentity: 'this', name: 'this', type: 'void *', hiddenThis: true },
			{ ordinal: 1, name: 'value', type: 'uint32_t' },
		], { method: true });
		assert.deepStrictEqual(thiscall.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'implicit', role: 'this', register: 'ecx' },
			{ kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4 },
		]);

		const vectorcall = apply('0x402030', 'vectorcall', [
			{ ordinal: 0, name: 'scalar', type: 'double' },
			{ ordinal: 1, name: 'flags', type: 'uint32_t' },
		]);
		assert.deepStrictEqual(vectorcall.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['xmm0'] },
			{ kind: 'register', registers: ['ecx'] },
		]);

		const win64 = apply('0x402040', 'win64', [
			{ ordinal: 0, name: 'ratio', type: 'double' },
			{ ordinal: 1, name: 'flags', type: 'uint64_t' },
			{ ordinal: 4, name: 'tail', type: 'uint64_t' },
		]);
		assert.deepStrictEqual(win64.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['xmm0'] },
			{ kind: 'register', registers: ['rdx'] },
			{ kind: 'stack', base: 'entry-sp', offsetBytes: 40, sizeBytes: 8 },
		]);

		const sysv64 = apply('0x402050', 'sysv64', [
			{ ordinal: 0, name: 'flags', type: 'uint64_t' },
			{ ordinal: 1, name: 'ratio', type: 'double' },
		]);
		assert.deepStrictEqual(sysv64.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['rdi'] },
			{ kind: 'register', registers: ['xmm0'] },
		]);

		const aapcs32 = apply('0x402060', 'aapcs32', [
			{ ordinal: 0, name: 'flags', type: 'uint32_t' },
		]);
		assert.deepStrictEqual(aapcs32.prototype.parameters[0].location, { kind: 'register', registers: ['r0'] });
		const aapcs64 = apply('0x402070', 'aapcs64', [
			{ ordinal: 0, name: 'flags', type: 'uint64_t' },
			{ ordinal: 1, name: 'ratio', type: 'double' },
		]);
		assert.deepStrictEqual(aapcs64.prototype.parameters.map(parameter => parameter.location), [
			{ kind: 'register', registers: ['x0'] },
			{ kind: 'register', registers: ['v0'] },
		]);

		const usercall = apply('0x402080', 'usercall', [{
			ordinal: 0,
			name: 'explicit_value',
			type: 'uint64_t',
			location: { kind: 'register', registers: ['r10'] },
		}]);
		assert.deepStrictEqual(usercall.prototype.parameters[0].location, { kind: 'register', registers: ['r10'] });

		const variadicFallback = apply('0x402090', 'fastcall', [{
			ordinal: 0, name: 'format', type: 'const char *',
		}], { variadic: true });
		assert.strictEqual(variadicFallback.prototype.callingConventionId, 'cdecl');
		assert.deepStrictEqual(variadicFallback.prototype.parameters[0].location, {
			kind: 'stack', base: 'entry-sp', offsetBytes: 4, sizeBytes: 4,
		});
	});
});
