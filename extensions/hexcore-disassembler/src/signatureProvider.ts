/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import type { DisassemblerEngine } from './disassemblerEngine';
import { lookupApi } from './peApiDatabase';
import { SemanticCommandService } from './semanticCommandService';
import type { CallingConventionId } from './semanticModel';

export interface SignatureProviderFact {
	providerKind: 'signature';
	providerId: string;
	functionIdentity: string;
	functionAddress?: string;
	returnType: string;
	parameters: readonly { ordinal: number; name: string; type: string }[];
	callingConventionId: CallingConventionId;
}

export interface SignatureProviderResult {
	status: 'ok' | 'partial';
	providerId: string;
	importCount: number;
	matchedCount: number;
	unmatched: readonly string[];
	facts: readonly SignatureProviderFact[];
	storeHash: string;
}

export function applyImportSignatureProvider(engine: DisassemblerEngine): SignatureProviderResult {
	const session = engine.getSessionStore();
	if (!session) { throw new Error('Signature provider requires a bound HXDB session.'); }
	const providerId = 'hexcore:windows-api-signatures:v1';
	const service = new SemanticCommandService(session, { producer: providerId, typeNamespace: 'windows-api-signatures' });
	const convention: CallingConventionId = engine.getArchitecture() === 'x64' ? 'win64' : 'stdcall';
	const facts: SignatureProviderFact[] = [];
	const unmatched: string[] = [];
	let importCount = 0;
	for (const library of engine.getImports()) {
		for (const imported of library.functions) {
			importCount++;
			const signature = lookupApi(imported.name);
			if (!signature) { unmatched.push(`${library.name}!${imported.name}`); continue; }
			const fact: SignatureProviderFact = {
				providerKind: 'signature', providerId,
				functionIdentity: `import:${library.name.toLowerCase()}!${imported.name.toLowerCase()}`,
				...(imported.address > 0 ? { functionAddress: `0x${imported.address.toString(16)}` } : {}),
				returnType: signature.returnType,
				parameters: signature.parameters.map((parameter, ordinal) => ({ ordinal, name: parameter.name, type: parameter.type })),
				callingConventionId: convention,
			};
			service.applyPrototype({
				functionIdentity: fact.functionIdentity,
				...(fact.functionAddress ? { functionAddress: fact.functionAddress } : {}),
				returnType: fact.returnType,
				parameters: fact.parameters.map(parameter => ({
					...parameter,
					abiValueClass: 'integer' as const,
					abiSizeBits: engine.getArchitecture() === 'x64' ? 64 : 32,
				})),
				callingConventionId: fact.callingConventionId,
				evidence: { strength: 'signature', source: 'signature', producer: providerId, generation: engine.getAnalysisGeneration() },
			});
			facts.push(fact);
		}
	}
	return {
		status: unmatched.length === 0 ? 'ok' : 'partial', providerId, importCount, matchedCount: facts.length,
		unmatched: unmatched.sort(), facts, storeHash: session.getSemanticStore().exportHash(),
	};
}
