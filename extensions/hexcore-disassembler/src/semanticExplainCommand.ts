/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type { DisassemblerEngine } from './disassemblerEngine';
import { openSemanticQueryView } from './semanticQueryView';
import { explainSemanticEntity, type SemanticExplanationKind, type SemanticExplanationRequest } from './semanticExplanation';

export function runSemanticExplainCommand(engine: DisassemblerEngine, arg: Record<string, unknown> = {}) {
	const session = engine.getSessionStore();
	if (!engine.isFileLoaded() || !session) {
		return { success: false, status: 'error', command: 'hexcore.semantic.explain', error: 'Semantic explanation requires an active target-bound session' };
	}
	const expectedInput = arg.expected && typeof arg.expected === 'object' && !Array.isArray(arg.expected) ? arg.expected as Record<string, unknown> : {};
	const expected = {
		...(typeof (arg.targetIdentity ?? expectedInput.targetIdentity) === 'string' ? { targetIdentity: String(arg.targetIdentity ?? expectedInput.targetIdentity) } : {}),
		...(typeof (arg.sessionId ?? expectedInput.sessionId) === 'string' ? { sessionId: String(arg.sessionId ?? expectedInput.sessionId) } : {}),
		...(typeof (arg.generation ?? expectedInput.generation) === 'number' ? { generation: Number(arg.generation ?? expectedInput.generation) } : {}),
		...(typeof (arg.universeSha256 ?? expectedInput.universeSha256) === 'string' ? { universeSha256: String(arg.universeSha256 ?? expectedInput.universeSha256) } : {}),
		...(typeof (arg.snapshotSha256 ?? expectedInput.snapshotSha256) === 'string' ? { snapshotSha256: String(arg.snapshotSha256 ?? expectedInput.snapshotSha256) } : {}),
	};
	const view = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
	const result = explainSemanticEntity(view, {
		kind: arg.kind as SemanticExplanationKind,
		identity: arg.identity as string,
		expected,
		...(typeof arg.maxNodes === 'number' ? { maxNodes: arg.maxNodes } : {}),
		...(typeof arg.maxEdges === 'number' ? { maxEdges: arg.maxEdges } : {}),
		...(typeof arg.maxBytes === 'number' ? { maxBytes: arg.maxBytes } : {}),
	} as SemanticExplanationRequest);
	return { ...result, command: 'hexcore.semantic.explain', targetIdentity: view.identity.targetIdentity,
		generation: view.identity.generation, universeSha256: view.identity.universeSha256, snapshotSha256: view.identity.snapshotSha256 };
}
