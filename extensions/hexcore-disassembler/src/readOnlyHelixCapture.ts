/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import type { DisassemblerEngine } from './disassemblerEngine';
import { createReadOnlyHelixAnalysisContext, type HelixAnalysisContext } from './helixAnalysisContext';
import { openSemanticQueryView, type SemanticQueryView } from './semanticQueryView';

const captures = new WeakSet<ReadOnlyHelixCapture>();
const token = Symbol('read-only-helix-capture');

/** In-process capability for a pinned native producer, not serializable job input. */
export class ReadOnlyHelixCapture {
	readonly context: HelixAnalysisContext;
	readonly byteSha256: string;
	readonly address: number;
	readonly endExclusive: number;
	readonly #engine: DisassemblerEngine;
	readonly #view: SemanticQueryView;
	readonly #revision: string;
	readonly #instructionSha256: string;
	constructor(engine: DisassemblerEngine, view: SemanticQueryView, address: number, constructionToken: typeof token) {
		if (constructionToken !== token) { throw new Error('Use captureReadOnlyHelixInput'); }
		this.context = createReadOnlyHelixAnalysisContext(engine, address, view);
		this.#engine = engine;
		this.#view = view;
		this.#revision = engine.getSessionStore()!.getSemanticReadRevision();
		this.address = address;
		this.endExclusive = Number.parseInt(this.context.function.end, 16);
		this.byteSha256 = digest(engine.getBytes(address, this.endExclusive - address)!);
		this.#instructionSha256 = instructionDigest(engine, address);
		captures.add(this);
		Object.freeze(this);
	}

	assertCurrent(engine: DisassemblerEngine): void {
		if (!captures.has(this) || engine !== this.#engine) { throw new Error('read-only-helix: foreign capture'); }
		const session = engine.getSessionStore();
		if (!session || session.getSemanticReadRevision() !== this.#revision || engine.getAnalysisGeneration() !== this.#view.identity.engineGeneration) { throw new Error('read-only-helix: captured state is no longer current'); }
		if (engine.getAnalysisImageSha256() !== this.context.target.binarySha256) { throw new Error('read-only-helix: captured image changed'); }
		const current = engine.getFunctionAt(this.address);
		if (!current || current.endAddress !== this.endExclusive || current.size !== this.endExclusive - this.address || current.name !== this.context.function.name || engine.getArchitecture() !== this.#view.identity.architecture) { throw new Error('read-only-helix: function/architecture changed'); }
		if (instructionDigest(engine, this.address) !== this.#instructionSha256) { throw new Error('read-only-helix: accepted instruction model changed'); }
		const bytes = engine.getBytes(this.address, this.endExclusive - this.address);
		if (!bytes || bytes.length !== this.endExclusive - this.address || digest(bytes) !== this.byteSha256) { throw new Error('read-only-helix: captured bytes changed'); }
		const now = openSemanticQueryView(session, { engineGeneration: engine.getAnalysisGeneration() });
		now.assertIdentity(this.#view.identity);
		if (now.identity.sessionId !== this.#view.identity.sessionId) { throw new Error('read-only-helix: session changed'); }
	}

	copyBytes(): Buffer {
		this.assertCurrent(this.#engine);
		return Buffer.from(this.#engine.getBytes(this.address, this.endExclusive - this.address)!);
	}
}

function digest(bytes: Buffer): string { return crypto.createHash('sha256').update(bytes).digest('hex'); }

function instructionDigest(engine: DisassemblerEngine, address: number): string {
	const hash = crypto.createHash('sha256');
	const replacer = (_key: string, value: unknown) => typeof value === 'bigint' ? { bigint: value.toString() } : value;
	for (const instruction of engine.getFunctionAt(address)?.instructions ?? []) { hash.update(JSON.stringify(instruction, replacer)); }
	hash.update(JSON.stringify(engine.peekFunctionBodyCompleteness(address), replacer));
	return hash.digest('hex');
}

export function captureReadOnlyHelixInput(engine: DisassemblerEngine, view: SemanticQueryView, address: number): ReadOnlyHelixCapture {
	return new ReadOnlyHelixCapture(engine, view, address, token);
}
