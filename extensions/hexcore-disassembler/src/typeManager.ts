/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	canonicalSerialize,
	canonicalizeSemanticType,
	type CanonicalSemanticType,
	type SemanticEvidence,
	type SemanticTypeSpec,
} from './semanticModel';
import type { SemanticStore, SemanticTypeDeleteResult } from './semanticStore';

export const TYPE_MANAGER_SCHEMA_VERSION = 1 as const;

export interface TypeManagerExport {
	format: 'hexcore-type-manager-export';
	contentHash: string;
	payload: {
		schemaVersion: typeof TYPE_MANAGER_SCHEMA_VERSION;
		targetIdentity: string;
		types: readonly CanonicalSemanticType[];
	};
}

function sha256(value: string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function analystEvidence(generation: number, producer: string): SemanticEvidence {
	if (!Number.isSafeInteger(generation) || generation < 0) {
		throw new Error('Type-manager generation must be a non-negative safe integer.');
	}
	return { strength: 'definitive', source: 'analyst', producer, generation, userDefined: true };
}

function nominalIdentity(targetIdentity: string, name: string, kind: string): string {
	return canonicalSerialize({ targetIdentity, scope: 'analyst-type-manager', kind, stableName: name });
}

export class TypeManager {
	constructor(private readonly store: SemanticStore, private readonly producer = 'hexcore:type-manager:r35') {}

	list(): CanonicalSemanticType[] { return this.store.listTypes(); }
	get(typeId: string): CanonicalSemanticType | undefined { return this.store.getType(typeId); }

	create(spec: SemanticTypeSpec, generation: number): CanonicalSemanticType {
		const evidence = analystEvidence(generation, this.producer);
		const namedNominal = ['struct', 'union', 'enum'].includes(spec.kind) && spec.name?.trim();
		const candidate = canonicalizeSemanticType({
			...spec,
			...(namedNominal && !spec.nominalIdentity
				? { nominalIdentity: nominalIdentity(this.store.targetIdentity, spec.name!.trim(), spec.kind) }
				: {}),
		}, evidence);
		return this.store.putType(candidate).accepted;
	}

	update(typeId: string, patch: Partial<SemanticTypeSpec>, generation: number): CanonicalSemanticType {
		const current = this.store.getType(typeId);
		if (!current) { throw new Error(`Unknown semantic type ${typeId}.`); }
		const { typeId: _typeId, canonicalHash: _canonicalHash, canonicalSerialization: _serialization,
			evidence: _evidence, evidenceSet: _evidenceSet, ...spec } = current;
		const candidate = canonicalizeSemanticType({ ...spec, ...patch, nominalIdentity: patch.nominalIdentity ?? spec.nominalIdentity },
			analystEvidence(generation, this.producer));
		if (candidate.typeId !== current.typeId) {
			throw new Error('Type update changed its stable identity; create a new type and migrate dependencies explicitly.');
		}
		return this.store.putType(candidate).accepted;
	}

	rename(typeId: string, name: string, generation: number): CanonicalSemanticType {
		const normalized = name.trim();
		if (!normalized) { throw new Error('Type name must not be empty.'); }
		return this.update(typeId, { name: normalized }, generation);
	}

	delete(typeId: string, generation: number): SemanticTypeDeleteResult {
		return this.store.deleteType(typeId, generation);
	}

	undo(typeId: string, generation: number): CanonicalSemanticType {
		const current = this.store.getType(typeId);
		if (!current) { throw new Error(`Unknown semantic type ${typeId}.`); }
		const candidates = this.store.listHistory('type', typeId).flatMap(entry => {
			try {
				const record = JSON.parse(entry.recordJson) as CanonicalSemanticType;
				return record.canonicalHash !== current.canonicalHash ? [record] : [];
			} catch { return []; }
		}).sort((left, right) => right.evidence.generation - left.evidence.generation || (left.canonicalHash < right.canonicalHash ? -1 : 1));
		const previous = candidates[0];
		if (!previous) { throw new Error(`No prior semantic version exists for ${typeId}.`); }
		const { typeId: _typeId, canonicalHash: _hash, canonicalSerialization: _serialization, evidence: _evidence, evidenceSet: _evidenceSet, ...spec } = previous;
		return this.store.putType(canonicalizeSemanticType(spec, analystEvidence(generation, `${this.producer}:undo`))).accepted;
	}

	export(): TypeManagerExport {
		const payload = {
			schemaVersion: TYPE_MANAGER_SCHEMA_VERSION,
			targetIdentity: this.store.targetIdentity,
			types: this.store.listTypes(),
		};
		return { format: 'hexcore-type-manager-export', contentHash: sha256(canonicalSerialize(payload)), payload };
	}

	import(envelope: TypeManagerExport): { changed: number; transactionHash: string; contentHash: string } {
		if (envelope.format !== 'hexcore-type-manager-export' || envelope.payload.schemaVersion !== TYPE_MANAGER_SCHEMA_VERSION) {
			throw new Error('Unsupported type-manager import envelope.');
		}
		if (envelope.payload.targetIdentity !== this.store.targetIdentity) {
			throw new Error('Type-manager import belongs to a different analysis target.');
		}
		const expected = sha256(canonicalSerialize(envelope.payload));
		if (expected !== envelope.contentHash) { throw new Error('Type-manager import content hash mismatch.'); }
		const before = new Map(this.store.listTypes().map(type => [type.typeId, type.canonicalHash]));
		const result = this.store.writeBatch({ types: envelope.payload.types });
		const changed = result.typeResults.filter(item => before.get(item.accepted.typeId) !== item.accepted.canonicalHash).length;
		return { changed, transactionHash: result.transactionHash, contentHash: envelope.contentHash };
	}
}
