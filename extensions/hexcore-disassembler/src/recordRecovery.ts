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
	type SemanticTypeMemberSpec,
} from './semanticModel';
import type { SemanticStore } from './semanticStore';
import type { FieldAccessEffect, FunctionPropagationSummary } from './wholeProgramPropagation';

export const RECORD_RECOVERY_SCHEMA_VERSION = 1 as const;

export interface RecoveredFieldObservation {
	functionIdentity: string;
	objectIdentity: string;
	fieldIdentity: string;
	offsetBytes: number;
	widthBits?: number;
	access: FieldAccessEffect['access'];
	typeId?: string;
	sameObjectProven: boolean;
}

export interface RecordRecoveryGroup {
	objectIdentity: string;
	status: 'promoted' | 'candidate' | 'blocked-overlap';
	sameObjectProven: boolean;
	observations: readonly RecoveredFieldObservation[];
	overlapCandidates: readonly { leftFieldIdentity: string; rightFieldIdentity: string; reason: string }[];
	recoveredTypeId?: string;
	reason: string;
}

export interface RecordRecoveryResult {
	schemaVersion: typeof RECORD_RECOVERY_SCHEMA_VERSION;
	status: 'ok' | 'partial';
	generation: number;
	groupCount: number;
	promotedCount: number;
	groups: readonly RecordRecoveryGroup[];
	transactionHash?: string;
	resultHash: string;
}

function compareAscii(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }
function sha256(value: string): string { return crypto.createHash('sha256').update(value).digest('hex'); }

function observationObjectIdentity(summary: FunctionPropagationSummary, field: FieldAccessEffect): string | undefined {
	if (!field.base.functionIdentity || field.base.functionIdentity !== summary.functionIdentity) { return undefined; }
	const fact = summary.valueFacts.find(candidate => candidate.value.identity === field.base.identity);
	if (fact?.pointsTo.length === 1) { return `points-to:${fact.pointsTo[0]}`; }
	return `scoped-value:${summary.functionIdentity}:${field.base.kind}:${field.base.identity}`;
}

function collectObservations(summaries: readonly FunctionPropagationSummary[]): RecoveredFieldObservation[] {
	const result: RecoveredFieldObservation[] = [];
	for (const summary of summaries) {
		for (const field of summary.fieldAccesses) {
			const objectIdentity = observationObjectIdentity(summary, field);
			const widthBits = field.value?.widthBits;
			result.push({
				functionIdentity: summary.functionIdentity,
				objectIdentity: objectIdentity ?? `unproven:${summary.functionIdentity}:${field.base.identity}`,
				fieldIdentity: field.fieldIdentity,
				offsetBytes: field.offsetBytes,
				...(widthBits ? { widthBits } : {}),
				access: field.access,
				...(field.typeId ? { typeId: field.typeId } : {}),
				sameObjectProven: objectIdentity !== undefined,
			});
		}
	}
	return result.sort((left, right) => compareAscii(left.objectIdentity, right.objectIdentity)
		|| left.offsetBytes - right.offsetBytes || compareAscii(left.fieldIdentity, right.fieldIdentity));
}

function overlapCandidates(observations: readonly RecoveredFieldObservation[]) {
	const result: Array<{ leftFieldIdentity: string; rightFieldIdentity: string; reason: string }> = [];
	for (let leftIndex = 0; leftIndex < observations.length; leftIndex++) {
		const left = observations[leftIndex];
		if (!left.widthBits) { continue; }
		for (let rightIndex = leftIndex + 1; rightIndex < observations.length; rightIndex++) {
			const right = observations[rightIndex];
			if (!right.widthBits || left.fieldIdentity === right.fieldIdentity) { continue; }
			const leftStart = left.offsetBytes * 8;
			const rightStart = right.offsetBytes * 8;
			if (leftStart < rightStart + right.widthBits && rightStart < leftStart + left.widthBits) {
				result.push({
					leftFieldIdentity: left.fieldIdentity,
					rightFieldIdentity: right.fieldIdentity,
					reason: 'Overlapping incompatible observations require an explicit union candidate.',
				});
			}
		}
	}
	return result;
}

export function recoverRecordsFromPropagation(store: SemanticStore, generation: number): RecordRecoveryResult {
	if (!Number.isSafeInteger(generation) || generation < 0) { throw new Error('Record recovery generation must be non-negative.'); }
	const summaries = store.getWholeProgramPropagationStore().listSummaries();
	const observations = collectObservations(summaries);
	const byObject = new Map<string, RecoveredFieldObservation[]>();
	for (const observation of observations) {
		const group = byObject.get(observation.objectIdentity) ?? [];
		group.push(observation);
		byObject.set(observation.objectIdentity, group);
	}
	const evidence: SemanticEvidence = { strength: 'derived', source: 'dataflow', producer: 'hexcore:record-recovery:r35', generation };
	const typesToWrite = new Map<string, CanonicalSemanticType>();
	const groups: RecordRecoveryGroup[] = [];
	for (const [objectIdentity, groupObservations] of [...byObject].sort(([left], [right]) => compareAscii(left, right))) {
		const sameObjectProven = groupObservations.every(item => item.sameObjectProven);
		const usable = groupObservations.filter(item => item.offsetBytes >= 0 && item.widthBits && item.widthBits > 0);
		const overlaps = overlapCandidates(usable);
		if (!sameObjectProven || usable.length < 2) {
			groups.push({
				objectIdentity, status: 'candidate', sameObjectProven, observations: groupObservations,
				overlapCandidates: overlaps,
				reason: !sameObjectProven ? 'Base storage identity is not proven.' : 'At least two bounded field observations are required.',
			});
			continue;
		}
		if (overlaps.length > 0) {
			groups.push({
				objectIdentity, status: 'blocked-overlap', sameObjectProven, observations: groupObservations,
				overlapCandidates: overlaps,
				reason: 'Incompatible overlap retained as a union candidate; no struct was published.',
			});
			continue;
		}
		const uniqueByOffset = new Map<number, RecoveredFieldObservation>();
		for (const observation of usable) {
			const current = uniqueByOffset.get(observation.offsetBytes);
			if (!current || (observation.widthBits ?? 0) > (current.widthBits ?? 0)) { uniqueByOffset.set(observation.offsetBytes, observation); }
		}
		const members: SemanticTypeMemberSpec[] = [];
		for (const observation of [...uniqueByOffset.values()].sort((left, right) => left.offsetBytes - right.offsetBytes)) {
			let typeId = observation.typeId;
			if (!typeId) {
				const integer = canonicalizeSemanticType({
					kind: 'integer', name: `uint${observation.widthBits}_t`, sizeBits: observation.widthBits, alignBits: Math.min(observation.widthBits!, 64), signed: false,
				}, evidence);
				typesToWrite.set(integer.typeId, integer);
				typeId = integer.typeId;
			}
			members.push({
				name: `field_0x${observation.offsetBytes.toString(16)}`,
				typeId,
				bitOffset: observation.offsetBytes * 8,
				bitSize: observation.widthBits,
				evidence,
			});
		}
		const sizeBits = Math.max(...members.map(member => member.bitOffset + (member.bitSize ?? 0)));
		const recovered = canonicalizeSemanticType({
			kind: 'struct',
			name: `inferred_${sha256(objectIdentity).slice(0, 12)}`,
			nominalIdentity: canonicalSerialize({ targetIdentity: store.targetIdentity, scope: 'record-recovery-r35', objectIdentity }),
			sizeBits,
			alignBits: Math.min(64, Math.max(...members.map(member => member.bitSize ?? 8))),
			members,
			dependencies: members.map(member => member.typeId),
		}, evidence);
		typesToWrite.set(recovered.typeId, recovered);
		groups.push({
			objectIdentity, status: 'promoted', sameObjectProven, observations: groupObservations,
			overlapCandidates: [], recoveredTypeId: recovered.typeId,
			reason: 'Multiple bounded field accesses share one proven scoped base identity.',
		});
	}
	const write = typesToWrite.size > 0 ? store.writeBatch({ types: [...typesToWrite.values()] }) : undefined;
	const logical = {
		schemaVersion: RECORD_RECOVERY_SCHEMA_VERSION,
		status: groups.every(group => group.status === 'promoted') ? 'ok' as const : 'partial' as const,
		generation,
		groupCount: groups.length,
		promotedCount: groups.filter(group => group.status === 'promoted').length,
		groups,
		...(write ? { transactionHash: write.transactionHash } : {}),
	};
	return { ...logical, resultHash: sha256(canonicalSerialize(logical)) };
}
