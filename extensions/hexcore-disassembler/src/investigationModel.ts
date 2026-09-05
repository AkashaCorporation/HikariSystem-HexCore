/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import {
	analysisObjectIdTargetId,
	createFindingId,
	isAnalysisObjectId,
	type AnalysisTarget,
} from 'hexcore-common';

export type InvestigationPreset = 'custom' | 'health' | 'anti-debug' | 'network' | 'credentials';

export interface InvestigationFunctionRange {
	address: number;
	endAddress: number;
	name: string;
}

export interface InvestigationStringMatch {
	query: string;
	address: number;
	string: string;
	encoding: string;
	references: number[];
}

export interface InvestigationFindingDraft {
	id: string;
	investigationId: string;
	kind: 'string-reference';
	query: string;
	label: string;
	stringAddress: string;
	referenceAddress: string | null;
	functionAddress: string | null;
	functionName: string | null;
	encoding: string;
	evidenceJson: string;
	saved: boolean;
}

const PRESET_QUERIES: Readonly<Record<Exclude<InvestigationPreset, 'custom'>, readonly string[]>> = {
	health: ['health', 'hitpoints', 'hit points', 'damage'],
	'anti-debug': [
		'IsDebuggerPresent',
		'CheckRemoteDebuggerPresent',
		'NtQueryInformationProcess',
		'OutputDebugString',
		'debugger'
	],
	network: ['http://', 'https://', 'socket', 'connect'],
	credentials: ['password', 'passwd', 'token', 'secret']
};

export function resolveInvestigationQueries(preset: InvestigationPreset, customQuery: string): string[] {
	if (preset === 'custom') {
		const query = customQuery.trim();
		return query.length >= 3 ? [query.slice(0, 256)] : [];
	}
	return [...PRESET_QUERIES[preset]];
}

export function buildStringInvestigationFindings(
	investigationId: string,
	matches: readonly InvestigationStringMatch[],
	functions: readonly InvestigationFunctionRange[],
	limit = 250,
	options: { target?: AnalysisTarget } = {}
): InvestigationFindingDraft[] {
	const sortedFunctions = [...functions].sort((a, b) => a.address - b.address);
	const findings: InvestigationFindingDraft[] = [];
	const seen = new Set<string>();

	for (const match of matches) {
		const references = match.references.length > 0 ? [...new Set(match.references)] : [null];
		for (const reference of references) {
			const key = `${match.address}:${reference ?? 'none'}:${match.string}`;
			if (seen.has(key)) {
				continue;
			}
			seen.add(key);

			const owner = reference === null ? undefined : findContainingFunction(sortedFunctions, reference);
			const stringAddress = toHexAddress(match.address);
			const referenceAddress = reference === null ? null : toHexAddress(reference);
			const functionAddress = owner ? toHexAddress(owner.address) : null;
			findings.push({
				id: options.target
					// Contract identity (C1): derived from the target plus the finding
					// subject (string address, reference address, encoding). The same
					// finding rediscovered by a re-run or another investigation keeps
					// its ID, so saved marks and timestamps survive re-recording.
					? createFindingId({
						target: options.target,
						category: 'string-reference',
						subject: { token: `${stringAddress}-${referenceAddress ?? 'none'}-${match.encoding}` },
					})
					// Legacy 24-hex identity for session-less contexts (unit tests).
					: crypto.createHash('sha256')
						.update(`${investigationId}|${key}|${functionAddress ?? ''}`)
						.digest('hex').slice(0, 24),
				investigationId,
				kind: 'string-reference',
				query: match.query,
				label: match.string.slice(0, 1000),
				stringAddress,
				referenceAddress,
				functionAddress,
				functionName: owner?.name ?? null,
				encoding: match.encoding,
				evidenceJson: JSON.stringify({
					query: match.query,
					encoding: match.encoding,
					stringAddress,
					referenceAddress
				}),
				saved: false
			});

			if (findings.length >= Math.max(1, limit)) {
				return findings;
			}
		}
	}

	return findings;
}

function findContainingFunction(
	functions: readonly InvestigationFunctionRange[],
	address: number
): InvestigationFunctionRange | undefined {
	let low = 0;
	let high = functions.length - 1;
	let candidate: InvestigationFunctionRange | undefined;
	while (low <= high) {
		const mid = Math.floor((low + high) / 2);
		const current = functions[mid];
		if (current.address <= address) {
			candidate = current;
			low = mid + 1;
		} else {
			high = mid - 1;
		}
	}
	return candidate && address < candidate.endAddress ? candidate : undefined;
}

function toHexAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}

/**
 * C5 boundary check (3.8.4): a contract finding ID embeds its owning target,
 * so a request referencing another target's finding is rejected with a typed
 * wrong-target error instead of a generic lookup failure. Legacy 24-hex IDs
 * carry no target; the per-binary session DB lookup remains their guard.
 */
export function assertFindingMatchesActiveTarget(
	findingId: string,
	activeTarget: AnalysisTarget | undefined
): void {
	if (!isAnalysisObjectId(findingId)) {
		return;
	}
	const owner = analysisObjectIdTargetId(findingId);
	if (owner && activeTarget && owner !== activeTarget.id) {
		throw new Error(
			`wrong-target: finding belongs to ${owner}, but the active target is ${activeTarget.id}`
		);
	}
}
