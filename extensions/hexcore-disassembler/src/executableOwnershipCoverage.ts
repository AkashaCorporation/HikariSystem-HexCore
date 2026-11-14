/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface OwnershipRange {
	start: number;
	end: number;
}

export interface ExecutableOwnershipInput {
	executableRanges: readonly OwnershipRange[];
	functionRanges: readonly OwnershipRange[];
	decodedInstructionRanges: readonly OwnershipRange[];
	unresolvedIndirectTransfers: number;
	discoveryBudgetPartial: boolean;
}

export interface ExecutableOwnershipCoverage {
	status: 'complete' | 'partial';
	totalExecutableBytes: number;
	ownedRangeBytes: number;
	unownedExecutableBytes: number;
	overlappingOwnedBytes: number;
	decodedInstructionBytes: number;
	rangeOwnershipRatio: number;
	decodedInstructionRatio: number;
	unresolvedIndirectTransfers: number;
	discoveryBudgetPartial: boolean;
	reasonCodes: string[];
}

function validRange(range: OwnershipRange): boolean {
	return Number.isSafeInteger(range.start) && Number.isSafeInteger(range.end) && range.end > range.start;
}

function unionRanges(ranges: readonly OwnershipRange[]): OwnershipRange[] {
	const sorted = ranges.filter(validRange).map(range => ({ ...range })).sort((left, right) =>
		left.start - right.start || left.end - right.end);
	const merged: OwnershipRange[] = [];
	for (const range of sorted) {
		const previous = merged[merged.length - 1];
		if (previous && range.start <= previous.end) {
			previous.end = Math.max(previous.end, range.end);
		} else {
			merged.push(range);
		}
	}
	return merged;
}

function rangeLength(ranges: readonly OwnershipRange[]): number {
	return ranges.reduce((total, range) => total + range.end - range.start, 0);
}

function clipsInside(ranges: readonly OwnershipRange[], executable: readonly OwnershipRange[]): OwnershipRange[] {
	const clips: OwnershipRange[] = [];
	for (const range of ranges) {
		if (!validRange(range)) { continue; }
		for (const section of executable) {
			const start = Math.max(range.start, section.start);
			const end = Math.min(range.end, section.end);
			if (end > start) { clips.push({ start, end }); }
		}
	}
	return clips;
}

function overlappingLength(ranges: readonly OwnershipRange[]): number {
	const events = new Map<number, number>();
	for (const range of ranges) {
		if (!validRange(range)) { continue; }
		events.set(range.start, (events.get(range.start) ?? 0) + 1);
		events.set(range.end, (events.get(range.end) ?? 0) - 1);
	}
	const points = [...events.keys()].sort((left, right) => left - right);
	let active = 0;
	let overlap = 0;
	for (let index = 0; index < points.length; index++) {
		const point = points[index];
		active += events.get(point) ?? 0;
		const next = points[index + 1];
		if (next !== undefined && active > 1) { overlap += next - point; }
	}
	return overlap;
}

export function calculateExecutableOwnershipCoverage(input: ExecutableOwnershipInput): ExecutableOwnershipCoverage {
	const executable = unionRanges(input.executableRanges);
	const totalExecutableBytes = rangeLength(executable);
	const functionClips = clipsInside(input.functionRanges, executable);
	const ownedRangeBytes = rangeLength(unionRanges(functionClips));
	const overlappingOwnedBytes = overlappingLength(functionClips);
	const decodedInstructionBytes = rangeLength(unionRanges(clipsInside(input.decodedInstructionRanges, executable)));
	const unownedExecutableBytes = Math.max(0, totalExecutableBytes - ownedRangeBytes);
	const unresolvedIndirectTransfers = Math.max(0, Math.trunc(input.unresolvedIndirectTransfers));
	const reasonCodes: string[] = [];
	if (unownedExecutableBytes > 0) { reasonCodes.push('unowned-executable-bytes'); }
	if (overlappingOwnedBytes > 0) { reasonCodes.push('overlapping-function-ownership'); }
	if (unresolvedIndirectTransfers > 0) { reasonCodes.push('unresolved-indirect-transfer'); }
	if (input.discoveryBudgetPartial) { reasonCodes.push('discovery-budget-partial'); }
	return {
		status: reasonCodes.length === 0 ? 'complete' : 'partial',
		totalExecutableBytes,
		ownedRangeBytes,
		unownedExecutableBytes,
		overlappingOwnedBytes,
		decodedInstructionBytes,
		rangeOwnershipRatio: totalExecutableBytes > 0 ? ownedRangeBytes / totalExecutableBytes : 1,
		decodedInstructionRatio: totalExecutableBytes > 0 ? decodedInstructionBytes / totalExecutableBytes : 1,
		unresolvedIndirectTransfers,
		discoveryBudgetPartial: input.discoveryBudgetPartial,
		reasonCodes,
	};
}
