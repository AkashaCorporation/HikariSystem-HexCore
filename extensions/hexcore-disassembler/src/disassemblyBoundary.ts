export interface InstructionBoundarySpan {
	address: number;
	size: number;
}

export interface InstructionBoundaryAssessment {
	status: 'aligned' | 'mid-instruction' | 'unassessed';
	source: 'materialized-function-body' | 'explicit-range-decoder' | 'none';
	suggestedAddress?: number;
}

export interface InstructionBoundaryContract {
	status: InstructionBoundaryAssessment['status'];
	source: 'materialized-function-body' | 'explicit-range-decoder' | 'lookbehind-decoder' | 'none';
	recoveredByAutoBacktrack: boolean;
	requiresPartial: boolean;
	suggestedAddress?: number;
}

/** Finds a decode anchor immediately after a nearby run of x86 padding. */
export function findPaddingAnchoredDecodeStart(
	bytes: Uint8Array,
	targetOffset: number,
	maxScan: number = 64,
): number | undefined {
	if (!Number.isInteger(targetOffset) || targetOffset <= 0 || targetOffset > bytes.length) {
		return undefined;
	}
	const isPadding = (value: number) => value === 0xcc || value === 0x90;
	const lowerBound = Math.max(0, targetOffset - Math.max(2, maxScan));
	for (let offset = targetOffset - 1; offset > lowerBound; offset--) {
		if (!isPadding(bytes[offset]) || !isPadding(bytes[offset - 1])) {
			continue;
		}
		let runEnd = offset;
		while (runEnd + 1 < targetOffset && isPadding(bytes[runEnd + 1])) {
			runEnd++;
		}
		return runEnd + 1;
	}
	return undefined;
}

/**
 * Checks a requested address against an already materialized function body.
 * This is stronger than decoding from an arbitrary look-behind offset because
 * it uses the instruction boundaries committed to the current analysis universe.
 */
export function assessInstructionBoundary(
	requestedAddress: number,
	instructions: readonly InstructionBoundarySpan[],
	source: 'materialized-function-body' | 'explicit-range-decoder' = 'materialized-function-body',
): InstructionBoundaryAssessment {
	for (const instruction of instructions) {
		if (instruction.address === requestedAddress) {
			return {
				status: 'aligned',
				source,
				suggestedAddress: instruction.address,
			};
		}
		if (instruction.size > 0 &&
			instruction.address < requestedAddress &&
			requestedAddress < instruction.address + instruction.size) {
			return {
				status: 'mid-instruction',
				source,
				suggestedAddress: instruction.address,
			};
		}
	}

	return { status: 'unassessed', source: 'none' };
}

export function resolveInstructionBoundaryContract(input: {
	requestedAddress: number;
	effectiveAddress: number;
	autoBacktrack: boolean;
	instructions: readonly InstructionBoundarySpan[];
	lookbehindAligned: boolean;
	lookbehindSuggestedAddress?: number;
	instructionSource?: 'materialized-function-body' | 'explicit-range-decoder';
}): InstructionBoundaryContract {
	const materialized = assessInstructionBoundary(
		input.requestedAddress,
		input.instructions,
		input.instructionSource,
	);
	const anchoredMidInstruction = input.instructionSource === 'explicit-range-decoder' && !input.lookbehindAligned;
	const status = anchoredMidInstruction
		? 'mid-instruction' as const
		: materialized.status !== 'unassessed'
		? materialized.status
		: input.lookbehindAligned ? 'unassessed' as const : 'mid-instruction' as const;
	const source = anchoredMidInstruction
		? 'lookbehind-decoder' as const
		: materialized.status !== 'unassessed'
		? materialized.source
		: input.lookbehindAligned ? 'none' as const : 'lookbehind-decoder' as const;
	const suggestedAddress = anchoredMidInstruction
		? input.lookbehindSuggestedAddress
		: materialized.suggestedAddress ?? input.lookbehindSuggestedAddress;
	const recoveredByAutoBacktrack = status === 'mid-instruction' &&
		input.autoBacktrack && input.effectiveAddress !== input.requestedAddress;

	return {
		status,
		source,
		recoveredByAutoBacktrack,
		requiresPartial: status === 'mid-instruction' && !recoveredByAutoBacktrack,
		...(suggestedAddress !== undefined ? { suggestedAddress } : {}),
	};
}
