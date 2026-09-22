export interface InstructionBoundarySpan {
	address: number;
	size: number;
}

export interface InstructionBoundaryAssessment {
	status: 'aligned' | 'mid-instruction' | 'unassessed';
	source: 'materialized-function-body' | 'none';
	suggestedAddress?: number;
}

export interface InstructionBoundaryContract {
	status: InstructionBoundaryAssessment['status'];
	source: 'materialized-function-body' | 'lookbehind-decoder' | 'none';
	recoveredByAutoBacktrack: boolean;
	requiresPartial: boolean;
	suggestedAddress?: number;
}

/**
 * Checks a requested address against an already materialized function body.
 * This is stronger than decoding from an arbitrary look-behind offset because
 * it uses the instruction boundaries committed to the current analysis universe.
 */
export function assessInstructionBoundary(
	requestedAddress: number,
	instructions: readonly InstructionBoundarySpan[],
): InstructionBoundaryAssessment {
	for (const instruction of instructions) {
		if (instruction.address === requestedAddress) {
			return {
				status: 'aligned',
				source: 'materialized-function-body',
				suggestedAddress: instruction.address,
			};
		}
		if (instruction.size > 0 &&
			instruction.address < requestedAddress &&
			requestedAddress < instruction.address + instruction.size) {
			return {
				status: 'mid-instruction',
				source: 'materialized-function-body',
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
}): InstructionBoundaryContract {
	const materialized = assessInstructionBoundary(input.requestedAddress, input.instructions);
	const status = materialized.status !== 'unassessed'
		? materialized.status
		: input.lookbehindAligned ? 'unassessed' as const : 'mid-instruction' as const;
	const source = materialized.status !== 'unassessed'
		? materialized.source
		: input.lookbehindAligned ? 'none' as const : 'lookbehind-decoder' as const;
	const suggestedAddress = materialized.suggestedAddress ?? input.lookbehindSuggestedAddress;
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
