/*---------------------------------------------------------------------------------------------
 * Function materialization coverage contract. Pure logic: no VS Code dependency.
 *--------------------------------------------------------------------------------------------*/

export interface FunctionMaterializationInput {
	totalFunctions: number;
	materializedFunctions: number;
	lazyFunctions: number;
	decodeEmptyFunctions: number;
	partialFunctions?: number;
	allowLazy?: boolean;
	allowDecodeEmpty?: boolean;
	minMaterializedRatio?: number;
}

export interface FunctionMaterializationAssessment {
	status: 'ok' | 'partial';
	analysisDepth: 'reconnaissance-only' | 'partial-disassembly' | 'complete-disassembly';
	negativeEvidenceUsable: false;
	materializedFunctionRatio: number;
	materializedFunctions: number;
	lazyFunctions: number;
	decodeEmptyFunctions: number;
	policy: {
		allowLazy: boolean;
		allowDecodeEmpty: boolean;
		minMaterializedRatio: number;
	};
	reason?: string;
}

export interface FunctionMaterializationPolicyOptions {
	allowLazy?: boolean;
	allowDecodeEmpty?: boolean;
	minMaterializedRatio?: number;
}

/** Validate and retain policy fields crossing the headless command boundary. */
export function normalizeFunctionMaterializationPolicy(
	raw: Record<string, unknown>,
): FunctionMaterializationPolicyOptions {
	const normalized: FunctionMaterializationPolicyOptions = {};
	for (const key of ['allowLazy', 'allowDecodeEmpty'] as const) {
		if (raw[key] === undefined) { continue; }
		if (typeof raw[key] !== 'boolean') {
			throw new Error(`Invalid "${key}" option: expected boolean.`);
		}
		normalized[key] = raw[key];
	}
	if (raw.minMaterializedRatio !== undefined) {
		const ratio = raw.minMaterializedRatio;
		if (typeof ratio !== 'number' || !Number.isFinite(ratio) || ratio < 0 || ratio > 1) {
			throw new Error('Invalid "minMaterializedRatio" option: expected a number between 0 and 1.');
		}
		normalized.minMaterializedRatio = ratio;
	}
	return normalized;
}

function count(value: number): number {
	return Number.isFinite(value) ? Math.max(0, Math.trunc(value)) : 0;
}

export function assessFunctionMaterialization(
	input: FunctionMaterializationInput,
): FunctionMaterializationAssessment {
	const totalFunctions = count(input.totalFunctions);
	const materializedFunctions = Math.min(totalFunctions, count(input.materializedFunctions));
	const lazyFunctions = count(input.lazyFunctions);
	const decodeEmptyFunctions = count(input.decodeEmptyFunctions);
	const partialFunctions = count(input.partialFunctions ?? 0);
	const allowLazy = input.allowLazy === true;
	const allowDecodeEmpty = input.allowDecodeEmpty === true;
	const configuredRatio = typeof input.minMaterializedRatio === 'number' && Number.isFinite(input.minMaterializedRatio)
		? input.minMaterializedRatio
		: (allowLazy ? 0 : 1);
	const minMaterializedRatio = Math.max(0, Math.min(1, configuredRatio));
	const materializedFunctionRatio = totalFunctions > 0 ? materializedFunctions / totalFunctions : 1;
	const reasons: string[] = [];
	if (partialFunctions > 0) reasons.push(`${partialFunctions} function body/bodies decoded partially`);

	if (materializedFunctionRatio < minMaterializedRatio) {
		reasons.push(
			`materialized ${(materializedFunctionRatio * 100).toFixed(2)}% ` +
			`(${materializedFunctions}/${totalFunctions}) below required ${(minMaterializedRatio * 100).toFixed(2)}%`,
		);
	}
	if (!allowLazy && lazyFunctions > 0) {
		reasons.push(`${lazyFunctions} function body/bodies remain lazy`);
	}
	if (!allowDecodeEmpty && decodeEmptyFunctions > 0) {
		reasons.push(`${decodeEmptyFunctions} function body/bodies decoded empty`);
	}

	return {
		status: reasons.length > 0 ? 'partial' : 'ok',
		analysisDepth: totalFunctions === 0 || materializedFunctions === 0 ? 'reconnaissance-only'
			: materializedFunctions === totalFunctions && !partialFunctions && !decodeEmptyFunctions && !lazyFunctions
				? 'complete-disassembly' : allowLazy && minMaterializedRatio === 0
					? 'reconnaissance-only' : 'partial-disassembly',
		// Discovery/disassembly alone never proves absence of a behavioral defect.
		negativeEvidenceUsable: false,
		materializedFunctionRatio,
		materializedFunctions,
		lazyFunctions,
		decodeEmptyFunctions,
		policy: { allowLazy, allowDecodeEmpty, minMaterializedRatio },
		...(reasons.length > 0 ? { reason: reasons.join('; ') } : {}),
	};
}
