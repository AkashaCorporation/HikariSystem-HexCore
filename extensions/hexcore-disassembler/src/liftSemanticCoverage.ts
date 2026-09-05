/*---------------------------------------------------------------------------------------------
 *  Lift semantic coverage classification. Pure logic: no VS Code dependency.
 *--------------------------------------------------------------------------------------------*/

export interface NativeLiftSemanticMetrics {
	decodedInstructions?: number;
	liftedInstructions?: number;
	unsupportedInstructions?: number;
	decodeFailureInstructions?: number;
	semanticCoverage?: number;
	unsupportedOpcodes?: Record<string, number>;
}

export interface LiftSemanticAssessment extends Required<Omit<NativeLiftSemanticMetrics, 'unsupportedOpcodes'>> {
	status: 'ok' | 'partial';
	unsupportedOpcodes: Record<string, number>;
	reason?: string;
}

function finiteCount(value: unknown): number | undefined {
	return typeof value === 'number' && Number.isFinite(value) && value >= 0
		? Math.floor(value)
		: undefined;
}

/** Count calls only; the HandleUnsupported declaration is not an instruction. */
export function countHandleUnsupportedCalls(ir: string): number {
	if (!ir) { return 0; }
	return Array.from(ir.matchAll(/^\s*(?:%[^=\n]+\s*=\s*)?call\b[^\n]*HandleUnsupported/gm)).length;
}

export function assessLiftSemanticCoverage(
	ir: string,
	native: NativeLiftSemanticMetrics = {},
	minimumCoverage = 1,
): LiftSemanticAssessment {
	const fallbackUnsupported = countHandleUnsupportedCalls(ir);
	const unsupportedInstructions = finiteCount(native.unsupportedInstructions) ?? fallbackUnsupported;
	const liftedInstructions = finiteCount(native.liftedInstructions) ?? 0;
	const decodeFailureInstructions = finiteCount(native.decodeFailureInstructions) ?? 0;
	const measuredTotal = liftedInstructions + unsupportedInstructions + decodeFailureInstructions;
	const decodedInstructions = finiteCount(native.decodedInstructions) ?? measuredTotal;
	const nativeCoverage = typeof native.semanticCoverage === 'number' && Number.isFinite(native.semanticCoverage)
		? Math.max(0, Math.min(1, native.semanticCoverage))
		: undefined;
	const semanticCoverage = nativeCoverage ?? (measuredTotal > 0
		? liftedInstructions / measuredTotal
		: (unsupportedInstructions > 0 ? 0 : 1));
	const threshold = Math.max(0, Math.min(1, minimumCoverage));
	const partial = unsupportedInstructions > 0 || decodeFailureInstructions > 0 || semanticCoverage < threshold;
	const reasons: string[] = [];
	if (unsupportedInstructions > 0) {
		reasons.push(`${unsupportedInstructions} decoded instruction(s) use HandleUnsupported`);
	}
	if (decodeFailureInstructions > 0) {
		reasons.push(`${decodeFailureInstructions} instruction(s) failed decode, ISEL, or semantic lifting`);
	}
	if (semanticCoverage < threshold) {
		reasons.push(`semantic coverage ${(semanticCoverage * 100).toFixed(1)}% is below ${(threshold * 100).toFixed(1)}%`);
	}

	return {
		status: partial ? 'partial' : 'ok',
		decodedInstructions,
		liftedInstructions,
		unsupportedInstructions,
		decodeFailureInstructions,
		semanticCoverage,
		unsupportedOpcodes: native.unsupportedOpcodes ?? {},
		...(reasons.length > 0 ? { reason: reasons.join('; ') } : {}),
	};
}

export function formatLiftSemanticHeader(assessment: LiftSemanticAssessment): string {
	const opcodes = Object.entries(assessment.unsupportedOpcodes)
		.filter((entry): entry is [string, number] => finiteCount(entry[1]) !== undefined && entry[1] > 0)
		.sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]));
	const retainedOpcodes = opcodes.slice(0, 32);
	const opcodeSummary = retainedOpcodes.length > 0
		? retainedOpcodes.map(([name, count]) => `${name}=${count}`).join(', ') +
			(opcodes.length > retainedOpcodes.length ? `, ... +${opcodes.length - retainedOpcodes.length} more` : '')
		: 'none';
	return [
		`; SemanticStatus: ${assessment.status}`,
		`; SemanticCoverage: ${(assessment.semanticCoverage * 100).toFixed(2)}% ` +
			`(decoded=${assessment.decodedInstructions}, lifted=${assessment.liftedInstructions}, ` +
			`unsupported=${assessment.unsupportedInstructions}, failures=${assessment.decodeFailureInstructions})`,
		`; UnsupportedOpcodes: ${opcodeSummary}`,
		...(assessment.reason ? [`; SemanticWarning: ${assessment.reason}`] : []),
		'',
	].join('\n');
}
