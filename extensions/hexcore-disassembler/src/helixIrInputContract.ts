/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type { ArchitectureConfig } from './capstoneWrapper';

export interface HelixIrInputContract {
	architecture: ArchitectureConfig;
	architectureSource: 'ir' | 'explicit' | 'bound-target' | 'legacy-default';
	status: 'ok' | 'partial';
	reasons: string[];
	liftEvidence?: {
		requestedByteRange?: { startAddress: number; endExclusive: number; size: number };
		decodedByteCoverage?: { decodedBytes: number; requestedBytes: number; coverage: number };
		semanticInstructionCoverage?: number;
	};
}

function architecture(value: string): ArchitectureConfig | undefined {
	const name = value.toLowerCase();
	if (['x64', 'x86_64', 'amd64', 'amd64_avx', 'amd64_avx512'].includes(name)) { return 'x64'; }
	if (['x86', 'x86_avx', 'x86_avx512'].includes(name) || /^i[3-6]86$/.test(name)) { return 'x86'; }
	if (name === 'arm64' || name === 'aarch64') { return 'arm64'; }
	if (name === 'arm' || /^(?:armv[4-8]|thumb)/.test(name)) { return 'arm'; }
	if (name === 'mips' || name === 'mips64') { return name; }
	return undefined;
}

/** Resolve the IR's own identity without borrowing unrelated active-engine state. */
export function inspectHelixIrInput(ir: string, requested?: string, boundTarget?: ArchitectureConfig, inheritedReasons: readonly string[] = []): HelixIrInputContract {
	if (/^[\s\uFEFF]*[\[{]/.test(ir)) {
		let json: unknown;
		try { json = JSON.parse(ir); } catch { /* The LLVM parser will diagnose malformed non-JSON input. */ }
		if (json && typeof json === 'object') {
			const record = json as Record<string, unknown>;
			const failed = record.stub === true || record.ok === false || record.success === false || record.status === 'error' || record.status === 'failed';
			throw new Error(`${failed ? 'upstream-error-artifact' : 'incompatible-artifact'}: expected LLVM IR, received a JSON artifact`);
		}
	}
	const triple = /^\s*target triple\s*=\s*"(?<triple>[^"]+)"/m.exec(ir)?.groups?.triple;
	const header = /^; Architecture:\s*(?<architecture>\S+)\s*$/m.exec(ir)?.groups?.architecture;
	const declared = triple?.split('-')[0] ?? header;
	const irArch = declared ? architecture(declared) : undefined;
	if (declared && !irArch) { throw new Error(`unsupported-architecture: IR declares ${declared}`); }
	const explicit = requested ? architecture(requested) : undefined;
	if (requested && !explicit) { throw new Error(`unsupported-architecture: requested ${requested}`); }
	if (irArch && explicit && irArch !== explicit) { throw new Error(`architecture-mismatch: IR is ${irArch}, requested ${explicit}`); }
	if (triple && header && architecture(header) !== irArch) { throw new Error('architecture-mismatch: IR triple and lift header disagree'); }
	if (irArch && boundTarget && irArch !== boundTarget) { throw new Error(`architecture-mismatch: IR is ${irArch}, bound target is ${boundTarget}`); }
	if (explicit && boundTarget && explicit !== boundTarget) { throw new Error(`architecture-mismatch: requested ${explicit}, bound target is ${boundTarget}`); }
	const reasons: string[] = [...inheritedReasons];
	const semanticStatus = /^; SemanticStatus:\s*(?<status>\S+)/m.exec(ir)?.groups?.status;
	if (semanticStatus === 'error' || semanticStatus === 'failed') { throw new Error(`upstream-error-artifact: input lift status is ${semanticStatus}`); }
	if (semanticStatus && semanticStatus !== 'ok') { reasons.push(`Input lift status: ${semanticStatus}`); }
	const warning = /^; SemanticWarning:\s*(?<warning>.+)$/m.exec(ir)?.groups?.warning;
	if (warning) { reasons.push(warning.trim()); }
	const requestedRangeMatch = /^; RequestedByteRange:\s*\[0x(?<start>[0-9a-f]+),\s*0x(?<end>[0-9a-f]+)\)/mi.exec(ir);
	const requestedStart = requestedRangeMatch?.groups?.start
		? Number.parseInt(requestedRangeMatch.groups.start, 16) : undefined;
	const requestedEnd = requestedRangeMatch?.groups?.end
		? Number.parseInt(requestedRangeMatch.groups.end, 16) : undefined;
	const requestedByteRange = requestedStart !== undefined && requestedEnd !== undefined &&
		Number.isSafeInteger(requestedStart) && Number.isSafeInteger(requestedEnd) && requestedEnd > requestedStart
		? { startAddress: requestedStart, endExclusive: requestedEnd, size: requestedEnd - requestedStart }
		: undefined;
	const decodedMatch = /^; RemillDecodedByteSet:\s*[0-9.]+%\s*\((?<decoded>\d+)\/(?<requested>\d+)\s+bytes\)/mi.exec(ir);
	const decodedBytes = decodedMatch?.groups?.decoded ? Number(decodedMatch.groups.decoded) : undefined;
	const requestedBytes = decodedMatch?.groups?.requested ? Number(decodedMatch.groups.requested) : undefined;
	const decodedByteCoverage = decodedBytes !== undefined && requestedBytes !== undefined && requestedBytes > 0
		? { decodedBytes, requestedBytes, coverage: Math.min(1, decodedBytes / requestedBytes) }
		: undefined;
	const semanticCoverageMatch = /^; SemanticCoverage:\s*(?<coverage>[0-9]+(?:\.[0-9]+)?)%/mi.exec(ir);
	const semanticInstructionCoverage = semanticCoverageMatch?.groups?.coverage
		? Math.min(1, Number(semanticCoverageMatch.groups.coverage) / 100)
		: undefined;
	if (decodedByteCoverage && decodedByteCoverage.coverage < 1) {
		reasons.push(
			`Input decoded byte coverage is ${(decodedByteCoverage.coverage * 100).toFixed(1)}% ` +
			`(${decodedByteCoverage.decodedBytes}/${decodedByteCoverage.requestedBytes})`,
		);
	}
	const architectureSource = irArch ? 'ir' : explicit ? 'explicit' : boundTarget ? 'bound-target' : 'legacy-default';
	if (architectureSource === 'legacy-default') { reasons.push('IR architecture unavailable; legacy x64 default is not authoritative'); }
	const hasLiftEvidence = requestedByteRange !== undefined || decodedByteCoverage !== undefined || semanticInstructionCoverage !== undefined;
	return {
		architecture: irArch ?? explicit ?? boundTarget ?? 'x64',
		architectureSource,
		status: reasons.length ? 'partial' : 'ok',
		reasons,
		...(hasLiftEvidence ? { liftEvidence: {
			...(requestedByteRange ? { requestedByteRange } : {}),
			...(decodedByteCoverage ? { decodedByteCoverage } : {}),
			...(semanticInstructionCoverage !== undefined ? { semanticInstructionCoverage } : {}),
		} } : {}),
	};
}
