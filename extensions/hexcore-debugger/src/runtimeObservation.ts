import * as crypto from 'crypto';
import * as fs from 'fs';
import type { SideChannelData } from './debugEngine';
import type { TraceExport } from './traceManager';

export interface RuntimeObservation {
	kind: 'api-argument' | 'api-return' | 'memory-read' | 'memory-write' | 'module-symbol';
	address?: string;
	pc?: string;
	target?: string;
	ordinal?: number;
	value?: string;
	size?: number;
	evidenceLevel: 'runtime-corroboration';
}

export interface RuntimeObservationArtifact {
	schemaVersion: 1;
	producer: 'hexcore-debugger:runtime-observations-r37';
	target: { binaryPath: string; binarySha256: string; architecture: string; executionBackend: string };
	inputConfiguration: Record<string, unknown>;
	inputConfigurationSha256: string;
	traceConfigurationSha256: string;
	observations: readonly RuntimeObservation[];
	truncated: boolean;
	partialReasons: readonly string[];
	normalizedIdentitySha256: string;
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value as Record<string, unknown>).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, child]) => [key, canonicalize(child)]));
	return value;
}
function hash(value: Buffer | string): string { return crypto.createHash('sha256').update(value).digest('hex'); }
function hashObject(value: unknown): string { return hash(JSON.stringify(canonicalize(value))); }

export function buildRuntimeObservationArtifact(input: {
	binaryPath: string;
	architecture: string;
	executionBackend: string;
	trace: TraceExport;
	sideChannels?: SideChannelData;
	inputConfiguration: Record<string, unknown>;
}): RuntimeObservationArtifact {
	const binarySha256 = hash(fs.readFileSync(input.binaryPath));
	const observations: RuntimeObservation[] = [];
	for (const entry of input.trace.entries) {
		const target = `${entry.library.toLowerCase()}!${entry.functionName.toLowerCase()}`;
		observations.push({ kind: 'module-symbol', pc: entry.pcAddress, target, evidenceLevel: 'runtime-corroboration' });
		entry.arguments.forEach((value, ordinal) => observations.push({ kind: 'api-argument', pc: entry.pcAddress, target, ordinal, value, evidenceLevel: 'runtime-corroboration' }));
		observations.push({ kind: 'api-return', pc: entry.pcAddress, target, value: entry.returnValue, evidenceLevel: 'runtime-corroboration' });
	}
	for (const access of input.sideChannels?.memoryAccesses ?? []) observations.push({
		kind: access.type === 'read' ? 'memory-read' : 'memory-write', address: access.address, pc: access.pc, size: access.size,
		evidenceLevel: 'runtime-corroboration',
	});
	observations.sort((left, right) => JSON.stringify(canonicalize(left)) < JSON.stringify(canonicalize(right)) ? -1 : 1);
	const inputConfigurationSha256 = hashObject(input.inputConfiguration);
	const traceConfigurationSha256 = hashObject(input.trace.configuration);
	const partialReasons: string[] = [];
	if (input.trace.dropped > 0 || input.trace.sampledOut > 0) partialReasons.push(`Trace omitted ${input.trace.dropped + input.trace.sampledOut} call(s).`);
	if (input.sideChannels?.truncated) partialReasons.push('Side-channel address tracking was truncated.');
	const logical = {
		schemaVersion: 1 as const, producer: 'hexcore-debugger:runtime-observations-r37' as const,
		target: { binaryPath: input.binaryPath, binarySha256, architecture: input.architecture, executionBackend: input.executionBackend },
		inputConfiguration: canonicalize(input.inputConfiguration) as Record<string, unknown>, inputConfigurationSha256, traceConfigurationSha256,
		observations, truncated: partialReasons.length > 0, partialReasons,
	};
	return { ...logical, normalizedIdentitySha256: hashObject(logical) };
}
