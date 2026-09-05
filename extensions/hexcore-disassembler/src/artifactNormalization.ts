import * as crypto from 'crypto';

export const CANONICAL_JSON_ALGORITHM = 'hexcore-canonical-json-v1';
export const CANONICAL_JSON_EXCLUDED_POINTERS = [
	'/generatedAt',
	'/normalization',
	'/analysisContext/engineGeneration',
	'/analysisContext/closureRestoration',
] as const;

function asRecord(value: unknown): Record<string, unknown> | undefined {
	return value !== null && typeof value === 'object' && !Array.isArray(value)
		? value as Record<string, unknown>
		: undefined;
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) { return value.map(canonicalize); }
	const record = asRecord(value);
	if (!record) { return value; }
	return Object.fromEntries(Object.keys(record).sort().map(key => [key, canonicalize(record[key])]));
}

export function canonicalArtifactJson(value: unknown): string {
	const record = asRecord(value);
	if (!record) { return JSON.stringify(canonicalize(value)); }
	const normalized = { ...record };
	delete normalized.generatedAt;
	delete normalized.normalization;
	const analysisContext = asRecord(normalized.analysisContext);
	if (analysisContext) {
		normalized.analysisContext = { ...analysisContext };
		delete (normalized.analysisContext as Record<string, unknown>).engineGeneration;
		delete (normalized.analysisContext as Record<string, unknown>).closureRestoration;
	}
	return JSON.stringify(canonicalize(normalized));
}

export function canonicalArtifactSha256(value: unknown): string {
	return crypto.createHash('sha256').update(canonicalArtifactJson(value)).digest('hex');
}

export function describeCanonicalArtifactIdentity(value: unknown) {
	return {
		algorithm: CANONICAL_JSON_ALGORITHM,
		excludedJsonPointers: [...CANONICAL_JSON_EXCLUDED_POINTERS],
		sha256: canonicalArtifactSha256(value),
	};
}
