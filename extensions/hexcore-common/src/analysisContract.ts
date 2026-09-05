/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as path from 'path';

export const ANALYSIS_CONTRACT_VERSION = 1 as const;

export type AnalysisBinaryFormat = 'pe' | 'elf' | 'minidump' | 'macho' | 'raw' | 'unknown';
export type AnalysisStatus = 'ok' | 'partial' | 'failed' | 'skipped';
export type AnalysisAddressSpace = 'file-offset' | 'rva' | 'va' | 'runtime-va';
export type AnalysisDiagnosticSeverity = 'info' | 'warning' | 'error';

export interface AnalysisAddress {
	space: AnalysisAddressSpace;
	/** Canonical, lower-case hexadecimal. Addresses are never serialized as JS numbers. */
	value: string;
	architecture?: string;
	overlayId?: string;
}
export interface AnalysisTargetInput {
	binarySha256: string;
	filePath: string;
	fileSize: number;
	format: AnalysisBinaryFormat;
	architecture?: string;
	imageBase?: string | bigint | number;
	overlayId?: string;
}

export interface AnalysisTarget {
	contractVersion: typeof ANALYSIS_CONTRACT_VERSION;
	id: string;
	binarySha256: string;
	filePath: string;
	fileSize: number;
	format: AnalysisBinaryFormat;
	architecture?: string;
	imageBase?: AnalysisAddress;
}

export interface AnalysisEngineIdentity {
	id: string;
	version: string;
	buildSha256?: string;
}

export interface AnalysisSessionInput {
	id: string;
	targetId: string;
	generation: number;
	createdAt?: string;
	parentGeneration?: number;
	engines?: readonly AnalysisEngineIdentity[];
}

export interface AnalysisSession {
	contractVersion: typeof ANALYSIS_CONTRACT_VERSION;
	id: string;
	targetId: string;
	generation: number;
	createdAt: string;
	parentGeneration?: number;
	engines: AnalysisEngineIdentity[];
}

export interface AnalysisDiagnostic {
	code: string;
	severity: AnalysisDiagnosticSeverity;
	message: string;
	retryable?: boolean;
	address?: AnalysisAddress;
	details?: Record<string, unknown>;
}

export interface AnalysisArtifactReference {
	id: string;
	path: string;
	sha256: string;
	mediaType?: string;
}

export interface AnalysisResult<T> {
	contractVersion: typeof ANALYSIS_CONTRACT_VERSION;
	status: AnalysisStatus;
	data?: T;
	diagnostics: AnalysisDiagnostic[];
	artifacts: AnalysisArtifactReference[];
}

export interface AnalysisResultInput<T> {
	status: AnalysisStatus;
	data?: T;
	diagnostics?: readonly AnalysisDiagnostic[];
	artifacts?: readonly AnalysisArtifactReference[];
}

export interface AnalysisArtifactProvenanceInput {
	target: AnalysisTarget;
	session: AnalysisSession;
	producer: readonly AnalysisEngineIdentity[];
	artifact: AnalysisArtifactReference;
	inputs?: readonly AnalysisArtifactReference[];
	status: AnalysisStatus;
	generatedAt?: string;
}

export interface AnalysisArtifactProvenance {
	contractVersion: typeof ANALYSIS_CONTRACT_VERSION;
	generatedAt: string;
	target: AnalysisTarget;
	session: AnalysisSession;
	producer: AnalysisEngineIdentity[];
	inputs: AnalysisArtifactReference[];
	artifact: AnalysisArtifactReference;
	status: AnalysisStatus;
}

/** Normalize and validate a SHA-256 digest for use as an identity component. */
export function normalizeSha256(value: string): string {
	const normalized = value.trim().toLowerCase();
	if (!/^[a-f0-9]{64}$/.test(normalized)) {
		throw new Error('SHA-256 must contain exactly 64 hexadecimal characters');
	}
	return normalized;
}

/**
 * Normalize an address without passing through an unsafe JavaScript number.
 * Numeric callers are accepted only while Number.isSafeInteger is true.
 */
export function normalizeAddressValue(value: string | bigint | number): string {
	let parsed: bigint;
	if (typeof value === 'bigint') {
		parsed = value;
	} else if (typeof value === 'number') {
		if (!Number.isSafeInteger(value)) {
			throw new Error('Address numbers must be safe integers; use a bigint or hexadecimal string');
		}
		parsed = BigInt(value);
	} else {
		const normalized = value.trim();
		if (!/^(?:0x[0-9a-f]+|[0-9]+)$/i.test(normalized)) {
			throw new Error(`Invalid address value: ${value}`);
		}
		parsed = BigInt(normalized);
	}
	if (parsed < 0n) {
		throw new Error('Addresses cannot be negative');
	}
	return `0x${parsed.toString(16)}`;
}

export function createAnalysisAddress(
	space: AnalysisAddressSpace,
	value: string | bigint | number,
	options: { architecture?: string; overlayId?: string } = {},
): AnalysisAddress {
	return {
		space,
		value: normalizeAddressValue(value),
		...(options.architecture ? { architecture: options.architecture } : {}),
		...(options.overlayId ? { overlayId: options.overlayId } : {}),
	};
}

/** Create the immutable identity shared by jobs, sessions, artifacts, and UI views. */
export function createAnalysisTarget(input: AnalysisTargetInput): AnalysisTarget {
	if (!Number.isSafeInteger(input.fileSize) || input.fileSize < 0) {
		throw new Error('Analysis target fileSize must be a non-negative safe integer');
	}
	const binarySha256 = normalizeSha256(input.binarySha256);
	const architecture = normalizeOptionalToken(input.architecture, 'architecture');
	const overlayId = normalizeOptionalToken(input.overlayId, 'overlayId');
	return {
		contractVersion: ANALYSIS_CONTRACT_VERSION,
		id: `target:sha256:${binarySha256}`,
		binarySha256,
		filePath: path.resolve(input.filePath),
		fileSize: input.fileSize,
		format: input.format,
		...(architecture ? { architecture } : {}),
		...(input.imageBase !== undefined ? {
			imageBase: createAnalysisAddress('va', input.imageBase, { architecture, overlayId }),
		} : {}),
	};
}

export function createAnalysisSession(input: AnalysisSessionInput): AnalysisSession {
	const id = normalizeRequiredToken(input.id, 'session id');
	const targetId = normalizeRequiredToken(input.targetId, 'target id');
	if (!Number.isSafeInteger(input.generation) || input.generation < 0) {
		throw new Error('Analysis session generation must be a non-negative safe integer');
	}
	if (input.parentGeneration !== undefined &&
		(!Number.isSafeInteger(input.parentGeneration) || input.parentGeneration < 0 || input.parentGeneration >= input.generation)) {
		throw new Error('parentGeneration must be a non-negative generation before the current generation');
	}
	const createdAt = input.createdAt ?? new Date().toISOString();
	if (Number.isNaN(Date.parse(createdAt))) {
		throw new Error('Analysis session createdAt must be an ISO-compatible timestamp');
	}
	return {
		contractVersion: ANALYSIS_CONTRACT_VERSION,
		id,
		targetId,
		generation: input.generation,
		createdAt,
		...(input.parentGeneration !== undefined ? { parentGeneration: input.parentGeneration } : {}),
		engines: (input.engines ?? []).map(normalizeEngineIdentity),
	};
}

/** Create an honest result envelope and enforce status/diagnostic invariants. */
export function createAnalysisResult<T>(input: AnalysisResultInput<T>): AnalysisResult<T> {
	const diagnostics = (input.diagnostics ?? []).map(normalizeDiagnostic);
	const artifacts = (input.artifacts ?? []).map(normalizeArtifactReference);
	const hasError = diagnostics.some(diagnostic => diagnostic.severity === 'error');
	if (input.status === 'ok' && hasError) {
		throw new Error('An ok analysis result cannot contain error diagnostics');
	}
	if (input.status === 'failed' && !hasError) {
		throw new Error('A failed analysis result must contain at least one error diagnostic');
	}
	return {
		contractVersion: ANALYSIS_CONTRACT_VERSION,
		status: input.status,
		...(input.data !== undefined ? { data: input.data } : {}),
		diagnostics,
		artifacts,
	};
}

export function isAnalysisResult(value: unknown): value is AnalysisResult<unknown> {
	if (!value || typeof value !== 'object') {
		return false;
	}
	const candidate = value as Partial<AnalysisResult<unknown>>;
	return candidate.contractVersion === ANALYSIS_CONTRACT_VERSION &&
		candidate.status !== undefined &&
		['ok', 'partial', 'failed', 'skipped'].includes(candidate.status) &&
		Array.isArray(candidate.diagnostics) &&
		Array.isArray(candidate.artifacts);
}

export function createAnalysisArtifactProvenance(input: AnalysisArtifactProvenanceInput): AnalysisArtifactProvenance {
	if (input.target.id !== input.session.targetId) {
		throw new Error('Artifact provenance session does not belong to the supplied target');
	}
	const generatedAt = input.generatedAt ?? new Date().toISOString();
	if (Number.isNaN(Date.parse(generatedAt))) {
		throw new Error('Artifact provenance generatedAt must be an ISO-compatible timestamp');
	}
	return {
		contractVersion: ANALYSIS_CONTRACT_VERSION,
		generatedAt,
		target: input.target,
		session: input.session,
		producer: input.producer.map(normalizeEngineIdentity),
		inputs: (input.inputs ?? []).map(normalizeArtifactReference),
		artifact: normalizeArtifactReference(input.artifact),
		status: input.status,
	};
}

function normalizeEngineIdentity(engine: AnalysisEngineIdentity): AnalysisEngineIdentity {
	return {
		id: normalizeRequiredToken(engine.id, 'engine id'),
		version: normalizeRequiredToken(engine.version, 'engine version'),
		...(engine.buildSha256 ? { buildSha256: normalizeSha256(engine.buildSha256) } : {}),
	};
}

function normalizeDiagnostic(diagnostic: AnalysisDiagnostic): AnalysisDiagnostic {
	return {
		code: normalizeRequiredToken(diagnostic.code, 'diagnostic code'),
		severity: diagnostic.severity,
		message: normalizeRequiredToken(diagnostic.message, 'diagnostic message'),
		...(diagnostic.retryable !== undefined ? { retryable: diagnostic.retryable } : {}),
		...(diagnostic.address ? { address: {
			...diagnostic.address,
			value: normalizeAddressValue(diagnostic.address.value),
		} } : {}),
		...(diagnostic.details ? { details: diagnostic.details } : {}),
	};
}

function normalizeArtifactReference(artifact: AnalysisArtifactReference): AnalysisArtifactReference {
	return {
		id: normalizeRequiredToken(artifact.id, 'artifact id'),
		path: path.resolve(normalizeRequiredToken(artifact.path, 'artifact path')),
		sha256: normalizeSha256(artifact.sha256),
		...(artifact.mediaType ? { mediaType: artifact.mediaType.trim() } : {}),
	};
}

function normalizeOptionalToken(value: string | undefined, label: string): string | undefined {
	if (value === undefined) {
		return undefined;
	}
	return normalizeRequiredToken(value, label);
}

function normalizeRequiredToken(value: string, label: string): string {
	const normalized = value.trim();
	if (!normalized) {
		throw new Error(`${label} cannot be empty`);
	}
	return normalized;
}
