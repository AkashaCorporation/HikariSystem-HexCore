/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as fs from 'fs';
import * as path from 'path';
import type { PipelineRunStatus, PipelineStepStatus } from './automationPipelineRunner';
import { canonicalJson, isRecord, sha256Canonical } from './agentBridgeProtocol';

const MAX_STEPS = 2048;
const MAX_ERROR_CHARS = 4096;
const MAX_ATTEMPTS_PER_STEP = 32;
const MAX_SIDE_ARTIFACTS_PER_STEP = 32;
const MAX_JSON_PREVIEW_FILE_BYTES = 64 * 1024;
const MAX_JSON_PREVIEW_STRING_CHARS = 2048;
const MAX_JSON_PREVIEW_ARRAY_ITEMS = 128;
const MAX_JSON_PREVIEW_OBJECT_KEYS = 128;
const MAX_JSON_PREVIEW_DEPTH = 6;
const MAX_RECORD_BYTES = 2 * 1024 * 1024;
const SECRET_KEY = /(?:authorization|cookie|password|passwd|secret|token|api[_-]?key|private[_-]?key)/i;

export interface AgentStepResultRecord {
	stepId?: string;
	stepIndex?: number;
	occurrence?: number;
	cmd: string;
	resolvedCmd: string;
	status: PipelineStepStatus['status'];
	durationMs: number;
	attemptCount: number;
	attempts?: PipelineStepStatus['attempts'];
	output?: {
		path: string;
		bytes?: number;
		sha256?: string;
		hashAuthority: 'artifact-provenance' | 'unavailable';
		artifactProvenancePath?: string;
		artifactKind?: string;
	};
	sideArtifacts?: AgentSideArtifact[];
	error?: string;
	errorCode?: string;
	detectedFormat?: string;
	resultPreview?: unknown;
	resultPreviewStatus?: 'included' | 'not-json' | 'omitted-size-limit' | 'unavailable' | 'redacted-or-truncated';
	recordCompacted?: true;
	recordSha256: string;
}

interface AgentSideArtifact {
	role: 'hast' | 'pairing';
	path: string;
	sha256: string;
	bytes: number;
	mediaType: string;
	pairingId: string;
}

export interface AgentResultRecord {
	schemaVersion: 1;
	protocolVersion: 1;
	generatedAt: string;
	job: {
		jobId: string;
		queueStatus: string;
		jobFile: string;
		jobFileSha256?: string;
		revision?: string;
	};
	pipeline: {
		status: PipelineRunStatus['status'];
		executionId: string;
		startedAt: string;
		finishedAt?: string;
		target: {
			path: string;
			sha256: string;
			format: string;
			architecture?: string;
			imageBase?: string;
		};
		outDir: string;
		provenanceManifestPath?: string;
		summary?: PipelineRunStatus['summary'];
	};
	steps: AgentStepResultRecord[];
	truncation: {
		stepLimit: number;
		omittedSteps: number;
		previewsDroppedForRecordLimit: boolean;
	};
	recordSha256: string;
}

export interface AgentResultPointer {
	path: string;
	sha256: string;
	bytes: number;
	executionId: string;
}

export interface PersistAgentResultOptions {
	jobId: string;
	queueStatus: string;
	revision?: string;
	run: PipelineRunStatus;
}

export function buildAgentResultRecord(options: PersistAgentResultOptions): AgentResultRecord {
	const selectedSteps = options.run.steps.slice(0, MAX_STEPS);
	const steps = selectedSteps.map(step => buildStepRecord(step, true));
	const base = buildRecordBase(options, steps, false);
	let finalized = finalizeRecord(base);
	if (Buffer.byteLength(JSON.stringify(finalized), 'utf8') > MAX_RECORD_BYTES) {
		let boundedSteps = selectedSteps.map(step => buildStepRecord(step, false));
		finalized = finalizeRecord(buildRecordBase(options, boundedSteps, true));
		while (boundedSteps.length > 1 && Buffer.byteLength(JSON.stringify(finalized), 'utf8') > MAX_RECORD_BYTES) {
			boundedSteps = boundedSteps.slice(0, Math.ceil(boundedSteps.length / 2));
			finalized = finalizeRecord(buildRecordBase(options, boundedSteps, true));
		}
		if (Buffer.byteLength(JSON.stringify(finalized), 'utf8') > MAX_RECORD_BYTES) {
			boundedSteps = boundedSteps.map(compactStepRecord);
			finalized = finalizeRecord(buildRecordBase(options, boundedSteps, true));
		}
	}
	return finalized;
}

export function persistAgentResultRecord(options: PersistAgentResultOptions): AgentResultPointer {
	const record = buildAgentResultRecord(options);
	const resultDir = path.join(options.run.outDir, '.hexcore-meta', 'agent-results');
	fs.mkdirSync(resultDir, { recursive: true });
	const resultPath = path.join(resultDir, `${safeFileComponent(record.pipeline.executionId)}.json`);
	const serialized = `${JSON.stringify(record, null, 2)}\n`;
	const tempPath = `${resultPath}.${process.pid}.${Date.now()}.tmp`;
	fs.writeFileSync(tempPath, serialized, { encoding: 'utf8', mode: 0o600 });
	fs.renameSync(tempPath, resultPath);
	return {
		path: resultPath,
		sha256: record.recordSha256,
		bytes: Buffer.byteLength(serialized, 'utf8'),
		executionId: record.pipeline.executionId,
	};
}

export function verifyAgentResultRecord(record: AgentResultRecord): boolean {
	const { recordSha256, ...withoutHash } = record;
	return recordSha256 === sha256Canonical(withoutHash);
}

function buildRecordBase(
	options: PersistAgentResultOptions,
	steps: AgentStepResultRecord[],
	previewsDroppedForRecordLimit: boolean,
): Omit<AgentResultRecord, 'recordSha256'> {
	const provenance = options.run.provenance;
	return {
		schemaVersion: 1,
		protocolVersion: 1,
		generatedAt: new Date().toISOString(),
		job: {
			jobId: options.jobId,
			queueStatus: options.queueStatus,
			jobFile: options.run.jobFile,
			...(options.run.jobFileSha256 ? { jobFileSha256: options.run.jobFileSha256 } : {}),
			...(options.revision ? { revision: options.revision } : {}),
		},
		pipeline: {
			status: options.run.status,
			executionId: provenance.executionId,
			startedAt: options.run.startedAt,
			...(options.run.finishedAt ? { finishedAt: options.run.finishedAt } : {}),
			target: {
				path: provenance.binaryPath,
				sha256: provenance.binarySha256,
				format: provenance.binaryFormat,
				...(provenance.architecture ? { architecture: provenance.architecture } : {}),
				...(provenance.imageBase ? { imageBase: provenance.imageBase } : {}),
			},
			outDir: options.run.outDir,
			...(options.run.provenanceManifestPath ? { provenanceManifestPath: options.run.provenanceManifestPath } : {}),
			...(options.run.summary ? { summary: options.run.summary } : {}),
		},
		steps,
		truncation: {
			stepLimit: MAX_STEPS,
			omittedSteps: Math.max(0, options.run.steps.length - steps.length),
			previewsDroppedForRecordLimit,
		},
	};
}

function finalizeRecord(base: Omit<AgentResultRecord, 'recordSha256'>): AgentResultRecord {
	return { ...base, recordSha256: sha256Canonical(base) };
}

function buildStepRecord(step: PipelineStepStatus, includePreview: boolean): AgentStepResultRecord {
	const artifactIdentity = readArtifactIdentity(step.artifactProvenancePath, step.outputPath);
	const preview = includePreview ? readBoundedJsonPreview(step.outputPath) : undefined;
	const sideArtifacts = (step as PipelineStepStatus & { sideArtifacts?: AgentSideArtifact[] }).sideArtifacts;
	const withoutHash: Omit<AgentStepResultRecord, 'recordSha256'> = {
		...(step.stepId ? { stepId: step.stepId } : {}),
		...(step.stepIndex !== undefined ? { stepIndex: step.stepIndex } : {}),
		...(step.occurrence !== undefined ? { occurrence: step.occurrence } : {}),
		cmd: step.cmd,
		resolvedCmd: step.resolvedCmd,
		status: step.status,
		durationMs: step.durationMs,
		attemptCount: step.attemptCount,
		...(step.attempts ? { attempts: step.attempts.slice(0, MAX_ATTEMPTS_PER_STEP).map(attempt => ({
			...attempt,
			...(attempt.error ? { error: truncate(attempt.error, MAX_ERROR_CHARS) } : {}),
		})) } : {}),
		...(step.outputPath ? {
			output: {
				path: step.outputPath,
				...(step.outputBytes !== undefined ? { bytes: step.outputBytes } : {}),
				...(artifactIdentity?.sha256 ? { sha256: artifactIdentity.sha256 } : {}),
				hashAuthority: artifactIdentity?.sha256 ? 'artifact-provenance' : 'unavailable',
				...(step.artifactProvenancePath ? { artifactProvenancePath: step.artifactProvenancePath } : {}),
				...(step.artifactKind ? { artifactKind: step.artifactKind } : {}),
			},
		} : {}),
		...(sideArtifacts ? { sideArtifacts: sideArtifacts.slice(0, MAX_SIDE_ARTIFACTS_PER_STEP) } : {}),
		...(step.error ? { error: truncate(step.error, MAX_ERROR_CHARS) } : {}),
		...(step.errorCode ? { errorCode: step.errorCode } : {}),
		...(step.detectedFormat ? { detectedFormat: step.detectedFormat } : {}),
		...(preview?.value !== undefined ? { resultPreview: preview.value } : {}),
		...(includePreview ? { resultPreviewStatus: preview?.status ?? 'unavailable' } : {}),
	};
	return { ...withoutHash, recordSha256: sha256Canonical(withoutHash) };
}

function readArtifactIdentity(filePath: string | undefined, outputPath: string | undefined): { sha256?: string } | undefined {
	if (!filePath) {
		return undefined;
	}
	try {
		const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8')) as unknown;
		if (isRecord(parsed) && isRecord(parsed.artifact) && typeof parsed.artifact.sha256 === 'string') {
			return { sha256: parsed.artifact.sha256 };
		}
		if (isRecord(parsed) && Array.isArray(parsed.artifacts)) {
			const outputIdentity = outputPath ? pathIdentity(outputPath) : undefined;
			const candidates = parsed.artifacts.filter(entry => isRecord(entry) && isRecord(entry.artifact));
			const matching = outputIdentity
				? candidates.find(entry => {
					const artifact = (entry as Record<string, unknown>).artifact;
					return isRecord(artifact)
						&& typeof artifact.path === 'string'
						&& pathIdentity(artifact.path) === outputIdentity;
				})
				: (candidates.length === 1 ? candidates[0] : undefined);
			const artifact = isRecord(matching) ? matching.artifact : undefined;
			if (isRecord(artifact) && typeof artifact.sha256 === 'string') {
				return { sha256: artifact.sha256 };
			}
		}
	} catch {
		// Missing provenance remains explicit through hashAuthority=unavailable.
	}
	return undefined;
}

function pathIdentity(filePath: string): string {
	const resolved = path.resolve(filePath);
	return process.platform === 'win32' ? resolved.toLowerCase() : resolved;
}

function readBoundedJsonPreview(filePath: string | undefined): { status: AgentStepResultRecord['resultPreviewStatus']; value?: unknown } | undefined {
	if (!filePath) {
		return { status: 'unavailable' };
	}
	try {
		const stat = fs.statSync(filePath);
		if (!stat.isFile()) {
			return { status: 'unavailable' };
		}
		if (stat.size > MAX_JSON_PREVIEW_FILE_BYTES) {
			return { status: 'omitted-size-limit' };
		}
		const text = fs.readFileSync(filePath, 'utf8');
		let parsed: unknown;
		try {
			parsed = JSON.parse(text);
		} catch {
			return { status: 'not-json' };
		}
		const state = { changed: false };
		const value = boundJsonValue(parsed, 0, state, '');
		return { status: state.changed ? 'redacted-or-truncated' : 'included', value };
	} catch {
		return { status: 'unavailable' };
	}
}

function boundJsonValue(value: unknown, depth: number, state: { changed: boolean }, key: string): unknown {
	if (SECRET_KEY.test(key)) {
		state.changed = true;
		return '[REDACTED]';
	}
	if (depth >= MAX_JSON_PREVIEW_DEPTH) {
		state.changed = true;
		return '[TRUNCATED_DEPTH]';
	}
	if (typeof value === 'string') {
		if (value.length > MAX_JSON_PREVIEW_STRING_CHARS) {
			state.changed = true;
			return `${value.slice(0, MAX_JSON_PREVIEW_STRING_CHARS)}...[TRUNCATED]`;
		}
		return value;
	}
	if (typeof value === 'number' || typeof value === 'boolean' || value === null) {
		return value;
	}
	if (Array.isArray(value)) {
		if (value.length > MAX_JSON_PREVIEW_ARRAY_ITEMS) {
			state.changed = true;
		}
		return value.slice(0, MAX_JSON_PREVIEW_ARRAY_ITEMS).map(entry => boundJsonValue(entry, depth + 1, state, key));
	}
	if (isRecord(value)) {
		const output: Record<string, unknown> = {};
		const keys = Object.keys(value).sort();
		if (keys.length > MAX_JSON_PREVIEW_OBJECT_KEYS) {
			state.changed = true;
		}
		for (const childKey of keys.slice(0, MAX_JSON_PREVIEW_OBJECT_KEYS)) {
			output[childKey] = boundJsonValue(value[childKey], depth + 1, state, childKey);
		}
		return output;
	}
	state.changed = true;
	return String(value);
}

function safeFileComponent(value: string): string {
	return value.replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 160) || 'unknown-execution';
}

function compactStepRecord(step: AgentStepResultRecord): AgentStepResultRecord {
	const withoutHash: Omit<AgentStepResultRecord, 'recordSha256'> = {
		...(step.stepId ? { stepId: truncate(step.stepId, 128) } : {}),
		...(step.stepIndex !== undefined ? { stepIndex: step.stepIndex } : {}),
		...(step.occurrence !== undefined ? { occurrence: step.occurrence } : {}),
		cmd: truncate(step.cmd, 512),
		resolvedCmd: truncate(step.resolvedCmd, 512),
		status: step.status,
		durationMs: step.durationMs,
		attemptCount: step.attemptCount,
		...(step.output ? {
			output: {
				path: truncate(step.output.path, 4096),
				...(step.output.bytes !== undefined ? { bytes: step.output.bytes } : {}),
				...(step.output.sha256 ? { sha256: step.output.sha256 } : {}),
				hashAuthority: step.output.hashAuthority,
				...(step.output.artifactProvenancePath ? { artifactProvenancePath: truncate(step.output.artifactProvenancePath, 4096) } : {}),
				...(step.output.artifactKind ? { artifactKind: truncate(step.output.artifactKind, 128) } : {}),
			},
		} : {}),
		recordCompacted: true,
	};
	return { ...withoutHash, recordSha256: sha256Canonical(withoutHash) };
}

function truncate(value: string, limit: number): string {
	return value.length <= limit ? value : `${value.slice(0, limit)}...[TRUNCATED]`;
}

export function canonicalAgentResultRecord(record: AgentResultRecord): string {
	return canonicalJson(record);
}
