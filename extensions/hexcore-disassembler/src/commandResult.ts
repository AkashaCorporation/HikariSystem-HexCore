/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Command result decoration (Analysis Contract C4)
 *  Adds the canonical contract fields (contractVersion, status, diagnostics,
 *  artifacts) to existing headless command responses. Legacy fields are kept
 *  intact and remain the compatibility surface; decoration is additive only.
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import {
	ANALYSIS_CONTRACT_VERSION,
	analysisError,
	isAnalysisErrorCode,
	type AnalysisArtifactReference,
	type AnalysisDiagnostic,
	type AnalysisStatus,
} from 'hexcore-common';
import type {
	PipelineJobValidationReport,
	PipelineRunStatus,
	PipelineStepStatus,
} from './automationPipelineRunner';

export interface ContractResultFields {
	contractVersion: typeof ANALYSIS_CONTRACT_VERSION;
	status: AnalysisStatus;
	diagnostics: AnalysisDiagnostic[];
	artifacts: AnalysisArtifactReference[];
}

export type ContractDecorated<T> = T & ContractResultFields;

/**
 * Attach contract fields to an existing response object. Contract fields win
 * over same-named legacy fields (the canonical vocabulary is authoritative);
 * every other legacy field is preserved untouched.
 */
export function withContractFields<T extends object>(
	response: T,
	fields: { status: AnalysisStatus; diagnostics?: AnalysisDiagnostic[]; artifacts?: AnalysisArtifactReference[] },
): ContractDecorated<T> {
	return {
		...response,
		contractVersion: ANALYSIS_CONTRACT_VERSION,
		status: fields.status,
		diagnostics: fields.diagnostics ?? [],
		artifacts: fields.artifacts ?? [],
	};
}

/**
 * Map the runner's terminal vocabulary to the contract one. The runner uses
 * `error` where the contract uses `failed`; a `running` snapshot is reported
 * honestly as partial with a warning, never as a finished state.
 */
export function toAnalysisStatus(runStatus: PipelineRunStatus['status']): AnalysisStatus {
	switch (runStatus) {
		case 'ok': return 'ok';
		case 'partial': return 'partial';
		case 'error': return 'failed';
		case 'running': return 'partial';
	}
}

/**
 * Decorate a pipeline run status for the command response. Artifact hashes
 * live in the provenance sidecars, not in the run status, so artifact
 * references are never fabricated here — the sidecar path is carried in
 * diagnostic details instead.
 */
export function decoratePipelineRunStatus(runStatus: PipelineRunStatus): ContractDecorated<PipelineRunStatus> {
	const diagnostics: AnalysisDiagnostic[] = [];
	if (runStatus.status === 'running') {
		diagnostics.push({
			code: 'partial-result',
			severity: 'warning',
			message: 'pipeline run status was read while still running',
			retryable: true,
		});
	}
	for (const step of runStatus.steps) {
		const diagnostic = stepDiagnostic(step);
		if (diagnostic) {
			diagnostics.push(diagnostic);
		}
	}
	return withContractFields(runStatus, { status: toAnalysisStatus(runStatus.status), diagnostics });
}

/** Decorate a job validation report: report.ok maps to ok/failed with typed diagnostics. */
export function decorateValidationReport(
	report: PipelineJobValidationReport,
): ContractDecorated<PipelineJobValidationReport> {
	const diagnostics: AnalysisDiagnostic[] = report.issues.map(issue => ({
		code: isAnalysisErrorCode(issue.code) ? issue.code : validationIssueCode(issue.message),
		severity: issue.level === 'error' ? 'error' : 'warning',
		message: issue.message,
		retryable: false,
		details: {
			issueCode: issue.code,
			...(issue.stepIndex !== undefined ? { stepIndex: issue.stepIndex } : {}),
			...(issue.command ? { command: issue.command } : {}),
		},
	}));
	return withContractFields(report, { status: report.ok ? 'ok' : 'failed', diagnostics });
}

/** Decorate a simple object response that succeeded (queueJob, jobStatus, listCapabilities). */
export function decorateOkResult<T extends object>(response: T): ContractDecorated<T> {
	return withContractFields(response, { status: 'ok' });
}

function stepDiagnostic(step: PipelineStepStatus): AnalysisDiagnostic | undefined {
	const details: Record<string, unknown> = { cmd: step.cmd, attemptCount: step.attemptCount };
	if (step.artifactProvenancePath) {
		details.artifactProvenancePath = step.artifactProvenancePath;
	}
	if (step.status === 'error') {
		const message = step.error ?? `pipeline step ${step.cmd} failed`;
		return /timed?\s*out|timeout/i.test(message)
			? analysisError('timeout', message, { details })
			: analysisError('engine-fault', message, { details });
	}
	if (step.status === 'partial') {
		return {
			code: 'partial-result',
			severity: 'warning',
			message: step.error ?? `pipeline step ${step.cmd} completed with reduced coverage`,
			retryable: true,
			details,
		};
	}
	if (step.status === 'skipped') {
		const reason = step.error ?? `pipeline step ${step.cmd} was skipped`;
		return {
			code: skippedStepCode(reason),
			severity: 'info',
			message: reason,
			retryable: false,
			details,
		};
	}
	return undefined;
}

function skippedStepCode(reason: string): 'parse-failed' | 'engine-unavailable' | 'invalid-input' {
	if (/header|format|not a (?:valid )?(?:pe|elf)|magic/i.test(reason)) {
		return 'parse-failed';
	}
	if (/unavailable|missing|not (?:installed|loaded)/i.test(reason)) {
		return 'engine-unavailable';
	}
	return 'invalid-input';
}

function validationIssueCode(message: string): 'output-unsafe' | 'not-found' | 'invalid-input' {
	if (/outdir|outside|escape|containment/i.test(message)) {
		return 'output-unsafe';
	}
	if (/not found|missing|does not exist/i.test(message)) {
		return 'not-found';
	}
	return 'invalid-input';
}
