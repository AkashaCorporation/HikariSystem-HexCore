/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import {
	createAnalysisResult,
	type AnalysisAddress,
	type AnalysisArtifactReference,
	type AnalysisDiagnostic,
	type AnalysisResult,
} from './analysisContract';

/**
 * Typed error codes for the Analysis Contract (3.8.4 work item C4).
 *
 * The registry is part of the contract: every headless command failure must
 * use one of these codes, and adding or renaming a code is a contract change.
 * Codes are lowercase kebab-case tokens so they serialize cleanly into
 * diagnostics, logs, and job files.
 */
export const ANALYSIS_ERROR_CODES = [
	'invalid-input',
	'not-found',
	'wrong-target',
	'stale-generation',
	'engine-unavailable',
	'engine-fault',
	'parse-failed',
	'output-unsafe',
	'budget-exceeded',
	'cancelled',
	'timeout',
	'partial-result',
] as const;

export type AnalysisErrorCode = typeof ANALYSIS_ERROR_CODES[number];

export interface AnalysisErrorSpec {
	/** Default retryability; callers may override per diagnostic. */
	retryable: boolean;
	description: string;
}

export const ANALYSIS_ERROR_SPECS: Readonly<Record<AnalysisErrorCode, AnalysisErrorSpec>> = {
	'invalid-input': { retryable: false, description: 'The command input failed validation.' },
	'not-found': { retryable: false, description: 'The requested target, object, or job does not exist.' },
	'wrong-target': { retryable: false, description: 'The result or reference belongs to a different analysis target.' },
	'stale-generation': { retryable: true, description: 'The result was produced by an older analysis generation.' },
	'engine-unavailable': { retryable: false, description: 'The required engine is not installed or failed to load.' },
	'engine-fault': { retryable: true, description: 'The engine reported a failure while executing.' },
	'parse-failed': { retryable: false, description: 'The input could not be parsed as its declared format.' },
	'output-unsafe': { retryable: false, description: 'The requested output path failed containment checks.' },
	'budget-exceeded': { retryable: false, description: 'An instruction, path, solver, or memory budget was exceeded.' },
	'cancelled': { retryable: false, description: 'The operation was cancelled by the caller.' },
	'timeout': { retryable: true, description: 'The operation exceeded its time budget.' },
	'partial-result': { retryable: true, description: 'The operation completed with reduced coverage or confidence.' },
};

export function isAnalysisErrorCode(value: unknown): value is AnalysisErrorCode {
	return typeof value === 'string' && (ANALYSIS_ERROR_CODES as readonly string[]).includes(value);
}

/**
 * Build a contract error diagnostic. Retryability defaults to the registry
 * spec and can be overridden for a specific occurrence.
 */
export function analysisError(
	code: AnalysisErrorCode,
	message: string,
	options: { retryable?: boolean; address?: AnalysisAddress; details?: Record<string, unknown> } = {},
): AnalysisDiagnostic {
	return {
		code,
		severity: 'error',
		message,
		retryable: options.retryable ?? ANALYSIS_ERROR_SPECS[code].retryable,
		...(options.address ? { address: options.address } : {}),
		...(options.details ? { details: options.details } : {}),
	};
}

/** Successful contract result; `ok` results never carry error diagnostics. */
export function okResult<T>(data?: T, artifacts?: readonly AnalysisArtifactReference[]): AnalysisResult<T> {
	return createAnalysisResult({
		status: 'ok',
		...(data !== undefined ? { data } : {}),
		...(artifacts ? { artifacts } : {}),
	});
}

/**
 * Partial contract result. Partial is honest reduced coverage, never a hidden
 * failure: diagnostics should explain what was capped, dropped, or degraded.
 */
export function partialResult<T>(
	data: T | undefined,
	diagnostics: readonly AnalysisDiagnostic[],
	artifacts?: readonly AnalysisArtifactReference[],
): AnalysisResult<T> {
	return createAnalysisResult({
		status: 'partial',
		...(data !== undefined ? { data } : {}),
		diagnostics,
		...(artifacts ? { artifacts } : {}),
	});
}

/** Failed contract result with a typed error code from the registry. */
export function failedResult<T = never>(
	code: AnalysisErrorCode,
	message: string,
	options: { retryable?: boolean; address?: AnalysisAddress; details?: Record<string, unknown> } = {},
): AnalysisResult<T> {
	return createAnalysisResult({
		status: 'failed',
		diagnostics: [analysisError(code, message, options)],
	});
}

/** Skipped contract result (a gate decided not to run, with the reason). */
export function skippedResult<T = never>(reason: string, code: AnalysisErrorCode = 'invalid-input'): AnalysisResult<T> {
	return createAnalysisResult({
		status: 'skipped',
		diagnostics: [{ code, severity: 'info', message: reason, retryable: false }],
	});
}
