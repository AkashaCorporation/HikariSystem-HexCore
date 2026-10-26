/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import type {
	FunctionAnalysisMaterialization,
	FunctionMaterializationOptions,
} from './disassemblerEngine';

export interface FunctionMaterializationCommandOptions {
	addresses: Array<string | number>;
	maxFunctions?: number;
	maxBytesPerFn?: number;
}

export interface FunctionMaterializationCommandEngine {
	materializeFunctionForAnalysis(
		address: number,
		options?: FunctionMaterializationOptions,
	): Promise<FunctionAnalysisMaterialization>;
	getAnalysisGeneration(): number;
	getFilePath(): string | undefined;
	getSessionStore(): {
		getAnalysisSession(): { id: string; generation: number } | undefined;
		getAnalysisUniverseManifest(): { universeSha256: string; materializedFunctions: readonly unknown[] } | undefined;
	} | undefined;
}

export interface FunctionMaterializationResultEntry {
	address: string;
	status: FunctionAnalysisMaterialization['status'];
	changed: boolean;
	instructionsAdded: number;
	engineGenerationBefore: number;
	engineGenerationAfter: number;
	sessionGenerationBefore?: number;
	sessionGenerationAfter?: number;
	bodyCompleteness?: FunctionAnalysisMaterialization['bodyCompleteness'];
}

export interface FunctionMaterializationCommandResult {
	schemaVersion: 1;
	status: 'ok' | 'partial';
	semanticStatus: 'ok' | 'partial';
	target?: string;
	requested: number;
	uniqueRequested: number;
	processed: number;
	truncated: boolean;
	maxFunctions: number;
	maxBytesPerFn?: number;
	committed: number;
	alreadyCurrent: number;
	partial: number;
	decodeEmpty: number;
	unknownFunctions: number;
	engineGenerationBefore: number;
	engineGenerationAfter: number;
	sessionId?: string;
	sessionGeneration?: number;
	universeSha256?: string;
	persistedMaterializedFunctions?: number;
	functions: FunctionMaterializationResultEntry[];
	warnings: string[];
}

const DEFAULT_MAX_FUNCTIONS = 256;
const MAX_FUNCTIONS = 4096;
const MAX_BYTES_PER_FUNCTION = 16 * 1024 * 1024;

export function parseMaterializationAddress(value: string | number): number {
	if (typeof value === 'number') {
		if (!Number.isSafeInteger(value) || value <= 0) {
			throw new Error(`Invalid function address: ${String(value)}`);
		}
		return value;
	}
	if (typeof value !== 'string' || value.trim().length === 0) {
		throw new Error(`Invalid function address: ${String(value)}`);
	}
	const text = value.trim();
	if (!/^0x/i.test(text)) {
		throw new Error(`String function addresses must use a 0x prefix: ${value}`);
	}
	const digits = text.slice(2);
	if (!/^[0-9a-f]+$/i.test(digits)) {
		throw new Error(`Invalid function address: ${value}`);
	}
	const parsed = Number.parseInt(digits, 16);
	if (!Number.isSafeInteger(parsed) || parsed <= 0) {
		throw new Error(`Invalid function address: ${value}`);
	}
	return parsed;
}

function positiveInteger(value: unknown, fallback: number, field: string, maximum: number): number {
	if (value === undefined) { return fallback; }
	if (typeof value !== 'number' || !Number.isInteger(value) || value <= 0 || value > maximum) {
		throw new Error(`${field} must be an integer in the range 1..${maximum}.`);
	}
	return value;
}

export async function runFunctionMaterializationCommand(
	engine: FunctionMaterializationCommandEngine,
	options: FunctionMaterializationCommandOptions,
): Promise<FunctionMaterializationCommandResult> {
	if (!Array.isArray(options.addresses) || options.addresses.length === 0) {
		throw new Error('materializeFunctions requires a non-empty addresses array.');
	}
	const maxFunctions = positiveInteger(options.maxFunctions, DEFAULT_MAX_FUNCTIONS, 'maxFunctions', MAX_FUNCTIONS);
	const maxBytesPerFn = options.maxBytesPerFn === undefined
		? undefined
		: positiveInteger(options.maxBytesPerFn, 1, 'maxBytesPerFn', MAX_BYTES_PER_FUNCTION);
	const unique: number[] = [];
	const seen = new Set<number>();
	for (const raw of options.addresses) {
		const address = parseMaterializationAddress(raw);
		if (!seen.has(address)) { seen.add(address); unique.push(address); }
	}
	const selected = unique.slice(0, maxFunctions);
	const engineGenerationBefore = engine.getAnalysisGeneration();
	const functions: FunctionMaterializationResultEntry[] = [];
	for (const address of selected) {
		const result = await engine.materializeFunctionForAnalysis(address,
			maxBytesPerFn === undefined ? undefined : { maxBytes: maxBytesPerFn });
		functions.push({
			address: `0x${address.toString(16).toUpperCase()}`,
			status: result.status,
			changed: result.changed,
			instructionsAdded: result.instructionsAdded,
			engineGenerationBefore: result.engineGenerationBefore,
			engineGenerationAfter: result.engineGenerationAfter,
			...(result.sessionGenerationBefore !== undefined ? { sessionGenerationBefore: result.sessionGenerationBefore } : {}),
			...(result.sessionGenerationAfter !== undefined ? { sessionGenerationAfter: result.sessionGenerationAfter } : {}),
			...(result.bodyCompleteness ? { bodyCompleteness: result.bodyCompleteness } : {}),
		});
	}
	const count = (status: FunctionAnalysisMaterialization['status']) =>
		functions.filter(entry => entry.status === status).length;
	const truncated = selected.length < unique.length;
	const committed = count('committed');
	const alreadyCurrent = count('already-current');
	const partial = count('partial');
	const decodeEmpty = count('decode-empty');
	const unknownFunctions = count('unknown-function');
	const warnings: string[] = [];
	if (truncated) { warnings.push(`Address list truncated from ${unique.length} to ${selected.length} by maxFunctions.`); }
	if (partial > 0) { warnings.push(`${partial} function(s) remained partial and retryable.`); }
	if (decodeEmpty > 0) { warnings.push(`${decodeEmpty} function(s) decoded no instructions.`); }
	if (unknownFunctions > 0) { warnings.push(`${unknownFunctions} address(es) are not known function starts.`); }
	const session = engine.getSessionStore()?.getAnalysisSession();
	const universe = engine.getSessionStore()?.getAnalysisUniverseManifest();
	const semanticStatus = truncated || partial > 0 || decodeEmpty > 0 || unknownFunctions > 0 ? 'partial' : 'ok';
	return {
		schemaVersion: 1,
		status: semanticStatus,
		semanticStatus,
		...(engine.getFilePath() ? { target: engine.getFilePath() } : {}),
		requested: options.addresses.length,
		uniqueRequested: unique.length,
		processed: functions.length,
		truncated,
		maxFunctions,
		...(maxBytesPerFn !== undefined ? { maxBytesPerFn } : {}),
		committed,
		alreadyCurrent,
		partial,
		decodeEmpty,
		unknownFunctions,
		engineGenerationBefore,
		engineGenerationAfter: engine.getAnalysisGeneration(),
		...(session ? { sessionId: session.id, sessionGeneration: session.generation } : {}),
		...(universe ? {
			universeSha256: universe.universeSha256,
			persistedMaterializedFunctions: universe.materializedFunctions.length,
		} : {}),
		functions,
		warnings,
	};
}
