/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as crypto from 'crypto';
import type { ArchitectureConfig } from './capstoneWrapper';
import type { HelixAnalysisContext } from './helixAnalysisContext';
import type { RemillLiftOptions } from './remillWrapper';
import { canonicalSerialize } from './semanticModel';

export interface ReadonlyNativeRequest {
	version: 1;
	context: HelixAnalysisContext;
	architecture: ArchitectureConfig;
	targetOs: 'windows' | 'linux';
	input: { kind: 'bytes'; bytesBase64: string; byteSha256: string; address: number; options: RemillLiftOptions } | { kind: 'ir'; text: string; irSha256: string };
	dataSections: Array<{ address: string; bytesBase64: string }>;
	externalSymbols: Array<{ address: number; name: string }>;
	preparationIssues: string[];
	relocationPreparation?: { sourceSha256: string; preparedSha256: string; patchCount: number };
	entryPreparation?: { policy: 'preserve'; sourceSha256: string; observedSkipBytes: number; observedKinds: string[] };
	irAncestry?: { artifactSha256: string; targetIdentity: string; sessionId: string; generation: number; universeSha256: string; producerCommand: string };
	maxOutputBytes: number;
}
export interface ReadonlyNativeResult {
	status: 'ok' | 'partial' | 'error';
	success: boolean;
	requestSha256: string;
	contextSha256: string;
	phase: 'initializing' | 'lifting' | 'decompiling' | 'terminal';
	architecture: string;
	source: string;
	hastBase64: string;
	irSha256?: string;
	hastSha256?: string;
	qualityIssues: string[];
	semanticEligible: boolean;
	error?: string;
}
export function nativeRequestSha256(request: ReadonlyNativeRequest): string {
	return crypto.createHash('sha256').update(canonicalSerialize(request)).digest('hex');
}
export function nativeBytesSha256(bytes: Buffer | string): string { return crypto.createHash('sha256').update(bytes).digest('hex'); }

export function validateNativeFunctionIdentity(context: HelixAnalysisContext, result: { functionName: string; entryAddress: string }): void {
	if (result.functionName !== context.function.name) { throw new Error(`native-query: HAST function identity mismatch: ${result.functionName || 'missing'}`); }
	if (!/^0x[0-9a-f]{1,16}$/i.test(result.entryAddress) || BigInt(result.entryAddress) !== BigInt(context.function.entry)) { throw new Error(`native-query: HAST entry identity mismatch: ${result.entryAddress || 'missing'}`); }
}

export function validateReadonlyNativeRequest(request: ReadonlyNativeRequest): void {
	if (!request || request.version !== 1 || !request.context?.queryIdentity) { throw new Error('native-query: missing pinned context'); }
	const identity = request.context.queryIdentity;
	if (typeof identity.sessionId !== 'string' || !identity.sessionId || !Number.isSafeInteger(identity.generation) || identity.generation < 0 || !Number.isSafeInteger(identity.engineGeneration) || request.context.analysis?.generation !== identity.engineGeneration || !/^[a-f0-9]{64}$/.test(identity.snapshotSha256) || !/^[a-f0-9]{64}$/.test(identity.universeSha256)) { throw new Error('native-query: incomplete snapshot identity'); }
	if (!Number.isSafeInteger(request.maxOutputBytes) || request.maxOutputBytes < 4096 || request.maxOutputBytes > 64 * 1024 * 1024) { throw new Error('native-query: invalid output budget'); }
	if (Buffer.byteLength(canonicalSerialize(request)) > 96 * 1024 * 1024) { throw new Error('native-query: request budget exceeded'); }
	const { contextSha256, ...payload } = request.context;
	if (nativeBytesSha256(JSON.stringify(payload)) !== contextSha256) { throw new Error('native-query: context digest mismatch'); }
	if (request.context.target.id !== request.context.queryIdentity.targetIdentity || request.context.target.architecture !== request.architecture || !['x86', 'x64', 'arm64'].includes(request.architecture)) { throw new Error('native-query: target/architecture mismatch'); }
	if (!['windows', 'linux'].includes(request.targetOs)) { throw new Error('native-query: invalid OS'); }
	if (request.context.abi.platform !== 'unknown' && request.context.abi.platform !== (request.targetOs === 'windows' ? 'windows' : 'sysv')) { throw new Error('native-query: platform mismatch'); }
	if (!Array.isArray(request.preparationIssues) || request.preparationIssues.some(issue => typeof issue !== 'string')) { throw new Error('native-query: invalid preparation quality'); }
	if (!Array.isArray(request.dataSections) || request.dataSections.length > 128 || !Array.isArray(request.externalSymbols) || request.externalSymbols.length > 100000) { throw new Error('native-query: context collection budget exceeded'); }
	for (const section of request.dataSections) {
		if (!/^0x[0-9a-f]{1,16}$/i.test(section.address) || typeof section.bytesBase64 !== 'string' || Buffer.from(section.bytesBase64, 'base64').toString('base64') !== section.bytesBase64) { throw new Error('native-query: invalid data section'); }
	}
	for (const symbol of request.externalSymbols) if (!Number.isSafeInteger(symbol.address) || symbol.address < 0 || typeof symbol.name !== 'string' || !symbol.name || symbol.name.length > 1024) { throw new Error('native-query: invalid symbol'); }
	if (request.input.kind === 'bytes') {
		const bytes = Buffer.from(request.input.bytesBase64, 'base64');
		if (!Number.isSafeInteger(request.input.address) || request.input.address < 0 || request.context.function.entry !== `0x${request.input.address.toString(16)}` || bytes.length === 0 || bytes.length > 4 * 1024 * 1024 || bytes.toString('base64') !== request.input.bytesBase64 || nativeBytesSha256(bytes) !== request.input.byteSha256) { throw new Error('native-query: invalid byte identity'); }
		if (Number.parseInt(request.context.function.end, 16) !== request.input.address + bytes.length) { throw new Error('native-query: byte window differs from accepted extent'); }
		for (const [key, maximum] of [['maxBytes', 4 * 1024 * 1024], ['maxInstructions', 250000], ['maxBasicBlocks', 64000]] as const) {
			const value = request.input.options?.[key];
			if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > maximum) { throw new Error(`native-query: invalid lift ${key}`); }
		}
		if (request.input.options.maxBytes !== bytes.length) { throw new Error('native-query: lift window budget mismatch'); }
		if (request.entryPreparation) {
			const entry = request.entryPreparation;
			if (entry.policy !== 'preserve' || entry.sourceSha256 !== (request.relocationPreparation?.sourceSha256 ?? request.input.byteSha256) || !Number.isSafeInteger(entry.observedSkipBytes) || entry.observedSkipBytes < 0 || entry.observedSkipBytes > bytes.length || !Array.isArray(entry.observedKinds) || entry.observedKinds.some(kind => !['cet-preamble', 'ftrace-preamble', 'nop-preamble'].includes(kind))) { throw new Error('native-query: invalid entry preparation'); }
		}
		if (request.relocationPreparation) {
			const prepared = request.relocationPreparation;
			if (!/^[a-f0-9]{64}$/.test(prepared.sourceSha256) || prepared.preparedSha256 !== request.input.byteSha256 || !Number.isSafeInteger(prepared.patchCount) || prepared.patchCount < 0 || prepared.patchCount > bytes.length || prepared.patchCount === 0 && prepared.sourceSha256 !== prepared.preparedSha256) { throw new Error('native-query: invalid relocation provenance'); }
		}
	} else if (request.input.kind === 'ir') {
		if (typeof request.input.text !== 'string' || Buffer.byteLength(request.input.text) > 32 * 1024 * 1024 || nativeBytesSha256(request.input.text) !== request.input.irSha256) { throw new Error('native-query: invalid IR identity'); }
		if (request.irAncestry && (request.irAncestry.artifactSha256 !== request.input.irSha256 || request.irAncestry.targetIdentity !== identity.targetIdentity || request.irAncestry.sessionId !== identity.sessionId || request.irAncestry.generation !== identity.generation || request.irAncestry.universeSha256 !== identity.universeSha256 || !request.irAncestry.producerCommand)) { throw new Error('native-query: IR ancestry mismatch'); }
	} else { throw new Error('native-query: unknown input kind'); }
}

export function nativeError(request: ReadonlyNativeRequest, requestSha256: string, error: string): ReadonlyNativeResult {
	error = error.slice(0, 768);
	return { status: 'error', success: false, requestSha256, contextSha256: request.context.contextSha256, phase: 'terminal', architecture: request.architecture, source: '', hastBase64: '', qualityIssues: [error], semanticEligible: false, error };
}
