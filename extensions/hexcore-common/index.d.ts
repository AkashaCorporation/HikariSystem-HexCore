/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export function formatBytes(bytes: number): string;
export function calculateEntropy(buffer: Buffer): number;
export function readNullTerminatedString(buffer: Buffer, maxLength?: number): string;
export function isPrintableASCII(byte: number): boolean;
export function toHexDump(buffer: Buffer, bytesPerLine?: number): string;
export function escapeHtml(text: string): string;
export function formatHex(value: number, padLength?: number): string;
export function processFileInChunks(
	filePath: string,
	chunkSize: number,
	processor: (chunk: Buffer, offset: number) => void | Promise<void>,
	onProgress?: (bytesProcessed: number, totalBytes: number) => void
): Promise<void>;

export function isWithinDir(parent: string, child: string): boolean;
export function resolvePathWithinRoots(candidatePath: string, roots: readonly string[]): string | undefined;
export function assertWithinWorkspaceOrHome(
	outputPath: string,
	workspaceRoots: readonly string[],
	homeDir?: string
): string;

export interface NativeModuleLoadOptions {
	moduleName: string;
	candidatePaths?: string[];
}

export interface NativeModuleLoadResult<T> {
	module?: T;
	error?: Error;
	attemptedPaths: string[];
	errorMessage: string;
}

export function loadNativeModule<T = unknown>(options: NativeModuleLoadOptions): NativeModuleLoadResult<T>;

export function getHexCoreBaseCSS(): string;

export function riskLevelToColor(level: 'safe' | 'warning' | 'danger'): string;
export function entropyToColor(value: number): string;

export const ANALYSIS_CONTRACT_VERSION: 1;

export type AnalysisBinaryFormat = 'pe' | 'elf' | 'minidump' | 'macho' | 'raw' | 'unknown';
export type AnalysisStatus = 'ok' | 'partial' | 'failed' | 'skipped';
export type AnalysisAddressSpace = 'file-offset' | 'rva' | 'va' | 'runtime-va';
export type AnalysisDiagnosticSeverity = 'info' | 'warning' | 'error';

export interface AnalysisAddress {
	space: AnalysisAddressSpace;
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

export function normalizeSha256(value: string): string;
export function normalizeAddressValue(value: string | bigint | number): string;
export function createAnalysisAddress(
	space: AnalysisAddressSpace,
	value: string | bigint | number,
	options?: { architecture?: string; overlayId?: string }
): AnalysisAddress;
export function createAnalysisTarget(input: AnalysisTargetInput): AnalysisTarget;
export function createAnalysisSession(input: AnalysisSessionInput): AnalysisSession;
export function createAnalysisResult<T>(input: AnalysisResultInput<T>): AnalysisResult<T>;
export function isAnalysisResult(value: unknown): value is AnalysisResult<unknown>;
export function createAnalysisArtifactProvenance(input: AnalysisArtifactProvenanceInput): AnalysisArtifactProvenance;

export type AnalysisObjectKind =
	| 'function'
	| 'basic-block'
	| 'instruction'
	| 'data-object'
	| 'string'
	| 'type'
	| 'variable'
	| 'xref'
	| 'finding'
	| 'artifact';

export interface AnalysisAddressedObjectIdInput {
	target: AnalysisTarget;
	space: AnalysisAddressSpace;
	address: string | bigint | number;
}

export interface AnalysisBasicBlockIdInput {
	target: AnalysisTarget;
	space: AnalysisAddressSpace;
	functionEntry: string | bigint | number;
	blockStart: string | bigint | number;
}

export interface AnalysisStringIdInput {
	target: AnalysisTarget;
	fileOffset: string | bigint | number;
}

export interface AnalysisTypeIdInput {
	target: AnalysisTarget;
	name: string;
}

export interface AnalysisVariableIdInput {
	target: AnalysisTarget;
	name: string;
	owner?: {
		space: AnalysisAddressSpace;
		functionEntry: string | bigint | number;
	} | 'global';
}

export interface AnalysisXrefIdInput {
	target: AnalysisTarget;
	from: { space: AnalysisAddressSpace; address: string | bigint | number };
	to: { space: AnalysisAddressSpace; address: string | bigint | number };
	kind: string;
}

export interface AnalysisFindingIdInput {
	target: AnalysisTarget;
	category: string;
	subject:
		| { space: AnalysisAddressSpace; address: string | bigint | number }
		| { token: string };
}

export interface ParsedAnalysisObjectId {
	kind: AnalysisObjectKind;
	targetId?: string;
	digest: string;
	parts: string[];
}

export function createFunctionId(input: AnalysisAddressedObjectIdInput): string;
export function createBasicBlockId(input: AnalysisBasicBlockIdInput): string;
export function createInstructionId(input: AnalysisAddressedObjectIdInput): string;
export function createDataObjectId(input: AnalysisAddressedObjectIdInput): string;
export function createStringId(input: AnalysisStringIdInput): string;
export function createTypeId(input: AnalysisTypeIdInput): string;
export function createVariableId(input: AnalysisVariableIdInput): string;
export function createXrefId(input: AnalysisXrefIdInput): string;
export function createFindingId(input: AnalysisFindingIdInput): string;
export function createArtifactId(contentSha256: string): string;
export function parseAnalysisObjectId(id: string): ParsedAnalysisObjectId;
export function isAnalysisObjectId(value: unknown): value is string;
export function analysisObjectIdTargetId(id: string): string | undefined;

export const ANALYSIS_ERROR_CODES: readonly [
	'invalid-input', 'not-found', 'wrong-target', 'stale-generation',
	'engine-unavailable', 'engine-fault', 'parse-failed', 'output-unsafe',
	'budget-exceeded', 'cancelled', 'timeout', 'partial-result'
];
export type AnalysisErrorCode = typeof ANALYSIS_ERROR_CODES[number];
export interface AnalysisErrorSpec {
	retryable: boolean;
	description: string;
}
export const ANALYSIS_ERROR_SPECS: Readonly<Record<AnalysisErrorCode, AnalysisErrorSpec>>;
export function isAnalysisErrorCode(value: unknown): value is AnalysisErrorCode;
export function analysisError(
	code: AnalysisErrorCode,
	message: string,
	options?: { retryable?: boolean; address?: AnalysisAddress; details?: Record<string, unknown> }
): AnalysisDiagnostic;
export function okResult<T>(data?: T, artifacts?: readonly AnalysisArtifactReference[]): AnalysisResult<T>;
export function partialResult<T>(
	data: T | undefined,
	diagnostics: readonly AnalysisDiagnostic[],
	artifacts?: readonly AnalysisArtifactReference[]
): AnalysisResult<T>;
export function failedResult<T = never>(
	code: AnalysisErrorCode,
	message: string,
	options?: { retryable?: boolean; address?: AnalysisAddress; details?: Record<string, unknown> }
): AnalysisResult<T>;
export function skippedResult<T = never>(reason: string, code?: AnalysisErrorCode): AnalysisResult<T>;

// v4.0.0 — SharedArrayBuffer zero-copy IPC primitives (Issue #31)

export const RING_BUFFER_MAGIC: number;
export const RING_BUFFER_VERSION: number;
export const RING_BUFFER_HEADER_SIZE: number;
export const SHARED_MEMORY_HEADER_SIZE: number;

export interface SharedRingBufferOptions {
	readonly slotSize: number;
	readonly slotCount: number;
}

export type SlotConsumer = (slot: Uint8Array, sequenceNumber: bigint) => void;

export class SharedRingBuffer {
	constructor(options: SharedRingBufferOptions);
	static attach(buffer: SharedArrayBuffer): SharedRingBuffer;
	readonly buffer: SharedArrayBuffer;
	readonly slotSize: number;
	readonly slotCount: number;
	drain(onSlot: SlotConsumer, maxPerBatch?: number): number;
	droppedCount(): number;
	get headIndex(): number;
	get tailIndex(): number;
	get occupancy(): number;
	tryProduce(writer: (slot: Uint8Array) => void): boolean;
}

export interface SharedMemoryBufferOptions {
	readonly payloadSize: number;
}

export const SHARED_MEMORY_STATUS: {
	readonly IDLE: 0;
	readonly BUSY: 1;
	readonly COMPLETE: 2;
	readonly ERROR: -1;
};

export class SharedMemoryBuffer {
	constructor(options: SharedMemoryBufferOptions);
	readonly buffer: SharedArrayBuffer;
	readonly totalSize: number;
	readonly payloadSize: number;
	readonly headerView: Int32Array;
	readonly payloadView: Uint8Array;
	getDataSize(): number;
	setDataSize(size: number): void;
	getStatus(): number;
	setStatus(status: number): void;
	getActivePayload(): Uint8Array;
}
