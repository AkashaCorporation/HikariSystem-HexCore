/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { ArchitectureConfig } from './capstoneWrapper';
import type { HelixAnalysisContext } from './helixAnalysisContext';
import type { HelixRuntimeIdentity } from './helixWrapper';

type JsonValue = null | boolean | string | JsonValue[] | { [key: string]: JsonValue };

export interface CanonicalHelixDataSection {
	vaStart: bigint;
	bytes: Buffer;
	name?: string;
}

export interface CanonicalHelixRequestBuildOptions {
	requestPath: string;
	irText: string;
	targetPath: string;
	architecture: ArchitectureConfig;
	imageBase: number;
	exactRange?: { startAddress: number; endExclusive: number };
	functionStarts?: readonly number[];
	dataSections?: readonly CanonicalHelixDataSection[];
	debugEnvelopeJson?: string;
	semanticContext?: HelixAnalysisContext;
	useCastLayer: boolean;
	skipOptimization: boolean;
	variableRenames?: readonly { oldName: string; newName: string }[];
	runtimeIdentity?: HelixRuntimeIdentity;
}

export interface LoadedCanonicalHelixRequest {
	requestPath: string;
	requestHash: string;
	semanticRequest: Record<string, JsonValue>;
	irPath: string;
	irSha256: string;
	irText: string;
	targetPath: string;
	architecture: ArchitectureConfig;
	exactRange: { startAddress: number; endExclusive: number };
	functionStarts: number[];
	dataSections: Array<{ vaStart: bigint; bytes: Buffer }>;
	debugTypeInfoJson: string;
	useCastLayer: boolean;
	skipOptimization: boolean;
	variableRenames: Array<{ oldName: string; newName: string }>;
}

export interface CanonicalHelixRequestEnvelope {
	schemaVersion: 1;
	requestHash: string;
	semanticRequest: Record<string, JsonValue>;
	artifacts: {
		target: { path: string; sha256: string };
		ir: { path: string; sha256: string; mediaType: 'text/x-llvm' };
		sections: Array<{ byteRef: string; path: string; sha256: string }>;
		debugEnvelope?: { byteRef: string; path: string; sha256: string; mediaType: 'application/json' };
	};
	runtimeIdentity?: Record<string, unknown>;
}

const SHA256_RE = /^[a-f0-9]{64}$/;
const HEX_RE = /^0x(?:0|[1-9a-f][0-9a-f]*)$/;

function sha256Bytes(value: Buffer | string): string {
	return crypto.createHash('sha256').update(value).digest('hex');
}

function jsonString(value: string): string {
	return JSON.stringify(value);
}

/** Canonical JSON used by both the Extension Host and helix_tool. */
export function canonicalHelixJson(value: JsonValue): string {
	if (value === null) { return 'null'; }
	if (typeof value === 'boolean') { return value ? 'true' : 'false'; }
	if (typeof value === 'string') { return jsonString(value); }
	if (Array.isArray(value)) {
		return `[${value.map(item => canonicalHelixJson(item)).join(',')}]`;
	}
	if (typeof value === 'object') {
		return `{${Object.keys(value).sort().map(key =>
			`${jsonString(key)}:${canonicalHelixJson(value[key])}`).join(',')}}`;
	}
	throw new Error('Canonical Helix semantic requests may contain only null, booleans, strings, arrays and objects');
}

function canonicalHash(value: Record<string, JsonValue>): string {
	return `sha256:${sha256Bytes(canonicalHelixJson(value))}`;
}

function hex(value: number | bigint): string {
	const numeric = typeof value === 'bigint' ? value : BigInt(value);
	if (numeric < 0n) throw new Error('Canonical Helix addresses and sizes cannot be negative');
	return `0x${numeric.toString(16)}`;
}

function parseHex(value: unknown, label: string): bigint {
	if (typeof value !== 'string' || !HEX_RE.test(value)) {
		throw new Error(`${label} must be a canonical lowercase hex string`);
	}
	return BigInt(value);
}

function safeNumber(value: bigint, label: string): number {
	if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
		throw new Error(`${label} exceeds JavaScript safe integer range`);
	}
	return Number(value);
}

function asObject(value: unknown, label: string): Record<string, unknown> {
	if (!value || typeof value !== 'object' || Array.isArray(value)) {
		throw new Error(`${label} must be an object`);
	}
	return value as Record<string, unknown>;
}

function asString(value: unknown, label: string): string {
	if (typeof value !== 'string' || value.length === 0) {
		throw new Error(`${label} must be a non-empty string`);
	}
	return value;
}

function asBoolean(value: unknown, label: string): boolean {
	if (typeof value !== 'boolean') throw new Error(`${label} must be boolean`);
	return value;
}

function assertSha256(value: string, label: string): string {
	if (!SHA256_RE.test(value)) throw new Error(`${label} must be lowercase SHA-256`);
	return value;
}

function resolveArtifactPath(requestPath: string, artifactPath: string): string {
	return path.isAbsolute(artifactPath)
		? path.resolve(artifactPath)
		: path.resolve(path.dirname(requestPath), artifactPath);
}

function relativeArtifactPath(requestPath: string, artifactPath: string): string {
	return path.relative(path.dirname(requestPath), artifactPath).replace(/\\/g, '/');
}

function parseIrRange(irText: string): {
	startAddress: number;
	endExclusive: number;
	sourceSha256: string;
} {
	const match = /^; RequestedByteRange: \[(0x[0-9A-Fa-f]+), (0x[0-9A-Fa-f]+)\).*\bsourceSha256=([a-f0-9]{64})\b/m.exec(irText);
	if (!match) {
		throw new Error('Canonical Helix export requires a hash-bound RequestedByteRange in the IR header');
	}
	const start = BigInt(match[1]);
	const end = BigInt(match[2]);
	if (end <= start) throw new Error('IR RequestedByteRange is empty or reversed');
	return {
		startAddress: safeNumber(start, 'IR range start'),
		endExclusive: safeNumber(end, 'IR range end'),
		sourceSha256: match[3],
	};
}

function normalizeArchitecture(architecture: string): ArchitectureConfig {
	switch (architecture) {
		case 'x86': case 'x64': case 'arm': case 'arm64': case 'mips': case 'mips64': return architecture;
		case 'x86_64': return 'x64';
		case 'aarch64': return 'arm64';
		default: throw new Error(`Unsupported canonical Helix architecture: ${architecture}`);
	}
}

function semanticArchitecture(architecture: ArchitectureConfig): string {
	return architecture === 'x64' ? 'x86_64' : architecture === 'arm64' ? 'aarch64' : architecture;
}

function validateNoNumbers(value: unknown, label = 'semanticRequest'): asserts value is JsonValue {
	if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
	if (Array.isArray(value)) {
		value.forEach((item, index) => validateNoNumbers(item, `${label}[${index}]`));
		return;
	}
	if (typeof value === 'object') {
		for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
			validateNoNumbers(item, `${label}.${key}`);
		}
		return;
	}
	throw new Error(`${label} contains a forbidden JSON number or unsupported value`);
}

export function writeCanonicalHelixRequest(options: CanonicalHelixRequestBuildOptions): CanonicalHelixRequestEnvelope {
	const requestPath = path.resolve(options.requestPath);
	const requestDir = path.dirname(requestPath);
	const assetDir = path.join(requestDir, `${path.basename(requestPath, path.extname(requestPath))}.assets`);
	fs.mkdirSync(assetDir, { recursive: true });

	const targetPath = path.resolve(options.targetPath);
	const targetBytes = fs.readFileSync(targetPath);
	const targetSha256 = sha256Bytes(targetBytes);
	const irSha256 = sha256Bytes(options.irText);
	const irPath = path.join(assetDir, `${irSha256}.ll`);
	fs.writeFileSync(irPath, options.irText, 'utf8');

	const irRange = parseIrRange(options.irText);
	const exactRange = options.exactRange ?? irRange;
	if (exactRange.startAddress !== irRange.startAddress || exactRange.endExclusive !== irRange.endExclusive) {
		throw new Error('Explicit canonical range differs from the hash-bound IR range');
	}

	const normalizedSections = [...(options.dataSections ?? [])]
		.map((section, index) => ({
			name: section.name ?? `section_${hex(section.vaStart)}`,
			vaStart: section.vaStart,
			bytes: Buffer.from(section.bytes),
			index,
		}))
		.sort((left, right) => left.vaStart < right.vaStart ? -1 : left.vaStart > right.vaStart ? 1 : left.index - right.index);
	const sectionRecords: Array<Record<string, JsonValue>> = [];
	const sectionArtifacts: CanonicalHelixRequestEnvelope['artifacts']['sections'] = [];
	let priorEnd = 0n;
	let priorHash = '';
	for (const section of normalizedSections) {
		const digest = sha256Bytes(section.bytes);
		const end = section.vaStart + BigInt(section.bytes.length);
		if (section.vaStart < priorEnd) {
			if (end === priorEnd && digest === priorHash) continue;
			throw new Error('Canonical Helix data sections overlap or duplicate with divergent bytes');
		}
		priorEnd = end;
		priorHash = digest;
		const byteRef = `artifact:sha256:${digest}`;
		const sectionPath = path.join(assetDir, `${digest}.bin`);
		fs.writeFileSync(sectionPath, section.bytes);
		sectionRecords.push({
			byteRef,
			name: section.name,
			sha256: digest,
			size: hex(section.bytes.length),
			va: hex(section.vaStart),
		});
		sectionArtifacts.push({ byteRef, path: relativeArtifactPath(requestPath, sectionPath), sha256: digest });
	}

	let debugEnvelopeRef: string | null = null;
	let debugArtifact: CanonicalHelixRequestEnvelope['artifacts']['debugEnvelope'];
	if (options.debugEnvelopeJson) {
		JSON.parse(options.debugEnvelopeJson);
		const digest = sha256Bytes(options.debugEnvelopeJson);
		const debugPath = path.join(assetDir, `${digest}.debug.json`);
		fs.writeFileSync(debugPath, options.debugEnvelopeJson, 'utf8');
		debugEnvelopeRef = `artifact:sha256:${digest}`;
		debugArtifact = {
			byteRef: debugEnvelopeRef,
			path: relativeArtifactPath(requestPath, debugPath),
			sha256: digest,
			mediaType: 'application/json',
		};
	}

	const functionStarts = [...new Set(options.functionStarts ?? [])]
		.filter(value => Number.isSafeInteger(value) && value >= 0)
		.sort((left, right) => left - right)
		.map(value => hex(value));
	const variableRenames = [...(options.variableRenames ?? [])]
		.map(item => ({ oldName: item.oldName, newName: item.newName }))
		.sort((left, right) => left.oldName.localeCompare(right.oldName) || left.newName.localeCompare(right.newName));
	const semanticContext = options.semanticContext;
	const semanticRequest: Record<string, JsonValue> = {
		analysisContext: {
			debugEnvelope: debugEnvelopeRef,
			functionStarts,
			generation: hex(semanticContext?.analysis.generation ?? 0),
			universe: semanticContext?.queryIdentity?.universeSha256
				? `sha256:${semanticContext.queryIdentity.universeSha256}` : null,
		},
		function: {
			byteLength: hex(exactRange.endExclusive - exactRange.startAddress),
			endAddress: hex(exactRange.endExclusive),
			entryAddress: hex(exactRange.startAddress),
			extractedBytesSha256: irRange.sourceSha256,
		},
		input: {
			irSha256,
			mediaType: 'text/x-llvm',
		},
		pipelineOptions: {
			enabledPasses: [],
			preserveCfg: false,
			skipOptimization: options.skipOptimization,
			useCastLayer: options.useCastLayer,
			variableRenames,
		},
		sections: sectionRecords,
		target: {
			arch: semanticArchitecture(options.architecture),
			imageBase: hex(options.imageBase),
			pointerSize: hex(options.architecture === 'x64' || options.architecture === 'arm64' || options.architecture === 'mips64' ? 8 : 4),
			sha256: targetSha256,
		},
	};
	const envelope: CanonicalHelixRequestEnvelope = {
		schemaVersion: 1,
		requestHash: canonicalHash(semanticRequest),
		semanticRequest,
		artifacts: {
			target: { path: targetPath, sha256: targetSha256 },
			ir: { path: relativeArtifactPath(requestPath, irPath), sha256: irSha256, mediaType: 'text/x-llvm' },
			sections: sectionArtifacts,
			...(debugArtifact ? { debugEnvelope: debugArtifact } : {}),
		},
		...(options.runtimeIdentity ? { runtimeIdentity: { ...options.runtimeIdentity } } : {}),
	};
	fs.writeFileSync(requestPath, `${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
	return envelope;
}

export function loadCanonicalHelixRequest(filePath: string): LoadedCanonicalHelixRequest {
	const requestPath = path.resolve(filePath);
	const envelope = asObject(JSON.parse(fs.readFileSync(requestPath, 'utf8')), 'canonical request');
	if (envelope.schemaVersion !== 1) throw new Error('Unsupported canonical Helix request schema');
	const semanticUnknown = asObject(envelope.semanticRequest, 'semanticRequest');
	validateNoNumbers(semanticUnknown);
	const semanticRequest = semanticUnknown as Record<string, JsonValue>;
	const requestHash = asString(envelope.requestHash, 'requestHash');
	if (requestHash !== canonicalHash(semanticRequest)) throw new Error('Canonical Helix requestHash mismatch');

	const artifacts = asObject(envelope.artifacts, 'artifacts');
	const targetArtifact = asObject(artifacts.target, 'artifacts.target');
	const targetPath = resolveArtifactPath(requestPath, asString(targetArtifact.path, 'artifacts.target.path'));
	const targetSha256 = assertSha256(asString(targetArtifact.sha256, 'artifacts.target.sha256'), 'artifacts.target.sha256');
	if (sha256Bytes(fs.readFileSync(targetPath)) !== targetSha256) throw new Error('Canonical Helix target artifact hash mismatch');
	const target = asObject(semanticRequest.target, 'semanticRequest.target');
	if (target.sha256 !== targetSha256) throw new Error('Canonical Helix target semantic/artifact hash mismatch');

	const irArtifact = asObject(artifacts.ir, 'artifacts.ir');
	const irPath = resolveArtifactPath(requestPath, asString(irArtifact.path, 'artifacts.ir.path'));
	const irText = fs.readFileSync(irPath, 'utf8');
	const irSha256 = assertSha256(asString(irArtifact.sha256, 'artifacts.ir.sha256'), 'artifacts.ir.sha256');
	if (sha256Bytes(irText) !== irSha256) throw new Error('Canonical Helix IR artifact hash mismatch');
	const input = asObject(semanticRequest.input, 'semanticRequest.input');
	if (input.irSha256 !== irSha256 || input.mediaType !== 'text/x-llvm') {
		throw new Error('Canonical Helix IR semantic/artifact identity mismatch');
	}

	const fn = asObject(semanticRequest.function, 'semanticRequest.function');
	const entry = parseHex(fn.entryAddress, 'function.entryAddress');
	const end = parseHex(fn.endAddress, 'function.endAddress');
	const byteLength = parseHex(fn.byteLength, 'function.byteLength');
	if (end <= entry || end - entry !== byteLength) throw new Error('Canonical Helix function range is inconsistent');
	const irRange = parseIrRange(irText);
	if (irRange.startAddress !== safeNumber(entry, 'function.entryAddress') ||
		irRange.endExclusive !== safeNumber(end, 'function.endAddress') ||
		fn.extractedBytesSha256 !== irRange.sourceSha256) {
		throw new Error('Canonical Helix function range differs from the retained IR');
	}

	const analysisContext = asObject(semanticRequest.analysisContext, 'semanticRequest.analysisContext');
	if (!Array.isArray(analysisContext.functionStarts)) throw new Error('analysisContext.functionStarts must be an array');
	const functionStarts = analysisContext.functionStarts.map((value, index) =>
		safeNumber(parseHex(value, `analysisContext.functionStarts[${index}]`), `analysisContext.functionStarts[${index}]`));
	if (functionStarts.some((value, index) => index > 0 && value <= functionStarts[index - 1])) {
		throw new Error('Canonical Helix functionStarts must be strictly sorted and deduplicated');
	}

	const sectionSemantics = semanticRequest.sections;
	const sectionArtifactList = artifacts.sections;
	if (!Array.isArray(sectionSemantics) || !Array.isArray(sectionArtifactList)) {
		throw new Error('Canonical Helix sections must include semantic and artifact arrays');
	}
	const sectionArtifacts = new Map(sectionArtifactList.map((entry, index) => {
		const record = asObject(entry, `artifacts.sections[${index}]`);
		return [asString(record.byteRef, `artifacts.sections[${index}].byteRef`), record];
	}));
	const dataSections = sectionSemantics.map((entryValue, index) => {
		const record = asObject(entryValue, `semanticRequest.sections[${index}]`);
		const byteRef = asString(record.byteRef, `semanticRequest.sections[${index}].byteRef`);
		const digest = assertSha256(asString(record.sha256, `semanticRequest.sections[${index}].sha256`), `semanticRequest.sections[${index}].sha256`);
		if (byteRef !== `artifact:sha256:${digest}`) throw new Error('Canonical Helix section byteRef/hash mismatch');
		const artifact = sectionArtifacts.get(byteRef);
		if (!artifact || artifact.sha256 !== digest) throw new Error('Canonical Helix section artifact is missing or mismatched');
		const sectionPath = resolveArtifactPath(requestPath, asString(artifact.path, `section artifact ${byteRef}`));
		const bytes = fs.readFileSync(sectionPath);
		if (sha256Bytes(bytes) !== digest || BigInt(bytes.length) !== parseHex(record.size, `semanticRequest.sections[${index}].size`)) {
			throw new Error('Canonical Helix section bytes differ from the request');
		}
		return { vaStart: parseHex(record.va, `semanticRequest.sections[${index}].va`), bytes };
	});

	let debugTypeInfoJson = '';
	if (analysisContext.debugEnvelope !== null) {
		const byteRef = asString(analysisContext.debugEnvelope, 'analysisContext.debugEnvelope');
		const artifact = asObject(artifacts.debugEnvelope, 'artifacts.debugEnvelope');
		const digest = assertSha256(asString(artifact.sha256, 'artifacts.debugEnvelope.sha256'), 'artifacts.debugEnvelope.sha256');
		if (byteRef !== `artifact:sha256:${digest}` || artifact.byteRef !== byteRef) {
			throw new Error('Canonical Helix debug envelope reference mismatch');
		}
		const debugPath = resolveArtifactPath(requestPath, asString(artifact.path, 'artifacts.debugEnvelope.path'));
		debugTypeInfoJson = fs.readFileSync(debugPath, 'utf8');
		if (sha256Bytes(debugTypeInfoJson) !== digest) throw new Error('Canonical Helix debug envelope hash mismatch');
		JSON.parse(debugTypeInfoJson);
	}

	const pipeline = asObject(semanticRequest.pipelineOptions, 'semanticRequest.pipelineOptions');
	if (pipeline.preserveCfg !== false || !Array.isArray(pipeline.enabledPasses) || pipeline.enabledPasses.length !== 0) {
		throw new Error('Canonical Helix v1 supports preserveCfg=false and no selective passes');
	}
	if (!Array.isArray(pipeline.variableRenames)) throw new Error('pipelineOptions.variableRenames must be an array');
	const variableRenames = pipeline.variableRenames.map((value, index) => {
		const rename = asObject(value, `pipelineOptions.variableRenames[${index}]`);
		return {
			oldName: asString(rename.oldName, `pipelineOptions.variableRenames[${index}].oldName`),
			newName: asString(rename.newName, `pipelineOptions.variableRenames[${index}].newName`),
		};
	});

	return {
		requestPath,
		requestHash,
		semanticRequest,
		irPath,
		irSha256,
		irText,
		targetPath,
		architecture: normalizeArchitecture(asString(target.arch, 'target.arch')),
		exactRange: { startAddress: safeNumber(entry, 'function.entryAddress'), endExclusive: safeNumber(end, 'function.endAddress') },
		functionStarts,
		dataSections,
		debugTypeInfoJson,
		useCastLayer: asBoolean(pipeline.useCastLayer, 'pipelineOptions.useCastLayer'),
		skipOptimization: asBoolean(pipeline.skipOptimization, 'pipelineOptions.skipOptimization'),
		variableRenames,
	};
}
