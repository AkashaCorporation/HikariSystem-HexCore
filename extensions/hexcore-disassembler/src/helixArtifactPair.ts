/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import type { HelixRuntimeIdentity } from './helixWrapper';
import type { HelixStructuredQualityIssue } from './helixOutputQuality';

export interface HastContractVariableSummary {
	name: string;
	type: string;
	storage?: string;
	parameterIndex?: number;
}

export interface HastContractFunctionSummary {
	name: string;
	address: string;
	returnType: string;
	params: HastContractVariableSummary[];
	locals: HastContractVariableSummary[];
	callingConvention: string;
	isVariadic: boolean;
	nativeQuality: { status: 'unreported' | 'no-known-loss' | 'known-loss'; issues: string[] };
}

export interface HastContractSummary {
	fileIdentifier: 'HAST';
	moduleName: string;
	schemaMajor: number;
	schemaMinor: number;
	capabilities: string[];
	producer?: string;
	producerVersion?: string;
	architecture?: string;
	pointerBits?: number;
	semanticEligible: boolean;
	functionCount: number;
	functions: HastContractFunctionSummary[];
}

export interface HelixArtifactPairPaths {
	cPath: string;
	hastPath: string;
	pairingPath: string;
}

export interface HelixArtifactPairInput {
	paths: HelixArtifactPairPaths;
	cSource: string;
	hastBuffer: Buffer;
	hastContract: HastContractSummary;
	runtimeIdentity: HelixRuntimeIdentity;
	input: { path?: string; sha256: string; mediaType: string };
	architecture: string;
	helixInvocation: unknown;
	nativeFunction: { name: string; address: string; instructionCount: number };
	qualityIssues: readonly HelixStructuredQualityIssue[];
	cfgBuffer: Buffer | null;
}

export interface HelixSideArtifact {
	role: 'hast' | 'pairing';
	path: string;
	sha256: string;
	bytes: number;
	mediaType: string;
	pairingId: string;
}

interface CFunctionSurface {
	name: string;
	returnType: string;
	params: Array<{ name: string; type: string }>;
	isVariadic: boolean;
}

export interface HelixArtifactPairEnvelope {
	schemaVersion: 1;
	kind: 'hexcore-helix-c-hast-pair';
	pairingId: string;
	request: { sha256: string; descriptor: Record<string, unknown> };
	runtimeIdentity: HelixRuntimeIdentity;
	artifacts: {
		c: { path: string; sha256: string; bytes: number; mediaType: 'text/x-c'; surfaceSha256: string };
		hast: { path: string; sha256: string; bytes: number; mediaType: 'application/vnd.hexcore.hast+flatbuffers'; contractSha256: string };
		cfg: { status: 'not-emitted' | 'available-not-persisted'; bytes: number; sha256?: string; reason: string };
	};
	hast: {
		schemaMajor: number;
		schemaMinor: number;
		capabilities: string[];
		producer?: string;
		producerVersion?: string;
		architecture?: string;
		pointerBits?: number;
		semanticEligible: boolean;
		functionCount: number;
		functions: Array<{
			name: string;
			address: string;
			returnType: string;
			params: Array<{ name: string; type: string; parameterIndex?: number }>;
			localCount: number;
			callingConvention: string;
			isVariadic: boolean;
			nativeQuality: HastContractFunctionSummary['nativeQuality'];
		}>;
	};
	equivalence: {
		status: 'verified';
		checks: Array<{ name: string; status: 'pass'; detail: string }>;
	};
}

function canonicalize(value: unknown): unknown {
	if (Array.isArray(value)) return value.map(canonicalize);
	if (!value || typeof value !== 'object') return value;
	return Object.fromEntries(Object.keys(value as Record<string, unknown>)
		.sort().map(key => [key, canonicalize((value as Record<string, unknown>)[key])]));
}

function canonicalBytes(value: unknown): Buffer {
	return Buffer.from(JSON.stringify(canonicalize(value)), 'utf8');
}

function sha256(data: Buffer | string): string {
	return crypto.createHash('sha256').update(data).digest('hex');
}

function normalizeType(value: string): string {
	return value.trim().replace(/\s+/g, ' ').replace(/\s*\*\s*/g, '*');
}

function splitParameters(raw: string): string[] {
	const result: string[] = [];
	let depth = 0;
	let start = 0;
	for (let index = 0; index < raw.length; index++) {
		const char = raw[index];
		if (char === '(' || char === '[') depth++;
		else if (char === ')' || char === ']') depth--;
		else if (char === ',' && depth === 0) {
			result.push(raw.slice(start, index).trim());
			start = index + 1;
		}
	}
	const tail = raw.slice(start).trim();
	if (tail) result.push(tail);
	return result;
}

export function extractCFunctionSurfaces(source: string): CFunctionSurface[] {
	const functions: CFunctionSurface[] = [];
	const signature = /^([A-Za-z_][\w\s]*?(?:\s*\*+)?)\s+([A-Za-z_]\w*)\(([^;\n]*)\)\s*\r?\n\{/gm;
	for (const match of source.matchAll(signature)) {
		const params: Array<{ name: string; type: string }> = [];
		let isVariadic = false;
		const rawParams = match[3].trim();
		if (rawParams && rawParams !== 'void') {
			for (const rawParam of splitParameters(rawParams)) {
				if (rawParam === '...') { isVariadic = true; continue; }
				const parameter = /^(.*\S)\s+([A-Za-z_]\w*)$/.exec(rawParam);
				if (!parameter) throw new Error(`Unable to parse C parameter declaration: ${rawParam}`);
				params.push({ name: parameter[2], type: normalizeType(parameter[1]) });
			}
		}
		functions.push({
			name: match[2],
			returnType: normalizeType(match[1]),
			params,
			isVariadic,
		});
	}
	return functions;
}

function compactHast(contract: HastContractSummary): HelixArtifactPairEnvelope['hast'] {
	return {
		schemaMajor: contract.schemaMajor,
		schemaMinor: contract.schemaMinor,
		capabilities: [...contract.capabilities],
		...(contract.producer ? { producer: contract.producer } : {}),
		...(contract.producerVersion ? { producerVersion: contract.producerVersion } : {}),
		...(contract.architecture ? { architecture: contract.architecture } : {}),
		...(contract.pointerBits !== undefined ? { pointerBits: contract.pointerBits } : {}),
		semanticEligible: contract.semanticEligible,
		functionCount: contract.functionCount,
		functions: contract.functions.map(item => ({
			name: item.name,
			address: item.address.toLowerCase(),
			returnType: normalizeType(item.returnType),
			params: item.params.map(param => ({
				name: param.name,
				type: normalizeType(param.type),
				...(param.parameterIndex !== undefined ? { parameterIndex: param.parameterIndex } : {}),
			})),
			localCount: item.locals.length,
			callingConvention: item.callingConvention,
			isVariadic: item.isVariadic,
			nativeQuality: { status: item.nativeQuality.status, issues: [...item.nativeQuality.issues] },
		})),
	};
}

function relativeArtifactPath(pairingPath: string, artifactPath: string): string {
	const base = path.dirname(path.resolve(pairingPath));
	const relative = path.relative(base, path.resolve(artifactPath));
	if (!relative || path.isAbsolute(relative) || relative === '..' || relative.startsWith(`..${path.sep}`)) {
		throw new Error(`Paired artifact must be inside the pairing envelope directory: ${artifactPath}`);
	}
	return relative.replace(/\\/g, '/');
}

function qualityChecks(
	hast: HelixArtifactPairEnvelope['hast'],
	qualityIssues: readonly HelixStructuredQualityIssue[],
): { ok: boolean; detail: string } {
	const cKinds = new Set(qualityIssues.map(issue => issue.kind));
	const mapping: Record<string, HelixStructuredQualityIssue['kind']> = {
		'suspicious-self-reference': 'self-reference',
		'synthesized-variable': 'placeholder-variable',
		'damning-defect': 'damning-defect',
	};
	const missing: string[] = [];
	for (const fn of hast.functions) {
		for (const issue of fn.nativeQuality.issues) {
			const mapped = mapping[issue];
			if (mapped && !cKinds.has(mapped)) missing.push(`${fn.name}:${issue}`);
			else if (!mapped && !cKinds.has('damning-defect')) missing.push(`${fn.name}:${issue}`);
		}
	}
	return {
		ok: missing.length === 0,
		detail: missing.length ? `missing C barriers: ${missing.join(', ')}` : 'native quality barriers retained',
	};
}

export function createHelixArtifactPairEnvelope(input: HelixArtifactPairInput): HelixArtifactPairEnvelope {
	if (!input.hastBuffer.length) throw new Error('Helix returned an empty HAST buffer');
	if (input.hastContract.fileIdentifier !== 'HAST') throw new Error('Invalid HAST contract identifier');
	const resolved = Object.values(input.paths).map(value => path.resolve(value));
	if (new Set(resolved.map(value => process.platform === 'win32' ? value.toLowerCase() : value)).size !== resolved.length) {
		throw new Error('C, HAST and pairing outputs must use distinct paths');
	}

	const cBytes = Buffer.from(input.cSource, 'utf8');
	const cSha256 = sha256(cBytes);
	const hastSha256 = sha256(input.hastBuffer);
	const cSurfaces = extractCFunctionSurfaces(input.cSource);
	const hast = compactHast(input.hastContract);
	const errors: string[] = [];
	if (cSurfaces.length !== hast.functionCount) {
		errors.push(`function count C=${cSurfaces.length} HAST=${hast.functionCount}`);
	}
	for (let index = 0; index < Math.min(cSurfaces.length, hast.functions.length); index++) {
		const c = cSurfaces[index];
		const fn = hast.functions[index];
		if (c.name !== fn.name) errors.push(`function[${index}] name C=${c.name} HAST=${fn.name}`);
		if (c.returnType !== fn.returnType) errors.push(`function[${index}] return C=${c.returnType} HAST=${fn.returnType}`);
		if (c.isVariadic !== fn.isVariadic) errors.push(`function[${index}] variadic mismatch`);
		if (c.params.length !== fn.params.length) {
			errors.push(`function[${index}] params C=${c.params.length} HAST=${fn.params.length}`);
		}
		for (let paramIndex = 0; paramIndex < Math.min(c.params.length, fn.params.length); paramIndex++) {
			const cParam = c.params[paramIndex];
			const hParam = fn.params[paramIndex];
			if (cParam.name !== hParam.name || cParam.type !== hParam.type) {
				errors.push(`function[${index}] param[${paramIndex}] C=${cParam.type} ${cParam.name} HAST=${hParam.type} ${hParam.name}`);
			}
		}
	}
	const nativeAddress = input.nativeFunction.address.toLowerCase();
	if (hast.functions[0]?.address !== nativeAddress) {
		errors.push(`entry address native=${nativeAddress} HAST=${hast.functions[0]?.address ?? '<none>'}`);
	}
	if (hast.functions[0]?.name !== input.nativeFunction.name) {
		errors.push(`entry name native=${input.nativeFunction.name} HAST=${hast.functions[0]?.name ?? '<none>'}`);
	}
	const barriers = qualityChecks(hast, input.qualityIssues);
	if (!barriers.ok) errors.push(barriers.detail);
	if (errors.length) throw new Error(`C/HAST pairing mismatch: ${errors.join('; ')}`);

	const requestDescriptor: Record<string, unknown> = {
		command: 'hexcore.helix.decompileIR',
		input: { sha256: input.input.sha256, mediaType: input.input.mediaType },
		architecture: input.architecture,
		helixInvocation: input.helixInvocation,
		runtime: {
			wrapperVersion: input.runtimeIdentity.wrapperVersion,
			nativeVersion: input.runtimeIdentity.nativeVersion,
			binarySha256: input.runtimeIdentity.binarySha256,
		},
	};
	const requestSha256 = sha256(canonicalBytes(requestDescriptor));
	const contractSha256 = sha256(canonicalBytes(hast));
	const surfaceSha256 = sha256(canonicalBytes(cSurfaces));
	const pairingId = `sha256:${sha256(canonicalBytes({ requestSha256, cSha256, hastSha256, contractSha256 }))}`;
	return {
		schemaVersion: 1,
		kind: 'hexcore-helix-c-hast-pair',
		pairingId,
		request: { sha256: requestSha256, descriptor: requestDescriptor },
		runtimeIdentity: { ...input.runtimeIdentity },
		artifacts: {
			c: {
				path: relativeArtifactPath(input.paths.pairingPath, input.paths.cPath),
				sha256: cSha256,
				bytes: cBytes.length,
				mediaType: 'text/x-c',
				surfaceSha256,
			},
			hast: {
				path: relativeArtifactPath(input.paths.pairingPath, input.paths.hastPath),
				sha256: hastSha256,
				bytes: input.hastBuffer.length,
				mediaType: 'application/vnd.hexcore.hast+flatbuffers',
				contractSha256,
			},
			cfg: input.cfgBuffer ? {
				status: 'available-not-persisted',
				bytes: input.cfgBuffer.length,
				sha256: sha256(input.cfgBuffer),
				reason: 'CFG buffer was returned but is outside the bounded A2 C/HAST contract',
			} : {
				status: 'not-emitted',
				bytes: 0,
				reason: 'decompileIR emitted no binary CFG buffer; A2 does not synthesize one',
			},
		},
		hast,
		equivalence: {
			status: 'verified',
			checks: [
				{ name: 'function-count', status: 'pass', detail: `${hast.functionCount} function(s)` },
				{ name: 'function-identity', status: 'pass', detail: `${input.nativeFunction.name}@${nativeAddress}` },
				{ name: 'declaration-surface', status: 'pass', detail: 'return and parameter declarations match' },
				{ name: 'native-quality', status: 'pass', detail: barriers.detail },
			],
		},
	};
}

export function persistHelixArtifactPair(input: HelixArtifactPairInput): {
	envelope: HelixArtifactPairEnvelope;
	sideArtifacts: HelixSideArtifact[];
} {
	const envelope = createHelixArtifactPairEnvelope(input);
	for (const outputPath of Object.values(input.paths)) fs.mkdirSync(path.dirname(outputPath), { recursive: true });
	fs.writeFileSync(input.paths.cPath, input.cSource, 'utf8');
	fs.writeFileSync(input.paths.hastPath, input.hastBuffer);
	const envelopeBytes = Buffer.from(`${JSON.stringify(envelope, null, 2)}\n`, 'utf8');
	fs.writeFileSync(input.paths.pairingPath, envelopeBytes);
	return {
		envelope,
		sideArtifacts: [
			{
				role: 'hast', path: path.resolve(input.paths.hastPath),
				sha256: envelope.artifacts.hast.sha256, bytes: envelope.artifacts.hast.bytes,
				mediaType: envelope.artifacts.hast.mediaType, pairingId: envelope.pairingId,
			},
			{
				role: 'pairing', path: path.resolve(input.paths.pairingPath),
				sha256: sha256(envelopeBytes), bytes: envelopeBytes.length,
				mediaType: 'application/vnd.hexcore.helix-pair+json', pairingId: envelope.pairingId,
			},
		],
	};
}

export function verifyHelixArtifactPair(
	pairingPath: string,
	inspectHast: (buffer: Uint8Array) => HastContractSummary,
): HelixArtifactPairEnvelope {
	const envelope = JSON.parse(fs.readFileSync(pairingPath, 'utf8')) as HelixArtifactPairEnvelope;
	if (envelope.schemaVersion !== 1 || envelope.kind !== 'hexcore-helix-c-hast-pair') {
		throw new Error('Unsupported Helix pairing envelope');
	}
	const base = path.dirname(path.resolve(pairingPath));
	const resolveArtifact = (relative: string): string => {
		const resolved = path.resolve(base, relative);
		if (resolved === base || !resolved.startsWith(`${base}${path.sep}`)) {
			throw new Error(`Pairing artifact escapes its envelope directory: ${relative}`);
		}
		return resolved;
	};
	const cBytes = fs.readFileSync(resolveArtifact(envelope.artifacts.c.path));
	const hastBytes = fs.readFileSync(resolveArtifact(envelope.artifacts.hast.path));
	if (sha256(cBytes) !== envelope.artifacts.c.sha256 || cBytes.length !== envelope.artifacts.c.bytes) {
		throw new Error('Paired C artifact identity mismatch');
	}
	if (sha256(hastBytes) !== envelope.artifacts.hast.sha256 || hastBytes.length !== envelope.artifacts.hast.bytes) {
		throw new Error('Paired HAST artifact identity mismatch');
	}
	const cSurfaceSha256 = sha256(canonicalBytes(extractCFunctionSurfaces(cBytes.toString('utf8'))));
	if (cSurfaceSha256 !== envelope.artifacts.c.surfaceSha256) {
		throw new Error('Paired C declaration surface mismatch');
	}
	const inspected = compactHast(inspectHast(hastBytes));
	if (sha256(canonicalBytes(inspected)) !== envelope.artifacts.hast.contractSha256) {
		throw new Error('Paired HAST contract mismatch');
	}
	if (sha256(canonicalBytes(envelope.request.descriptor)) !== envelope.request.sha256) {
		throw new Error('Helix pairing request identity mismatch');
	}
	const pairingId = `sha256:${sha256(canonicalBytes({
		requestSha256: envelope.request.sha256,
		cSha256: envelope.artifacts.c.sha256,
		hastSha256: envelope.artifacts.hast.sha256,
		contractSha256: envelope.artifacts.hast.contractSha256,
	}))}`;
	if (pairingId !== envelope.pairingId) throw new Error('Helix pairing ID mismatch');
	return envelope;
}
