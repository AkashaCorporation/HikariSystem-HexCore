/*---------------------------------------------------------------------------------------------
 * Evidence-gated Windows filesystem boundary audit. It assembles pivots; it never assigns severity.
 *--------------------------------------------------------------------------------------------*/

import type { Function as DisassembledFunction, ImportLibrary, Instruction, StringReference } from './disassemblerEngine';
import { analyzeWindowsValueDataflow, type DeepWindowsValueDataflow } from './windowsValueDataflow';

export type FilesystemEvidenceStatus = 'confirmed' | 'signal' | 'missing' | 'blocked' | 'not-assessed';
export type FilesystemRole =
	| 'path-producer'
	| 'filesystem-lifecycle'
	| 'filesystem-sink'
	| 'security-descriptor'
	| 'principal-token'
	| 'path-validation'
	| 'archive-parser';

export interface ManifestPrincipal {
	status?: string;
	requestedExecutionLevel?: string | null;
	uiAccess?: boolean | null;
	source?: { section?: string; fileOffset?: number; encoding?: string };
}

export interface FilesystemOwnerEvidence {
	functionAddress: string;
	functionName: string;
	callSites: string[];
	callers: string[];
	callees: string[];
}

export interface FilesystemCapabilityEvidence {
	dll: string;
	api: string;
	iatAddress: string;
	roles: FilesystemRole[];
	status: 'owned-callsite' | 'import-signal';
	owners: FilesystemOwnerEvidence[];
}

export interface FilesystemStringPivot {
	value: string;
	address: string;
	kind: 'path' | 'archive' | 'security';
	attribution: 'product' | 'third-party' | 'unknown';
	evidenceClass: 'semantic-candidate' | 'message-table';
	references: string[];
	owners: Array<{ functionAddress: string; functionName: string }>;
}

export interface FilesystemChainEdge {
	kind: 'principal' | 'state-location' | 'writer' | 'lifecycle' | 'parser' | 'path-property' | 'reparse-safety' | 'sink';
	status: FilesystemEvidenceStatus;
	summary: string;
	evidence: string[];
	blockers: string[];
}

export interface FilesystemCandidateFunction {
	address: string;
	name: string;
	roles: FilesystemRole[];
	apiEvidence: string[];
	stringEvidence: string[];
	callers: string[];
	callees: string[];
	evidenceCount: number;
	roleDiversity: number;
	graphDegree: number;
	dataflowPathCount: number;
	productEvidenceCount: number;
	thirdPartyEvidenceCount: number;
	criticalApiWeight: number;
	productGraphLinks: number;
	rankScore: number;
	rankReasons: string[];
}

export interface FilesystemCandidateEdge {
	from: string;
	to: string;
	type: 'call';
	status: 'graph-signal';
}

export interface FilesystemCandidateChain {
	kind: FilesystemTypedPath['kind'] | 'product-helper-route' | 'product-candidate-route';
	status: FilesystemTypedPath['status'];
	functions: Array<{ address: string; name: string; primaryCandidate: boolean }>;
	score: number;
	blockers: string[];
}

export interface FilesystemCriticalHelper {
	address: string;
	name: string;
	depth: 1 | 2;
	sourceCandidates: string[];
	via?: string;
	score: number;
	reasons: string[];
	callers: string[];
	callees: string[];
}

export interface FilesystemRelatedFunction {
	address: string;
	name: string;
	relation: 'caller' | 'callee' | 'caller-and-callee';
	sourceCandidates: string[];
	callers: string[];
	callees: string[];
}

export type FilesystemDataflowFactKind =
	| 'sid-producer'
	| 'acl-builder'
	| 'acl-apply'
	| 'path-producer'
	| 'path-validator'
	| 'handle-open'
	| 'handle-close'
	| 'filesystem-mutation'
	| 'write-sink'
	| 'archive-parser';

export interface FilesystemDataflowFact {
	kind: FilesystemDataflowFactKind;
	functionAddress: string;
	functionName: string;
	api: string;
	callSite?: string;
	context: string[];
	immediateCandidates: Array<{ value: string; labels: string[] }>;
	status: 'callsite-fact' | 'owner-summary';
}

export interface FilesystemTypedPath {
	kind: 'sid-to-acl' | 'acl-to-apply' | 'path-to-open' | 'open-to-write' | 'open-to-close' | 'parser-to-path' | 'path-to-sink';
	status: 'proven-value-flow' | 'co-located-signal' | 'call-neighborhood-signal' | 'blocked';
	functions: string[];
	evidence: string[];
	blockers: string[];
	sameValueProven: boolean;
}

export interface FilesystemHandleLifecycle {
	functionAddress: string;
	functionName: string;
	orderedFacts: Array<{ kind: FilesystemDataflowFactKind; api: string; callSite?: string }>;
	sameHandleProven: boolean;
	status: 'proven-value-flow' | 'co-located-signal';
}

export interface WindowsFilesystemDataflow {
	facts: FilesystemDataflowFact[];
	typedPaths: FilesystemTypedPath[];
	handleLifecycles: FilesystemHandleLifecycle[];
	deepValueFlow: DeepWindowsValueDataflow;
	limitations: string[];
}

export interface WindowsFilesystemAuditResult {
	status: 'ok' | 'partial';
	securityEvidenceUsable: false;
	verdict: 'incomplete' | 'candidate-chain';
	principal: ManifestPrincipal;
	coverage: {
		totalFunctions: number;
		materializedFunctions: number;
		lazyFunctions: number;
		materializedFunctionRatio: number;
	};
	capabilities: FilesystemCapabilityEvidence[];
	stringPivots: FilesystemStringPivot[];
	candidateFunctions: FilesystemCandidateFunction[];
	candidateEdges: FilesystemCandidateEdge[];
	topCandidateChains: FilesystemCandidateChain[];
	criticalHelpers: FilesystemCriticalHelper[];
	relatedFunctions: FilesystemRelatedFunction[];
	dataflow: WindowsFilesystemDataflow;
	chain: FilesystemChainEdge[];
	limitations: string[];
	generatedAt: string;
}

const API_ROLES: ReadonlyArray<{ pattern: RegExp; roles: FilesystemRole[] }> = [
	{ pattern: /^(GetTempPath|GetTempFileName|GetFullPathName|GetEnvironmentVariable|SHGetFolderPath)/i, roles: ['path-producer'] },
	{ pattern: /^(PathCanonicalize|PathCchCanonicalize|PathCombine|PathCchCombine|GetFinalPathNameByHandle)/i, roles: ['path-validation'] },
	{ pattern: /^(CreateFile(?:A|W)?|NtCreateFile|DeleteFile(?:A|W)?|MoveFile(?:Ex)?(?:A|W)?|ReplaceFile(?:A|W)?|CopyFile(?:Ex)?(?:A|W)?|CreateDirectory(?:A|W)?|RemoveDirectory(?:A|W)?|SetFileInformationByHandle|CloseHandle)$/i, roles: ['filesystem-lifecycle'] },
	{ pattern: /^(WriteFile(?:Ex)?|fopen|_wfopen|fwrite|_write|NtWriteFile)$/i, roles: ['filesystem-sink'] },
	{ pattern: /^(InitializeAcl|AddAccessAllowedAce|AddAccessDeniedAce|SetNamedSecurityInfo|SetSecurityInfo|SetFileSecurity|GetNamedSecurityInfo|GetSecurityInfo)/i, roles: ['security-descriptor'] },
	{ pattern: /^(OpenProcessToken|GetTokenInformation|CheckTokenMembership|CreateWellKnownSid|AllocateAndInitializeSid|LookupAccountName|EqualSid)/i, roles: ['principal-token'] },
	{ pattern: /^(zip_|unz|archive_|CreateDecompressor|Decompress)/i, roles: ['archive-parser'] },
];

function toHex(address: number): string {
	return `0x${Math.max(0, address).toString(16).toUpperCase()}`;
}

function rolesForApi(name: string): FilesystemRole[] {
	return [...new Set(API_ROLES.filter(entry => entry.pattern.test(name)).flatMap(entry => entry.roles))];
}

function instructionIatCandidates(instruction: Instruction): number[] {
	const candidates = new Set<number>();
	if (instruction.targetAddress !== undefined) { candidates.add(Number(instruction.targetAddress)); }
	const operand = instruction.opStr ?? '';
	const absolute = /\[\s*(0x[0-9a-f]+)\s*\]/i.exec(operand);
	if (absolute) { candidates.add(parseInt(absolute[1], 16)); }
	const rip = /\[\s*rip\s*([+-])\s*(0x[0-9a-f]+|\d+)\s*\]/i.exec(operand);
	if (rip) {
		const displacement = rip[2].toLowerCase().startsWith('0x') ? parseInt(rip[2], 16) : parseInt(rip[2], 10);
		const signed = rip[1] === '-' ? -displacement : displacement;
		candidates.add(instruction.address + instruction.size + signed);
	}
	return [...candidates];
}

function ownerForAddress(functions: readonly DisassembledFunction[], address: number): DisassembledFunction | undefined {
	return functions.find(fn => address >= fn.address && address < fn.endAddress);
}

function classifyStringAttribution(value: string): FilesystemStringPivot['attribution'] {
	if (/third[_ -]?party|external[\\/]|libcurl|\bcurl\b|openssl|sqlite|boost|microsoft visual c\+\+|mfc/i.test(value)) { return 'third-party'; }
	if (/backblaze|bzrestore|restapipp|bzrestorelib|restore_processor|ZipUtils\.cpp/i.test(value)) { return 'product'; }
	if (/bzmono/i.test(value) && !/vendor|third[_ -]?party|external/i.test(value)) { return 'product'; }
	return 'unknown';
}

function isMessageTableOwner(fn: DisassembledFunction): boolean {
	let entries = 0;
	const enumValues = new Set<number>();
	for (let index = 0; index + 2 < fn.instructions.length; index++) {
		const load = fn.instructions[index];
		const storePointer = fn.instructions[index + 1];
		const storeEnum = fn.instructions[index + 2];
		const loadOperands = /^\s*([a-z][a-z0-9]*)\s*,\s*\[rip\s*[+-]/i.exec(load.opStr);
		if (load.mnemonic.toLowerCase() !== 'lea' || !loadOperands) { continue; }
		const pointerOperands = splitAuditOperands(storePointer.opStr);
		const enumOperands = splitAuditOperands(storeEnum.opStr);
		if (storePointer.mnemonic.toLowerCase() !== 'mov' || !pointerOperands ||
			!pointerOperands[0].includes('[') || pointerOperands[1].trim().toLowerCase() !== loadOperands[1].toLowerCase()) {
			continue;
		}
		if (storeEnum.mnemonic.toLowerCase() !== 'mov' || !enumOperands ||
			!enumOperands[0].includes('[') || !/^(?:0x[0-9a-f]+|\d+)$/i.test(enumOperands[1].trim())) {
			continue;
		}
		const value = enumOperands[1].trim().toLowerCase().startsWith('0x')
			? parseInt(enumOperands[1].trim(), 16)
			: parseInt(enumOperands[1].trim(), 10);
		enumValues.add(value);
		entries++;
	}
	return entries >= 6 && enumValues.size >= 6;
}

function splitAuditOperands(opStr: string): [string, string] | undefined {
	let bracketDepth = 0;
	for (let index = 0; index < opStr.length; index++) {
		if (opStr[index] === '[') { bracketDepth++; }
		if (opStr[index] === ']') { bracketDepth--; }
		if (opStr[index] === ',' && bracketDepth === 0) {
			return [opStr.slice(0, index).trim(), opStr.slice(index + 1).trim()];
		}
	}
	return undefined;
}

function collectCapabilityEvidence(
	imports: readonly ImportLibrary[],
	functions: readonly DisassembledFunction[],
): FilesystemCapabilityEvidence[] {
	const imported = imports.flatMap(library => library.functions.map(fn => ({
		dll: library.name,
		api: fn.name,
		iatAddress: fn.address,
		roles: rolesForApi(fn.name),
	}))).filter(candidate => candidate.roles.length > 0);
	const importByAddress = new Map(imported.map(candidate => [candidate.iatAddress, candidate]));
	const ownerMap = new Map<number, Map<number, number[]>>();

	for (const fn of functions) {
		for (const callee of fn.callees) {
			if (!importByAddress.has(callee)) { continue; }
			const byFunction = ownerMap.get(callee) ?? new Map<number, number[]>();
			byFunction.set(fn.address, byFunction.get(fn.address) ?? []);
			ownerMap.set(callee, byFunction);
		}
		for (const instruction of fn.instructions) {
			if (!instruction.isCall) { continue; }
			for (const candidate of instructionIatCandidates(instruction)) {
				if (!importByAddress.has(candidate)) { continue; }
				const byFunction = ownerMap.get(candidate) ?? new Map<number, number[]>();
				const sites = byFunction.get(fn.address) ?? [];
				if (!sites.includes(instruction.address)) { sites.push(instruction.address); }
				byFunction.set(fn.address, sites);
				ownerMap.set(candidate, byFunction);
			}
		}
	}

	const byFunctionAddress = new Map(functions.map(fn => [fn.address, fn]));
	return imported.map(candidate => {
		const owners = [...(ownerMap.get(candidate.iatAddress)?.entries() ?? [])].map(([address, sites]) => {
			const fn = byFunctionAddress.get(address)!;
			return {
				functionAddress: toHex(fn.address),
				functionName: fn.name,
				callSites: sites.map(toHex).sort(),
				callers: fn.callers.map(toHex).sort(),
				callees: fn.callees.map(toHex).sort(),
			};
		});
		return {
			dll: candidate.dll,
			api: candidate.api,
			iatAddress: toHex(candidate.iatAddress),
			roles: candidate.roles,
			status: owners.length > 0 ? 'owned-callsite' as const : 'import-signal' as const,
			owners,
		};
	}).sort((left, right) =>
		left.roles[0].localeCompare(right.roles[0]) || left.api.localeCompare(right.api));
}

function collectStringPivots(
	strings: readonly StringReference[],
	functions: readonly DisassembledFunction[],
	maxSignals: number,
): FilesystemStringPivot[] {
	const patterns: Array<{ kind: FilesystemStringPivot['kind']; pattern: RegExp }> = [
		{ kind: 'security', pattern: /\b(dacl|acl|sid|authenticated users|everyone|file_delete_child)\b/i },
		{ kind: 'archive', pattern: /\b(zip|unzip|archive|extract|compressed)\b/i },
		{ kind: 'path', pattern: /\b(path|directory|folder|temp|restore|hunk)\b|[a-z]:\\|\\\\/i },
	];
	const result: FilesystemStringPivot[] = [];
	const messageTableOwners = new Set(functions.filter(isMessageTableOwner).map(fn => fn.address));
	for (const entry of strings) {
		const matched = patterns.find(candidate => candidate.pattern.test(entry.string));
		if (!matched || entry.references.length === 0) { continue; }
		const owners = [...new Map(entry.references
			.map(reference => ownerForAddress(functions, reference))
			.filter((owner): owner is DisassembledFunction => owner !== undefined)
			.map(owner => [owner.address, {
				functionAddress: toHex(owner.address),
				functionName: owner.name,
			}])).values()];
		result.push({
			value: entry.string,
			address: toHex(entry.address),
			kind: matched.kind,
			attribution: classifyStringAttribution(entry.string),
			evidenceClass: owners.length > 0 && owners.every(owner => messageTableOwners.has(parseInt(owner.functionAddress.slice(2), 16)))
				? 'message-table'
				: 'semantic-candidate',
			references: entry.references.map(toHex).sort(),
			owners,
		});
		if (result.length >= maxSignals) { break; }
	}
	return result;
}

function evidenceForRole(capabilities: readonly FilesystemCapabilityEvidence[], role: FilesystemRole): string[] {
	return capabilities.filter(capability => capability.roles.includes(role)).map(capability =>
		`${capability.dll}!${capability.api}@${capability.iatAddress}:${capability.status}`);
}

function buildCandidateIndex(
	capabilities: readonly FilesystemCapabilityEvidence[],
	strings: readonly FilesystemStringPivot[],
	functions: readonly DisassembledFunction[],
): {
	candidateFunctions: FilesystemCandidateFunction[];
	candidateEdges: FilesystemCandidateEdge[];
	relatedFunctions: FilesystemRelatedFunction[];
} {
	const candidates = new Map<number, {
		fn: DisassembledFunction;
		roles: Set<FilesystemRole>;
		apis: Set<string>;
		strings: Set<string>;
	}>();
	const byAddress = new Map(functions.map(fn => [toHex(fn.address).toLowerCase(), fn]));
	const ensure = (address: string) => {
		const fn = byAddress.get(address.toLowerCase());
		if (!fn) { return undefined; }
		let candidate = candidates.get(fn.address);
		if (!candidate) {
			candidate = { fn, roles: new Set(), apis: new Set(), strings: new Set() };
			candidates.set(fn.address, candidate);
		}
		return candidate;
	};

	for (const capability of capabilities) {
		for (const owner of capability.owners) {
			const candidate = ensure(owner.functionAddress);
			if (!candidate) { continue; }
			capability.roles.forEach(role => candidate.roles.add(role));
			candidate.apis.add(
				`${capability.dll}!${capability.api}@${owner.callSites.join(',') || capability.iatAddress}`,
			);
		}
	}
	for (const pivot of strings) {
		if (pivot.evidenceClass === 'message-table') { continue; }
		for (const owner of pivot.owners) {
			const candidate = ensure(owner.functionAddress);
			if (!candidate) { continue; }
			if (pivot.kind === 'archive') { candidate.roles.add('archive-parser'); }
			if (pivot.kind === 'path') { candidate.roles.add('path-producer'); }
			candidate.strings.add(`${pivot.attribution}:${pivot.kind}:${pivot.value}@${pivot.address}`);
		}
	}

	const candidateFunctions = [...candidates.values()].map(candidate => ({
		address: toHex(candidate.fn.address),
		name: candidate.fn.name,
		roles: [...candidate.roles].sort(),
		apiEvidence: [...candidate.apis].sort(),
		stringEvidence: [...candidate.strings].sort(),
		callers: candidate.fn.callers.map(toHex).sort(),
		callees: candidate.fn.callees.map(toHex).sort(),
		evidenceCount: candidate.apis.size + candidate.strings.size,
		roleDiversity: candidate.roles.size,
		graphDegree: 0,
		dataflowPathCount: 0,
		productEvidenceCount: [...candidate.strings].filter(value => value.startsWith('product:')).length,
		thirdPartyEvidenceCount: [...candidate.strings].filter(value => value.startsWith('third-party:')).length,
		criticalApiWeight: 0,
		productGraphLinks: 0,
		rankScore: 0,
		rankReasons: [],
	})).sort((left, right) =>
		right.evidenceCount - left.evidenceCount || left.address.localeCompare(right.address));
	const candidateAddresses = new Set(candidateFunctions.map(candidate => candidate.address.toLowerCase()));
	const candidateEdges: FilesystemCandidateEdge[] = [];
	const related = new Map<number, { fn: DisassembledFunction; callers: Set<string>; callees: Set<string> }>();
	const functionByAddress = new Map(functions.map(fn => [fn.address, fn]));
	for (const candidate of candidateFunctions) {
		const source = functionByAddress.get(parseInt(candidate.address.slice(2), 16));
		if (!source) { continue; }
		for (const address of source.callers) {
			const fn = functionByAddress.get(address);
			if (!fn || candidateAddresses.has(toHex(address).toLowerCase())) { continue; }
			const entry = related.get(address) ?? { fn, callers: new Set(), callees: new Set() };
			entry.callers.add(candidate.address);
			related.set(address, entry);
		}
		for (const callee of candidate.callees) {
			if (candidateAddresses.has(callee.toLowerCase())) {
				candidateEdges.push({ from: candidate.address, to: callee, type: 'call', status: 'graph-signal' });
				continue;
			}
			const address = parseInt(callee.slice(2), 16);
			const fn = functionByAddress.get(address);
			if (!fn) { continue; }
			const entry = related.get(address) ?? { fn, callers: new Set(), callees: new Set() };
			entry.callees.add(candidate.address);
			related.set(address, entry);
		}
	}
	const relatedFunctions = [...related.values()].map(entry => ({
		address: toHex(entry.fn.address),
		name: entry.fn.name,
		relation: entry.callers.size > 0 && entry.callees.size > 0
			? 'caller-and-callee' as const
			: entry.callers.size > 0 ? 'caller' as const : 'callee' as const,
		sourceCandidates: [...new Set([...entry.callers, ...entry.callees])].sort(),
		callers: entry.fn.callers.map(toHex).sort(),
		callees: entry.fn.callees.map(toHex).sort(),
	})).sort((left, right) => left.address.localeCompare(right.address)).slice(0, 2000);
	return { candidateFunctions, candidateEdges, relatedFunctions };
}

function dataflowKindForApi(api: string): FilesystemDataflowFactKind | undefined {
	if (/^(AllocateAndInitializeSid|CreateWellKnownSid|LookupAccountName)/i.test(api)) { return 'sid-producer'; }
	if (/^(InitializeAcl|AddAccessAllowedAce|AddAccessDeniedAce)/i.test(api)) { return 'acl-builder'; }
	if (/^(SetFileSecurity|SetNamedSecurityInfo|SetSecurityInfo)/i.test(api)) { return 'acl-apply'; }
	if (/^(GetTempPath|GetTempFileName|GetFullPathName|GetEnvironmentVariable|SHGetFolderPath)/i.test(api)) { return 'path-producer'; }
	if (/^(PathCanonicalize|PathCchCanonicalize|PathCombine|PathCchCombine|GetFinalPathNameByHandle)/i.test(api)) { return 'path-validator'; }
	if (/^(CreateFile(?:A|W)?|NtCreateFile)$/i.test(api)) { return 'handle-open'; }
	if (/^CloseHandle$/i.test(api)) { return 'handle-close'; }
	if (/^(DeleteFile|MoveFile|MoveFileEx|ReplaceFile|CopyFile|CreateDirectory|RemoveDirectory|SetFileInformationByHandle)/i.test(api)) { return 'filesystem-mutation'; }
	if (/^(WriteFile(?:Ex)?|fopen|_wfopen|fwrite|_write|NtWriteFile)$/i.test(api)) { return 'write-sink'; }
	if (/^(zip_|unz|archive_|CreateDecompressor|Decompress)/i.test(api)) { return 'archive-parser'; }
	return undefined;
}

function labelsForImmediate(value: number, api: string): string[] {
	const labels: string[] = [];
	const accessBits: Array<[number, string]> = [
		[0x00000001, 'FILE_READ_DATA/LIST_DIRECTORY'],
		[0x00000002, 'FILE_WRITE_DATA/ADD_FILE'],
		[0x00000004, 'FILE_APPEND_DATA/ADD_SUBDIRECTORY'],
		[0x00000040, 'FILE_DELETE_CHILD'],
		[0x00010000, 'DELETE'],
		[0x00040000, 'WRITE_DAC'],
		[0x00080000, 'WRITE_OWNER'],
		[0x00100000, 'SYNCHRONIZE'],
		[0x10000000, 'GENERIC_ALL'],
		[0x40000000, 'GENERIC_WRITE'],
		[0x80000000, 'GENERIC_READ'],
	];
	if (/Access|Acl|Security|CreateFile|NtCreateFile/i.test(api)) {
		for (const [bit, name] of accessBits) {
			if ((value >>> 0) === (bit >>> 0) || (((value >>> 0) & (bit >>> 0)) !== 0 && value > 0xff)) {
				labels.push(name);
			}
		}
	}
	if (/Sid/i.test(api)) {
		if (value === 17) { labels.push('WinAuthenticatedUserSid'); }
		if (value === 27) { labels.push('WinBuiltinUsersSid'); }
		if (value === 1) { labels.push('SECURITY_WORLD_RID candidate'); }
	}
	return labels;
}

function callContext(
	fn: DisassembledFunction,
	callSite: number | undefined,
	api: string,
): { context: string[]; immediateCandidates: Array<{ value: string; labels: string[] }> } {
	if (callSite === undefined) { return { context: [], immediateCandidates: [] }; }
	const index = fn.instructions.findIndex(instruction => instruction.address === callSite);
	if (index < 0) { return { context: [], immediateCandidates: [] }; }
	const instructions = fn.instructions.slice(Math.max(0, index - 8), index + 1);
	const immediateValues = new Set<number>();
	// The call target itself is an address, not an argument immediate.
	for (const instruction of instructions.slice(0, -1)) {
		for (const match of instruction.opStr.matchAll(/\b0x([0-9a-f]+)\b|\b(\d+)\b/gi)) {
			const value = match[1] ? parseInt(match[1], 16) : parseInt(match[2], 10);
			if (Number.isSafeInteger(value) && value >= 0 && value <= 0xffffffff) { immediateValues.add(value); }
		}
	}
	return {
		context: instructions.map(instruction =>
			`${toHex(instruction.address)} ${instruction.mnemonic} ${instruction.opStr}`.trim()),
		immediateCandidates: [...immediateValues]
			.map(value => ({ value: toHex(value), labels: labelsForImmediate(value, api) }))
			.filter(candidate => candidate.labels.length > 0),
	};
}

function collectDataflowFacts(
	capabilities: readonly FilesystemCapabilityEvidence[],
	strings: readonly FilesystemStringPivot[],
	functions: readonly DisassembledFunction[],
): FilesystemDataflowFact[] {
	const byAddress = new Map(functions.map(fn => [toHex(fn.address).toLowerCase(), fn]));
	const facts: FilesystemDataflowFact[] = [];
	for (const capability of capabilities) {
		const kind = dataflowKindForApi(capability.api);
		if (!kind) { continue; }
		for (const owner of capability.owners) {
			const fn = byAddress.get(owner.functionAddress.toLowerCase());
			if (!fn) { continue; }
			const sites = owner.callSites.length > 0 ? owner.callSites : [undefined];
			for (const site of sites) {
				const siteAddress = site ? parseInt(site.slice(2), 16) : undefined;
				const context = callContext(fn, siteAddress, capability.api);
				facts.push({
					kind,
					functionAddress: owner.functionAddress,
					functionName: owner.functionName,
					api: `${capability.dll}!${capability.api}`,
					...(site ? { callSite: site } : {}),
					...context,
					status: site ? 'callsite-fact' : 'owner-summary',
				});
			}
		}
	}
	for (const pivot of strings) {
		const kind: FilesystemDataflowFactKind = pivot.kind === 'archive' ? 'archive-parser' : 'path-producer';
		if (pivot.kind === 'security') { continue; }
		for (const owner of pivot.owners) {
			facts.push({
				kind,
				functionAddress: owner.functionAddress,
				functionName: owner.functionName,
				api: `string:${pivot.value}`,
				context: [],
				immediateCandidates: [],
				status: 'owner-summary',
			});
		}
	}
	return facts.sort((left, right) =>
		left.functionAddress.localeCompare(right.functionAddress) || left.kind.localeCompare(right.kind) ||
		(left.callSite ?? '').localeCompare(right.callSite ?? ''));
}

function shortestNeighborhoodPath(
	functions: readonly DisassembledFunction[],
	starts: Set<number>,
	ends: Set<number>,
	maxDepth = 4,
): number[] | undefined {
	for (const address of starts) { if (ends.has(address)) { return [address]; } }
	const known = new Set(functions.map(fn => fn.address));
	const neighbors = new Map<number, Set<number>>();
	for (const fn of functions) {
		const set = neighbors.get(fn.address) ?? new Set<number>();
		for (const callee of fn.callees) {
			if (!known.has(callee)) { continue; }
			set.add(callee);
			const reverse = neighbors.get(callee) ?? new Set<number>();
			reverse.add(fn.address);
			neighbors.set(callee, reverse);
		}
		neighbors.set(fn.address, set);
	}
	const queue = [...starts].sort((a, b) => a - b).map(address => [address]);
	const visited = new Set(queue.map(pathValue => pathValue[0]));
	while (queue.length > 0) {
		const current = queue.shift()!;
		if (current.length - 1 >= maxDepth) { continue; }
		for (const next of [...(neighbors.get(current[current.length - 1]) ?? [])].sort((a, b) => a - b)) {
			if (visited.has(next)) { continue; }
			const candidate = [...current, next];
			if (ends.has(next)) { return candidate; }
			visited.add(next);
			queue.push(candidate);
		}
	}
	return undefined;
}

function buildTypedPath(
	kind: FilesystemTypedPath['kind'],
	startKinds: FilesystemDataflowFactKind[],
	endKinds: FilesystemDataflowFactKind[],
	facts: readonly FilesystemDataflowFact[],
	functions: readonly DisassembledFunction[],
	allowColocated = true,
): FilesystemTypedPath {
	const addresses = (kinds: FilesystemDataflowFactKind[]) => new Set(facts
		.filter(fact => kinds.includes(fact.kind))
		.map(fact => parseInt(fact.functionAddress.slice(2), 16)));
	const starts = addresses(startKinds);
	const ends = addresses(endKinds);
	if (!allowColocated) {
		for (const address of starts) { ends.delete(address); }
	}
	const pathValue = starts.size > 0 && ends.size > 0
		? shortestNeighborhoodPath(functions, starts, ends)
		: undefined;
	if (!pathValue) {
		return {
			kind, status: 'blocked', functions: [], evidence: [], sameValueProven: false,
			blockers: ['No bounded call-graph neighborhood connects the required typed facts.'],
		};
	}
	const functionSet = new Set(pathValue.map(toHex));
	return {
		kind,
		status: pathValue.length === 1 ? 'co-located-signal' : 'call-neighborhood-signal',
		functions: pathValue.map(toHex),
		evidence: facts.filter(fact => functionSet.has(fact.functionAddress))
			.map(fact => `${fact.kind}:${fact.api}@${fact.callSite ?? fact.functionAddress}`).slice(0, 32),
		blockers: [
			'Call-graph proximity does not prove that the same SID, ACL, path, or handle value crosses this route.',
		],
		sameValueProven: false,
	};
}

function buildWindowsDataflow(
	capabilities: readonly FilesystemCapabilityEvidence[],
	strings: readonly FilesystemStringPivot[],
	functions: readonly DisassembledFunction[],
	architecture = 'x64',
): WindowsFilesystemDataflow {
	const facts = collectDataflowFacts(capabilities, strings, functions);
	const deepValueFlow = analyzeWindowsValueDataflow(functions, facts, architecture);
	const proofForPath = (kind: FilesystemTypedPath['kind']) => {
		return deepValueFlow.proofs.find(proof => {
			if (kind === 'sid-to-acl') { return proof.kind === 'same-sid' && /AddAccess/i.test(proof.consumer.api); }
			if (kind === 'path-to-open') { return proof.kind === 'same-path' && /CreateFile|fopen/i.test(proof.consumer.api); }
			if (kind === 'open-to-write') { return proof.kind === 'same-handle' && /WriteFile|fwrite/i.test(proof.consumer.api); }
			if (kind === 'open-to-close') { return proof.kind === 'same-handle' && /CloseHandle/i.test(proof.consumer.api); }
			return false;
		});
	};
	const typedPaths = [
		buildTypedPath('sid-to-acl', ['sid-producer'], ['acl-builder'], facts, functions),
		buildTypedPath('acl-to-apply', ['acl-builder'], ['acl-apply'], facts, functions),
		buildTypedPath('path-to-open', ['path-producer', 'path-validator'], ['handle-open'], facts, functions),
		buildTypedPath('open-to-write', ['handle-open'], ['write-sink'], facts, functions),
		buildTypedPath('open-to-close', ['handle-open'], ['handle-close'], facts, functions),
		buildTypedPath('parser-to-path', ['archive-parser'], ['path-producer', 'path-validator'], facts, functions, false),
		buildTypedPath('path-to-sink', ['path-producer', 'path-validator'], ['write-sink'], facts, functions),
	].map(flow => {
		const proof = proofForPath(flow.kind);
		return proof ? {
			...flow,
			status: 'proven-value-flow' as const,
			functions: [proof.functionAddress],
			evidence: [`${proof.kind}:${proof.producer.api}@${proof.producer.callSite}->${proof.consumer.api}@${proof.consumer.callSite}:${proof.canonicalIdentity}`],
			blockers: [],
			sameValueProven: true,
		} : flow;
	});
	const byFunction = new Map<string, FilesystemDataflowFact[]>();
	for (const fact of facts) {
		const list = byFunction.get(fact.functionAddress) ?? [];
		list.push(fact);
		byFunction.set(fact.functionAddress, list);
	}
	const handleLifecycles: FilesystemHandleLifecycle[] = [];
	for (const [functionAddress, functionFacts] of byFunction) {
		const kinds = new Set(functionFacts.map(fact => fact.kind));
		if (!kinds.has('handle-open') || ![...kinds].some(kind => ['write-sink', 'handle-close', 'path-validator', 'filesystem-mutation'].includes(kind))) {
			continue;
		}
		const ordered = [...functionFacts]
			.filter(fact => ['handle-open', 'write-sink', 'handle-close', 'path-validator', 'filesystem-mutation'].includes(fact.kind))
			.sort((left, right) => parseInt((left.callSite ?? functionAddress).slice(2), 16) - parseInt((right.callSite ?? functionAddress).slice(2), 16));
		handleLifecycles.push({
			functionAddress,
			functionName: ordered[0]?.functionName ?? functionAddress,
			orderedFacts: ordered.map(fact => ({ kind: fact.kind, api: fact.api, ...(fact.callSite ? { callSite: fact.callSite } : {}) })),
			sameHandleProven: deepValueFlow.proofs.some(proof => proof.kind === 'same-handle' && proof.functionAddress === functionAddress),
			status: deepValueFlow.proofs.some(proof => proof.kind === 'same-handle' && proof.functionAddress === functionAddress)
				? 'proven-value-flow'
				: 'co-located-signal',
		});
	}
	return {
		facts,
		typedPaths,
		handleLifecycles: handleLifecycles.sort((left, right) => left.functionAddress.localeCompare(right.functionAddress)),
		deepValueFlow,
		limitations: [
			'Immediate values come from a bounded pre-call window and are candidates until register/value def-use is resolved.',
			'Neighborhood paths are undirected call-graph signals and do not prove interprocedural value transfer.',
			'Handle lifecycle co-location does not prove that calls operate on the same handle.',
		],
	};
}

function rankCandidateIndex(
	index: {
		candidateFunctions: FilesystemCandidateFunction[];
		candidateEdges: FilesystemCandidateEdge[];
		relatedFunctions: FilesystemRelatedFunction[];
	},
	dataflow: WindowsFilesystemDataflow,
	functions: readonly DisassembledFunction[],
): typeof index & { topCandidateChains: FilesystemCandidateChain[]; criticalHelpers: FilesystemCriticalHelper[] } {
	const degree = new Map<string, number>();
	for (const edge of index.candidateEdges) {
		degree.set(edge.from, (degree.get(edge.from) ?? 0) + 1);
		degree.set(edge.to, (degree.get(edge.to) ?? 0) + 1);
	}
	const pathParticipation = new Map<string, number>();
	for (const flow of dataflow.typedPaths) {
		if (flow.status === 'blocked') { continue; }
		for (const address of new Set(flow.functions)) {
			pathParticipation.set(address, (pathParticipation.get(address) ?? 0) + 1);
		}
	}
	const productCandidates = new Set(index.candidateFunctions
		.filter(candidate => candidate.productEvidenceCount > 0)
		.map(candidate => candidate.address));
	const productGraphLinks = new Map<string, number>();
	for (const edge of index.candidateEdges) {
		if (productCandidates.has(edge.from)) {
			productGraphLinks.set(edge.to, (productGraphLinks.get(edge.to) ?? 0) + 1);
		}
		if (productCandidates.has(edge.to)) {
			productGraphLinks.set(edge.from, (productGraphLinks.get(edge.from) ?? 0) + 1);
		}
	}
	const criticalApiWeight = (candidate: FilesystemCandidateFunction): number => {
		const joined = candidate.apiEvidence.join(' ');
		let weight = 0;
		if (/AllocateAndInitializeSid|CreateWellKnownSid|LookupAccountName/i.test(joined)) { weight += 25; }
		if (/InitializeAcl|AddAccessAllowedAce|AddAccessDeniedAce/i.test(joined)) { weight += 25; }
		if (/SetFileSecurity|SetNamedSecurityInfo|SetSecurityInfo/i.test(joined)) { weight += 30; }
		if (/CreateFile|NtCreateFile/i.test(joined)) { weight += 10; }
		if (/WriteFile|NtWriteFile|fwrite|fopen/i.test(joined)) { weight += 15; }
		if (/GetFinalPathNameByHandle|PathCanonicalize|PathCch/i.test(joined)) { weight += 15; }
		return weight;
	};
	const ranked = index.candidateFunctions.map(candidate => {
		const graphDegree = degree.get(candidate.address) ?? 0;
		const dataflowPathCount = pathParticipation.get(candidate.address) ?? 0;
		const apiWeight = criticalApiWeight(candidate);
		const productLinks = productGraphLinks.get(candidate.address) ?? 0;
		const boundedProductLinks = Math.min(productLinks, 3);
		const rankScore = candidate.evidenceCount + candidate.roleDiversity * 6 +
			Math.min(graphDegree, 12) * 2 + dataflowPathCount * 15 +
			candidate.productEvidenceCount * 12 - candidate.thirdPartyEvidenceCount * 3 +
			apiWeight + boundedProductLinks * 15;
		const rankReasons = [
			`${candidate.evidenceCount} direct evidence item(s)`,
			`${candidate.roleDiversity} role(s)`,
			...(graphDegree > 0 ? [`candidate graph degree ${graphDegree}`] : []),
			...(dataflowPathCount > 0 ? [`participates in ${dataflowPathCount} typed path(s)`] : []),
			...(candidate.productEvidenceCount > 0 ? [`${candidate.productEvidenceCount} product-attributed string(s)`] : []),
			...(candidate.thirdPartyEvidenceCount > 0 ? [`${candidate.thirdPartyEvidenceCount} third-party string(s) down-ranked`] : []),
			...(apiWeight > 0 ? [`critical boundary API weight ${apiWeight}`] : []),
			...(productLinks > 0 ? [`${productLinks} direct product-evidence graph link(s), capped at ${boundedProductLinks}`] : []),
		];
		return { ...candidate, graphDegree, dataflowPathCount, criticalApiWeight: apiWeight, productGraphLinks: productLinks, rankScore, rankReasons };
	}).sort((left, right) => right.rankScore - left.rankScore || right.evidenceCount - left.evidenceCount || left.address.localeCompare(right.address));
	const primary = new Set(ranked.map(candidate => candidate.address));
	const byAddress = new Map(functions.map(fn => [toHex(fn.address), fn.name]));
	const kindWeight: Record<FilesystemTypedPath['kind'], number> = {
		'sid-to-acl': 45,
		'acl-to-apply': 45,
		'path-to-open': 35,
		'open-to-write': 50,
		'open-to-close': 20,
		'parser-to-path': 50,
		'path-to-sink': 50,
	};
	const scoreByAddress = new Map(ranked.map(candidate => [candidate.address, candidate.rankScore]));
	const typedCandidateChains: FilesystemCandidateChain[] = dataflow.typedPaths.filter(flow => flow.status !== 'blocked').map(flow => ({
		kind: flow.kind,
		status: flow.status,
		functions: flow.functions.map(address => ({
			address,
			name: byAddress.get(address) ?? address,
			primaryCandidate: primary.has(address),
		})),
		score: kindWeight[flow.kind] + flow.functions.reduce((sum, address) => sum + Math.min(scoreByAddress.get(address) ?? 5, 40), 0),
		blockers: flow.blockers,
	}));

	const productRoots = new Set(ranked.filter(candidate => candidate.productEvidenceCount > 0).map(candidate => candidate.address));
	const functionByAddress = new Map(functions.map(fn => [toHex(fn.address), fn]));
	const depthOne: FilesystemCriticalHelper[] = index.relatedFunctions.flatMap(related => {
		const sources = related.sourceCandidates.filter(source => productRoots.has(source));
		if (sources.length === 0) { return []; }
		return [{
			address: related.address,
			name: related.name,
			depth: 1 as const,
			sourceCandidates: sources,
			score: Math.min(sources.length, 4) * 25 + Math.min(related.callees.length, 10) - Math.min(related.callers.length, 50),
			reasons: [`directly related to ${sources.length} product-attributed candidate(s)`],
			callers: related.callers,
			callees: related.callees,
		}];
	});
	const primaryOrDepthOne = new Set([...primary, ...depthOne.map(helper => helper.address)]);
	const depthTwoMap = new Map<string, FilesystemCriticalHelper>();
	for (const parent of depthOne) {
		for (const callee of parent.callees) {
			if (primaryOrDepthOne.has(callee)) { continue; }
			const fn = functionByAddress.get(callee);
			if (!fn) { continue; }
			const existing = depthTwoMap.get(callee);
			const roots = [...new Set([...(existing?.sourceCandidates ?? []), ...parent.sourceCandidates])].sort();
			depthTwoMap.set(callee, {
				address: callee,
				name: fn.name,
				depth: 2,
				sourceCandidates: roots,
				via: parent.address,
				score: Math.min(roots.length, 4) * 15 + Math.min(fn.callees.length, 10) - Math.min(fn.callers.length, 40),
				reasons: [`depth-2 helper via ${parent.address}`, `reachable from ${roots.length} product-attributed candidate(s)`],
				callers: fn.callers.map(toHex).sort(),
				callees: fn.callees.map(toHex).sort(),
			});
		}
	}
	const criticalHelpers = [...depthOne, ...depthTwoMap.values()]
		.filter(helper => helper.score > 0)
		.sort((left, right) => right.score - left.score || left.address.localeCompare(right.address))
		.slice(0, 100);
	const helperChains: FilesystemCandidateChain[] = criticalHelpers.slice(0, 30).map(helper => {
		const root = helper.sourceCandidates[0];
		const route = helper.depth === 2 && helper.via ? [root, helper.via, helper.address] : [root, helper.address];
		return {
			kind: 'product-helper-route',
			status: 'call-neighborhood-signal',
			functions: route.map(address => ({
				address,
				name: byAddress.get(address) ?? address,
				primaryCandidate: primary.has(address),
			})),
			score: helper.score + 50,
			blockers: ['Product-attributed reachability does not prove path, archive, or handle value transfer.'],
		};
	});
	const rankedByAddress = new Map(ranked.map(candidate => [candidate.address, candidate]));
	const productCandidateChains: FilesystemCandidateChain[] = index.candidateEdges.flatMap(edge => {
		const source = rankedByAddress.get(edge.from);
		const target = rankedByAddress.get(edge.to);
		if (!source || !target || source.productEvidenceCount === 0) { return []; }
		const archiveContext = source.stringEvidence.some(value => /zip|archive|extract/i.test(value));
		return [{
			kind: 'product-candidate-route' as const,
			status: 'call-neighborhood-signal' as const,
			functions: [source, target].map(candidate => ({
				address: candidate.address,
				name: candidate.name,
				primaryCandidate: true,
			})),
			score: 50 + Math.min(source.rankScore, 40) + Math.min(target.rankScore, 40) + (archiveContext ? 40 : 0),
			blockers: ['A product-attributed direct call does not prove archive, path, or handle value transfer.'],
		}];
	});
	const topCandidateChains = [...typedCandidateChains, ...helperChains, ...productCandidateChains]
		.sort((left, right) => right.score - left.score || left.kind.localeCompare(right.kind));
	return { ...index, candidateFunctions: ranked, topCandidateChains, criticalHelpers };
}

function buildChain(
	principal: ManifestPrincipal,
	capabilities: readonly FilesystemCapabilityEvidence[],
	strings: readonly FilesystemStringPivot[],
	dataflow?: WindowsFilesystemDataflow,
): FilesystemChainEdge[] {
	const principalConfirmed = principal.requestedExecutionLevel === 'requireAdministrator';
	const pathEvidence = evidenceForRole(capabilities, 'path-producer').concat(
		strings.filter(item => item.kind === 'path').slice(0, 12).map(item => `string:${item.value}@${item.address}`),
	);
	const parserEvidence = evidenceForRole(capabilities, 'archive-parser').concat(
		strings.filter(item => item.kind === 'archive').slice(0, 12).map(item => `string:${item.value}@${item.address}`),
	);
	const securityEvidence = evidenceForRole(capabilities, 'security-descriptor')
		.concat(evidenceForRole(capabilities, 'principal-token'));
	const lifecycleEvidence = evidenceForRole(capabilities, 'filesystem-lifecycle');
	const validationEvidence = evidenceForRole(capabilities, 'path-validation');
	const sinkEvidence = evidenceForRole(capabilities, 'filesystem-sink');
	const reparseEvidence = capabilities
		.filter(capability => capability.status === 'owned-callsite' && /^(?:GetFileAttributes|GetFileInformationByHandleEx|GetFinalPathNameByHandle|DeviceIoControl)$/i.test(capability.api))
		.map(capability => `${capability.dll}!${capability.api}@${capability.iatAddress}:owned-callsite`)
		.concat(strings.filter(item => /\b(?:reparse|junction|symlink|symbolic link|hardlink)\b/i.test(item.value))
			.slice(0, 12).map(item => `string:${item.value}@${item.address}`));
	const flowEvidence = (kinds: FilesystemTypedPath['kind'][]) => (dataflow?.typedPaths ?? [])
		.filter(flow => kinds.includes(flow.kind) && flow.status !== 'blocked')
		.map(flow => `${flow.kind}:${flow.functions.join('->')}:${flow.status}`);
	return [
		{
			kind: 'principal',
			status: principalConfirmed ? 'confirmed' : (principal.requestedExecutionLevel ? 'signal' : 'missing'),
			summary: principalConfirmed ? 'Embedded manifest requests administrator execution.' : 'Elevated principal not confirmed.',
			evidence: principalConfirmed ? [`manifest:${principal.requestedExecutionLevel};uiAccess=${principal.uiAccess}`] : [],
			blockers: principalConfirmed ? [] : ['Resolve the embedded manifest or privileged service/token transition.'],
		},
		{
			kind: 'state-location', status: pathEvidence.length ? 'signal' : 'missing',
			summary: 'Path producers and referenced path vocabulary are navigation signals only.',
			evidence: pathEvidence, blockers: ['Recover the exact path expression and predictability constraints.'],
		},
		{
			kind: 'writer', status: 'blocked', summary: 'Writable principal and child replacement rights are not inferred from imports.',
			evidence: securityEvidence.concat(flowEvidence(['sid-to-acl', 'acl-to-apply'])), blockers: ['Recover SID construction, ACL entries, inheritance, effective access masks, and same-value def-use.'],
		},
		{
			kind: 'lifecycle', status: lifecycleEvidence.length ? 'signal' : 'missing', summary: 'Filesystem lifecycle APIs need handle/order correlation.',
			evidence: lifecycleEvidence.concat(flowEvidence(['open-to-close'])), blockers: ['Prove create/open/close/reopen/move calls operate on the same path and handle value.'],
		},
		{
			kind: 'parser', status: parserEvidence.length ? 'signal' : 'missing', summary: 'Archive vocabulary/imports do not prove the parser consumer.',
			evidence: parserEvidence.concat(flowEvidence(['parser-to-path'])), blockers: ['Prove the downloaded state value reaches the concrete ZIP/archive parser entry.'],
		},
		{
			kind: 'path-property', status: validationEvidence.length ? 'signal' : 'missing', summary: 'Canonicalization imports do not prove descendant enforcement.',
			evidence: validationEvidence.concat(flowEvidence(['path-to-open'])), blockers: ['Recover absolute-path, traversal, prefix, descendant-check semantics, and path-value def-use.'],
		},
		{
			kind: 'reparse-safety',
			status: reparseEvidence.length > 0 ? 'signal' : 'not-assessed',
			summary: reparseEvidence.length > 0
				? 'Reparse-related observations exist, but safe component traversal is not proven.'
				: 'Reparse/junction safety was not assessed.',
			evidence: reparseEvidence,
			blockers: [
				'Prove FILE_ATTRIBUTE_REPARSE_POINT/reparse-tag handling, handle-relative traversal, and final-path descendant enforcement for every writable component.',
			],
		},
		{
			kind: 'sink', status: sinkEvidence.length ? 'signal' : 'missing', summary: 'Write APIs require path/open-mode and call-chain proof.',
			evidence: sinkEvidence.concat(flowEvidence(['open-to-write', 'path-to-sink'])), blockers: ['Recover final target path, disposition/share mode, write arguments, and same-handle def-use.'],
		},
	];
}

export function buildWindowsFilesystemAudit(input: {
	principal?: ManifestPrincipal;
	imports: readonly ImportLibrary[];
	functions: readonly DisassembledFunction[];
	strings: readonly StringReference[];
	lazyFunctions: number;
	maxStringSignals?: number;
	architecture?: string;
}): WindowsFilesystemAuditResult {
	const principal = input.principal ?? { status: 'not-assessed', requestedExecutionLevel: null, uiAccess: null };
	const capabilities = collectCapabilityEvidence(input.imports, input.functions);
	const stringPivots = collectStringPivots(input.strings, input.functions, input.maxStringSignals ?? 200);
	const semanticStringPivots = stringPivots.filter(pivot => pivot.evidenceClass === 'semantic-candidate');
	const dataflow = buildWindowsDataflow(capabilities, semanticStringPivots, input.functions, input.architecture ?? 'x64');
	const candidateIndex = rankCandidateIndex(
		buildCandidateIndex(capabilities, semanticStringPivots, input.functions),
		dataflow,
		input.functions,
	);
	const chain = buildChain(principal, capabilities, semanticStringPivots, dataflow);
	const materializedFunctions = input.functions.filter(fn => fn.instructions.length > 0).length;
	const totalFunctions = input.functions.length;
	const incomplete = chain.some(edge => edge.status !== 'confirmed');
	return {
		status: incomplete ? 'partial' : 'ok',
		securityEvidenceUsable: false,
		verdict: incomplete ? 'incomplete' : 'candidate-chain',
		principal,
		coverage: {
			totalFunctions,
			materializedFunctions,
			lazyFunctions: input.lazyFunctions,
			materializedFunctionRatio: totalFunctions > 0 ? materializedFunctions / totalFunctions : 1,
		},
		capabilities,
		stringPivots,
		...candidateIndex,
		dataflow,
		chain,
		limitations: [
			'Import-only capabilities remain signals until a materialized owner/callsite is recovered.',
			'Dense enum-to-message tables retain their strings as message-table evidence but do not create filesystem roles.',
			'Owned callsites still do not prove argument values, handle identity, ordering, or attacker control.',
			'This command never assigns product vulnerability severity.',
		],
		generatedAt: new Date().toISOString(),
	};
}
