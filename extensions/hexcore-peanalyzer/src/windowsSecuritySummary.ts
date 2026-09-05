/*---------------------------------------------------------------------------------------------
 * Windows PE trust-boundary facts. Import presence is a signal, never proof of reachability.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import type { ImportEntry, SectionHeader, SecurityMitigation } from './peParser';

export type RequestedExecutionLevel = 'asInvoker' | 'highestAvailable' | 'requireAdministrator' | 'unknown';

export interface ExecutionManifestSummary {
	status: 'found' | 'not-found' | 'unreadable';
	requestedExecutionLevel: RequestedExecutionLevel | null;
	uiAccess: boolean | null;
	source?: {
		section: string;
		fileOffset: number;
		encoding: 'utf8' | 'utf16le';
	};
	rawLevel?: string;
	reason?: string;
}

export type WindowsCapabilityRole =
	| 'path-producer'
	| 'filesystem-lifecycle'
	| 'filesystem-sink'
	| 'security-descriptor'
	| 'principal-token'
	| 'path-validation'
	| 'archive-parser';

export interface WindowsImportCapability {
	dll: string;
	api: string;
	iatRva: number;
	roles: WindowsCapabilityRole[];
	evidenceStatus: 'import-signal';
}

export interface WindowsSecuritySummary {
	status: 'signals-only';
	principal: ExecutionManifestSummary;
	mitigations: Array<SecurityMitigation & { evidenceSource: 'dll-characteristics' }>;
	capabilities: WindowsImportCapability[];
	limitations: string[];
}

const API_ROLES: ReadonlyArray<{ pattern: RegExp; roles: WindowsCapabilityRole[] }> = [
	{ pattern: /^(GetTempPath|GetTempFileName|GetFullPathName|GetEnvironmentVariable|SHGetFolderPath)/i, roles: ['path-producer'] },
	{ pattern: /^(PathCanonicalize|PathCchCanonicalize|PathCombine|PathCchCombine|GetFinalPathNameByHandle)/i, roles: ['path-validation'] },
	{ pattern: /^(CreateFile(?:A|W)?|NtCreateFile|DeleteFile(?:A|W)?|MoveFile(?:Ex)?(?:A|W)?|ReplaceFile(?:A|W)?|CopyFile(?:Ex)?(?:A|W)?|CreateDirectory(?:A|W)?|RemoveDirectory(?:A|W)?|SetFileInformationByHandle|CloseHandle)$/i, roles: ['filesystem-lifecycle'] },
	{ pattern: /^(WriteFile(?:Ex)?|fopen|_wfopen|fwrite|_write|NtWriteFile)$/i, roles: ['filesystem-sink'] },
	{ pattern: /^(InitializeAcl|AddAccessAllowedAce|AddAccessDeniedAce|SetNamedSecurityInfo|SetSecurityInfo|SetFileSecurity|GetNamedSecurityInfo|GetSecurityInfo)/i, roles: ['security-descriptor'] },
	{ pattern: /^(OpenProcessToken|GetTokenInformation|CheckTokenMembership|CreateWellKnownSid|AllocateAndInitializeSid|LookupAccountName|EqualSid)/i, roles: ['principal-token'] },
	{ pattern: /^(zip_|unz|archive_|CreateDecompressor|Decompress)/i, roles: ['archive-parser'] },
];

function normalizeLevel(raw: string | undefined): { level: RequestedExecutionLevel | null; rawLevel?: string } {
	if (!raw) { return { level: null }; }
	const known = ['asInvoker', 'highestAvailable', 'requireAdministrator'] as const;
	const exact = known.find(candidate => candidate.toLowerCase() === raw.toLowerCase());
	return exact ? { level: exact } : { level: 'unknown', rawLevel: raw };
}

function findManifestTag(text: string): { index: number; tag: string } | undefined {
	const match = /<requestedExecutionLevel\b[^>]*>/i.exec(text);
	return match ? { index: match.index, tag: match[0] } : undefined;
}

function attribute(tag: string, name: string): string | undefined {
	const match = new RegExp(`\\b${name}\\s*=\\s*["']([^"']+)["']`, 'i').exec(tag);
	return match?.[1];
}

export function extractExecutionManifestFromBuffer(
	buffer: Buffer,
	fileOffset = 0,
	section = '.rsrc',
): ExecutionManifestSummary {
	for (const encoding of ['utf8', 'utf16le'] as const) {
		const text = buffer.toString(encoding);
		const found = findManifestTag(text);
		if (!found) { continue; }
		const rawLevel = attribute(found.tag, 'level');
		const normalized = normalizeLevel(rawLevel);
		const rawUiAccess = attribute(found.tag, 'uiAccess');
		return {
			status: 'found',
			requestedExecutionLevel: normalized.level,
			uiAccess: rawUiAccess === undefined ? null : rawUiAccess.toLowerCase() === 'true',
			source: {
				section,
				fileOffset: fileOffset + found.index * (encoding === 'utf16le' ? 2 : 1),
				encoding,
			},
			...(normalized.rawLevel ? { rawLevel: normalized.rawLevel } : {}),
		};
	}
	return { status: 'not-found', requestedExecutionLevel: null, uiAccess: null };
}

export function extractExecutionManifest(
	filePath: string,
	sections: readonly SectionHeader[],
	maxResourceBytes = 8 * 1024 * 1024,
): ExecutionManifestSummary {
	const resource = sections.find(candidate => candidate.name.toLowerCase() === '.rsrc');
	if (!resource || resource.sizeOfRawData <= 0) {
		return { status: 'not-found', requestedExecutionLevel: null, uiAccess: null, reason: 'PE has no raw-backed .rsrc section' };
	}
	try {
		const size = Math.min(resource.sizeOfRawData, maxResourceBytes);
		const buffer = Buffer.alloc(size);
		const fd = fs.openSync(filePath, 'r');
		try {
			const bytesRead = fs.readSync(fd, buffer, 0, size, resource.pointerToRawData);
			return extractExecutionManifestFromBuffer(
				buffer.subarray(0, bytesRead),
				resource.pointerToRawData,
				resource.name,
			);
		} finally {
			fs.closeSync(fd);
		}
	} catch (error) {
		return {
			status: 'unreadable',
			requestedExecutionLevel: null,
			uiAccess: null,
			reason: error instanceof Error ? error.message : String(error),
		};
	}
}

export function classifyWindowsImports(imports: readonly ImportEntry[]): WindowsImportCapability[] {
	const capabilities: WindowsImportCapability[] = [];
	for (const library of imports) {
		for (const fn of library.functions) {
			const roles = [...new Set(API_ROLES
				.filter(entry => entry.pattern.test(fn.name))
				.flatMap(entry => entry.roles))];
			if (roles.length === 0) { continue; }
			capabilities.push({
				dll: library.dllName,
				api: fn.name,
				iatRva: fn.address,
				roles,
				evidenceStatus: 'import-signal',
			});
		}
	}
	return capabilities.sort((left, right) =>
		left.roles[0].localeCompare(right.roles[0]) || left.api.localeCompare(right.api));
}

export function buildWindowsSecuritySummary(
	manifest: ExecutionManifestSummary,
	mitigations: readonly SecurityMitigation[],
	imports: readonly ImportEntry[],
): WindowsSecuritySummary {
	return {
		status: 'signals-only',
		principal: manifest,
		mitigations: mitigations.map(mitigation => ({ ...mitigation, evidenceSource: 'dll-characteristics' })),
		capabilities: classifyWindowsImports(imports),
		limitations: [
			'Import presence does not prove that product code reaches the API.',
			'IAT ownership and caller/callee linkage require Disassembler analysis.',
			'DACL, SID, access-mask, handle-lifecycle, and path-safety claims require argument/data-flow evidence.',
		],
	};
}
