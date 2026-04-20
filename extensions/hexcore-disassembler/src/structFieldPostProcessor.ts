/*---------------------------------------------------------------------------------------------
 *  HexCore Struct Field Post-Processor (v3.8.0)
 *
 *  Renames Helix pseudo-C output using struct field info extracted from
 *  BTF (.ko / vmlinux) or PDB (PE).
 *
 *  Helix already does:
 *    - field_0xNN naming (offset-based)
 *    - struct grouping via RecoverStructTypes
 *    - array detection (array_0x10[i])
 *    - type propagation (pointer, int32, etc.)
 *
 *  What Helix CANNOT do without external info:
 *    - Know that offset 0xC6F0 is called "jit_pool_head" (needs debug info)
 *    - Know that param_1 is "struct kbase_context *" (needs DWARF/BTF/PDB sigs)
 *
 *  This module bridges that gap by post-processing the C source string.
 *---------------------------------------------------------------------------------------------*/

import type { StructInfoJson, StructInfo, FunctionSignatureInfo } from './elfBtfLoader';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A single field rename that was applied */
export interface FieldRenameEntry {
	/** Original field name in Helix output (e.g. "field_0xC6F0") */
	original: string;
	/** New field name from debug info (e.g. "jit_pool_head") */
	renamed: string;
	/** Struct this field belongs to */
	structName: string;
	/** Byte offset */
	offset: number;
}

/** A parameter rename that was applied */
export interface ParamRenameEntry {
	/** Original param name (e.g. "param_1") */
	original: string;
	/** New param name (e.g. "kctx") */
	renamed: string;
	/** Resolved C type (e.g. "struct kbase_context *") */
	type: string;
}

/** Result of post-processing */
export interface PostProcessResult {
	/** Modified source code */
	source: string;
	/** Field renames applied */
	fieldRenames: FieldRenameEntry[];
	/** Parameter renames applied */
	paramRenames: ParamRenameEntry[];
	/** Struct typedef block prepended to source (if any) */
	structTypedefs: string;
	/** Total rename count */
	totalRenames: number;
}

// ---------------------------------------------------------------------------
// Offset lookup table builder
// ---------------------------------------------------------------------------

/**
 * Build a map from byte offset → field name for a struct.
 * Handles both hex string offsets ("0xC6F0") and numeric.
 */
function buildOffsetMap(structInfo: StructInfo): Map<number, { name: string; type: string; size: number }> {
	const map = new Map<number, { name: string; type: string; size: number }>();
	for (const field of structInfo.fields) {
		const offset = typeof field.offset === 'string'
			? parseInt(field.offset, 16)
			: field.offset;
		if (!isNaN(offset) && field.name) {
			map.set(offset, { name: field.name, type: field.type, size: field.size });
		}
	}
	return map;
}

// ---------------------------------------------------------------------------
// Field rename pass
// ---------------------------------------------------------------------------

// Matches Helix field access patterns:
//   ->field_0xABC      (pointer deref)
//   .field_0xABC       (direct access)
//   ->array_0xABC[     (array access)
const FIELD_PATTERN = /([.>])field_0x([0-9a-fA-F]+)\b/g;
const ARRAY_PATTERN = /([.>])array_0x([0-9a-fA-F]+)\b/g;

/**
 * Rename field_0xNN patterns in source using struct info.
 *
 * Strategy: We don't know which struct a given `field_0xNN` belongs to,
 * so we check ALL structs for a field at that offset. If exactly one
 * struct has a named field at that offset, we rename. If multiple structs
 * have fields at the same offset (ambiguous), we skip unless we can
 * disambiguate via parameter types.
 *
 * @param source The Helix pseudo-C output
 * @param structInfo The struct info JSON
 * @param paramStructMap Map of variable name → struct name (for disambiguation)
 */
function renameFields(
	source: string,
	structInfo: StructInfoJson,
	paramStructMap: Map<string, string>,
): { source: string; renames: FieldRenameEntry[] } {
	const renames: FieldRenameEntry[] = [];

	// Build offset maps for all structs
	const structMaps = new Map<string, Map<number, { name: string; type: string; size: number }>>();
	for (const [name, info] of Object.entries(structInfo.structs)) {
		structMaps.set(name, buildOffsetMap(info));
	}

	// Process field_0xNN patterns
	// replace callback: (match, accessor, hexOffset, matchOffset, fullStr)
	let result = source.replace(FIELD_PATTERN, (match: string, accessor: string, hexOffset: string, matchOffset: number, fullStr: string) => {
		const byteOffset = parseInt(hexOffset, 16);

		// Try to find the variable name before the accessor to disambiguate
		const beforeMatch = fullStr.substring(0, matchOffset);
		const varNameMatch = beforeMatch.match(/(\w+)\s*(?:->|\.)$/);
		const varName = varNameMatch?.[1];

		// If we know which struct this variable is, use that directly
		if (varName && paramStructMap.has(varName)) {
			const structName = paramStructMap.get(varName)!;
			const fieldMap = structMaps.get(structName);
			if (fieldMap) {
				const field = fieldMap.get(byteOffset);
				if (field) {
					renames.push({
						original: `field_0x${hexOffset}`,
						renamed: field.name,
						structName,
						offset: byteOffset,
					});
					return `${accessor}${field.name}`;
				}
			}
		}

		// No disambiguation — check all structs
		const candidates: Array<{ structName: string; fieldName: string }> = [];
		for (const [structName, fieldMap] of structMaps) {
			const field = fieldMap.get(byteOffset);
			if (field) {
				candidates.push({ structName, fieldName: field.name });
			}
		}

		// Only rename if unambiguous (one candidate) or all candidates agree on the name
		if (candidates.length === 1) {
			renames.push({
				original: `field_0x${hexOffset}`,
				renamed: candidates[0].fieldName,
				structName: candidates[0].structName,
				offset: byteOffset,
			});
			return `${accessor}${candidates[0].fieldName}`;
		}

		if (candidates.length > 1) {
			const allSameName = candidates.every(c => c.fieldName === candidates[0].fieldName);
			if (allSameName) {
				renames.push({
					original: `field_0x${hexOffset}`,
					renamed: candidates[0].fieldName,
					structName: candidates[0].structName,
					offset: byteOffset,
				});
				return `${accessor}${candidates[0].fieldName}`;
			}
		}

		return match; // ambiguous or no match — leave as is
	});

	// Same pass for array_0xNN patterns
	result = result.replace(ARRAY_PATTERN, (match, accessor: string, hexOffset: string) => {
		const byteOffset = parseInt(hexOffset, 16);

		const candidates: Array<{ structName: string; fieldName: string }> = [];
		for (const [structName, fieldMap] of structMaps) {
			const field = fieldMap.get(byteOffset);
			if (field) {
				candidates.push({ structName, fieldName: field.name });
			}
		}

		if (candidates.length === 1 || (candidates.length > 1 && candidates.every(c => c.fieldName === candidates[0].fieldName))) {
			renames.push({
				original: `array_0x${hexOffset}`,
				renamed: candidates[0].fieldName,
				structName: candidates[0].structName,
				offset: byteOffset,
			});
			return `${accessor}${candidates[0].fieldName}`;
		}

		return match;
	});

	return { source: result, renames };
}

// ---------------------------------------------------------------------------
// Parameter rename pass
// ---------------------------------------------------------------------------

/**
 * Rename param_N to the actual parameter name from function signatures.
 * Also adds type annotations as comments.
 */
function renameParams(
	source: string,
	functionName: string,
	structInfo: StructInfoJson,
): { source: string; renames: ParamRenameEntry[]; paramStructMap: Map<string, string> } {
	const renames: ParamRenameEntry[] = [];
	const paramStructMap = new Map<string, string>();

	const funcSig = structInfo.functions[functionName];
	if (!funcSig) {
		return { source, renames, paramStructMap };
	}

	let result = source;

	for (const param of funcSig.params) {
		// Helix uses 1-based param indexing: param_1, param_2, ...
		const helixParamName = `param_${param.index + 1}`;
		const newName = param.name;

		// Don't rename if the param name is generic (unnamed in BTF)
		if (newName.startsWith('param_')) { continue; }

		// Build regex for word-boundary replacement
		const regex = new RegExp(`\\b${escapeRegex(helixParamName)}\\b`, 'g');

		if (regex.test(result)) {
			result = result.replace(regex, newName);
			renames.push({
				original: helixParamName,
				renamed: newName,
				type: param.type,
			});

			// Track struct association for field disambiguation
			if (param.structName) {
				paramStructMap.set(newName, param.structName);
			}
		}
	}

	return { source: result, renames, paramStructMap };
}

// ---------------------------------------------------------------------------
// Struct typedef generator
// ---------------------------------------------------------------------------

/**
 * Generate struct typedef comments to prepend to the decompiled output.
 * Shows the recovered struct layout for context.
 */
function generateStructTypedefs(structInfo: StructInfoJson, usedStructs: Set<string>): string {
	if (usedStructs.size === 0) { return ''; }

	const lines: string[] = ['/* --- Struct layouts from debug info --- */'];

	for (const structName of usedStructs) {
		const info = structInfo.structs[structName];
		if (!info) { continue; }

		lines.push(`/* struct ${structName} (${info.size} bytes) {`);
		for (const field of info.fields) {
			lines.push(`     +${field.offset}  ${field.type} ${field.name};  // ${field.size} bytes`);
		}
		lines.push(' } */');
		lines.push('');
	}

	return lines.join('\n');
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

/**
 * Post-process Helix pseudo-C output with struct field names from debug info.
 *
 * @param source The raw Helix pseudo-C output
 * @param structInfo Struct info JSON (from BTF, DWARF, or PDB)
 * @param functionName The function being decompiled (for param type resolution)
 * @param options Configuration options
 * @returns Post-processed source with field and parameter names
 */
export function applyStructFieldNames(
	source: string,
	structInfo: StructInfoJson,
	functionName?: string,
	options?: {
		/** Prepend struct typedefs as comments (default: true) */
		includeTypedefs?: boolean;
		/** Rename parameters from function signatures (default: true) */
		renameParameters?: boolean;
	},
): PostProcessResult {
	const includeTypedefs = options?.includeTypedefs !== false;
	const renameParameters = options?.renameParameters !== false;

	let processed = source;
	let paramRenames: ParamRenameEntry[] = [];
	let paramStructMap = new Map<string, string>();

	// Pass 1: Rename parameters (must come first so field disambiguation works)
	if (renameParameters && functionName) {
		const paramResult = renameParams(processed, functionName, structInfo);
		processed = paramResult.source;
		paramRenames = paramResult.renames;
		paramStructMap = paramResult.paramStructMap;
	}

	// Pass 2: Rename struct fields
	const fieldResult = renameFields(processed, structInfo, paramStructMap);
	processed = fieldResult.source;

	// Collect used structs for typedef generation
	const usedStructs = new Set<string>();
	for (const r of fieldResult.renames) {
		usedStructs.add(r.structName);
	}
	for (const r of paramRenames) {
		const funcSig = structInfo.functions[functionName ?? ''];
		if (funcSig) {
			for (const p of funcSig.params) {
				if (p.structName) { usedStructs.add(p.structName); }
			}
		}
	}

	// Generate typedef block
	const structTypedefs = includeTypedefs ? generateStructTypedefs(structInfo, usedStructs) : '';

	if (structTypedefs) {
		processed = structTypedefs + '\n' + processed;
	}

	return {
		source: processed,
		fieldRenames: fieldResult.renames,
		paramRenames,
		structTypedefs,
		totalRenames: fieldResult.renames.length + paramRenames.length,
	};
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
