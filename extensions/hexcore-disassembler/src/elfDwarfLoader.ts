/*---------------------------------------------------------------------------------------------
 *  HexCore DWARF Debug Info Loader (v3.8.0)
 *
 *  Minimal DWARF parser for extracting struct layouts and function signatures
 *  from ELF binaries that have .debug_info but no .BTF section.
 *
 *  Produces the same StructInfoJson format as elfBtfLoader.ts so the
 *  structFieldPostProcessor can consume it identically.
 *
 *  Supports DWARF v2/v3/v4/v5, 32-bit and 64-bit ELF, little-endian.
 *  Only parses what we need: struct layouts + function signatures.
 *---------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import type { StructInfoJson, StructInfo, StructFieldInfo, FunctionSignatureInfo, FunctionParamInfo } from './elfBtfLoader';

// Re-export the shared types
export type { StructInfoJson, StructInfo, StructFieldInfo, FunctionSignatureInfo, FunctionParamInfo };

// ---------------------------------------------------------------------------
// DWARF constants
// ---------------------------------------------------------------------------

// Tags
const DW_TAG_array_type = 0x01;
const DW_TAG_enumeration_type = 0x04;
const DW_TAG_formal_parameter = 0x05;
const DW_TAG_member = 0x0D;
const DW_TAG_pointer_type = 0x0F;
const DW_TAG_structure_type = 0x13;
const DW_TAG_subroutine_type = 0x15;
const DW_TAG_typedef = 0x16;
const DW_TAG_union_type = 0x17;
const DW_TAG_subprogram = 0x2E;
const DW_TAG_base_type = 0x24;
const DW_TAG_const_type = 0x26;
const DW_TAG_volatile_type = 0x35;
const DW_TAG_restrict_type = 0x37;
const DW_TAG_subrange_type = 0x21;
const DW_TAG_unspecified_parameters = 0x18;

// Attributes
const DW_AT_name = 0x03;
const DW_AT_byte_size = 0x0B;
const DW_AT_bit_size = 0x0D;
const DW_AT_bit_offset = 0x0C;
const DW_AT_type = 0x49;
const DW_AT_data_member_location = 0x38;
const DW_AT_upper_bound = 0x2F;
const DW_AT_count = 0x37;
const DW_AT_encoding = 0x3E;
const DW_AT_low_pc = 0x11;
const DW_AT_high_pc = 0x12;

// DWARF 5 split-form bases (per-CU).  When a CU uses DW_FORM_strx*/addrx* for
// its attribute values, those forms index into .debug_str_offsets / .debug_addr
// offset by these CU-local bases.  Both use DW_FORM_sec_offset for their own
// values so they can always be read directly without index resolution.
const DW_AT_str_offsets_base = 0x72;
const DW_AT_addr_base = 0x73;

// Forms
const DW_FORM_addr = 0x01;
const DW_FORM_block2 = 0x03;
const DW_FORM_block4 = 0x04;
const DW_FORM_data2 = 0x05;
const DW_FORM_data4 = 0x06;
const DW_FORM_data8 = 0x07;
const DW_FORM_string = 0x08;
const DW_FORM_block = 0x09;
const DW_FORM_block1 = 0x0A;
const DW_FORM_data1 = 0x0B;
const DW_FORM_flag = 0x0C;
const DW_FORM_sdata = 0x0D;
const DW_FORM_strp = 0x0E;
const DW_FORM_udata = 0x0F;
const DW_FORM_ref_addr = 0x10;
const DW_FORM_ref1 = 0x11;
const DW_FORM_ref2 = 0x12;
const DW_FORM_ref4 = 0x13;
const DW_FORM_ref8 = 0x14;
const DW_FORM_ref_udata = 0x15;
const DW_FORM_indirect = 0x16;
const DW_FORM_sec_offset = 0x17;
const DW_FORM_exprloc = 0x18;
const DW_FORM_flag_present = 0x19;
const DW_FORM_ref_sig8 = 0x20;
// DWARF 5
const DW_FORM_strx = 0x1A;
const DW_FORM_addrx = 0x1B;
const DW_FORM_ref_sup4 = 0x1C;
const DW_FORM_strp_sup = 0x1D;
const DW_FORM_data16 = 0x1E;
const DW_FORM_line_strp = 0x1F;
const DW_FORM_implicit_const = 0x21;
const DW_FORM_loclistx = 0x22;
const DW_FORM_rnglistx = 0x23;
const DW_FORM_ref_sup8 = 0x24;
const DW_FORM_strx1 = 0x25;
const DW_FORM_strx2 = 0x26;
const DW_FORM_strx3 = 0x27;
const DW_FORM_strx4 = 0x28;
const DW_FORM_addrx1 = 0x29;
const DW_FORM_addrx2 = 0x2A;
const DW_FORM_addrx3 = 0x2B;
const DW_FORM_addrx4 = 0x2C;

// DW_OP for member location expressions
const DW_OP_plus_uconst = 0x23;
const DW_OP_constu = 0x10;

// ---------------------------------------------------------------------------
// LEB128 decoder
// ---------------------------------------------------------------------------

interface BufferCursor {
	buf: Buffer;
	pos: number;
}

function readULEB128(c: BufferCursor): number {
	let result = 0;
	let shift = 0;
	while (c.pos < c.buf.length) {
		const byte = c.buf[c.pos++];
		result |= (byte & 0x7F) << shift;
		if ((byte & 0x80) === 0) break;
		shift += 7;
		if (shift > 35) break; // overflow guard
	}
	return result >>> 0; // ensure unsigned
}

function readSLEB128(c: BufferCursor): number {
	let result = 0;
	let shift = 0;
	let byte = 0;
	while (c.pos < c.buf.length) {
		byte = c.buf[c.pos++];
		result |= (byte & 0x7F) << shift;
		shift += 7;
		if ((byte & 0x80) === 0) break;
		if (shift > 35) break;
	}
	if (shift < 32 && (byte & 0x40)) {
		result |= -(1 << shift);
	}
	return result;
}

// ---------------------------------------------------------------------------
// Abbreviation table parser
// ---------------------------------------------------------------------------

interface AbbrevAttr {
	name: number;     // DW_AT_*
	form: number;     // DW_FORM_*
	implicitConst?: number; // value for DW_FORM_implicit_const
}

interface AbbrevEntry {
	code: number;
	tag: number;
	hasChildren: boolean;
	attrs: AbbrevAttr[];
}

function parseAbbrevTable(abbrevData: Buffer, offset: number): Map<number, AbbrevEntry> {
	const table = new Map<number, AbbrevEntry>();
	const c: BufferCursor = { buf: abbrevData, pos: offset };

	while (c.pos < abbrevData.length) {
		const code = readULEB128(c);
		if (code === 0) break; // end of table

		const tag = readULEB128(c);
		const hasChildren = c.buf[c.pos++] !== 0;
		const attrs: AbbrevAttr[] = [];

		while (c.pos < abbrevData.length) {
			const attrName = readULEB128(c);
			const attrForm = readULEB128(c);
			if (attrName === 0 && attrForm === 0) break; // end of attr list

			const attr: AbbrevAttr = { name: attrName, form: attrForm };
			if (attrForm === DW_FORM_implicit_const) {
				attr.implicitConst = readSLEB128(c);
			}
			attrs.push(attr);
		}

		table.set(code, { code, tag, hasChildren, attrs });
	}

	return table;
}

// ---------------------------------------------------------------------------
// Form value reader
// ---------------------------------------------------------------------------

interface FormReadContext {
	c: BufferCursor;
	addrSize: number;
	is64Bit: boolean;    // DWARF 64-bit format (not ELF 64-bit)
	version: number;
	cuOffset: number;    // start of this CU in .debug_info
	strData: Buffer;     // .debug_str section

	// DWARF 5 split-form support.  These are mutated as we walk a CU:
	// when the CU DIE's DW_AT_str_offsets_base / DW_AT_addr_base attrs
	// are read, the parser's attr loop updates these fields so that
	// subsequent DW_FORM_strx* / DW_FORM_addrx* values in the same CU
	// can be resolved.  -1 = base not yet known (CU DIE attrs out of
	// order or this DWARF doesn't use split forms).
	debugAddr: Buffer | null;        // .debug_addr section (DWARF 5)
	debugStrOffsets: Buffer | null;  // .debug_str_offsets section (DWARF 5)
	debugLineStr: Buffer | null;     // .debug_line_str section (DWARF 5)
	addrBase: number;                // CU-specific, offset into .debug_addr
	strOffsetsBase: number;          // CU-specific, offset into .debug_str_offsets
}

/** Read a fixed-size little-endian integer from a buffer at an absolute position. */
function readAt(buf: Buffer, pos: number, n: number): number {
	if (n === 1) { return buf[pos]; }
	if (n === 2) { return buf.readUInt16LE(pos); }
	if (n === 4) { return buf.readUInt32LE(pos); }
	if (n === 8) {
		const lo = buf.readUInt32LE(pos);
		const hi = buf.readUInt32LE(pos + 4);
		return lo + hi * 0x100000000;
	}
	let v = 0;
	for (let i = 0; i < n; i++) { v |= buf[pos + i] << (i * 8); }
	return v >>> 0;
}

/** Resolve a DW_FORM_strx* index via the current CU's str_offsets_base. */
function resolveStrx(ctx: FormReadContext, index: number): string {
	if (!ctx.debugStrOffsets || ctx.strOffsetsBase < 0) { return ''; }
	// Each .debug_str_offsets entry is 4 bytes (DWARF32) or 8 bytes (DWARF64).
	// The base points PAST the section header, directly at entry 0.
	const entrySize = ctx.is64Bit ? 8 : 4;
	const pos = ctx.strOffsetsBase + index * entrySize;
	if (pos + entrySize > ctx.debugStrOffsets.length) { return ''; }
	const strOffset = readAt(ctx.debugStrOffsets, pos, entrySize);
	if (strOffset >= ctx.strData.length) { return ''; }
	return readCString(ctx.strData, strOffset);
}

/** Resolve a DW_FORM_addrx* index via the current CU's addr_base. */
function resolveAddrx(ctx: FormReadContext, index: number): number {
	if (!ctx.debugAddr || ctx.addrBase < 0) { return 0; }
	// Each .debug_addr entry is addr_size bytes.
	const pos = ctx.addrBase + index * ctx.addrSize;
	if (pos + ctx.addrSize > ctx.debugAddr.length) { return 0; }
	return readAt(ctx.debugAddr, pos, ctx.addrSize);
}

/** Read a form value and return as number (or string for DW_FORM_string/strp). */
function readFormValue(ctx: FormReadContext, form: number, implicitConst?: number): number | string | Buffer | null {
	const { c, addrSize, is64Bit, version, strData } = ctx;

	switch (form) {
		case DW_FORM_addr:
			return readN(c, addrSize);
		case DW_FORM_data1:
		case DW_FORM_ref1:
		case DW_FORM_flag:
			return c.buf[c.pos++];
		case DW_FORM_data2:
		case DW_FORM_ref2:
			return readU16(c);
		case DW_FORM_data4:
		case DW_FORM_ref4:
			return readU32(c);
		case DW_FORM_data8:
		case DW_FORM_ref8:
		case DW_FORM_ref_sig8:
			return readN(c, 8);
		case DW_FORM_data16:
			c.pos += 16;
			return 0;
		case DW_FORM_sdata:
			return readSLEB128(c);
		case DW_FORM_udata:
		case DW_FORM_ref_udata:
			return readULEB128(c);
		case DW_FORM_string: {
			const start = c.pos;
			while (c.pos < c.buf.length && c.buf[c.pos] !== 0) c.pos++;
			const str = c.buf.subarray(start, c.pos).toString('utf-8');
			c.pos++; // skip null terminator
			return str;
		}
		case DW_FORM_strp:
		case DW_FORM_line_strp:
		case DW_FORM_strp_sup: {
			const strOffset = is64Bit ? readN(c, 8) : readU32(c);
			return readCString(strData, strOffset);
		}
		case DW_FORM_strx: {
			const idx = readULEB128(c);
			return resolveStrx(ctx, idx);
		}
		case DW_FORM_addrx: {
			const idx = readULEB128(c);
			return resolveAddrx(ctx, idx);
		}
		// rnglistx / loclistx still skip — range/location lists aren't
		// used by our current extractors (struct layouts + function
		// boundaries).  Tracked as future work if we ever need them.
		case DW_FORM_loclistx:
		case DW_FORM_rnglistx:
			readULEB128(c);
			return 0;
		case DW_FORM_strx1: {
			const idx = c.buf[c.pos++];
			return resolveStrx(ctx, idx);
		}
		case DW_FORM_addrx1: {
			const idx = c.buf[c.pos++];
			return resolveAddrx(ctx, idx);
		}
		case DW_FORM_strx2: {
			const idx = readU16(c);
			return resolveStrx(ctx, idx);
		}
		case DW_FORM_addrx2: {
			const idx = readU16(c);
			return resolveAddrx(ctx, idx);
		}
		case DW_FORM_strx3: {
			const idx = readN(c, 3);
			return resolveStrx(ctx, idx);
		}
		case DW_FORM_addrx3: {
			const idx = readN(c, 3);
			return resolveAddrx(ctx, idx);
		}
		case DW_FORM_strx4: {
			const idx = readU32(c);
			return resolveStrx(ctx, idx);
		}
		case DW_FORM_addrx4: {
			const idx = readU32(c);
			return resolveAddrx(ctx, idx);
		}
		case DW_FORM_ref_addr:
			// DWARF 2: addr_size; DWARF 3+: 4 (32-bit) or 8 (64-bit)
			if (version <= 2) return readN(c, addrSize);
			return is64Bit ? readN(c, 8) : readU32(c);
		case DW_FORM_ref_sup4:
			return readU32(c);
		case DW_FORM_ref_sup8:
			return readN(c, 8);
		case DW_FORM_sec_offset:
			return is64Bit ? readN(c, 8) : readU32(c);
		case DW_FORM_exprloc: {
			const len = readULEB128(c);
			const blockBuf = c.buf.subarray(c.pos, c.pos + len);
			c.pos += len;
			return blockBuf;
		}
		case DW_FORM_block1: {
			const len = c.buf[c.pos++];
			const blockBuf = c.buf.subarray(c.pos, c.pos + len);
			c.pos += len;
			return blockBuf;
		}
		case DW_FORM_block2: {
			const len = readU16(c);
			const blockBuf = c.buf.subarray(c.pos, c.pos + len);
			c.pos += len;
			return blockBuf;
		}
		case DW_FORM_block4: {
			const len = readU32(c);
			const blockBuf = c.buf.subarray(c.pos, c.pos + len);
			c.pos += len;
			return blockBuf;
		}
		case DW_FORM_block: {
			const len = readULEB128(c);
			const blockBuf = c.buf.subarray(c.pos, c.pos + len);
			c.pos += len;
			return blockBuf;
		}
		case DW_FORM_flag_present:
			return 1; // implicit true, consumes no data
		case DW_FORM_implicit_const:
			return implicitConst ?? 0;
		case DW_FORM_indirect: {
			const actualForm = readULEB128(c);
			return readFormValue(ctx, actualForm);
		}
		default:
			// Unknown form — can't skip safely
			return null;
	}
}

function readU16(c: BufferCursor): number {
	const v = c.buf.readUInt16LE(c.pos);
	c.pos += 2;
	return v;
}

function readU32(c: BufferCursor): number {
	const v = c.buf.readUInt32LE(c.pos);
	c.pos += 4;
	return v;
}

function readN(c: BufferCursor, n: number): number {
	if (n <= 4) {
		let v = 0;
		for (let i = 0; i < n; i++) v |= c.buf[c.pos++] << (i * 8);
		return v >>> 0;
	}
	// For 8 bytes, use BigInt then convert (loses precision above 2^53 but fine for offsets)
	const lo = c.buf.readUInt32LE(c.pos);
	const hi = c.buf.readUInt32LE(c.pos + 4);
	c.pos += 8;
	return lo + hi * 0x100000000;
}

function readCString(buf: Buffer, offset: number): string {
	if (offset >= buf.length) return '';
	let end = offset;
	while (end < buf.length && buf[end] !== 0) end++;
	return buf.subarray(offset, end).toString('utf-8');
}

// ---------------------------------------------------------------------------
// DIE representation
// ---------------------------------------------------------------------------

interface DIE {
	offset: number;      // offset within .debug_info
	tag: number;
	attrs: Map<number, number | string | Buffer>;
	children: DIE[];
}

// ---------------------------------------------------------------------------
// Core parser: walk .debug_info and build DIE trees
// ---------------------------------------------------------------------------

interface ParsedCU {
	dies: DIE[];         // top-level DIEs (with children nested)
	allDies: Map<number, DIE>; // offset → DIE for type resolution
	version: number;     // DWARF version (2/3/4/5) — affects DW_AT_high_pc semantics
}

function parseDwarfInfo(
	infoData: Buffer,
	abbrevData: Buffer,
	strData: Buffer,
	debugAddr: Buffer | null = null,
	debugStrOffsets: Buffer | null = null,
	debugLineStr: Buffer | null = null,
): ParsedCU[] {
	const cus: ParsedCU[] = [];
	const c: BufferCursor = { buf: infoData, pos: 0 };

	while (c.pos < infoData.length) {
		const cuStart = c.pos;

		// Read CU header
		let unitLength = readU32(c);
		let is64Bit = false;
		if (unitLength === 0xFFFFFFFF) {
			// 64-bit DWARF format
			unitLength = readN(c, 8);
			is64Bit = true;
		}
		const cuEnd = c.pos + unitLength;

		const version = readU16(c);

		let abbrevOffset: number;
		let addrSize: number;

		let unitType = 1; // DW_UT_compile (default for pre-DWARF 5)
		if (version >= 5) {
			unitType = c.buf[c.pos++];
			addrSize = c.buf[c.pos++];
			abbrevOffset = is64Bit ? readN(c, 8) : readU32(c);
			// DWARF 5 has extended headers for certain unit types:
			//   DW_UT_skeleton (4), DW_UT_split_compile (3): +8 bytes dwo_id
			//   DW_UT_type (2), DW_UT_split_type (6): +8 dwo_id/type_sig +4/8 type_offset
			if (unitType === 4 /* skeleton */ || unitType === 3 /* split_compile */) {
				c.pos += 8; // dwo_id
			} else if (unitType === 2 /* type */ || unitType === 6 /* split_type */) {
				c.pos += 8; // type_signature
				c.pos += is64Bit ? 8 : 4; // type_offset
			}
		} else {
			abbrevOffset = is64Bit ? readN(c, 8) : readU32(c);
			addrSize = c.buf[c.pos++];
		}

		// Parse abbreviation table for this CU
		const abbrevTable = parseAbbrevTable(abbrevData, abbrevOffset);

		const ctx: FormReadContext = {
			c,
			addrSize,
			is64Bit,
			version,
			cuOffset: cuStart,
			strData,
			// DWARF 5 split-form plumbing — bases start as -1 (unknown).
			// As soon as the CU DIE's DW_AT_addr_base / DW_AT_str_offsets_base
			// are read by the attr loop, they get promoted via the post-read
			// hook below.  Until then, strx*/addrx* resolve to empty/0 safely.
			debugAddr,
			debugStrOffsets,
			debugLineStr,
			addrBase: -1,
			strOffsetsBase: -1,
		};

		const allDies = new Map<number, DIE>();

		// Parse DIE tree recursively
		function parseDIEs(): DIE[] {
			const result: DIE[] = [];

			while (c.pos < cuEnd) {
				const dieOffset = c.pos;
				const abbrevCode = readULEB128(c);

				if (abbrevCode === 0) {
					// Null DIE — end of children list
					break;
				}

				const abbrev = abbrevTable.get(abbrevCode);
				if (!abbrev) {
					// Unknown abbrev code. On ELF ET_REL (kernel modules)
					// this indicates the debug section is still holding
					// relocation placeholders (abbrev_offset=0) because
					// .rela.debug_info hasn't been applied — our raw-bytes
					// parser can't resolve that. Graceful fallback: skip
					// this CU. .symtab path handles boundaries on the
					// common-case ET_REL workflow.
					c.pos = cuEnd;
					break;
				}

				const attrs = new Map<number, number | string | Buffer>();

				for (const attr of abbrev.attrs) {
					const value = readFormValue(ctx, attr.form, attr.implicitConst);
					if (value !== null && value !== undefined) {
						// For CU-relative refs, convert to absolute offset
						if (attr.form === DW_FORM_ref1 || attr.form === DW_FORM_ref2 ||
							attr.form === DW_FORM_ref4 || attr.form === DW_FORM_ref8 ||
							attr.form === DW_FORM_ref_udata) {
							attrs.set(attr.name, (value as number) + cuStart);
						} else {
							attrs.set(attr.name, value);
						}

						// DWARF 5: promote per-CU split-form bases as soon as
						// they're read, so subsequent strx*/addrx* values in
						// the same CU can resolve.  In well-formed DWARF these
						// attrs come early in the CU DIE (right after name/etc),
						// so the ordering works out in practice.
						if (attr.name === DW_AT_addr_base && typeof value === 'number') {
							ctx.addrBase = value;
						} else if (attr.name === DW_AT_str_offsets_base && typeof value === 'number') {
							ctx.strOffsetsBase = value;
						}
					}
				}

				const die: DIE = { offset: dieOffset, tag: abbrev.tag, attrs, children: [] };
				allDies.set(dieOffset, die);

				if (abbrev.hasChildren) {
					die.children = parseDIEs();
				}

				result.push(die);
			}

			return result;
		}

		const dies = parseDIEs();
		cus.push({ dies, allDies, version });

		// Ensure we're at the end of the CU
		c.pos = cuEnd;
	}

	return cus;
}

// ---------------------------------------------------------------------------
// Type resolver — chase DW_AT_type refs to build human-readable type strings
// ---------------------------------------------------------------------------

function resolveType(offset: number | undefined, allDies: Map<number, DIE>, depth: number = 0): string {
	if (offset === undefined || depth > 20) return 'void';

	const die = allDies.get(offset);
	if (!die) return 'void';

	const name = die.attrs.get(DW_AT_name);
	const typeRef = die.attrs.get(DW_AT_type) as number | undefined;

	switch (die.tag) {
		case DW_TAG_base_type:
			return typeof name === 'string' ? name : 'int';

		case DW_TAG_pointer_type: {
			const pointee = resolveType(typeRef, allDies, depth + 1);
			return `${pointee} *`;
		}

		case DW_TAG_const_type: {
			const base = resolveType(typeRef, allDies, depth + 1);
			return `const ${base}`;
		}

		case DW_TAG_volatile_type: {
			const base = resolveType(typeRef, allDies, depth + 1);
			return `volatile ${base}`;
		}

		case DW_TAG_restrict_type: {
			const base = resolveType(typeRef, allDies, depth + 1);
			return `restrict ${base}`;
		}

		case DW_TAG_typedef:
			return typeof name === 'string' ? name : resolveType(typeRef, allDies, depth + 1);

		case DW_TAG_structure_type:
			return typeof name === 'string' ? `struct ${name}` : 'struct <anonymous>';

		case DW_TAG_union_type:
			return typeof name === 'string' ? `union ${name}` : 'union <anonymous>';

		case DW_TAG_enumeration_type:
			return typeof name === 'string' ? `enum ${name}` : 'enum <anonymous>';

		case DW_TAG_array_type: {
			const elemType = resolveType(typeRef, allDies, depth + 1);
			// Look for DW_TAG_subrange_type child for array size
			for (const child of die.children) {
				if (child.tag === DW_TAG_subrange_type) {
					const upper = child.attrs.get(DW_AT_upper_bound) as number | undefined;
					const count = child.attrs.get(DW_AT_count) as number | undefined;
					const n = count ?? (upper !== undefined ? upper + 1 : undefined);
					if (n !== undefined) return `${elemType}[${n}]`;
				}
			}
			return `${elemType}[]`;
		}

		case DW_TAG_subroutine_type: {
			const retType = resolveType(typeRef, allDies, depth + 1);
			return `${retType} (*)()`;
		}

		default:
			return typeof name === 'string' ? name : 'void';
	}
}

/** Get the byte size of a type DIE */
function resolveTypeSize(offset: number | undefined, allDies: Map<number, DIE>, pointerSize: number, depth: number = 0): number {
	if (offset === undefined || depth > 20) return 0;

	const die = allDies.get(offset);
	if (!die) return 0;

	const byteSize = die.attrs.get(DW_AT_byte_size) as number | undefined;
	if (byteSize !== undefined) return byteSize;

	const typeRef = die.attrs.get(DW_AT_type) as number | undefined;

	switch (die.tag) {
		case DW_TAG_pointer_type:
			return pointerSize;
		case DW_TAG_typedef:
		case DW_TAG_const_type:
		case DW_TAG_volatile_type:
		case DW_TAG_restrict_type:
			return resolveTypeSize(typeRef, allDies, pointerSize, depth + 1);
		default:
			return 0;
	}
}

// ---------------------------------------------------------------------------
// Extract member location from DW_AT_data_member_location
// ---------------------------------------------------------------------------

function extractMemberOffset(value: number | string | Buffer | undefined): number {
	if (value === undefined) return 0;

	// Simple constant (DWARF 4+: DW_FORM_data1/data2/data4/udata/sdata)
	if (typeof value === 'number') return value;

	// Block expression (DWARF 2/3: DW_FORM_block1/exprloc)
	if (Buffer.isBuffer(value) && value.length > 0) {
		const op = value[0];
		if (op === DW_OP_plus_uconst) {
			// DW_OP_plus_uconst <uleb128>
			const bc: BufferCursor = { buf: value, pos: 1 };
			return readULEB128(bc);
		}
		if (op === DW_OP_constu) {
			// DW_OP_constu <uleb128> (sometimes used)
			const bc: BufferCursor = { buf: value, pos: 1 };
			return readULEB128(bc);
		}
		// Single-byte constant ops (DW_OP_lit0..DW_OP_lit31 = 0x30..0x4F)
		if (op >= 0x30 && op <= 0x4F) {
			return op - 0x30;
		}
	}

	return 0;
}

// ---------------------------------------------------------------------------
// Main extraction: DWARF DIEs → StructInfoJson
// ---------------------------------------------------------------------------

function extractStructsAndFunctions(cus: ParsedCU[], pointerSize: number): StructInfoJson {
	const structs: Record<string, StructInfo> = {};
	const functions: Record<string, FunctionSignatureInfo> = {};
	const boundaries: import('./elfBtfLoader').FunctionBoundaryInfo[] = [];
	const seenBoundaryStarts = new Set<number>();

	for (const cu of cus) {
		// DWARF 2/3: DW_AT_high_pc is always an absolute address.
		// DWARF 4+: DW_AT_high_pc CAN be a constant (offset from low_pc)
		// depending on the DW_FORM. We don't currently track forms per
		// attribute after readFormValue — version-gate is the documented
		// simplification recommended by the DWARF 5 spec itself.
		const highPcIsOffset = cu.version >= 4;

		// DWARF 5 split forms (DW_FORM_strx*/addrx* via .debug_addr and
		// .debug_str_offsets) are resolved in readFormValue using each
		// CU's DW_AT_addr_base / DW_AT_str_offsets_base promoted onto
		// FormReadContext during the attr walk.  No special handling
		// needed here — values arrive pre-resolved.

		// Collect all DIEs recursively
		function walk(dies: DIE[]): void {
			for (const die of dies) {
				// Extract struct/union layouts
				if ((die.tag === DW_TAG_structure_type || die.tag === DW_TAG_union_type) && die.children.length > 0) {
					const name = die.attrs.get(DW_AT_name);
					if (typeof name !== 'string' || !name) {
						walk(die.children);
						continue;
					}

					const byteSize = die.attrs.get(DW_AT_byte_size) as number | undefined;
					const fields: StructFieldInfo[] = [];

					for (const child of die.children) {
						if (child.tag !== DW_TAG_member) continue;

						const memberName = child.attrs.get(DW_AT_name);
						if (typeof memberName !== 'string' || !memberName) continue;

						const memberTypeRef = child.attrs.get(DW_AT_type) as number | undefined;
						const memberLocVal = child.attrs.get(DW_AT_data_member_location);
						const memberOffset = extractMemberOffset(memberLocVal);
						const memberType = resolveType(memberTypeRef, cu.allDies);
						const memberSize = resolveTypeSize(memberTypeRef, cu.allDies, pointerSize);

						fields.push({
							name: memberName,
							offset: `0x${memberOffset.toString(16).toUpperCase()}`,
							size: memberSize,
							type: memberType,
						});
					}

					if (fields.length > 0) {
						// Only overwrite if new version has more fields (handles forward decls)
						if (!structs[name] || fields.length > structs[name].fields.length) {
							structs[name] = {
								size: byteSize ?? 0,
								fields,
							};
						}
					}
				}

				// Extract function signatures (DW_TAG_subprogram)
				if (die.tag === DW_TAG_subprogram) {
					const name = die.attrs.get(DW_AT_name);
					if (typeof name !== 'string' || !name) {
						walk(die.children);
						continue;
					}

					const retTypeRef = die.attrs.get(DW_AT_type) as number | undefined;
					const returnType = resolveType(retTypeRef, cu.allDies);
					const params: FunctionParamInfo[] = [];

					let paramIdx = 0;
					for (const child of die.children) {
						if (child.tag === DW_TAG_formal_parameter) {
							const paramName = child.attrs.get(DW_AT_name);
							const paramTypeRef = child.attrs.get(DW_AT_type) as number | undefined;
							const paramType = resolveType(paramTypeRef, cu.allDies);

							const info: FunctionParamInfo = {
								index: paramIdx,
								name: typeof paramName === 'string' ? paramName : `param_${paramIdx}`,
								type: paramType,
							};

							// Detect struct pointer params for disambiguation
							const ptrMatch = paramType.match(/^(?:const\s+)?struct\s+(\w+)\s*\*$/);
							if (ptrMatch) {
								info.structName = ptrMatch[1];
							}

							params.push(info);
							paramIdx++;
						}
						// Skip DW_TAG_unspecified_parameters (variadic ...)
					}

					// Only store if we got at least the name (params may be empty for void f(void))
					if (!functions[name] || params.length > (functions[name].params?.length ?? 0)) {
						functions[name] = { returnType, params };
					}

					// Extract function boundary (low_pc/high_pc) for Pathfinder CFG feeder.
					// Only record subprograms with BOTH low_pc and high_pc. Inline
					// subprograms and declaration-only DIEs may have one or neither.
					const lowPc = die.attrs.get(DW_AT_low_pc);
					const highPcVal = die.attrs.get(DW_AT_high_pc);
					if (typeof lowPc === 'number' && lowPc !== 0 && typeof highPcVal === 'number') {
						const highPc = highPcIsOffset ? lowPc + highPcVal : highPcVal;
						// Skip degenerate entries (end <= start).
						if (highPc > lowPc && !seenBoundaryStarts.has(lowPc)) {
							boundaries.push({ name, lowPc, highPc });
							seenBoundaryStarts.add(lowPc);
						}
					}
				}

				// Recurse into children for nested types
				walk(die.children);
			}
		}

		walk(cu.dies);
	}

	return boundaries.length > 0
		? { structs, functions, boundaries }
		: { structs, functions };
}

// ---------------------------------------------------------------------------
// ELF section extraction (reads .debug_info, .debug_abbrev, .debug_str)
// ---------------------------------------------------------------------------

interface ElfSections {
	debugInfo: Buffer | null;
	debugAbbrev: Buffer | null;
	debugStr: Buffer | null;
	debugAddr: Buffer | null;        // DWARF 5 — indexed addresses
	debugStrOffsets: Buffer | null;  // DWARF 5 — indexed string offsets
	debugLineStr: Buffer | null;     // DWARF 5 — line table string pool
	is64Bit: boolean;
}

/** ELF RELA entry (x86_64 relocation with explicit addend). */
interface RelaEntry {
	offset: number;
	symbolIndex: number;
	type: number;
	addend: number;
}

/** ELF symbol table entry. */
interface SymbolEntry {
	nameOff: number;
	info: number;
	other: number;
	shndx: number;
	value: number;
	size: number;
}

/** Apply x86_64 RELA-style relocations to a debug section buffer in-place.
 * Kernel modules (ELF ET_REL) ship debug sections with cross-section
 * references (e.g. `.debug_info` → `.debug_abbrev` offset) held as
 * placeholders resolved at load time via `.rela.debug_*` entries. The
 * plain bytes always read as 0 until relocated. `llvm-dwarfdump` applies
 * these transparently; our in-TS parser did not, which caused every CU
 * past CU0 to see abbrev_offset=0 and fail to parse any DIEs. */
function applyX86_64Relocations(
	target: Buffer,
	relas: RelaEntry[],
	symbols: SymbolEntry[],
): void {
	// x86_64 relocation types we handle for debug sections.  Other types
	// (PLT32, GOTPCREL, etc.) don't appear in debug section relocations.
	const R_X86_64_NONE = 0;
	const R_X86_64_64 = 1;
	const R_X86_64_32 = 10;
	const R_X86_64_32S = 11;

	for (const r of relas) {
		if (r.type === R_X86_64_NONE) { continue; }
		const sym = symbols[r.symbolIndex];
		if (!sym) { continue; }
		const value = sym.value + r.addend;

		if (r.type === R_X86_64_64) {
			if (r.offset + 8 > target.length) { continue; }
			// Write as little-endian 64-bit. Node's writeBigInt64LE requires bigint.
			target.writeBigUInt64LE(BigInt.asUintN(64, BigInt(value)), r.offset);
		} else if (r.type === R_X86_64_32 || r.type === R_X86_64_32S) {
			if (r.offset + 4 > target.length) { continue; }
			target.writeUInt32LE(value >>> 0, r.offset);
		}
		// Other types (PC32, GOT*, etc.) intentionally ignored for debug.
	}
}

function extractDwarfSections(filePath: string): ElfSections {
	const fd = fs.openSync(filePath, 'r');
	const result: ElfSections = {
		debugInfo: null, debugAbbrev: null, debugStr: null,
		debugAddr: null, debugStrOffsets: null, debugLineStr: null,
		is64Bit: false,
	};

	try {
		const headerBuf = Buffer.alloc(64);
		fs.readSync(fd, headerBuf, 0, 64, 0);

		// Check ELF magic
		if (headerBuf[0] !== 0x7F || headerBuf[1] !== 0x45 || headerBuf[2] !== 0x4C || headerBuf[3] !== 0x46) {
			return result;
		}

		const elfClass = headerBuf[4]; // 1=32-bit, 2=64-bit
		const is64Bit = elfClass === 2;
		result.is64Bit = is64Bit;

		// ET_REL check: e_type at offset 16 (2 bytes).  1 = ET_REL.
		const eType = headerBuf.readUInt16LE(16);
		const isRelocatable = eType === 1;

		// Parse ELF header
		let e_shoff: number, e_shentsize: number, e_shnum: number, e_shstrndx: number;
		if (is64Bit) {
			e_shoff = Number(headerBuf.readBigUInt64LE(40));
			e_shentsize = headerBuf.readUInt16LE(58);
			e_shnum = headerBuf.readUInt16LE(60);
			e_shstrndx = headerBuf.readUInt16LE(62);
		} else {
			e_shoff = headerBuf.readUInt32LE(32);
			e_shentsize = headerBuf.readUInt16LE(46);
			e_shnum = headerBuf.readUInt16LE(48);
			e_shstrndx = headerBuf.readUInt16LE(50);
		}

		// Read section header string table
		const shstrEntry = Buffer.alloc(is64Bit ? 64 : 40);
		fs.readSync(fd, shstrEntry, 0, shstrEntry.length, e_shoff + e_shstrndx * e_shentsize);
		const shstrAddr = is64Bit ? Number(shstrEntry.readBigUInt64LE(24)) : shstrEntry.readUInt32LE(16);
		const shstrSize = is64Bit ? Number(shstrEntry.readBigUInt64LE(32)) : shstrEntry.readUInt32LE(20);
		const strTable = Buffer.alloc(shstrSize);
		fs.readSync(fd, strTable, 0, shstrSize, shstrAddr);

		// First pass: collect ALL section metadata so we can cross-reference
		// .rela.X → X mappings via sh_info, and .rela's symbol table via sh_link.
		interface SecMeta {
			name: string;
			type: number;
			link: number;
			info: number;
			addr: number;
			size: number;
			entsize: number;
		}
		const sections: SecMeta[] = [];
		for (let i = 0; i < e_shnum; i++) {
			const shEntry = Buffer.alloc(is64Bit ? 64 : 40);
			fs.readSync(fd, shEntry, 0, shEntry.length, e_shoff + i * e_shentsize);
			const nameOff = shEntry.readUInt32LE(0);
			let sectionName = '';
			for (let j = nameOff; j < strTable.length && strTable[j] !== 0; j++) {
				sectionName += String.fromCharCode(strTable[j]);
			}
			const type = shEntry.readUInt32LE(4);
			let link: number, info: number, addr: number, size: number, entsize: number;
			if (is64Bit) {
				addr = Number(shEntry.readBigUInt64LE(24));
				size = Number(shEntry.readBigUInt64LE(32));
				link = shEntry.readUInt32LE(40);
				info = shEntry.readUInt32LE(44);
				entsize = Number(shEntry.readBigUInt64LE(56));
			} else {
				addr = shEntry.readUInt32LE(16);
				size = shEntry.readUInt32LE(20);
				link = shEntry.readUInt32LE(24);
				info = shEntry.readUInt32LE(28);
				entsize = shEntry.readUInt32LE(36);
			}
			sections.push({ name: sectionName, type, link, info, addr, size, entsize });
		}

		const debugTargets = new Map<string, 'debugInfo' | 'debugAbbrev' | 'debugStr' | 'debugAddr' | 'debugStrOffsets' | 'debugLineStr'>([
			['.debug_info', 'debugInfo'],
			['.debug_abbrev', 'debugAbbrev'],
			['.debug_str', 'debugStr'],
			['.debug_addr', 'debugAddr'],
			['.debug_str_offsets', 'debugStrOffsets'],
			['.debug_line_str', 'debugLineStr'],
		]);

		// Second pass: load debug section contents.
		for (let i = 0; i < sections.length; i++) {
			const s = sections[i];
			const key = debugTargets.get(s.name);
			if (key) {
				const data = Buffer.alloc(s.size);
				fs.readSync(fd, data, 0, s.size, s.addr);
				result[key] = data;
			}
		}

		// ET_REL relocation application.  Debug sections on kernel modules
		// carry cross-section references as 0-placeholders until the linker
		// applies RELA entries.  We reproduce that here so our raw-bytes
		// parser reads the same values llvm-dwarfdump would show.
		if (isRelocatable && is64Bit) {
			// Build a symbol table cache (first .symtab wins — ET_REL usually
			// has exactly one).
			let symbols: SymbolEntry[] | null = null;
			for (let i = 0; i < sections.length; i++) {
				const s = sections[i];
				// SHT_SYMTAB = 2
				if (s.type === 2 && s.entsize > 0) {
					const rawSyms = Buffer.alloc(s.size);
					fs.readSync(fd, rawSyms, 0, s.size, s.addr);
					const count = s.size / s.entsize;
					symbols = new Array(count);
					for (let k = 0; k < count; k++) {
						const off = k * s.entsize;
						// ELF64 symbol layout: name(4) info(1) other(1) shndx(2) value(8) size(8)
						symbols[k] = {
							nameOff: rawSyms.readUInt32LE(off),
							info: rawSyms[off + 4],
							other: rawSyms[off + 5],
							shndx: rawSyms.readUInt16LE(off + 6),
							value: Number(rawSyms.readBigUInt64LE(off + 8)),
							size: Number(rawSyms.readBigUInt64LE(off + 16)),
						};
					}
					break;
				}
			}

			if (symbols) {
				// For each .rela section targeting a debug section we loaded,
				// apply its entries.
				for (let i = 0; i < sections.length; i++) {
					const s = sections[i];
					// SHT_RELA = 4.  sh_info is target section index.
					if (s.type !== 4 || s.entsize === 0) { continue; }
					const targetSec = sections[s.info];
					if (!targetSec) { continue; }
					const debugKey = debugTargets.get(targetSec.name);
					if (!debugKey) { continue; }  // not a debug section
					const targetBuf = result[debugKey];
					if (!targetBuf) { continue; }

					const rawRelas = Buffer.alloc(s.size);
					fs.readSync(fd, rawRelas, 0, s.size, s.addr);
					const count = s.size / s.entsize;
					const relas: RelaEntry[] = new Array(count);
					for (let k = 0; k < count; k++) {
						const off = k * s.entsize;
						// ELF64 RELA: offset(8) info(8) addend(8 signed)
						const offset = Number(rawRelas.readBigUInt64LE(off));
						const info = rawRelas.readBigUInt64LE(off + 8);
						const addendRaw = rawRelas.readBigInt64LE(off + 16);
						relas[k] = {
							offset,
							symbolIndex: Number(info >> 32n),
							type: Number(info & 0xFFFFFFFFn),
							addend: Number(addendRaw),
						};
					}
					applyX86_64Relocations(targetBuf, relas, symbols);
				}
			}
		}
	} finally {
		fs.closeSync(fd);
	}

	return result;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load DWARF debug info from an ELF file and extract struct layouts + function signatures.
 *
 * Produces the same StructInfoJson format as the BTF loader, so the
 * structFieldPostProcessor can consume it identically.
 *
 * @param filePath Path to the ELF file (.ko, vmlinux, etc.)
 * @returns StructInfoJson or null if no DWARF data found
 */
export async function loadDwarfStructInfo(filePath: string): Promise<StructInfoJson | null> {
	try {
		const sections = extractDwarfSections(filePath);

		if (!sections.debugInfo || !sections.debugAbbrev) {
			return null; // No DWARF data
		}

		const strData = sections.debugStr ?? Buffer.alloc(0);
		const pointerSize = sections.is64Bit ? 8 : 4;

		const cus = parseDwarfInfo(
			sections.debugInfo,
			sections.debugAbbrev,
			strData,
			sections.debugAddr,
			sections.debugStrOffsets,
			sections.debugLineStr,
		);
		if (cus.length === 0) return null;

		const result = extractStructsAndFunctions(cus, pointerSize);

		// Only return if we actually found something useful
		if (Object.keys(result.structs).length === 0 && Object.keys(result.functions).length === 0) {
			return null;
		}

		return result;
	} catch (error) {
		console.error(`Error loading DWARF from ${filePath}:`, error);
		return null;
	}
}

/**
 * Get struct info for a specific function from DWARF data.
 * Returns only the structs referenced by the function's parameters.
 */
export async function getDwarfStructInfoForFunction(
	filePath: string,
	functionName: string,
): Promise<StructInfoJson | null> {
	const full = await loadDwarfStructInfo(filePath);
	if (!full) return null;

	const funcSig = full.functions[functionName];
	if (!funcSig) return null;

	// Collect only referenced structs
	const relevantStructs: Record<string, StructInfo> = {};
	for (const param of funcSig.params) {
		if (param.structName && full.structs[param.structName]) {
			relevantStructs[param.structName] = full.structs[param.structName];

			// One level of nested structs
			for (const field of full.structs[param.structName].fields) {
				const nestedMatch = field.type.match(/^struct\s+(\w+)$/);
				if (nestedMatch && full.structs[nestedMatch[1]]) {
					relevantStructs[nestedMatch[1]] = full.structs[nestedMatch[1]];
				}
			}
		}
	}

	return {
		structs: relevantStructs,
		functions: { [functionName]: funcSig },
	};
}

/**
 * Quick check: does this ELF file have DWARF debug sections?
 * Cheaper than a full parse — just checks for section headers.
 */
export function hasDwarfSections(filePath: string): boolean {
	try {
		const fd = fs.openSync(filePath, 'r');
		try {
			const headerBuf = Buffer.alloc(64);
			fs.readSync(fd, headerBuf, 0, 64, 0);

			if (headerBuf[0] !== 0x7F || headerBuf[1] !== 0x45 || headerBuf[2] !== 0x4C || headerBuf[3] !== 0x46) {
				return false;
			}

			const is64Bit = headerBuf[4] === 2;
			let e_shoff: number, e_shentsize: number, e_shnum: number, e_shstrndx: number;
			if (is64Bit) {
				e_shoff = Number(headerBuf.readBigUInt64LE(40));
				e_shentsize = headerBuf.readUInt16LE(58);
				e_shnum = headerBuf.readUInt16LE(60);
				e_shstrndx = headerBuf.readUInt16LE(62);
			} else {
				e_shoff = headerBuf.readUInt32LE(32);
				e_shentsize = headerBuf.readUInt16LE(46);
				e_shnum = headerBuf.readUInt16LE(48);
				e_shstrndx = headerBuf.readUInt16LE(50);
			}

			const shstrEntry = Buffer.alloc(is64Bit ? 64 : 40);
			fs.readSync(fd, shstrEntry, 0, shstrEntry.length, e_shoff + e_shstrndx * e_shentsize);
			const shstrAddr = is64Bit ? Number(shstrEntry.readBigUInt64LE(24)) : shstrEntry.readUInt32LE(16);
			const shstrSize = is64Bit ? Number(shstrEntry.readBigUInt64LE(32)) : shstrEntry.readUInt32LE(20);
			const strTable = Buffer.alloc(shstrSize);
			fs.readSync(fd, strTable, 0, shstrSize, shstrAddr);

			for (let i = 0; i < e_shnum; i++) {
				const shEntry = Buffer.alloc(is64Bit ? 64 : 40);
				fs.readSync(fd, shEntry, 0, shEntry.length, e_shoff + i * e_shentsize);
				const nameOff = shEntry.readUInt32LE(0);

				let sectionName = '';
				for (let j = nameOff; j < strTable.length && strTable[j] !== 0; j++) {
					sectionName += String.fromCharCode(strTable[j]);
				}

				if (sectionName === '.debug_info') return true;
			}

			return false;
		} finally {
			fs.closeSync(fd);
		}
	} catch {
		return false;
	}
}
