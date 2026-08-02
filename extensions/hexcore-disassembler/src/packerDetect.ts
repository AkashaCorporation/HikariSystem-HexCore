/*---------------------------------------------------------------------------------------------
 * Packer / UPX detection (issue #55)
 *
 * Pure (no vscode). Used by:
 *   - computeAnalyzeAllCapabilities (capability string 'packed' / 'packed:upx')
 *   - headless hexcore.disasm.detectPacker
 *
 * Detect only (MIT). No spawn of external `upx`, no PATH dependency, no GPL
 * bundling — same product rule as keeping Unicorn out of the MIT core.
 * Unpacking is future/optional product work (own engine), not this module.
 *
 * Goal: jobs-only CTF flow must *know* the binary is packed before decompile
 * on a 0-function UPX stub burns confidence and agent time.
 *---------------------------------------------------------------------------------------------*/

export type PackerFamily =
	| 'upx'
	| 'themida'
	| 'vmprotect'
	| 'aspack'
	| 'enigma'
	| 'mpress'
	| 'unknown'
	| 'none';

export interface PackerMarker {
	kind: 'magic' | 'section' | 'string' | 'overlay';
	detail: string;
	/** File offset when known (byte index into raw buffer) */
	offset?: number;
}

export interface PackerDetectResult {
	packed: boolean;
	/** Best-effort primary family */
	family: PackerFamily;
	/** 0–100 */
	confidence: number;
	markers: PackerMarker[];
	/** All families with any signal */
	families: PackerFamily[];
	/** Human / agent next step */
	recommendation: string;
	/** True when UPX markers look versioned (banner string) */
	upxVersionHint?: string;
}

export interface PackerSectionLike {
	name: string;
	isCode?: boolean;
	rawSize?: number;
	virtualSize?: number;
}

export interface PackerStringLike {
	string?: string;
	value?: string;
	text?: string;
}

const UPX_MAGIC = Buffer.from('UPX!');

/**
 * Detect packers from raw file bytes + optional section/string tables.
 * Safe on empty buffers; does not throw.
 */
export function detectPacker(
	fileBytes: Buffer | Uint8Array | undefined,
	opts?: {
		sections?: ReadonlyArray<PackerSectionLike>;
		strings?: ReadonlyArray<PackerStringLike>;
	},
): PackerDetectResult {
	const buf = fileBytes
		? (Buffer.isBuffer(fileBytes) ? fileBytes : Buffer.from(fileBytes))
		: Buffer.alloc(0);
	const markers: PackerMarker[] = [];
	const familyHits = new Set<PackerFamily>();

	// ── magic / banner in raw bytes ─────────────────────────────────────
	if (buf.length >= 4) {
		let idx = 0;
		while (idx < buf.length) {
			const at = buf.indexOf(UPX_MAGIC, idx);
			if (at < 0) { break; }
			markers.push({ kind: 'magic', detail: 'UPX! magic', offset: at });
			familyHits.add('upx');
			idx = at + 4;
			if (markers.filter(m => m.kind === 'magic').length >= 8) { break; } // enough
		}
		// Common UPX info string (also appears in ransom HTB)
		const info = buf.indexOf(Buffer.from('packed with the UPX'));
		if (info >= 0) {
			markers.push({ kind: 'string', detail: 'UPX banner: packed with the UPX', offset: info });
			familyHits.add('upx');
		}
		const id = scanAscii(buf, /\$Id:\s*UPX\s+([\d.]+)/i);
		if (id) {
			markers.push({ kind: 'string', detail: `UPX Id banner version ${id.match}`, offset: id.offset });
			familyHits.add('upx');
		}
	}

	// ── PE/ELF section names ────────────────────────────────────────────
	for (const s of opts?.sections ?? []) {
		const n = s.name || '';
		if (/upx/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('upx');
		}
		if (/\.themida|themida/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('themida');
		}
		if (/\.vmp|vmp/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('vmprotect');
		}
		if (/\.aspack|aspack/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('aspack');
		}
		if (/\.enigma|enigma/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('enigma');
		}
		if (/\.mpress|mpress/i.test(n)) {
			markers.push({ kind: 'section', detail: `section name "${n}"` });
			familyHits.add('mpress');
		}
		// BSS-like packer stub: code section with zero raw, large virtual
		if (s.isCode && (s.rawSize ?? 0) === 0 && (s.virtualSize ?? 0) > 0x1000) {
			markers.push({
				kind: 'section',
				detail: `code section "${n}" rawSize=0 virtualSize=${s.virtualSize} (stub/packer heuristic)`,
			});
			familyHits.add('unknown');
		}
	}

	// ── engine string table ─────────────────────────────────────────────
	for (const s of opts?.strings ?? []) {
		const text = s.string || s.value || s.text || '';
		if (!text) { continue; }
		if (/UPX!|packed with the UPX|\$Id:\s*UPX/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('upx');
		}
		if (/\bthemida\b/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('themida');
		}
		if (/vmprotect/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('vmprotect');
		}
		if (/\baspack\b/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('aspack');
		}
		if (/enigma protector/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('enigma');
		}
		if (/\bmpress\b/i.test(text)) {
			markers.push({ kind: 'string', detail: clip(text, 80) });
			familyHits.add('mpress');
		}
	}

	// Dedupe markers by detail
	const seen = new Set<string>();
	const uniqMarkers = markers.filter(m => {
		const k = `${m.kind}|${m.detail}|${m.offset ?? ''}`;
		if (seen.has(k)) { return false; }
		seen.add(k);
		return true;
	});

	const families = [...familyHits].filter(f => f !== 'none') as PackerFamily[];
	const packed = families.length > 0 && !(families.length === 1 && families[0] === 'unknown' && uniqMarkers.length === 0);
	// unknown-only from rawSize=0 heuristic still counts as packed if we have that marker
	const reallyPacked = uniqMarkers.length > 0;

	let family: PackerFamily = 'none';
	if (reallyPacked) {
		if (familyHits.has('upx')) { family = 'upx'; }
		else if (familyHits.has('themida')) { family = 'themida'; }
		else if (familyHits.has('vmprotect')) { family = 'vmprotect'; }
		else if (familyHits.has('aspack')) { family = 'aspack'; }
		else if (familyHits.has('enigma')) { family = 'enigma'; }
		else if (familyHits.has('mpress')) { family = 'mpress'; }
		else { family = 'unknown'; }
	}

	let confidence = 0;
	if (reallyPacked) {
		const magicHits = uniqMarkers.filter(m => m.kind === 'magic').length;
		const stringHits = uniqMarkers.filter(m => m.kind === 'string').length;
		const sectionHits = uniqMarkers.filter(m => m.kind === 'section').length;
		confidence = Math.min(100, 40 + magicHits * 20 + stringHits * 15 + sectionHits * 15);
		if (family === 'upx' && magicHits > 0) { confidence = Math.max(confidence, 85); }
		if (family === 'upx' && magicHits > 0 && stringHits > 0) { confidence = Math.max(confidence, 95); }
	}

	const upxVer = uniqMarkers
		.map(m => m.detail.match(/UPX\s+([\d.]+)/i)?.[1])
		.find(Boolean);

	let recommendation = 'No packer markers found; proceed with analyzeAll / decompile.';
	if (reallyPacked && family === 'upx') {
		recommendation =
			'UPX-packed: do NOT decompile entry / trust analyzeAll on this image (often 0 real functions). ' +
			'Unpack offline, then re-run analyzeAll / helix on the unpacked file. ' +
			'HexCore does not ship or invoke external UPX (MIT core).';
	} else if (reallyPacked) {
		recommendation =
			`Packer signals (${family}): unpack with family-specific tooling before deep decompile. ` +
			'analyzeAll may report 0 real functions. HexCore detect-only — no external unpacker PATH.';
	}

	return {
		packed: reallyPacked,
		family,
		confidence,
		markers: uniqMarkers,
		families: reallyPacked ? (families.length ? families : [family]) : [],
		recommendation,
		upxVersionHint: upxVer,
	};
}

/**
 * Capability tags for analyzeAll JSON (backward compatible).
 * Always includes legacy `packed` when any packer signal; adds `packed:upx` for UPX.
 */
export function packerCapabilityTags(detect: PackerDetectResult): string[] {
	if (!detect.packed) { return []; }
	const tags = ['packed'];
	if (detect.family === 'upx' || detect.families.includes('upx')) {
		tags.push('packed:upx');
	}
	return tags;
}

function clip(s: string, n: number): string {
	const t = s.replace(/\s+/g, ' ').trim();
	return t.length <= n ? t : t.slice(0, n - 1) + '…';
}

function scanAscii(buf: Buffer, re: RegExp): { match: string; offset: number } | undefined {
	// Scan in chunks to avoid huge string alloc on multi-MB files
	const step = 256 * 1024;
	for (let off = 0; off < buf.length; off += step) {
		const slice = buf.subarray(off, Math.min(buf.length, off + step + 64));
		const text = slice.toString('latin1');
		const m = text.match(re);
		if (m && m.index !== undefined) {
			return { match: m[1] || m[0], offset: off + m.index };
		}
	}
	return undefined;
}
