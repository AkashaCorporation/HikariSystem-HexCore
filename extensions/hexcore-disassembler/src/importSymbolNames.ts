/*---------------------------------------------------------------------------------------------
 * Import / PLT call-target naming for Helix Pseudo-C (issue #52, option a)
 *
 * Helix emits every call target as sub_<va> / g_<va>. The disassembler already
 * knows import GOT-slot VAs and ELF `<sym>@plt` names. This pure post-process
 * rewrites ONLY tokens whose full 64-bit VA is in the map — local helpers and
 * unknown addresses stay as sub_/g_.
 *---------------------------------------------------------------------------------------------*/

export interface NamedAddress {
	address: number;
	name: string;
}

/**
 * Build addr→cleanName from engine function + import lists.
 * Skips anonymous `sub_*` function names. Strips `@plt` and GLIBC `@@` tags.
 */
export function buildImportSymbolMap(
	functions: ReadonlyArray<{ address: number; name?: string }>,
	imports: ReadonlyArray<{ functions?: ReadonlyArray<{ address: number; name?: string }> }>,
): Map<number, string> {
	const symMap = new Map<number, string>();
	const cleanSym = (s: string): string => s
		.replace(/@plt$/i, '')
		.replace(/@@.*$/, '')
		.replace(/[^A-Za-z0-9_]/g, '_');

	for (const f of functions) {
		if (!f.name || typeof f.address !== 'number') { continue; }
		if (/^sub_[0-9a-fA-F]+$/i.test(f.name)) { continue; }
		symMap.set(f.address, cleanSym(f.name));
	}
	for (const lib of imports) {
		for (const fn of lib.functions ?? []) {
			if (!fn.name || !fn.address) { continue; }
			symMap.set(fn.address, cleanSym(fn.name));
		}
	}
	return symMap;
}

/**
 * Rewrite `sub_<hex>` / `g_<hex>` tokens in Helix C when the VA is in the map.
 * Conservative: full-token match only; never rewrites partial identifiers.
 */
export function applyImportSymbolNamesToSource(
	source: string,
	symMap: Map<number, string>,
): { source: string; renamed: number } {
	if (!source || symMap.size === 0) {
		return { source, renamed: 0 };
	}
	let renamed = 0;
	const out = source.replace(/\b(?:sub|g)_([0-9a-fA-F]{4,})\b/g, (tok, hex: string) => {
		const name = symMap.get(Number.parseInt(hex, 16));
		if (!name) {
			return tok;
		}
		renamed++;
		return name;
	});
	return { source: out, renamed };
}
