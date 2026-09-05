/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export interface PeSectionMappingShape {
	name: string;
	virtualAddress: number;
	virtualSize: number;
	rawAddress: number;
	rawSize: number;
}

export interface AddressMapping {
	address: number;
	rva: number;
	fileOffset?: number;
	availableBytes?: number;
	section?: string;
	source: 'file-header' | 'file-section' | 'virtual-zero-fill' | 'unmapped';
	valid: boolean;
	reason?: string;
}

/** Resolve a PE RVA only when the requested byte is physically backed by the file. */
export function resolvePeRvaMapping(
	rva: number,
	baseAddress: number,
	sections: readonly PeSectionMappingShape[],
	fileSize: number,
): AddressMapping {
	const address = baseAddress + rva;
	if (!Number.isSafeInteger(rva) || rva < 0) {
		return { address, rva, source: 'unmapped', valid: false, reason: 'Address is below the PE image base.' };
	}

	for (const section of sections) {
		const sectionRva = section.virtualAddress - baseAddress;
		const delta = rva - sectionRva;
		if (delta < 0) { continue; }
		if (delta < section.rawSize) {
			const fileOffset = section.rawAddress + delta;
			if (fileOffset >= 0 && fileOffset < fileSize) {
				return {
					address, rva, fileOffset,
					availableBytes: Math.min(section.rawSize - delta, fileSize - fileOffset),
					section: section.name, source: 'file-section', valid: true
				};
			}
			return {
				address, rva, fileOffset, section: section.name, source: 'unmapped', valid: false,
				reason: 'The section mapping points beyond the available file bytes.'
			};
		}
		if (delta < section.virtualSize) {
			return {
				address, rva, section: section.name, source: 'virtual-zero-fill', valid: false,
				reason: 'The address is virtual zero-fill and has no file-backed byte.'
			};
		}
	}

	const firstSectionRaw = sections
		.map(section => section.rawAddress)
		.filter(offset => offset > 0)
		.reduce((minimum, offset) => Math.min(minimum, offset), fileSize);
	if (rva < Math.min(firstSectionRaw, fileSize)) {
		return {
			address, rva, fileOffset: rva,
			availableBytes: Math.min(firstSectionRaw, fileSize) - rva,
			source: 'file-header', valid: true
		};
	}

	return { address, rva, source: 'unmapped', valid: false, reason: 'The RVA is not backed by a PE header or section.' };
}
