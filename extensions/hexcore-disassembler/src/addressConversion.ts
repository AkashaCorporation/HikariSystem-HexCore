/*---------------------------------------------------------------------------------------------
 *  Copyright (c) HikariSystem. All rights reserved.
 *  Licensed under the MIT License.
 *--------------------------------------------------------------------------------------------*/

/**
 * Convert a virtual address to a file offset by subtracting the base address.
 *
 * @param address - The virtual address in the binary's address space
 * @param baseAddress - The base address (image base) of the loaded binary
 * @returns The corresponding file offset
 */
export function addressToOffset(address: number, baseAddress: number): number {
	return address - baseAddress;
}

/**
 * Convert a file offset to a virtual address by adding the base address.
 *
 * @param offset - The file offset within the binary
 * @param baseAddress - The base address (image base) of the loaded binary
 * @returns The corresponding virtual address
 */
export function offsetToAddress(offset: number, baseAddress: number): number {
	return offset + baseAddress;
}
