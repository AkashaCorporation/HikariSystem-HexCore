export interface MappedRegionLike {
	address: bigint;
	size: bigint | number;
	permissions: string;
}

export interface NamedAllocationLike {
	address: bigint;
	size: number;
	name?: string;
}

export interface MergedMemoryRegion {
	address: bigint;
	size: number;
	permissions: string;
	name?: string;
}

/**
 * Keep Unicorn's memory map authoritative and enrich exact mapped regions with
 * allocator names. The allocator tracks heap/fault allocations only; using it
 * as the complete region list hides the loaded image and stack from headless
 * state artifacts.
 */
export function mergeMappedMemoryRegions(
	mappedRegions: readonly MappedRegionLike[],
	allocations: readonly NamedAllocationLike[]
): MergedMemoryRegion[] {
	return mappedRegions
		.map(region => {
			const size = Number(region.size);
			const exact = allocations.find(allocation =>
				allocation.address === region.address && allocation.size === size
			);
			const merged: MergedMemoryRegion = {
				address: region.address,
				size,
				permissions: region.permissions
			};
			if (exact?.name) {
				merged.name = exact.name;
			}
			return merged;
		})
		.sort((left, right) => left.address < right.address ? -1 : left.address > right.address ? 1 : 0);
}
