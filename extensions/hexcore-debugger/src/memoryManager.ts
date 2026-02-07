/*---------------------------------------------------------------------------------------------
 *  HexCore Debugger - Memory Manager
 *  Page fault handler and heap management for emulation
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

export interface Allocation {
	address: bigint;
	size: number;
	permissions: number;
	name?: string;
}

export interface HeapBlock {
	address: bigint;
	size: number;
	free: boolean;
}

// Permission constants matching Unicorn PROT_*
const PROT_READ = 1;
const PROT_WRITE = 2;
const PROT_EXEC = 4;
const PROT_ALL = 7;

export class MemoryManager {
	private allocations: Map<bigint, Allocation> = new Map();
	private heapBase: bigint;
	private heapCurrent: bigint;
	private heapLimit: bigint;
	private heapBlocks: HeapBlock[] = [];
	private pageSize: number;
	private nextVirtualAllocBase: bigint = 0x10000000n;

	// Callback to actually map memory in the emulator
	private mapCallback: (address: bigint, size: number, perms: number) => void;

	constructor(
		mapCallback: (address: bigint, size: number, perms: number) => void,
		pageSize: number = 0x1000
	) {
		this.mapCallback = mapCallback;
		this.pageSize = pageSize;
		this.heapBase = 0x05000000n;
		this.heapCurrent = this.heapBase;
		this.heapLimit = this.heapBase + 0x01000000n; // 16MB heap
	}

	/**
	 * Initialize the default heap region
	 */
	initializeHeap(): void {
		const heapSize = Number(this.heapLimit - this.heapBase);
		this.mapCallback(this.heapBase, heapSize, PROT_READ | PROT_WRITE);
		this.trackAllocation(this.heapBase, heapSize, PROT_READ | PROT_WRITE, 'heap');
	}

	/**
	 * Handle page fault - auto-allocate unmapped memory
	 * Returns true if the fault was handled, false to let it crash
	 */
	handlePageFault(address: bigint, size: number, _accessType: number): boolean {
		const alignedAddr = this.alignDown(address);
		const alignedSize = this.alignUp(size + Number(address - alignedAddr));

		// Don't auto-allocate in suspicious regions (NULL page, very high addresses)
		if (address < 0x1000n) {
			return false;
		}
		if (address > 0x00007FFFFFFFFFFFn) {
			return false;
		}

		// Check if this overlaps with an existing allocation
		if (this.isAllocated(alignedAddr, alignedSize)) {
			return false;
		}

		try {
			this.mapCallback(alignedAddr, alignedSize, PROT_ALL);
			this.trackAllocation(alignedAddr, alignedSize, PROT_ALL, 'fault-mapped');
			return true;
		} catch {
			return false;
		}
	}

	/**
	 * VirtualAlloc emulation
	 */
	virtualAlloc(requestedAddress: bigint, size: number, _allocType: number, protect: number): bigint {
		const alignedSize = this.alignUp(size);
		let address: bigint;

		if (requestedAddress !== 0n) {
			address = this.alignDown(requestedAddress);
		} else {
			address = this.nextVirtualAllocBase;
			this.nextVirtualAllocBase += BigInt(alignedSize) + BigInt(this.pageSize);
		}

		const ucProtect = this.windowsProtToUnicorn(protect);

		// Check for overlap with existing allocations
		if (this.isAllocated(address, alignedSize)) {
			// MEM_COMMIT on already-reserved region: just change permissions
			return address;
		}

		try {
			this.mapCallback(address, alignedSize, ucProtect);
			this.trackAllocation(address, alignedSize, ucProtect, 'VirtualAlloc');
			return address;
		} catch {
			return 0n;
		}
	}

	/**
	 * VirtualFree emulation
	 */
	virtualFree(address: bigint, _size: number, _freeType: number): boolean {
		// We can't unmap from Unicorn easily, just mark as freed
		this.allocations.delete(address);
		return true;
	}

	/**
	 * VirtualProtect emulation
	 */
	virtualProtect(address: bigint, size: number, newProtect: number): { success: boolean; oldProtect: number } {
		const alloc = this.findAllocation(address);
		const oldProtect = alloc ? this.unicornProtToWindows(alloc.permissions) : 0x04; // PAGE_READWRITE
		// Note: Unicorn's memProtect would be called by the caller
		return { success: true, oldProtect };
	}

	/**
	 * HeapAlloc emulation
	 */
	heapAlloc(size: number, zeroMemory: boolean): bigint {
		// Find a free block that fits
		for (const block of this.heapBlocks) {
			if (block.free && block.size >= size) {
				block.free = false;
				return block.address;
			}
		}

		// Allocate from the heap bump allocator
		const aligned = this.alignUp(size < 16 ? 16 : size);
		if (this.heapCurrent + BigInt(aligned) > this.heapLimit) {
			return 0n; // Out of heap space
		}

		const address = this.heapCurrent;
		this.heapCurrent += BigInt(aligned);
		this.heapBlocks.push({ address, size: aligned, free: false });

		return address;
	}

	/**
	 * HeapFree emulation
	 */
	heapFree(address: bigint): boolean {
		for (const block of this.heapBlocks) {
			if (block.address === address && !block.free) {
				block.free = true;
				return true;
			}
		}
		return false;
	}

	/**
	 * Track an allocation
	 */
	trackAllocation(address: bigint, size: number, permissions: number, name?: string): void {
		this.allocations.set(address, { address, size, permissions, name });
	}

	/**
	 * Get all tracked allocations
	 */
	getAllocations(): Allocation[] {
		return Array.from(this.allocations.values());
	}

	/**
	 * Find allocation containing the given address
	 */
	findAllocation(address: bigint): Allocation | undefined {
		for (const alloc of this.allocations.values()) {
			if (address >= alloc.address && address < alloc.address + BigInt(alloc.size)) {
				return alloc;
			}
		}
		return undefined;
	}

	private isAllocated(address: bigint, size: number): boolean {
		const end = address + BigInt(size);
		for (const alloc of this.allocations.values()) {
			const allocEnd = alloc.address + BigInt(alloc.size);
			if (address < allocEnd && end > alloc.address) {
				return true;
			}
		}
		return false;
	}

	private alignDown(address: bigint): bigint {
		const ps = BigInt(this.pageSize);
		return (address / ps) * ps;
	}

	private alignUp(size: number): number {
		return Math.ceil(size / this.pageSize) * this.pageSize;
	}

	/**
	 * Convert Windows memory protection constants to Unicorn PROT_*
	 */
	private windowsProtToUnicorn(protect: number): number {
		switch (protect) {
			case 0x01: return 0;                                // PAGE_NOACCESS
			case 0x02: return PROT_READ;                        // PAGE_READONLY
			case 0x04: return PROT_READ | PROT_WRITE;           // PAGE_READWRITE
			case 0x08: return PROT_READ | PROT_WRITE;           // PAGE_WRITECOPY
			case 0x10: return PROT_EXEC;                        // PAGE_EXECUTE
			case 0x20: return PROT_EXEC | PROT_READ;            // PAGE_EXECUTE_READ
			case 0x40: return PROT_ALL;                         // PAGE_EXECUTE_READWRITE
			case 0x80: return PROT_ALL;                         // PAGE_EXECUTE_WRITECOPY
			default:   return PROT_READ | PROT_WRITE;
		}
	}

	/**
	 * Convert Unicorn PROT_* to Windows memory protection constants
	 */
	private unicornProtToWindows(perms: number): number {
		if (perms & PROT_EXEC) {
			if (perms & PROT_WRITE) { return 0x40; } // PAGE_EXECUTE_READWRITE
			if (perms & PROT_READ) { return 0x20; }  // PAGE_EXECUTE_READ
			return 0x10;                               // PAGE_EXECUTE
		}
		if (perms & PROT_WRITE) { return 0x04; }     // PAGE_READWRITE
		if (perms & PROT_READ) { return 0x02; }      // PAGE_READONLY
		return 0x01;                                   // PAGE_NOACCESS
	}

	dispose(): void {
		this.allocations.clear();
		this.heapBlocks = [];
		this.heapCurrent = this.heapBase;
	}
}
