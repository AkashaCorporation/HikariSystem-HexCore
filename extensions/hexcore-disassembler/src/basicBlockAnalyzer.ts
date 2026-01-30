/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Basic Block Analyzer
 *  Splits disassembled code into basic blocks for CFG visualization
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { Instruction } from './disassemblerEngine';

/**
 * A basic block is a sequence of instructions with:
 * - One entry point (first instruction)
 * - One or two exit points (last instruction - can branch)
 * - No jumps INTO the middle of the block
 */
export interface BasicBlock {
	id: number;
	startAddress: number;
	endAddress: number;
	instructions: Instruction[];
	successors: number[];      // Block IDs this block can jump to
	predecessors: number[];    // Block IDs that can jump to this block
	type: 'entry' | 'normal' | 'exit' | 'call';
}

export interface Edge {
	from: number;           // Block ID
	to: number;             // Block ID
	type: 'unconditional' | 'true' | 'false' | 'call' | 'fallthrough';
	label?: string;
}

export interface CFG {
	blocks: Map<number, BasicBlock>;
	edges: Edge[];
	entryBlockId: number;
	functionName: string;
	functionAddress: number;
}

/**
 * Analyzes a function's instructions and builds a Control Flow Graph
 */
export class BasicBlockAnalyzer {
	private blockIdCounter: number = 0;
	private addressToBlockId: Map<number, number> = new Map();

	/**
	 * Build a CFG from a list of instructions belonging to a function
	 */
	buildCFG(instructions: Instruction[], functionName: string, functionAddress: number): CFG {
		if (instructions.length === 0) {
			return this.createEmptyCFG(functionName, functionAddress);
		}

		this.blockIdCounter = 0;
		this.addressToBlockId.clear();

		// Step 1: Find all block leaders (first instruction of each block)
		const leaders = this.findBlockLeaders(instructions);

		// Step 2: Create basic blocks
		const blocks = this.createBasicBlocks(instructions, leaders);

		// Step 3: Build edges between blocks
		const edges = this.buildEdges(blocks);

		// Step 4: Set predecessors based on edges
		this.setPredecessors(blocks, edges);

		// Find entry block (block containing first instruction)
		const entryBlockId = this.addressToBlockId.get(instructions[0].address) ?? 0;

		return {
			blocks,
			edges,
			entryBlockId,
			functionName,
			functionAddress
		};
	}

	/**
	 * Find all block leaders (addresses that start a new block)
	 * A leader is:
	 * 1. The first instruction
	 * 2. Target of any jump/call
	 * 3. Instruction following a jump/call/ret
	 */
	private findBlockLeaders(instructions: Instruction[]): Set<number> {
		const leaders = new Set<number>();
		const instructionAddresses = new Set(instructions.map(i => i.address));

		// First instruction is always a leader
		if (instructions.length > 0) {
			leaders.add(instructions[0].address);
		}

		for (let i = 0; i < instructions.length; i++) {
			const inst = instructions[i];

			// If this is a jump/call, the target is a leader
			if ((inst.isJump || inst.isCall) && inst.targetAddress !== undefined) {
				if (instructionAddresses.has(inst.targetAddress)) {
					leaders.add(inst.targetAddress);
				}
			}

			// If this is a jump/call/ret, the next instruction is a leader
			if (inst.isJump || inst.isCall || inst.isRet) {
				if (i + 1 < instructions.length) {
					leaders.add(instructions[i + 1].address);
				}
			}
		}

		return leaders;
	}

	/**
	 * Create basic blocks from instructions using the identified leaders
	 */
	private createBasicBlocks(instructions: Instruction[], leaders: Set<number>): Map<number, BasicBlock> {
		const blocks = new Map<number, BasicBlock>();
		let currentBlock: BasicBlock | null = null;

		for (const inst of instructions) {
			// Start a new block if this is a leader
			if (leaders.has(inst.address)) {
				// Finish previous block
				if (currentBlock) {
					currentBlock.endAddress = currentBlock.instructions[currentBlock.instructions.length - 1].address;
					blocks.set(currentBlock.id, currentBlock);
				}

				// Create new block
				const blockId = this.blockIdCounter++;
				currentBlock = {
					id: blockId,
					startAddress: inst.address,
					endAddress: inst.address,
					instructions: [],
					successors: [],
					predecessors: [],
					type: blockId === 0 ? 'entry' : 'normal'
				};
				this.addressToBlockId.set(inst.address, blockId);
			}

			// Add instruction to current block
			if (currentBlock) {
				currentBlock.instructions.push(inst);

				// Mark block type
				if (inst.isRet) {
					currentBlock.type = 'exit';
				} else if (inst.isCall) {
					currentBlock.type = 'call';
				}
			}
		}

		// Add final block
		if (currentBlock && currentBlock.instructions.length > 0) {
			currentBlock.endAddress = currentBlock.instructions[currentBlock.instructions.length - 1].address;
			blocks.set(currentBlock.id, currentBlock);
		}

		return blocks;
	}

	/**
	 * Build edges between blocks based on control flow
	 */
	private buildEdges(blocks: Map<number, BasicBlock>): Edge[] {
		const edges: Edge[] = [];
		const blockAddresses = new Map<number, number>(); // startAddress -> blockId

		for (const [id, block] of blocks) {
			blockAddresses.set(block.startAddress, id);
		}

		for (const [fromId, block] of blocks) {
			if (block.instructions.length === 0) continue;

			const lastInst = block.instructions[block.instructions.length - 1];

			// Handle jumps
			if (lastInst.isJump) {
				if (lastInst.targetAddress !== undefined) {
					const targetBlockId = blockAddresses.get(lastInst.targetAddress);
					if (targetBlockId !== undefined) {
						block.successors.push(targetBlockId);

						if (lastInst.isConditional) {
							// Conditional jump: add true edge
							edges.push({
								from: fromId,
								to: targetBlockId,
								type: 'true',
								label: 'true'
							});

							// Also add fallthrough edge (false branch)
							const nextAddr = lastInst.address + lastInst.size;
							const fallthroughBlockId = blockAddresses.get(nextAddr);
							if (fallthroughBlockId !== undefined) {
								block.successors.push(fallthroughBlockId);
								edges.push({
									from: fromId,
									to: fallthroughBlockId,
									type: 'false',
									label: 'false'
								});
							}
						} else {
							// Unconditional jump
							edges.push({
								from: fromId,
								to: targetBlockId,
								type: 'unconditional'
							});
						}
					}
				}
			} else if (lastInst.isRet) {
				// Return - no successors (exit block)
			} else if (lastInst.isCall) {
				// Call - add fallthrough to next block
				const nextAddr = lastInst.address + lastInst.size;
				const nextBlockId = blockAddresses.get(nextAddr);
				if (nextBlockId !== undefined) {
					block.successors.push(nextBlockId);
					edges.push({
						from: fromId,
						to: nextBlockId,
						type: 'fallthrough'
					});
				}
			} else {
				// Normal instruction - fallthrough to next block
				const nextAddr = lastInst.address + lastInst.size;
				const nextBlockId = blockAddresses.get(nextAddr);
				if (nextBlockId !== undefined) {
					block.successors.push(nextBlockId);
					edges.push({
						from: fromId,
						to: nextBlockId,
						type: 'fallthrough'
					});
				}
			}
		}

		return edges;
	}

	/**
	 * Set predecessor lists based on edges
	 */
	private setPredecessors(blocks: Map<number, BasicBlock>, edges: Edge[]): void {
		for (const edge of edges) {
			const toBlock = blocks.get(edge.to);
			if (toBlock && !toBlock.predecessors.includes(edge.from)) {
				toBlock.predecessors.push(edge.from);
			}
		}
	}

	/**
	 * Create an empty CFG for functions with no instructions
	 */
	private createEmptyCFG(functionName: string, functionAddress: number): CFG {
		return {
			blocks: new Map(),
			edges: [],
			entryBlockId: -1,
			functionName,
			functionAddress
		};
	}

	/**
	 * Get block ID for a given address
	 */
	getBlockAtAddress(address: number): number | undefined {
		return this.addressToBlockId.get(address);
	}
}
