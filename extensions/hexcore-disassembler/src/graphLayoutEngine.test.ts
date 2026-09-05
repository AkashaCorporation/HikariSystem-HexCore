import * as assert from 'assert';
import { CFG, BasicBlock, Edge } from './basicBlockAnalyzer';
import { Instruction } from './disassemblerEngine';
import { GraphLayoutEngine, LAYOUT_CONSTANTS } from './graphLayoutEngine';

function instruction(address: number): Instruction {
	return {
		address,
		bytes: Buffer.from([0x90]),
		mnemonic: 'nop',
		opStr: '',
		size: 1,
		isCall: false,
		isJump: false,
		isRet: false,
		isConditional: false
	};
}

function block(id: number, address: number, instructionCount = 1): BasicBlock {
	return {
		id,
		startAddress: address,
		endAddress: address + instructionCount,
		instructions: Array.from({ length: instructionCount }, (_, index) => instruction(address + index)),
		successors: [],
		predecessors: [],
		type: id === 0 ? 'entry' : 'normal'
	};
}

function cfg(blocks: BasicBlock[], edges: Edge[]): CFG {
	return {
		blocks: new Map(blocks.map(item => [item.id, item])),
		edges,
		entryBlockId: 0,
		functionName: 'test',
		functionAddress: blocks[0].startAddress
	};
}

suite('GraphLayoutEngine', () => {
	test('routes a forward edge that skips a layer through a side channel', () => {
		const blocks = [block(0, 0x1000), block(1, 0x1010), block(2, 0x1020)];
		blocks[0].successors = [2, 1];
		blocks[1].successors = [2];
		blocks[1].predecessors = [0];
		blocks[2].predecessors = [0, 1];
		const layout = new GraphLayoutEngine().calculateLayout(cfg(blocks, [
			{ from: 0, to: 2, type: 'true', label: 'true' },
			{ from: 0, to: 1, type: 'false', label: 'false' },
			{ from: 1, to: 2, type: 'fallthrough' }
		]));

		const longEdge = layout.edges.find(edge => edge.from === 0 && edge.to === 2);
		assert.ok(longEdge);
		assert.strictEqual(longEdge.points.length, 6);
		assert.ok(longEdge.points[2].x < layout.nodes.get(1)!.x);
		assert.notStrictEqual(longEdge.points.at(-1)!.x, layout.edges.at(-1)!.points.at(-1)!.x);
	});

	test('grids disconnected blocks and caps large block preview height', () => {
		const blocks = Array.from({ length: 35 }, (_, id) => block(id, 0x2000 + id * 0x10, id === 34 ? 478 : 1));
		const layout = new GraphLayoutEngine().calculateLayout(cfg(blocks, []));
		const largeNode = layout.nodes.get(34)!;
		const visibleRows = LAYOUT_CONSTANTS.MAX_VISIBLE_INSTRUCTIONS + 1;
		const expectedHeight = LAYOUT_CONSTANTS.HEADER_HEIGHT
			+ visibleRows * LAYOUT_CONSTANTS.INSTRUCTION_HEIGHT
			+ LAYOUT_CONSTANTS.NODE_PADDING;

		assert.strictEqual(largeNode.height, expectedHeight);
		assert.ok(new Set(Array.from(layout.nodes.values(), node => node.y)).size > 1);
		assert.ok(layout.width < 2500);
		assert.ok(layout.height < 2000);
	});
});
