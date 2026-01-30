/*---------------------------------------------------------------------------------------------
 *  HexCore Disassembler - Graph Layout Engine
 *  Calculates positions for CFG visualization using hierarchical layout
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { BasicBlock, CFG, Edge } from './basicBlockAnalyzer';

export interface NodeLayout {
	id: number;
	x: number;
	y: number;
	width: number;
	height: number;
	layer: number;
}

export interface EdgeLayout {
	from: number;
	to: number;
	type: Edge['type'];
	label?: string;
	points: { x: number; y: number }[];
}

export interface GraphLayout {
	nodes: Map<number, NodeLayout>;
	edges: EdgeLayout[];
	width: number;
	height: number;
}

// Layout constants
const NODE_WIDTH = 280;
const NODE_PADDING = 20;
const LAYER_SPACING = 100;
const NODE_SPACING = 40;
const INSTRUCTION_HEIGHT = 18;
const HEADER_HEIGHT = 28;

/**
 * Calculates layout for a CFG using a simplified Sugiyama algorithm
 */
export class GraphLayoutEngine {

	/**
	 * Calculate layout for a CFG
	 */
	calculateLayout(cfg: CFG): GraphLayout {
		if (cfg.blocks.size === 0) {
			return { nodes: new Map(), edges: [], width: 0, height: 0 };
		}

		// Step 1: Assign layers using BFS from entry
		const layers = this.assignLayers(cfg);

		// Step 2: Order nodes within each layer to minimize crossings
		const orderedLayers = this.orderNodesInLayers(cfg, layers);

		// Step 3: Calculate node positions
		const nodes = this.calculateNodePositions(cfg, orderedLayers);

		// Step 4: Route edges
		const edges = this.routeEdges(cfg, nodes);

		// Calculate total dimensions
		let maxWidth = 0;
		let maxHeight = 0;
		for (const node of nodes.values()) {
			maxWidth = Math.max(maxWidth, node.x + node.width);
			maxHeight = Math.max(maxHeight, node.y + node.height);
		}

		return {
			nodes,
			edges,
			width: maxWidth + NODE_PADDING * 2,
			height: maxHeight + NODE_PADDING * 2
		};
	}

	/**
	 * Assign layer numbers to each block using BFS
	 * Entry block is layer 0, successors are in subsequent layers
	 */
	private assignLayers(cfg: CFG): Map<number, number> {
		const layers = new Map<number, number>();
		const visited = new Set<number>();
		const queue: { id: number; layer: number }[] = [];

		// Start from entry block
		if (cfg.entryBlockId >= 0) {
			queue.push({ id: cfg.entryBlockId, layer: 0 });
		}

		while (queue.length > 0) {
			const { id, layer } = queue.shift()!;

			if (visited.has(id)) {
				// Update layer if we found a longer path
				const existingLayer = layers.get(id) ?? 0;
				if (layer > existingLayer) {
					layers.set(id, layer);
				}
				continue;
			}

			visited.add(id);
			layers.set(id, layer);

			const block = cfg.blocks.get(id);
			if (block) {
				for (const successorId of block.successors) {
					queue.push({ id: successorId, layer: layer + 1 });
				}
			}
		}

		// Handle unreachable blocks (put them at layer 0)
		for (const [id] of cfg.blocks) {
			if (!layers.has(id)) {
				layers.set(id, 0);
			}
		}

		return layers;
	}

	/**
	 * Order nodes within each layer to minimize edge crossings
	 * Uses barycenter heuristic
	 */
	private orderNodesInLayers(cfg: CFG, layers: Map<number, number>): number[][] {
		// Group blocks by layer
		const layerGroups = new Map<number, number[]>();
		let maxLayer = 0;

		for (const [id, layer] of layers) {
			if (!layerGroups.has(layer)) {
				layerGroups.set(layer, []);
			}
			layerGroups.get(layer)!.push(id);
			maxLayer = Math.max(maxLayer, layer);
		}

		// Convert to array
		const orderedLayers: number[][] = [];
		for (let i = 0; i <= maxLayer; i++) {
			orderedLayers.push(layerGroups.get(i) || []);
		}

		// Apply barycenter ordering for each layer (except first)
		for (let i = 1; i < orderedLayers.length; i++) {
			const prevLayer = orderedLayers[i - 1];
			const currentLayer = orderedLayers[i];

			// Calculate barycenter for each node
			const barycenters: { id: number; value: number }[] = [];

			for (const nodeId of currentLayer) {
				const block = cfg.blocks.get(nodeId);
				if (!block) continue;

				// Find positions of predecessors in previous layer
				let sum = 0;
				let count = 0;
				for (const predId of block.predecessors) {
					const predPos = prevLayer.indexOf(predId);
					if (predPos >= 0) {
						sum += predPos;
						count++;
					}
				}

				const barycenter = count > 0 ? sum / count : currentLayer.indexOf(nodeId);
				barycenters.push({ id: nodeId, value: barycenter });
			}

			// Sort by barycenter
			barycenters.sort((a, b) => a.value - b.value);
			orderedLayers[i] = barycenters.map(b => b.id);
		}

		return orderedLayers;
	}

	/**
	 * Calculate X/Y positions for each node
	 */
	private calculateNodePositions(cfg: CFG, orderedLayers: number[][]): Map<number, NodeLayout> {
		const nodes = new Map<number, NodeLayout>();

		let currentY = NODE_PADDING;

		for (let layer = 0; layer < orderedLayers.length; layer++) {
			const layerNodes = orderedLayers[layer];
			let maxHeight = 0;

			// Calculate total width of this layer
			const totalWidth = layerNodes.length * NODE_WIDTH + (layerNodes.length - 1) * NODE_SPACING;
			let currentX = NODE_PADDING + (layerNodes.length > 1 ? 0 : NODE_WIDTH / 2);

			// Center the layer
			if (orderedLayers.length > 1 && orderedLayers[0].length > 0) {
				const maxLayerWidth = Math.max(...orderedLayers.map(l => l.length)) * (NODE_WIDTH + NODE_SPACING);
				currentX = NODE_PADDING + (maxLayerWidth - totalWidth) / 2;
			}

			for (const nodeId of layerNodes) {
				const block = cfg.blocks.get(nodeId);
				if (!block) continue;

				// Calculate height based on number of instructions
				const height = HEADER_HEIGHT + block.instructions.length * INSTRUCTION_HEIGHT + NODE_PADDING;

				nodes.set(nodeId, {
					id: nodeId,
					x: currentX,
					y: currentY,
					width: NODE_WIDTH,
					height,
					layer
				});

				maxHeight = Math.max(maxHeight, height);
				currentX += NODE_WIDTH + NODE_SPACING;
			}

			currentY += maxHeight + LAYER_SPACING;
		}

		return nodes;
	}

	/**
	 * Route edges between nodes
	 */
	private routeEdges(cfg: CFG, nodes: Map<number, NodeLayout>): EdgeLayout[] {
		const edgeLayouts: EdgeLayout[] = [];

		for (const edge of cfg.edges) {
			const fromNode = nodes.get(edge.from);
			const toNode = nodes.get(edge.to);

			if (!fromNode || !toNode) continue;

			// Calculate connection points
			const fromX = fromNode.x + fromNode.width / 2;
			const fromY = fromNode.y + fromNode.height;
			const toX = toNode.x + toNode.width / 2;
			const toY = toNode.y;

			// For conditional jumps, offset the exit points
			let exitOffset = 0;
			if (edge.type === 'true') {
				exitOffset = -30;
			} else if (edge.type === 'false') {
				exitOffset = 30;
			}

			// Create edge path (bezier curve for smooth edges)
			const points: { x: number; y: number }[] = [];

			if (toNode.layer > fromNode.layer) {
				// Forward edge (normal flow)
				points.push({ x: fromX + exitOffset, y: fromY });

				// Control point for smooth curve
				const midY = (fromY + toY) / 2;
				points.push({ x: fromX + exitOffset, y: midY });
				points.push({ x: toX, y: midY });
				points.push({ x: toX, y: toY });
			} else {
				// Back edge (loop)
				const loopOffset = NODE_WIDTH / 2 + 20;
				points.push({ x: fromX + exitOffset, y: fromY });
				points.push({ x: fromX + exitOffset, y: fromY + 20 });
				points.push({ x: fromNode.x + fromNode.width + loopOffset, y: fromY + 20 });
				points.push({ x: fromNode.x + fromNode.width + loopOffset, y: toY - 20 });
				points.push({ x: toX, y: toY - 20 });
				points.push({ x: toX, y: toY });
			}

			edgeLayouts.push({
				from: edge.from,
				to: edge.to,
				type: edge.type,
				label: edge.label,
				points
			});
		}

		return edgeLayouts;
	}
}

// Export constants for use in rendering
export const LAYOUT_CONSTANTS = {
	NODE_WIDTH,
	NODE_PADDING,
	LAYER_SPACING,
	NODE_SPACING,
	INSTRUCTION_HEIGHT,
	HEADER_HEIGHT
};
