/*---------------------------------------------------------------------------------------------
 *  HexCore Entropy Analyzer v1.1.0
 *  ASCII graph generation
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import { EntropyBlock } from './types';

export function generateAsciiGraph(blocks: EntropyBlock[], width: number, height: number): string {
	const lines: string[] = [];

	const step = Math.max(1, Math.floor(blocks.length / width));
	const sampledBlocks: number[] = [];

	for (let i = 0; i < width && i * step < blocks.length; i++) {
		const startIdx = i * step;
		const endIdx = Math.min(startIdx + step, blocks.length);
		let maxEntropy = 0;
		for (let j = startIdx; j < endIdx; j++) {
			if (blocks[j].entropy > maxEntropy) {
				maxEntropy = blocks[j].entropy;
			}
		}
		sampledBlocks.push(maxEntropy);
	}

	for (let row = height - 1; row >= 0; row--) {
		const threshold = (row / height) * 8;
		let line = '';

		if (row === height - 1) {
			line = '8.0|';
		} else if (row === Math.floor(height / 2)) {
			line = '4.0|';
		} else if (row === 0) {
			line = '0.0|';
		} else {
			line = '   |';
		}

		for (const entropy of sampledBlocks) {
			if (entropy >= threshold) {
				if (entropy > 7.0) {
					line += '#';
				} else if (entropy > 5.0) {
					line += '=';
				} else if (entropy > 3.0) {
					line += '-';
				} else {
					line += '.';
				}
			} else {
				line += ' ';
			}
		}
		lines.push(line);
	}

	lines.push('   +' + '-'.repeat(sampledBlocks.length));
	lines.push('    0' + ' '.repeat(Math.floor(sampledBlocks.length / 2) - 3) + 'Offset' + ' '.repeat(Math.floor(sampledBlocks.length / 2) - 6) + 'EOF');

	return lines.join('\n');
}
