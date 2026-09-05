/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { generateAsciiGraph } from './graphGenerator';
import type { EntropyBlock } from './types';

suite('Entropy ASCII graph', () => {
	test('renders empty and very small samples without negative repeat counts', () => {
		for (let count = 0; count <= 2; count++) {
			const blocks: EntropyBlock[] = Array.from({ length: count }, (_, index) => ({
				offset: index * 4096,
				size: 4096,
				entropy: 4 + index,
			}));
			const graph = generateAsciiGraph(blocks, 60, 20);
			assert.ok(graph.includes('0'));
			assert.ok(graph.includes(count === 0 ? '(empty)' : 'EOF'));
		}
	});

	test('keeps the centered axis labels for regular samples', () => {
		const blocks: EntropyBlock[] = Array.from({ length: 60 }, (_, index) => ({
			offset: index * 4096,
			size: 4096,
			entropy: index % 8,
		}));
		const graph = generateAsciiGraph(blocks, 60, 20);
		assert.ok(graph.includes('Offset'));
		assert.ok(graph.includes('EOF'));
	});
});
