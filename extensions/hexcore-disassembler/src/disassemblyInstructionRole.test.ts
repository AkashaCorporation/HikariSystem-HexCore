/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { classifyDisassemblyInstructionRole } from './disassemblyInstructionRole';

suite('disassembly instruction roles', () => {
	const semanticAddresses = new Set([
		0x140001200, 0x140001202, 0x140001204, 0x140001206,
		0x140001208, 0x14000120c, 0x14000120e,
	]);
	const common = {
		isContext: false,
		semanticAddresses,
		semanticEnd: 0x14000120f,
		boundaryEndExclusive: 0x140001210,
	};

	test('marks the return as semantic body', () => {
		assert.strictEqual(classifyDisassemblyInstructionRole({
			...common, address: 0x14000120e, mnemonic: 'ret',
		}), 'semantic-body');
	});

	test('marks the trailing INT3 as alignment padding', () => {
		assert.strictEqual(classifyDisassemblyInstructionRole({
			...common, address: 0x14000120f, mnemonic: 'int3',
		}), 'alignment-padding');
	});

	test('does not call an unexplained instruction semantic', () => {
		assert.strictEqual(classifyDisassemblyInstructionRole({
			...common, address: 0x14000120f, mnemonic: 'mov',
		}), 'unclassified');
	});

	test('keeps context distinct from function ownership', () => {
		assert.strictEqual(classifyDisassemblyInstructionRole({
			...common, address: 0x14000120e, mnemonic: 'ret', isContext: true,
		}), 'context');
	});
});
