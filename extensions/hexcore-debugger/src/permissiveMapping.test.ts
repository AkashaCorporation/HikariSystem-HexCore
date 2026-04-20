/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

// Feature: v3.7.1, Property P1: Permissive Memory Mapping toggle

import * as assert from 'assert';
import * as fc from 'fast-check';

/**
 * Simulates the permissive memory mapping logic used in PE32/x64 ELF workers
 * and loadRawBinary. When permissiveMemoryMapping is true, all sections get
 * RWX (7). When false/omitted, sections keep their original permissions.
 */
function resolveProtection(sectionProt: number, permissive: boolean | undefined): number {
	return (permissive ?? false) ? 7 : sectionProt;
}

suite('Property P1: Permissive Memory Mapping toggle', () => {

	/**
	 * P1.1: When permissiveMemoryMapping is true, all regions are mapped RWX (7).
	 */
	test('permissive=true always yields RWX (7)', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 7 }), (sectionProt) => {
				assert.strictEqual(resolveProtection(sectionProt, true), 7);
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * P1.2: When permissiveMemoryMapping is false, sections keep original permissions.
	 */
	test('permissive=false preserves original section permissions', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 7 }), (sectionProt) => {
				assert.strictEqual(resolveProtection(sectionProt, false), sectionProt);
			}),
			{ numRuns: 100 }
		);
	});

	/**
	 * P1.3: Default (undefined) behaves as false.
	 */
	test('permissive=undefined defaults to false (preserves permissions)', () => {
		fc.assert(
			fc.property(fc.integer({ min: 0, max: 7 }), (sectionProt) => {
				assert.strictEqual(resolveProtection(sectionProt, undefined), sectionProt);
			}),
			{ numRuns: 100 }
		);
	});
});
