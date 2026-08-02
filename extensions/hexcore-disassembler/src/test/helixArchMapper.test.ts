/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
import { HelixArch, isHelixArchSupported, mapCapstoneToHelix } from '../helixArchMapper';
import type { ArchitectureConfig } from '../capstoneWrapper';

suite('helixArchMapper', () => {
	test('maps supported architectures', () => {
		assert.deepStrictEqual(mapCapstoneToHelix('x64' as ArchitectureConfig), {
			supported: true,
			helixArch: HelixArch.X86_64,
		});
		assert.deepStrictEqual(mapCapstoneToHelix('arm64' as ArchitectureConfig), {
			supported: true,
			helixArch: HelixArch.Aarch64,
		});
	});

	test('rejects inherited Object prototype keys', () => {
		assert.deepStrictEqual(mapCapstoneToHelix('__proto__' as ArchitectureConfig), {
			supported: false,
			helixArch: HelixArch.X86_64,
		});
		assert.strictEqual(isHelixArchSupported('__proto__' as ArchitectureConfig), false);
	});
});
