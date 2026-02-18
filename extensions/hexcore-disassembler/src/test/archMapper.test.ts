/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import 'mocha';
// eslint-disable-next-line local/code-import-patterns
import * as fc from 'fast-check';
import {
	mapCapstoneToRemill,
	isArchSupported,
	serializeArchMap,
	deserializeArchMap,
	ArchMapResult,
} from '../archMapper';
import type { ArchitectureConfig } from '../capstoneWrapper';

suite('archMapper', () => {

	// -----------------------------------------------------------------------
	// Unit tests (Task 1.4)
	// -----------------------------------------------------------------------

	suite('mapCapstoneToRemill', () => {

		test('maps x86 → x86', () => {
			const result = mapCapstoneToRemill('x86' as ArchitectureConfig, 'linux');
			assert.deepStrictEqual(result, {
				supported: true,
				remillArch: 'x86',
				remillOs: 'linux',
			});
		});

		test('maps x64 → amd64', () => {
			const result = mapCapstoneToRemill('x64' as ArchitectureConfig, 'linux');
			assert.deepStrictEqual(result, {
				supported: true,
				remillArch: 'amd64',
				remillOs: 'linux',
			});
		});

		test('maps arm64 → aarch64', () => {
			const result = mapCapstoneToRemill('arm64' as ArchitectureConfig, 'windows');
			assert.deepStrictEqual(result, {
				supported: true,
				remillArch: 'aarch64',
				remillOs: 'windows',
			});
		});

		test('returns unsupported for mips', () => {
			const result = mapCapstoneToRemill('mips' as ArchitectureConfig);
			assert.deepStrictEqual(result, {
				supported: false,
				remillArch: '',
			});
		});

		test('returns unsupported for arm (32-bit)', () => {
			const result = mapCapstoneToRemill('arm' as ArchitectureConfig);
			assert.deepStrictEqual(result, {
				supported: false,
				remillArch: '',
			});
		});

		test('returns unsupported for mips64', () => {
			const result = mapCapstoneToRemill('mips64' as ArchitectureConfig);
			assert.deepStrictEqual(result, {
				supported: false,
				remillArch: '',
			});
		});

		test('auto-detects OS when not provided', () => {
			const result = mapCapstoneToRemill('x64' as ArchitectureConfig);
			assert.strictEqual(result.supported, true);
			assert.strictEqual(result.remillArch, 'amd64');
			// OS should be a non-empty string (platform-specific)
			assert.ok(typeof result.remillOs === 'string' && result.remillOs.length > 0);
		});
	});

	suite('isArchSupported', () => {

		test('returns true for x86', () => {
			assert.strictEqual(isArchSupported('x86' as ArchitectureConfig), true);
		});

		test('returns true for x64', () => {
			assert.strictEqual(isArchSupported('x64' as ArchitectureConfig), true);
		});

		test('returns true for arm64', () => {
			assert.strictEqual(isArchSupported('arm64' as ArchitectureConfig), true);
		});

		test('returns false for mips', () => {
			assert.strictEqual(isArchSupported('mips' as ArchitectureConfig), false);
		});

		test('returns false for arm (32-bit)', () => {
			assert.strictEqual(isArchSupported('arm' as ArchitectureConfig), false);
		});
	});

	// -----------------------------------------------------------------------
	// Property-based tests (Tasks 1.2, 1.3)
	// -----------------------------------------------------------------------

	suite('property-based: Architecture Mapping Round-Trip (Req 2.6)', () => {

		test('serializeArchMap → deserializeArchMap round-trip preserves all entries', () => {
			fc.assert(
				fc.property(fc.constant(null), () => {
					const serialized = serializeArchMap();
					const deserialized = deserializeArchMap(serialized);
					const reSerialized = serializeArchMap();
					// Round-trip: serialize, deserialize, re-serialize should be equal
					assert.strictEqual(serialized, JSON.stringify(deserialized));
					assert.strictEqual(serialized, reSerialized);
				}),
				{ numRuns: 100 }
			);
		});

		test('deserializeArchMap recovers all keys from serialized form', () => {
			const serialized = serializeArchMap();
			const deserialized = deserializeArchMap(serialized);

			// Known supported architectures must be present
			assert.deepStrictEqual(deserialized, {
				'x86': 'x86',
				'x64': 'amd64',
				'arm64': 'aarch64',
			});
		});

		test('round-trip preserves entries for arbitrary valid JSON maps', () => {
			const archPairArb = fc.tuple(
				fc.stringOf(fc.char().filter((c: string) => c !== '"' && c !== '\\'), { minLength: 1, maxLength: 10 }),
				fc.stringOf(fc.char().filter((c: string) => c !== '"' && c !== '\\'), { minLength: 1, maxLength: 10 })
			);

			fc.assert(
				fc.property(
					fc.array(archPairArb, { minLength: 0, maxLength: 20 }),
					(pairs: [string, string][]) => {
						const map: Record<string, string> = {};
						for (const [k, v] of pairs) {
							map[k] = v;
						}
						const json = JSON.stringify(map);
						const recovered = deserializeArchMap(json);
						assert.deepStrictEqual(recovered, map);
					}
				),
				{ numRuns: 100 }
			);
		});
	});

	suite('property-based: Architecture Mapping Consistency (Req 2.1–2.5)', () => {

		const supportedArchs: ArchitectureConfig[] = ['x86', 'x64', 'arm64'] as ArchitectureConfig[];
		const unsupportedArchs: ArchitectureConfig[] = ['mips', 'mips64', 'arm'] as ArchitectureConfig[];
		const allArchs = [...supportedArchs, ...unsupportedArchs];

		test('supported architectures always produce supported=true with non-empty remillArch', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(...supportedArchs),
					(arch: ArchitectureConfig) => {
						const result = mapCapstoneToRemill(arch);
						assert.strictEqual(result.supported, true);
						assert.ok(result.remillArch.length > 0, `remillArch should be non-empty for ${arch}`);
						assert.ok(typeof result.remillOs === 'string', `remillOs should be a string for ${arch}`);
					}
				),
				{ numRuns: 100 }
			);
		});

		test('unsupported architectures always produce supported=false with empty remillArch', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(...unsupportedArchs),
					(arch: ArchitectureConfig) => {
						const result = mapCapstoneToRemill(arch);
						assert.strictEqual(result.supported, false);
						assert.strictEqual(result.remillArch, '');
						assert.strictEqual(result.remillOs, undefined);
					}
				),
				{ numRuns: 100 }
			);
		});

		test('isArchSupported is consistent with mapCapstoneToRemill.supported', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(...allArchs),
					(arch: ArchitectureConfig) => {
						const mapResult = mapCapstoneToRemill(arch);
						assert.strictEqual(isArchSupported(arch), mapResult.supported);
					}
				),
				{ numRuns: 100 }
			);
		});

		test('mapCapstoneToRemill is deterministic: same input always produces same output', () => {
			fc.assert(
				fc.property(
					fc.constantFrom(...allArchs),
					fc.constantFrom('linux', 'windows', 'macos'),
					(arch: ArchitectureConfig, os: string) => {
						const r1 = mapCapstoneToRemill(arch, os);
						const r2 = mapCapstoneToRemill(arch, os);
						assert.deepStrictEqual(r1, r2);
					}
				),
				{ numRuns: 100 }
			);
		});

		test('arbitrary strings not in ARCH_MAP return unsupported', () => {
			fc.assert(
				fc.property(
					fc.string({ minLength: 1, maxLength: 20 }).filter(
						(s: string) => !['x86', 'x64', 'arm64'].includes(s)
					),
					(arch: string) => {
						const result = mapCapstoneToRemill(arch as ArchitectureConfig);
						assert.strictEqual(result.supported, false);
						assert.strictEqual(result.remillArch, '');
					}
				),
				{ numRuns: 100 }
			);
		});
	});
});
