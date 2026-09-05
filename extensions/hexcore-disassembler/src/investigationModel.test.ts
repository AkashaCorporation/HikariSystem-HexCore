/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Akasha Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import { createAnalysisTarget } from 'hexcore-common';
import {
	assertFindingMatchesActiveTarget,
	buildStringInvestigationFindings,
	resolveInvestigationQueries
} from './investigationModel';

suite('Analysis Center investigations', () => {
	test('custom queries are trimmed, bounded, and reject blank input', () => {
		assert.deepStrictEqual(resolveInvestigationQueries('custom', '  health  '), ['health']);
		assert.deepStrictEqual(resolveInvestigationQueries('custom', '   '), []);
		assert.deepStrictEqual(resolveInvestigationQueries('custom', 'hp'), []);
		assert.strictEqual(resolveInvestigationQueries('custom', 'x'.repeat(400))[0].length, 256);
	});

	test('anti-debug preset expands to concrete searchable terms', () => {
		const queries = resolveInvestigationQueries('anti-debug', 'ignored');
		assert.ok(queries.includes('IsDebuggerPresent'));
		assert.ok(queries.includes('NtQueryInformationProcess'));
		assert.ok(queries.includes('debugger'));
	});

	test('maps string references to their owning function', () => {
		const findings = buildStringInvestigationFindings('investigation-1', [{
			query: 'health',
			address: 0x5000,
			string: 'PlayerHealth',
			encoding: 'ascii',
			references: [0x1010]
		}], [{
			address: 0x1000,
			endAddress: 0x1100,
			name: 'update_player'
		}]);

		assert.strictEqual(findings.length, 1);
		assert.strictEqual(findings[0].functionAddress, '0x1000');
		assert.strictEqual(findings[0].functionName, 'update_player');
		assert.strictEqual(findings[0].referenceAddress, '0x1010');
	});

	test('keeps unreferenced strings as evidence without inventing a function', () => {
		const findings = buildStringInvestigationFindings('investigation-2', [{
			query: 'debugger',
			address: 0x7000,
			string: 'debugger detected',
			encoding: 'unicode',
			references: []
		}], []);

		assert.strictEqual(findings.length, 1);
		assert.strictEqual(findings[0].stringAddress, '0x7000');
		assert.strictEqual(findings[0].referenceAddress, null);
		assert.strictEqual(findings[0].functionAddress, null);
	});

	test('deduplicates repeated references and enforces the result cap', () => {
		const findings = buildStringInvestigationFindings('investigation-3', [{
			query: 'token',
			address: 0x8000,
			string: 'token',
			encoding: 'ascii',
			references: [0x2001, 0x2001, 0x2002]
		}], [{ address: 0x2000, endAddress: 0x2100, name: 'parse_token' }], 2);

		assert.strictEqual(findings.length, 2);
		assert.notStrictEqual(findings[0].id, findings[1].id);
	});

	test('assigns stable contract finding IDs when a target is bound (3.8.4 C1)', () => {
		const target = createAnalysisTarget({
			binarySha256: 'a'.repeat(64),
			filePath: 'sample.exe',
			fileSize: 4096,
			format: 'pe',
			architecture: 'x86_64',
			imageBase: '0x140000000',
		});
		const matches = [{
			query: 'health',
			address: 0x5000,
			string: 'PlayerHealth',
			encoding: 'ascii',
			references: [0x1010]
		}];
		const functions = [{ address: 0x1000, endAddress: 0x1100, name: 'update_player' }];

		const firstRun = buildStringInvestigationFindings('investigation-A', matches, functions, 250, { target });
		const rerun = buildStringInvestigationFindings('investigation-B', matches, functions, 250, { target });
		assert.strictEqual(firstRun.length, 1);
		// The same finding rediscovered by another investigation keeps its ID.
		assert.strictEqual(firstRun[0].id, rerun[0].id);
		assert.match(firstRun[0].id, /^finding:sha256:[a-f0-9]{64}:string-reference:token:/);

		// A different target yields a different identity for the same evidence.
		const otherTarget = createAnalysisTarget({
			binarySha256: 'b'.repeat(64),
			filePath: 'sample.exe',
			fileSize: 4096,
			format: 'pe',
		});
		const otherRun = buildStringInvestigationFindings('investigation-A', matches, functions, 250, { target: otherTarget });
		assert.notStrictEqual(firstRun[0].id, otherRun[0].id);

		// Without a target, the legacy 24-hex identity remains for session-less callers.
		const legacy = buildStringInvestigationFindings('investigation-A', matches, functions);
		assert.match(legacy[0].id, /^[a-f0-9]{24}$/);
	});

	test('assertFindingMatchesActiveTarget rejects cross-target IDs with a typed error (3.8.4 C5)', () => {
		const target = createAnalysisTarget({
			binarySha256: 'a'.repeat(64),
			filePath: 'sample.exe',
			fileSize: 4096,
			format: 'pe',
		});
		const otherTarget = createAnalysisTarget({
			binarySha256: 'b'.repeat(64),
			filePath: 'other.exe',
			fileSize: 4096,
			format: 'pe',
		});
		const matches = [{
			query: 'health',
			address: 0x5000,
			string: 'PlayerHealth',
			encoding: 'ascii',
			references: [0x1010]
		}];
		const findingId = buildStringInvestigationFindings('inv', matches, [], 250, { target })[0].id;

		// Same target: accepted. No active target (legacy flow): accepted.
		assert.doesNotThrow(() => assertFindingMatchesActiveTarget(findingId, target));
		assert.doesNotThrow(() => assertFindingMatchesActiveTarget(findingId, undefined));

		// Another target's finding is a typed wrong-target rejection.
		assert.throws(() => assertFindingMatchesActiveTarget(findingId, otherTarget), /wrong-target/);

		// Legacy 24-hex IDs carry no target and pass through to the DB guard.
		assert.doesNotThrow(() => assertFindingMatchesActiveTarget('a'.repeat(24), otherTarget));
	});
});
