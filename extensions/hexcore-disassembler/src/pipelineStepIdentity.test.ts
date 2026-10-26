/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import { inspectStepIdentities, resolveGotoTarget, resolveStepToken, stepReferencePattern } from './pipelineStepIdentity';

suite('named pipeline step identity', () => {
	test('uses a case-sensitive map independent of execution order', () => {
		const { ids, issues } = inspectStepIdentities([{ id: 'lift-main' }, { id: 'Lift-main' }, { id: 'constructor' }]);
		assert.deepStrictEqual(issues, []);
		assert.strictEqual(resolveStepToken('lift-main', 3, ids), 0);
		assert.strictEqual(resolveStepToken('Lift-main', 3, ids), 1);
		assert.strictEqual(resolveGotoTarget('constructor', 3, ids), 2);
	});
	test('rejects invalid, reserved and duplicate identifiers', () => {
		for (const id of ['', '1', 'has space', 'prev', '_hidden', 'a'.repeat(65), 1, null, {}]) {
			assert.strictEqual(inspectStepIdentities([{ id }]).issues[0].code, 'STEP_ID_INVALID');
		}
		assert.strictEqual(inspectStepIdentities([{ id: 'same' }, { id: 'same' }]).issues[0].code, 'STEP_ID_DUPLICATE');
	});
	test('retains numeric/prev references and legacy numeric goto strings', () => {
		assert.strictEqual(resolveStepToken('001', 5), 1);
		assert.strictEqual(resolveStepToken('prev', 5), 4);
		assert.strictEqual(resolveGotoTarget('0x2', 4), 2);
		assert.throws(() => resolveGotoTarget('missing', 4), /declared step ID/);
		assert.throws(() => resolveGotoTarget(1.5, 4), /integer step index/);
	});
	test('tokenization surfaces malformed names instead of ignoring them', () => {
		const tokens = [...'$step[lift-main].output $step[].output $step[bad.id].result.x'.matchAll(stepReferencePattern())].map(match => match.groups!.token);
		assert.deepStrictEqual(tokens, ['lift-main', '', 'bad.id']);
		assert.throws(() => resolveStepToken('bad.id', 3), /invalid step reference/);
	});
});
