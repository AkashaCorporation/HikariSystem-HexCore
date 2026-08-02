import * as assert from 'assert';
import { matchRegexOffsets } from './yaraEngine';

assert.deepStrictEqual(matchRegexOffsets('MZ.{2}PE', 'xxMZ12PEyy'), [2]);
assert.deepStrictEqual(matchRegexOffsets('ab', 'abxxab'), [0, 4]);
assert.deepStrictEqual(matchRegexOffsets('\\xFF', `A${String.fromCharCode(0xFF)}B`), [1]);
assert.deepStrictEqual(matchRegexOffsets('^|$', 'abc'), [0, 3]);

const hostile = `${'a'.repeat(250_000)}!`;
const started = Date.now();
assert.deepStrictEqual(matchRegexOffsets('(a+)+$', hostile), []);
assert.deepStrictEqual(matchRegexOffsets('(a|aa)*b', hostile), []);
assert.ok(Date.now() - started < 1_000, 'catastrophic regex controls must remain time-bounded');

console.log('regexSafety: 7/7 passing');
