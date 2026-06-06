// Smoke test for the CyberChef-adopted scoring substrate (scoringEngine.ts):
// Shannon entropy + monogram chi-squared + plaintext-likelihood. Verifies the
// invariants independently (the math bounds + a strong English-vs-random
// separation) rather than brittle absolute thresholds. Run under mocha --ui tdd.
import * as assert from 'assert';
import { randomBytes } from 'crypto';
import { shannonEntropy, chiSquaredEnglish, plaintextLikelihood } from './scoringEngine';

const EN_A = Buffer.from('the most common english words are the of and to in that it is was for', 'ascii');
const EN_B = Buffer.from('this is a sentence of ordinary english prose written for the test today', 'ascii');

suite('scoringEngine: entropy + chi-squared (CyberChef Magic substrate)', () => {
	test('shannonEntropy is bounded 0..8: single-symbol -> 0, full 0..255 ramp -> 8', () => {
		const same = Buffer.alloc(256, 0x41);
		assert.ok(shannonEntropy(same) < 1e-9, 'all-same buffer has ~0 entropy');
		const ramp = Buffer.alloc(256);
		for (let i = 0; i < 256; i++) { ramp[i] = i; }
		assert.ok(Math.abs(shannonEntropy(ramp) - 8) < 1e-9, 'uniform 0..255 is 8 bits/byte');
	});

	test('shannonEntropy: natural English sits in the structured-text band', () => {
		const h = shannonEntropy(EN_A);
		assert.ok(h >= 3.0 && h <= 5.5, `english entropy ${h} in [3.0, 5.5]`);
		assert.ok(shannonEntropy(EN_A) < shannonEntropy(randomBytes(512)), 'english entropy below random');
	});

	test('chiSquaredEnglish: English is much closer to the Mayzner table than random', () => {
		const chiEn = chiSquaredEnglish(EN_A);
		const chiRnd = chiSquaredEnglish(randomBytes(512));
		assert.ok(chiEn < chiRnd, `english chi-sqr ${chiEn} < random ${chiRnd}`);
		assert.ok(chiEn < 400, `english chi-sqr ${chiEn} is small`);
	});

	test('plaintextLikelihood: strong English >> random separation', () => {
		const pEnA = plaintextLikelihood(EN_A);
		const pEnB = plaintextLikelihood(EN_B);
		const pRnd = plaintextLikelihood(randomBytes(512));
		assert.ok(pEnA >= 0.5 && pEnB >= 0.5, `english likelihood ${pEnA}/${pEnB} >= 0.5`);
		assert.ok(pRnd <= 0.1, `random likelihood ${pRnd} <= 0.1`);
		assert.ok(pEnA - pRnd > 0.4, 'english-vs-random separation > 0.4');
	});

	test('window-scoped: a sub-range scores independently of the whole buffer', () => {
		const buf = Buffer.concat([randomBytes(64), EN_A]);
		// the English tail is more plaintext-like than the random head
		assert.ok(plaintextLikelihood(buf, 64) > plaintextLikelihood(buf, 0, 64),
			'english window scores above the random window');
	});
});
