/* PRNG fidelity: TS GlibcPRNG must match native glibc bit-for-bit. */
const path = require('path');
const { GlibcPRNG } = require(path.join(__dirname, '..', 'out', 'prng.js'));

// Native glibc reference (gcc, WSL): seed followed by first 8 rand() outputs.
const NATIVE = {
	0:          [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492],
	1:          [1804289383, 846930886, 1681692777, 1714636915, 1957747793, 424238335, 719885386, 1649760492],
	2:          [1505335290, 1738766719, 190686788, 260874575, 747983061, 906156498, 1502820864, 142559277],
	42:         [71876166, 708592740, 1483128881, 907283241, 442951012, 537146758, 1366999021, 1854614940],
	1337:       [292616681, 1638893262, 255706927, 995816787, 588263094, 1540293802, 343418821, 903681492],
	12345:      [383100999, 858300821, 357768173, 455528251, 133005921, 116285904, 591987137, 102557902],
	2147483646: [1320593690, 1199968952, 1432693999, 317934276, 69604050, 522196235, 1290561954, 354237423],
	99999:      [1268809316, 1366423099, 1000818142, 2078760739, 905264172, 1538814804, 425552616, 242719814],
	314159:     [414777680, 2009630532, 102799611, 1785840038, 1157731385, 59849040, 2016895726, 1169205285],
	1000000007: [110759905, 1327133856, 601025079, 673070893, 996726755, 1835848883, 2940937, 75760567],
	777:        [947371799, 2013380011, 1359686060, 1503739543, 459541900, 1184792193, 2114725554, 435210838],
	65536:      [553316596, 1748907888, 680492731, 191440832, 1061163313, 953167306, 1813102830, 422412382],
};

let allPass = true;
for (const [seedStr, expected] of Object.entries(NATIVE)) {
	const seed = Number(seedStr);
	const p = new GlibcPRNG();
	p.seed(seed);
	const got = [];
	for (let i = 0; i < expected.length; i++) { got.push(p.rand()); }
	const ok = got.every((v, i) => v === expected[i]);
	if (!ok) {
		allPass = false;
		console.log(`FAIL seed=${seed}`);
		console.log(`  expected ${expected.join(' ')}`);
		console.log(`  got      ${got.join(' ')}`);
	} else {
		console.log(`PASS seed=${seed} (first=${got[0]} 0x${(got[0] >>> 0).toString(16)})`);
	}
}
console.log(`\n[prng] RESULT: ${allPass ? 'PASS (bit-for-bit glibc parity, 12 seeds)' : 'FAIL'}`);
process.exit(allPass ? 0 : 1);
