import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { extractIOCs } from './iocExtractor';

suite('IOC extraction validation contract', () => {
	test('rejects OID prefixes and invalid short IPv6 while retaining real addresses', () => {
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-ioc-validation-'));
		const file = path.join(directory, 'fixture.bin');
		fs.writeFileSync(file, Buffer.from(
			'oid=1.3.6.1.5.5.7.3.1 invalid=E:E:E:D public=8.8.8.8 ipv6=2001:0db8:0000:0000:0000:ff00:0042:8329\0',
			'ascii',
		));
		try {
			const result = extractIOCs({
				filePath: file,
				categories: ['ipv4', 'ipv6'],
				excludePrivate: false,
				maxMatches: 100,
				storageMode: 'memory',
			});
			assert.deepStrictEqual(result.indicators.ipv4.map(item => item.value), ['8.8.8.8']);
			assert.deepStrictEqual(result.indicators.ipv6.map(item => item.value), ['2001:0db8:0000:0000:0000:ff00:0042:8329']);
			assert.ok(result.summary.validation.rejectedValidator >= 2);
			assert.strictEqual(result.summary.validation.acceptedUnique, 2);
			assert.strictEqual(
				result.summary.validation.rawPatternMatches,
				result.summary.validation.acceptedUnique + result.summary.validation.rejectedTotal,
			);
		} finally {
			fs.rmSync(directory, { recursive: true, force: true });
		}
	});
});
