import * as assert from 'assert';
import {
	buildWindowsSecuritySummary,
	extractExecutionManifestFromBuffer,
} from './windowsSecuritySummary';

suite('Windows PE security summary', () => {
	test('extracts requireAdministrator and uiAccess from an ASCII manifest', () => {
		const prefix = Buffer.from('xxxx', 'ascii');
		const manifest = Buffer.from('<requestedExecutionLevel level="requireAdministrator" uiAccess="false">', 'ascii');
		const result = extractExecutionManifestFromBuffer(Buffer.concat([prefix, manifest]), 0x2000);
		assert.strictEqual(result.status, 'found');
		assert.strictEqual(result.requestedExecutionLevel, 'requireAdministrator');
		assert.strictEqual(result.uiAccess, false);
		assert.strictEqual(result.source?.fileOffset, 0x2004);
		assert.strictEqual(result.source?.encoding, 'utf8');
	});

	test('extracts a UTF-16 manifest and keeps unknown levels explicit', () => {
		const text = '<requestedExecutionLevel uiAccess="true" level="customBroker">';
		const result = extractExecutionManifestFromBuffer(Buffer.from(text, 'utf16le'), 0x5000);
		assert.strictEqual(result.status, 'found');
		assert.strictEqual(result.requestedExecutionLevel, 'unknown');
		assert.strictEqual(result.rawLevel, 'customBroker');
		assert.strictEqual(result.uiAccess, true);
		assert.strictEqual(result.source?.encoding, 'utf16le');
	});

	test('keeps imported filesystem APIs as signals instead of findings', () => {
		const summary = buildWindowsSecuritySummary(
			{ status: 'found', requestedExecutionLevel: 'requireAdministrator', uiAccess: false },
			[{ name: 'ASLR', enabled: true, description: 'ASLR enabled' }],
			[{
				dllName: 'ADVAPI32.dll',
				functions: [
					{ name: 'AddAccessAllowedAce', address: 0x665020 },
					{ name: 'RegCloseKey', address: 0x665010 },
				],
			}],
		);
		assert.strictEqual(summary.status, 'signals-only');
		assert.deepStrictEqual(summary.capabilities, [{
			dll: 'ADVAPI32.dll',
			api: 'AddAccessAllowedAce',
			iatRva: 0x665020,
			roles: ['security-descriptor'],
			evidenceStatus: 'import-signal',
		}]);
	});
});
