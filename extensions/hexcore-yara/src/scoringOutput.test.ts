/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import type { ScanResult } from './yaraEngine';

suite('YARA scoring output contract', () => {
	test('JSON and both Markdown reports preserve advisory status and context', () => {
		const Module = require('module');
		const original = Module._resolveFilename;
		Module._resolveFilename = function (request: string, ...args: unknown[]) {
			return request === 'vscode' ? '__vscode_yara_output__' : original.call(this, request, ...args);
		};
		require.cache['__vscode_yara_output__'] = { id: '__vscode_yara_output__', filename: '__vscode_yara_output__', loaded: true, exports: { TreeItem: class {} } } as NodeModule;
		const extension = require('./extension');
		const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-yara-output-'));
		try {
			const result: ScanResult = {
				file: 'classes.dex', threatScore: 0, scanTime: 1, fileSize: 100, categories: { test: 1 },
				matches: [{ ruleName: 'Constant', namespace: 'test', severity: 'high', score: 75, scoreContribution: 0, advisoryOnly: true, advisoryReason: 'Generic constant', meta: {}, strings: [] }],
				binaryContext: { format: 'dex', architecture: 'dalvik', executableSectionCount: 0 },
				scoring: { policy: 'qualified-rule-maximum-v1', scoredMatches: 0, advisoryMatches: 1, advisoryScore: 75 },
			};
			const output = path.join(directory, 'result.json');
			extension.writeScanOutput(result, { path: output, format: 'json' });
			const saved = JSON.parse(fs.readFileSync(output, 'utf8'));
			assert.deepStrictEqual(saved.scoring, result.scoring);
			assert.deepStrictEqual(saved.binaryContext, result.binaryContext);
			for (const text of [extension.buildScanMarkdown(result), extension.buildThreatReportMarkdown(result.file, result)]) {
				assert.match(text, /Advisory Score \(excluded\).*75/);
				assert.match(text, /dex \/ dalvik/);
				assert.doesNotMatch(text, /appears clean|🟢 CLEAN/);
			}
		} finally { fs.rmSync(directory, { recursive: true, force: true }); }
	});
});
