/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

const fs = require('fs');
const path = require('path');

const filePath = path.join(__dirname, '..', 'build', 'node_modules', '@vscode', 'vsce', 'out', 'npm.js');

const originalSnippet = `function getNpmDependencies(cwd) {
    return checkNPM()
        .then(() => exec('npm list --production --parseable --depth=99999 --loglevel=error', { cwd, maxBuffer: 5000 * 1024 }))
        .then(({ stdout }) => stdout.split(/[\\r\\n]/).filter(dir => path.isAbsolute(dir)));
}`;

const patchedSnippet = `function getNpmDependencies(cwd) {
    return checkNPM()
        .then(() => exec('npm ls --all --omit=dev --parseable', { cwd, maxBuffer: 5000 * 1024, env: { ...process.env, NODE_ENV: 'production' } }))
        .catch(err => {
        const stdout = err && typeof err.stdout === 'string' ? err.stdout : '';
        const message = err && err.message ? err.message : String(err);
        if (/ELSPROBLEMS/.test(message)) {
            return { stdout };
        }
        throw err;
    })
        .then(({ stdout }) => stdout.split(/[\\r\\n]/).filter(dir => path.isAbsolute(dir)));
}`;

function main() {
	if (!fs.existsSync(filePath)) {
		throw new Error(`vsce npm implementation not found: ${filePath}`);
	}

	let content = fs.readFileSync(filePath, 'utf8');

	if (content.includes("npm ls --all --omit=dev --parseable")) {
		console.log('[patch-vsce] Already patched.');
		return;
	}

	if (!content.includes(originalSnippet)) {
		throw new Error('[patch-vsce] Expected source snippet not found in vsce npm.js. Aborting patch.');
	}

	content = content.replace(originalSnippet, patchedSnippet);
	fs.writeFileSync(filePath, content, 'utf8');
	console.log('[patch-vsce] Patched build/node_modules/@vscode/vsce/out/npm.js');
}

main();
