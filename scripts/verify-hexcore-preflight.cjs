/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const errors = [];

function readText(relativePath) {
	const fullPath = path.join(root, relativePath);
	if (!fs.existsSync(fullPath)) {
		errors.push(`Missing file: ${relativePath}`);
		return '';
	}
	return fs.readFileSync(fullPath, 'utf8');
}

function readOptionalText(relativePath) {
	const fullPath = path.join(root, relativePath);
	if (!fs.existsSync(fullPath)) {
		return undefined;
	}
	return fs.readFileSync(fullPath, 'utf8');
}

function readJson(relativePath) {
	const text = readText(relativePath);
	if (!text) {
		return null;
	}
	try {
		return JSON.parse(text);
	} catch (error) {
		errors.push(`Invalid JSON: ${relativePath}: ${String(error)}`);
		return null;
	}
}

function assertIncludes(haystack, needle, label) {
	if (!haystack.includes(needle)) {
		errors.push(`Missing expected content in ${label}: ${needle}`);
	}
}

function verifyYaraCommands() {
	const yaraPackage = readJson('extensions/hexcore-yara/package.json');
	const yaraSource = readText('extensions/hexcore-yara/src/extension.ts');
	const yaraOut = readOptionalText('extensions/hexcore-yara/out/extension.js');

	const required = [
		'hexcore.yara.scan',
		'hexcore.yara.scanWorkspace',
		'hexcore.yara.loadDefender'
	];

	if (yaraPackage) {
		const contributed = (yaraPackage.contributes?.commands || []).map(command => command.command);
		for (const command of required) {
			if (!contributed.includes(command)) {
				errors.push(`hexcore-yara/package.json does not contribute command: ${command}`);
			}
		}
	}

	for (const command of required) {
		assertIncludes(yaraSource, `registerCommand('${command}'`, 'extensions/hexcore-yara/src/extension.ts');
		if (yaraOut) {
			assertIncludes(yaraOut, `registerCommand('${command}'`, 'extensions/hexcore-yara/out/extension.js');
		}
	}
}

function verifyPipelineCapabilities() {
	const runnerSource = readText('extensions/hexcore-disassembler/src/automationPipelineRunner.ts');
	const runnerOut = readOptionalText('extensions/hexcore-disassembler/out/automationPipelineRunner.js');

	const requiredCapabilities = [
		'hexcore.yara.scan',
		'hexcore.pipeline.listCapabilities',
		'hexcore.pipeline.runJob'
	];

	for (const capability of requiredCapabilities) {
		assertIncludes(runnerSource, `'${capability}'`, 'extensions/hexcore-disassembler/src/automationPipelineRunner.ts');
		if (runnerOut) {
			assertIncludes(runnerOut, `'${capability}'`, 'extensions/hexcore-disassembler/out/automationPipelineRunner.js');
		}
	}
}

function verifyBuildCoverage() {
	const winBuildScript = readText('scripts/build-hexcore-win.ps1');
	const gulpExtensions = readText('build/gulpfile.extensions.ts');
	const npmDirs = readText('build/npm/dirs.ts');
	readJson('extensions/hexcore-hql/package-lock.json');

	assertIncludes(winBuildScript, '"extensions/hexcore-yara"', 'scripts/build-hexcore-win.ps1');
	assertIncludes(winBuildScript, 'extensions/hexcore-hql', 'scripts/build-hexcore-win.ps1');
	assertIncludes(gulpExtensions, `'extensions/hexcore-yara/tsconfig.json'`, 'build/gulpfile.extensions.ts');
	assertIncludes(npmDirs, `'extensions/hexcore-yara'`, 'build/npm/dirs.ts');
	assertIncludes(npmDirs, `'extensions/hexcore-hql'`, 'build/npm/dirs.ts');
}

function verifyDebuggerWorkerPackaging() {
	const tsconfig = readJson('extensions/hexcore-debugger/tsconfig.json');
	if (tsconfig?.compilerOptions?.allowJs !== true) {
		errors.push('extensions/hexcore-debugger/tsconfig.json must enable allowJs so runtime workers are emitted into out/');
	}

	const workers = [
		['pe32Worker.js', 'pe32WorkerClient.ts'],
		['arm64Worker.js', 'arm64WorkerClient.ts'],
		['x64ElfWorker.js', 'x64ElfWorkerClient.ts']
	];
	for (const [worker, client] of workers) {
		readText(`extensions/hexcore-debugger/src/${worker}`);
		const clientSource = readText(`extensions/hexcore-debugger/src/${client}`);
		assertIncludes(clientSource, `path.join(__dirname, '${worker}')`, `extensions/hexcore-debugger/src/${client}`);
	}
}

function verifyRevenantPackaging() {
	const workflow = readText('.github/workflows/hexcore-installer.yml');
	const vscodeIgnore = readText('extensions/hexcore-revenant/.vscodeignore');

	for (const required of [
		'revenant-engine-win-x64.tar.gz',
		'bin/win-x64/revenant-engine.exe',
		'revenant-engine-linux-x64.tar.gz',
		'bin/linux-x64/revenant-engine'
	]) {
		assertIncludes(workflow, required, '.github/workflows/hexcore-installer.yml');
	}

	if (vscodeIgnore.split(/\r?\n/).some(line => /^\s*bin(?:\/|\*|$)/.test(line))) {
		errors.push('extensions/hexcore-revenant/.vscodeignore must not exclude bin/; the bundled backend is a release prebuild');
	}
}

function verifyPortableDistribution() {
	const updater = readText('src/vs/platform/update/electron-main/updateService.win32.ts');
	const workflow = readText('.github/workflows/hexcore-installer.yml');
	const manifestGenerator = readText('scripts/generate-hexcore-engine-manifest.cjs');
	readText('scripts/generate-hexcore-engine-manifest.test.cjs');

	assertIncludes(
		updater,
		'this.productService.updateUrl && this.productService.commit',
		'src/vs/platform/update/electron-main/updateService.win32.ts'
	);

	const helixStep = workflow.match(/- name: Fetch HexCore Helix Prebuilds \(Windows\)[\s\S]*?(?=\n\s+- name:)/)?.[0] || '';
	if (/continue-on-error:\s*true/.test(helixStep)) {
		errors.push('Windows Helix prebuild installation must not use continue-on-error');
	}
	for (const required of [
		'hexcore-helix.win32-x64-msvc.node',
		'Required Helix prebuild is missing after install',
		'generate-hexcore-engine-manifest.cjs',
		'generate-hexcore-engine-manifest.test.cjs',
		'hexcore-engine-manifest.json'
	]) {
		assertIncludes(workflow, required, '.github/workflows/hexcore-installer.yml');
	}

	for (const required of [
		'hexcore-capstone',
		'hexcore-remill',
		'hexcore-helix',
		'hexcore-souper',
		'hexcore-elixir',
		'hexcore-revenant',
		`'.node'`,
		`'.bc'`
	]) {
		assertIncludes(manifestGenerator, required, 'scripts/generate-hexcore-engine-manifest.cjs');
	}
}

function verifyInterfaceDefaults() {
	const product = readJson('product.json');
	const themePackage = readJson('extensions/theme-bathexcore/package.json');
	const theme = readJson('extensions/theme-bathexcore/themes/hexcore-analysis-dark.json');
	const workflow = readText('.github/workflows/hexcore-installer.yml');

	if (product?.configurationDefaults?.['workbench.colorTheme'] !== 'HexCore Analysis Dark') {
		errors.push('product.json must default to the HexCore Analysis Dark theme');
	}
	if (product?.configurationDefaults?.['workbench.iconTheme'] !== 'vs-seti') {
		errors.push('product.json must default to the Seti file icon theme');
	}
	const contributedTheme = themePackage?.contributes?.themes?.find(candidate => candidate.id === 'hexcore-analysis-dark');
	if (contributedTheme?.label !== 'HexCore Analysis Dark' || contributedTheme?.path !== './themes/hexcore-analysis-dark.json') {
		errors.push('theme-bathexcore must contribute HexCore Analysis Dark from the canonical theme path');
	}
	if (theme?.semanticHighlighting !== true || theme?.type !== 'dark') {
		errors.push('HexCore Analysis Dark must be a semantic dark theme');
	}
	assertIncludes(workflow, 'Verify packaged HexCore theme', '.github/workflows/hexcore-installer.yml');
	assertIncludes(workflow, 'hexcore-analysis-dark.json', '.github/workflows/hexcore-installer.yml');
}

function verifyExtensionCompileCoverage() {
	// A tsc-built extension declares "main": "./out/..." and is compiled by the
	// "Compile HexCore Extensions" step in hexcore-installer.yml. Its out/ tree is a
	// gitignored build artifact, so if the extension is missing from that compile loop the
	// shipped zip has no compiled entrypoint and the extension fails to activate ("Cannot
		// find module out/extension.js") - exactly the hexcore-elixir regression behind issue #36.
	//
	// This is a STATIC config check, NOT a disk check: the preflight step runs BEFORE the
	// "Compile HexCore Extensions" step in CI, so out/ does not exist yet at this point.
	// Asserting the compiled artifact exists would (and did) fail on EVERY extension. Instead
	// we parse the workflow and assert every out/-main extension is wired into the compile
		// loop of EVERY build job (Windows + Linux) - the elixir bug shipped because it was
	// omitted from both, and a single-job omission would silently break that platform's zip.
	const extensionsDir = path.join(root, 'extensions');
	if (!fs.existsSync(extensionsDir)) {
		errors.push('Missing directory: extensions');
		return;
	}

	const workflowRel = '.github/workflows/hexcore-installer.yml';
	const workflow = readText(workflowRel);
	if (!workflow) {
		return; // readText already recorded a "Missing file" error
	}

	// One "Compile HexCore Extensions" step per build job (Windows + Linux today).
	const compileJobCount = (workflow.match(/Compile HexCore Extensions/g) || []).length;

	// Count, per extension and package script, how many build lines reference it. Each line
	// looks like `cd ../hexcore-NAME && npm ci ... && npm run compile`; the first
	// hexcore-* token on such a line is the cd target. Native/prebuilt fetch steps use
	// `node`/bare `npm ci` (no `npm run ...`), so they are correctly ignored.
	const buildCounts = new Map();
	for (const line of workflow.split(/\r?\n/)) {
		const scriptMatch = line.match(/npm run (compile|build)\b/);
		if (!scriptMatch) {
			continue;
		}
		const match = line.match(/hexcore-[a-z0-9-]+/);
		if (match) {
			const key = `${match[0]}:${scriptMatch[1]}`;
			buildCounts.set(key, (buildCounts.get(key) || 0) + 1);
		}
	}

	const extensionDirs = fs.readdirSync(extensionsDir, { withFileTypes: true })
		.filter(entry => entry.isDirectory() && entry.name.startsWith('hexcore-'))
		.map(entry => entry.name);

	for (const extensionName of extensionDirs) {
		const packagePath = path.join('extensions', extensionName, 'package.json');
		const packageJson = readJson(packagePath);
		if (!packageJson) {
			continue;
		}

		// Native extensions (e.g. hexcore-helix, hexcore-remill) ship prebuilt. TypeScript
		// extensions use either the conventional compile -> out/ contract or build -> dist/.
		const main = packageJson.main;
		const packageScript = typeof main === 'string' && main.startsWith('./out/')
			? 'compile'
			: typeof main === 'string' && main.startsWith('dist/')
				? 'build'
				: undefined;
		if (!packageScript) {
			continue;
		}

		const count = buildCounts.get(`${extensionName}:${packageScript}`) || 0;
		if (count === 0) {
			errors.push(`${packagePath} has "main": "${main}" but ${extensionName} is not in the "Compile HexCore Extensions" step of ${workflowRel} - add 'cd .../${extensionName} && npm ci --ignore-scripts && npm run ${packageScript}' to every build job`);
		} else if (compileJobCount > 0 && count < compileJobCount) {
			errors.push(`${packagePath} has "main": "${main}" but ${extensionName} is built in only ${count} of ${compileJobCount} build jobs in ${workflowRel} - it must be in every job's "Compile HexCore Extensions" loop (Windows + Linux)`);
		}
	}
}

function verifyManifestActivationEvents() {
	const extensionsDir = path.join(root, 'extensions');
	if (!fs.existsSync(extensionsDir)) {
		errors.push('Missing directory: extensions');
		return;
	}

	const extensionDirs = fs.readdirSync(extensionsDir, { withFileTypes: true })
		.filter(entry => entry.isDirectory() && entry.name.startsWith('hexcore-'))
		.map(entry => entry.name);

	for (const extensionName of extensionDirs) {
		const packagePath = path.join('extensions', extensionName, 'package.json');
		const packageJson = readJson(packagePath);
		if (!packageJson) {
			continue;
		}

		if (typeof packageJson.main === 'string' && packageJson.main.length > 0) {
			if (!Array.isArray(packageJson.activationEvents)) {
				errors.push(`${packagePath} has "main" but is missing "activationEvents"`);
			}
		}
	}
}

verifyYaraCommands();
verifyPipelineCapabilities();
verifyBuildCoverage();
verifyDebuggerWorkerPackaging();
verifyRevenantPackaging();
verifyPortableDistribution();
verifyInterfaceDefaults();
verifyExtensionCompileCoverage();
verifyManifestActivationEvents();

if (errors.length > 0) {
	console.error('HexCore preflight checks failed:\n');
	for (const error of errors) {
		console.error(`- ${error}`);
	}
	process.exit(1);
}

console.log('HexCore preflight checks passed.');
