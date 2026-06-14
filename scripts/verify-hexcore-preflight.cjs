/*---------------------------------------------------------------------------------------------
 *  HexCore CI preflight checks
 *  Ensures critical command registrations and build coverage are in sync.
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

	assertIncludes(winBuildScript, '"extensions/hexcore-yara"', 'scripts/build-hexcore-win.ps1');
	assertIncludes(gulpExtensions, "'extensions/hexcore-yara/tsconfig.json'", 'build/gulpfile.extensions.ts');
	assertIncludes(npmDirs, "'extensions/hexcore-yara'", 'build/npm/dirs.ts');
}

function verifyExtensionCompileCoverage() {
	// A tsc-built extension declares "main": "./out/..." and is compiled by the
	// "Compile HexCore Extensions" step in hexcore-installer.yml. Its out/ tree is a
	// gitignored build artifact, so if the extension is missing from that compile loop the
	// shipped zip has no compiled entrypoint and the extension fails to activate ("Cannot
	// find module out/extension.js") — exactly the hexcore-elixir regression behind issue #36.
	//
	// This is a STATIC config check, NOT a disk check: the preflight step runs BEFORE the
	// "Compile HexCore Extensions" step in CI, so out/ does not exist yet at this point.
	// Asserting the compiled artifact exists would (and did) fail on EVERY extension. Instead
	// we parse the workflow and assert every out/-main extension is wired into the compile
	// loop of EVERY build job (Windows + Linux) — the elixir bug shipped because it was
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

	// Count, per extension, how many `npm run compile` lines reference it. Each compile-loop
	// line looks like `cd ../hexcore-NAME && npm ci ... && npm run compile`; the first
	// hexcore-* token on such a line is the cd target. Native/prebuilt fetch steps use
	// `node`/bare `npm ci` (no `npm run compile`), so they are correctly ignored.
	const compileCounts = new Map();
	for (const line of workflow.split(/\r?\n/)) {
		if (!line.includes('npm run compile')) {
			continue;
		}
		const match = line.match(/hexcore-[a-z0-9-]+/);
		if (match) {
			compileCounts.set(match[0], (compileCounts.get(match[0]) || 0) + 1);
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

		// Only tsc-built extensions (./out/ main) need the compile loop. Native extensions
		// (e.g. hexcore-helix, hexcore-remill) ship prebuilt and point main elsewhere.
		const main = packageJson.main;
		if (typeof main !== 'string' || !main.startsWith('./out/')) {
			continue;
		}

		const count = compileCounts.get(extensionName) || 0;
		if (count === 0) {
			errors.push(`${packagePath} has "main": "${main}" but ${extensionName} is not in the "Compile HexCore Extensions" step of ${workflowRel} — add 'cd .../${extensionName} && npm ci --ignore-scripts && npm run compile' to every build job`);
		} else if (compileJobCount > 0 && count < compileJobCount) {
			errors.push(`${packagePath} has "main": "${main}" but ${extensionName} is compiled in only ${count} of ${compileJobCount} build jobs in ${workflowRel} — it must be in every job's "Compile HexCore Extensions" loop (Windows + Linux)`);
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
