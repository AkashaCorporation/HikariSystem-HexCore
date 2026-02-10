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
verifyManifestActivationEvents();

if (errors.length > 0) {
	console.error('HexCore preflight checks failed:\n');
	for (const error of errors) {
		console.error(`- ${error}`);
	}
	process.exit(1);
}

console.log('HexCore preflight checks passed.');
