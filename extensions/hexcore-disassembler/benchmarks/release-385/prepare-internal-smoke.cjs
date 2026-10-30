/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/
'use strict';

const fs = require('fs');
const path = require('path');

function copyDirectory(sourceRoot, outputRoot, name) {
	const source = path.join(sourceRoot, name);
	if (fs.existsSync(source)) {
		fs.cpSync(source, path.join(outputRoot, name), { recursive: true, force: false });
	}
}

function walk(directory, result = []) {
	for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
		const fullPath = path.join(directory, entry.name);
		if (entry.isDirectory()) {
			walk(fullPath, result);
		} else {
			result.push(fullPath);
		}
	}
	return result;
}

function rewriteJob(jobPath, sourceRoot, outputRoot) {
	const job = JSON.parse(fs.readFileSync(jobPath, 'utf8'));
	job.autoRun = false;
	if (typeof job.file === 'string') {
		const relativeJobPath = path.relative(path.join(outputRoot, 'jobs'), jobPath);
		const sourceJobPath = path.join(sourceRoot, 'jobs', relativeJobPath);
		const sourceTarget = path.isAbsolute(job.file)
			? job.file
			: path.resolve(path.dirname(sourceJobPath), job.file);
		const relative = path.relative(sourceRoot, sourceTarget);
		if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
			throw new Error(`Job target escapes the source suite: ${jobPath}`);
		}
		job.file = path.join(outputRoot, relative);
	}
	const jobName = path.basename(jobPath, '.hexcore_job.json');
	job.outDir = path.join(outputRoot, 'hexcore-reports', jobName);
	fs.writeFileSync(jobPath, `${JSON.stringify(job, null, 2)}\n`, 'utf8');
}

function main() {
	const [sourceArg, outputArg] = process.argv.slice(2);
	if (!sourceArg || !outputArg) {
		throw new Error('Usage: node prepare-internal-smoke.cjs <source-suite> <new-output-root>');
	}
	const sourceRoot = path.resolve(sourceArg);
	const outputRoot = path.resolve(outputArg);
	if (!fs.statSync(sourceRoot).isDirectory()) {
		throw new Error(`Source suite is not a directory: ${sourceRoot}`);
	}
	if (fs.existsSync(outputRoot)) {
		throw new Error(`Output root already exists: ${outputRoot}`);
	}
	fs.mkdirSync(outputRoot, { recursive: true });
	for (const name of ['.vscode', 'fixtures', 'rules', 'jobs']) {
		copyDirectory(sourceRoot, outputRoot, name);
	}
	for (const name of ['SUITE_MANIFEST.json', 'SMOKE_ASSESSMENT.md', 'SMOKE_ASSESSMENT.json']) {
		const source = path.join(sourceRoot, name);
		if (fs.existsSync(source)) {
			fs.copyFileSync(source, path.join(outputRoot, `baseline-${name}`), fs.constants.COPYFILE_EXCL);
		}
	}
	const jobs = walk(path.join(outputRoot, 'jobs'))
		.filter(file => file.endsWith('.hexcore_job.json'));
	for (const job of jobs) {
		rewriteJob(job, sourceRoot, outputRoot);
	}
	process.stdout.write(`${JSON.stringify({ outputRoot, jobs: jobs.length }, null, 2)}\n`);
}

main();
