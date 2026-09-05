import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { assertWithinWorkspaceOrHome, isWithinDir, resolvePathWithinRoots } from './outputPathGuard';

const base = path.join(os.tmpdir(), 'hexcore-output-guard');
const workspace = path.join(base, 'workspace');
const home = path.join(base, 'home');

assert.strictEqual(isWithinDir(workspace, path.join(workspace, 'reports', 'out.json')), true);
assert.strictEqual(isWithinDir(workspace, path.join(base, 'workspace-sibling', 'out.json')), false);
assert.strictEqual(
	assertWithinWorkspaceOrHome(path.join(workspace, 'out.json'), [workspace], home),
	path.resolve(workspace, 'out.json')
);
assert.strictEqual(
	assertWithinWorkspaceOrHome(path.join(home, 'out.json'), [workspace], home),
	path.resolve(home, 'out.json')
);
assert.throws(
	() => assertWithinWorkspaceOrHome(path.join(base, 'workspace-sibling', 'out.json'), [workspace], home),
	/within workspace or user home/
);
assert.throws(
	() => assertWithinWorkspaceOrHome(path.join(workspace, '..', 'escaped', 'out.json'), [workspace], home),
	/within workspace or user home/
);

if (process.platform === 'win32') {
	assert.strictEqual(
		resolvePathWithinRoots(path.join(workspace.toLowerCase(), 'reports', 'out.json'), [workspace.toUpperCase()]),
		path.resolve(workspace, 'reports', 'out.json')
	);
}

const symlinkBase = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-output-guard-link-'));
try {
	const symlinkWorkspace = path.join(symlinkBase, 'workspace');
	const outside = path.join(symlinkBase, 'outside');
	const redirected = path.join(symlinkWorkspace, 'redirected');
	fs.mkdirSync(symlinkWorkspace, { recursive: true });
	fs.mkdirSync(outside, { recursive: true });
	fs.symlinkSync(outside, redirected, process.platform === 'win32' ? 'junction' : 'dir');
	assert.strictEqual(resolvePathWithinRoots(path.join(redirected, 'out.json'), [symlinkWorkspace]), undefined);
} finally {
	fs.rmSync(symlinkBase, { recursive: true, force: true });
}

console.log(`outputPathGuard: ${process.platform === 'win32' ? 8 : 7}/8 passing (${process.platform === 'win32' ? 0 : 1} Windows-only)`);
