import * as assert from 'assert';
import * as os from 'os';
import * as path from 'path';
import { assertWithinWorkspaceOrHome, isWithinDir } from './outputPathGuard';

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

console.log('outputPathGuard: 6/6 passing');
