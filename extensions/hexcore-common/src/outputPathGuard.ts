import * as os from 'os';
import * as path from 'path';

/** True when child is parent itself or a lexical descendant of parent. */
export function isWithinDir(parent: string, child: string): boolean {
	const relative = path.relative(path.resolve(parent), path.resolve(child));
	return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

/**
 * Validate a headless export path against workspace roots and the user home.
 * Returns the normalized absolute path that callers must use for the write.
 */
export function assertWithinWorkspaceOrHome(
	outputPath: string,
	workspaceRoots: readonly string[],
	homeDir: string = os.homedir()
): string {
	const resolved = path.resolve(outputPath);
	const roots = [...workspaceRoots, homeDir];
	if (!roots.some(root => isWithinDir(root, resolved))) {
		throw new Error(`Output path must be within workspace or user home directory: ${resolved}`);
	}
	return resolved;
}
