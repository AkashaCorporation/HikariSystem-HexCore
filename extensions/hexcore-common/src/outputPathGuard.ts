import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/** True when child is parent itself or a lexical descendant of parent. */
export function isWithinDir(parent: string, child: string): boolean {
	const relative = path.relative(path.resolve(parent), path.resolve(child));
	return relative === '' || (relative !== '..' && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative));
}

/** Resolve symlinks/junctions through the deepest existing ancestor. */
function resolveCanonicalPath(candidatePath: string): string {
	let existingAncestor = path.resolve(candidatePath);
	const missingSegments: string[] = [];

	while (!fs.existsSync(existingAncestor)) {
		const parent = path.dirname(existingAncestor);
		if (parent === existingAncestor) {
			return path.resolve(candidatePath);
		}
		missingSegments.unshift(path.basename(existingAncestor));
		existingAncestor = parent;
	}

	const canonicalAncestor = fs.realpathSync.native(existingAncestor);
	return path.resolve(canonicalAncestor, ...missingSegments);
}

/**
 * Return the canonical candidate when it is inside one of the allowed roots.
 * Existing symlinks/junctions are resolved so a lexical in-workspace path
 * cannot escape through a redirected parent directory.
 */
export function resolvePathWithinRoots(candidatePath: string, roots: readonly string[]): string | undefined {
	const canonicalCandidate = resolveCanonicalPath(candidatePath);
	for (const root of roots) {
		const canonicalRoot = resolveCanonicalPath(root);
		if (isWithinDir(canonicalRoot, canonicalCandidate)) {
			return canonicalCandidate;
		}
	}
	return undefined;
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
	const roots = [...workspaceRoots, homeDir];
	const resolved = resolvePathWithinRoots(outputPath, roots);
	if (!resolved) {
		throw new Error(`Output path must be within workspace or user home directory: ${path.resolve(outputPath)}`);
	}
	return resolved;
}
