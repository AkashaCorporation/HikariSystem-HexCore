import * as path from 'path';

export interface DrcovOutputPaths {
	drcovPath: string;
	metadataPath: string;
}

/** Keep the requested artifact and its JSON metadata on distinct paths. */
export function resolveDrcovOutputPaths(requestedPath: string): DrcovOutputPaths {
	const extension = path.extname(requestedPath).toLowerCase();
	if (extension === '.drcov') {
		return {
			drcovPath: requestedPath,
			metadataPath: `${requestedPath}.json`,
		};
	}
	if (extension === '.json') {
		return {
			drcovPath: requestedPath.slice(0, -extension.length) + '.drcov',
			metadataPath: requestedPath,
		};
	}
	return {
		drcovPath: `${requestedPath}.drcov`,
		metadataPath: requestedPath,
	};
}
