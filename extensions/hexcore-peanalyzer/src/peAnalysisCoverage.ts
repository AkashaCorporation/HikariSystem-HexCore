export interface PEDataDirectoryLike {
	virtualAddress: number;
	size: number;
}

export interface PEAnalysisCoverageEntry {
	status: 'not-present' | 'parsed' | 'partial' | 'not-assessed';
	directoryRva: number;
	directorySize: number;
	recordCount: number;
	reason?: string;
}

export function assessPEAnalysisCoverage(
	directory: PEDataDirectoryLike | undefined,
	parserAvailable: boolean,
	recordCount: number,
): PEAnalysisCoverageEntry {
	const directoryRva = directory?.virtualAddress ?? 0;
	const directorySize = directory?.size ?? 0;
	if (directoryRva === 0 || directorySize === 0) {
		return { status: 'not-present', directoryRva, directorySize, recordCount: 0 };
	}
	if (!parserAvailable) {
		return {
			status: 'not-assessed',
			directoryRva,
			directorySize,
			recordCount: 0,
			reason: 'No parser is implemented for this directory in the shallow PE analyzer.',
		};
	}
	if (recordCount === 0) {
		return {
			status: 'partial',
			directoryRva,
			directorySize,
			recordCount: 0,
			reason: 'Directory is present but the bounded parser returned no records; empty and parse failure are not conflated.',
		};
	}
	return { status: 'parsed', directoryRva, directorySize, recordCount };
}
