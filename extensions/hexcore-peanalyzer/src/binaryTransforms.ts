import * as fs from 'fs';
import { analyzePEFile, type SectionHeader } from './peParser';

export const DEFAULT_TRANSFORM_LIMIT = 256 * 1024 * 1024;
export const MAX_TRANSFORM_LIMIT = 1024 * 1024 * 1024;

export interface ExtractedSection {
	bytes: Buffer;
	section: SectionHeader;
}

export function normalizeTransformLimit(value?: number): number {
	if (value === undefined) {
		return DEFAULT_TRANSFORM_LIMIT;
	}
	if (!Number.isSafeInteger(value) || value <= 0 || value > MAX_TRANSFORM_LIMIT) {
		throw new Error(`maxBytes must be an integer in [1, ${MAX_TRANSFORM_LIMIT}]`);
	}
	return value;
}

export async function extractPESectionBytes(
	filePath: string,
	sectionName: string,
	maxBytes = DEFAULT_TRANSFORM_LIMIT
): Promise<ExtractedSection> {
	const limit = normalizeTransformLimit(maxBytes);
	const analysis = await analyzePEFile(filePath);
	if (!analysis.isPE) {
		throw new Error(`extractSection requires a valid PE file: ${analysis.error ?? 'PE parsing failed'}`);
	}
	const normalizedName = sectionName.trim().toLowerCase();
	if (!normalizedName) {
		throw new Error('extractSection requires a non-empty section name');
	}
	const section = analysis.sections.find(candidate => candidate.name.toLowerCase() === normalizedName);
	if (!section) {
		throw new Error(`PE section not found: ${sectionName}`);
	}
	if (section.sizeOfRawData > limit) {
		throw new Error(`PE section ${section.name} is ${section.sizeOfRawData} bytes, above maxBytes=${limit}`);
	}
	const fileSize = fs.statSync(filePath).size;
	const end = section.pointerToRawData + section.sizeOfRawData;
	if (!Number.isSafeInteger(end) || section.pointerToRawData < 0 || end > fileSize) {
		throw new Error(
			`PE section ${section.name} raw range [${section.pointerToRawData}, ${end}) exceeds file size ${fileSize}`
		);
	}
	const handle = fs.openSync(filePath, 'r');
	try {
		const bytes = Buffer.alloc(section.sizeOfRawData);
		const read = fs.readSync(handle, bytes, 0, bytes.length, section.pointerToRawData);
		if (read !== bytes.length) {
			throw new Error(`Short read extracting ${section.name}: expected ${bytes.length}, received ${read}`);
		}
		return { bytes, section };
	} finally {
		fs.closeSync(handle);
	}
}

/** Standard RC4 KSA + PRGA with an optional bounded keystream drop. */
export function rc4Transform(input: Buffer, key: Buffer, drop = 0): Buffer {
	if (key.length === 0 || key.length > 65536) {
		throw new Error('RC4 key length must be in [1, 65536] bytes');
	}
	if (!Number.isSafeInteger(drop) || drop < 0 || drop > 16 * 1024 * 1024) {
		throw new Error('RC4 drop must be an integer in [0, 16777216]');
	}

	const state = new Uint8Array(256);
	for (let i = 0; i < state.length; i++) {
		state[i] = i;
	}
	let j = 0;
	for (let i = 0; i < state.length; i++) {
		j = (j + state[i] + key[i % key.length]) & 0xff;
		[state[i], state[j]] = [state[j], state[i]];
	}

	let i = 0;
	j = 0;
	const nextByte = (): number => {
		i = (i + 1) & 0xff;
		j = (j + state[i]) & 0xff;
		[state[i], state[j]] = [state[j], state[i]];
		return state[(state[i] + state[j]) & 0xff];
	};
	for (let skipped = 0; skipped < drop; skipped++) {
		nextByte();
	}

	const output = Buffer.allocUnsafe(input.length);
	for (let offset = 0; offset < input.length; offset++) {
		output[offset] = input[offset] ^ nextByte();
	}
	return output;
}

export function decodeTransformKey(options: {
	key?: string | number[];
	keyHex?: string;
	keyBase64?: string;
}): Buffer {
	const supplied = [options.key !== undefined, options.keyHex !== undefined, options.keyBase64 !== undefined]
		.filter(Boolean).length;
	if (supplied !== 1) {
		throw new Error('Provide exactly one RC4 key: key (UTF-8 or byte array), keyHex, or keyBase64');
	}
	let key: Buffer;
	if (Array.isArray(options.key)) {
		if (options.key.some(value => !Number.isInteger(value) || value < 0 || value > 255)) {
			throw new Error('RC4 key byte arrays may contain only integers in [0, 255]');
		}
		key = Buffer.from(options.key);
	} else if (typeof options.key === 'string') {
		key = Buffer.from(options.key, 'utf8');
	} else if (typeof options.keyHex === 'string') {
		if (options.keyHex.length % 2 !== 0 || !/^[\da-f]*$/i.test(options.keyHex)) {
			throw new Error('keyHex must contain an even number of hexadecimal digits');
		}
		key = Buffer.from(options.keyHex, 'hex');
	} else {
		key = Buffer.from(options.keyBase64!, 'base64');
	}
	if (key.length === 0) {
		throw new Error('RC4 key must not be empty');
	}
	return key;
}
