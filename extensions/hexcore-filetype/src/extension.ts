/*---------------------------------------------------------------------------------------------
 *  HexCore File Type Detector v1.0.0
 *  Identify true file type using magic bytes signature detection
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as vscode from 'vscode';
import * as fs from 'fs';
import * as path from 'path';

type OutputFormat = 'json' | 'md';

interface CommandOutputOptions {
	path: string;
	format?: OutputFormat;
}

interface DetectFileTypeCommandOptions {
	file?: string;
	output?: CommandOutputOptions;
	quiet?: boolean;
}

interface FileSignature {
	name: string;
	extension: string;
	category: string;
	magic: number[];
	offset?: number;
	description: string;
}

interface DetectionMatch {
	name: string;
	extension: string;
	category: string;
	description: string;
	magicHex: string;
	offset: number;
}

interface FileTypeDetectionResult {
	fileName: string;
	filePath: string;
	fileSize: number;
	currentExtension: string;
	magicBytesHex: string;
	matches: DetectionMatch[];
	extensionMatch: boolean;
	suggestedExtension?: string;
	reportMarkdown: string;
}

// Comprehensive magic bytes database
const SIGNATURES: FileSignature[] = [
	// Executables
	{ name: 'Windows Executable', extension: 'exe/dll', category: 'Executable', magic: [0x4D, 0x5A], description: 'PE/MZ executable' },
	{ name: 'ELF Binary', extension: 'elf/so', category: 'Executable', magic: [0x7F, 0x45, 0x4C, 0x46], description: 'Linux/Unix executable' },
	{ name: 'Mach-O 32-bit', extension: 'macho', category: 'Executable', magic: [0xFE, 0xED, 0xFA, 0xCE], description: 'macOS executable' },
	{ name: 'Mach-O 64-bit', extension: 'macho', category: 'Executable', magic: [0xFE, 0xED, 0xFA, 0xCF], description: 'macOS 64-bit executable' },
	{ name: 'Java Class', extension: 'class', category: 'Executable', magic: [0xCA, 0xFE, 0xBA, 0xBE], description: 'Java bytecode' },
	{ name: 'DEX', extension: 'dex', category: 'Executable', magic: [0x64, 0x65, 0x78, 0x0A], description: 'Android Dalvik executable' },

	// Archives
	{ name: 'ZIP Archive', extension: 'zip', category: 'Archive', magic: [0x50, 0x4B, 0x03, 0x04], description: 'ZIP compressed file' },
	{ name: 'ZIP Empty', extension: 'zip', category: 'Archive', magic: [0x50, 0x4B, 0x05, 0x06], description: 'Empty ZIP archive' },
	{ name: 'RAR Archive', extension: 'rar', category: 'Archive', magic: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], description: 'RAR compressed file' },
	{ name: '7-Zip Archive', extension: '7z', category: 'Archive', magic: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], description: '7-Zip compressed file' },
	{ name: 'GZIP', extension: 'gz', category: 'Archive', magic: [0x1F, 0x8B], description: 'GZIP compressed file' },
	{ name: 'TAR', extension: 'tar', category: 'Archive', magic: [0x75, 0x73, 0x74, 0x61, 0x72], offset: 257, description: 'TAR archive' },
	{ name: 'XZ', extension: 'xz', category: 'Archive', magic: [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], description: 'XZ compressed file' },
	{ name: 'BZIP2', extension: 'bz2', category: 'Archive', magic: [0x42, 0x5A, 0x68], description: 'BZIP2 compressed file' },

	// Images
	{ name: 'PNG Image', extension: 'png', category: 'Image', magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], description: 'PNG image' },
	{ name: 'JPEG Image', extension: 'jpg', category: 'Image', magic: [0xFF, 0xD8, 0xFF], description: 'JPEG image' },
	{ name: 'GIF Image', extension: 'gif', category: 'Image', magic: [0x47, 0x49, 0x46, 0x38], description: 'GIF image' },
	{ name: 'BMP Image', extension: 'bmp', category: 'Image', magic: [0x42, 0x4D], description: 'Bitmap image' },
	{ name: 'WebP Image', extension: 'webp', category: 'Image', magic: [0x52, 0x49, 0x46, 0x46], description: 'WebP image (RIFF container)' },
	{ name: 'ICO Icon', extension: 'ico', category: 'Image', magic: [0x00, 0x00, 0x01, 0x00], description: 'Windows icon' },
	{ name: 'TIFF Image', extension: 'tiff', category: 'Image', magic: [0x49, 0x49, 0x2A, 0x00], description: 'TIFF image (little-endian)' },

	// Documents
	{ name: 'PDF Document', extension: 'pdf', category: 'Document', magic: [0x25, 0x50, 0x44, 0x46], description: 'PDF document' },
	{ name: 'Office Document (OOXML)', extension: 'docx/xlsx/pptx', category: 'Document', magic: [0x50, 0x4B, 0x03, 0x04], description: 'Microsoft Office Open XML' },
	{ name: 'Office Document (OLE)', extension: 'doc/xls/ppt', category: 'Document', magic: [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1], description: 'Microsoft OLE Compound' },
	{ name: 'RTF Document', extension: 'rtf', category: 'Document', magic: [0x7B, 0x5C, 0x72, 0x74, 0x66], description: 'Rich Text Format' },

	// Audio/Video
	{ name: 'MP3 Audio', extension: 'mp3', category: 'Audio', magic: [0xFF, 0xFB], description: 'MP3 audio' },
	{ name: 'MP3 Audio (ID3)', extension: 'mp3', category: 'Audio', magic: [0x49, 0x44, 0x33], description: 'MP3 with ID3 tag' },
	{ name: 'WAV Audio', extension: 'wav', category: 'Audio', magic: [0x52, 0x49, 0x46, 0x46], description: 'WAV audio (RIFF container)' },
	{ name: 'OGG Audio', extension: 'ogg', category: 'Audio', magic: [0x4F, 0x67, 0x67, 0x53], description: 'OGG Vorbis audio' },
	{ name: 'FLAC Audio', extension: 'flac', category: 'Audio', magic: [0x66, 0x4C, 0x61, 0x43], description: 'FLAC lossless audio' },
	{ name: 'MP4 Video', extension: 'mp4', category: 'Video', magic: [0x00, 0x00, 0x00], description: 'MP4/MOV container' },
	{ name: 'AVI Video', extension: 'avi', category: 'Video', magic: [0x52, 0x49, 0x46, 0x46], description: 'AVI video (RIFF container)' },
	{ name: 'MKV Video', extension: 'mkv', category: 'Video', magic: [0x1A, 0x45, 0xDF, 0xA3], description: 'Matroska video' },
	{ name: 'FLV Video', extension: 'flv', category: 'Video', magic: [0x46, 0x4C, 0x56, 0x01], description: 'Flash video' },

	// Database
	{ name: 'SQLite Database', extension: 'sqlite/db', category: 'Database', magic: [0x53, 0x51, 0x4C, 0x69, 0x74, 0x65], description: 'SQLite database' },

	// Scripts/Text
	{ name: 'Shell Script', extension: 'sh', category: 'Script', magic: [0x23, 0x21], description: 'Unix shell script (shebang)' },
	{ name: 'XML Document', extension: 'xml', category: 'Text', magic: [0x3C, 0x3F, 0x78, 0x6D, 0x6C], description: 'XML document' },
	{ name: 'HTML Document', extension: 'html', category: 'Text', magic: [0x3C, 0x21, 0x44, 0x4F, 0x43], description: 'HTML document' },

	// Crypto/Keys
	{ name: 'PGP Public Key', extension: 'pgp', category: 'Crypto', magic: [0x99, 0x01], description: 'PGP public key' },
	{ name: 'SSH Private Key', extension: 'pem', category: 'Crypto', magic: [0x2D, 0x2D, 0x2D, 0x2D, 0x2D], description: 'PEM encoded key' },

	// Firmware/ROM
	{ name: 'Android Boot', extension: 'img', category: 'Firmware', magic: [0x41, 0x4E, 0x44, 0x52, 0x4F, 0x49, 0x44, 0x21], description: 'Android boot image' },

	// Virtual Machines
	{ name: 'VMware VMDK', extension: 'vmdk', category: 'VM', magic: [0x4B, 0x44, 0x4D, 0x56], description: 'VMware disk image' },
	{ name: 'VirtualBox VDI', extension: 'vdi', category: 'VM', magic: [0x3C, 0x3C, 0x3C, 0x20], description: 'VirtualBox disk image' },
];

export function activate(context: vscode.ExtensionContext) {
	console.log('HexCore File Type Detector extension activated');

	context.subscriptions.push(
		vscode.commands.registerCommand('hexcore.filetype.detect', async (arg?: vscode.Uri | DetectFileTypeCommandOptions) => {
			const options = normalizeOptions(arg);
			const uri = await resolveTargetUri(arg, options);
			if (!uri) {
				return;
			}

			try {
				return await detectFileType(uri, options);
			} catch (error: unknown) {
				if (!options.quiet) {
					vscode.window.showErrorMessage(`File type detection failed: ${toErrorMessage(error)}`);
				}
				throw error;
			}
		})
	);
}

function normalizeOptions(arg?: vscode.Uri | DetectFileTypeCommandOptions): DetectFileTypeCommandOptions {
	if (arg instanceof vscode.Uri || arg === undefined) {
		return {};
	}
	return arg;
}

async function resolveTargetUri(
	arg: vscode.Uri | DetectFileTypeCommandOptions | undefined,
	options: DetectFileTypeCommandOptions
): Promise<vscode.Uri | undefined> {
	if (arg instanceof vscode.Uri) {
		return arg;
	}

	if (typeof options.file === 'string' && options.file.length > 0) {
		return vscode.Uri.file(options.file);
	}

	const activeUri = getActiveFileUri();
	if (activeUri) {
		return activeUri;
	}

	if (options.quiet) {
		return undefined;
	}

	const files = await vscode.window.showOpenDialog({
		canSelectMany: false,
		canSelectFiles: true,
		title: 'Select file to identify'
	});
	return files?.[0];
}

function getActiveFileUri(): vscode.Uri | undefined {
	const active = vscode.window.activeTextEditor?.document.uri;
	if (!active || active.scheme !== 'file') {
		return undefined;
	}
	return active;
}

async function detectFileType(uri: vscode.Uri, options: DetectFileTypeCommandOptions): Promise<FileTypeDetectionResult> {
	const filePath = uri.fsPath;
	const fileName = path.basename(filePath);
	const fileExtension = path.extname(filePath).toLowerCase().replace('.', '');

	const stats = fs.statSync(filePath);
	const fd = fs.openSync(filePath, 'r');
	const buffer = Buffer.alloc(Math.min(512, stats.size));
	try {
		fs.readSync(fd, buffer, 0, buffer.length, 0);
	} finally {
		fs.closeSync(fd);
	}

	const matches = findMatchingSignatures(buffer);
	let extensionMatch = true;
	let suggestedExtension: string | undefined;

	if (matches.length > 0) {
		const expectedExts = matches[0].extension.split('/');
		if (!expectedExts.includes(fileExtension) && fileExtension !== '') {
			extensionMatch = false;
			suggestedExtension = expectedExts[0];
		}
	}

	const report = generateReport(fileName, filePath, stats.size, fileExtension, buffer, matches, extensionMatch, suggestedExtension ?? '');
	const result: FileTypeDetectionResult = {
		fileName,
		filePath,
		fileSize: stats.size,
		currentExtension: fileExtension,
		magicBytesHex: buffer.subarray(0, 32).toString('hex').toUpperCase().match(/.{2}/g)?.join(' ') ?? '',
		matches: matches.map(match => ({
			name: match.name,
			extension: match.extension,
			category: match.category,
			description: match.description,
			magicHex: match.magic.map(byte => byte.toString(16).toUpperCase().padStart(2, '0')).join(' '),
			offset: match.offset ?? 0
		})),
		extensionMatch,
		suggestedExtension,
		reportMarkdown: report
	};

	if (options.output) {
		writeOutput(result, options.output);
	}

	if (!options.quiet) {
		const doc = await vscode.workspace.openTextDocument({
			content: report,
			language: 'markdown'
		});
		await vscode.window.showTextDocument(doc, { preview: false });

		if (!extensionMatch && matches.length > 0 && suggestedExtension) {
			vscode.window.showWarningMessage(
				`File extension mismatch! "${fileName}" appears to be "${matches[0].name}" (expected .${suggestedExtension})`
			);
		}
	}

	return result;
}

function writeOutput(result: FileTypeDetectionResult, output: CommandOutputOptions): void {
	const outputFormat = normalizeOutputFormat(output.path, output.format);

	// Validate output path is within workspace or user home to prevent arbitrary writes
	const resolvedPath = path.resolve(output.path);
	const workspaceFolders = vscode.workspace.workspaceFolders;
	const homeDir = require('os').homedir();
	const isInWorkspace = workspaceFolders?.some(f => resolvedPath.startsWith(f.uri.fsPath));
	const isInHome = resolvedPath.startsWith(homeDir);
	if (!isInWorkspace && !isInHome) {
		throw new Error(`Output path must be within workspace or user home directory: ${resolvedPath}`);
	}

	fs.mkdirSync(path.dirname(resolvedPath), { recursive: true });

	if (outputFormat === 'md') {
		fs.writeFileSync(resolvedPath, result.reportMarkdown, 'utf8');
		return;
	}

	fs.writeFileSync(
		output.path,
		JSON.stringify(
			{
				fileName: result.fileName,
				filePath: result.filePath,
				fileSize: result.fileSize,
				currentExtension: result.currentExtension,
				magicBytesHex: result.magicBytesHex,
				matches: result.matches,
				extensionMatch: result.extensionMatch,
				suggestedExtension: result.suggestedExtension,
				generatedAt: new Date().toISOString()
			},
			null,
			2
		),
		'utf8'
	);
}

function normalizeOutputFormat(outputPath: string, format?: OutputFormat): OutputFormat {
	if (format === 'json' || format === 'md') {
		return format;
	}
	return path.extname(outputPath).toLowerCase() === '.md' ? 'md' : 'json';
}

function findMatchingSignatures(buffer: Buffer): FileSignature[] {
	const matches: FileSignature[] = [];

	for (const sig of SIGNATURES) {
		const offset = sig.offset ?? 0;
		if (offset + sig.magic.length > buffer.length) {
			continue;
		}

		let match = true;
		for (let i = 0; i < sig.magic.length; i++) {
			if (buffer[offset + i] !== sig.magic[i]) {
				match = false;
				break;
			}
		}

		if (match) {
			matches.push(sig);
		}
	}

	return matches;
}

function generateReport(
	fileName: string,
	filePath: string,
	fileSize: number,
	currentExtension: string,
	buffer: Buffer,
	matches: FileSignature[],
	extensionMatch: boolean,
	suggestedExtension: string
): string {
	const hexDump = buffer.subarray(0, 32).toString('hex').toUpperCase().match(/.{2}/g)?.join(' ') || '';

	let report = `# HexCore File Type Detection Report

## File Information

| Property | Value |
|----------|-------|
| **File Name** | ${fileName} |
| **File Path** | ${filePath} |
| **File Size** | ${formatBytes(fileSize)} |
| **Current Extension** | .${currentExtension || '(none)'} |

---

## Magic Bytes (First 32 Bytes)

\`\`\`
${hexDump}
\`\`\`

---

## Detection Results

`;

	if (matches.length > 0) {
		const primary = matches[0];

		report += `### Detected File Type

| Property | Value |
|----------|-------|
| **Type** | ${primary.name} |
| **Category** | ${primary.category} |
| **Expected Extension** | .${primary.extension} |
| **Description** | ${primary.description} |
| **Magic Bytes** | ${primary.magic.map(b => b.toString(16).toUpperCase().padStart(2, '0')).join(' ')} |

`;

		if (!extensionMatch) {
			report += `> **WARNING: Extension Mismatch**
>
> The file extension ".${currentExtension}" does not match the detected type.
> This could indicate:
> - File was renamed to hide its true type
> - Possible malicious file disguised as another format
> - Corrupted file
>
> **Suggested extension:** .${suggestedExtension}

`;
		} else {
			report += `**Status:** Extension matches detected file type.

`;
		}

		if (matches.length > 1) {
			report += `### Alternative Matches

| Type | Category | Extension |
|------|----------|-----------|
`;
			for (const match of matches.slice(1)) {
				report += `| ${match.name} | ${match.category} | .${match.extension} |\n`;
			}
			report += '\n';
		}
	} else {
		report += `### Unknown File Type

No matching file signature found in the database.

This could be:
- A text file or script
- An unknown or proprietary format
- A corrupted file
- Encrypted or obfuscated data

`;
	}

	report += `---

## Signature Database

Total signatures in database: **${SIGNATURES.length}**

Categories: Executable, Archive, Image, Document, Audio, Video, Database, Script, Crypto, Firmware, VM

---
*Generated by HexCore File Type Detector v1.0.0*
`;

	return report;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) {
		return '0 B';
	}
	const k = 1024;
	const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
	const i = Math.floor(Math.log(bytes) / Math.log(k));
	return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function toErrorMessage(error: unknown): string {
	if (error instanceof Error) {
		return error.message;
	}
	return String(error);
}

export function deactivate() { }
