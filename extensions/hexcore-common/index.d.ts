/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

export function formatBytes(bytes: number): string;
export function calculateEntropy(buffer: Buffer): number;
export function readNullTerminatedString(buffer: Buffer, maxLength?: number): string;
export function isPrintableASCII(byte: number): boolean;
export function toHexDump(buffer: Buffer, bytesPerLine?: number): string;
export function escapeHtml(text: string): string;
export function formatHex(value: number, padLength?: number): string;
export function processFileInChunks(
	filePath: string,
	chunkSize: number,
	processor: (chunk: Buffer, offset: number) => void | Promise<void>,
	onProgress?: (bytesProcessed: number, totalBytes: number) => void
): Promise<void>;

export interface NativeModuleLoadOptions {
	moduleName: string;
	candidatePaths?: string[];
}

export interface NativeModuleLoadResult<T> {
	module?: T;
	error?: Error;
	attemptedPaths: string[];
	errorMessage: string;
}

export function loadNativeModule<T = unknown>(options: NativeModuleLoadOptions): NativeModuleLoadResult<T>;

export function getHexCoreBaseCSS(): string;

export function riskLevelToColor(level: 'safe' | 'warning' | 'danger'): string;
export function entropyToColor(value: number): string;
