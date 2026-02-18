/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { hexDumpRange } from './hexDump';
import { hexSearchPattern } from './hexSearch';

suite('Unit Tests: hexDump', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hexviewer-unit-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * Validates: Requirements 7.1
	 * Dump offset 0, size 16 on a known file — verify raw base64 decodes
	 * to correct bytes and hexDump string format is correct.
	 */
	test('dump offset 0 size 16 on known file', () => {
		const knownBytes = Buffer.from([
			0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
			0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00
		]);
		const filePath = path.join(tmpDir, 'known.bin');
		fs.writeFileSync(filePath, knownBytes);

		const result = hexDumpRange(filePath, 0, 16);

		// raw base64 decodes to the original bytes
		const decoded = Buffer.from(result.raw, 'base64');
		assert.ok(decoded.equals(knownBytes), 'raw base64 must decode to original bytes');

		// metadata
		assert.strictEqual(result.offset, 0);
		assert.strictEqual(result.size, 16);
		assert.strictEqual(result.filePath, filePath);
		assert.strictEqual(typeof result.generatedAt, 'string');

		// hexDump string contains the hex representation
		assert.ok(result.hexDump.includes('4D 5A 90 00'), 'hexDump must contain first bytes in hex');
		assert.ok(result.hexDump.startsWith('00000000'), 'hexDump must start with offset 00000000');
	});

	/**
	 * Validates: Requirements 7.5
	 * Offset exceeding file size throws an error.
	 */
	test('dump with offset exceeding file size throws error', () => {
		const filePath = path.join(tmpDir, 'small.bin');
		fs.writeFileSync(filePath, Buffer.from([0x01, 0x02, 0x03]));

		assert.throws(
			() => hexDumpRange(filePath, 100, 16),
			(err: Error) => err.message.includes('exceeds file size')
		);
	});

	/**
	 * Validates: Requirements 7.5
	 * Offset + size exceeding file size throws an error.
	 */
	test('dump with offset+size exceeding file size throws error', () => {
		const filePath = path.join(tmpDir, 'medium.bin');
		fs.writeFileSync(filePath, Buffer.alloc(32, 0xAA));

		assert.throws(
			() => hexDumpRange(filePath, 20, 16),
			(err: Error) => err.message.includes('exceeds file size')
		);
	});

	/**
	 * Validates: Requirements 7.1
	 * File not found throws an error.
	 */
	test('dump on non-existent file throws error', () => {
		const filePath = path.join(tmpDir, 'does-not-exist.bin');

		assert.throws(
			() => hexDumpRange(filePath, 0, 16),
			(err: Error) => err.message.includes('File not found')
		);
	});
});

suite('Unit Tests: hexSearch', () => {

	let tmpDir: string;

	setup(() => {
		tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'hexcore-hexviewer-unit-'));
	});

	teardown(() => {
		fs.rmSync(tmpDir, { recursive: true, force: true });
	});

	/**
	 * Validates: Requirements 7.3
	 * Search for "4D5A" in a file starting with MZ header — finds at offset 0.
	 */
	test('search "4D5A" in PE-like file finds match at offset 0', () => {
		const peHeader = Buffer.alloc(64, 0x00);
		peHeader[0] = 0x4D; // M
		peHeader[1] = 0x5A; // Z
		const filePath = path.join(tmpDir, 'pe.bin');
		fs.writeFileSync(filePath, peHeader);

		const result = hexSearchPattern(filePath, '4D5A');

		assert.strictEqual(result.totalMatches, 1);
		assert.strictEqual(result.matches[0].offset, 0);
		assert.strictEqual(result.pattern, '4D5A');
		assert.strictEqual(result.filePath, filePath);
	});

	/**
	 * Validates: Requirements 7.6
	 * Invalid hex pattern (odd length) throws an error.
	 */
	test('search with odd-length hex pattern throws error', () => {
		const filePath = path.join(tmpDir, 'dummy.bin');
		fs.writeFileSync(filePath, Buffer.alloc(16, 0x00));

		assert.throws(
			() => hexSearchPattern(filePath, '4D5'),
			(err: Error) => err.message.includes('even number')
		);
	});

	/**
	 * Validates: Requirements 7.6
	 * Invalid hex characters throw an error.
	 */
	test('search with invalid hex characters throws error', () => {
		const filePath = path.join(tmpDir, 'dummy.bin');
		fs.writeFileSync(filePath, Buffer.alloc(16, 0x00));

		assert.throws(
			() => hexSearchPattern(filePath, 'ZZZZ'),
			(err: Error) => err.message.includes('Only hex characters')
		);
	});

	/**
	 * Validates: Requirements 7.3
	 * Search in empty file returns 0 matches.
	 */
	test('search in empty file returns 0 matches', () => {
		const filePath = path.join(tmpDir, 'empty.bin');
		fs.writeFileSync(filePath, Buffer.alloc(0));

		const result = hexSearchPattern(filePath, '4D5A');

		assert.strictEqual(result.totalMatches, 0);
		assert.deepStrictEqual(result.matches, []);
	});

	/**
	 * Validates: Requirements 7.3
	 * Pattern spanning chunk boundary (64KB) is found correctly.
	 * Creates a file > 64KB with a 4-byte pattern placed exactly at the
	 * 64KB boundary (2 bytes before, 2 bytes after).
	 */
	test('search finds pattern spanning 64KB chunk boundary', () => {
		const CHUNK_SIZE = 64 * 1024;
		const pattern = Buffer.from([0xDE, 0xAD, 0xBE, 0xEF]);
		const fileSize = CHUNK_SIZE + 1024;

		// Fill with 0x00 — safe because pattern bytes are non-zero
		const buf = Buffer.alloc(fileSize, 0x00);

		// Place pattern so it straddles the 64KB boundary:
		// bytes at offsets CHUNK_SIZE-2, CHUNK_SIZE-1, CHUNK_SIZE, CHUNK_SIZE+1
		const boundaryOffset = CHUNK_SIZE - 2;
		pattern.copy(buf, boundaryOffset);

		const filePath = path.join(tmpDir, 'boundary.bin');
		fs.writeFileSync(filePath, buf);

		const result = hexSearchPattern(filePath, 'DEADBEEF');

		assert.strictEqual(result.totalMatches, 1, 'Must find exactly 1 match at chunk boundary');
		assert.strictEqual(result.matches[0].offset, boundaryOffset,
			`Match must be at offset ${boundaryOffset} (chunk boundary - 2)`);
	});
});
