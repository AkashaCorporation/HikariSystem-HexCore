import * as assert from 'assert';
import { preflightPeMachine } from './pePreflight';

function pe(machine: number): Buffer {
	const buffer = Buffer.alloc(0x100);
	buffer.write('MZ', 0, 'ascii');
	buffer.writeUInt32LE(0x80, 0x3c);
	buffer.writeUInt32LE(0x00004550, 0x80);
	buffer.writeUInt16LE(machine, 0x84);
	return buffer;
}

suite('Elixir target preflight', () => {
	test('accepts PE32+ x86_64', () => {
		assert.doesNotThrow(() => preflightPeMachine(pe(0x8664), 'target.exe'));
	});

	test('rejects PE32 x86 with an actionable message', () => {
		assert.throws(() => preflightPeMachine(pe(0x014c), 'target.exe'), /HexCore Debugger/);
	});

	test('rejects ELF before spawning the worker', () => {
		const elf = Buffer.alloc(0x100);
		elf.set([0x7f, 0x45, 0x4c, 0x46]);
		assert.throws(() => preflightPeMachine(elf, 'target.elf'), /PE32\+ x86_64 only/);
	});
});
