import * as path from 'path';

const PE_MACHINE_LABELS: Record<number, string> = {
	0x014c: 'x86 (PE32, IMAGE_FILE_MACHINE_I386)',
	0x0200: 'ia64 (IMAGE_FILE_MACHINE_IA64)',
	0x8664: 'x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64)',
	0x01c0: 'ARM (IMAGE_FILE_MACHINE_ARM)',
	0xaa64: 'ARM64 (IMAGE_FILE_MACHINE_ARM64)',
	0x01c4: 'ARM Thumb-2 (IMAGE_FILE_MACHINE_ARMNT)'
};

export function preflightPeMachine(data: Buffer, binaryPath: string): void {
	if (data.length < 0x40) {
		throw new Error(`Binary too small to be a PE (${data.length} bytes): ${binaryPath}`);
	}
	if (data[0] !== 0x4d || data[1] !== 0x5a) {
		throw new Error(`Elixir currently supports PE32+ x86_64 only; ${path.basename(binaryPath)} is not a PE file.`);
	}
	const lfanew = data.readUInt32LE(0x3c);
	if (lfanew + 24 > data.length) {
		throw new Error(`Invalid PE header offset 0x${lfanew.toString(16)}: ${binaryPath}`);
	}
	if (data.readUInt32LE(lfanew) !== 0x00004550) {
		throw new Error(`Not a PE file (missing PE\\0\\0 signature): ${binaryPath}`);
	}
	const machine = data.readUInt16LE(lfanew + 4);
	if (machine !== 0x8664) {
		const label = PE_MACHINE_LABELS[machine] ?? `unknown (0x${machine.toString(16)})`;
		throw new Error(
			`Elixir requires x86_64 (PE32+, IMAGE_FILE_MACHINE_AMD64=0x8664); ` +
			`got ${label} — ${path.basename(binaryPath)}. Use the HexCore Debugger for this target.`
		);
	}
}
