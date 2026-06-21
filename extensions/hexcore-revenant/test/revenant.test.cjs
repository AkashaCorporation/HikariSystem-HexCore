// HexCore Revenant -- base validation suite (dependency-free, node:assert).
// Run:  node test/revenant.test.cjs
// Hardens the pre-alpha before the engine contract is frozen: managed C#/IL,
// mixed-mode, native refusal, corrupt/truncated, garbage, missing file, and the
// detectDotNet unit checks. Requires the compiled out/ (run tsc first).
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { decompile, detectDotNet, isDotNetFile, locateIlspy } = require(path.join(__dirname, '..', 'out', 'ilspyRunner.js'));

const MANAGED = String.raw`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Accessibility.dll`;
const BYPASS = String.raw`C:\Users\Mazum\Desktop\New-Star\Easy\rev_bypass\Bypass.exe`;
const MIXED = String.raw`C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Data.OracleClient.dll`;
const NATIVE = String.raw`C:\Windows\System32\notepad.exe`;

let pass = 0, fail = 0;
const results = [];
async function test(name, fn) {
	try { await fn(); pass++; results.push(`  PASS  ${name}`); }
	catch (e) { fail++; results.push(`  FAIL  ${name}\n        ${e.message}`); }
}

(async () => {
	// --- fixtures (self-contained, cleaned up at the end) ---
	const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'revenant-test-'));
	const truncated = path.join(tmp, 'truncated.dll');
	const garbage = path.join(tmp, 'garbage.bin');
	const empty = path.join(tmp, 'empty.dll');
	fs.writeFileSync(truncated, fs.readFileSync(MANAGED).subarray(0, 2048)); // valid header, body cut
	fs.writeFileSync(garbage, Buffer.from('this is not a PE file at all, just text.'.repeat(20)));
	fs.writeFileSync(empty, Buffer.alloc(0));

	await test('ilspycmd is locatable', () => {
		assert.ok(locateIlspy(), 'ilspycmd not found on this machine');
	});

	await test('detectDotNet: native buffer => false', () => {
		assert.strictEqual(detectDotNet(fs.readFileSync(NATIVE).subarray(0, 4096)), false);
	});
	await test('detectDotNet: managed buffer => true', () => {
		assert.strictEqual(detectDotNet(fs.readFileSync(MANAGED).subarray(0, 4096)), true);
	});
	await test('detectDotNet: garbage/empty => false (no throw)', () => {
		assert.strictEqual(detectDotNet(Buffer.from('nope')), false);
		assert.strictEqual(detectDotNet(Buffer.alloc(0)), false);
	});

	await test('managed DLL -> C# (ok, isDotNet, real types)', async () => {
		const r = await decompile(MANAGED, { mode: 'csharp' });
		assert.ok(r.ok, `expected ok, got: ${r.error}`);
		assert.strictEqual(r.isDotNet, true);
		assert.match(r.code, /\b(class|interface|struct|enum)\b/);
	});

	await test('managed EXE (Bypass.exe, the #32 repro) -> C#', async () => {
		const r = await decompile(BYPASS, { mode: 'csharp' });
		assert.ok(r.ok, `expected ok, got: ${r.error}`);
		assert.ok(r.code.length > 200, 'expected a non-trivial body');
	});

	await test('IL mode -> CIL (.class/.method markers)', async () => {
		const r = await decompile(BYPASS, { mode: 'il' });
		assert.ok(r.ok, `expected ok, got: ${r.error}`);
		assert.match(r.code, /\.(class|method)\b/);
	});

	await test('mixed-mode (C++/CLI) -> detected managed, structured result (no throw)', async () => {
		const r = await decompile(MIXED, { mode: 'csharp' });
		assert.strictEqual(r.isDotNet, true, 'mixed-mode carries a CLR header -> isDotNet');
		assert.strictEqual(typeof r.ok, 'boolean');
		// ilspycmd decompiles the managed half; we assert it did not crash and is structured.
	});

	await test('native PE refused (isDotNet:false, never invokes ilspycmd)', async () => {
		const r = await decompile(NATIVE, { mode: 'csharp' });
		assert.strictEqual(r.ok, false);
		assert.strictEqual(r.isDotNet, false);
		assert.strictEqual(r.tool, null, 'ilspycmd must not be invoked on a native target');
		assert.match(r.error, /not a managed/i);
	});

	await test('truncated .NET -> structured failure, no crash', async () => {
		const r = await decompile(truncated, { mode: 'csharp' });
		assert.strictEqual(r.ok, false);
		assert.strictEqual(typeof r.error, 'string');
	});

	await test('garbage file -> not .NET, refused, no crash', async () => {
		const r = await decompile(garbage, { mode: 'csharp' });
		assert.strictEqual(r.ok, false);
		assert.strictEqual(r.isDotNet, false);
	});

	await test('empty file -> not .NET, refused, no crash', async () => {
		const r = await decompile(empty, { mode: 'csharp' });
		assert.strictEqual(r.ok, false);
		assert.strictEqual(r.isDotNet, false);
	});

	await test('nonexistent file -> ok:false, "not found"', async () => {
		const r = await decompile(path.join(tmp, 'does-not-exist.dll'));
		assert.strictEqual(r.ok, false);
		assert.match(r.error, /not found/i);
	});

	await test('isDotNetFile agrees with detectDotNet on real files', () => {
		assert.strictEqual(isDotNetFile(MANAGED), true);
		assert.strictEqual(isDotNetFile(NATIVE), false);
	});

	// --- cleanup + report ---
	try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* */ }
	console.log(results.join('\n'));
	console.log(`\n${pass} passed, ${fail} failed`);
	process.exit(fail === 0 ? 0 : 1);
})();
