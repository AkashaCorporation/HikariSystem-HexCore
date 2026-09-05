import * as assert from 'assert';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { HQLMatcher } from '../src/engine/matcher.js';
import { BUILTIN_SIGNATURES } from '../src/signatures/builtin.js';
import type { CFunctionDecl, CNode } from '../src/types/ast.js';
import {
  getDefaultSignatures,
  loadSignatureDirectory,
  mergeSignatureLibraries,
} from '../src/signatures/loader.js';

const signatureRoot = path.resolve(__dirname, '../signatures');
const loaded = loadSignatureDirectory(signatureRoot);
assert.ok(loaded.some(sig => sig.id === 'memory-safety.refcount_free_no_invalidate'));
assert.ok(loaded.some(sig => sig.id === 'memory-safety.refcount_free_no_invalidate_binary'));
assert.ok(loaded.some(sig => sig.id.startsWith('anti-analysis.')));

const object = { kind: 'CVarRefExpr', name: 'obj', type: 'struct object *' } as const;
const field = (name: string) => ({
  kind: 'CFieldAccessExpr' as const,
  object,
  field: name,
  arrow: true,
});
const freeCall = { kind: 'CCallExpr' as const, callee: 'kfree', arguments: [field('buf')] };
const decrementCall = {
  kind: 'CCallExpr' as const,
  callee: 'refcount_dec_and_test',
  arguments: [field('refcount')],
};
const decrementBinary = {
  kind: 'CBinaryExpr' as const,
  operator: '-=',
  left: field('refcount'),
  right: { kind: 'CIntLitExpr' as const, value: 1, width: 32, signed: false },
};
const functionWith = (...body: CNode[]): CFunctionDecl => ({
  kind: 'CFunctionDecl',
  name: 'release_object',
  returnType: 'void',
  params: [],
  body: { kind: 'CBlockStmt', body },
});
const matcher = new HQLMatcher();
const callRule = loaded.find(sig => sig.id === 'memory-safety.refcount_free_no_invalidate')!;
const binaryRule = loaded.find(sig => sig.id === 'memory-safety.refcount_free_no_invalidate_binary')!;
assert.ok(matcher.evaluate(functionWith(decrementCall, freeCall), callRule));
assert.ok(matcher.evaluate(functionWith(decrementBinary, freeCall), binaryRule));
assert.strictEqual(matcher.evaluate(functionWith(freeCall), callRule), null);
assert.strictEqual(matcher.evaluate(functionWith(decrementCall), callRule), null);

const duplicate = { ...BUILTIN_SIGNATURES[0], name: 'disk duplicate' };
assert.throws(() => mergeSignatureLibraries(BUILTIN_SIGNATURES, [duplicate]), /duplicate signature ID/);

const defaults = getDefaultSignatures();
assert.strictEqual(defaults.length, BUILTIN_SIGNATURES.length);
assert.strictEqual(defaults.length, loaded.length);
assert.ok(defaults.some(sig => sig.id === 'memory-safety.refcount_free_no_invalidate'));

const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'hql-signatures-'));
try {
  fs.writeFileSync(path.join(temp, 'bad.hql.json'), '{ nope', 'utf8');
  fs.writeFileSync(path.join(temp, 'invalid.hql.json'), '{"id":"missing-fields"}', 'utf8');
  fs.writeFileSync(path.join(temp, 'invalid-kind.hql.json'), JSON.stringify({
    id: 'invalid.kind',
    name: 'Invalid kind',
    description: 'Must fail closed',
    severity: 'info',
    condition: { query: { target: 'CStringLiteral' } },
  }), 'utf8');
  fs.writeFileSync(path.join(temp, 'invalid-operator.hql.json'), JSON.stringify({
    id: 'invalid.operator', name: 'Invalid operator', description: 'Must fail closed', severity: 'info',
    condition: { query: { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: 'ROTATE_MAGIC' }] } },
  }), 'utf8');
  fs.writeFileSync(path.join(temp, 'invalid-operand.hql.json'), JSON.stringify({
    id: 'invalid.operand', name: 'Invalid operand', description: 'Must fail closed', severity: 'info',
    condition: { query: { target: 'CUnaryExpr', operands: [{ position: 1, query: { target: 'CIntLitExpr' } }] } },
  }), 'utf8');
  fs.writeFileSync(path.join(temp, 'unsafe-int.hql.json'), JSON.stringify({
    id: 'invalid.unsafe-int', name: 'Unsafe integer', description: 'Must use a string', severity: 'info',
    condition: { query: { target: 'CIntLitExpr', attributes: [{ field: 'value', value: 9007199254740992 }] } },
  }), 'utf8');
  fs.copyFileSync(
    path.join(signatureRoot, 'memory-safety', 'refcount-uaf.hql.json'),
    path.join(temp, 'valid.hql.json'),
  );
  assert.throws(() => loadSignatureDirectory(temp), /rejected 6 file\(s\)/);
  fs.rmSync(path.join(temp, 'bad.hql.json'));
  fs.rmSync(path.join(temp, 'invalid.hql.json'));
  fs.rmSync(path.join(temp, 'invalid-kind.hql.json'));
  fs.rmSync(path.join(temp, 'invalid-operator.hql.json'));
  fs.rmSync(path.join(temp, 'invalid-operand.hql.json'));
  fs.rmSync(path.join(temp, 'unsafe-int.hql.json'));
  assert.strictEqual(loadSignatureDirectory(temp).length, 1);
} finally {
  fs.rmSync(temp, { recursive: true, force: true });
}

console.log(`signatureLoader: ${loaded.length} disk signatures, ${defaults.length} merged — OK`);
