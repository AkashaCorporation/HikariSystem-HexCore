// ─── HQL Smoke Test ───
// Validates: AST construction, query matching, scan, and signature evaluation.
// Run: npx tsx test/smoke.ts

import type {
  CForStmt,
  CBinaryExpr,
  CCallExpr,
  CVarRefExpr,
  CBlockStmt,
  CIntLitExpr,
  CFunctionDecl,
  CVarDecl,
} from '../src/types/ast.js';
import type { HQLQuery, HQLSignature } from '../src/types/hql.js';
import { HQLMatcher } from '../src/engine/matcher.js';

// ─── Build a mini-AST: a function with a XOR loop pattern ───
// Simulates: void decrypt(char* buf, int len) {
//   for (int i = 0; i < len; i++) {
//     buf[i] = buf[i] ^ 0xFF;
//   }
// }

const varI: CVarRefExpr = { kind: 'CVarRefExpr', name: 'i', type: 'int' };
const varLen: CVarRefExpr = { kind: 'CVarRefExpr', name: 'len', type: 'int' };
const xorConst: CIntLitExpr = { kind: 'CIntLitExpr', value: 0xFF, width: 8, signed: false };

const xorExpr: CBinaryExpr = {
  kind: 'CBinaryExpr',
  operator: '^',
  left: { kind: 'CVarRefExpr', name: 'buf_i', type: 'char' } as CVarRefExpr,
  right: xorConst,
};

const memcpyCall: CCallExpr = {
  kind: 'CCallExpr',
  callee: 'memcpy',
  arguments: [
    { kind: 'CVarRefExpr', name: 'dst', type: 'void*' } as CVarRefExpr,
    { kind: 'CVarRefExpr', name: 'src', type: 'void*' } as CVarRefExpr,
    { kind: 'CVarRefExpr', name: 'n', type: 'size_t' } as CVarRefExpr,
  ],
};

const loopCondition: CBinaryExpr = {
  kind: 'CBinaryExpr',
  operator: '<',
  left: varI,
  right: varLen,
};

const loopBody: CBlockStmt = {
  kind: 'CBlockStmt',
  body: [xorExpr, memcpyCall],
};

const forLoop: CForStmt = {
  kind: 'CForStmt',
  init: { kind: 'CVarDecl', name: 'i', type: 'int', init: { kind: 'CIntLitExpr', value: 0, width: 32, signed: true } as CIntLitExpr } as CVarDecl,
  condition: loopCondition,
  update: { kind: 'CUnaryExpr', operator: '++', operand: varI, prefix: false } as any,
  body: loopBody,
};

const funcDecl: CFunctionDecl = {
  kind: 'CFunctionDecl',
  name: 'decrypt',
  returnType: 'void',
  params: [
    { kind: 'CVarDecl', name: 'buf', type: 'char*' } as CVarDecl,
    { kind: 'CVarDecl', name: 'len', type: 'int' } as CVarDecl,
  ],
  body: { kind: 'CBlockStmt', body: [forLoop] },
};

// ─── Tests ───

const matcher = new HQLMatcher();
let passed = 0;
let failed = 0;

function assert(condition: boolean, msg: string): void {
  if (condition) {
    console.log(`  ✅ ${msg}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${msg}`);
    failed++;
  }
}

console.log('\n🔬 HQL Engine — Smoke Test\n');

// Test 1: Match a specific node kind
console.log('▸ Test 1: Kind matching');
const q1: HQLQuery = { target: 'CBinaryExpr' };
assert(matcher.match(xorExpr, q1), 'CBinaryExpr matches CBinaryExpr');
assert(!matcher.match(forLoop, q1), 'CForStmt does NOT match CBinaryExpr');

// Test 2: Attribute matching
console.log('▸ Test 2: Attribute matching');
const q2: HQLQuery = {
  target: 'CBinaryExpr',
  attributes: [{ field: 'operator', value: '^' }],
};
assert(matcher.match(xorExpr, q2), 'XOR expr matches operator "^"');
assert(!matcher.match(loopCondition, q2), 'Less-than expr does NOT match operator "^"');

// Test 3: Scan — find all CBinaryExpr in the function
console.log('▸ Test 3: Scan (collect all matches)');
const q3: HQLQuery = { target: 'CBinaryExpr' };
const scanResults = matcher.scan(funcDecl, q3);
assert(scanResults.length === 2, `Found ${scanResults.length} CBinaryExpr nodes (expected 2)`);

// Test 4: Containment — for loop containing XOR
console.log('▸ Test 4: Containment query');
const q4: HQLQuery = {
  target: 'CForStmt',
  contains: [
    { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: '^' }] },
  ],
};
assert(matcher.match(forLoop, q4), 'CForStmt contains CBinaryExpr with XOR');

const q4_fail: HQLQuery = {
  target: 'CForStmt',
  contains: [
    { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: '/' }] },
  ],
};
assert(!matcher.match(forLoop, q4_fail), 'CForStmt does NOT contain division');

// Test 5: Operand matching
console.log('▸ Test 5: Operand matching');
const q5: HQLQuery = {
  target: 'CBinaryExpr',
  operands: [
    { position: 1, query: { target: 'CIntLitExpr' } },
  ],
};
assert(matcher.match(xorExpr, q5), 'XOR right operand is CIntLitExpr');

// Test 6: Glob matching on callee
console.log('▸ Test 6: Glob attribute matching');
const q6: HQLQuery = {
  target: 'CCallExpr',
  attributes: [{ field: 'callee', value: 'mem*' }],
};
assert(matcher.match(memcpyCall, q6), 'memcpy matches glob "mem*"');

// Test 7: Regex matching
console.log('▸ Test 7: Regex attribute matching');
const q7: HQLQuery = {
  target: 'CCallExpr',
  attributes: [{ field: 'callee', value: 're:^mem(cpy|set|move)$' }],
};
assert(matcher.match(memcpyCall, q7), 'memcpy matches regex');

// Test 8: Full signature evaluation — XOR loop crypto pattern
console.log('▸ Test 8: Signature evaluation');
const cryptoSig: HQLSignature = {
  id: 'crypto.xor_loop',
  name: 'XOR Loop Encryption',
  description: 'Detects byte-level XOR encryption in a loop structure',
  severity: 'medium',
  mitre: ['T1027'],
  queries: [
    {
      target: 'CForStmt',
      contains: [
        { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: '^' }] },
      ],
    },
  ],
};
const result = matcher.evaluate(funcDecl, cryptoSig);
assert(result !== null, 'Crypto signature fired');
assert(result?.signatureId === 'crypto.xor_loop', `Signature ID: ${result?.signatureId}`);
assert((result?.confidence ?? 0) > 0, `Confidence: ${result?.confidence}`);

// Test 9: Signature that should NOT fire
console.log('▸ Test 9: Negative signature evaluation');
const injectionSig: HQLSignature = {
  id: 'injection.process_hollow',
  name: 'Process Hollowing',
  description: 'Detects process hollowing pattern',
  severity: 'critical',
  queries: [
    {
      target: 'CCallExpr',
      attributes: [{ field: 'callee', value: 'NtUnmapViewOfSection' }],
    },
  ],
};
const negResult = matcher.evaluate(funcDecl, injectionSig);
assert(negResult === null, 'Injection signature did NOT fire (correct)');

// ─── Summary ───
console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);
process.exit(failed > 0 ? 1 : 0);
