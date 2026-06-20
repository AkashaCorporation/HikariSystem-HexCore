// ─── Built-in HQL signature library ───
// A starter set of semantic signatures over the Helix C-AST. These are
// architecture/compiler independent: they match algorithmic STRUCTURE, not bytes.
// Extend freely; each is a named behavioral pattern.

import type { HQLSignature } from '../types/hql.js';

const FNV32_PRIME = 16777619;        // 0x01000193
const FNV64_PRIME = 1099511628211;   // 0x100000001b3
const CRC32_POLY_REV = 0xEDB88320;   // reversed CRC-32 polynomial

export const BUILTIN_SIGNATURES: HQLSignature[] = [
  {
    id: 'crypto.fnv1',
    name: 'FNV hash (32-bit)',
    description: 'A multiply by the 32-bit FNV prime (0x01000193) -- the core mixing step of FNV-1/FNV-1a string hashing.',
    severity: 'info',
    queries: [
      {
        target: 'CBinaryExpr',
        attributes: [{ field: 'operator', value: 're:^\\*=?$' }],
        contains: [{ target: 'CIntLitExpr', attributes: [{ field: 'value', value: FNV32_PRIME }] }],
      },
    ],
  },
  {
    id: 'crypto.fnv1_64',
    name: 'FNV hash (64-bit)',
    description: 'A multiply by the 64-bit FNV prime (0x100000001b3).',
    severity: 'info',
    queries: [
      {
        target: 'CBinaryExpr',
        attributes: [{ field: 'operator', value: 're:^\\*=?$' }],
        contains: [{ target: 'CIntLitExpr', attributes: [{ field: 'value', value: FNV64_PRIME }] }],
      },
    ],
  },
  {
    id: 'crypto.crc32',
    name: 'CRC-32',
    description: 'The reversed CRC-32 polynomial 0xEDB88320 as a constant -- table init or bit-by-bit CRC.',
    severity: 'info',
    queries: [
      { target: 'CIntLitExpr', attributes: [{ field: 'value', value: CRC32_POLY_REV }] },
    ],
  },
  {
    id: 'crypto.xor_present',
    name: 'XOR mixing',
    description: 'A bitwise-XOR expression in the function -- byte mixing, simple obfuscation, or a stream cipher step.',
    severity: 'low',
    mitre: ['T1027'],
    queries: [
      {
        target: 'CFunctionDecl',
        contains: [{ target: 'CBinaryExpr', attributes: [{ field: 'operator', value: 're:^\\^=?$' }] }],
      },
    ],
  },
  {
    id: 'struct.guarded_loop',
    name: 'Guarded loop',
    description: 'A loop nested inside a guard (if -> do/while) -- init-once, stack-probe (__chkstk), or lazy-init patterns.',
    severity: 'info',
    queries: [
      { target: 'CIfStmt', contains: [{ target: 'CDoWhileStmt' }] },
    ],
  },
  {
    id: 'algo.multiply_xor_loop',
    name: 'Multiply-XOR hash loop',
    description: 'A loop body combining a multiply and a XOR -- the shape of most rolling/avalanche hash functions (FNV, DJB-variants, custom).',
    severity: 'low',
    queries: [
      {
        target: 'CFunctionDecl',
        contains: [
          { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: 're:^\\*=?$' }] },
          { target: 'CBinaryExpr', attributes: [{ field: 'operator', value: 're:^\\^=?$' }] },
        ],
      },
    ],
  },
];
