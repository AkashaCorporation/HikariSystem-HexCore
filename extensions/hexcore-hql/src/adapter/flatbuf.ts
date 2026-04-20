// ─── HAST FlatBuffer → CNode Adapter ───
// Reads the binary HAST (schemas/ast.fbs) produced by Helix and hydrates
// it into the CNode tree that the HQL matcher consumes.
//
// Zero generated code — reads FlatBuffer tables directly via the
// flatbuffers npm ByteBuffer API.
//
// v3.7.4: Optional SessionDbReader for analyst rename/retype propagation.

import type { SessionDbReader } from './sessionDb.js';
import type {
  CNode,
  CFunctionDecl,
  CVarDecl,
  CBlockStmt,
  CIntLitExpr,
  CFloatLitExpr,
  CStringLitExpr,
  CAddrLitExpr,
  CVarRefExpr,
  CBinaryExpr,
  CUnaryExpr,
  CCastExpr,
  CCallExpr,
  CTernaryExpr,
  CSubscriptExpr,
  CFieldAccessExpr,
  CIfStmt,
  CWhileStmt,
  CDoWhileStmt,
  CForStmt,
  CSwitchStmt,
  CCaseStmt,
  CReturnStmt,
  CGotoStmt,
  CLabelStmt,
  CBreakStmt,
  CContinueStmt,
} from '../types/ast.js';

import * as flatbuffers from 'flatbuffers';

// ─── Schema vtable offsets (4 + field_index * 2) ───
// Must match ast.fbs field ordering — all offsets reserved even if not yet used.

/* eslint-disable @typescript-eslint/no-unused-vars */

// AstModule
const M_NAME = 4, M_FUNCTIONS = 6;

// DecompiledFunction
const F_NAME = 4, F_ADDRESS = 6, F_RETURN_TYPE = 8,
      F_PARAMS = 10, F_LOCALS = 12, F_BODY = 14,
      F_CALLING_CONVENTION = 16, F_IS_VARIADIC = 18;

// DataType
const DT_KIND = 4, DT_IS_SIGNED = 6, DT_BITS = 8,
      DT_ELEMENT_TYPE = 10, DT_NAME = 14;

// Variable
const V_NAME = 4, V_TYPE = 6, V_STORAGE = 8;

/* eslint-enable @typescript-eslint/no-unused-vars */

// Expression
const E_KIND = 4, E_INT_VALUE = 6, E_FLOAT_VALUE = 8,
      E_STRING_VALUE = 10, E_OPERATOR = 12, E_CAST_TYPE = 14,
      E_CHILDREN = 16, E_VARIABLE = 18, E_ADDRESS = 20;

// Statement
const S_KIND = 4, S_VARIABLE = 6, S_EXPRESSIONS = 8,
      S_CHILDREN = 10, S_CASES = 12, S_TEXT = 14;

// SwitchCase
const SC_VALUES = 4, SC_BODY = 6;

// ─── ByteBuffer helpers ───

type BB = flatbuffers.ByteBuffer;

/** Read field offset from vtable, or 0 if absent. */
function fieldOff(bb: BB, tablePos: number, voff: number): number {
  return bb.__offset(tablePos, voff);
}

/** Follow an offset-type field to get the target table position. */
function readTable(bb: BB, tablePos: number, voff: number): number | null {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.__indirect(tablePos + o) : null;
}

/** Read a string field. */
function readStr(bb: BB, tablePos: number, voff: number): string | null {
  const o = fieldOff(bb, tablePos, voff);
  const val = o ? bb.__string(tablePos + o) : null;
  return typeof val === 'string' ? val : val ? new TextDecoder().decode(val) : null;
}

/** Read a uint8 / byte field. */
function readU8(bb: BB, tablePos: number, voff: number, def = 0): number {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.readUint8(tablePos + o) : def;
}

/** Read a uint16 field. */
function readU16(bb: BB, tablePos: number, voff: number, def = 0): number {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.readUint16(tablePos + o) : def;
}

/** Read an int64 field as Number (safe for values < 2^53). */
function readI64(bb: BB, tablePos: number, voff: number): number {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return 0;
  return Number(bb.readInt64(tablePos + o));
}

/** Read a uint64 field as Number. */
function readU64(bb: BB, tablePos: number, voff: number): number {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return 0;
  return Number(bb.readUint64(tablePos + o));
}

/** Read a float64 field. */
function readF64(bb: BB, tablePos: number, voff: number): number {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.readFloat64(tablePos + o) : 0;
}

/** Get the length and start of a vector field. Returns [start, len]. */
function readVec(bb: BB, tablePos: number, voff: number): [number, number] | null {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return null;
  const vecPos = tablePos + o;
  return [bb.__vector(vecPos), bb.__vector_len(vecPos)];
}

// ─── DataType → type string ───

function readTypeStr(bb: BB, pos: number): string {
  const kind = readU8(bb, pos, DT_KIND, 255);
  const signed = readU8(bb, pos, DT_IS_SIGNED, 0) !== 0;
  const bits = readU16(bb, pos, DT_BITS);

  switch (kind) {
    case 0: return 'void';
    case 1: return 'bool';
    case 2: // Int
      if (bits === 0) return signed ? 'int' : 'unsigned int';
      return `${signed ? '' : 'u'}int${bits}_t`;
    case 3: // Float
      return bits === 32 ? 'float' : 'double';
    case 4: { // Pointer
      const elem = readTable(bb, pos, DT_ELEMENT_TYPE);
      const inner = elem ? readTypeStr(bb, elem) : 'void';
      return `${inner}*`;
    }
    case 5: { // Array
      const elem = readTable(bb, pos, DT_ELEMENT_TYPE);
      const inner = elem ? readTypeStr(bb, elem) : 'unknown';
      return `${inner}[]`;
    }
    case 6: { // Struct
      const name = readStr(bb, pos, DT_NAME);
      return name ? `struct ${name}` : 'struct <anon>';
    }
    case 7: { // Union
      const name = readStr(bb, pos, DT_NAME);
      return name ? `union ${name}` : 'union <anon>';
    }
    case 8: return 'funcptr';
    default: return 'unknown';
  }
}

// ─── Expression → CNode ───

function readExpr(bb: BB, pos: number): CNode {
  const kind = readU8(bb, pos, E_KIND, 255);

  // Read common fields
  const strVal = readStr(bb, pos, E_STRING_VALUE);
  const opStr = readStr(bb, pos, E_OPERATOR);

  // Read children vector
  const childrenArr: CNode[] = [];
  const cv = readVec(bb, pos, E_CHILDREN);
  if (cv) {
    const [start, len] = cv;
    for (let i = 0; i < len; i++) {
      const childPos = bb.__indirect(start + i * 4);
      childrenArr.push(readExpr(bb, childPos));
    }
  }

  switch (kind) {
    case 0: { // IntLit
      const value = readI64(bb, pos, E_INT_VALUE);
      return {
        kind: 'CIntLitExpr',
        value,
        width: 32,
        signed: true,
      } satisfies CIntLitExpr;
    }
    case 1: { // FloatLit
      const value = readF64(bb, pos, E_FLOAT_VALUE);
      return {
        kind: 'CFloatLitExpr',
        value,
        precision: 'double',
      } satisfies CFloatLitExpr;
    }
    case 2: // StringLit
      return {
        kind: 'CStringLitExpr',
        value: strVal ?? '',
        encoding: 'ascii',
      } satisfies CStringLitExpr;

    case 12: { // AddressLit
      const addr = readU64(bb, pos, E_ADDRESS);
      return {
        kind: 'CAddrLitExpr',
        address: `0x${addr.toString(16)}`,
      } satisfies CAddrLitExpr;
    }
    case 3: { // VarRef
      // Read type from the embedded Variable table
      let typeStr = 'unknown';
      const varPos = readTable(bb, pos, E_VARIABLE);
      if (varPos) {
        const tPos = readTable(bb, varPos, V_TYPE);
        if (tPos) typeStr = readTypeStr(bb, tPos);
      }
      return {
        kind: 'CVarRefExpr',
        name: strVal ?? 'var',
        type: typeStr,
      } satisfies CVarRefExpr;
    }
    case 5: // Binary
      return {
        kind: 'CBinaryExpr',
        operator: opStr ?? '?',
        left: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        right: childrenArr[1] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
      } satisfies CBinaryExpr;

    case 4: // Unary
      return {
        kind: 'CUnaryExpr',
        operator: opStr ?? '?',
        operand: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        prefix: true,
      } satisfies CUnaryExpr;

    case 6: { // Cast
      let targetType = 'unknown';
      const ctPos = readTable(bb, pos, E_CAST_TYPE);
      if (ctPos) targetType = readTypeStr(bb, ctPos);
      return {
        kind: 'CCastExpr',
        targetType,
        operand: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
      } satisfies CCastExpr;
    }
    case 7: // Call
      return {
        kind: 'CCallExpr',
        callee: strVal ?? 'unknown',
        arguments: childrenArr,
      } satisfies CCallExpr;

    case 11: // Ternary
      return {
        kind: 'CTernaryExpr',
        condition: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        consequent: childrenArr[1] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        alternate: childrenArr[2] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
      } satisfies CTernaryExpr;

    case 8: // Subscript
      return {
        kind: 'CSubscriptExpr',
        base: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        index: childrenArr[1] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
      } satisfies CSubscriptExpr;

    case 9: // Member (.)
      return {
        kind: 'CFieldAccessExpr',
        object: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        field: strVal ?? 'field',
        arrow: false,
      } satisfies CFieldAccessExpr;

    case 10: // DerefMember (->)
      return {
        kind: 'CFieldAccessExpr',
        object: childrenArr[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        field: strVal ?? 'field',
        arrow: true,
      } satisfies CFieldAccessExpr;

    default:
      // Unknown expression — return as int literal 0
      return { kind: 'CIntLitExpr', value: 0, width: 32, signed: true };
  }
}

// ─── Statement → CNode ───

function readStmt(bb: BB, pos: number): CNode {
  const kind = readU8(bb, pos, S_KIND, 255);
  const text = readStr(bb, pos, S_TEXT);

  // Read expressions vector
  const exprs: CNode[] = [];
  const ev = readVec(bb, pos, S_EXPRESSIONS);
  if (ev) {
    const [start, len] = ev;
    for (let i = 0; i < len; i++) {
      const ePos = bb.__indirect(start + i * 4);
      exprs.push(readExpr(bb, ePos));
    }
  }

  // Read children vector
  const children: CNode[] = [];
  const chv = readVec(bb, pos, S_CHILDREN);
  if (chv) {
    const [start, len] = chv;
    for (let i = 0; i < len; i++) {
      const cPos = bb.__indirect(start + i * 4);
      children.push(readStmt(bb, cPos));
    }
  }

  switch (kind) {
    case 0: { // VarDecl
      const varPos = readTable(bb, pos, S_VARIABLE);
      let name = 'var';
      let type = 'unknown';
      if (varPos) {
        name = readStr(bb, varPos, V_NAME) ?? 'var';
        const tPos = readTable(bb, varPos, V_TYPE);
        if (tPos) type = readTypeStr(bb, tPos);
      }
      return {
        kind: 'CVarDecl',
        name,
        type,
        init: exprs[0],
      } satisfies CVarDecl;
    }

    case 1: // Assign → treated as ExprStmt with assignment expression
      // The HQL CNode types don't have a standalone CAssignStmt.
      // Map to a binary expression with '=' operator wrapped in a block.
      return {
        kind: 'CBinaryExpr',
        operator: text || '=',
        left: exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        right: exprs[1] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
      } satisfies CBinaryExpr;

    case 2: // ExprStmt → unwrap the expression
      return exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true };

    case 3: // Return
      return {
        kind: 'CReturnStmt',
        value: exprs[0],
      } satisfies CReturnStmt;

    case 4: { // If
      // text = number of then-body statements
      const thenCount = text ? parseInt(text, 10) : children.length;
      const thenBody = children.slice(0, thenCount);
      const elseBody = children.slice(thenCount);
      const thenBlock: CBlockStmt = { kind: 'CBlockStmt', body: thenBody };
      const elseBlock: CBlockStmt | undefined =
        elseBody.length > 0 ? { kind: 'CBlockStmt', body: elseBody } : undefined;
      return {
        kind: 'CIfStmt',
        condition: exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        then: thenBlock,
        ...(elseBlock ? { else: elseBlock } : {}),
      } satisfies CIfStmt;
    }

    case 5: // While
      return {
        kind: 'CWhileStmt',
        condition: exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        body: { kind: 'CBlockStmt', body: children } satisfies CBlockStmt,
      } satisfies CWhileStmt;

    case 6: // DoWhile
      return {
        kind: 'CDoWhileStmt',
        condition: exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        body: { kind: 'CBlockStmt', body: children } satisfies CBlockStmt,
      } satisfies CDoWhileStmt;

    case 7: { // For
      // text = "has_init,has_step" e.g. "1,1"
      let hasInit = 0, hasStep = 0;
      if (text) {
        const parts = text.split(',');
        hasInit = parseInt(parts[0], 10) || 0;
        hasStep = parseInt(parts[1], 10) || 0;
      }
      let idx = 0;
      const init = hasInit ? children[idx++] : undefined;
      const step = hasStep ? children[idx++] : undefined;
      const body = children.slice(idx);
      return {
        kind: 'CForStmt',
        init,
        condition: exprs[0],
        update: step,
        body: { kind: 'CBlockStmt', body } satisfies CBlockStmt,
      } satisfies CForStmt;
    }

    case 8: { // Switch
      // Read cases from the cases vector
      const cases: CCaseStmt[] = [];
      const casesVec = readVec(bb, pos, S_CASES);
      if (casesVec) {
        const [start, len] = casesVec;
        for (let i = 0; i < len; i++) {
          const casePos = bb.__indirect(start + i * 4);
          cases.push(readSwitchCase(bb, casePos));
        }
      }
      return {
        kind: 'CSwitchStmt',
        discriminant: exprs[0] ?? { kind: 'CIntLitExpr', value: 0, width: 32, signed: true },
        cases,
      } satisfies CSwitchStmt;
    }

    case 9: // Break
      return { kind: 'CBreakStmt' } satisfies CBreakStmt;

    case 10: // Continue
      return { kind: 'CContinueStmt' } satisfies CContinueStmt;

    case 11: // Goto
      return {
        kind: 'CGotoStmt',
        label: text ?? 'unknown',
      } satisfies CGotoStmt;

    case 12: // Label
      return {
        kind: 'CLabelStmt',
        label: text ?? 'unknown',
        body: children[0] ?? { kind: 'CBreakStmt' },
      } satisfies CLabelStmt;

    case 13: // Asm — map to a comment-like node (no CAsm in HQL types)
      return {
        kind: 'CIntLitExpr',
        value: 0,
        width: 32,
        signed: true,
      };

    case 14: // Comment — no CComment in HQL types; skip
      return {
        kind: 'CIntLitExpr',
        value: 0,
        width: 32,
        signed: true,
      };

    default:
      return { kind: 'CIntLitExpr', value: 0, width: 32, signed: true };
  }
}

function readSwitchCase(bb: BB, pos: number): CCaseStmt {
  const body: CNode[] = [];
  const bv = readVec(bb, pos, SC_BODY);
  if (bv) {
    const [start, len] = bv;
    for (let i = 0; i < len; i++) {
      const sPos = bb.__indirect(start + i * 4);
      body.push(readStmt(bb, sPos));
    }
  }

  // values vector — empty means default case
  const vv = readVec(bb, pos, SC_VALUES);
  let value: CNode | undefined;
  if (vv) {
    const [start, len] = vv;
    if (len > 0) {
      const v = Number(bb.readInt64(start));
      value = { kind: 'CIntLitExpr', value: v, width: 32, signed: true } satisfies CIntLitExpr;
    }
  }

  return {
    kind: 'CCaseStmt',
    value,
    body,
  };
}

// ─── Variable → CVarDecl ───

function readVariable(bb: BB, pos: number): CVarDecl {
  const name = readStr(bb, pos, V_NAME) ?? 'var';
  let type = 'unknown';
  const tPos = readTable(bb, pos, V_TYPE);
  if (tPos) type = readTypeStr(bb, tPos);

  return {
    kind: 'CVarDecl',
    name,
    type,
  };
}

// ─── DecompiledFunction → CFunctionDecl ───

function readFunction(bb: BB, pos: number, session?: SessionDbReader): CFunctionDecl {
  let name = readStr(bb, pos, F_NAME) ?? 'unknown';
  const address = readU64(bb, pos, F_ADDRESS);

  let returnType = 'void';
  const rtPos = readTable(bb, pos, F_RETURN_TYPE);
  if (rtPos) returnType = readTypeStr(bb, rtPos);

  // v3.7.4: Apply analyst renames/retypes from session database
  if (session) {
    const addrHex = `0x${address.toString(16)}`;
    const sessionName = session.getFunctionName(addrHex);
    if (sessionName) { name = sessionName; }
    const sessionRetType = session.getFunctionReturnType(addrHex);
    if (sessionRetType) { returnType = sessionRetType; }
  }

  // Params
  const params: CVarDecl[] = [];
  const pv = readVec(bb, pos, F_PARAMS);
  if (pv) {
    const [start, len] = pv;
    for (let i = 0; i < len; i++) {
      const vPos = bb.__indirect(start + i * 4);
      params.push(readVariable(bb, vPos));
    }
  }

  // v3.7.4: Apply variable renames from session database
  if (session) {
    const addrHex = `0x${address.toString(16)}`;
    const renames = session.getVariableRenames(addrHex);
    for (const rename of renames) {
      const param = params.find(p => p.name === rename.original_name);
      if (param) {
        if (rename.new_name) { param.name = rename.new_name; }
        if (rename.new_type) { param.type = rename.new_type; }
      }
    }
  }

  // Body statements
  const bodyStmts: CNode[] = [];
  const bv = readVec(bb, pos, F_BODY);
  if (bv) {
    const [start, len] = bv;
    for (let i = 0; i < len; i++) {
      const sPos = bb.__indirect(start + i * 4);
      bodyStmts.push(readStmt(bb, sPos));
    }
  }

  const body: CBlockStmt = { kind: 'CBlockStmt', body: bodyStmts };

  return {
    kind: 'CFunctionDecl',
    name,
    returnType,
    params,
    body,
  };
}

// ─── Public API ───

/**
 * Hydrate a HAST FlatBuffer into an array of CFunctionDecl nodes
 * ready for the HQL matcher.
 *
 * @param buffer   Raw bytes of a HAST FlatBuffer (file identifier "HAST").
 * @param session  Optional SessionDbReader for analyst rename/retype propagation (v3.7.4).
 * @returns        Array of CFunctionDecl nodes representing the decompiled module.
 * @throws         If the buffer is invalid or too small.
 */
export function hydrateHAST(buffer: Uint8Array, session?: SessionDbReader): CFunctionDecl[] {
  if (buffer.length < 8) {
    throw new Error('HAST buffer too small (< 8 bytes)');
  }

  // Verify file identifier "HAST"
  if (buffer[4] !== 0x48 || buffer[5] !== 0x41 ||
      buffer[6] !== 0x53 || buffer[7] !== 0x54) {
    throw new Error('Invalid HAST file identifier');
  }

  const bb = new flatbuffers.ByteBuffer(buffer);

  // Read root table (AstModule)
  const rootOff = bb.readInt32(bb.position()) + bb.position();

  // Read functions vector
  const functions: CFunctionDecl[] = [];
  const fv = readVec(bb, rootOff, M_FUNCTIONS);
  if (fv) {
    const [start, len] = fv;
    for (let i = 0; i < len; i++) {
      const fPos = bb.__indirect(start + i * 4);
      functions.push(readFunction(bb, fPos, session));
    }
  }

  return functions;
}
