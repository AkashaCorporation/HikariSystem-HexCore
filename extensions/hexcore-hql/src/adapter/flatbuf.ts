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
  CAssignStmt,
  CExprStmt,
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
  CUnknownExpr,
  CUnknownStmt,
  CAsmStmt,
  CCommentStmt,
  HASTAdapterCoverage,
  HASTModuleMetadata,
} from '../types/ast.js';
import { HAST_CAPABILITIES } from '../types/ast.js';

import * as flatbuffers from 'flatbuffers';

// ─── Schema vtable offsets (4 + field_index * 2) ───
// Must match ast.fbs field ordering — all offsets reserved even if not yet used.

/* eslint-disable @typescript-eslint/no-unused-vars */

// AstModule
const M_NAME = 4, M_FUNCTIONS = 6,
      M_SCHEMA_MAJOR = 12, M_SCHEMA_MINOR = 14, M_CAPABILITIES = 16,
      M_PRODUCER = 18, M_PRODUCER_VERSION = 20, M_ARCH = 22, M_POINTER_BITS = 24;

// DecompiledFunction
const F_NAME = 4, F_ADDRESS = 6, F_RETURN_TYPE = 8,
      F_PARAMS = 10, F_LOCALS = 12, F_BODY = 14,
      F_CALLING_CONVENTION = 16, F_IS_VARIADIC = 18;

// DataType
const DT_KIND = 4, DT_IS_SIGNED = 6, DT_BITS = 8,
      DT_ELEMENT_TYPE = 10, DT_NAME = 14;

// Variable
const V_NAME = 4, V_TYPE = 6, V_STORAGE = 8, V_STACK_OFFSET = 10,
      V_IDENTITY_ID = 12, V_PARAMETER_INDEX = 14;

/* eslint-enable @typescript-eslint/no-unused-vars */

// Expression
const E_KIND = 4, E_INT_VALUE = 6, E_FLOAT_VALUE = 8,
      E_STRING_VALUE = 10, E_OPERATOR = 12, E_CAST_TYPE = 14,
      E_CHILDREN = 16, E_VARIABLE = 18, E_ADDRESS = 20,
      E_RESULT_TYPE = 22, E_NODE_ID = 24, E_SOURCE_ADDRESS = 26,
      E_CALL_TARGET = 28, E_FIELD_OFFSET = 30;

// Statement
const S_KIND = 4, S_VARIABLE = 6, S_EXPRESSIONS = 8,
      S_CHILDREN = 10, S_CASES = 12, S_TEXT = 14,
      S_NODE_ID = 16, S_SOURCE_ADDRESS = 18, S_CHILD_ROLES = 20;

// SwitchCase
const SC_VALUES = 4, SC_BODY = 6;

// ─── ByteBuffer helpers ───

type BB = flatbuffers.ByteBuffer;

function assertValidTable(bb: BB, tablePos: number, label: string): void {
  const capacity = bb.capacity();
  if (!Number.isSafeInteger(tablePos) || tablePos < 4 || tablePos + 4 > capacity) {
    throw new Error(`${label} table position ${tablePos} is outside the HAST buffer`);
  }
  const vtableDistance = bb.readInt32(tablePos);
  const vtablePos = tablePos - vtableDistance;
  if (vtableDistance === 0 || vtablePos < 0 || vtablePos + 4 > capacity) {
    throw new Error(`${label} has an invalid vtable`);
  }
  const vtableSize = bb.readUint16(vtablePos);
  const objectSize = bb.readUint16(vtablePos + 2);
  if (vtableSize < 4 || objectSize < 4 || vtablePos + vtableSize > capacity || tablePos + objectSize > capacity) {
    throw new Error(`${label} table bounds exceed the HAST buffer`);
  }
}

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

function readU32(bb: BB, tablePos: number, voff: number, def = 0): number {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.readUint32(tablePos + o) : def;
}

/** Read an int64 field exactly. */
function readI64(bb: BB, tablePos: number, voff: number): bigint {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return 0n;
  return BigInt(bb.readInt64(tablePos + o));
}

function readI64Optional(bb: BB, tablePos: number, voff: number): bigint | undefined {
  const o = fieldOff(bb, tablePos, voff);
  return o ? BigInt(bb.readInt64(tablePos + o)) : undefined;
}

/** Read a uint64 field exactly. */
function readU64(bb: BB, tablePos: number, voff: number): bigint {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return 0n;
  return BigInt(bb.readUint64(tablePos + o));
}

function readU64Optional(bb: BB, tablePos: number, voff: number): bigint | undefined {
  const o = fieldOff(bb, tablePos, voff);
  return o ? BigInt(bb.readUint64(tablePos + o)) : undefined;
}

function exactInteger(value: bigint): number | string {
  return value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER)
    ? Number(value)
    : value.toString(10);
}

function intLiteral(value: bigint, signed: boolean): CIntLitExpr {
  const exactValue = value.toString(10);
  const safe = value >= BigInt(Number.MIN_SAFE_INTEGER) && value <= BigInt(Number.MAX_SAFE_INTEGER);
  return {
    kind: 'CIntLitExpr',
    value: safe ? Number(value) : exactValue,
    exactValue,
    width: 64,
    signed,
  };
}

function unknownExpr(sourceKind: number, reason: string): CUnknownExpr {
  return { kind: 'CUnknownExpr', sourceKind, reason, lossy: true };
}

function unknownStmt(sourceKind: number, reason: string): CUnknownStmt {
  return { kind: 'CUnknownStmt', sourceKind, reason, lossy: true };
}

/** Read a float64 field. */
function readF64(bb: BB, tablePos: number, voff: number): number {
  const o = fieldOff(bb, tablePos, voff);
  return o ? bb.readFloat64(tablePos + o) : 0;
}

/** Get the length and start of a vector field. Returns [start, len]. */
function readVec(bb: BB, tablePos: number, voff: number, elementSize = 4): [number, number] | null {
  const o = fieldOff(bb, tablePos, voff);
  if (!o) return null;
  const vecPos = tablePos + o;
  const start = bb.__vector(vecPos);
  const len = bb.__vector_len(vecPos);
  // `len` is a raw attacker-influenced int32; reject a vector whose element range
  // [start, start + len*4) falls outside the buffer (each element is a 4-byte
  // offset). Without this a huge len drives an unbounded caller loop / OOM -- the
  // flatbuffers ByteBuffer does NO bounds-checking, so the out-of-range element
  // reads return garbage instead of throwing and the loop just churns.
  if (len < 0 || start < 0 || start + len * elementSize > bb.capacity()) { return null; }
  return [start, len];
}

function readByteVec(bb: BB, tablePos: number, voff: number): number[] | undefined {
  const vector = readVec(bb, tablePos, voff, 1);
  if (!vector) return undefined;
  const [start, len] = vector;
  if (start + len > bb.capacity()) throw new Error('HAST byte vector exceeds the buffer');
  return Array.from({ length: len }, (_, index) => bb.readUint8(start + index));
}

// ─── DataType → type string ───

function readTypeStr(bb: BB, pos: number): string {
  assertValidTable(bb, pos, 'DataType');
  const kind = readU8(bb, pos, DT_KIND, 0);
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

function storageName(value: number): CVarDecl['storage'] {
  const names: NonNullable<CVarDecl['storage']>[] = ['stack', 'register', 'global', 'parameter', 'temporary'];
  return names[value] ?? 'unknown';
}

function variableMetadata(bb: BB, pos: number): Pick<CVarDecl, 'type' | 'identityId' | 'storage' | 'stackOffset' | 'parameterIndex'> {
  let type = 'unknown';
  const typePos = readTable(bb, pos, V_TYPE);
  if (typePos) type = readTypeStr(bb, typePos);
  const identityId = readU64Optional(bb, pos, V_IDENTITY_ID);
  const stackOffset = readI64Optional(bb, pos, V_STACK_OFFSET);
  const parameterOffset = fieldOff(bb, pos, V_PARAMETER_INDEX);
  return {
    type,
    ...(identityId !== undefined ? { identityId: identityId.toString(10) } : {}),
    storage: storageName(readU8(bb, pos, V_STORAGE, 0)),
    ...(stackOffset !== undefined ? { stackOffset: exactInteger(stackOffset) } : {}),
    ...(parameterOffset ? { parameterIndex: bb.readUint32(pos + parameterOffset) } : {}),
  };
}

// ─── Expression → CNode ───

function readExpr(bb: BB, pos: number): CNode {
  assertValidTable(bb, pos, 'Expression');
  const kind = readU8(bb, pos, E_KIND, 0);
  const nodeId = readU64Optional(bb, pos, E_NODE_ID);
  const sourceAddress = readU64Optional(bb, pos, E_SOURCE_ADDRESS);
  const resultTypePos = readTable(bb, pos, E_RESULT_TYPE);
  const common = {
    ...(nodeId !== undefined ? { nodeId: nodeId.toString(10) } : {}),
    ...(sourceAddress !== undefined ? { sourceAddress: `0x${sourceAddress.toString(16)}` } : {}),
    ...(resultTypePos ? { resultType: readTypeStr(bb, resultTypePos) } : {}),
  };

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
      return { ...intLiteral(value, true), ...common };
    }
    case 1: { // FloatLit
      const value = readF64(bb, pos, E_FLOAT_VALUE);
      return {
        kind: 'CFloatLitExpr',
        ...common,
        value,
        precision: 'double',
      } satisfies CFloatLitExpr;
    }
    case 2: // StringLit
      return {
        kind: 'CStringLitExpr',
        ...common,
        value: strVal ?? '',
        encoding: 'ascii',
      } satisfies CStringLitExpr;

    case 12: { // AddressLit
      const addr = readU64(bb, pos, E_ADDRESS);
      return {
        kind: 'CAddrLitExpr',
        ...common,
        address: `0x${addr.toString(16)}`,
      } satisfies CAddrLitExpr;
    }
    case 3: { // VarRef
      const varPos = readTable(bb, pos, E_VARIABLE);
      const metadata = varPos ? variableMetadata(bb, varPos) : { type: 'unknown' };
      return {
        kind: 'CVarRefExpr',
        ...common,
        name: strVal ?? 'var',
        ...metadata,
      } satisfies CVarRefExpr;
    }
    case 5: // Binary
      return {
        kind: 'CBinaryExpr',
        ...common,
        operator: opStr ?? '?',
        left: childrenArr[0] ?? unknownExpr(kind, 'binary expression missing left operand'),
        right: childrenArr[1] ?? unknownExpr(kind, 'binary expression missing right operand'),
      } satisfies CBinaryExpr;

    case 4: // Unary
      return {
        kind: 'CUnaryExpr',
        ...common,
        operator: opStr ?? '?',
        operand: childrenArr[0] ?? unknownExpr(kind, 'unary expression missing operand'),
        prefix: true,
      } satisfies CUnaryExpr;

    case 6: { // Cast
      let targetType = 'unknown';
      const ctPos = readTable(bb, pos, E_CAST_TYPE);
      if (ctPos) targetType = readTypeStr(bb, ctPos);
      return {
        kind: 'CCastExpr',
        ...common,
        targetType,
        operand: childrenArr[0] ?? unknownExpr(kind, 'cast expression missing operand'),
      } satisfies CCastExpr;
    }
    case 7: { // Call
      const callTarget = readU64Optional(bb, pos, E_CALL_TARGET);
      return {
        kind: 'CCallExpr',
        ...common,
        callee: strVal ?? 'unknown',
        arguments: childrenArr,
        ...(callTarget !== undefined ? { callTarget: `0x${callTarget.toString(16)}` } : {}),
      } satisfies CCallExpr;
    }

    case 11: // Ternary
      return {
        kind: 'CTernaryExpr',
        ...common,
        condition: childrenArr[0] ?? unknownExpr(kind, 'ternary expression missing condition'),
        consequent: childrenArr[1] ?? unknownExpr(kind, 'ternary expression missing consequent'),
        alternate: childrenArr[2] ?? unknownExpr(kind, 'ternary expression missing alternate'),
      } satisfies CTernaryExpr;

    case 8: // Subscript
      return {
        kind: 'CSubscriptExpr',
        ...common,
        base: childrenArr[0] ?? unknownExpr(kind, 'subscript expression missing base'),
        index: childrenArr[1] ?? unknownExpr(kind, 'subscript expression missing index'),
      } satisfies CSubscriptExpr;

    case 9: { // Member (.)
      const fieldOffset = readU64Optional(bb, pos, E_FIELD_OFFSET);
      return {
        kind: 'CFieldAccessExpr',
        ...common,
        object: childrenArr[0] ?? unknownExpr(kind, 'field access missing object'),
        field: strVal ?? 'field',
        arrow: false,
        ...(fieldOffset !== undefined ? { fieldOffset: `0x${fieldOffset.toString(16)}` } : {}),
      } satisfies CFieldAccessExpr;
    }

    case 10: { // DerefMember (->)
      const fieldOffset = readU64Optional(bb, pos, E_FIELD_OFFSET);
      return {
        kind: 'CFieldAccessExpr',
        ...common,
        object: childrenArr[0] ?? unknownExpr(kind, 'field access missing object'),
        field: strVal ?? 'field',
        arrow: true,
        ...(fieldOffset !== undefined ? { fieldOffset: `0x${fieldOffset.toString(16)}` } : {}),
      } satisfies CFieldAccessExpr;
    }

    default:
      // Unknown expressions remain explicit loss markers.
      return { ...unknownExpr(kind, strVal ?? `unsupported expression kind ${kind}`), ...common };
  }
}

// ─── Statement → CNode ───

function readStmt(bb: BB, pos: number): CNode {
  assertValidTable(bb, pos, 'Statement');
  const kind = readU8(bb, pos, S_KIND, 0);
  const text = readStr(bb, pos, S_TEXT);
  const nodeId = readU64Optional(bb, pos, S_NODE_ID);
  const sourceAddress = readU64Optional(bb, pos, S_SOURCE_ADDRESS);
  const common = {
    ...(nodeId !== undefined ? { nodeId: nodeId.toString(10) } : {}),
    ...(sourceAddress !== undefined ? { sourceAddress: `0x${sourceAddress.toString(16)}` } : {}),
  };

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
  const childRoles = readByteVec(bb, pos, S_CHILD_ROLES);
  if (childRoles && childRoles.length !== children.length) {
    throw new Error(`Statement child_roles length ${childRoles.length} does not match children length ${children.length}`);
  }

  switch (kind) {
    case 0: { // VarDecl
      const varPos = readTable(bb, pos, S_VARIABLE);
      let name = 'var';
      let metadata: ReturnType<typeof variableMetadata> = { type: 'unknown' };
      if (varPos) {
        name = readStr(bb, varPos, V_NAME) ?? 'var';
        metadata = variableMetadata(bb, varPos);
      }
      return {
        kind: 'CVarDecl',
        ...common,
        name,
        ...metadata,
        init: exprs[0],
      } satisfies CVarDecl;
    }

    case 1: { // Assign
      // The HQL CNode types don't have a standalone CAssignStmt.
      // Map to a binary expression with '=' operator wrapped in a block.
	  const unaryCompound = text === '++' || text === '--';
      return {
        kind: 'CAssignStmt',
        ...common,
        target: exprs[0] ?? unknownExpr(kind, 'assignment missing destination'),
		...(exprs[1]
		  ? { value: exprs[1] }
		  : unaryCompound
			? {}
			: { value: unknownExpr(kind, 'assignment missing source') }),
        ...(text ? { compoundOperator: text } : {}),
      } satisfies CAssignStmt;
	}

    case 2: // ExprStmt → unwrap the expression
      return {
        kind: 'CExprStmt',
        ...common,
        expression: exprs[0] ?? unknownExpr(kind, 'expression statement missing expression'),
      } satisfies CExprStmt;

    case 3: // Return
      return {
        kind: 'CReturnStmt',
        ...common,
        value: exprs[0],
      } satisfies CReturnStmt;

    case 4: { // If
      // text = number of then-body statements. parseInt can yield NaN (non-numeric
      // S_TEXT) or a negative/oversized value; clamp it like the For-case below so
      // a malformed count cannot silently swap/lose the then vs else bodies.
      let thenBody: CNode[];
      let elseBody: CNode[];
      if (childRoles) {
        if (childRoles.some(role => role !== 1 && role !== 2)) throw new Error('If statement has invalid typed child role');
        thenBody = children.filter((_, index) => childRoles[index] === 1);
        elseBody = children.filter((_, index) => childRoles[index] === 2);
      } else {
        let thenCount = text ? parseInt(text, 10) : children.length;
        if (!Number.isFinite(thenCount)) { thenCount = children.length; }
        thenCount = Math.max(0, Math.min(thenCount, children.length));
        thenBody = children.slice(0, thenCount);
        elseBody = children.slice(thenCount);
      }
      const thenBlock: CBlockStmt = { kind: 'CBlockStmt', body: thenBody };
      const elseBlock: CBlockStmt | undefined =
        elseBody.length > 0 ? { kind: 'CBlockStmt', body: elseBody } : undefined;
      return {
        kind: 'CIfStmt',
        ...common,
        condition: exprs[0] ?? unknownExpr(kind, 'if statement missing condition'),
        then: thenBlock,
        ...(elseBlock ? { else: elseBlock } : {}),
      } satisfies CIfStmt;
    }

    case 5: // While
      return {
        kind: 'CWhileStmt',
        ...common,
        condition: exprs[0] ?? unknownExpr(kind, 'while statement missing condition'),
        body: { kind: 'CBlockStmt', body: children } satisfies CBlockStmt,
      } satisfies CWhileStmt;

    case 6: // DoWhile
      return {
        kind: 'CDoWhileStmt',
        ...common,
        condition: exprs[0] ?? unknownExpr(kind, 'do-while statement missing condition'),
        body: { kind: 'CBlockStmt', body: children } satisfies CBlockStmt,
      } satisfies CDoWhileStmt;

    case 7: { // For
      // text = "has_init,has_step" e.g. "1,1"
      let init: CNode | undefined;
      let step: CNode | undefined;
      let body: CNode[];
      if (childRoles) {
        if (childRoles.some(role => role !== 3 && role !== 4 && role !== 5)) throw new Error('For statement has invalid typed child role');
        init = children.find((_, index) => childRoles[index] === 4);
        step = children.find((_, index) => childRoles[index] === 5);
        body = children.filter((_, index) => childRoles[index] === 3);
      } else {
        let hasInit = 0, hasStep = 0;
        if (text) {
          const parts = text.split(',');
          hasInit = parseInt(parts[0], 10) || 0;
          hasStep = parseInt(parts[1], 10) || 0;
        }
        let index = 0;
        init = hasInit ? children[index++] : undefined;
        step = hasStep ? children[index++] : undefined;
        body = children.slice(index);
      }
      return {
        kind: 'CForStmt',
        ...common,
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
        ...common,
        discriminant: exprs[0] ?? unknownExpr(kind, 'switch statement missing discriminant'),
        cases,
      } satisfies CSwitchStmt;
    }

    case 9: // Break
      return { kind: 'CBreakStmt', ...common } satisfies CBreakStmt;

    case 10: // Continue
      return { kind: 'CContinueStmt', ...common } satisfies CContinueStmt;

    case 11: // Goto
      return {
        kind: 'CGotoStmt',
        ...common,
        label: text ?? 'unknown',
      } satisfies CGotoStmt;

    case 12: // Label
      return {
        kind: 'CLabelStmt',
        ...common,
        label: text ?? 'unknown',
        body: children[0] ?? unknownStmt(kind, 'label statement missing body'),
      } satisfies CLabelStmt;

    case 13: // Asm
      return { kind: 'CAsmStmt', ...common, text: text ?? '' } satisfies CAsmStmt;

    case 14: // Comment
      return { kind: 'CCommentStmt', ...common, text: text ?? '' } satisfies CCommentStmt;

    case 15: // Block
      return { kind: 'CBlockStmt', ...common, body: children } satisfies CBlockStmt;

    default:
      return { ...unknownStmt(kind, `unsupported statement kind ${kind}`), ...common };
  }
}

function readSwitchCase(bb: BB, pos: number): CCaseStmt {
  assertValidTable(bb, pos, 'SwitchCase');
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
      value = intLiteral(BigInt(bb.readInt64(start)), true);
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
  assertValidTable(bb, pos, 'Variable');
  const name = readStr(bb, pos, V_NAME) ?? 'var';

  return {
    kind: 'CVarDecl',
    name,
    ...variableMetadata(bb, pos),
  };
}

// ─── DecompiledFunction → CFunctionDecl ───

function readFunction(bb: BB, pos: number, session: SessionDbReader | undefined, hast: HASTModuleMetadata): CFunctionDecl {
  assertValidTable(bb, pos, 'DecompiledFunction');
  let name = readStr(bb, pos, F_NAME) ?? 'unknown';
  const address = readU64(bb, pos, F_ADDRESS);
  const addrHex = `0x${address.toString(16)}`;

  let returnType = 'void';
  const rtPos = readTable(bb, pos, F_RETURN_TYPE);
  if (rtPos) returnType = readTypeStr(bb, rtPos);

  // v3.7.4: Apply analyst renames/retypes from session database
  if (session) {
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

  const locals: CVarDecl[] = [];
  const lv = readVec(bb, pos, F_LOCALS);
  if (lv) {
    const [start, len] = lv;
    for (let index = 0; index < len; index++) locals.push(readVariable(bb, bb.__indirect(start + index * 4)));
  }

  // v3.7.4: Apply variable renames from session database
  if (session) {
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

  const fn: CFunctionDecl = {
    kind: 'CFunctionDecl',
    name,
    address: addrHex,
    returnType,
    params,
    locals,
    body,
    callingConvention: readStr(bb, pos, F_CALLING_CONVENTION) ?? 'unknown',
    isVariadic: readU8(bb, pos, F_IS_VARIADIC, 0) !== 0,
    hast,
  };
  applyFunctionVariableMetadata(fn);
  fn.adapterCoverage = measureAdapterCoverage(fn);
  return fn;
}

function applyFunctionVariableMetadata(fn: CFunctionDecl): void {
  const declarations = new Map<string, CVarDecl>();
  for (const declaration of [...fn.params, ...(fn.locals ?? [])]) {
    if (declaration.identityId !== undefined) declarations.set(declaration.identityId, declaration);
  }
  const visit = (node: CNode): void => {
    if (node.kind === 'CVarRefExpr' && node.identityId !== undefined) {
      const declaration = declarations.get(node.identityId);
      if (declaration) {
        node.type = declaration.type;
        node.storage = declaration.storage;
        node.stackOffset = declaration.stackOffset;
        node.parameterIndex = declaration.parameterIndex;
      }
    }
    for (const child of directChildren(node)) visit(child);
  };
  if (fn.body) visit(fn.body);
}

function directChildren(node: CNode): CNode[] {
  switch (node.kind) {
    case 'CBinaryExpr': return [node.left, node.right];
    case 'CUnaryExpr':
    case 'CCastExpr': return [node.operand];
    case 'CCallExpr': return node.arguments;
    case 'CTernaryExpr': return [node.condition, node.consequent, node.alternate];
    case 'CSubscriptExpr': return [node.base, node.index];
    case 'CFieldAccessExpr': return [node.object];
    case 'CArrayInitExpr': return node.elements;
    case 'CCompoundLitExpr': return node.fields;
    case 'CBlockStmt': return node.body;
    case 'CAssignStmt': return node.value ? [node.target, node.value] : [node.target];
    case 'CExprStmt': return [node.expression];
    case 'CIfStmt': return node.else ? [node.condition, node.then, node.else] : [node.condition, node.then];
    case 'CForStmt': return [node.init, node.condition, node.update, node.body].filter((n): n is CNode => n !== undefined);
    case 'CWhileStmt':
    case 'CDoWhileStmt': return [node.condition, node.body];
    case 'CReturnStmt': return node.value ? [node.value] : [];
    case 'CSwitchStmt': return [node.discriminant, ...node.cases];
    case 'CCaseStmt': return node.value ? [node.value, ...node.body] : node.body;
    case 'CLabelStmt': return [node.body];
    case 'CFunctionDecl': {
      const declarations = [...node.params, ...(node.locals ?? [])];
      return node.body ? [...declarations, node.body] : declarations;
    }
    case 'CVarDecl': return node.init ? [node.init] : [];
    case 'CStructDecl': return node.fields;
    default: return [];
  }
}

function measureAdapterCoverage(root: CNode): HASTAdapterCoverage {
  let totalNodes = 0;
  let lossyNodes = 0;
  const unsupportedNodeCounts: Record<string, number> = {};
  const visit = (node: CNode): void => {
    totalNodes++;
    if (node.kind === 'CUnknownExpr' || node.kind === 'CUnknownStmt' || node.kind === 'CAsmStmt') {
      lossyNodes++;
      const key = node.kind === 'CUnknownExpr' || node.kind === 'CUnknownStmt'
        ? `${node.kind}:${node.sourceKind}`
        : node.kind;
      unsupportedNodeCounts[key] = (unsupportedNodeCounts[key] ?? 0) + 1;
    }
    for (const child of directChildren(node)) visit(child);
  };
  visit(root);
  return {
    totalNodes,
    lossyNodes,
    coverage: totalNodes === 0 ? 0 : (totalNodes - lossyNodes) / totalNodes,
    unsupportedNodeCounts,
  };
}

function architectureName(value: number): string {
  return ['x86', 'x86_64', 'arm', 'aarch64', 'mips', 'mips64', 'powerpc', 'powerpc64', 'sparc', 'sparc64', 'riscv32', 'riscv64'][value] ?? 'unknown';
}

function readModuleMetadata(bb: BB, rootPos: number): HASTModuleMetadata {
  const schemaMajor = readU16(bb, rootPos, M_SCHEMA_MAJOR, 0);
  const schemaMinor = readU16(bb, rootPos, M_SCHEMA_MINOR, 0);
  if (schemaMajor > 1) throw new Error(`Unsupported HAST schema major ${schemaMajor}`);
  const capabilityIds = readByteVec(bb, rootPos, M_CAPABILITIES) ?? [];
  const capabilities: string[] = capabilityIds.map(id => HAST_CAPABILITIES[id] ?? `unknown-${id}`);
  const producer = readStr(bb, rootPos, M_PRODUCER);
  const producerVersion = readStr(bb, rootPos, M_PRODUCER_VERSION);
  const requiredSemanticCapabilities = ['node-ids', 'symbol-identities', 'typed-child-roles'];
  return {
    schemaMajor,
    schemaMinor,
    capabilities,
    ...(producer ? { producer } : {}),
    ...(producerVersion ? { producerVersion } : {}),
    architecture: architectureName(readU8(bb, rootPos, M_ARCH, 255)),
    pointerBits: readU16(bb, rootPos, M_POINTER_BITS, 0),
    semanticEligible: schemaMajor === 1 && requiredSemanticCapabilities.every(capability => capabilities.includes(capability)),
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
  assertValidTable(bb, rootOff, 'AstModule');
  const moduleMetadata = readModuleMetadata(bb, rootOff);

  // Read functions vector
  const functions: CFunctionDecl[] = [];
  const fv = readVec(bb, rootOff, M_FUNCTIONS);
  if (fv) {
    const [start, len] = fv;
    for (let i = 0; i < len; i++) {
      const fPos = bb.__indirect(start + i * 4);
      try {
        functions.push(readFunction(bb, fPos, session, moduleMetadata));
      } catch (error) {
        const reason = `HAST function[${i}] hydration failed: ${error instanceof Error ? error.message : String(error)}`.slice(0, 512);
        const unknown = unknownStmt(255, reason);
        functions.push({
          kind: 'CFunctionDecl',
          name: `<unhydrated_${i}>`,
          address: `hast-index:${i}`,
          returnType: 'unknown',
          params: [],
          locals: [],
          body: { kind: 'CBlockStmt', body: [unknown] },
          callingConvention: 'unknown',
          isVariadic: false,
          hast: moduleMetadata,
          adapterCoverage: {
            totalNodes: 3,
            lossyNodes: 1,
            coverage: 2 / 3,
            unsupportedNodeCounts: { 'CUnknownStmt:255': 1 },
            errors: [reason],
          },
        });
      }
    }
  }

  return functions;
}
