// ─── Helix C-AST Node Type Definitions ───
// 31 node types exported by the Helix decompiler (MLIR/C++23).
// Discriminated union via `kind` tag — no reflection, no runtime overhead.

// ─── Base ───

export interface ASTNodeBase {
  /** Discriminator tag — matches the Helix node type name */
  kind: string;
  /** Source location from decompiled output (optional) */
  loc?: { line: number; col: number; file?: string };
  /** Stable function-local HAST node identity (canonical uint64 decimal). */
  nodeId?: string;
  /** Exact machine-code source address when retained by Helix. */
  sourceAddress?: string;
  resultType?: string;
}

// ─── Expressions ───

export interface CIntLitExpr extends ASTNodeBase {
  kind: 'CIntLitExpr';
  /** Safe JS number when exact; canonical decimal string beyond 2^53. */
  value: number | string;
  /** Canonical exact decimal representation, always present for hydrated HAST. */
  exactValue?: string;
  width: number; // bit-width: 8, 16, 32, 64
  signed: boolean;
}

export interface CFloatLitExpr extends ASTNodeBase {
  kind: 'CFloatLitExpr';
  value: number;
  precision: 'float' | 'double';
}

export interface CStringLitExpr extends ASTNodeBase {
  kind: 'CStringLitExpr';
  value: string;
  encoding: 'ascii' | 'utf8' | 'wide';
}

export interface CAddrLitExpr extends ASTNodeBase {
  kind: 'CAddrLitExpr';
  address: string; // hex string, e.g. "0x401000"
  symbol?: string; // resolved symbol name if available
}

export interface CVarRefExpr extends ASTNodeBase {
  kind: 'CVarRefExpr';
  name: string;
  type: string;
  identityId?: string;
  storage?: 'stack' | 'register' | 'global' | 'parameter' | 'temporary' | 'unknown';
  stackOffset?: number | string;
  parameterIndex?: number;
}

export interface CBinaryExpr extends ASTNodeBase {
  kind: 'CBinaryExpr';
  operator: string; // +, -, *, /, %, ^, &, |, <<, >>, ==, !=, <, >, <=, >=, &&, ||
  left: CNode;
  right: CNode;
}

export interface CUnaryExpr extends ASTNodeBase {
  kind: 'CUnaryExpr';
  operator: string; // !, ~, -, ++, --, &, *
  operand: CNode;
  prefix: boolean;
}

export interface CCastExpr extends ASTNodeBase {
  kind: 'CCastExpr';
  targetType: string;
  operand: CNode;
}

export interface CCallExpr extends ASTNodeBase {
  kind: 'CCallExpr';
  callee: string;
  arguments: CNode[];
  callTarget?: string;
}

export interface CTernaryExpr extends ASTNodeBase {
  kind: 'CTernaryExpr';
  condition: CNode;
  consequent: CNode;
  alternate: CNode;
}

export interface CSubscriptExpr extends ASTNodeBase {
  kind: 'CSubscriptExpr';
  base: CNode;
  index: CNode;
}

export interface CFieldAccessExpr extends ASTNodeBase {
  kind: 'CFieldAccessExpr';
  object: CNode;
  field: string;
  arrow: boolean; // true = "->", false = "."
  fieldOffset?: string;
}

export interface CArrayInitExpr extends ASTNodeBase {
  kind: 'CArrayInitExpr';
  elements: CNode[];
}

export interface CCompoundLitExpr extends ASTNodeBase {
  kind: 'CCompoundLitExpr';
  type: string;
  fields: CNode[];
}

// ─── Statements ───

export interface CBlockStmt extends ASTNodeBase {
  kind: 'CBlockStmt';
  body: CNode[];
}

export interface CAssignStmt extends ASTNodeBase {
  kind: 'CAssignStmt';
  target: CNode;
  /** Absent only for self-contained unary compound forms (`++` / `--`). */
  value?: CNode;
  compoundOperator?: string;
}

export interface CExprStmt extends ASTNodeBase {
  kind: 'CExprStmt';
  expression: CNode;
}

export interface CIfStmt extends ASTNodeBase {
  kind: 'CIfStmt';
  condition: CNode;
  then: CNode;
  else?: CNode;
}

export interface CForStmt extends ASTNodeBase {
  kind: 'CForStmt';
  init?: CNode;
  condition?: CNode;
  update?: CNode;
  body: CNode;
}

export interface CWhileStmt extends ASTNodeBase {
  kind: 'CWhileStmt';
  condition: CNode;
  body: CNode;
}

export interface CDoWhileStmt extends ASTNodeBase {
  kind: 'CDoWhileStmt';
  condition: CNode;
  body: CNode;
}

export interface CReturnStmt extends ASTNodeBase {
  kind: 'CReturnStmt';
  value?: CNode;
}

export interface CSwitchStmt extends ASTNodeBase {
  kind: 'CSwitchStmt';
  discriminant: CNode;
  cases: CCaseStmt[];
}

export interface CCaseStmt extends ASTNodeBase {
  kind: 'CCaseStmt';
  value?: CNode;  // undefined = default case
  body: CNode[];
}

export interface CBreakStmt extends ASTNodeBase {
  kind: 'CBreakStmt';
}

export interface CContinueStmt extends ASTNodeBase {
  kind: 'CContinueStmt';
}

export interface CGotoStmt extends ASTNodeBase {
  kind: 'CGotoStmt';
  label: string;
}

export interface CLabelStmt extends ASTNodeBase {
  kind: 'CLabelStmt';
  label: string;
  body: CNode;
}

// ─── Declarations ───

export interface CFunctionDecl extends ASTNodeBase {
  kind: 'CFunctionDecl';
  name: string;
  address?: string;
  returnType: string;
  params: CVarDecl[];
  locals?: CVarDecl[];
  body?: CBlockStmt;
  callingConvention?: string;
  isVariadic?: boolean;
  hast?: HASTModuleMetadata;
  adapterCoverage?: HASTAdapterCoverage;
}

export interface CVarDecl extends ASTNodeBase {
  kind: 'CVarDecl';
  name: string;
  type: string;
  init?: CNode;
  identityId?: string;
  storage?: 'stack' | 'register' | 'global' | 'parameter' | 'temporary' | 'unknown';
  stackOffset?: number | string;
  parameterIndex?: number;
}

export interface CStructDecl extends ASTNodeBase {
  kind: 'CStructDecl';
  name: string;
  fields: CVarDecl[];
}

export interface CTypedefDecl extends ASTNodeBase {
  kind: 'CTypedefDecl';
  name: string;
  underlyingType: string;
}

export interface CEnumDecl extends ASTNodeBase {
  kind: 'CEnumDecl';
  name: string;
  members: { name: string; value?: number | string }[];
}

export interface CUnknownExpr extends ASTNodeBase {
  kind: 'CUnknownExpr';
  sourceKind: number;
  reason: string;
  lossy: true;
}

export interface CUnknownStmt extends ASTNodeBase {
  kind: 'CUnknownStmt';
  sourceKind: number;
  reason: string;
  lossy: true;
}

export interface CAsmStmt extends ASTNodeBase {
  kind: 'CAsmStmt';
  text: string;
}

export interface CCommentStmt extends ASTNodeBase {
  kind: 'CCommentStmt';
  text: string;
}

export interface HASTAdapterCoverage {
  totalNodes: number;
  lossyNodes: number;
  coverage: number;
  unsupportedNodeCounts: Record<string, number>;
  /** Function-level hydration failures retained instead of silently dropped. */
  errors?: string[];
}

export interface HASTModuleMetadata {
  schemaMajor: number;
  schemaMinor: number;
  capabilities: string[];
  producer?: string;
  producerVersion?: string;
  architecture?: string;
  pointerBits?: number;
  semanticEligible: boolean;
}

export const HAST_CAPABILITIES = Object.freeze([
  'node-ids',
  'source-addresses',
  'symbol-identities',
  'typed-child-roles',
  'call-targets',
  'field-offsets',
  'expression-result-types',
] as const);

// ─── Discriminated Union ───

export type CNode =
  // Expressions
  | CIntLitExpr
  | CFloatLitExpr
  | CStringLitExpr
  | CAddrLitExpr
  | CVarRefExpr
  | CBinaryExpr
  | CUnaryExpr
  | CCastExpr
  | CCallExpr
  | CTernaryExpr
  | CSubscriptExpr
  | CFieldAccessExpr
  | CArrayInitExpr
  | CCompoundLitExpr
  // Statements
  | CBlockStmt
  | CAssignStmt
  | CExprStmt
  | CIfStmt
  | CForStmt
  | CWhileStmt
  | CDoWhileStmt
  | CReturnStmt
  | CSwitchStmt
  | CCaseStmt
  | CBreakStmt
  | CContinueStmt
  | CGotoStmt
  | CLabelStmt
  // Declarations
  | CFunctionDecl
  | CVarDecl
  | CStructDecl
  | CTypedefDecl
  | CEnumDecl
  | CUnknownExpr
  | CUnknownStmt
  | CAsmStmt
  | CCommentStmt;

export type CLossAwareNode = CUnknownExpr | CUnknownStmt | CAsmStmt | CCommentStmt;

/** All valid node kind strings */
export type CNodeKind = CNode['kind'];

export const C_NODE_KINDS: readonly CNodeKind[] = [
  'CIntLitExpr', 'CFloatLitExpr', 'CStringLitExpr', 'CAddrLitExpr', 'CVarRefExpr',
  'CBinaryExpr', 'CUnaryExpr', 'CCastExpr', 'CCallExpr', 'CTernaryExpr',
  'CSubscriptExpr', 'CFieldAccessExpr', 'CArrayInitExpr', 'CCompoundLitExpr',
  'CBlockStmt', 'CAssignStmt', 'CExprStmt', 'CIfStmt', 'CForStmt', 'CWhileStmt', 'CDoWhileStmt', 'CReturnStmt',
  'CSwitchStmt', 'CCaseStmt', 'CBreakStmt', 'CContinueStmt', 'CGotoStmt', 'CLabelStmt',
  'CFunctionDecl', 'CVarDecl', 'CStructDecl', 'CTypedefDecl', 'CEnumDecl',
  'CUnknownExpr', 'CUnknownStmt', 'CAsmStmt', 'CCommentStmt',
];
