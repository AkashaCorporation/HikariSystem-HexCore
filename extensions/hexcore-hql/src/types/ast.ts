// ─── Helix C-AST Node Type Definitions ───
// 31 node types exported by the Helix decompiler (MLIR/C++23).
// Discriminated union via `kind` tag — no reflection, no runtime overhead.

// ─── Base ───

export interface ASTNodeBase {
  /** Discriminator tag — matches the Helix node type name */
  kind: string;
  /** Source location from decompiled output (optional) */
  loc?: { line: number; col: number; file?: string };
}

// ─── Expressions ───

export interface CIntLitExpr extends ASTNodeBase {
  kind: 'CIntLitExpr';
  value: number;
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
  returnType: string;
  params: CVarDecl[];
  body?: CBlockStmt;
}

export interface CVarDecl extends ASTNodeBase {
  kind: 'CVarDecl';
  name: string;
  type: string;
  init?: CNode;
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
  members: { name: string; value?: number }[];
}

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
  | CEnumDecl;

/** All valid node kind strings */
export type CNodeKind = CNode['kind'];
