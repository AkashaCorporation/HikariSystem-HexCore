// ─── hexcore-hql Public API ───
// Clean entry point for the HexCore pipeline.

// AST Types
export type {
  ASTNodeBase,
  CNode,
  CNodeKind,
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
  CArrayInitExpr,
  CCompoundLitExpr,
  CBlockStmt,
  CIfStmt,
  CForStmt,
  CWhileStmt,
  CDoWhileStmt,
  CReturnStmt,
  CSwitchStmt,
  CCaseStmt,
  CBreakStmt,
  CContinueStmt,
  CGotoStmt,
  CLabelStmt,
  CFunctionDecl,
  CVarDecl,
  CStructDecl,
  CTypedefDecl,
  CEnumDecl,
} from './types/ast.js';

// HQL Query Types
export type {
  HQLQuery,
  HQLAttributeCheck,
  HQLOperandCheck,
  HQLSignature,
  HQLMatchResult,
} from './types/hql.js';

// Matcher Engine
export { HQLMatcher } from './engine/matcher.js';

// HAST FlatBuffer Adapter
export { hydrateHAST } from './adapter/flatbuf.js';

// v3.7.4: Session DB Reader (read-only access to disassembler's .hexcore_session.db)
export { SessionDbReader } from './adapter/sessionDb.js';
export type { SessionFunctionEntry, SessionVariableRename, HexcoreBetterSqlite3Module } from './adapter/sessionDb.js';
