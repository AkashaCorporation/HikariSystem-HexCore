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
  CAssignStmt,
  CExprStmt,
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
  CUnknownExpr,
  CUnknownStmt,
  CAsmStmt,
  CCommentStmt,
  HASTAdapterCoverage,
  HASTModuleMetadata,
  CLossAwareNode,
} from './types/ast.js';
export { C_NODE_KINDS, HAST_CAPABILITIES } from './types/ast.js';

// HQL Query Types
export type {
  HQLQuery,
  HQLAttributeCheck,
  HQLOperandCheck,
  HQLSignature,
  HQLMatchResult,
  HQLCondition,
  HQLCountCondition,
  HQLEvidenceLevel,
  HQLRuleStatus,
  HQLRuleProvenance,
  HQLCompatibility,
  HQLSemanticFactKind,
  HQLSemanticFact,
  HQLSemanticQuery,
  HQLSemanticCondition,
} from './types/hql.js';

// Matcher Engine
export { HQLMatcher } from './engine/matcher.js';

// HAST FlatBuffer Adapter
export { hydrateHAST } from './adapter/flatbuf.js';

// Built-in signature library + one-call scan API
export { BUILTIN_SIGNATURES } from './signatures/builtin.js';
export {
  getDefaultSignatures,
  loadSignatureDirectory,
  mergeSignatureLibraries,
} from './signatures/loader.js';
export { scanHAST, signatureSetSha256 } from './scan.js';
export type { HQLFunctionFindings, HQLScanOptions } from './scan.js';
export * from './atlas/index.js';

// v3.7.4: Session DB Reader (read-only access to disassembler's .hexcore_session.db)
export { SessionDbReader } from './adapter/sessionDb.js';
export type { SessionFunctionEntry, SessionVariableRename, HexcoreBetterSqlite3Module } from './adapter/sessionDb.js';
