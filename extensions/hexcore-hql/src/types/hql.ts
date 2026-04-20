// ─── HQL Query DSL ───
// JSON-like query structure for semantic pattern matching against C-AST.
// No regex, no opcodes. Nodes, edges, operators.

import type { CNodeKind, CNode } from './ast.js';

/** Attribute predicate — match against node properties */
export interface HQLAttributeCheck {
  /** Property name on the AST node (e.g. "operator", "callee", "name") */
  field: string;
  /**
   * Expected value. Matching rules:
   * - string: exact match or glob pattern (with *)
   * - number: exact numeric match
   * - boolean: exact boolean match
   * - RegExp-like string prefixed with "re:": regex match (e.g. "re:^memcpy|memmove$")
   */
  value: string | number | boolean;
}

/** Positional operand check — for expressions with ordered children */
export interface HQLOperandCheck {
  /** Operand position (0-indexed) */
  position: number;
  /** Sub-query the operand must satisfy */
  query: HQLQuery;
}

/** Core query node — recursive structure for tree matching */
export interface HQLQuery {
  /** Target node kind to match (e.g. "CCallExpr", "CBinaryExpr") */
  target?: CNodeKind;
  /** Attribute predicates — ALL must match (AND semantics) */
  attributes?: HQLAttributeCheck[];
  /**
   * Containment queries — the matched node's subtree must contain
   * nodes satisfying these sub-queries. DFS semantic search.
   */
  contains?: HQLQuery[];
  /** Positional operand checks for expression nodes */
  operands?: HQLOperandCheck[];
  /**
   * Minimum depth at which `contains` matches should be searched.
   * Useful to skip shallow matches. Default: 0 (any depth).
   */
  minDepth?: number;
  /**
   * Maximum depth for `contains` search.
   * Prevents unbounded recursion on massive ASTs. Default: Infinity.
   */
  maxDepth?: number;
}

/** Full HQL signature — a named behavioral pattern */
export interface HQLSignature {
  /** Unique signature ID (e.g. "crypto.xor_loop", "injection.process_hollow") */
  id: string;
  /** Human-readable name */
  name: string;
  /** What this signature detects */
  description: string;
  /** Severity: info, low, medium, high, critical */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** MITRE ATT&CK TTP mapping (optional) */
  mitre?: string[];
  /**
   * Queries that compose this signature.
   * ALL queries must match for the signature to fire (AND semantics).
   */
  queries: HQLQuery[];
}

/** Result of a signature evaluation against an AST */
export interface HQLMatchResult {
  /** Signature that fired */
  signatureId: string;
  /** Nodes that matched each query in the signature */
  matches: CNode[];
  /** Confidence score 0.0 - 1.0 based on match depth/quality */
  confidence: number;
}
