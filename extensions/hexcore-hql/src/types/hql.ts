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
  target: CNodeKind;
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

export type HQLEvidenceLevel = 'signal' | 'candidate' | 'proven';
export type HQLRuleStatus = 'nursery' | 'released' | 'retired';

export interface HQLRuleProvenance {
  kind: 'internal' | 'derived' | 'external';
  source: string;
  url?: string;
  commit?: string;
  path?: string;
  modified?: boolean;
}

export interface HQLCompatibility {
  hql: string;
  helix?: string;
  hastSchema: number;
}

export type HQLCondition =
  | { query: HQLQuery }
  | { all: HQLCondition[] }
  | { any: HQLCondition[] }
  | { not: HQLCondition }
  | { count: HQLCountCondition };

export interface HQLCountCondition {
  query: HQLQuery;
  min?: number;
  max?: number;
  exactly?: number;
}

export type HQLSemanticFactKind =
  | 'function-prototype'
  | 'type-binding'
  | 'xref'
  | 'indirect-target'
  | 'summary-call'
  | 'summary-global'
  | 'summary-ownership'
  | 'summary-field'
  | 'summary-barrier'
  | 'semantic-conflict';

export interface HQLSemanticFact {
  kind: HQLSemanticFactKind;
  attributes: Readonly<Record<string, string | number | boolean>>;
  proofStatus: 'signal' | 'candidate' | 'proven';
  provenance: readonly { producer: string; source: string; strength: string; generation: number }[];
}

export interface HQLSemanticQuery {
  fact: HQLSemanticFactKind;
  attributes?: HQLAttributeCheck[];
}

export type HQLSemanticCondition =
  | { fact: HQLSemanticQuery }
  | { all: HQLSemanticCondition[] }
  | { any: HQLSemanticCondition[] }
  | { not: HQLSemanticCondition }
  | { count: { fact: HQLSemanticQuery; min?: number; max?: number; exactly?: number } };

/** Full HQL signature — a named behavioral pattern */
export interface HQLSignature {
  /** Unique signature ID (e.g. "crypto.xor_loop", "injection.process_hollow") */
  id: string;
  /** Semantic version of this exact rule contract. */
  version?: string;
  namespace?: string;
  status?: HQLRuleStatus;
  author?: string;
  license?: string;
  provenance?: HQLRuleProvenance;
  compatibility?: HQLCompatibility;
  fixtures?: { manifest: string };
  limitations?: string[];
  supersedes?: string[];
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
  queries?: HQLQuery[];
  /** Recursive rule expression. Exactly one of condition/queries is required. */
  condition?: HQLCondition;
  /** Optional typed HXDB condition evaluated against the exact function generation. */
  semanticCondition?: HQLSemanticCondition;
  /** Evidentiary claim independent from presentation severity. Default: signal. */
  evidenceLevel?: HQLEvidenceLevel;
  /** Optional calibrated confidence; absent until backed by a versioned corpus. */
  calibration?: {
    confidence: number;
    corpus: string;
    corpusSha256: string;
  };
}

/** Result of a signature evaluation against an AST */
export interface HQLMatchResult {
  /** Signature that fired */
  signatureId: string;
  /** Nodes that matched each query in the signature */
  matches: CNode[];
  /** Typed HXDB facts that satisfied semanticCondition. */
  semanticMatches?: HQLSemanticFact[];
  /** Boolean rule completeness, not probabilistic confidence. */
  structuralCompleteness: number;
  /** Evidence claim after adapter-loss downgrades. */
  evidenceLevel: HQLEvidenceLevel;
  /** Present only for explicitly calibrated signatures. */
  confidence?: number;
  /** Adapter coverage of the scanned function. */
  adapterCoverage?: number;
  /** True when a matched subtree contains unsupported/lossy adapter nodes. */
  adapterLossAffected?: boolean;
}
