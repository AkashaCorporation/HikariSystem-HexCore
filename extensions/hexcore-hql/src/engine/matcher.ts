// ─── HQL Matcher Engine ───
// Recursive tree-walking matcher. Pure TS, zero allocations in hot paths.
// This is where arcaico byte-matching tools go to die.

import type { CNode } from '../types/ast.js';
import type {
  HQLQuery,
  HQLAttributeCheck,
  HQLOperandCheck,
  HQLSignature,
  HQLMatchResult,
} from '../types/hql.js';

/**
 * Extracts direct children from any CNode.
 * No reflection, no Object.values noise — explicit structural extraction
 * for maximum V8 inline cache performance.
 */
function getChildren(node: CNode): CNode[] {
  switch (node.kind) {
    // ── Expressions with children ──
    case 'CBinaryExpr':
      return [node.left, node.right];
    case 'CUnaryExpr':
    case 'CCastExpr':
      return [node.operand];
    case 'CCallExpr':
      return [...node.arguments];
    case 'CTernaryExpr':
      return [node.condition, node.consequent, node.alternate];
    case 'CSubscriptExpr':
      return [node.base, node.index];
    case 'CFieldAccessExpr':
      return [node.object];
    case 'CArrayInitExpr':
      return [...node.elements];
    case 'CCompoundLitExpr':
      return [...node.fields];

    // ── Statements ──
    case 'CBlockStmt':
      return [...node.body];
    case 'CIfStmt':
      return node.else
        ? [node.condition, node.then, node.else]
        : [node.condition, node.then];
    case 'CForStmt': {
      const children: CNode[] = [];
      if (node.init) children.push(node.init);
      if (node.condition) children.push(node.condition);
      if (node.update) children.push(node.update);
      children.push(node.body);
      return children;
    }
    case 'CWhileStmt':
    case 'CDoWhileStmt':
      return [node.condition, node.body];
    case 'CReturnStmt':
      return node.value ? [node.value] : [];
    case 'CSwitchStmt':
      return [node.discriminant, ...node.cases];
    case 'CCaseStmt':
      return node.value ? [node.value, ...node.body] : [...node.body];
    case 'CLabelStmt':
      return [node.body];

    // ── Declarations ──
    case 'CFunctionDecl': {
      const children: CNode[] = [...node.params];
      if (node.body) children.push(node.body);
      return children;
    }
    case 'CVarDecl':
      return node.init ? [node.init] : [];
    case 'CStructDecl':
      return [...node.fields];

    // ── Leaf nodes ──
    case 'CIntLitExpr':
    case 'CFloatLitExpr':
    case 'CStringLitExpr':
    case 'CAddrLitExpr':
    case 'CVarRefExpr':
    case 'CBreakStmt':
    case 'CContinueStmt':
    case 'CGotoStmt':
    case 'CTypedefDecl':
    case 'CEnumDecl':
      return [];
  }
}

/**
 * Gets ordered operands for expression nodes.
 * Returns children in positional order for operand-level matching.
 */
function getOperands(node: CNode): CNode[] {
  switch (node.kind) {
    case 'CBinaryExpr':
      return [node.left, node.right];
    case 'CUnaryExpr':
      return [node.operand];
    case 'CCallExpr':
      return node.arguments;
    case 'CTernaryExpr':
      return [node.condition, node.consequent, node.alternate];
    case 'CSubscriptExpr':
      return [node.base, node.index];
    default:
      return [];
  }
}

/**
 * Checks if a value matches an attribute predicate.
 * Supports: exact match, glob (*), and regex (re: prefix).
 */
function matchValue(actual: unknown, expected: string | number | boolean): boolean {
  if (typeof expected === 'boolean' || typeof expected === 'number') {
    return actual === expected;
  }

  // Regex match: "re:pattern"
  if (expected.startsWith('re:')) {
    const pattern = expected.slice(3);
    return typeof actual === 'string' && new RegExp(pattern).test(actual);
  }

  // Glob match: contains *
  if (expected.includes('*')) {
    const regex = new RegExp(
      '^' + expected.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'
    );
    return typeof actual === 'string' && regex.test(actual);
  }

  // Exact string match
  return actual === expected;
}

/**
 * HQLMatcher — Semantic Pattern Matching Engine.
 *
 * Walks the C-AST via structural recursion and evaluates HQL queries
 * against node properties. No bytes, no opcodes — pure semantic analysis.
 */
export class HQLMatcher {
  /**
   * Check if a single node matches a query (non-recursive into children
   * unless `contains` or `operands` require it).
   */
  match(node: CNode, query: HQLQuery): boolean {
    // 1. Kind filter — fast reject
    if (query.target && node.kind !== query.target) {
      return false;
    }

    // 2. Attribute checks — ALL must pass
    if (query.attributes && !this.matchAttributes(node, query.attributes)) {
      return false;
    }

    // 3. Operand checks — positional sub-query matching
    if (query.operands && !this.matchOperands(node, query.operands)) {
      return false;
    }

    // 4. Containment checks — DFS into subtree
    if (query.contains && !this.matchContains(node, query.contains, query.minDepth, query.maxDepth)) {
      return false;
    }

    return true;
  }

  /**
   * Scan entire AST subtree, collecting all nodes that satisfy the query.
   * DFS traversal — returns results in pre-order.
   */
  scan(root: CNode, query: HQLQuery): CNode[] {
    const results: CNode[] = [];
    this.dfs(root, query, results);
    return results;
  }

  /**
   * Evaluate a full HQL signature against an AST.
   * ALL queries in the signature must produce at least one match.
   */
  evaluate(root: CNode, signature: HQLSignature): HQLMatchResult | null {
    const allMatches: CNode[] = [];

    for (const query of signature.queries) {
      const matches = this.scan(root, query);
      if (matches.length === 0) {
        return null; // AND semantics: one miss = no fire
      }
      allMatches.push(...matches);
    }

    return {
      signatureId: signature.id,
      matches: allMatches,
      confidence: this.computeConfidence(allMatches, signature),
    };
  }

  // ─── Private ───

  /** DFS collector for scan() */
  private dfs(node: CNode, query: HQLQuery, results: CNode[]): void {
    if (this.match(node, query)) {
      results.push(node);
    }
    const children = getChildren(node);
    for (let i = 0; i < children.length; i++) {
      this.dfs(children[i], query, results);
    }
  }

  /** Verify all attribute predicates against node properties */
  private matchAttributes(node: CNode, attrs: HQLAttributeCheck[]): boolean {
    for (let i = 0; i < attrs.length; i++) {
      const attr = attrs[i];
      const actual = (node as unknown as Record<string, unknown>)[attr.field];
      if (actual === undefined || !matchValue(actual, attr.value)) {
        return false;
      }
    }
    return true;
  }

  /** Verify positional operands satisfy their sub-queries */
  private matchOperands(node: CNode, checks: HQLOperandCheck[]): boolean {
    const operands = getOperands(node);
    for (let i = 0; i < checks.length; i++) {
      const check = checks[i];
      if (check.position >= operands.length) {
        return false;
      }
      if (!this.match(operands[check.position], check.query)) {
        return false;
      }
    }
    return true;
  }

  /**
   * DFS containment check — searches the node's subtree for matches
   * to each sub-query. Depth bounds are respected.
   */
  private matchContains(
    node: CNode,
    subQueries: HQLQuery[],
    minDepth?: number,
    maxDepth?: number
  ): boolean {
    const min = minDepth ?? 0;
    const max = maxDepth ?? Infinity;

    for (let i = 0; i < subQueries.length; i++) {
      if (!this.containsDFS(node, subQueries[i], 0, min, max)) {
        return false; // AND semantics
      }
    }
    return true;
  }

  /** Bounded DFS for containment matching */
  private containsDFS(
    node: CNode,
    query: HQLQuery,
    depth: number,
    minDepth: number,
    maxDepth: number
  ): boolean {
    if (depth > maxDepth) return false;

    if (depth >= minDepth && this.match(node, query)) {
      return true;
    }

    const children = getChildren(node);
    for (let i = 0; i < children.length; i++) {
      if (this.containsDFS(children[i], query, depth + 1, minDepth, maxDepth)) {
        return true;
      }
    }
    return false;
  }

  /**
   * Confidence heuristic — more unique matches = higher confidence.
   * Trivial for now, can be upgraded with weighted scoring per node type.
   */
  private computeConfidence(matches: CNode[], signature: HQLSignature): number {
    const uniqueKinds = new Set(matches.map(m => m.kind)).size;
    const queryCount = signature.queries.length;
    // Base: ratio of unique matched kinds to total queries, capped at 1.0
    return Math.min(1.0, (uniqueKinds / queryCount) * 0.8 + 0.2);
  }
}
