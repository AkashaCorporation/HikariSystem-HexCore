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
  HQLCondition,
  HQLEvidenceLevel,
  HQLSemanticCondition,
  HQLSemanticFact,
  HQLSemanticQuery,
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
    case 'CAssignStmt':
      return node.value ? [node.target, node.value] : [node.target];
    case 'CExprStmt':
      return [node.expression];
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
    case 'CUnknownExpr':
    case 'CUnknownStmt':
    case 'CAsmStmt':
    case 'CCommentStmt':
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
    case 'CCastExpr':
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
  if (typeof expected === 'boolean') {
    return actual === expected;
  }

  if (typeof expected === 'number') {
    if (actual === expected) return true;
    if (Number.isSafeInteger(expected) && typeof actual === 'string') {
      const exact = parseIntegerString(actual);
      return exact !== undefined && exact === BigInt(expected);
    }
    return false;
  }

  // Regex match: "re:pattern"
  if (expected.startsWith('re:')) {
    const pattern = expected.slice(3);
    return typeof actual === 'string' && new RegExp(pattern).test(actual);
  }

  // Glob match: contains * and is not the literal multiplication operator.
  if (expected.length > 1 && expected.includes('*')) {
    const regex = new RegExp(
      '^' + expected.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'
    );
    return typeof actual === 'string' && regex.test(actual);
  }

  // Exact string match
  const expectedInteger = parseIntegerString(expected);
  if (expectedInteger !== undefined) {
    if (typeof actual === 'number' && Number.isSafeInteger(actual)) return expectedInteger === BigInt(actual);
    if (typeof actual === 'string') {
      const actualInteger = parseIntegerString(actual);
      if (actualInteger !== undefined) return expectedInteger === actualInteger;
    }
  }
  return actual === expected;
}

function parseIntegerString(value: string): bigint | undefined {
  if (/^\d+$/.test(value) || /^0x[0-9a-f]+$/i.test(value)) return BigInt(value);
  if (/^-\d+$/.test(value)) return BigInt(value);
  if (/^-0x[0-9a-f]+$/i.test(value)) return -BigInt(value.slice(1));
  return undefined;
}

interface ConditionEvaluation {
  matched: boolean;
  matches: CNode[];
  satisfiedLeaves: number;
  totalLeaves: number;
}

interface SemanticConditionEvaluation {
  matched: boolean;
  matches: HQLSemanticFact[];
  satisfiedLeaves: number;
  totalLeaves: number;
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
  evaluate(root: CNode, signature: HQLSignature, semanticFacts: readonly HQLSemanticFact[] = []): HQLMatchResult | null {
    const condition: HQLCondition | undefined = signature.condition ?? (signature.queries
      ? { all: signature.queries.map(query => ({ query })) }
      : undefined);
    const evaluated = condition
      ? this.evaluateCondition(root, condition)
      : { matched: true, matches: [], satisfiedLeaves: 0, totalLeaves: 0 };
    if (!evaluated.matched) return null;
    const semantic = signature.semanticCondition
      ? this.evaluateSemanticCondition(semanticFacts, signature.semanticCondition)
      : { matched: true, matches: [], satisfiedLeaves: 0, totalLeaves: 0 };
    if (!semantic.matched) return null;
    const allMatches = [...new Set(evaluated.matches)];
    const adapterCoverage = root.kind === 'CFunctionDecl' ? root.adapterCoverage?.coverage : undefined;
    const absenceDependsOnCompleteAst = condition ? this.conditionReliesOnAbsence(condition) : false;
    const adapterLossAffected = allMatches.some(node => this.containsLossyNode(node)) ||
      (absenceDependsOnCompleteAst && adapterCoverage !== undefined && adapterCoverage < 1);
    const requestedLevel = signature.evidenceLevel ?? 'signal';
    let evidenceLevel = adapterLossAffected
      ? this.downgradeEvidenceLevel(requestedLevel)
      : requestedLevel;
    if (semantic.matches.length > 0) {
      const semanticCeiling = semantic.matches.reduce<HQLEvidenceLevel>((ceiling, fact) =>
        this.lowerEvidenceLevel(ceiling, fact.proofStatus), 'proven');
      evidenceLevel = this.lowerEvidenceLevel(evidenceLevel, semanticCeiling);
    }

    return {
      signatureId: signature.id,
      matches: allMatches,
      ...(semantic.matches.length > 0 ? { semanticMatches: [...new Set(semantic.matches)] } : {}),
      structuralCompleteness: evaluated.totalLeaves + semantic.totalLeaves > 0
        ? (evaluated.satisfiedLeaves + semantic.satisfiedLeaves) / (evaluated.totalLeaves + semantic.totalLeaves)
        : 0,
      evidenceLevel,
      ...(signature.calibration && !adapterLossAffected ? { confidence: signature.calibration.confidence } : {}),
      ...(adapterCoverage !== undefined ? { adapterCoverage } : {}),
      ...(adapterLossAffected ? { adapterLossAffected: true } : {}),
    };
  }

  evaluateSemanticCondition(facts: readonly HQLSemanticFact[], condition: HQLSemanticCondition): SemanticConditionEvaluation {
    if ('fact' in condition) {
      const matches = facts.filter(fact => this.matchSemanticFact(fact, condition.fact));
      return { matched: matches.length > 0, matches, satisfiedLeaves: matches.length > 0 ? 1 : 0, totalLeaves: 1 };
    }
    if ('all' in condition) {
      const parts = condition.all.map(child => this.evaluateSemanticCondition(facts, child));
      return { matched: parts.length > 0 && parts.every(part => part.matched), matches: parts.flatMap(part => part.matches), satisfiedLeaves: parts.reduce((sum, part) => sum + part.satisfiedLeaves, 0), totalLeaves: parts.reduce((sum, part) => sum + part.totalLeaves, 0) };
    }
    if ('any' in condition) {
      const parts = condition.any.map(child => this.evaluateSemanticCondition(facts, child));
      const matched = parts.filter(part => part.matched);
      return { matched: matched.length > 0, matches: matched.flatMap(part => part.matches), satisfiedLeaves: matched.length > 0 ? 1 : 0, totalLeaves: 1 };
    }
    if ('not' in condition) {
      const inner = this.evaluateSemanticCondition(facts, condition.not);
      return { matched: !inner.matched, matches: [], satisfiedLeaves: inner.matched ? 0 : 1, totalLeaves: 1 };
    }
    const matches = facts.filter(fact => this.matchSemanticFact(fact, condition.count.fact));
    const { exactly, min, max } = condition.count;
    const matched = exactly !== undefined ? matches.length === exactly : matches.length >= (min ?? 1) && matches.length <= (max ?? Infinity);
    return { matched, matches: matched ? matches : [], satisfiedLeaves: matched ? 1 : 0, totalLeaves: 1 };
  }

  evaluateCondition(root: CNode, condition: HQLCondition): ConditionEvaluation {
    if ('query' in condition) {
      const matches = this.scan(root, condition.query);
      return { matched: matches.length > 0, matches, satisfiedLeaves: matches.length > 0 ? 1 : 0, totalLeaves: 1 };
    }
    if ('all' in condition) {
      const parts = condition.all.map(child => this.evaluateCondition(root, child));
      return {
        matched: parts.length > 0 && parts.every(part => part.matched),
        matches: parts.flatMap(part => part.matches),
        satisfiedLeaves: parts.reduce((sum, part) => sum + part.satisfiedLeaves, 0),
        totalLeaves: parts.reduce((sum, part) => sum + part.totalLeaves, 0),
      };
    }
    if ('any' in condition) {
      const parts = condition.any.map(child => this.evaluateCondition(root, child));
      const matchedParts = parts.filter(part => part.matched);
      return {
        matched: matchedParts.length > 0,
        matches: matchedParts.flatMap(part => part.matches),
        satisfiedLeaves: matchedParts.length > 0 ? 1 : 0,
        totalLeaves: 1,
      };
    }
    if ('not' in condition) {
      const inner = this.evaluateCondition(root, condition.not);
      return { matched: !inner.matched, matches: [], satisfiedLeaves: inner.matched ? 0 : 1, totalLeaves: 1 };
    }
    const matches = this.scan(root, condition.count.query);
    const { exactly, min, max } = condition.count;
    const matched = exactly !== undefined
      ? matches.length === exactly
      : matches.length >= (min ?? 1) && matches.length <= (max ?? Infinity);
    return { matched, matches: matched ? matches : [], satisfiedLeaves: matched ? 1 : 0, totalLeaves: 1 };
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

  private matchSemanticFact(fact: HQLSemanticFact, query: HQLSemanticQuery): boolean {
    if (fact.kind !== query.fact) return false;
    return (query.attributes ?? []).every(attribute => matchValue(fact.attributes[attribute.field], attribute.value));
  }

  private lowerEvidenceLevel(left: HQLEvidenceLevel, right: HQLEvidenceLevel): HQLEvidenceLevel {
    const rank: Record<HQLEvidenceLevel, number> = { signal: 0, candidate: 1, proven: 2 };
    return rank[left] <= rank[right] ? left : right;
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

  /** Lossy adapter coverage can never retain a proven evidence claim. */
  private downgradeEvidenceLevel(level: HQLEvidenceLevel): HQLEvidenceLevel {
    return level === 'proven' ? 'candidate' : 'signal';
  }

  private containsLossyNode(node: CNode): boolean {
    if (node.kind === 'CUnknownExpr' || node.kind === 'CUnknownStmt' || node.kind === 'CAsmStmt') {
      return true;
    }
    return getChildren(node).some(child => this.containsLossyNode(child));
  }

  private conditionReliesOnAbsence(condition: HQLCondition): boolean {
    if ('not' in condition) return true;
    if ('count' in condition) return condition.count.exactly !== undefined || condition.count.max !== undefined;
    if ('all' in condition) return condition.all.some(child => this.conditionReliesOnAbsence(child));
    if ('any' in condition) return condition.any.some(child => this.conditionReliesOnAbsence(child));
    return false;
  }
}
