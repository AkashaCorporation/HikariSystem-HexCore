import { C_NODE_KINDS, type CNodeKind } from '../types/ast.js';
import type { HQLCondition, HQLQuery, HQLSemanticCondition, HQLSignature } from '../types/hql.js';

const NODE_KINDS = new Set<string>(C_NODE_KINDS);
const SEVERITIES = new Set(['info', 'low', 'medium', 'high', 'critical']);
const EVIDENCE_LEVELS = new Set(['signal', 'candidate', 'proven']);
const BINARY_OPERATORS = new Set([
  '+', '-', '*', '/', '%', '^', '&', '|', '<<', '>>', '==', '!=', '<', '>', '<=', '>=',
  '&&', '||', '=', '+=', '-=', '*=', '/=', '%=', '^=', '&=', '|=', '<<=', '>>=', ',',
]);
const UNARY_OPERATORS = new Set(['!', '~', '-', '+', '++', '--', '&', '*']);
const FIXED_OPERAND_COUNTS: Partial<Record<CNodeKind, number>> = {
  CBinaryExpr: 2,
  CUnaryExpr: 1,
  CCastExpr: 1,
  CTernaryExpr: 3,
  CSubscriptExpr: 2,
};
const OPERAND_TARGETS = new Set<CNodeKind>([...Object.keys(FIXED_OPERAND_COUNTS) as CNodeKind[], 'CCallExpr']);
const QUERY_KEYS = new Set(['target', 'attributes', 'contains', 'operands', 'minDepth', 'maxDepth']);
const BASE_NODE_FIELDS = new Set(['kind', 'nodeId', 'sourceAddress', 'resultType']);
const SIGNATURE_KEYS = new Set([
  'id', 'name', 'description', 'severity', 'mitre', 'queries', 'condition', 'evidenceLevel', 'calibration',
  'version', 'namespace', 'status', 'author', 'license', 'provenance', 'compatibility', 'fixtures', 'limitations', 'supersedes', 'semanticCondition',
]);
const SEMANTIC_FACT_FIELDS: Record<string, ReadonlySet<string>> = {
  'function-prototype': new Set(['functionIdentity', 'callingConventionId', 'returnTypeId', 'variadic', 'noreturn', 'method', 'provider', 'evidenceStrength', 'generation']),
  'type-binding': new Set(['bindingId', 'scope', 'valueIdentity', 'typeId', 'functionIdentity', 'provider', 'evidenceStrength', 'generation']),
  xref: new Set(['relation', 'family', 'sourceAddress', 'targetKind', 'targetIdentity', 'targetAddress', 'accessWidthBits', 'provider', 'evidenceStrength', 'generation']),
  'indirect-target': new Set(['relation', 'sourceAddress', 'targetIdentity', 'status', 'resolutionSource', 'candidateSetId', 'provider', 'generation']),
  'summary-call': new Set(['callsiteIdentity', 'calleeIdentity', 'argumentCount', 'indirectCandidateCount', 'generation']),
  'summary-global': new Set(['globalIdentity', 'access', 'generation']),
  'summary-ownership': new Set(['ownershipKind', 'valueIdentity', 'objectIdentity', 'generation']),
  'summary-field': new Set(['fieldIdentity', 'baseIdentity', 'offsetBytes', 'access', 'typeId', 'generation']),
  'summary-barrier': new Set(['barrierIdentity', 'reason', 'lossy', 'generation']),
  'semantic-conflict': new Set(['factKind', 'factKey', 'reason', 'winnerHash', 'loserHash']),
};

const NODE_FIELDS: Record<CNodeKind, ReadonlySet<string>> = {
  CIntLitExpr: new Set(['kind', 'value', 'exactValue', 'width', 'signed']),
  CFloatLitExpr: new Set(['kind', 'value', 'precision']),
  CStringLitExpr: new Set(['kind', 'value', 'encoding']),
  CAddrLitExpr: new Set(['kind', 'address', 'symbol']),
  CVarRefExpr: new Set(['kind', 'name', 'type', 'identityId', 'storage', 'stackOffset', 'parameterIndex']),
  CBinaryExpr: new Set(['kind', 'operator']),
  CUnaryExpr: new Set(['kind', 'operator', 'prefix']),
  CCastExpr: new Set(['kind', 'targetType']),
  CCallExpr: new Set(['kind', 'callee', 'callTarget']),
  CTernaryExpr: new Set(['kind']),
  CSubscriptExpr: new Set(['kind']),
  CFieldAccessExpr: new Set(['kind', 'field', 'arrow', 'fieldOffset']),
  CArrayInitExpr: new Set(['kind']),
  CCompoundLitExpr: new Set(['kind', 'type']),
  CBlockStmt: new Set(['kind']),
  CAssignStmt: new Set(['kind', 'compoundOperator', 'nodeId', 'sourceAddress']),
  CExprStmt: new Set(['kind', 'nodeId', 'sourceAddress']),
  CIfStmt: new Set(['kind']),
  CForStmt: new Set(['kind']),
  CWhileStmt: new Set(['kind']),
  CDoWhileStmt: new Set(['kind']),
  CReturnStmt: new Set(['kind']),
  CSwitchStmt: new Set(['kind']),
  CCaseStmt: new Set(['kind']),
  CBreakStmt: new Set(['kind']),
  CContinueStmt: new Set(['kind']),
  CGotoStmt: new Set(['kind', 'label']),
  CLabelStmt: new Set(['kind', 'label']),
  CFunctionDecl: new Set(['kind', 'name', 'address', 'returnType', 'callingConvention', 'isVariadic']),
  CVarDecl: new Set(['kind', 'name', 'type', 'identityId', 'storage', 'stackOffset', 'parameterIndex']),
  CStructDecl: new Set(['kind', 'name']),
  CTypedefDecl: new Set(['kind', 'name', 'underlyingType']),
  CEnumDecl: new Set(['kind', 'name']),
  CUnknownExpr: new Set(['kind', 'sourceKind', 'reason', 'lossy']),
  CUnknownStmt: new Set(['kind', 'sourceKind', 'reason', 'lossy']),
  CAsmStmt: new Set(['kind', 'text']),
  CCommentStmt: new Set(['kind', 'text']),
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function rejectUnknownKeys(value: Record<string, unknown>, allowed: ReadonlySet<string>, path: string, errors: string[]): void {
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) errors.push(`${path}.${key}: unknown field`);
  }
}

function validateQuery(value: unknown, path: string, errors: string[]): value is HQLQuery {
  if (!isRecord(value)) { errors.push(`${path}: expected query object`); return false; }
  rejectUnknownKeys(value, QUERY_KEYS, path, errors);
  const target = value.target;
  if (typeof target !== 'string' || !NODE_KINDS.has(target)) {
    errors.push(`${path}.target: expected a valid CNode kind`);
  }
  if (value.attributes !== undefined) {
    if (!Array.isArray(value.attributes)) errors.push(`${path}.attributes: expected array`);
    else {
      const fields = typeof target === 'string' && NODE_KINDS.has(target) ? NODE_FIELDS[target as CNodeKind] : undefined;
      value.attributes.forEach((raw, index) => {
        const attrPath = `${path}.attributes[${index}]`;
        if (!isRecord(raw)) { errors.push(`${attrPath}: expected object`); return; }
        rejectUnknownKeys(raw, new Set(['field', 'value']), attrPath, errors);
        if (typeof raw.field !== 'string' || (!fields?.has(raw.field) && !BASE_NODE_FIELDS.has(raw.field))) errors.push(`${attrPath}.field: invalid for ${String(target)}`);
        if (!['string', 'number', 'boolean'].includes(typeof raw.value)) errors.push(`${attrPath}.value: expected scalar`);
        if (target === 'CIntLitExpr' && raw.field === 'value' && typeof raw.value === 'number' && !Number.isSafeInteger(raw.value)) {
          errors.push(`${attrPath}.value: integer literals outside the safe range require a canonical decimal or hexadecimal string`);
        }
        if (typeof raw.value === 'string' && raw.value.startsWith('re:')) {
          try { new RegExp(raw.value.slice(3)); } catch { errors.push(`${attrPath}.value: invalid regex`); }
        }
        if (raw.field === 'operator' && typeof raw.value === 'string' && !raw.value.startsWith('re:') && !raw.value.includes('*')) {
          const allowed = target === 'CBinaryExpr' ? BINARY_OPERATORS : target === 'CUnaryExpr' ? UNARY_OPERATORS : undefined;
          if (allowed && !allowed.has(raw.value)) errors.push(`${attrPath}.value: invalid ${String(target)} operator`);
        }
      });
    }
  }
  if (value.contains !== undefined) {
    if (!Array.isArray(value.contains) || value.contains.length === 0) errors.push(`${path}.contains: expected non-empty array`);
    else value.contains.forEach((query, index) => validateQuery(query, `${path}.contains[${index}]`, errors));
  }
  if (value.operands !== undefined) {
    if (!Array.isArray(value.operands) || value.operands.length === 0) errors.push(`${path}.operands: expected non-empty array`);
    else value.operands.forEach((raw, index) => {
      const operandPath = `${path}.operands[${index}]`;
      if (!isRecord(raw)) { errors.push(`${operandPath}: expected object`); return; }
      rejectUnknownKeys(raw, new Set(['position', 'query']), operandPath, errors);
      if (!Number.isInteger(raw.position) || Number(raw.position) < 0) errors.push(`${operandPath}.position: expected non-negative integer`);
      if (typeof target === 'string' && NODE_KINDS.has(target) && !OPERAND_TARGETS.has(target as CNodeKind)) {
        errors.push(`${path}.operands: ${target} has no positional operands`);
      }
      const fixedCount = typeof target === 'string' ? FIXED_OPERAND_COUNTS[target as CNodeKind] : undefined;
      if (fixedCount !== undefined && Number.isInteger(raw.position) && Number(raw.position) >= fixedCount) {
        errors.push(`${operandPath}.position: out of range for ${target}`);
      }
      validateQuery(raw.query, `${operandPath}.query`, errors);
    });
  }
  for (const key of ['minDepth', 'maxDepth'] as const) {
    if (value[key] !== undefined && (!Number.isInteger(value[key]) || Number(value[key]) < 0)) {
      errors.push(`${path}.${key}: expected non-negative integer`);
    }
  }
  if (typeof value.minDepth === 'number' && typeof value.maxDepth === 'number' && value.minDepth > value.maxDepth) {
    errors.push(`${path}: minDepth exceeds maxDepth`);
  }
  return errors.length === 0;
}

function validateCondition(value: unknown, path: string, errors: string[]): value is HQLCondition {
  if (!isRecord(value)) { errors.push(`${path}: expected condition object`); return false; }
  const combinators = ['query', 'all', 'any', 'not', 'count'].filter(key => key in value);
  if (combinators.length !== 1 || Object.keys(value).length !== 1) {
    errors.push(`${path}: expected exactly one of query/all/any/not/count`);
    return false;
  }
  const kind = combinators[0];
  if (kind === 'query') return validateQuery(value.query, `${path}.query`, errors);
  if (kind === 'all' || kind === 'any') {
    const children = value[kind];
    if (!Array.isArray(children) || children.length === 0) { errors.push(`${path}.${kind}: expected non-empty array`); return false; }
    children.forEach((child, index) => validateCondition(child, `${path}.${kind}[${index}]`, errors));
    return errors.length === 0;
  }
  if (kind === 'not') return validateCondition(value.not, `${path}.not`, errors);
  const count = value.count;
  if (!isRecord(count)) { errors.push(`${path}.count: expected object`); return false; }
  rejectUnknownKeys(count, new Set(['query', 'min', 'max', 'exactly']), `${path}.count`, errors);
  validateQuery(count.query, `${path}.count.query`, errors);
  const bounds = ['min', 'max', 'exactly'] as const;
  for (const bound of bounds) {
    if (count[bound] !== undefined && (!Number.isInteger(count[bound]) || Number(count[bound]) < 0)) {
      errors.push(`${path}.count.${bound}: expected non-negative integer`);
    }
  }
  if (count.exactly !== undefined && (count.min !== undefined || count.max !== undefined)) {
    errors.push(`${path}.count: exactly cannot be combined with min/max`);
  }
  if (typeof count.min === 'number' && typeof count.max === 'number' && count.min > count.max) {
    errors.push(`${path}.count: min exceeds max`);
  }
  return errors.length === 0;
}

function validateSemanticQuery(value: unknown, path: string, errors: string[]): boolean {
  if (!isRecord(value)) { errors.push(`${path}: expected semantic query object`); return false; }
  rejectUnknownKeys(value, new Set(['fact', 'attributes']), path, errors);
  if (typeof value.fact !== 'string' || !SEMANTIC_FACT_FIELDS[value.fact]) errors.push(`${path}.fact: invalid semantic fact kind`);
  if (value.attributes !== undefined) {
    if (!Array.isArray(value.attributes)) errors.push(`${path}.attributes: expected array`);
    else value.attributes.forEach((raw, index) => {
      const attrPath = `${path}.attributes[${index}]`;
      if (!isRecord(raw)) { errors.push(`${attrPath}: expected object`); return; }
      rejectUnknownKeys(raw, new Set(['field', 'value']), attrPath, errors);
      if (typeof raw.field !== 'string' || !SEMANTIC_FACT_FIELDS[String(value.fact)]?.has(raw.field)) errors.push(`${attrPath}.field: invalid for ${String(value.fact)}`);
      if (!['string', 'number', 'boolean'].includes(typeof raw.value)) errors.push(`${attrPath}.value: expected scalar`);
      if (typeof raw.value === 'string' && raw.value.startsWith('re:')) {
        try { new RegExp(raw.value.slice(3)); } catch { errors.push(`${attrPath}.value: invalid regex`); }
      }
    });
  }
  return errors.length === 0;
}

function validateSemanticCondition(value: unknown, path: string, errors: string[]): value is HQLSemanticCondition {
  if (!isRecord(value)) { errors.push(`${path}: expected semantic condition object`); return false; }
  const combinators = ['fact', 'all', 'any', 'not', 'count'].filter(key => key in value);
  if (combinators.length !== 1 || Object.keys(value).length !== 1) { errors.push(`${path}: expected exactly one of fact/all/any/not/count`); return false; }
  const kind = combinators[0];
  if (kind === 'fact') return validateSemanticQuery(value.fact, `${path}.fact`, errors);
  if (kind === 'all' || kind === 'any') {
    const children = value[kind];
    if (!Array.isArray(children) || children.length === 0) { errors.push(`${path}.${kind}: expected non-empty array`); return false; }
    children.forEach((child, index) => validateSemanticCondition(child, `${path}.${kind}[${index}]`, errors));
    return errors.length === 0;
  }
  if (kind === 'not') return validateSemanticCondition(value.not, `${path}.not`, errors);
  const count = value.count;
  if (!isRecord(count)) { errors.push(`${path}.count: expected object`); return false; }
  rejectUnknownKeys(count, new Set(['fact', 'min', 'max', 'exactly']), `${path}.count`, errors);
  validateSemanticQuery(count.fact, `${path}.count.fact`, errors);
  for (const bound of ['min', 'max', 'exactly'] as const) if (count[bound] !== undefined && (!Number.isInteger(count[bound]) || Number(count[bound]) < 0)) errors.push(`${path}.count.${bound}: expected non-negative integer`);
  if (count.exactly !== undefined && (count.min !== undefined || count.max !== undefined)) errors.push(`${path}.count: exactly cannot be combined with min/max`);
  return errors.length === 0;
}

export function validateSignature(value: unknown): string[] {
  const errors: string[] = [];
  if (!isRecord(value)) return ['$: expected signature object'];
  rejectUnknownKeys(value, SIGNATURE_KEYS, '$', errors);
  if (typeof value.id !== 'string' || value.id.length === 0) errors.push('$.id: expected non-empty string');
  if (value.version !== undefined && (typeof value.version !== 'string' || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(value.version))) errors.push('$.version: expected semantic version');
  if (value.namespace !== undefined && (typeof value.namespace !== 'string' || !/^[a-z0-9][a-z0-9-]*$/.test(value.namespace))) errors.push('$.namespace: invalid');
  if (typeof value.id === 'string' && typeof value.namespace === 'string' && value.id.split('.')[0] !== value.namespace) errors.push('$.namespace: must match rule ID prefix');
  if (value.status !== undefined && !['nursery', 'released', 'retired'].includes(String(value.status))) errors.push('$.status: invalid');
	if (value.status !== undefined) {
		for (const key of ['version', 'namespace', 'author', 'license', 'provenance', 'compatibility', 'fixtures', 'limitations']) {
			if (value[key] === undefined) errors.push(`$.${key}: required for Atlas-managed rules`);
		}
	}
  if (value.author !== undefined && (typeof value.author !== 'string' || value.author.length === 0)) errors.push('$.author: expected non-empty string');
  if (value.license !== undefined && (typeof value.license !== 'string' || value.license.length === 0)) errors.push('$.license: expected non-empty string');
  if (value.provenance !== undefined) {
    if (!isRecord(value.provenance)) errors.push('$.provenance: expected object');
    else {
      rejectUnknownKeys(value.provenance, new Set(['kind', 'source', 'url', 'commit', 'path', 'modified']), '$.provenance', errors);
      if (!['internal', 'derived', 'external'].includes(String(value.provenance.kind))) errors.push('$.provenance.kind: invalid');
      if (typeof value.provenance.source !== 'string' || value.provenance.source.length === 0) errors.push('$.provenance.source: required');
      for (const key of ['url', 'commit', 'path'] as const) if (value.provenance[key] !== undefined && typeof value.provenance[key] !== 'string') errors.push(`$.provenance.${key}: expected string`);
      if (value.provenance.modified !== undefined && typeof value.provenance.modified !== 'boolean') errors.push('$.provenance.modified: expected boolean');
    }
  }
  if (value.compatibility !== undefined) {
    if (!isRecord(value.compatibility)) errors.push('$.compatibility: expected object');
    else {
      rejectUnknownKeys(value.compatibility, new Set(['hql', 'helix', 'hastSchema']), '$.compatibility', errors);
      if (typeof value.compatibility.hql !== 'string' || value.compatibility.hql.length === 0) errors.push('$.compatibility.hql: required');
      if (value.compatibility.helix !== undefined && typeof value.compatibility.helix !== 'string') errors.push('$.compatibility.helix: expected string');
      if (!Number.isSafeInteger(value.compatibility.hastSchema) || Number(value.compatibility.hastSchema) <= 0) errors.push('$.compatibility.hastSchema: expected positive safe integer');
    }
  }
  if (value.fixtures !== undefined) {
    if (!isRecord(value.fixtures)) errors.push('$.fixtures: expected object');
    else {
      rejectUnknownKeys(value.fixtures, new Set(['manifest']), '$.fixtures', errors);
      if (typeof value.fixtures.manifest !== 'string' || value.fixtures.manifest.length === 0 || pathIsUnsafe(value.fixtures.manifest)) errors.push('$.fixtures.manifest: expected safe relative path');
    }
  }
  for (const key of ['limitations', 'supersedes'] as const) {
    if (value[key] !== undefined && (!Array.isArray(value[key]) || value[key].some(item => typeof item !== 'string'))) errors.push(`$.${key}: expected string array`);
  }
  if (typeof value.name !== 'string' || value.name.length === 0) errors.push('$.name: expected non-empty string');
  if (typeof value.description !== 'string' || value.description.length === 0) errors.push('$.description: expected non-empty string');
  if (typeof value.severity !== 'string' || !SEVERITIES.has(value.severity)) errors.push('$.severity: invalid');
  if (value.evidenceLevel !== undefined && (typeof value.evidenceLevel !== 'string' || !EVIDENCE_LEVELS.has(value.evidenceLevel))) {
    errors.push('$.evidenceLevel: invalid');
  }
  if (value.mitre !== undefined && (!Array.isArray(value.mitre) || value.mitre.some(item => typeof item !== 'string'))) {
    errors.push('$.mitre: expected string array');
  }
  const hasQueries = value.queries !== undefined;
  const hasCondition = value.condition !== undefined;
  const hasSemanticCondition = value.semanticCondition !== undefined;
  if (hasQueries && hasCondition) errors.push('$: queries and condition are mutually exclusive');
  if (!hasQueries && !hasCondition && !hasSemanticCondition) errors.push('$: at least one AST or semantic condition is required');
  if (hasQueries) {
    if (!Array.isArray(value.queries) || value.queries.length === 0) errors.push('$.queries: expected non-empty array');
    else value.queries.forEach((query, index) => validateQuery(query, `$.queries[${index}]`, errors));
  }
  if (hasCondition) validateCondition(value.condition, '$.condition', errors);
  if (hasSemanticCondition) validateSemanticCondition(value.semanticCondition, '$.semanticCondition', errors);
  if (value.calibration !== undefined) {
    if (!isRecord(value.calibration)) errors.push('$.calibration: expected object');
    else {
      rejectUnknownKeys(value.calibration, new Set(['confidence', 'corpus', 'corpusSha256']), '$.calibration', errors);
      if (typeof value.calibration.confidence !== 'number' || value.calibration.confidence < 0 || value.calibration.confidence > 1) errors.push('$.calibration.confidence: expected 0..1');
      if (typeof value.calibration.corpus !== 'string' || value.calibration.corpus.length === 0) errors.push('$.calibration.corpus: required');
      if (typeof value.calibration.corpusSha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(value.calibration.corpusSha256)) errors.push('$.calibration.corpusSha256: expected SHA-256');
    }
  }
  return errors;
}

function pathIsUnsafe(value: string): boolean {
  return value.startsWith('/') || value.startsWith('\\') || /^[A-Za-z]:/.test(value) || value.split(/[\\/]/).includes('..');
}

export function assertValidSignature(value: unknown, source = '<signature>'): asserts value is HQLSignature {
  const errors = validateSignature(value);
  if (errors.length > 0) throw new Error(`${source}: ${errors.join('; ')}`);
}
