import { createHash } from 'node:crypto';

import type { CFunctionDecl, CNode } from '../types/ast';

export const FUNCTION_ATLAS_SCHEMA_VERSION = 1;
export const FUNCTION_ATLAS_NORMALIZER_VERSION = 'hast-structural-v1';

export interface FunctionAtlasCompilerProvenance {
  name: string;
  version: string;
  targetTriple: string;
  optimization: string;
  /** Exact compiler arguments in their effective order. */
  flags: string[];
}

export interface FunctionAtlasProvenance {
  corpusId: string;
  corpusVersion: string;
  sampleId: string;
  sourceSha256: string;
  groundTruthSha256: string;
  binarySha256: string;
  architecture: string;
  format: string;
  compiler: FunctionAtlasCompilerProvenance;
  producer: {
    name: string;
    version: string;
    hastSchema: number;
  };
}

export interface FunctionAtlasBuildInput {
  function: CFunctionDecl;
  provenance: FunctionAtlasProvenance;
  /** Exact source identity. These fields do not affect the normalized content ID. */
  sourceFunctionName?: string;
  sourceAddress?: string;
}

export interface FunctionAtlasFeature {
  feature: string;
  weight: number;
}

export interface FunctionAtlasTriviality {
  trivial: boolean;
  reasons: string[];
}

export interface FunctionAtlasRecord {
  schemaVersion: number;
  normalizerVersion: string;
  /** Address of normalized semantic content, stable across names, addresses, and exact build provenance. */
  contentId: string;
  /** Address of this exact corpus/compiler/binary/function instance. */
  instanceId: string;
  sourceFunctionName: string;
  sourceAddress?: string;
  provenance: FunctionAtlasProvenance;
  normalizedTreeSha256: string;
  featureVectorSha256: string;
  simHash64: string;
  nodeCount: number;
  distinctFeatureCount: number;
  features: FunctionAtlasFeature[];
  triviality: FunctionAtlasTriviality;
}

export interface FunctionAtlasMatch {
  contentId: string;
  instanceId: string;
  sourceFunctionName: string;
  sourceAddress?: string;
  provenance: FunctionAtlasProvenance;
  /** Structural cosine/simhash score in [0, 1]. */
  similarity: number;
  /** Corpus-rarity-weighted evidence mass in [0, 1], independent of similarity. */
  significance: number;
  cosine: number;
  simHashAgreement: number;
  sharedFeatureCount: number;
}

export interface FunctionAtlasQueryOptions {
  topK?: number;
  minSimilarity?: number;
  minSignificance?: number;
  includeTrivial?: boolean;
  excludeSameBinary?: boolean;
  excludeInstanceIds?: readonly string[];
}

export interface FunctionAtlasQueryResult {
  queryContentId: string;
  queryInstanceId: string;
  suppressed: boolean;
  suppressionReasons: string[];
  corpusSize: number;
  matches: FunctionAtlasMatch[];
}

export interface FunctionAtlasAddResult {
  indexed: boolean;
  replaced: boolean;
  record: FunctionAtlasRecord;
  reasons: string[];
}

export interface FunctionAtlasBenchmarkArtifact {
  schemaVersion: number;
  normalizerVersion: string;
  artifactSha256: string;
  program: string;
  binarySha256: string;
  provenance: FunctionAtlasProvenance;
  queries: Array<{
    function: string;
    address?: string;
    contentId: string;
    instanceId: string;
    suppressed: boolean;
    suppressionReasons: string[];
    matches: FunctionAtlasMatch[];
  }>;
}

export interface FunctionAtlasIndex {
  add(record: FunctionAtlasRecord, options?: { includeTrivial?: boolean }): FunctionAtlasAddResult;
  get(instanceId: string): FunctionAtlasRecord | undefined;
  remove(instanceId: string): boolean;
  list(): FunctionAtlasRecord[];
  query(record: FunctionAtlasRecord, options?: FunctionAtlasQueryOptions): FunctionAtlasQueryResult;
  clear(): void;
}

export interface FunctionAtlasSqliteStatement {
  run(...params: unknown[]): { changes: number };
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}

export interface FunctionAtlasSqliteDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): FunctionAtlasSqliteStatement;
}

interface NormalizedNode {
  kind: string;
  attributes?: Record<string, string | number | boolean>;
  children?: Array<{ role: string; node: NormalizedNode }>;
}

interface FeatureAccumulator {
  nodeCount: number;
  controlCount: number;
  callCount: number;
  operatorCount: number;
  features: Map<string, number>;
}

const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const GENERATED_SYMBOL = /^(?:sub|fun|fn|loc|lab|unk|off|qword|dword|word|byte)_[0-9a-f]+$/i;
const GENERATED_VARIABLE = /^(?:v|var|arg|param|tmp|scf_[rw]?)[_$]?[0-9a-f]+$/i;

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record).sort().map(key => `${JSON.stringify(key)}:${canonicalJson(record[key])}`).join(',')}}`;
}

function roundScore(value: number): number {
  return Math.round(Math.max(0, Math.min(1, value)) * 1_000_000_000) / 1_000_000_000;
}

function normalizeType(type: string | undefined): string {
  if (!type) return 'unknown';
  const compact = type.toLowerCase().replace(/\b(?:const|volatile|restrict|struct|class)\b/g, '')
    .replace(/\s+/g, '')
    .replace(/(?:uint64_t|unsigned__int64|unsignedlonglong)/g, 'u64')
    .replace(/(?:__int64|int64_t|longlong)/g, 'i64')
    .replace(/(?:uint32_t|unsignedlong|unsignedint)/g, 'u32')
    .replace(/int32_t/g, 'i32')
    .replace(/\blong\b/g, 'i32')
    .replace(/\bint\b/g, 'i32')
    .replace(/(?:uint16_t|unsignedshort)/g, 'u16')
    .replace(/int16_t/g, 'i16')
    .replace(/\bshort\b/g, 'i16')
    .replace(/(?:uint8_t|unsignedchar)/g, 'u8')
    .replace(/int8_t/g, 'i8')
    .replace(/\bchar\b/g, 'i8');
  if (compact.includes('*')) return `ptr:${compact.replace(/\*+/g, '') || 'unknown'}`;
  return compact || 'unknown';
}

function normalizeSymbol(symbol: string | undefined): string {
  if (!symbol) return 'indirect';
  let normalized = symbol.trim().toLowerCase()
    .replace(/^__imp_/, '')
    .replace(/^_+/, '')
    .replace(/@[0-9]+$/, '');
  if (GENERATED_SYMBOL.test(normalized) || GENERATED_VARIABLE.test(normalized)) normalized = 'local';
  return normalized || 'indirect';
}

function normalizeInteger(value: number | string, width: number, signed: boolean): string {
  const exact = typeof value === 'number' ? String(value) : value.trim();
  return `${signed ? 's' : 'u'}${width}:${exact}`;
}

function normalizeString(value: string, encoding: string): string {
  const category = /^[\x20-\x7e]*$/.test(value) ? 'printable' : 'binary';
  return `${encoding}:${category}:${value.length}:${sha256(value).slice(0, 16)}`;
}

function childrenOf(node: CNode): Array<{ role: string; node: CNode }> {
  switch (node.kind) {
    case 'CBinaryExpr': return [{ role: 'left', node: node.left }, { role: 'right', node: node.right }];
    case 'CUnaryExpr': return [{ role: 'operand', node: node.operand }];
    case 'CCastExpr': return [{ role: 'operand', node: node.operand }];
    case 'CCallExpr': return node.arguments.map((child, index) => ({ role: `argument:${index}`, node: child }));
    case 'CTernaryExpr': return [
      { role: 'condition', node: node.condition },
      { role: 'consequent', node: node.consequent },
      { role: 'alternate', node: node.alternate },
    ];
    case 'CSubscriptExpr': return [{ role: 'base', node: node.base }, { role: 'index', node: node.index }];
    case 'CFieldAccessExpr': return [{ role: 'object', node: node.object }];
    case 'CArrayInitExpr': return node.elements.map((child, index) => ({ role: `element:${index}`, node: child }));
    case 'CCompoundLitExpr': return node.fields.map((child, index) => ({ role: `field:${index}`, node: child }));
    case 'CBlockStmt': return node.body.map((child, index) => ({ role: `statement:${index}`, node: child }));
    case 'CAssignStmt': return [
      { role: 'target', node: node.target },
      ...(node.value ? [{ role: 'value', node: node.value }] : []),
    ];
    case 'CExprStmt': return [{ role: 'expression', node: node.expression }];
    case 'CIfStmt': return [
      { role: 'condition', node: node.condition },
      { role: 'then', node: node.then },
      ...(node.else ? [{ role: 'else', node: node.else }] : []),
    ];
    case 'CForStmt': return [
      ...(node.init ? [{ role: 'init', node: node.init }] : []),
      ...(node.condition ? [{ role: 'condition', node: node.condition }] : []),
      ...(node.update ? [{ role: 'update', node: node.update }] : []),
      { role: 'body', node: node.body },
    ];
    case 'CWhileStmt':
    case 'CDoWhileStmt': return [{ role: 'condition', node: node.condition }, { role: 'body', node: node.body }];
    case 'CReturnStmt': return node.value ? [{ role: 'value', node: node.value }] : [];
    case 'CSwitchStmt': return [
      { role: 'discriminant', node: node.discriminant },
      ...node.cases.map((child, index) => ({ role: `case:${index}`, node: child as CNode })),
    ];
    case 'CCaseStmt': return [
      ...(node.value ? [{ role: 'value', node: node.value }] : []),
      ...node.body.map((child, index) => ({ role: `statement:${index}`, node: child })),
    ];
    case 'CLabelStmt': return [{ role: 'body', node: node.body }];
    case 'CFunctionDecl': return [
      ...node.params.map((child, index) => ({ role: `parameter:${index}`, node: child as CNode })),
      ...(node.locals ?? []).map((child, index) => ({ role: `local:${index}`, node: child as CNode })),
      ...(node.body ? [{ role: 'body', node: node.body as CNode }] : []),
    ];
    case 'CVarDecl': return node.init ? [{ role: 'init', node: node.init }] : [];
    case 'CStructDecl': return node.fields.map((child, index) => ({ role: `field:${index}`, node: child as CNode }));
    default: return [];
  }
}

function attributesOf(node: CNode): Record<string, string | number | boolean> | undefined {
  const resultType = node.resultType ? normalizeType(node.resultType) : undefined;
  switch (node.kind) {
    case 'CIntLitExpr': return { integer: normalizeInteger(node.exactValue ?? node.value, node.width, node.signed), ...(resultType ? { resultType } : {}) };
    case 'CFloatLitExpr': return { precision: node.precision, value: Number.isFinite(node.value) ? node.value : String(node.value), ...(resultType ? { resultType } : {}) };
    case 'CStringLitExpr': return { string: normalizeString(node.value, node.encoding) };
    case 'CAddrLitExpr': return { symbol: normalizeSymbol(node.symbol) };
    case 'CVarRefExpr': return { storage: node.storage ?? 'unknown', type: normalizeType(node.type), ...(resultType ? { resultType } : {}) };
    case 'CBinaryExpr': return { operator: node.operator, ...(resultType ? { resultType } : {}) };
    case 'CUnaryExpr': return { operator: node.operator, prefix: node.prefix, ...(resultType ? { resultType } : {}) };
    case 'CCastExpr': return { targetType: normalizeType(node.targetType), ...(resultType ? { resultType } : {}) };
    case 'CCallExpr': return { callee: normalizeSymbol(node.callTarget ?? node.callee), arity: node.arguments.length, ...(resultType ? { resultType } : {}) };
    case 'CFieldAccessExpr': return { arrow: node.arrow, field: node.fieldOffset ?? normalizeSymbol(node.field), ...(resultType ? { resultType } : {}) };
    case 'CCompoundLitExpr': return { type: normalizeType(node.type) };
    case 'CAssignStmt': return node.compoundOperator ? { compoundOperator: node.compoundOperator } : undefined;
    case 'CGotoStmt': return { label: 'local' };
    case 'CLabelStmt': return { label: 'local' };
    case 'CFunctionDecl': return {
      returnType: normalizeType(node.returnType),
      parameterCount: node.params.length,
      callingConvention: (node.callingConvention ?? 'unknown').toLowerCase(),
      variadic: node.isVariadic ?? false,
    };
    case 'CVarDecl': return { storage: node.storage ?? 'unknown', type: normalizeType(node.type) };
    case 'CStructDecl': return { fieldCount: node.fields.length };
    case 'CTypedefDecl': return { underlyingType: normalizeType(node.underlyingType) };
    case 'CEnumDecl': return { memberCount: node.members.length };
    case 'CUnknownExpr':
    case 'CUnknownStmt': return { sourceKind: node.sourceKind, lossy: true };
    case 'CAsmStmt': return { textSha256: sha256(node.text).slice(0, 16) };
    case 'CCommentStmt': return undefined;
    default: return resultType ? { resultType } : undefined;
  }
}

function addFeature(accumulator: FeatureAccumulator, feature: string, weight: number): void {
  accumulator.features.set(feature, (accumulator.features.get(feature) ?? 0) + weight);
}

function normalizeNode(
  node: CNode,
  accumulator: FeatureAccumulator,
  parentKind = 'root',
  role = 'root',
): NormalizedNode {
  accumulator.nodeCount += 1;
  addFeature(accumulator, `kind:${node.kind}`, 1);
  addFeature(accumulator, `edge:${parentKind}/${role}>${node.kind}`, 0.65);

  if (['CIfStmt', 'CForStmt', 'CWhileStmt', 'CDoWhileStmt', 'CSwitchStmt', 'CTernaryExpr'].includes(node.kind)) {
    accumulator.controlCount += 1;
    addFeature(accumulator, `control:${node.kind}`, 1.4);
  }
  if (node.kind === 'CCallExpr') accumulator.callCount += 1;
  if (node.kind === 'CBinaryExpr' || node.kind === 'CUnaryExpr' || node.kind === 'CAssignStmt') accumulator.operatorCount += 1;

  const attributes = attributesOf(node);
  if (attributes) {
    for (const [key, value] of Object.entries(attributes).sort(([left], [right]) => compareAscii(left, right))) {
      const featureWeight = key === 'callee' ? 2 : key === 'operator' || key === 'integer' ? 1.4 : 0.7;
      addFeature(accumulator, `attribute:${node.kind}:${key}=${String(value)}`, featureWeight);
    }
  }

  const sequenceIndices = new Map<string, number>();
  const children = childrenOf(node).filter(child => child.node.kind !== 'CCommentStmt').map(child => {
    const sequence = /^(.*):[0-9]+$/.exec(child.role);
    const role = sequence
      ? `${sequence[1]}:${sequenceIndices.get(sequence[1]) ?? 0}`
      : child.role;
    if (sequence) sequenceIndices.set(sequence[1], (sequenceIndices.get(sequence[1]) ?? 0) + 1);
    return {
      role,
      node: normalizeNode(child.node, accumulator, node.kind, role),
    };
  });
  return {
    kind: node.kind,
    ...(attributes && Object.keys(attributes).length > 0 ? { attributes } : {}),
    ...(children.length > 0 ? { children } : {}),
  };
}

function sortedFeatures(features: Map<string, number>): FunctionAtlasFeature[] {
  return [...features.entries()]
    .sort(([left], [right]) => compareAscii(left, right))
    .map(([feature, weight]) => ({ feature, weight: Math.round(weight * 1_000_000) / 1_000_000 }));
}

function computeSimHash64(features: readonly FunctionAtlasFeature[]): string {
  const totals = new Array<number>(64).fill(0);
  for (const entry of features) {
    const digest = createHash('sha256').update(entry.feature, 'utf8').digest();
    const bits = digest.readBigUInt64BE(0);
    for (let bit = 0; bit < 64; bit += 1) {
      const mask = 1n << BigInt(63 - bit);
      totals[bit] += (bits & mask) !== 0n ? entry.weight : -entry.weight;
    }
  }
  let hash = 0n;
  for (let bit = 0; bit < 64; bit += 1) {
    if (totals[bit] > 0) hash |= 1n << BigInt(63 - bit);
  }
  return hash.toString(16).padStart(16, '0');
}

function classifyTriviality(accumulator: FeatureAccumulator, features: readonly FunctionAtlasFeature[]): FunctionAtlasTriviality {
  const reasons: string[] = [];
  if (accumulator.nodeCount < 6) reasons.push('node-count-below-6');
  if (features.length < 8) reasons.push('distinct-feature-count-below-8');
  if (accumulator.controlCount === 0 && accumulator.callCount === 0 && accumulator.operatorCount <= 1 && accumulator.nodeCount < 12) {
    reasons.push('no-distinguishing-control-call-or-operator-shape');
  }
  return { trivial: reasons.length > 0, reasons };
}

function assertNonEmpty(value: string, field: string): void {
  if (!value.trim()) throw new Error(`Function Atlas provenance field ${field} must be non-empty`);
}

function assertSha256(value: string, field: string): void {
  if (!SHA256_PATTERN.test(value)) throw new Error(`Function Atlas provenance field ${field} must be lowercase SHA-256`);
}

export function validateFunctionAtlasProvenance(provenance: FunctionAtlasProvenance): void {
  assertNonEmpty(provenance.corpusId, 'corpusId');
  assertNonEmpty(provenance.corpusVersion, 'corpusVersion');
  assertNonEmpty(provenance.sampleId, 'sampleId');
  assertSha256(provenance.sourceSha256, 'sourceSha256');
  assertSha256(provenance.groundTruthSha256, 'groundTruthSha256');
  assertSha256(provenance.binarySha256, 'binarySha256');
  assertNonEmpty(provenance.architecture, 'architecture');
  assertNonEmpty(provenance.format, 'format');
  assertNonEmpty(provenance.compiler.name, 'compiler.name');
  assertNonEmpty(provenance.compiler.version, 'compiler.version');
  assertNonEmpty(provenance.compiler.targetTriple, 'compiler.targetTriple');
  assertNonEmpty(provenance.compiler.optimization, 'compiler.optimization');
  if (!Array.isArray(provenance.compiler.flags) || provenance.compiler.flags.some(flag => typeof flag !== 'string' || !flag)) {
    throw new Error('Function Atlas provenance compiler.flags must be the exact non-empty compiler argument list');
  }
  assertNonEmpty(provenance.producer.name, 'producer.name');
  assertNonEmpty(provenance.producer.version, 'producer.version');
  if (!Number.isInteger(provenance.producer.hastSchema) || provenance.producer.hastSchema < 1) {
    throw new Error('Function Atlas provenance producer.hastSchema must be a positive integer');
  }
}

export function buildFunctionAtlasRecord(input: FunctionAtlasBuildInput): FunctionAtlasRecord {
  validateFunctionAtlasProvenance(input.provenance);
  const accumulator: FeatureAccumulator = {
    nodeCount: 0,
    controlCount: 0,
    callCount: 0,
    operatorCount: 0,
    features: new Map(),
  };
  const normalizedTree = normalizeNode(input.function, accumulator);
  const normalizedTreeJson = canonicalJson(normalizedTree);
  const normalizedTreeSha256 = sha256(normalizedTreeJson);
  const features = sortedFeatures(accumulator.features);
  const featureVectorSha256 = sha256(canonicalJson(features));
  const contentId = `hqlfn:v${FUNCTION_ATLAS_SCHEMA_VERSION}:${normalizedTreeSha256}`;
  const sourceFunctionName = input.sourceFunctionName ?? input.function.name;
  const sourceAddress = input.sourceAddress ?? input.function.address;
  const instanceIdentity = {
    contentId,
    sourceFunctionName,
    sourceAddress: sourceAddress ?? null,
    provenance: input.provenance,
  };
  return {
    schemaVersion: FUNCTION_ATLAS_SCHEMA_VERSION,
    normalizerVersion: FUNCTION_ATLAS_NORMALIZER_VERSION,
    contentId,
    instanceId: `hqlfni:v${FUNCTION_ATLAS_SCHEMA_VERSION}:${sha256(canonicalJson(instanceIdentity))}`,
    sourceFunctionName,
    ...(sourceAddress ? { sourceAddress } : {}),
    provenance: JSON.parse(canonicalJson(input.provenance)) as FunctionAtlasProvenance,
    normalizedTreeSha256,
    featureVectorSha256,
    simHash64: computeSimHash64(features),
    nodeCount: accumulator.nodeCount,
    distinctFeatureCount: features.length,
    features,
    triviality: classifyTriviality(accumulator, features),
  };
}

export function validateFunctionAtlasRecord(record: FunctionAtlasRecord): void {
  if (record.schemaVersion !== FUNCTION_ATLAS_SCHEMA_VERSION) {
    throw new Error(`Unsupported Function Atlas schema version: ${record.schemaVersion}`);
  }
  if (record.normalizerVersion !== FUNCTION_ATLAS_NORMALIZER_VERSION) {
    throw new Error(`Unsupported Function Atlas normalizer: ${record.normalizerVersion}`);
  }
  validateFunctionAtlasProvenance(record.provenance);
  if (record.contentId !== `hqlfn:v${FUNCTION_ATLAS_SCHEMA_VERSION}:${record.normalizedTreeSha256}`) {
    throw new Error('Function Atlas contentId does not address normalizedTreeSha256');
  }
  assertSha256(record.normalizedTreeSha256, 'normalizedTreeSha256');
  assertSha256(record.featureVectorSha256, 'featureVectorSha256');
  if (!/^[0-9a-f]{16}$/.test(record.simHash64)) throw new Error('Function Atlas simHash64 must be exact lowercase hex');
  if (!Number.isInteger(record.nodeCount) || record.nodeCount < 1) throw new Error('Function Atlas nodeCount must be positive');
  if (record.distinctFeatureCount !== record.features.length) throw new Error('Function Atlas distinctFeatureCount drift');
  let previous = '';
  for (const feature of record.features) {
    if (!feature.feature || feature.feature <= previous) throw new Error('Function Atlas features must be unique and lexically sorted');
    if (!Number.isFinite(feature.weight) || feature.weight <= 0) throw new Error('Function Atlas feature weights must be positive and finite');
    previous = feature.feature;
  }
  if (record.featureVectorSha256 !== sha256(canonicalJson(record.features))) throw new Error('Function Atlas feature vector hash drift');
  if (record.simHash64 !== computeSimHash64(record.features)) throw new Error('Function Atlas simhash drift');
  const expectedInstance = `hqlfni:v${FUNCTION_ATLAS_SCHEMA_VERSION}:${sha256(canonicalJson({
    contentId: record.contentId,
    sourceFunctionName: record.sourceFunctionName,
    sourceAddress: record.sourceAddress ?? null,
    provenance: record.provenance,
  }))}`;
  if (record.instanceId !== expectedInstance) throw new Error('Function Atlas instanceId provenance drift');
}

function featureMap(record: FunctionAtlasRecord): Map<string, number> {
  return new Map(record.features.map(entry => [entry.feature, entry.weight]));
}

function cosine(left: Map<string, number>, right: Map<string, number>): number {
  let dot = 0;
  let leftNorm = 0;
  let rightNorm = 0;
  for (const value of left.values()) leftNorm += value * value;
  for (const value of right.values()) rightNorm += value * value;
  for (const [feature, value] of left) dot += value * (right.get(feature) ?? 0);
  if (leftNorm === 0 || rightNorm === 0) return 0;
  return dot / Math.sqrt(leftNorm * rightNorm);
}

function simHashAgreement(left: string, right: string): number {
  let difference = BigInt(`0x${left}`) ^ BigInt(`0x${right}`);
  let distance = 0;
  while (difference !== 0n) {
    difference &= difference - 1n;
    distance += 1;
  }
  return 1 - distance / 64;
}

function documentFrequency(records: readonly FunctionAtlasRecord[]): Map<string, number> {
  const frequencies = new Map<string, number>();
  for (const record of records) {
    for (const feature of new Set(record.features.map(entry => entry.feature))) {
      frequencies.set(feature, (frequencies.get(feature) ?? 0) + 1);
    }
  }
  return frequencies;
}

function computeSignificance(
  query: Map<string, number>,
  candidate: Map<string, number>,
  frequencies: Map<string, number>,
  corpusSize: number,
): { significance: number; sharedFeatureCount: number } {
  let sharedInformation = 0;
  let sharedFeatureCount = 0;
  for (const [feature, queryWeight] of query) {
    const candidateWeight = candidate.get(feature);
    if (candidateWeight === undefined) continue;
    sharedFeatureCount += 1;
    const idf = Math.log((corpusSize + 1) / ((frequencies.get(feature) ?? 0) + 1)) + 1;
    sharedInformation += Math.min(queryWeight, candidateWeight) * idf;
  }
  return {
    significance: 1 - Math.exp(-sharedInformation / 14),
    sharedFeatureCount,
  };
}

export function rankFunctionAtlasRecords(
  query: FunctionAtlasRecord,
  corpus: readonly FunctionAtlasRecord[],
  options: FunctionAtlasQueryOptions = {},
): FunctionAtlasQueryResult {
  validateFunctionAtlasRecord(query);
  for (const candidate of corpus) validateFunctionAtlasRecord(candidate);
  const includeTrivial = options.includeTrivial ?? false;
  const topK = Math.max(1, Math.floor(options.topK ?? 10));
  if (query.triviality.trivial && !includeTrivial) {
    return {
      queryContentId: query.contentId,
      queryInstanceId: query.instanceId,
      suppressed: true,
      suppressionReasons: [...query.triviality.reasons],
      corpusSize: corpus.length,
      matches: [],
    };
  }

  const excluded = new Set(options.excludeInstanceIds ?? []);
  excluded.add(query.instanceId);
  const candidates = corpus.filter(candidate => {
    if (excluded.has(candidate.instanceId)) return false;
    if (candidate.triviality.trivial && !includeTrivial) return false;
    if ((options.excludeSameBinary ?? true) && candidate.provenance.binarySha256 === query.provenance.binarySha256) return false;
    return true;
  });
  const statisticsCorpus = [query, ...candidates];
  const frequencies = documentFrequency(statisticsCorpus);
  const queryFeatures = featureMap(query);
  const matches: FunctionAtlasMatch[] = [];
  for (const candidate of candidates) {
    const candidateFeatures = featureMap(candidate);
    const cosineScore = cosine(queryFeatures, candidateFeatures);
    const hashAgreement = simHashAgreement(query.simHash64, candidate.simHash64);
    const similarity = roundScore(cosineScore * 0.85 + hashAgreement * 0.15);
    const significanceResult = computeSignificance(queryFeatures, candidateFeatures, frequencies, statisticsCorpus.length);
    const significance = roundScore(significanceResult.significance);
    if (similarity < (options.minSimilarity ?? 0) || significance < (options.minSignificance ?? 0)) continue;
    matches.push({
      contentId: candidate.contentId,
      instanceId: candidate.instanceId,
      sourceFunctionName: candidate.sourceFunctionName,
      ...(candidate.sourceAddress ? { sourceAddress: candidate.sourceAddress } : {}),
      provenance: candidate.provenance,
      similarity,
      significance,
      cosine: roundScore(cosineScore),
      simHashAgreement: roundScore(hashAgreement),
      sharedFeatureCount: significanceResult.sharedFeatureCount,
    });
  }
  matches.sort((left, right) =>
    right.similarity - left.similarity
    || right.significance - left.significance
    || compareAscii(left.contentId, right.contentId)
    || compareAscii(left.instanceId, right.instanceId));
  return {
    queryContentId: query.contentId,
    queryInstanceId: query.instanceId,
    suppressed: false,
    suppressionReasons: [],
    corpusSize: corpus.length,
    matches: matches.slice(0, topK),
  };
}

/** Build the deterministic interchange consumed by the BSim parity evaluator. */
export function buildFunctionAtlasBenchmarkArtifact(
  entries: ReadonlyArray<{ record: FunctionAtlasRecord; result: FunctionAtlasQueryResult }>,
): FunctionAtlasBenchmarkArtifact {
  if (entries.length === 0) throw new Error('Function Atlas benchmark artifact requires at least one query');
  for (const entry of entries) {
    validateFunctionAtlasRecord(entry.record);
    if (entry.result.queryContentId !== entry.record.contentId || entry.result.queryInstanceId !== entry.record.instanceId) {
      throw new Error(`Function Atlas query result identity drift for ${entry.record.sourceFunctionName}`);
    }
  }
  const first = entries[0].record;
  for (const entry of entries.slice(1)) {
    if (entry.record.provenance.binarySha256 !== first.provenance.binarySha256
      || entry.record.provenance.sampleId !== first.provenance.sampleId) {
      throw new Error('Function Atlas benchmark artifact cannot mix binary/sample provenance');
    }
  }
  const queries = entries.map(entry => ({
    function: entry.record.sourceFunctionName,
    ...(entry.record.sourceAddress ? { address: entry.record.sourceAddress } : {}),
    contentId: entry.record.contentId,
    instanceId: entry.record.instanceId,
    suppressed: entry.result.suppressed,
    suppressionReasons: [...entry.result.suppressionReasons].sort(),
    matches: [...entry.result.matches],
  })).sort((left, right) =>
    compareAscii(left.address ?? '', right.address ?? '')
    || compareAscii(left.function, right.function)
    || compareAscii(left.instanceId, right.instanceId));
  const logical = {
    schemaVersion: FUNCTION_ATLAS_SCHEMA_VERSION,
    normalizerVersion: FUNCTION_ATLAS_NORMALIZER_VERSION,
    program: first.provenance.sampleId,
    binarySha256: first.provenance.binarySha256,
    provenance: first.provenance,
    queries,
  };
  return {
    ...logical,
    artifactSha256: sha256(canonicalJson(logical)),
  };
}

export class InMemoryFunctionAtlasIndex implements FunctionAtlasIndex {
  private readonly records = new Map<string, FunctionAtlasRecord>();

  add(record: FunctionAtlasRecord, options: { includeTrivial?: boolean } = {}): FunctionAtlasAddResult {
    validateFunctionAtlasRecord(record);
    const existing = this.records.has(record.instanceId);
    if (record.triviality.trivial && !(options.includeTrivial ?? false)) {
      return { indexed: false, replaced: false, record, reasons: [...record.triviality.reasons] };
    }
    this.records.set(record.instanceId, record);
    return { indexed: true, replaced: existing, record, reasons: [] };
  }

  get(instanceId: string): FunctionAtlasRecord | undefined {
    return this.records.get(instanceId);
  }

  remove(instanceId: string): boolean {
    return this.records.delete(instanceId);
  }

  list(): FunctionAtlasRecord[] {
    return [...this.records.values()].sort((left, right) => compareAscii(left.instanceId, right.instanceId));
  }

  query(record: FunctionAtlasRecord, options: FunctionAtlasQueryOptions = {}): FunctionAtlasQueryResult {
    return rankFunctionAtlasRecords(record, this.list(), options);
  }

  clear(): void {
    this.records.clear();
  }
}

/**
 * SQLite persistence keeps canonical records only. Ranking deliberately uses the
 * same in-memory implementation so SQLite row order cannot affect results.
 */
export class SqliteFunctionAtlasIndex implements FunctionAtlasIndex {
  constructor(private readonly database: FunctionAtlasSqliteDatabase) {
    database.exec(`
      CREATE TABLE IF NOT EXISTS hql_function_atlas (
        instance_id TEXT PRIMARY KEY,
        content_id TEXT NOT NULL,
        binary_sha256 TEXT NOT NULL,
        trivial INTEGER NOT NULL,
        record_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS hql_function_atlas_content ON hql_function_atlas(content_id);
      CREATE INDEX IF NOT EXISTS hql_function_atlas_binary ON hql_function_atlas(binary_sha256);
    `);
  }

  add(record: FunctionAtlasRecord, options: { includeTrivial?: boolean } = {}): FunctionAtlasAddResult {
    validateFunctionAtlasRecord(record);
    if (record.triviality.trivial && !(options.includeTrivial ?? false)) {
      return { indexed: false, replaced: false, record, reasons: [...record.triviality.reasons] };
    }
    const existing = this.get(record.instanceId) !== undefined;
    this.database.prepare(`
      INSERT OR REPLACE INTO hql_function_atlas(instance_id, content_id, binary_sha256, trivial, record_json)
      VALUES (?, ?, ?, ?, ?)
    `).run(
      record.instanceId,
      record.contentId,
      record.provenance.binarySha256,
      record.triviality.trivial ? 1 : 0,
      canonicalJson(record),
    );
    return { indexed: true, replaced: existing, record, reasons: [] };
  }

  get(instanceId: string): FunctionAtlasRecord | undefined {
    const row = this.database.prepare('SELECT record_json FROM hql_function_atlas WHERE instance_id = ?').get(instanceId) as { record_json?: string } | undefined;
    if (!row?.record_json) return undefined;
    const record = JSON.parse(row.record_json) as FunctionAtlasRecord;
    validateFunctionAtlasRecord(record);
    return record;
  }

  remove(instanceId: string): boolean {
    return this.database.prepare('DELETE FROM hql_function_atlas WHERE instance_id = ?').run(instanceId).changes > 0;
  }

  list(): FunctionAtlasRecord[] {
    const rows = this.database.prepare('SELECT record_json FROM hql_function_atlas ORDER BY instance_id').all() as Array<{ record_json: string }>;
    return rows.map(row => {
      const record = JSON.parse(row.record_json) as FunctionAtlasRecord;
      validateFunctionAtlasRecord(record);
      return record;
    });
  }

  query(record: FunctionAtlasRecord, options: FunctionAtlasQueryOptions = {}): FunctionAtlasQueryResult {
    return rankFunctionAtlasRecords(record, this.list(), options);
  }

  clear(): void {
    this.database.exec('DELETE FROM hql_function_atlas;');
  }
}
