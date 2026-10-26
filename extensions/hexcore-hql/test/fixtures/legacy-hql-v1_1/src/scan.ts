// ─── HQL scan API ───
// One call: hydrate a Helix HAST FlatBuffer and run a set of signatures over
// every function in it. This is the entry point the IDE / pipeline consumes.

import { hydrateHAST } from './adapter/flatbuf.js';
import { HQLMatcher } from './engine/matcher.js';
import { getDefaultSignatures } from './signatures/loader.js';
import { createHash } from 'crypto';
import type { SessionDbReader } from './adapter/sessionDb.js';
import type { HQLSignature, HQLMatchResult } from './types/hql.js';
import type { HASTAdapterCoverage, HASTModuleMetadata } from './types/ast.js';

export interface HQLFunctionFindings {
  /** Function name (after any session rename). */
  function: string;
  /** Exact function address from the HAST. */
  address: string;
  /** Number of hydrated AST nodes, including explicit loss markers. */
  nodeCount: number;
  /** Per-function adapter fidelity. */
  adapterCoverage: HASTAdapterCoverage;
  hast: HASTModuleMetadata;
  /** Identity of the complete active signature set. */
  signatureSetSha256: string;
  /** Clarifies that signatureSetSha256 identifies rules, not function input. */
  signatureSetScope: 'active-rule-set';
  /** Identity of HAST + signatures + semantic budgets. */
  cacheKey: string;
  /** Explicit budget outcome; partial records are never clean negatives. */
  status: 'ok' | 'partial';
  truncated: boolean;
  truncationReasons: string[];
  partialReasons: string[];
  evaluatedSignatureCount: number;
  /** Signature results that fired on this function. */
  findings: HQLMatchResult[];
  semanticFactCount: number;
  semanticFactsSha256: string;
  semanticReadErrors: string[];
}

export interface HQLScanOptions {
	semanticSnapshotSha256?: string;
  maxFunctions?: number;
  maxNodesPerFunction?: number;
  maxFindingsPerFunction?: number;
  signal?: AbortSignal;
  /** Quality of the producer, distinct from the fidelity of HAST adaptation. */
  upstream?: HQLUpstreamQuality;
}

export interface HQLUpstreamQuality {
  architecture?: string;
  status?: 'ok' | 'partial' | 'error';
  semanticEligible?: boolean;
  qualityIssues?: readonly unknown[];
  warning?: string;
}

function normalizedArchitecture(value: string | undefined): string | undefined {
  const name = value?.toLowerCase();
  if (name === 'arm64') return 'aarch64';
  if (name === 'x64' || name === 'amd64') return 'x86_64';
  if (name && /^i[3-6]86$/.test(name)) return 'x86';
  return name;
}

function formatUpstreamQualityIssue(issue: unknown): string {
  if (typeof issue === 'string') return issue;
  if (issue && typeof issue === 'object') {
    const record = issue as Record<string, unknown>;
    if (typeof record.detail === 'string' && record.detail.trim()) return record.detail.trim();
    const kind = typeof record.kind === 'string' ? record.kind : undefined;
    const count = typeof record.count === 'number' ? record.count : undefined;
    if (kind) return count !== undefined ? `${kind} (${count})` : kind;
    try { return JSON.stringify(record); } catch { return 'unserializable quality issue'; }
  }
  return String(issue);
}

function upstreamReasons(hast: HASTModuleMetadata | undefined, upstream: HQLUpstreamQuality | undefined): string[] {
  const reasons: string[] = [];
  if (hast?.semanticEligible !== true) reasons.push('HAST semantic contract is not eligible');
  if (!hast?.nativeQuality || hast.nativeQuality.status === 'unreported') {
    reasons.push('Native function quality was not reported');
  } else if (hast.nativeQuality.status === 'known-loss') {
    reasons.push(...hast.nativeQuality.issues.map(issue => `Native quality issue: ${issue}`));
  }
  if (!upstream) return reasons;
  if (upstream.status !== 'ok') reasons.push(`Upstream semantic status: ${upstream.status ?? 'unknown'}`);
  if (upstream.semanticEligible === false) reasons.push('Upstream semantics are not eligible');
  for (const issue of upstream.qualityIssues ?? []) reasons.push(`Upstream quality issue: ${formatUpstreamQualityIssue(issue)}`);
  if (upstream.warning) reasons.push(`Upstream warning: ${upstream.warning}`);
  const expected = normalizedArchitecture(upstream.architecture);
  const actual = normalizedArchitecture(hast?.architecture);
  if (expected && expected !== actual) reasons.push(`HAST architecture mismatch: expected ${expected}, received ${actual ?? 'unknown'}`);
  if (!expected || expected === 'unknown') reasons.push('Upstream architecture is unknown');
  return [...new Set(reasons)];
}

const DEFAULT_SCAN_OPTIONS = Object.freeze({
  maxFunctions: 4096,
  maxNodesPerFunction: 250_000,
  maxFindingsPerFunction: 1024,
});

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => compareAscii(left, right))
        .map(([key, child]) => [key, canonicalize(child)]),
    );
  }
  return value;
}

function compareAscii(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function signatureSetSha256(signatures: readonly HQLSignature[]): string {
  const ordered = [...signatures].sort((left, right) => compareAscii(left.id, right.id));
  return createHash('sha256')
    .update(JSON.stringify(canonicalize(ordered)), 'utf8')
    .digest('hex');
}

function positiveInteger(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) throw new Error(`HQL ${name} must be a positive safe integer`);
  return resolved;
}

/**
 * Hydrate a HAST FlatBuffer (Helix `decompileIr().astBuffer`) and evaluate every
 * signature against every function. Clean functions are retained as explicit
 * negative controls with identity and adapter fidelity.
 *
 * @param astBuffer  Raw HAST FlatBuffer bytes from Helix.
 * @param signatures Signatures to evaluate (default: the built-in library).
 * @param session    Optional SessionDbReader for analyst rename/retype propagation.
 */
export function scanHAST(
  astBuffer: Uint8Array,
  signatures?: HQLSignature[],
  session?: SessionDbReader,
  options: HQLScanOptions = {},
): HQLFunctionFindings[] {
	if (options.semanticSnapshotSha256 !== undefined && !/^[a-f0-9]{64}$/i.test(options.semanticSnapshotSha256)) { throw new Error('Invalid semantic snapshot SHA-256'); }
  if (options.signal?.aborted) throw new Error('HQL scan cancelled before hydration');
  const activeSignatures = signatures ?? getDefaultSignatures();
  const fns = hydrateHAST(astBuffer, session);
  const limits = {
    maxFunctions: positiveInteger(options.maxFunctions, DEFAULT_SCAN_OPTIONS.maxFunctions, 'maxFunctions'),
    maxNodesPerFunction: positiveInteger(options.maxNodesPerFunction, DEFAULT_SCAN_OPTIONS.maxNodesPerFunction, 'maxNodesPerFunction'),
    maxFindingsPerFunction: positiveInteger(options.maxFindingsPerFunction, DEFAULT_SCAN_OPTIONS.maxFindingsPerFunction, 'maxFindingsPerFunction'),
  };
  if (fns.length > limits.maxFunctions) {
    throw new Error(`HQL function budget exceeded: ${fns.length} > ${limits.maxFunctions}`);
  }
  const matcher = new HQLMatcher();
  const out: HQLFunctionFindings[] = [];
  const setSha256 = signatureSetSha256(activeSignatures);
  const astSha256 = createHash('sha256').update(astBuffer).digest('hex');
  const baseCacheIdentity = {
    contract: 'hexcore-hql-scan-v5-native-quality',
    astSha256,
    signatureSetSha256: setSha256,
    limits,
    upstream: options.upstream ?? null,
    semanticSnapshotSha256: options.semanticSnapshotSha256?.toLowerCase() ?? null,
  };
  for (const fn of fns) {
    if (options.signal?.aborted) throw new Error(`HQL scan cancelled before function ${fn.address ?? fn.name}`);
    const findings: HQLMatchResult[] = [];
    const semanticFacts = session?.getSemanticFacts(fn.address ?? '0x0') ?? [];
    const semanticReadErrors = session?.getSemanticReadErrors() ?? [];
    const semanticFactsSha256 = createHash('sha256').update(JSON.stringify(canonicalize(semanticFacts))).digest('hex');
    const cacheKey = createHash('sha256').update(JSON.stringify(canonicalize({ ...baseCacheIdentity, semanticFactsSha256 }))).digest('hex');
    const adapterCoverage = fn.adapterCoverage ?? {
      totalNodes: 0,
      lossyNodes: 0,
      coverage: 0,
      unsupportedNodeCounts: {},
    };
    const truncationReasons: string[] = [];
	const producerReasons = upstreamReasons(fn.hast, options.upstream);
	const partialReasons: string[] = [
		...producerReasons,
		...(adapterCoverage.errors ?? []),
		...semanticReadErrors.map(error => `HXDB semantic read failed: ${error}`),
	];
	if (adapterCoverage.lossyNodes > 0) {
	  partialReasons.push(`Adapter coverage incomplete: ${adapterCoverage.lossyNodes}/${adapterCoverage.totalNodes} node(s) are lossy`);
	}
    let evaluatedSignatureCount = 0;
    if (adapterCoverage.totalNodes > limits.maxNodesPerFunction) {
      truncationReasons.push(`AST node budget exceeded: ${adapterCoverage.totalNodes} > ${limits.maxNodesPerFunction}`);
    } else if (producerReasons.length === 0 && semanticReadErrors.length === 0) {
      for (const sig of activeSignatures) {
        if (options.signal?.aborted) throw new Error(`HQL scan cancelled while evaluating ${fn.address ?? fn.name}`);
        evaluatedSignatureCount++;
        const result = matcher.evaluate(fn, sig, semanticFacts);
        if (!result) continue;
        if (findings.length >= limits.maxFindingsPerFunction) {
          truncationReasons.push(`Finding budget exceeded: more than ${limits.maxFindingsPerFunction}`);
          break;
        }
        findings.push(result);
      }
    }
    out.push({
      function: fn.name,
      address: fn.address ?? '0x0',
      nodeCount: adapterCoverage.totalNodes,
      adapterCoverage,
      hast: { ...(fn.hast ?? {
        schemaMajor: 0, schemaMinor: 0, capabilities: [], architecture: 'unknown', pointerBits: 0, semanticEligible: false,
      }), semanticEligible: fn.hast?.semanticEligible === true && partialReasons.length === 0 && truncationReasons.length === 0 },
      signatureSetSha256: setSha256,
      signatureSetScope: 'active-rule-set',
      cacheKey,
      status: truncationReasons.length > 0 || partialReasons.length > 0 ? 'partial' : 'ok',
      truncated: truncationReasons.length > 0,
      truncationReasons,
      partialReasons,
      evaluatedSignatureCount,
      findings,
      semanticFactCount: semanticFacts.length,
      semanticFactsSha256,
      semanticReadErrors,
    });
  }
  return out;
}
