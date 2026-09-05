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
  maxFunctions?: number;
  maxNodesPerFunction?: number;
  maxFindingsPerFunction?: number;
  signal?: AbortSignal;
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
    contract: 'hexcore-hql-scan-v2',
    astSha256,
    signatureSetSha256: setSha256,
    limits,
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
	const partialReasons: string[] = [
		...(adapterCoverage.errors ?? []),
		...semanticReadErrors.map(error => `HXDB semantic read failed: ${error}`),
	];
	if (adapterCoverage.lossyNodes > 0) {
	  partialReasons.push(`Adapter coverage incomplete: ${adapterCoverage.lossyNodes}/${adapterCoverage.totalNodes} node(s) are lossy`);
	}
    let evaluatedSignatureCount = 0;
    if (adapterCoverage.totalNodes > limits.maxNodesPerFunction) {
      truncationReasons.push(`AST node budget exceeded: ${adapterCoverage.totalNodes} > ${limits.maxNodesPerFunction}`);
    } else {
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
      hast: fn.hast ?? {
        schemaMajor: 0, schemaMinor: 0, capabilities: [], architecture: 'unknown', pointerBits: 0, semanticEligible: false,
      },
      signatureSetSha256: setSha256,
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
