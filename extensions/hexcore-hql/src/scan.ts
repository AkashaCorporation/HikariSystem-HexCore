// ─── HQL scan API ───
// One call: hydrate a Helix HAST FlatBuffer and run a set of signatures over
// every function in it. This is the entry point the IDE / pipeline consumes.

import { hydrateHAST } from './adapter/flatbuf.js';
import { HQLMatcher } from './engine/matcher.js';
import { getDefaultSignatures } from './signatures/loader.js';
import type { SessionDbReader } from './adapter/sessionDb.js';
import type { HQLSignature, HQLMatchResult } from './types/hql.js';

export interface HQLFunctionFindings {
  /** Function name (after any session rename). */
  function: string;
  /** Signature results that fired on this function. */
  findings: HQLMatchResult[];
}

/**
 * Hydrate a HAST FlatBuffer (Helix `decompileIr().astBuffer`) and evaluate every
 * signature against every function. Returns only functions with >= 1 finding.
 *
 * @param astBuffer  Raw HAST FlatBuffer bytes from Helix.
 * @param signatures Signatures to evaluate (default: the built-in library).
 * @param session    Optional SessionDbReader for analyst rename/retype propagation.
 */
export function scanHAST(
  astBuffer: Uint8Array,
  signatures?: HQLSignature[],
  session?: SessionDbReader,
): HQLFunctionFindings[] {
  const activeSignatures = signatures ?? getDefaultSignatures();
  const fns = hydrateHAST(astBuffer, session);
  const matcher = new HQLMatcher();
  const out: HQLFunctionFindings[] = [];
  for (const fn of fns) {
    const findings: HQLMatchResult[] = [];
    for (const sig of activeSignatures) {
      const r = matcher.evaluate(fn, sig);
      if (r) { findings.push(r); }
    }
    if (findings.length > 0) {
      out.push({ function: fn.name, findings });
    }
  }
  return out;
}
