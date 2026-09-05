import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface SimilarityBenchmarkMatch {
  executable: string;
  function: string;
  address?: string;
  similarity: number;
  significance?: number;
}

export interface SimilarityBenchmarkQuery {
  program: string;
  executableSha256?: string;
  function: string;
  address?: string;
  suppressed?: boolean;
  matches: SimilarityBenchmarkMatch[];
}

export interface SimilarityBenchmarkMetrics {
  queryCount: number;
  eligibleQueryCount: number;
  suppressedQueryCount: number;
  top1Correct: number;
  top1Accuracy: number;
  top5Correct: number;
  top5Accuracy: number;
  meanReciprocalRank: number;
  expectedMatches: number;
  retrievedCorrectMatches: number;
  recall: number;
  falseMatches: number;
  falseMatchesAt5: number;
  queriesWithoutCorrectMatch: number;
}

export interface SimilarityBenchmarkReport {
  schemaVersion: 1;
  groundTruthSha256: string;
  provenance?: unknown;
  provenanceSha256?: string;
  bsim: {
    inputSha256: string;
    metrics: SimilarityBenchmarkMetrics;
  };
  functionAtlas?: {
    inputSha256: string;
    metrics: SimilarityBenchmarkMetrics;
  };
  comparison?: {
    top1AccuracyDelta: number;
    top5AccuracyDelta: number;
    meanReciprocalRankDelta: number;
    recallDelta: number;
    falseMatchesDelta: number;
  };
}

interface BSimFile {
  schemaVersion: number;
  program: string;
  executableSha256?: string;
  queries: Array<{
    function: string;
    address?: string;
    matches?: Array<{ executable: string; function: string; address?: string; similarity: number; significance?: number }>;
  }>;
}

interface FunctionAtlasFile {
  schemaVersion?: number;
  normalizerVersion?: string;
  artifactSha256?: string;
  program?: string;
  sampleId?: string;
  executableSha256?: string;
  binarySha256?: string;
  queries?: Array<{
    function?: string;
    sourceFunctionName?: string;
    address?: string;
    sourceAddress?: string;
    suppressed?: boolean;
    matches?: Array<{
      executable?: string;
      function?: string;
      sourceFunctionName?: string;
      address?: string;
      sourceAddress?: string;
      similarity: number;
      significance?: number;
      provenance?: { sampleId?: string; binarySha256?: string };
    }>;
  }>;
}

interface GroundTruth {
  functions?: Record<string, unknown>;
  similarityGroups?: Record<string, string | string[]>;
  aliases?: Record<string, string>;
}

function sha256(buffer: Buffer | string): string {
  return createHash('sha256').update(buffer).digest('hex');
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

function round(value: number): number {
  return Math.round(value * 1_000_000_000) / 1_000_000_000;
}

function normalizeFunction(value: string): string {
  return value.trim().toLowerCase().replace(/^_+/, '').replace(/@[0-9]+$/, '');
}

function normalizeExecutable(value: string): string {
  return path.basename(value.trim()).toLowerCase().replace(/\.(?:exe|dll|so|dylib)$/i, '');
}

function normalizeAddress(value: string | undefined): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]+$/.test(trimmed)) return value.trim().toLowerCase();
  return BigInt(`0x${trimmed}`).toString(16);
}

function isBsimFile(value: unknown): value is BSimFile {
  const record = value as Partial<BSimFile> | null;
  return !!record && typeof record.program === 'string' && Array.isArray(record.queries);
}

function isFunctionAtlasFile(value: unknown): value is FunctionAtlasFile {
  const record = value as Partial<FunctionAtlasFile> | null;
  return !!record && Array.isArray(record.queries);
}

function inputFiles(inputPath: string): string[] {
  const resolved = path.resolve(inputPath);
  if (!fs.existsSync(resolved)) throw new Error(`Similarity benchmark input does not exist: ${resolved}`);
  if (fs.statSync(resolved).isFile()) return [resolved];
  return fs.readdirSync(resolved, { withFileTypes: true })
    .filter(entry => entry.isFile() && entry.name.toLowerCase().endsWith('.json'))
    .map(entry => path.join(resolved, entry.name))
    .sort((left, right) => compareAscii(left, right));
}

function readDocuments(inputPath: string, kind: 'bsim' | 'function-atlas'): { queries: SimilarityBenchmarkQuery[]; inputSha256: string } {
  const documents: Array<{ path: string; rawSha256: string; value: unknown }> = [];
  for (const file of inputFiles(inputPath)) {
    const raw = fs.readFileSync(file);
    const value = JSON.parse(raw.toString('utf8')) as unknown;
    if (kind === 'bsim' ? isBsimFile(value) : isFunctionAtlasFile(value)) {
      if (kind === 'bsim' && (value as BSimFile).schemaVersion !== 1) {
        throw new Error(`Unsupported BSim query schema in ${file}`);
      }
      if (kind === 'function-atlas') {
        const atlas = value as FunctionAtlasFile;
        if (atlas.schemaVersion !== undefined && atlas.schemaVersion !== 1) {
          throw new Error(`Unsupported Function Atlas query schema in ${file}`);
        }
        if (atlas.artifactSha256) {
          const { artifactSha256, ...logical } = atlas;
          if (artifactSha256 !== sha256(canonicalJson(logical))) {
            throw new Error(`Function Atlas artifact hash drift in ${file}`);
          }
        }
      }
      documents.push({ path: path.basename(file), rawSha256: sha256(raw), value });
    }
  }
  if (documents.length === 0) throw new Error(`No ${kind} query documents found under ${path.resolve(inputPath)}`);

  const queries: SimilarityBenchmarkQuery[] = [];
  for (const document of documents.sort((left, right) => compareAscii(left.path, right.path))) {
    if (kind === 'bsim') {
      const value = document.value as BSimFile;
      for (const query of value.queries) {
        queries.push({
          program: value.program,
          ...(value.executableSha256 ? { executableSha256: value.executableSha256.toLowerCase() } : {}),
          function: query.function,
          ...(query.address ? { address: query.address } : {}),
          matches: (query.matches ?? []).map(match => ({
            executable: match.executable,
            function: match.function,
            ...(match.address ? { address: match.address } : {}),
            similarity: match.similarity,
            ...(match.significance !== undefined ? { significance: match.significance } : {}),
          })),
        });
      }
    } else {
      const value = document.value as FunctionAtlasFile;
      const program = value.program ?? value.sampleId ?? path.parse(document.path).name;
      for (const query of value.queries ?? []) {
        const functionName = query.function ?? query.sourceFunctionName;
        if (!functionName) throw new Error(`Function Atlas query in ${document.path} has no function identity`);
        queries.push({
          program,
          ...(value.executableSha256 ?? value.binarySha256 ? { executableSha256: (value.executableSha256 ?? value.binarySha256)!.toLowerCase() } : {}),
          function: functionName,
          ...(query.address ?? query.sourceAddress ? { address: query.address ?? query.sourceAddress } : {}),
          ...(query.suppressed !== undefined ? { suppressed: query.suppressed } : {}),
          matches: (query.matches ?? []).map(match => ({
            executable: match.executable ?? match.provenance?.sampleId ?? 'unknown',
            function: match.function ?? match.sourceFunctionName ?? 'unknown',
            ...(match.address ?? match.sourceAddress ? { address: match.address ?? match.sourceAddress } : {}),
            similarity: match.similarity,
            ...(match.significance !== undefined ? { significance: match.significance } : {}),
          })),
        });
      }
    }
  }
  queries.sort((left, right) =>
    compareAscii(normalizeExecutable(left.program), normalizeExecutable(right.program))
    || compareAscii(normalizeFunction(left.function), normalizeFunction(right.function))
    || compareAscii(left.address ?? '', right.address ?? ''));
  return {
    queries,
    inputSha256: sha256(canonicalJson(documents.map(document => ({ path: document.path, sha256: document.rawSha256 })))),
  };
}

function groundTruthGroups(groundTruth: GroundTruth): Map<string, string> {
  const groups = new Map<string, string>();
  for (const functionName of Object.keys(groundTruth.functions ?? {})) {
    const normalized = normalizeFunction(functionName);
    groups.set(normalized, normalized);
  }
  for (const [key, value] of Object.entries(groundTruth.similarityGroups ?? {})) {
    if (Array.isArray(value)) {
      const group = normalizeFunction(key);
      for (const member of value) groups.set(normalizeFunction(member), group);
    } else {
      groups.set(normalizeFunction(key), normalizeFunction(value));
    }
  }
  for (const [alias, canonical] of Object.entries(groundTruth.aliases ?? {})) {
    const canonicalName = normalizeFunction(canonical);
    groups.set(normalizeFunction(alias), groups.get(canonicalName) ?? canonicalName);
  }
  if (groups.size === 0) throw new Error('Ground truth must define functions or similarityGroups');
  return groups;
}

function matchKey(executable: string, functionName: string): string {
  return `${normalizeExecutable(executable)}\u0000${normalizeFunction(functionName)}`;
}

export function evaluateSimilarityQueries(
  queries: readonly SimilarityBenchmarkQuery[],
  groundTruth: GroundTruth,
): SimilarityBenchmarkMetrics {
  const groups = groundTruthGroups(groundTruth);
  const addressFunctions = new Map<string, string>();
  for (const query of queries) {
    const address = normalizeAddress(query.address);
    if (address) addressFunctions.set(`${normalizeExecutable(query.program)}\u0000${address}`, query.function);
  }
  const resolvedFunction = (match: SimilarityBenchmarkMatch): string => {
    const address = normalizeAddress(match.address);
    if (!address) return match.function;
    return addressFunctions.get(`${normalizeExecutable(match.executable)}\u0000${address}`) ?? match.function;
  };
  const universe = new Map<string, Set<string>>();
  for (const query of queries) {
    const functionName = normalizeFunction(query.function);
    const group = groups.get(functionName);
    if (!group) continue;
    const key = matchKey(query.program, query.function);
    const entries = universe.get(group) ?? new Set<string>();
    entries.add(key);
    universe.set(group, entries);
  }

  let eligibleQueryCount = 0;
  let suppressedQueryCount = 0;
  let top1Correct = 0;
  let top5Correct = 0;
  let reciprocalRankTotal = 0;
  let expectedMatches = 0;
  let retrievedCorrectMatches = 0;
  let falseMatches = 0;
  let falseMatchesAt5 = 0;
  let queriesWithoutCorrectMatch = 0;

  for (const query of queries) {
    if (query.suppressed) {
      suppressedQueryCount += 1;
      continue;
    }
    const queryFunction = normalizeFunction(query.function);
    const group = groups.get(queryFunction);
    if (!group) continue;
    const self = matchKey(query.program, query.function);
    const expected = new Set([...(universe.get(group) ?? [])].filter(key => key !== self));
    if (expected.size === 0) continue;
    eligibleQueryCount += 1;
    expectedMatches += expected.size;

    const seen = new Set<string>();
    const ranked = query.matches
      .filter(match => {
        const key = matchKey(match.executable, resolvedFunction(match));
        if (key === self || seen.has(key)) return false;
        seen.add(key);
        return true;
      });
    let firstCorrectRank = 0;
    const correctSeen = new Set<string>();
    ranked.forEach((match, index) => {
      const candidateFunction = resolvedFunction(match);
      const key = matchKey(match.executable, candidateFunction);
      const candidateGroup = groups.get(normalizeFunction(candidateFunction));
      const correct = candidateGroup === group && expected.has(key);
      if (correct) {
        correctSeen.add(key);
        if (firstCorrectRank === 0) firstCorrectRank = index + 1;
      } else {
        falseMatches += 1;
        if (index < 5) falseMatchesAt5 += 1;
      }
    });
    retrievedCorrectMatches += correctSeen.size;
    if (firstCorrectRank === 1) top1Correct += 1;
    if (firstCorrectRank > 0 && firstCorrectRank <= 5) top5Correct += 1;
    if (firstCorrectRank > 0) reciprocalRankTotal += 1 / firstCorrectRank;
    else queriesWithoutCorrectMatch += 1;
  }

  return {
    queryCount: queries.length,
    eligibleQueryCount,
    suppressedQueryCount,
    top1Correct,
    top1Accuracy: round(eligibleQueryCount > 0 ? top1Correct / eligibleQueryCount : 0),
    top5Correct,
    top5Accuracy: round(eligibleQueryCount > 0 ? top5Correct / eligibleQueryCount : 0),
    meanReciprocalRank: round(eligibleQueryCount > 0 ? reciprocalRankTotal / eligibleQueryCount : 0),
    expectedMatches,
    retrievedCorrectMatches,
    recall: round(expectedMatches > 0 ? retrievedCorrectMatches / expectedMatches : 0),
    falseMatches,
    falseMatchesAt5,
    queriesWithoutCorrectMatch,
  };
}

export function evaluateSimilarityBenchmark(options: {
  bsimPath: string;
  groundTruthPath: string;
  functionAtlasPath?: string;
  provenancePath?: string;
}): SimilarityBenchmarkReport {
  const groundTruthRaw = fs.readFileSync(path.resolve(options.groundTruthPath));
  const groundTruth = JSON.parse(groundTruthRaw.toString('utf8')) as GroundTruth;
  const bsim = readDocuments(options.bsimPath, 'bsim');
  const report: SimilarityBenchmarkReport = {
    schemaVersion: 1,
    groundTruthSha256: sha256(groundTruthRaw),
    bsim: { inputSha256: bsim.inputSha256, metrics: evaluateSimilarityQueries(bsim.queries, groundTruth) },
  };
  if (options.provenancePath) {
    const provenanceRaw = fs.readFileSync(path.resolve(options.provenancePath));
    const provenance = JSON.parse(provenanceRaw.toString('utf8').replace(/^\uFEFF/, '')) as unknown;
    report.provenance = provenance;
    report.provenanceSha256 = sha256(canonicalJson(provenance));
  }
  if (options.functionAtlasPath) {
    const atlas = readDocuments(options.functionAtlasPath, 'function-atlas');
    report.functionAtlas = {
      inputSha256: atlas.inputSha256,
      metrics: evaluateSimilarityQueries(atlas.queries, groundTruth),
    };
    report.comparison = {
      top1AccuracyDelta: round(report.functionAtlas.metrics.top1Accuracy - report.bsim.metrics.top1Accuracy),
      top5AccuracyDelta: round(report.functionAtlas.metrics.top5Accuracy - report.bsim.metrics.top5Accuracy),
      meanReciprocalRankDelta: round(report.functionAtlas.metrics.meanReciprocalRank - report.bsim.metrics.meanReciprocalRank),
      recallDelta: round(report.functionAtlas.metrics.recall - report.bsim.metrics.recall),
      falseMatchesDelta: report.functionAtlas.metrics.falseMatches - report.bsim.metrics.falseMatches,
    };
  }
  return report;
}

function cliArguments(argv: readonly string[]): Record<string, string> {
  const result: Record<string, string> = {};
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) throw new Error(`Unexpected argument: ${argument}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${argument}`);
    result[argument.slice(2)] = value;
    index += 1;
  }
  return result;
}

if (require.main === module) {
  const args = cliArguments(process.argv.slice(2));
  if (!args.bsim || !args.groundTruth) {
    throw new Error('usage: evaluate.ts --bsim <query-json-or-dir> --groundTruth <json> [--functionAtlas <json-or-dir>] [--provenance <run-manifest.json>] [--out <json>]');
  }
  const report = evaluateSimilarityBenchmark({
    bsimPath: args.bsim,
    groundTruthPath: args.groundTruth,
    ...(args.functionAtlas ? { functionAtlasPath: args.functionAtlas } : {}),
    ...(args.provenance ? { provenancePath: args.provenance } : {}),
  });
  const output = `${JSON.stringify(report, null, 2)}\n`;
  if (args.out) {
    fs.mkdirSync(path.dirname(path.resolve(args.out)), { recursive: true });
    fs.writeFileSync(path.resolve(args.out), output, 'utf8');
  } else {
    process.stdout.write(output);
  }
}
