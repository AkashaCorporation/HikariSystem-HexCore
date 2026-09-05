import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';

export type SolverStatus = 'sat' | 'unsat' | 'unknown';
type SolverSort = { kind: 'int' } | { kind: 'bv'; bits: number };

export interface SolverVariable {
	name: string;
	type?: 'int' | 'bv';
	bits?: number;
	min?: number | string;
	max?: number | string;
	domain?: { min: number | string; max: number | string } | [number | string, number | string];
}

export interface ConstraintSolverOptions {
	variables?: SolverVariable[];
	constraints?: unknown[];
	smt2?: string;
	timeoutMs?: number;
	maxModels?: number;
	solverPath?: string;
	output?: string | { path?: string };
	quiet?: boolean;
	/** Preserve an inconclusive solver result as partial instead of failing the pipeline contract. */
	allowUnknown?: boolean;
	/** Preserve a timed-out solver result as partial instead of failing the pipeline contract. */
	allowTimeout?: boolean;
}

export interface ConstraintSolverResult {
	status: SolverStatus;
	semanticStatus: 'ok' | 'partial' | 'error';
	semanticWarning?: string;
	error?: string;
	models: Array<Record<string, string>>;
	modelCount: number;
	truncated: boolean;
	timeout: boolean;
	metrics: {
		elapsedMs: number;
		solverCalls: number;
		variableCount: number;
		constraintCount: number;
	};
	provenance: {
		solver: 'Z3';
		version: string;
		executableSha256: string;
		inputMode: 'json' | 'smt2';
	};
	generatedAt: string;
}

export function classifySolverSemanticResult(
	status: SolverStatus,
	timedOut: boolean,
	options: Pick<ConstraintSolverOptions, 'allowUnknown' | 'allowTimeout'> = {},
): Pick<ConstraintSolverResult, 'semanticStatus' | 'semanticWarning' | 'error'> {
	if (timedOut) {
		const reason = 'Z3 timed out before completing the requested solve.';
		return options.allowTimeout === true
			? { semanticStatus: 'partial', semanticWarning: reason }
			: { semanticStatus: 'error', error: reason };
	}
	if (status === 'unknown') {
		const reason = 'Z3 returned unknown; satisfiability was not established.';
		return options.allowUnknown === true
			? { semanticStatus: 'partial', semanticWarning: reason }
			: { semanticStatus: 'error', error: reason };
	}
	return { semanticStatus: 'ok' };
}

const MAX_VARIABLES = 2048;
const MAX_CONSTRAINTS = 10000;
const MAX_SCRIPT_BYTES = 4 * 1024 * 1024;
const MAX_TIMEOUT_MS = 300000;
const MAX_MODELS = 100;
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_.$-]*$/;

function assertIdentifier(value: unknown): string {
	if (typeof value !== 'string' || !IDENTIFIER.test(value)) {
		throw new Error(`Invalid SMT identifier: ${String(value)}`);
	}
	return value;
}

function parseInteger(value: unknown, label: string): string {
	const text = typeof value === 'bigint' ? value.toString() : String(value);
	if (!/^-?\d+$/.test(text)) {
		throw new Error(`${label} must be an integer.`);
	}
	return text.startsWith('-') ? `(- ${text.slice(1)})` : text;
}

function parseSort(variable: SolverVariable): SolverSort {
	if (variable.type === 'bv' || variable.bits !== undefined) {
		const bits = Number(variable.bits);
		if (!Number.isInteger(bits) || bits < 1 || bits > 4096) {
			throw new Error(`Variable ${variable.name} has an invalid bit width.`);
		}
		return { kind: 'bv', bits };
	}
	return { kind: 'int' };
}

function bvLiteral(value: unknown, bits: number): string {
	const raw = typeof value === 'bigint' ? value : BigInt(String(value));
	const modulus = 1n << BigInt(bits);
	const normalized = ((raw % modulus) + modulus) % modulus;
	return `(_ bv${normalized.toString()} ${bits})`;
}

interface RenderedExpression { text: string; sort: SolverSort | { kind: 'bool' }; }

function sameSort(left: RenderedExpression['sort'], right: RenderedExpression['sort']): boolean {
	return left.kind === right.kind && (left.kind !== 'bv' || right.kind !== 'bv' || left.bits === right.bits);
}

function renderExpression(node: unknown, sorts: Map<string, SolverSort>): RenderedExpression {
	if (typeof node === 'boolean') return { text: node ? 'true' : 'false', sort: { kind: 'bool' } };
	if (typeof node === 'number' || typeof node === 'bigint') {
		return { text: parseInteger(node, 'Literal'), sort: { kind: 'int' } };
	}
	if (typeof node === 'string') {
		const name = assertIdentifier(node);
		const sort = sorts.get(name);
		if (!sort) throw new Error(`Unknown solver variable: ${name}`);
		return { text: name, sort };
	}
	if (!node || typeof node !== 'object' || Array.isArray(node)) {
		throw new Error('Constraint expressions must be scalars or expression objects.');
	}

	const expr = node as Record<string, unknown>;
	if (expr.value !== undefined && expr.type === 'int') {
		return { text: parseInteger(expr.value, 'Integer literal'), sort: { kind: 'int' } };
	}
	if (expr.value !== undefined && expr.bits !== undefined) {
		const bits = Number(expr.bits);
		if (!Number.isInteger(bits) || bits < 1 || bits > 4096) throw new Error('Bitvector literal has an invalid width.');
		return { text: bvLiteral(expr.value, bits), sort: { kind: 'bv', bits } };
	}

	const op = String(expr.op ?? '').toLowerCase();
	const rawArgs = Array.isArray(expr.args) ? expr.args : expr.value !== undefined ? [expr.value] : [];
	const args = rawArgs.map(arg => renderExpression(arg, sorts));
	const requireArgs = (count: number) => {
		if (args.length !== count) throw new Error(`${op} expects ${count} argument(s).`);
	};
	const requireMinArgs = (count: number) => {
		if (args.length < count) throw new Error(`${op} expects at least ${count} argument(s).`);
	};
	const firstSort = args[0]?.sort;
	const isBv = firstSort?.kind === 'bv';

	if (op === 'not') {
		requireArgs(1);
		if (args[0].sort.kind !== 'bool') throw new Error('not requires a boolean argument.');
		return { text: `(not ${args[0].text})`, sort: { kind: 'bool' } };
	}
	if (op === 'neg') {
		requireArgs(1);
		if (firstSort?.kind === 'bool') throw new Error('neg requires an integer or bitvector argument.');
		return { text: `(${isBv ? 'bvneg' : '-'} ${args[0].text})`, sort: firstSort as SolverSort };
	}
	if (op === 'extract') {
		requireArgs(1);
		const high = Number(expr.high);
		const low = Number(expr.low);
		if (!isBv || !Number.isInteger(high) || !Number.isInteger(low) || low < 0 || high < low || high >= firstSort.bits) {
			throw new Error('extract requires a bitvector and valid high/low indices.');
		}
		return { text: `((_ extract ${high} ${low}) ${args[0].text})`, sort: { kind: 'bv', bits: high - low + 1 } };
	}
	if (op === 'concat') {
		requireMinArgs(2);
		if (args.some(arg => arg.sort.kind !== 'bv')) throw new Error('concat accepts bitvectors only.');
		return {
			text: `(concat ${args.map(arg => arg.text).join(' ')})`,
			sort: { kind: 'bv', bits: args.reduce((sum, arg) => sum + (arg.sort.kind === 'bv' ? arg.sort.bits : 0), 0) },
		};
	}
	if (op === 'ite') {
		requireArgs(3);
		if (args[0].sort.kind !== 'bool') throw new Error('ite requires a boolean condition.');
		if (!sameSort(args[1].sort, args[2].sort)) throw new Error('ite branches must have identical sorts.');
		return { text: `(ite ${args.map(arg => arg.text).join(' ')})`, sort: args[1].sort };
	}

	const arithmetic: Record<string, [string, string]> = {
		add: ['+', 'bvadd'], sub: ['-', 'bvsub'], mul: ['*', 'bvmul'],
		and: ['and', 'bvand'], or: ['or', 'bvor'], xor: ['xor', 'bvxor'],
		shl: ['shl', 'bvshl'], lshr: ['div', 'bvlshr'], ashr: ['div', 'bvashr'],
	};
	if (arithmetic[op]) {
		requireMinArgs(2);
		if (firstSort?.kind === 'bool' || args.some(arg => !sameSort(arg.sort, firstSort!))) {
			throw new Error(`${op} requires arguments with identical integer or bitvector sorts.`);
		}
		const smtOp = arithmetic[op][isBv ? 1 : 0];
		if ((op === 'and' || op === 'or' || op === 'xor' || op === 'shl' || op === 'lshr' || op === 'ashr') && !isBv) {
			throw new Error(`${op} requires bitvectors.`);
		}
		return { text: `(${smtOp} ${args.map(arg => arg.text).join(' ')})`, sort: firstSort as SolverSort };
	}

	const comparisons: Record<string, [string, string]> = {
		eq: ['=', '='], ne: ['distinct', 'distinct'], lt: ['<', 'bvslt'], le: ['<=', 'bvsle'],
		gt: ['>', 'bvsgt'], ge: ['>=', 'bvsge'], ult: ['<', 'bvult'], ule: ['<=', 'bvule'],
		ugt: ['>', 'bvugt'], uge: ['>=', 'bvuge'],
	};
	if (comparisons[op]) {
		requireArgs(2);
		if (!sameSort(args[0].sort, args[1].sort)) throw new Error(`${op} requires arguments with identical sorts.`);
		if ((op === 'ult' || op === 'ule' || op === 'ugt' || op === 'uge') && !isBv) {
			throw new Error(`${op} requires bitvectors.`);
		}
		return { text: `(${comparisons[op][isBv ? 1 : 0]} ${args[0].text} ${args[1].text})`, sort: { kind: 'bool' } };
	}

	throw new Error(`Unsupported constraint operation: ${op || '<missing>'}`);
}

function normalizeDomain(variable: SolverVariable): { min: unknown; max: unknown } | undefined {
	if (Array.isArray(variable.domain)) return { min: variable.domain[0], max: variable.domain[1] };
	if (variable.domain) return variable.domain;
	if (variable.min !== undefined || variable.max !== undefined) {
		if (variable.min === undefined || variable.max === undefined) throw new Error(`Variable ${variable.name} requires both min and max.`);
		return { min: variable.min, max: variable.max };
	}
	return undefined;
}

export function buildSolverScript(options: ConstraintSolverOptions, blockers: string[] = []): { script: string; names: string[]; inputMode: 'json' | 'smt2' } {
	const variables = options.variables ?? [];
	const constraints = options.constraints ?? [];
	if (variables.length > MAX_VARIABLES) throw new Error(`At most ${MAX_VARIABLES} variables are supported.`);
	if (constraints.length > MAX_CONSTRAINTS) throw new Error(`At most ${MAX_CONSTRAINTS} constraints are supported.`);
	const names: string[] = [];
	const sorts = new Map<string, SolverSort>();
	const lines = ['(set-option :produce-models true)'];

	for (const variable of variables) {
		const name = assertIdentifier(variable.name);
		if (sorts.has(name)) throw new Error(`Duplicate solver variable: ${name}`);
		const sort = parseSort(variable);
		sorts.set(name, sort);
		names.push(name);
		lines.push(`(declare-const ${name} ${sort.kind === 'int' ? 'Int' : `(_ BitVec ${sort.bits})`})`);
		const domain = normalizeDomain(variable);
		if (domain) {
			const min = sort.kind === 'int' ? parseInteger(domain.min, `${name}.min`) : bvLiteral(domain.min, sort.bits);
			const max = sort.kind === 'int' ? parseInteger(domain.max, `${name}.max`) : bvLiteral(domain.max, sort.bits);
			const lower = sort.kind === 'int' ? '>=' : 'bvuge';
			const upper = sort.kind === 'int' ? '<=' : 'bvule';
			lines.push(`(assert (${lower} ${name} ${min}))`, `(assert (${upper} ${name} ${max}))`);
		}
	}

	if (options.smt2 !== undefined) {
		if (typeof options.smt2 !== 'string') throw new Error('smt2 must be a string.');
		if (/\(\s*(check-sat|get-model|get-value|exit|reset)\b/i.test(options.smt2)) {
			throw new Error('smt2 input must contain declarations/assertions only; solver control commands are added by HexCore.');
		}
		lines.push(options.smt2);
	} else {
		for (const constraint of constraints) {
			const rendered = renderExpression(constraint, sorts);
			if (rendered.sort.kind !== 'bool') throw new Error('Each top-level constraint must be boolean.');
			lines.push(`(assert ${rendered.text})`);
		}
	}
	for (const blocker of blockers) lines.push(`(assert ${blocker})`);
	lines.push('(check-sat)');
	if (names.length > 0) lines.push(`(get-value (${names.join(' ')}))`);
	lines.push('(exit)');
	const script = lines.join('\n') + '\n';
	if (Buffer.byteLength(script, 'utf8') > MAX_SCRIPT_BYTES) throw new Error(`Solver input exceeds ${MAX_SCRIPT_BYTES} bytes.`);
	return { script, names, inputMode: options.smt2 !== undefined ? 'smt2' : 'json' };
}

function tokenizeSexpr(text: string): string[] {
	return text.match(/\(|\)|[^\s()]+/g) ?? [];
}

function parseSexpr(tokens: string[], index = 0): { value: unknown; next: number } {
	if (tokens[index] !== '(') return { value: tokens[index], next: index + 1 };
	const values: unknown[] = [];
	let cursor = index + 1;
	while (cursor < tokens.length && tokens[cursor] !== ')') {
		const parsed = parseSexpr(tokens, cursor);
		values.push(parsed.value);
		cursor = parsed.next;
	}
	if (tokens[cursor] !== ')') throw new Error('Malformed Z3 model output.');
	return { value: values, next: cursor + 1 };
}

function valueToString(value: unknown): string {
	if (typeof value === 'string') {
		if (/^#x[0-9a-f]+$/i.test(value)) return BigInt(`0x${value.slice(2)}`).toString();
		if (/^#b[01]+$/i.test(value)) return BigInt(`0b${value.slice(2)}`).toString();
		return value;
	}
	if (Array.isArray(value)) {
		if (value.length === 2 && value[0] === '-' && typeof value[1] === 'string') return `-${value[1]}`;
		if (value.length === 3 && value[0] === '_' && typeof value[1] === 'string' && value[1].startsWith('bv')) return value[1].slice(2);
		return `(${value.map(valueToString).join(' ')})`;
	}
	return String(value);
}

export function parseSolverOutput(stdout: string, names: string[]): { status: SolverStatus; model?: Record<string, string> } {
	const lines = stdout.trim().split(/\r?\n/).map(line => line.trim()).filter(Boolean);
	const statusIndex = lines.findIndex(line => line === 'sat' || line === 'unsat' || line === 'unknown');
	if (statusIndex < 0) throw new Error(`Z3 returned no status: ${stdout.trim().slice(0, 500)}`);
	const status = lines[statusIndex] as SolverStatus;
	if (status !== 'sat' || names.length === 0) return { status };
	const modelText = lines.slice(statusIndex + 1).join(' ');
	const parsed = parseSexpr(tokenizeSexpr(modelText)).value;
	if (!Array.isArray(parsed)) throw new Error('Z3 returned an invalid value list.');
	const model: Record<string, string> = {};
	for (const pair of parsed) {
		if (Array.isArray(pair) && pair.length >= 2 && typeof pair[0] === 'string') {
			model[pair[0]] = valueToString(pair[1]);
		}
	}
	return { status, model };
}

function resolveSolverPath(explicitPath?: string): string {
	const candidates = [
		explicitPath,
		process.env.HEXCORE_Z3_PATH,
		path.resolve(__dirname, '..', '..', 'hexcore-souper', 'prebuilds', `${process.platform}-${process.arch}`, process.platform === 'win32' ? 'z3.exe' : 'z3'),
		path.resolve(__dirname, '..', '..', 'hexcore-souper', 'deps', 'z3', process.platform === 'win32' ? 'z3.exe' : 'z3'),
	].filter((candidate): candidate is string => typeof candidate === 'string' && candidate.length > 0);
	for (const candidate of candidates) {
		const resolved = path.resolve(candidate);
		if (fs.existsSync(resolved) && fs.statSync(resolved).isFile()) return resolved;
	}
	throw new Error('Z3 executable not found. Install the hexcore-souper runtime or set HEXCORE_Z3_PATH.');
}

async function runZ3(executable: string, script: string, timeoutMs: number): Promise<{ stdout: string; stderr: string; timedOut: boolean }> {
	return new Promise((resolve, reject) => {
		const child = spawn(executable, ['-in', '-smt2'], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
		let stdout = '';
		let stderr = '';
		let settled = false;
		const timer = setTimeout(() => {
			if (settled) return;
			settled = true;
			child.kill();
			resolve({ stdout, stderr, timedOut: true });
		}, timeoutMs);
		child.stdout.on('data', chunk => { stdout += chunk.toString(); });
		child.stderr.on('data', chunk => { stderr += chunk.toString(); });
		child.on('error', error => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			reject(error);
		});
		child.on('close', code => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			const hasStatus = /(^|\r?\n)(sat|unsat|unknown)(\r?\n|$)/.test(stdout);
			if (code !== 0 && !hasStatus) reject(new Error(`Z3 exited with code ${code}: ${(stderr || stdout).trim()}`));
			else resolve({ stdout, stderr, timedOut: false });
		});
		child.stdin.end(script);
	});
}

function buildModelBlocker(model: Record<string, string>, sorts: Map<string, SolverSort>): string {
	const equalities = Object.entries(model).map(([name, value]) => {
		const sort = sorts.get(name);
		if (!sort) throw new Error(`Missing sort for model variable ${name}.`);
		const literal = sort.kind === 'bv' ? bvLiteral(value, sort.bits) : parseInteger(value, name);
		return `(= ${name} ${literal})`;
	});
	return `(not (and ${equalities.join(' ')}))`;
}

async function getZ3Version(executable: string): Promise<string> {
	return new Promise(resolve => {
		const child = spawn(executable, ['-version'], { windowsHide: true, stdio: ['ignore', 'pipe', 'ignore'] });
		let stdout = '';
		const timer = setTimeout(() => { child.kill(); resolve('unknown'); }, 3000);
		child.stdout.on('data', chunk => { stdout += chunk.toString(); });
		child.on('error', () => { clearTimeout(timer); resolve('unknown'); });
		child.on('close', () => { clearTimeout(timer); resolve(stdout.trim() || 'unknown'); });
	});
}

export async function solveConstraints(options: ConstraintSolverOptions): Promise<ConstraintSolverResult> {
	const startedAt = Date.now();
	const timeoutMs = Math.max(1, Math.min(MAX_TIMEOUT_MS, Math.trunc(Number(options.timeoutMs ?? 30000))));
	const maxModels = Math.max(1, Math.min(MAX_MODELS, Math.trunc(Number(options.maxModels ?? 1))));
	const executable = resolveSolverPath(options.solverPath);
	const sorts = new Map<string, SolverSort>();
	for (const variable of options.variables ?? []) sorts.set(assertIdentifier(variable.name), parseSort(variable));
	const blockers: string[] = [];
	const models: Array<Record<string, string>> = [];
	let status: SolverStatus = 'unknown';
	let timedOut = false;
	let solverCalls = 0;
	let inputMode: 'json' | 'smt2' = options.smt2 !== undefined ? 'smt2' : 'json';

	while (models.length < maxModels) {
		const remainingMs = timeoutMs - (Date.now() - startedAt);
		if (remainingMs <= 0) { timedOut = true; status = 'unknown'; break; }
		const built = buildSolverScript(options, blockers);
		inputMode = built.inputMode;
		const execution = await runZ3(executable, built.script, remainingMs);
		solverCalls++;
		if (execution.timedOut) { timedOut = true; status = 'unknown'; break; }
		const parsed = parseSolverOutput(execution.stdout, built.names);
		status = parsed.status;
		if (status !== 'sat' || !parsed.model) break;
		models.push(parsed.model);
		if (models.length >= maxModels) break;
		blockers.push(buildModelBlocker(parsed.model, sorts));
	}

	const executableSha256 = crypto.createHash('sha256').update(fs.readFileSync(executable)).digest('hex');
	const result: ConstraintSolverResult = {
		status: models.length > 0 ? 'sat' : status,
		semanticStatus: 'ok',
		models,
		modelCount: models.length,
		truncated: models.length >= maxModels && status === 'sat',
		timeout: timedOut,
		metrics: {
			elapsedMs: Date.now() - startedAt,
			solverCalls,
			variableCount: options.variables?.length ?? 0,
			constraintCount: options.constraints?.length ?? 0,
		},
		provenance: {
			solver: 'Z3',
			version: await getZ3Version(executable),
			executableSha256,
			inputMode,
		},
		generatedAt: new Date().toISOString(),
	};
	Object.assign(result, classifySolverSemanticResult(result.status, timedOut, options));
	if (timedOut) {
		const reason = `Z3 timed out after ${timeoutMs}ms before completing the requested solve.`;
		if (result.semanticStatus === 'partial') { result.semanticWarning = reason; }
		else { result.error = reason; }
	}
	const output = typeof options.output === 'string' ? options.output : options.output?.path;
	if (output) {
		const resolved = path.resolve(output);
		fs.mkdirSync(path.dirname(resolved), { recursive: true });
		fs.writeFileSync(resolved, JSON.stringify(result, null, 2), 'utf8');
	}
	return result;
}
