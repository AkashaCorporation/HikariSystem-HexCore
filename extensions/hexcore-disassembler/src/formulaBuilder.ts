/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

import { Instruction } from './disassemblerEngine';

export interface FormulaStep {
	address: string;
	mnemonic: string;
	operands: string;
	updatedRegister?: string;
	expression?: string;
}

export interface FormulaBuildResult {
	targetRegister: string;
	expression: string;
	instructionCount: number;
	supportedInstructionCount: number;
	unsupportedInstructions: FormulaStep[];
	steps: FormulaStep[];
	registerExpressions: Record<string, string>;
	reportMarkdown: string;
}

export function buildInstructionFormula(
	instructions: Instruction[],
	targetRegister?: string
): FormulaBuildResult {
	const state = new Map<string, string>();
	const steps: FormulaStep[] = [];
	const unsupported: FormulaStep[] = [];
	const touchedRegisters: string[] = [];

	for (const instruction of instructions) {
		const mnemonic = instruction.mnemonic.toLowerCase();
		const operands = splitOperands(instruction.opStr);
		let updatedRegister: string | undefined;
		let updatedExpression: string | undefined;

		if ((mnemonic === 'mov' || mnemonic === 'movz' || mnemonic === 'movk' || mnemonic === 'movn' || mnemonic === 'mvn') && operands.length >= 2) {
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				if (mnemonic === 'movn' || mnemonic === 'mvn') {
					updatedExpression = `~(${resolveOperandExpression(operands[1], state, false)})`;
				} else if (mnemonic === 'movk') {
					// MOVK keeps upper bits — combine with existing
					const existing = state.get(dst) ?? dst;
					updatedExpression = `(${existing} | ${resolveOperandExpression(operands[1], state, false)})`;
				} else {
					updatedExpression = resolveOperandExpression(operands[1], state, false);
				}
			}
		} else if (mnemonic === 'lea' && operands.length >= 2) {
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				updatedExpression = resolveOperandExpression(operands[1], state, true);
			}
		} else if (mnemonic === 'add' && operands.length >= 2) {
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				if (operands.length >= 3) {
					// ARM 3-operand: add x0, x1, x2 → x0 = x1 + x2
					const left = resolveOperandExpression(operands[1], state, false);
					const right = resolveOperandExpression(operands[2], state, false);
					updatedExpression = `(${left} + ${right})`;
				} else {
					// x86 2-operand: add eax, ebx → eax = eax + ebx
					const left = state.get(dst) ?? dst;
					const right = resolveOperandExpression(operands[1], state, false);
					updatedExpression = `(${left} + ${right})`;
				}
			}
		} else if (mnemonic === 'sub' && operands.length >= 2) {
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				if (operands.length >= 3) {
					// ARM 3-operand: sub x0, x1, x2 → x0 = x1 - x2
					const left = resolveOperandExpression(operands[1], state, false);
					const right = resolveOperandExpression(operands[2], state, false);
					updatedExpression = `(${left} - ${right})`;
				} else {
					const left = state.get(dst) ?? dst;
					const right = resolveOperandExpression(operands[1], state, false);
					updatedExpression = `(${left} - ${right})`;
				}
			}
		} else if (mnemonic === 'imul' || mnemonic === 'mul') {
			if (operands.length >= 3) {
				const dst = normalizeRegister(operands[0]);
				if (dst) {
					updatedRegister = dst;
					const left = resolveOperandExpression(operands[1], state, false);
					const right = resolveOperandExpression(operands[2], state, false);
					updatedExpression = `(${left} * ${right})`;
				}
			} else if (operands.length >= 2) {
				const dst = normalizeRegister(operands[0]);
				if (dst) {
					updatedRegister = dst;
					const left = state.get(dst) ?? dst;
					const right = resolveOperandExpression(operands[1], state, false);
					updatedExpression = `(${left} * ${right})`;
				}
			}
		} else if (mnemonic === 'madd' && operands.length >= 4) {
			// ARM64: madd x0, x1, x2, x3 → x0 = x1 * x2 + x3
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				const a = resolveOperandExpression(operands[1], state, false);
				const b = resolveOperandExpression(operands[2], state, false);
				const c = resolveOperandExpression(operands[3], state, false);
				updatedExpression = `((${a} * ${b}) + ${c})`;
			}
		} else if (mnemonic === 'msub' && operands.length >= 4) {
			// ARM64: msub x0, x1, x2, x3 → x0 = x3 - x1 * x2
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				const a = resolveOperandExpression(operands[1], state, false);
				const b = resolveOperandExpression(operands[2], state, false);
				const c = resolveOperandExpression(operands[3], state, false);
				updatedExpression = `(${c} - (${a} * ${b}))`;
			}
		} else if (mnemonic === 'mla' && operands.length >= 4) {
			// ARM32: mla r0, r1, r2, r3 → r0 = r1 * r2 + r3
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				const a = resolveOperandExpression(operands[1], state, false);
				const b = resolveOperandExpression(operands[2], state, false);
				const c = resolveOperandExpression(operands[3], state, false);
				updatedExpression = `((${a} * ${b}) + ${c})`;
			}
		} else if (mnemonic === 'neg' && operands.length >= 2) {
			// ARM64: neg x0, x1 → x0 = -x1
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				updatedExpression = `-(${resolveOperandExpression(operands[1], state, false)})`;
			}
		} else if ((mnemonic === 'xor' || mnemonic === 'eor') && operands.length >= 2) {
			const dst = normalizeRegister(operands[0]);
			if (mnemonic === 'eor' && operands.length >= 3) {
				// ARM 3-operand: eor x0, x1, x2
				const src1 = normalizeRegister(operands[1]);
				const src2 = normalizeRegister(operands[2]);
				if (dst && src1 && src2 && src1 === src2) {
					updatedRegister = dst;
					updatedExpression = '0';
				}
			} else {
				// x86 2-operand: xor eax, eax
				const src = normalizeRegister(operands[1]);
				if (dst && src && dst === src) {
					updatedRegister = dst;
					updatedExpression = '0';
				}
			}
		} else if ((mnemonic === 'lsl' || mnemonic === 'lsr' || mnemonic === 'asr') && operands.length >= 3) {
			// ARM: lsl x0, x1, #4 → x0 = x1 << 4
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				const src = resolveOperandExpression(operands[1], state, false);
				const shift = resolveOperandExpression(operands[2], state, false);
				const op = mnemonic === 'lsl' ? '<<' : mnemonic === 'lsr' ? '>>' : '>>>';
				updatedExpression = `(${src} ${op} ${shift})`;
			}
		} else if ((mnemonic === 'orr' || mnemonic === 'and') && operands.length >= 3) {
			// ARM: orr x0, x1, x2 / and x0, x1, x2
			const dst = normalizeRegister(operands[0]);
			if (dst) {
				updatedRegister = dst;
				const left = resolveOperandExpression(operands[1], state, false);
				const right = resolveOperandExpression(operands[2], state, false);
				const op = mnemonic === 'orr' ? '|' : '&';
				updatedExpression = `(${left} ${op} ${right})`;
			}
		}

		const step: FormulaStep = {
			address: toHexAddress(instruction.address),
			mnemonic: instruction.mnemonic,
			operands: instruction.opStr
		};

		if (updatedRegister && updatedExpression) {
			state.set(updatedRegister, normalizeExpression(updatedExpression));
			if (!touchedRegisters.includes(updatedRegister)) {
				touchedRegisters.push(updatedRegister);
			}
			step.updatedRegister = updatedRegister;
			step.expression = state.get(updatedRegister);
		} else if (isPotentialMathInstruction(mnemonic)) {
			unsupported.push(step);
		}

		steps.push(step);
	}

	const registerExpressions: Record<string, string> = {};
	for (const [register, expression] of state.entries()) {
		registerExpressions[register] = expression;
	}

	const preferredTarget = normalizeRegister(targetRegister ?? '');
	let primaryRegister = preferredTarget && registerExpressions[preferredTarget]
		? preferredTarget
		: undefined;
	if (!primaryRegister && touchedRegisters.length > 0) {
		primaryRegister = touchedRegisters[touchedRegisters.length - 1];
	}
	if (!primaryRegister && instructions.length > 0) {
		const firstOperands = splitOperands(instructions[instructions.length - 1].opStr);
		primaryRegister = normalizeRegister(firstOperands[0]) ?? 'result';
	}
	if (!primaryRegister) {
		primaryRegister = 'result';
	}

	const expression = registerExpressions[primaryRegister] ?? primaryRegister;
	const reportMarkdown = generateFormulaReport(primaryRegister, expression, steps, unsupported);

	return {
		targetRegister: primaryRegister,
		expression,
		instructionCount: instructions.length,
		supportedInstructionCount: steps.filter(step => step.updatedRegister !== undefined).length,
		unsupportedInstructions: unsupported,
		steps,
		registerExpressions,
		reportMarkdown
	};
}

function isPotentialMathInstruction(mnemonic: string): boolean {
	return [
		// x86/x64
		'mov', 'lea', 'imul', 'add', 'sub', 'xor',
		// ARM64/ARM32 equivalents
		'movz', 'movk', 'movn', 'mul', 'madd', 'msub', 'neg',
		'eor', 'orr', 'and', 'lsl', 'lsr', 'asr',
		// ARM32-specific
		'mla', 'mvn'
	].includes(mnemonic);
}

function splitOperands(opStr: string): string[] {
	const operands: string[] = [];
	let current = '';
	let bracketDepth = 0;

	for (const ch of opStr) {
		if (ch === '[') {
			bracketDepth++;
		} else if (ch === ']') {
			bracketDepth = Math.max(0, bracketDepth - 1);
		}

		if (ch === ',' && bracketDepth === 0) {
			const token = current.trim();
			if (token.length > 0) {
				operands.push(token);
			}
			current = '';
		} else {
			current += ch;
		}
	}

	const last = current.trim();
	if (last.length > 0) {
		operands.push(last);
	}

	return operands;
}

function normalizeRegister(value: string): string | undefined {
	const token = value
		.trim()
		.toLowerCase()
		.replace(/^(byte|word|dword|qword|xmmword)\s+ptr\s+/, '');
	// Reject ARM memory operands and immediates
	if (token.startsWith('[') || token.startsWith('#')) {
		return undefined;
	}
	return isRegisterToken(token) ? token : undefined;
}

function isRegisterToken(token: string): boolean {
	// x86/x64 registers
	if (/^(?:r(?:[a-d]x|[sb]p|[sd]i|ip)|e(?:[a-d]x|[sb]p|[sd]i|ip)|[abcd][hl]|[abcd]x|[sd]i|[sb]p|sil|dil|spl|bpl|r(?:[0-9]|1[0-5])(?:d|w|b)?|xmm[0-9]+|ymm[0-9]+)$/.test(token)) {
		return true;
	}
	// ARM64 registers: x0-x30, w0-w30, sp, lr, fp, xzr, wzr, pc
	if (/^(?:[xw](?:[0-9]|[12][0-9]|30)|sp|lr|fp|xzr|wzr|pc)$/.test(token)) {
		return true;
	}
	// ARM32 registers: r0-r15
	if (/^r(?:[0-9]|1[0-5])$/.test(token)) {
		return true;
	}
	return false;
}

function resolveOperandExpression(
	operand: string,
	state: Map<string, string>,
	allowLeaMemory: boolean
): string {
	const cleaned = stripPointerPrefix(operand.trim());
	const normalizedRegister = normalizeRegister(cleaned);
	if (normalizedRegister) {
		return state.get(normalizedRegister) ?? normalizedRegister;
	}

	const immediate = normalizeImmediate(cleaned);
	if (immediate) {
		return immediate;
	}

	const memMatch = cleaned.match(/^(?:[a-z]{1,3}:)?\[(.*)\]$/i);
	if (memMatch) {
		const inner = normalizeMathRegisters(memMatch[1], state);
		return allowLeaMemory ? `(${inner})` : `[${inner}]`;
	}

	return normalizeMathRegisters(cleaned, state);
}

function stripPointerPrefix(operand: string): string {
	return operand.replace(/^(byte|word|dword|qword|xmmword)\s+ptr\s+/i, '');
}

function normalizeImmediate(token: string): string | undefined {
	// Strip ARM immediate prefix (#)
	const cleaned = token.startsWith('#') ? token.slice(1) : token;
	if (/^-?(0x[0-9a-f]+)$/i.test(cleaned)) {
		const sign = cleaned.startsWith('-') ? '-' : '';
		const raw = cleaned.replace(/^-?0x/i, '');
		return `${sign}0x${raw.toUpperCase()}`;
	}
	if (/^-?[0-9a-f]+h$/i.test(cleaned)) {
		const sign = cleaned.startsWith('-') ? '-' : '';
		const raw = cleaned.replace(/^-?/, '').replace(/h$/i, '');
		return `${sign}0x${raw.toUpperCase()}`;
	}
	if (/^-?\d+$/.test(cleaned)) {
		return cleaned;
	}
	return undefined;
}

function normalizeMathRegisters(expression: string, state: Map<string, string>): string {
	const replaced = expression.replace(/\b([a-z][a-z0-9]+)\b/gi, (_, candidate: string) => {
		const reg = normalizeRegister(candidate);
		if (!reg) {
			return candidate;
		}
		return `(${state.get(reg) ?? reg})`;
	});
	return normalizeExpression(replaced);
}

function normalizeExpression(expression: string): string {
	return expression
		.replace(/\s+/g, ' ')
		.replace(/\s*([\+\-\*\/])\s*/g, ' $1 ')
		.replace(/\(\s+/g, '(')
		.replace(/\s+\)/g, ')')
		.trim();
}

function generateFormulaReport(
	targetRegister: string,
	expression: string,
	steps: FormulaStep[],
	unsupported: FormulaStep[]
): string {
	let markdown = `# HexCore Formula Extraction Report

## Result

- Target register: \`${targetRegister}\`
- Normalized expression: \`${expression}\`
- Processed instructions: \`${steps.length}\`
- Unsupported math instructions: \`${unsupported.length}\`

## Step Trace

| Address | Instruction | Update |
|---------|-------------|--------|
`;

	for (const step of steps) {
		const instruction = `${step.mnemonic} ${step.operands}`.trim();
		const update = step.updatedRegister && step.expression
			? `${step.updatedRegister} = ${step.expression}`
			: '-';
		markdown += `| ${step.address} | \`${escapeMarkdown(instruction)}\` | \`${escapeMarkdown(update)}\` |\n`;
	}

	if (unsupported.length > 0) {
		markdown += `
## Unsupported Math Instructions

| Address | Instruction |
|---------|-------------|
`;
		for (const step of unsupported) {
			const instruction = `${step.mnemonic} ${step.operands}`.trim();
			markdown += `| ${step.address} | \`${escapeMarkdown(instruction)}\` |\n`;
		}
	}

	return markdown;
}

function escapeMarkdown(value: string): string {
	return value.replace(/\|/g, '\\|').replace(/`/g, '\\`');
}

function toHexAddress(address: number): string {
	return `0x${address.toString(16).toUpperCase()}`;
}
