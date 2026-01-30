/*---------------------------------------------------------------------------------------------
 *  HexCore YARA Engine
 *  YARA rule matching engine
 *  Copyright (c) HikariSystem. All rights reserved.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'fs';
import * as path from 'path';

export interface RuleMatch {
	ruleName: string;
	namespace: string;
	meta: Record<string, string>;
	strings: Array<{ identifier: string; offset: number; data: string }>;
}

// Built-in YARA rules for common packers/malware
const BUILTIN_RULES = `
rule UPX_Packed {
    meta:
        description = "Detects UPX packed files"
        author = "HexCore"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
        $upx2 = "UPX!"
    condition:
        any of them
}

rule VMProtect {
    meta:
        description = "Detects VMProtect packed files"
    strings:
        $vmp0 = ".vmp0"
        $vmp1 = ".vmp1"
    condition:
        any of them
}

rule Themida {
    meta:
        description = "Detects Themida packed files"
    strings:
        $themida = ".themida"
    condition:
        any of them
}

rule Suspicious_API {
    meta:
        description = "Detects suspicious API calls"
    strings:
        $api1 = "VirtualAlloc"
        $api2 = "WriteProcessMemory"
        $api3 = "CreateRemoteThread"
        $api4 = "InternetOpen"
        $api5 = "URLDownloadToFile"
    condition:
        any of them
}

rule Base64_Executable {
    meta:
        description = "Detects base64 encoded executables"
    strings:
        $mz_b64 = "TVqQAAMAAAAEAAAA"
        $mz_b64_url = "TVqQAAMAAAAEAAAA" base64
    condition:
        any of them
}

rule Shellcode_Pattern {
    meta:
        description = "Detects common shellcode patterns"
    strings:
        $sc1 = { 31 c0 50 68 2f 2f 73 68 68 2f 62 69 6e 89 e3 50 53 89 e1 99 b0 0b cd 80 }
        $sc2 = { 31 c0 50 68 63 61 6c 63 54 5b 50 53 b8 }
    condition:
        any of them
}

rule PE_Reverse_Shell {
    meta:
        description = "Potential reverse shell indicator"
    strings:
        $cmd1 = "cmd.exe /c"
        $cmd2 = "powershell -e"
        $cmd3 = "bash -i >& /dev/tcp/"
    condition:
        any of them
}
`;

export class YaraEngine {
	private rules: Array<{ name: string; source: string; compiled?: any }> = [];

	constructor() {
		// Load built-in rules
		this.loadRuleString('builtins', BUILTIN_RULES);
	}

	loadRuleString(namespace: string, source: string): void {
		this.rules.push({ name: namespace, source });
	}

	loadRulesFromDirectory(dirPath: string): void {
		if (!fs.existsSync(dirPath)) return;
		
		const files = fs.readdirSync(dirPath);
		for (const file of files) {
			if (file.endsWith('.yar') || file.endsWith('.yara')) {
				const content = fs.readFileSync(path.join(dirPath, file), 'utf-8');
				this.loadRuleString(file, content);
			}
		}
	}

	async scanFile(filePath: string): Promise<RuleMatch[]> {
		const content = fs.readFileSync(filePath);
		const matches: RuleMatch[] = [];

		// Simple pattern matching (in production, use actual YARA library)
		for (const rule of this.rules) {
			const ruleMatches = this.matchRule(rule, content);
			matches.push(...ruleMatches);
		}

		return matches;
	}

	async scanDirectory(dirPath: string): Promise<Array<{ file: string; matches: RuleMatch[] }>> {
		const results: Array<{ file: string; matches: RuleMatch[] }> = [];
		
		const scanDir = async (dir: string) => {
			const entries = fs.readdirSync(dir, { withFileTypes: true });
			for (const entry of entries) {
				const fullPath = path.join(dir, entry.name);
				if (entry.isDirectory()) {
					await scanDir(fullPath);
				} else if (entry.isFile()) {
					const matches = await this.scanFile(fullPath);
					if (matches.length > 0) {
						results.push({ file: fullPath, matches });
					}
				}
			}
		};
		
		await scanDir(dirPath);
		return results;
	}

	async updateRules(): Promise<void> {
		// In production, would download from threat intelligence feeds
		// For now, just reload built-ins
		this.rules = this.rules.filter(r => r.name !== 'builtins');
		this.loadRuleString('builtins', BUILTIN_RULES);
	}

	createRuleFromString(name: string, content: string): string {
		const hexBytes = Buffer.from(content).toString('hex').match(/.{1,2}/g)?.join(' ') || '';
		
		return `rule ${name} {
    meta:
        description = "Auto-generated rule"
        author = "HexCore"
        date = "${new Date().toISOString().split('T')[0]}"
    strings:
        $s1 = "${content.replace(/"/g, '\\"')}"
        $h1 = { ${hexBytes} }
    condition:
        any of them
}`;
	}

	private matchRule(rule: { name: string; source: string }, content: Buffer): RuleMatch[] {
		const matches: RuleMatch[] = [];
		
		// Parse and match simple string patterns from the rule
		const stringMatches = this.extractStrings(rule.source);
		const matchedStrings: Array<{ identifier: string; offset: number; data: string }> = [];
		
		for (const [id, pattern] of stringMatches) {
			const cleanPattern = pattern.replace(/^"|"$/g, '').replace(/\\"/g, '"');
			let offset = content.indexOf(Buffer.from(cleanPattern));
			
			// Try hex pattern
			if (offset === -1 && pattern.includes('{')) {
				const hexMatch = pattern.match(/\{([^}]+)\}/);
				if (hexMatch) {
					const hexBytes = hexMatch[1].replace(/\s/g, '');
					const bytes = Buffer.from(hexBytes, 'hex');
					offset = content.indexOf(bytes);
				}
			}
			
			if (offset !== -1) {
				matchedStrings.push({
					identifier: id,
					offset,
					data: cleanPattern.substring(0, 50)
				});
			}
		}

		if (matchedStrings.length > 0) {
			// Extract rule names
			const ruleNames = rule.source.match(/rule\s+(\w+)/g) || [];
			for (const ruleName of ruleNames) {
				const name = ruleName.replace('rule', '').trim();
				matches.push({
					ruleName: name,
					namespace: rule.name,
					meta: { description: 'Matched by HexCore YARA' },
					strings: matchedStrings
				});
			}
		}

		return matches;
	}

	private extractStrings(source: string): Array<[string, string]> {
		const strings: Array<[string, string]> = [];
		const lines = source.split('\n');
		
		for (const line of lines) {
			const match = line.match(/\$(\w+)\s*=\s*(.+)/);
			if (match) {
				strings.push([match[1], match[2].trim()]);
			}
		}
		
		return strings;
	}
}
