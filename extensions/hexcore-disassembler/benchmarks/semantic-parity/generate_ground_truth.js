"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const crypto = __importStar(require("crypto"));
const path = __importStar(require("path"));
const pdbProvider_1 = require("../../src/pdbProvider");
const manifestPath = path.resolve(process.argv[2] ?? '');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8').replace(/^\uFEFF/, ''));
const source = fs.readFileSync(manifest.sourcePath, 'utf8');
const functions = [...source.matchAll(/^\/\/ HXGT (\{.+\})$/gm)].map(match => JSON.parse(match[1]));
const sourceRecords = [...source.matchAll(/^\/\/ HXGT_RECORD (\{.+\})$/gm)].map(match => JSON.parse(match[1]));
const configurations = [];
for (const entry of manifest.entries) {
    const expectedFunctions = Object.fromEntries(functions.map(item => [item.function, {
            ...item,
            expectedCallingConvention: entry.architecture === 'x64' ? item.x64Convention ?? 'win64' : item.x86Convention ?? 'cdecl',
            export: entry.exports.find((candidate) => candidate.name === item.function),
        }]));
    let pdb = null;
    if (entry.pdbPath) {
        pdb = (0, pdbProvider_1.loadPdbProvider)({ pdbPath: entry.pdbPath, imageBase: 0x180000000 });
        if (pdb.status === 'error' || !pdb.identityValidated)
            throw new Error(`${entry.id}: PDB provider failed`);
        for (const [name, expected] of Object.entries(expectedFunctions)) {
            const symbol = pdb.functions.find((fn) => fn.name === name);
            if (!symbol)
                throw new Error(`${entry.id}: PDB missing ${name}`);
            expected.pdb = { address: symbol.address, size: symbol.size, prototype: symbol.prototype, locals: symbol.locals };
        }
    }
    configurations.push({ id: entry.id, binarySha256: entry.binarySha256, pdbSha256: entry.pdbSha256, functions: expectedFunctions, pdbIdentity: pdb?.identity ?? null, pdbContentHash: pdb?.contentHash ?? null,
        records: pdb ? Object.fromEntries(sourceRecords.map(record => [record.name, pdb.debugTypes.structs[record.name] ?? null])) : null });
}
const logical = { schemaVersion: 1, corpusId: manifest.corpusId, sourceSha256: manifest.sourceSha256, sourceAnnotationsSha256: crypto.createHash('sha256').update(JSON.stringify({ functions, sourceRecords })).digest('hex'), configurations };
const output = { ...logical, contentHash: crypto.createHash('sha256').update(JSON.stringify(logical)).digest('hex') };
fs.writeFileSync(path.join(path.dirname(manifestPath), 'ground-truth.json'), JSON.stringify(output, null, 2) + '\n');
console.log(`Ground truth: ${configurations.length} configurations, ${functions.length} functions, ${sourceRecords.length} records, ${output.contentHash}`);
//# sourceMappingURL=generate_ground_truth.js.map