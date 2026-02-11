# HexCore Job Templates

This document provides safe default `.hexcore_job.json` templates for users and AI agents.

## Rules

- Keep `.hexcore_job.json` in the workspace root used by HexCore.
- Prefer absolute paths for `file` in multi-folder workspaces.
- Set `expectOutput: false` when you do not need step artifacts.
- Use explicit `output` only for reports you want to keep.

## Template: Constant Sanity Only (Lightweight)

```json
{
	"file": "C:\\path\\to\\target.exe",
	"outDir": "C:\\path\\to\\hexcore-reports\\constant-sanity",
	"quiet": true,
	"steps": [
		{
			"cmd": "hexcore.disasm.checkConstants",
			"args": {
				"notesFile": "C:\\path\\to\\ANALYST_NOTES.md",
				"maxFindings": 200
			},
			"output": {
				"path": "06-constant-sanity.md",
				"format": "md"
			},
			"timeoutMs": 300000
		}
	]
}
```

## Template: Lean Two-Step (No Large Intermediate Files)

```json
{
	"file": "C:\\path\\to\\target.exe",
	"outDir": "C:\\path\\to\\hexcore-reports\\lean-two-step",
	"quiet": true,
	"steps": [
		{
			"cmd": "hexcore.disasm.analyzeAll",
			"args": {
				"maxFunctions": 2500,
				"maxFunctionSize": 65536,
				"forceReload": true
			},
			"timeoutMs": 240000,
			"expectOutput": false
		},
		{
			"cmd": "hexcore.disasm.checkConstants",
			"args": {
				"notesFile": "C:\\path\\to\\ANALYST_NOTES.md",
				"maxFindings": 200
			},
			"output": {
				"path": "06-constant-sanity.md",
				"format": "md"
			},
			"timeoutMs": 300000
		}
	]
}
```

## Template: Full Static (Verbose)

```json
{
	"file": "C:\\path\\to\\target.exe",
	"outDir": "C:\\path\\to\\hexcore-reports\\full-static",
	"quiet": true,
	"steps": [
		{ "cmd": "hexcore.filetype.detect", "timeoutMs": 60000 },
		{ "cmd": "hexcore.hashcalc.calculate", "args": { "algorithms": "all" }, "timeoutMs": 90000 },
		{ "cmd": "hexcore.entropy.analyze", "timeoutMs": 90000 },
		{ "cmd": "hexcore.strings.extract", "args": { "minLength": 5, "maxStrings": 50000 }, "timeoutMs": 180000 },
		{ "cmd": "hexcore.disasm.analyzeAll", "args": { "maxFunctions": 3000, "maxFunctionSize": 65536, "forceReload": true }, "timeoutMs": 300000 },
		{ "cmd": "hexcore.disasm.checkConstants", "args": { "maxFindings": 200 }, "output": { "path": "06-constant-sanity.md", "format": "md" }, "timeoutMs": 300000 }
	]
}
```

## Troubleshooting

- `No .hexcore_job.json file was found.`:
	- Ensure the file exists in the workspace root currently opened in HexCore.
- `timed out after ...`:
	- Increase `timeoutMs` for heavy binaries.
	- Lower `maxFunctions` and `maxFunctionSize` on `analyzeAll`.
- Missing report file:
	- Confirm step status is `ok` in `hexcore-pipeline.status.json`.
	- If step failed/timed out, output file will not be created.

