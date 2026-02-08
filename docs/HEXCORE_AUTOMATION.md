# HexCore Automation Job

HexCore now supports running analysis pipelines from a workspace job file named `.hexcore_job.json`.

## How It Works

- If `.hexcore_job.json` exists in the workspace, HexCore watches it and runs it automatically on create/change.
- You can also run manually with command: `Run HexCore Automation Job` (`hexcore.pipeline.runJob`).
- Job execution writes:
	- `hexcore-pipeline.log`
	- `hexcore-pipeline.status.json`
- Both files are written to the job `outDir`.

## Example Job

```json
{
	"file": "C:\\bin\\sample.exe",
	"outDir": "C:\\reports\\sample",
	"steps": [
		{ "cmd": "hexcore.filetype.detect" },
		{ "cmd": "hexcore.peanalyzer.analyze" },
		{ "cmd": "hexcore.hash.file" },
		{ "cmd": "hexcore.entropy.analyze" },
		{ "cmd": "hexcore.strings.extract", "args": { "minLength": 5 } },
		{ "cmd": "hexcore.disasm.analyzeAll" }
	]
}
```

## Step Notes

- `hexcore.hash.file` is supported as an alias and resolves to `hexcore.hashcalc.calculate`.
- `hexcore.hash.calculate` is supported as an alias and resolves to `hexcore.hashcalc.calculate`.
- `hexcore.pe.analyze` is supported as an alias and resolves to `hexcore.peanalyzer.analyze`.
- `hexcore.disasm.open` is supported as an alias and resolves to `hexcore.disasm.openFile`.
- `hexcore.peanalyzer.analyze` now supports headless execution with `file`, `quiet`, and `output`.
- Every step runs in headless mode (`quiet: true`) and receives `file`.
- If a step does not define output, HexCore auto-generates output files inside `outDir`.
- Commands marked as interactive are blocked in pipeline mode with a clear error.
- Before each step, the runner verifies command registration in Extension Host and attempts to activate the owner extension when needed.
- If command activation fails, `hexcore-pipeline.status.json` now includes owner-extension diagnostics (active/missing/activation-failed).
- To override output file/format per step:

```json
{
	"cmd": "hexcore.filetype.detect",
	"output": {
		"path": "01-filetype.md",
		"format": "md"
	}
}
```

Relative output paths are resolved from `outDir`.

## Step Controls

Each step supports optional controls:

```json
{
	"cmd": "hexcore.filetype.detect",
	"timeoutMs": 30000,
	"expectOutput": true,
	"continueOnError": false
}
```

- `timeoutMs`: override per-step timeout.
- `expectOutput`: force output existence validation on/off.
- `continueOnError`: continue remaining steps after a failure.
