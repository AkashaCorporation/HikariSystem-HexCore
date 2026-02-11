# HexCore Automation Job

HexCore now supports running analysis pipelines from a workspace job file named `.hexcore_job.json`.

## How It Works

- If `.hexcore_job.json` exists in the workspace, HexCore watches it and runs it automatically on create/change.
- You can also run manually with command: `Run HexCore Automation Job` (`hexcore.pipeline.runJob`).
- Generate `.hexcore_job.json` from built-in/workspace profiles: `Create HexCore Job from Preset` (`hexcore.pipeline.createPresetJob`).
- Save current `.hexcore_job.json` as reusable workspace profile: `Save Current Job as Workspace Profile` (`hexcore.pipeline.saveJobAsProfile`).
- Validate job contract without executing steps: `Validate HexCore Automation Job` (`hexcore.pipeline.validateJob`).
- Validate all workspace jobs in one pass: `Validate HexCore Jobs in Workspace` (`hexcore.pipeline.validateWorkspace`).
- Diagnose command registration/capability health: `Run HexCore Pipeline Doctor` (`hexcore.pipeline.doctor`).
- Job execution writes:
	- `hexcore-pipeline.log`
	- `hexcore-pipeline.status.json`
- Both files are written to the job `outDir`.
- `.hexcore_job.json` now has JSON Schema validation in editor via `hexcore-disassembler/schemas/hexcore-job.schema.json`.

## 3.2.2 Hotfix Notes

- Fixed pipeline capability gap for `hexcore.yara.scan`.
- Added pipeline-safe support for `hexcore.pipeline.listCapabilities`.
- Runner now handles command capability checks more explicitly, including interactive command blocking.
- Extension activation reliability was improved for packaged builds to reduce `Command '...' not found`.

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
		{ "cmd": "hexcore.disasm.analyzeAll" },
		{ "cmd": "hexcore.yara.scan" }
	]
}
```

## Step Notes

- `hexcore.hash.file` is supported as an alias and resolves to `hexcore.hashcalc.calculate`.
- `hexcore.hash.calculate` is supported as an alias and resolves to `hexcore.hashcalc.calculate`.
- `hexcore.pe.analyze` is supported as an alias and resolves to `hexcore.peanalyzer.analyze`.
- `hexcore.disasm.open` is supported as an alias and resolves to `hexcore.disasm.openFile`.
- `hexcore.peanalyzer.analyze` now supports headless execution with `file`, `quiet`, and `output`.
- `hexcore.yara.scan` now supports headless execution with `file`, `quiet`, and `output`.
- `hexcore.pipeline.listCapabilities` can run in pipeline mode and export capability JSON.
- `hexcore.pipeline.validateJob` returns a preflight report with declared/headless/registration checks per step.
- `hexcore.pipeline.validateWorkspace` aggregates validation for every `.hexcore_job.json` found in the current workspace.
- `hexcore.pipeline.createPresetJob` builds deterministic job templates for:
	- quick triage
	- full static
	- ctf reverse
- `hexcore.pipeline.saveJobAsProfile` stores custom profiles in workspace file `.hexcore_profiles.json`.
- `hexcore.pipeline.doctor` returns environment diagnostics (registered commands, owner extension state, undeclared `hexcore.*` commands).
- `hexcore.disasm.buildFormula` supports headless extraction of arithmetic expressions from instruction ranges (`startAddress`/`endAddress` or explicit `addresses`).
- Every step runs in headless mode (`quiet: true`) and receives `file`.
- If a step does not define output, HexCore auto-generates output files inside `outDir`.
- Commands marked as interactive are blocked in pipeline mode with a clear error.
- `outputPath` is now only reported for steps that actually request/provide output, avoiding false "OK + missing file" status noise.
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
	"retryCount": 2,
	"retryDelayMs": 1500,
	"expectOutput": true,
	"continueOnError": false
}
```

- `timeoutMs`: override per-step timeout.
- `retryCount`: number of retries after an initial failure (default `0`).
- `retryDelayMs`: delay between retry attempts in milliseconds (default `1000`).
- `expectOutput`: force output existence validation on/off.
- `continueOnError`: continue remaining steps after a failure.

For `hexcore.disasm.analyzeAll`, you can pass safe limits through `args`:

```json
{
	"cmd": "hexcore.disasm.analyzeAll",
	"args": {
		"maxFunctions": 2500,
		"maxFunctionSize": 65536,
		"forceReload": true
	}
}
```

- `maxFunctions`: max number of discovered functions for the run.
- `maxFunctionSize`: max bytes per function analysis.
- `forceReload`: force reloading target binary before analysis (recommended for deterministic headless runs).

For `hexcore.disasm.buildFormula`, pass range or explicit addresses:

```json
{
	"cmd": "hexcore.disasm.buildFormula",
	"args": {
		"startAddress": "0x401020",
		"endAddress": "0x40103F",
		"targetRegister": "eax"
	},
	"output": {
		"path": "formula-main-check.json"
	}
}
```

## Troubleshooting

- `Command '...' not found`:
	- Confirm you are on HexCore release with hotfix `3.2.2+`.
	- Run `hexcore.pipeline.listCapabilities` and confirm the command appears.
	- Reload window after update to refresh extension activation.

- `Command is not declared in pipeline capability map`:
	- Use the exact command name from capabilities export.
	- For YARA pipeline step, use `hexcore.yara.scan`.

- `Command is not headless-safe for pipeline`:
	- This is expected for interactive commands (file pickers/prompts/UI-only actions).
	- Replace with a headless command variant in `.hexcore_job.json`.
