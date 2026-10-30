# HexCore Agent Bridge v1

The Agent Bridge is a local, workspace-scoped transport over the existing
HexCore automation queue. It does not create another scheduler and it does not
execute arbitrary VS Code commands. HexCore must already be open with the same
workspace.

## Architecture

```text
hexcore-agent CLI
  -> authenticated JSONL over a Windows named pipe
  -> AgentBridgeServer in the Disassembler extension
  -> existing JobQueueManager / AutomationPipelineRunner
```

One bridge is started for each open workspace folder. Discovery is written to:

```text
%TEMP%\hexcore-agent\<workspace-sha256>\bridge.json
```

The discovery document contains a random 256-bit token and the per-instance
pipe name. The token is never logged or returned by a bridge method. Discovery
is removed on normal disposal when it still belongs to that instance. After an
abrupt Extension Host exit, the CLI detects the dead PID, removes only that
stale instance document, and reports `bridge-stale`.

The bridge resolves the job file, analysis target, and output directory against
the authenticated workspace. Lexical and physical paths are checked, including
existing symlink/junction targets. A bridge request cannot use a workspace job
as a proxy to read or write outside that workspace.

## CLI

From a development checkout:

```powershell
.\scripts\hexcore-agent.cmd help
.\scripts\hexcore-agent.cmd validate .hexcore_job.json --workspace C:\research\case
.\scripts\hexcore-agent.cmd doctor --summary --workspace C:\research\case
.\scripts\hexcore-agent.cmd submit .hexcore_job.json --workspace C:\research\case --wait
```

From an extracted Windows package:

```powershell
.\bin\hexcore-agent.cmd help
.\bin\hexcore-agent.cmd schema --workspace C:\research\case
.\bin\hexcore-agent.cmd submit .hexcore_job.json --workspace C:\research\case --wait
```

The packaged wrapper uses `HexCore.exe` with `ELECTRON_RUN_AS_NODE`; a separate
Node.js installation is not required. The extension also declares
`hexcore-agent` as its Node CLI entry point.
The workspace must be trusted in HexCore before the bridge is available. This is
an intentional security boundary because automation can execute commands from a
workspace job. The CLI never accepts the trust prompt, weakens Restricted Mode,
or launches a hidden automation host. After trust is granted, the existing
`onStartupFinished` activation creates discovery automatically.
All non-streaming commands emit one JSON value. `events` emits JSONL: one
subscription response followed by lifecycle events.

| Command | Contract |
|---------|----------|
| `validate <job>` | Applies containment and the live runner preflight without enqueueing or creating report artifacts. |
| `submit <job>` | Validates and submits through `queueJobIfAbsent`; returns revision and dedup state. |
| `status <jobId>` | Returns bounded queue and pipeline state without exposing the queue's raw result object. |
| `wait <jobId>` | Observes the existing job; timeout does not cancel it. |
| `events <jobId>` | Streams submitted/deduped, running, and terminal events with monotonic sequence numbers. |
| `cancel <jobId>` | Requests cancellation; a running job becomes terminal only after its executor/native child settles. |
| `capabilities` | Returns protocol method schemas, the job schema, pipeline capabilities, and limits. |
| `schema` | Returns only the live `.hexcore_job.json` schema and protocol version. |
| `doctor` | Runs the installed pipeline doctor in the live Extension Host. |

Common options:

```text
--workspace PATH
--timeout-ms N
--priority high|normal|low
--session ID
--since-sequence N
--summary
```

CLI exit code `1` means transport/protocol failure. Exit code `2` means the
observed job ended failed/cancelled or the pipeline status is `error`. A
pipeline `partial` result remains a successful transport response and stays
explicit in JSON. `validate` uses exit code `3` for a syntactically delivered
but invalid job contract. `--summary` bounds `doctor`/`capabilities` output for
agent context.

## Edit, Validate, Run

Jobs intended for explicit agent/user submission should declare:

```json
{
  "autoRun": false,
  "file": ".\\target.exe",
  "outDir": ".\\hexcore-reports\\case",
  "steps": [
    { "id": "analyze", "cmd": "hexcore.disasm.analyzeAll" }
  ]
}
```

`autoRun:false` disables startup and file-watcher execution only. Manual Run Job
and Agent Bridge `submit` remain available. This lets an agent edit repeatedly,
run `validate`, inspect the SHA-256 revision, and submit only the accepted bytes.

Watcher and bridge use the same SHA-256 content identity. An active identical
revision deduplicates to one queue job rather than being interpreted as two
different revisions.

## Evidence Contract

Terminal observation writes one record per execution under:

```text
<outDir>\.hexcore-meta\agent-results\<executionId>.json
```

The record preserves:

- queue status, revision, execution ID, target SHA-256, format, and provenance;
- `ok`, `partial`, `error`, and `skipped` step status without promotion;
- bounded JSON result previews, including explicit `UNKNOWN` values;
- redaction of token/password/secret/cookie/API-key fields;
- artifact-provenance hashes and side-artifact hashes when supplied by the
  pipeline;
- one canonical SHA-256 per step and one canonical SHA-256 for the full record;
- explicit truncation counters and hash-authority status.

The record is capped at 2 MiB. JSON previews are read only from output files no
larger than 64 KiB. Large or non-JSON outputs are referenced by path, size, and
their existing provenance hash rather than copied into the bridge response.

## Protocol

Each client sends one newline-delimited request:

```json
{"protocolVersion":1,"requestId":"uuid","token":"workspace-secret","method":"status","params":{"jobId":"uuid"}}
```

Responses and events are versioned envelopes. Requests are capped at 1 MiB and
response/event lines at 4 MiB. Authentication is compared with a timing-safe
token check.

## V1 Boundaries

- Windows named pipes are the supported product transport. The implementation
  has a Unix-domain-socket fallback for tests, not a Linux product promise.
- Event replay is bounded to the most recent 512 events in the current bridge
  process and is not persisted across an Extension Host reload.
- V1 streams queue lifecycle transitions. Fine-grained live step-start/progress
  events remain P2; per-step terminal evidence is already persisted.
- The CLI does not launch HexCore, bypass job validation, expand analysis
  budgets, or expose an arbitrary command RPC.
- Remote transport, shared tokens, and unattended service mode are out of scope.
