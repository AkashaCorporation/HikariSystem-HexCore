# HQL Atlas Core Fixtures

`v1/manifest.json` is the canonical inventory for the first-party HQL rule
library. Case IDs are persistent: a semantic change creates a new case instead
of silently reusing an old ID.

Each case stores:

- the active signature and stable branch ID;
- one compact, deterministically hydrated C-AST;
- the expected match outcome and exact fixture locations;
- SHA-256 of the canonical compact AST.

Canonical JSON recursively sorts object keys, preserves array order, emits no
insignificant whitespace, and hashes the UTF-8 bytes. The manifest also pins
the canonical hash of every fixture file.

Every rule has at least one positive and two negatives. Every branch of a
top-level `any` condition independently carries the same gate. The runner checks
both the isolated branch and the complete signature so one branch cannot hide a
regression in another.

Run the gate from `extensions/hexcore-hql`:

```powershell
npx tsx test/atlasFixtures.ts
```
