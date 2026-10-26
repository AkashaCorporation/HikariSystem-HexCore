# Function Atlas Regressions

`x86-width-and-unary-regression.ll` pins the x86 Remill IR that exposed two
independent failures: 32/64-bit register-width drift in the Helix pipeline and
synthetic adapter loss for valid unary compound assignments. Its companion
JSON binds the exact engines, IR, expected HAST contract, and accepted
224-function benchmark artifact.

Minimal positive regression:

```powershell
$env:HEXCORE_HELIX_HAST_NODE='C:\path\to\pinned\hexcore-helix.node'
node .\reproduce.js
```

`adapter-losses.resolved.json` is the terminal negative-control record. The
accepted 16-binary run contains zero adapter-loss failures; a future loss must
make the main benchmark fail before a baseline can be published.

The frozen producer is described by `../producer-manifest.json`. Resolution is
content-addressed: use `HEXCORE_HELIX_HAST_NODE`, the local development wrapper,
or `HEXCORE_PRODUCER_CACHE`. Missing bytes report
`HOLD-MISSING-FROZEN-PRODUCER`; hash drift is never accepted.

The current producer passes this focused regression and the complete HQL test
suite. The 16-binary/224-function migration remains `HOLD-QUALITY`: 102
functions are semantically eligible and 122 are withheld by explicit native
quality barriers. Do not replace the previous canonical similarity artifact or
weaken `semanticEligible` merely to make that corpus green.
