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
