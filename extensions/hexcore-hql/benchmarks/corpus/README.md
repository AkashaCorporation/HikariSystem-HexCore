# Semantic Benchmark Corpus

`semantic_benchmark.c` is a benign, source-known DLL corpus. Exported functions are never invoked by the benchmark; they exist to provide stable identities and positive/negative semantic shapes.

Acceptance requires manifest schema 2 to record the actual compiler, `vcvarsall`, and `dumpbin` paths and hashes; clean compiler banner and its hash; exact compiler/linker argument arrays; configuration hash; architecture; optimization/debug mode; command line; source/ground-truth hashes; binary/PDB hashes; and exported RVAs. Labels such as `clang` are rejected unless the compiler banner proves ClangCL.

An existing binary is reused only when its previous manifest proves the same configuration, toolchain, source, ground truth, and binary hashes. Otherwise the build fails and requires an explicit `-Force` rebuild. The exported function set must exactly equal the ground-truth universe.
