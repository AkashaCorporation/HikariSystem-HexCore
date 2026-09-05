# HQL Atlas v1

## Purpose

HQL Atlas is a versioned semantic knowledge base for HexCore. It separates four concerns that must not be conflated:

1. the rule expression;
2. the evidence claim;
3. fixture and corpus performance;
4. the derived search index.

Reviewable files in Git are canonical. SQLite is a disposable index/cache rebuilt deterministically from those files.

## Canonical record

Each released rule must carry:

- stable ID, semantic version, namespace, status, author, license, and provenance;
- HQL, Helix, and HAST compatibility ranges;
- supported architectures, formats, and static/dynamic scope;
- recursive condition tree and referenced library rules;
- evidence level independent from presentation severity;
- positive and negative fixture hashes with expected match locations;
- limitations, known false positives, and retired/superseded lineage;
- corpus version, precision, recall, runtime, and calibration metadata where available;
- source, transform, sink, barrier, and sanitizer roles where applicable.

Recommended namespaces are `capability`, `security-boundary`, `dataflow`, `anti-analysis`, `memory-safety`, `crypto`, `compiler-runtime`, `library`, and `nursery`.

## Release gates

A rule cannot leave `nursery` unless:

- recursive schema validation passes;
- every alternative branch has at least one positive and two negative fixtures;
- fixture inputs and expected locations are content-addressed;
- the active signature-set SHA-256 is reproducible;
- unsupported HAST nodes and adapter coverage are recorded;
- broad structural matches remain `signal` or `candidate`;
- a `confidence` value is omitted until a named, hashed corpus calibrates it.

Rules claiming `proven` additionally require the semantic property they name. Co-occurrence, reachability, a nearby string, or a matching API name is not same-object dataflow, dominance, ordering, or absence of a barrier.

## Derived SQLite index

The database may index rules, versions, namespaces, compatibility, fixture hashes, benchmark runs, false-positive notes, and supersession edges. A build manifest must include:

- canonical source tree hash;
- builder version;
- schema version;
- deterministic row counts and table hashes.

Deleting the database and rebuilding it from a clean checkout must produce the same logical contents. Runtime edits to SQLite never become canonical rule changes.

## Benchmark lanes

The first rule-engine comparison is Mandiant capa and its public rule corpus:

- https://github.com/mandiant/capa
- https://github.com/mandiant/capa-rules

The comparison measures expressiveness, linting, fixtures, scope, precision/recall, runtime, and evidence rendering. It does not copy external rules blindly; licenses and provenance remain explicit.

Function similarity is a separate future Function Atlas lane inspired by Ghidra BSim:

- https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GhidraClass/BSim/README.md

FLOSS is an evidence producer for decoded strings tied to binary, function, address, extractor version, and source hash:

- https://github.com/mandiant/flare-floss

A decoded string remains a fact. Promotion to behavior or vulnerability requires independent semantic evidence.
