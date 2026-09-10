# Validation and known limits

This page distinguishes tests of the interface from evaluation of a model's
malware analysis. Neither a successful tool call nor a passing test suite proves
that every analytical conclusion is correct.

## Evidence carried into this candidate

The preceding developer candidate passed 435 portable checks on Python 3.12
locally and Python 3.10 on Linux, including installation from its source ZIP.
A live FlawedGrace review resume processed nine findings, reused 22 saved edits,
and added seven verified edits. Native repeat-resume checks preserved the IDBs,
operation history, notebook, decisions and budget without new model requests.

Those experiments retain their original code revisions. They are not a new
clean-baseline investigation on every packaging change. ComRAT and FlawedGrace
experiments support the interface's behavior; they do not establish broad model
accuracy or universal completion.

The full regression suite, live probes and research records are maintained
outside this public candidate. The public tree retains the `conformance` CLI
and [a harmless runnable example](../examples/verified-edit/README.md). The CLI
checks mutation/readback/persistence; it is not one command certifying every
security, compaction, component and review boundary.

## Candidate-specific checks

The 0.2.0a11 exported runtime passed these checks:

| Check | Result |
| --- | --- |
| Private regression checks bound to public production imports | 430 passed, zero failed, on local Python 3.12 and Linux Python 3.10 |
| Full private preparation suite, including developer packaging checks | 440 passed, zero failed |
| Public source inventory | 105 files; matched the curated source map and archive manifest; no broken local Markdown links |
| Harmless public example on IDA Pro 9.3 | Rename, missing-comment feedback, corrective comment and persistence passed; clean input unchanged |
| Standalone safe annotation export on IDA Pro 9.3 | Passed on the harmless fixture and a saved malware child IDB; source bytes and measured semantic state unchanged |
| Repeat resume of a settled nine-finding review | IDBs, operations, notebook, decisions and recorded usage unchanged; zero new model requests |

The ten checks omitted from the public-import run inspect developer-only test
layout and packaging. They passed in the private preparation suite; they were
not silently counted as public-runtime passes. Private fixtures and test code
remain outside the distributed tree. The public runnable example uses only
distributed source plus the documented external tools.

The export-helper repair supplies its missing semantic-snapshot entrypoint,
checks worker availability before launch, and rejects output paths that alias
the source or each other. Native testing also caught IDAPython treating
`SystemExit(0)` as a script error; the worker now returns normally. These changes
were tested together, not only against a mocked executor.

The settled review correctly remained analytically incomplete because external
runtime-delivered modules were unavailable. Passing the repeat-resume check
means preserving that honest outcome without duplicate work, not certifying the
malware analysis as complete.

No primary malware investigation or API access is needed to verify the small
export-worker fix. Model instructions, investigation/review policy, and the SDK
configuration are unchanged by the public export.

## Limits readers should know

- Mechanical verification establishes the recorded target state, not the truth
  of a malware interpretation. Independent review is also fallible.
- Mandatory caller-state comparison can be unavailable when Hex-Rays cannot
  decompile a caller. A proposed type may then remain unverified even if it
  parses. The host discards the candidate rather than claiming success.
- Evidence expires by component revision. Harmless annotation changes can
  require reinspection; automatic dependency-aware evidence reuse is not present.
- A high-priority question requiring an absent runtime-delivered module can
  leave analytical status incomplete. The host does not yet separately certify
  that all analysis possible from the supplied artifacts has been exhausted.
- Optional reconciliation and selected direct-call enforcement are experimental,
  finite-scope capabilities, not exhaustive call-graph coverage.
- The supported runner is pinned to Agents SDK 0.20.0. There is no tested promise
  that any provider, model, future SDK, or other disassembler can be swapped in
  without adapter work and conformance checks.
- Full static-extractor isolation requires Linux facilities listed in the
  README. A Python syntax validator alone is not a sandbox.
- The runtime and ledger remain large modules. This release curates the public
  surface without a late refactor of tested transaction or review behavior.
- Native persistence validation is specific to the supported IDA/Hex-Rays setup.
  Another installation needs its own disposable live checks.

Do not present a deferred question, rejected operation, or budget stop as a
completed finding. Keep the ledger and notebook alongside the IDBs when asking
another analyst to inspect the work.
