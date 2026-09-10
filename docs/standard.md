# Model-to-IDA interface standard, proposal v0.1

This proposal defines the boundary between an investigative model and its IDA
host. It does not prescribe one analysis route or certify the model's judgment.
The reference implementation is described in [architecture](architecture.md);
its tested scope and limitations are in [validation](validation.md).

## Responsibilities

| Participant | Responsibility |
| --- | --- |
| Investigating model | Inspect evidence, explain behavior, propose supported state, record uncertainty |
| Host | Bind identity, validate requests, apply and measure changes, preserve outcomes and unfinished work |
| IDA | Hold the current names, comments, interfaces, types, and relationships used in subsequent analysis |
| Reviewer | Challenge analytical claims and identify missing evidence, without directly changing the reviewed source |

The keywords **must** and **should** describe the proposed contract. They do not
mean that every listed capability is enabled in every reference-harness profile.

## 1. Discoverable evidence

The host must advertise supported queries and mutations, including required
fields, bounds, and errors. Results must identify their component and revision.
Paged queries must expose their continuation state; the model must not mistake a
bounded result for a complete inventory. The reference interface provides
counts, `has_more`, and revision-bound cursors for its pageable query families.

Function summaries, disassembly, pseudocode, callers/callees, cross-references,
types, and component metadata are distinct evidence surfaces. The host must not
present an inference or a historical citation as newly measured live evidence.
Not every query exposes every IDA capability; bounded read-only IDAPython is an
explicit escape route with a separate isolation contract.

## 2. Exact target and evidence identity

Each component must bind to an original input hash and a database identity.
An address alone is insufficient in a multi-component project. Locals and
relationships require native anchors sufficient to distinguish their intended
objects and, where necessary, their exact callsites.

The model receives opaque target references. The host creates operation and
revision identities rather than asking the model to invent bookkeeping IDs.
New edits must cite admitted evidence valid for the current revision. Stale or
mismatched references must be rejected with enough information to reacquire the
right evidence. This implementation conservatively expires evidence by whole
component revision; dependency-aware reuse is not implemented.

## 3. Requested state, observed state, accepted state

Every operation must retain its target, desired state, supporting evidence,
preconditions, and outcome. The host must distinguish:

1. the model's hypothesis or intention;
2. the operation submitted to IDA;
3. the state read back from IDA; and
4. the state accepted as durable in the project.

Canonical operations are defined in [the machine contracts](../schemas/verified_ida/README.md).
They cover function names/comments/prototypes, locals, globals, named types,
relationships, and a small number of trusted-worker-only operations. The model
tool vocabulary is intentionally narrower than the worker vocabulary.

The model-facing edit supplies `target_ref`, mutation `kind`, semantic `value`,
and evidence references. The host fills in the complete canonical operation.
JSON schemas are machine contracts, not a required model-authored campaign log.

## 4. Verification and recovery

Unverified candidate edits must not replace the canonical database. Verification
must report whether application and exact readback succeeded, and must retain
failures rather than converting them into success through retries.

The reference host applies one edit to an isolated candidate. It reads back
the requested surface through a separate path and checks relevant semantic
effects. Prototype, local-type, global-type, and named-type changes additionally
use a collateral semantic-state comparison. Other edit kinds do not receive
that same full collateral measurement.

Supported type dependencies may legitimately add IDA state. A verifier must
distinguish those effects from unrelated mutations, and must report unavailable
measurement as unavailable—not as an empty, therefore unchanged, result.

Accepted promotion must be recoverable across interruption. Packed-IDB
replacement and SQLite commit are separate atomic steps. The reference recovery
path reconciles their hashes and ledger state, rolls back uncommitted promotion,
and fails closed if it cannot establish which state is valid.

Fresh-process checkpoints must test that accepted state survives save/reopen.
A verified receipt is not an assertion of analytical truth. The receipt must
keep mechanical status and semantic review status separate.

## 5. Actionable feedback

A failure must identify its operation, stage, requested and observed state,
error, and bounded recovery direction. The model should be able to repair a
specific problem without reconstructing the entire investigation.

Post-edit feedback should also expose meaningful effects and scoped gaps: for
example, a renamed function without a durable explanation or native argument
names that remain generated. Native IDA provenance is preferred to spelling
heuristics. Heuristic and unknown evidence must not masquerade as native facts.

Required mechanical work and advisory discovery must be distinguishable.
Reading an inventory must not silently make every item a blocking obligation.

## 6. Three complementary records

| Record | Contains |
| --- | --- |
| IDBs | Current accepted reverse-engineering conclusions |
| `verified_ida.sqlite` | Inspections, targets, operations, revisions, receipts, checkpoints, findings and decisions |
| `reversing_log.md` | Current project state, hypotheses, uncertainty, next actions and analytical revisions |

The notebook must not replace the operation ledger. Transport failures and
receipt identities must not be embedded as analytical comments in the IDB.
The notebook's current-state sections can be revised; its investigation journal
preserves important changes chronologically.

Compaction must not erase these durable records. The runner must preserve valid
tool-call/result structure and distinguish known compaction boundaries from
ordinary messages. Current instructions, authoritative project state, and live
IDA evidence must remain recoverable after context reduction.

## 7. Components and deterministic investigation scope

Recovered executable children must retain byte identity, extraction provenance,
parent linkage, and independent database state. Switching component must not
redirect a stale operation into a different IDB. The notebook should preserve
the parent's context before the investigator follows the child.

A host should support explicit, enforceable investigation scopes for selected
claims. Once a scope is selected, its targets and completion requirements must
be visible and deterministic. Semantic judgment still determines what the code
means; the host enforces inspection, disposition, and required revalidation.

The experimental reference profile freezes at most eight reconciliation
findings, with at most twelve targets per finding. Selected statically decoded
direct calls can require bottom-up inspection and parent revalidation.
Supported terminal boundaries do not recursively expand merely because they
have further callees. Indirect calls, virtual dispatch, callbacks, tail calls,
and whole-program annotation are not enforced by this implementation.

## 8. Independent review and closure

Review collection must operate on disposable copies with before/after semantic
verification. A reviewer supplies evidence-linked, component-qualified findings,
not direct writes to the primary IDBs. Historical evidence may establish
provenance but must not be cited as current-stage inspection.

Application must retain original findings, exact targets, and dispositions.
The reference application resumes the saved investigation session in the review
candidate and processes one finding per execution unit. It can apply, reject,
revise, or explicitly defer a finding; editing is not mandatory if the finding
is wrong. Prior edits, decisions, notebooks and budgets survive resumption.

High-priority deferrals and unresolved mechanical failures can block completion.
Budget exhaustion must not certify success. A model's final report alone must
not establish that the artifact is complete. Newly discovered unrelated issues
must not indefinitely renew a fixed correction campaign's mandatory worklist.

The current host does not prove that the whole binary is understood. It reports
what was verified, what remains unresolved, and whether the selected completion
policy was satisfied. Human review remains necessary for consequential claims.
