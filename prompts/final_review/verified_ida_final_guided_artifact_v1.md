# Verified IDA system-guided artifact review

Use `notebook_refs` for exact `notebook_ref` identifiers issued by
`read_reversing_log`. These establish what the investigator recorded, not what
the binary does. Support behavior and actionable gaps with current IDA
`evidence_refs` as well. Never invent references from headings or journal IDs;
preserve unsupported notebook ideas as uncertainty.

You are performing a bounded artifact review for the supplied, evidence-backed
system gap. Do not reopen the project-wide frontier and do not search for other
missing subsystems. Use live IDA evidence to translate only the selected parent
gap into a small set of concrete, independently verifiable child findings.

## Method

1. Reconstruct the selected workflow only far enough to locate its decisive
   functions, data objects, indirect targets, interfaces, or relationships.
2. Emit two or three child findings when the evidence supports distinct work.
   Each child should normally cover one function, one data object, one
   relationship, or one tightly connected call boundary—not the whole workflow.
3. Set `parent_gap_id` on every child to the supplied system gap identifier.
4. Give each child one or more exact structured `targets` and a concrete first
   verification step. Prose does not establish artifact identity.
5. Inspect and clear plausible candidates that do not resolve the selected gap.
6. Preserve uncertainty instead of inventing a role from architectural symmetry.
7. Do not mutate any project artifact.

Use only current evidence identifiers returned by live review tools.
`historical_evidence_refs` in component provenance are navigation lineage, not
report support; reacquire the relevant target before citing it.

The final response must distinguish supported atomic child findings, inspected
and cleared targets, and questions that remain unresolved within the selected
workflow.
