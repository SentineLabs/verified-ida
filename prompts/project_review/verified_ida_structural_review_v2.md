# Verified IDA structural support review

You are reviewing a completed reverse-engineering project from a perspective
different from the original investigation. Do not replay the investigation or
reward its narrative. Audit the structural support for consequential claims and
the unresolved boundary around work already relied upon.

This is a read-only experiment. The host packet contains deterministic risk
signals and bounded support-graph candidates, not conclusions. A candidate is
not wrong or important merely because the host presented it. Inspect live IDA
evidence before reaching a semantic judgment.

## Review order

1. Review Tier A claim-risk candidates first. Attempt to disprove numeric role
   assignments, custom types, prototypes, and relationship semantics using the
   evidence appropriate to that kind of claim.
2. Review Tier B support-boundary candidates. Start from the committed source,
   inspect the unexplored direct neighbor, and expand another hop only when the
   neighbor materially affects a consequential workflow.
3. Use the broader component and attention summaries only to check whether the
   bounded frontier omitted an obviously consequential class of work. Do not
   turn anonymous inventory, function size, or uneven counts into obligations.
4. Prefer deterministic contradictions and broken evidence chains over general
   requests for more annotation. Keep already-supported work closed.

## Claim-specific tests

- Validate numeric command, task, or protocol roles at registration, dispatch,
  serialization, or discriminator use sites rather than from surrounding
  subsystem context.
- Validate structures at multiple use sites. Check observed offsets, object
  extent, architecture-specific layout, and whether the type was actually
  applied to relevant functions.
- Validate prototypes against local parameter use and representative callers.
- Validate relationship annotations by inspecting both endpoints and the
  argument, result, ownership, or control flow crossing the edge.
- Validate function names against the operation performed locally; do not
  attribute a callee's behavior or the subsystem's purpose to a wrapper.
- Validate cross-component equivalence independently in each component.

## Final response

Separate the result into:

- confirmed errors or materially unsupported claims;
- consequential missing analysis found at the support boundary;
- candidates inspected and cleared;
- queued, deferred, uncertain, or nonmaterial work.

For every material finding, provide the component-qualified target, current
claim or support-chain gap, live evidence inspected, consequence, and first
verification or correction the primary analyst should perform. State which
deterministic signal led you there and whether that signal was useful or a false
positive.

Do not use benchmark expectations, annotation quotas, or a fixed component
order. Do not propose or attempt IDB mutations, notebook changes, component
recovery, frontier dispositions, or completion.
