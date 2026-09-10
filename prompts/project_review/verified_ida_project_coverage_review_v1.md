# Verified IDA project-scale semantic coverage review

You are reviewing a completed reverse-engineering project. Your task is to
look for consequential analytical work that the existing investigation may
have missed, not to reward or restate its current narrative.

This is a read-only semantic review. Inspect the live IDAs and operational
evidence, but do not propose or attempt IDB mutations, notebook updates,
component recovery, frontier dispositions, or mechanical completion. The
existing notebook and annotations are evidence, not authoritative answers.

## Review method

1. Compare the program's component graph, relative component sizes, and the
   attention the investigation gave each component. Equal attention is not a
   goal; explain whether the allocation matches each component's role.
2. Challenge the current system-level explanation. For each consequential
   behavior it relies upon, determine whether the owning or controlling
   component, implementation functions, interfaces or shared types, and
   important relationships are represented durably in IDA.
3. Examine the bounded advisory candidates and use live IDA queries to look for
   high-signal unresolved work outside the notebook's existing references:
   entrypoints and exports, component boundaries, dispatchers, vtables,
   import/string clusters, and structurally central functions. Counts and
   anonymity alone are not evidence that work is important.
4. Consider whether a deep investigation of one component or subsystem
   displaced consequential work in its parent, siblings, or other active
   workstreams.
5. Do not recommend a workstream solely from inventory statistics. Inspect
   representative live code or relationships and cite the component-qualified
   addresses that support each recommendation.
6. Distinguish missing analysis from intentionally deferred libraries,
   compiler/runtime substrate, duplication, and uncertainty that cannot be
   resolved statically.

## Final response

State whether material analytical work remains. If it does, inventory and
prioritize the consequential workstreams, explain their relative importance,
and identify the highest-value next action. Keep the active set concise, but
preserve additional work as queued, deferred, uncertain, or nonmaterial rather
than discarding it.

For every recommended workstream, include:

- the affected component and workflow;
- the live evidence inspected;
- what is missing or potentially incorrect in the current IDB;
- why resolving it would materially improve understanding of the program; and
- the first concrete inspection that should be performed.

Also identify current claims that appear sufficiently supported and should not
be reopened. Do not use benchmark expectations, annotation quotas, or a fixed
component order.
