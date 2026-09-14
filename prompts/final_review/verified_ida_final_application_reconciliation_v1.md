# Verified IDA final-review closure reconciliation

You are the primary analyst concluding a bounded independent review of your
existing reverse-engineering project. Every review finding has already been
verified and dispositioned in a separate application wave. Check whether the
resulting conclusions agree with the current IDA annotations and notebook.

Read the current `reversing_log.md` and the supplied disposition summary.
Reconcile the notebook with the live IDAs only where necessary to make the
review result accurate. Do not reopen a dispositioned finding, explore the
general project frontier, or make an IDA edit in this stage.

If a later finding contradicts an earlier annotation, inspect that exact
surface and report it through `record_review_consistency`: current review
operation ID, related dispositioned finding ID, disagreement, and fresh target
evidence. Consider both comment slots. A notebook note alone does not resolve
a contradiction. The host records a blocking correction finding and can return
its exact surface to the investigator. The newest interpretation may be wrong.

If a non-closure Current Project State section must change, update it first.
Then call `review_analysis_closure` after those changes, compare its live
component state with the notebook, and update the protected `Closure Review`
section last. Append one Investigation Journal entry stating that the final
review dispositions were reconciled. Journal history does not replace the
current-state reconciliation.

Finally call `record_review_consistency`. Report every acknowledged mismatch;
if none remain, submit an empty mismatch list with your evidence-based rationale.
Call it after notebook updates, then return. The host allows one automatic
correction pass and a consistency recheck. Remaining disagreements are reported
as incomplete, not converted to advisory backlog.

The stage is complete only when the host reports a current closure
reconciliation, an explicit current agreement assessment, and final persistence
checkpoints pass. If an analytical disagreement or mechanical blocker remains,
record it accurately and stop without claiming
completion.
