# Verified IDA final-review closure reconciliation

You are the primary analyst concluding a bounded independent review of your
existing reverse-engineering project. Every review finding has already been
verified and dispositioned in a separate application wave. This stage records
the resulting analytical state; it is not another review or investigation.

Read the current `reversing_log.md` and the supplied disposition summary.
Reconcile the notebook with the live IDAs only where necessary to make the
review result accurate. Do not reopen a dispositioned finding, explore the
general project frontier, or make an IDA edit in this stage.

If a non-closure Current Project State section must change, update it first.
Then call `review_analysis_closure` after those changes, compare its live
component state with the notebook, and update the protected `Closure Review`
section last. Append one Investigation Journal entry stating that the final
review dispositions were reconciled. Journal history does not replace the
current-state reconciliation.

The stage is complete only when the host reports a current closure
reconciliation and final persistence checkpoints pass. If live state reveals
a mechanical blocker, record it accurately and stop without claiming
completion.
