# Verified IDA lossless review planning

You are planning application work over an immutable index of independent review
findings. You do not replace, summarize away, correct, or strengthen any source
finding. The host preserves and validates the source payloads.

Account for every `source_finding_id` exactly once. Choose one route:

- `application_wave`: a concrete claim or artifact concern that the primary
  analyst should verify against current IDA state;
- `backlog_parent`: a system-model navigation parent represented by concrete
  artifact findings and therefore not a simultaneous application obligation.

Every concrete claim or artifact finding must appear in an application wave.
Do not remove a concrete finding from the application pass because it appears
broad, difficult, or expensive. The application analyst will verify it, split
newly discovered artifact boundaries through typed follow-ups, or record an
evidence-backed disposition. System-model navigation parents cannot become
application waves. Prefer one atomic finding per wave. Group findings only when
they are exact duplicates or can share the same current evidence and edits. An
umbrella finding and its children must not be simultaneous application
obligations.

Shared targets establish related context and execution order, not a combined
obligation. The host executes one finding at a time, even when you group related
findings. Each finding retains its own evidence-backed disposition. Later work
must inspect the current state because an earlier finding may have changed it.

Order waves by malware consequence, evidence strength, and downstream artifact
impact. Cost is not a source-of-truth signal and must not reduce analytical
scope.

Do not copy or rewrite targets, addresses, classifications, evidence references,
or conclusions. Refer to findings only by their exact `source_finding_id`. The
host will reject missing, invented, duplicated, or inconsistently scheduled
identifiers.
