"""Fixed review identity and append-only application recovery; no IDA writes."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from .contracts import canonical_json, VERIFIED_STATUSES
from .final_review import (FinalReviewError, application_review_targets,
                           operation_review_target, review_target_identity,
                           review_identity_authorized)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def write_state(path: Path, value: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def application_configuration(stage_dir: Path, *, model: str,
                              reasoning_effort: str, resume: bool) -> dict[str, Any]:
    """Persist configuration before work, independently of a terminal summary.

    Older interrupted applications can be recovered only from agreeing saved
    application summaries. This never infers a new operation or usage baseline.
    """
    path = stage_dir / "configuration.json"
    baseline_path = stage_dir / "baseline.json"
    if not baseline_path.is_file():
        raise FinalReviewError("Saved application baseline is missing")
    identity = {"model": model, "reasoning_effort": reasoning_effort,
                "baseline_sha256": digest(json.loads(baseline_path.read_text()))}
    if path.exists():
        saved = json.loads(path.read_text())
        if any(saved.get(key) != value for key, value in identity.items()):
            raise FinalReviewError("Resume must retain the reviewed model configuration and baseline")
        return saved
    evidence = []
    if resume:
        paths = [stage_dir / "summary.json", *sorted(
            (stage_dir / "attempts").glob("*/waves/*/summary.json"))]
        for source in paths:
            if not source.is_file():
                continue
            row = json.loads(source.read_text())
            if (row.get("model") != model
                    or row.get("reasoning_effort") != reasoning_effort):
                raise FinalReviewError("Saved application configuration evidence disagrees")
            evidence.append({"path": str(source.relative_to(stage_dir)),
                             "sha256": digest(row)})
        if not evidence:
            raise FinalReviewError("No saved application configuration evidence; cannot safely resume")
    saved = {"schema": "verified_ida.review_application_configuration.v1",
             **identity, "recovered_from": evidence}
    write_state(path, saved)
    return saved


def focused_application_waves(waves: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Keep order and every source finding; overlap does not increase a unit."""
    result = []
    seen = set()
    wave_ids = set()
    for wave in waves:
        members = list(wave["source_finding_ids"])
        if not members:
            raise FinalReviewError("Empty application wave")
        for index, finding_id in enumerate(members, 1):
            if finding_id in seen:
                raise FinalReviewError("Repeated application finding: %s" % finding_id)
            seen.add(finding_id)
            wave_id = str(wave["wave_id"])
            if len(members) > 1:
                wave_id += "-finding-%02d" % index
            if wave_id in wave_ids:
                raise FinalReviewError("Duplicate focused wave ID: %s" % wave_id)
            wave_ids.add(wave_id)
            result.append({**dict(wave), "wave_id": wave_id,
                           "source_finding_ids": [finding_id],
                           "source_wave_id": wave.get("source_wave_id", wave["wave_id"])})
    return result


def application_baseline(path: Path, *, runtime: Any, review_index: Mapping[str, Any],
                         plan: Mapping[str, Any], resume: bool) -> dict[str, Any]:
    """Bind eligibility to the ORIGINAL operation prefix, never the resume time."""
    history = runtime.journal.operations_after(0)
    identity = {"review_index_sha256": digest(review_index), "plan_sha256": digest(plan)}
    if path.exists():
        if not resume:
            raise FinalReviewError("Application baseline already exists")
        baseline = json.loads(path.read_text(encoding="utf-8"))
        if any(baseline.get(key) != value for key, value in identity.items()):
            raise FinalReviewError("Frozen review index or execution plan changed")
    else:
        if resume:
            raise FinalReviewError("Saved application baseline is missing; cannot infer prior operation history")
        original = history
        baseline = {"schema": "verified_ida.review_application_baseline.v1", **identity,
                    "operations": [{"operation_id": row["operation_id"],
                                    "operation_digest": row["operation_digest"]}
                                   for row in original],
                    "operation_cutoff": len(original)}
    prefix = [{"operation_id": row["operation_id"], "operation_digest": row["operation_digest"]}
              for row in history[:len(baseline["operations"])]]
    if prefix != baseline["operations"]:
        raise FinalReviewError("Application history does not extend its immutable source baseline")
    expected_cutoff = int(history[len(prefix) - 1]["operation_rowid"]) if prefix else 0
    if path.exists() and baseline["operation_cutoff"] != expected_cutoff:
        raise FinalReviewError("Application baseline operation cutoff changed")
    baseline["operation_cutoff"] = expected_cutoff
    if not path.exists():
        write_state(path, baseline)
    return baseline


def application_feedback(ledger: Any, finding_ids: Iterable[str]) -> dict[str, Any]:
    ids = list(finding_ids)
    targets = {review_target_identity(target) for key in ids
               for target in application_review_targets(ledger.findings[key], ledger.runtime)}
    claimed = {str(op) for row in ledger.dispositions.values() for op in row.get("operation_ids", [])}
    operations = [{"operation_id": row["operation_id"], "kind": row["kind"],
                   "component_id": row["component_id"], "target_key": row["target_key"],
                   "already_accounted": row["operation_id"] in claimed}
                  for row in ledger.runtime.journal.current_operations()
                  if row["operation_id"] not in ledger.prior_operation_ids
                  and review_identity_authorized(operation_review_target(row), targets)
                  and dict(row.get("receipt") or {}).get("status") in VERIFIED_STATUSES]
    return {"schema": "verified_ida.application_finding_state.v1",
            "finding_ids": ids,
            "open_finding_ids": [key for key in ids if key not in ledger.dispositions],
            "saved_review_operations": operations,
            "required_next_step": (
                "Verify this finding against current IDA state, then record its disposition. "
                "Reuse relevant saved review operation IDs; do not repeat a correct edit. "
                "An edit is not proof of semantic resolution. Once dispositioned, update "
                "Current Project State and append the journal result before returning."
            )}


def restore_application_ledger(stage_dir: Path, *, runtime: Any, model: str, reasoning_effort: str) -> Any:
    """Validate frozen review identity and original history before finalization."""
    from .final_review import ReviewDispositionLedger
    plan = json.loads((stage_dir / "execution_plan.json").read_text())
    index = json.loads((stage_dir.parent / "consolidation/review_index.json").read_text())
    baseline = application_baseline(stage_dir / "baseline.json", runtime=runtime,
                                    review_index=index, plan=plan, resume=True)
    application_configuration(stage_dir, model=model, reasoning_effort=reasoning_effort, resume=True)
    source_rows = {row["source_finding_id"]: row for row in index["source_findings"]}
    originals = [{"finding_id": key, "source_finding": source_rows[key]}
                 for wave in plan["waves"] for key in wave["source_finding_ids"]]
    return ReviewDispositionLedger.resume(path=stage_dir / "dispositions.json", runtime=runtime,
        findings=originals, prior_operation_ids={row["operation_id"] for row in baseline["operations"]},
        allow_legacy=bool(baseline.get("legacy_import")))
