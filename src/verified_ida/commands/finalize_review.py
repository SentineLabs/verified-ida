#!/usr/bin/env python3
"""Retry closure finalization for an already-applied final-review run."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from verified_ida.commands.analyze import _session, _session_identity
from verified_ida.commands.review import (
    _run_application_reconciliation,
    _session_message_count,
    _write_json,
)
from verified_ida.final_review import FinalReviewError, project_component_hashes, review_completion_blockers
from verified_ida.runtime import VerifiedIdaRuntime
from verified_ida.review_budget import add_review_budget_arguments, run_budgeted_review
from verified_ida.safety_budget import SafetyBudgetExceeded


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--stage-name", default="reconciliation-retry-01")
    parser.add_argument(
        "--model", default=os.environ.get("ANALYSIS_MODEL", "gpt-5.6-sol")
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh"],
        default="xhigh",
    )
    parser.add_argument("--runaway-max-turns", type=int, default=48)
    add_review_budget_arguments(parser)
    arguments = parser.parse_args(argv)
    if not arguments.stage_name.replace("-", "").replace("_", "").isalnum():
        parser.error("--stage-name must contain only letters, digits, '-' or '_'")
    if arguments.runaway_max_turns < 8:
        parser.error("--runaway-max-turns must be at least 8")
    return arguments


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FinalReviewError("Finalization input is missing: %s" % path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalReviewError("Finalization input must be an object: %s" % path)
    return value


def _source_is_unchanged(project: Path) -> tuple[bool, str]:
    manifest = _load_json(project / "final_review_clone_manifest.json")
    source = Path(str(manifest["source_project"])).expanduser().resolve()
    expected = {
        "%s:%s" % (row["component_id"], row["kind"]): row["sha256"]
        for row in manifest.get("source_component_files") or []
    }
    return project_component_hashes(source) == expected, str(source)


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(list(sys.argv[1:] if argv is None else argv))
    result = run_budgeted_review(arguments, _run, resume=True)
    # An already-exhausted allowance stops before _run is entered. Record that
    # retry as well, without replacing the original campaign's budget/history.
    stop_path = arguments.run_dir.expanduser().resolve() / "review_budget_stop.json"
    if result == 2 and stop_path.is_file():
        stop = _load_json(stop_path)
        _publish_summary(arguments, {
            "schema": "verified_ida.final_review_finalization_retry.v1",
            "status": "stopped_budget", "phase": "finalization",
            "completion": {"may_finish": False}, "budget_stop": stop,
        })
    return result


def _run(arguments: argparse.Namespace) -> int:
    """Always publish a terminal retry result; preserve earlier run history."""
    run_dir = arguments.run_dir.expanduser().resolve()
    lifecycle: dict[str, Any] = {"cleanup_errors": []}
    try:
        summary = _finalize(arguments, lifecycle)
    except Exception as exc:
        cause: BaseException | None = exc
        while cause is not None and not isinstance(cause, SafetyBudgetExceeded):
            cause = cause.__cause__ or cause.__context__
        summary = {
            "schema": "verified_ida.final_review_finalization_retry.v1",
            "status": "stopped_budget" if isinstance(cause, SafetyBudgetExceeded) else "failed",
            "phase": "finalization", "run_dir": str(run_dir),
            "completion": {"may_finish": False},
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "cleanup_errors": lifecycle["cleanup_errors"],
        }
        try:
            _publish_summary(arguments, summary)
        except Exception as reporting_error:
            print("Finalization reporting also failed: %s" % reporting_error, file=sys.stderr)
        raise
    _publish_summary(arguments, summary)
    print(json.dumps(summary, indent=2, sort_keys=True, default=str))
    return 0 if summary["status"] == "completed" else 2


def _publish_summary(arguments: argparse.Namespace, summary: dict[str, Any]) -> None:
    run_dir = arguments.run_dir.expanduser().resolve()
    summary["stage_name"] = arguments.stage_name
    stage_path = run_dir / (arguments.stage_name + "-summary.json")
    if not stage_path.exists():
        _write_json(stage_path, summary)
    _write_json(run_dir / "finalization_summary.json", summary)
    path = run_dir / "summary.json"
    if path.exists():
        current = _load_json(path)
        current.setdefault("pre_finalization_status", current.get("status"))
        current.update(status=summary["status"], phase="finalization",
                       completion=summary["completion"], finalization=summary)
        _write_json(path, current)


def _finalize(arguments: argparse.Namespace, lifecycle: dict[str, Any]) -> dict[str, Any]:
    run_dir = arguments.run_dir.expanduser().resolve()
    project = run_dir / "project"
    disposition_path = run_dir / "review" / "application" / "dispositions.json"
    dispositions = _load_json(disposition_path)
    if dispositions.get("open_finding_ids"):
        raise FinalReviewError(
            "Cannot finalize while review findings remain open: %s"
            % ", ".join(dispositions["open_finding_ids"])
        )
    rows = list(dispositions.get("dispositions") or [])
    application_dir = disposition_path.parent
    plan_path = application_dir / "execution_plan.json"
    if not plan_path.exists():
        # Older runs recorded the effective plan in the collection directory.
        planning = run_dir / "review" / "consolidation" / "planning"
        experimental = planning / "experimental_validated_plan.json"
        plan_path = experimental if experimental.exists() else planning / "validated_plan.json"
    plan = _load_json(plan_path)
    ledger = SimpleNamespace(
        dispositions={str(row["finding_id"]): dict(row) for row in rows}
    )
    finding_rows = dispositions.get("findings")
    if finding_rows is None:
        finding_rows = [row.get("finding") or {} for row in rows]
    findings = {str(row["finding_id"]): row for row in finding_rows}
    scheduled = {str(fid) for wave in plan["waves"] for fid in wave["source_finding_ids"]}
    scheduled.update(str(row["follow_up"]["finding_id"]) for row in rows if row.get("follow_up"))
    if (len(ledger.dispositions) != len(rows) or len(findings) != len(finding_rows)
            or set(findings) != scheduled or dispositions.get("finding_count") != len(findings)
            or dispositions.get("disposition_count") != len(rows)):
        raise FinalReviewError("Persisted findings, dispositions, and application plan disagree")
    if any(row.get("finding") != findings[row["finding_id"]] for row in rows):
        raise FinalReviewError("Persisted disposition differs from its registered finding")
    blockers = review_completion_blockers(findings, ledger.dispositions, plan)
    if blockers:
        raise FinalReviewError("Cannot finalize while analytical blockers remain: %s" % ", ".join(blockers))
    stage_dir = run_dir / "review" / "application" / arguments.stage_name
    source_unchanged_before, source_project = _source_is_unchanged(project)
    if not source_unchanged_before:
        raise FinalReviewError("The canonical source project changed before retry")

    from agents import set_tracing_disabled  # type: ignore

    set_tracing_disabled(True)
    runtime = VerifiedIdaRuntime.initialize(
        project,
        analysis_feedback_profile="scoped",
    )
    primary_error: Exception | None = None
    try:
        mechanical_before = runtime.journal.mechanical_issues()
        if mechanical_before:
            raise FinalReviewError(
                "Resolve current mechanical failures before closure finalization: %s"
                % ", ".join(
                    str(row["operation_id"]) for row in mechanical_before
                )
            )
        identity = _session_identity(project)
        session_id = str(identity["session_id"])
        session_state = {
            "schema": "verified_ida.final_review_session_continuity.v1",
            "session_id": session_id,
            "identity_source": str(identity["source"]),
            "session_database": str((project / "model_session.sqlite").resolve()),
            "initial_message_count": _session_message_count(project, session_id),
            "resumed_original_investigation": True,
            "finalization_retry": True,
        }
        reconciliation = _run_application_reconciliation(
            runtime=runtime,
            stage_dir=stage_dir,
            ledger=ledger,
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
            application_session=_session(project),
            session_state=session_state,
            runaway_max_turns=arguments.runaway_max_turns,
        )
        source_unchanged_after, _source_project = _source_is_unchanged(project)
        completion = runtime.completion_status()
        completed = (
            reconciliation.get("status") == "completed"
            and bool(completion.get("may_finish"))
            and source_unchanged_after
        )
        summary = {
            "schema": "verified_ida.final_review_finalization_retry.v1",
            "status": "completed" if completed else "incomplete",
            "run_dir": str(run_dir),
            "project_dir": str(project),
            "source_project": source_project,
            "source_project_unchanged": source_unchanged_after,
            "disposition_count": len(rows),
            "open_finding_count": len(
                list(dispositions.get("open_finding_ids") or [])
            ),
            "mechanical_failure_count": len(
                runtime.journal.mechanical_issues()
            ),
            "reconciliation": reconciliation,
            "project_completion": completion,
            "completion": {**completion, "may_finish": completed},
        }
        return summary
    except Exception as exc:
        primary_error = exc
        raise
    finally:
        try:
            runtime.close()
        except Exception as exc:
            lifecycle["cleanup_errors"].append({
                "type": type(exc).__name__, "message": str(exc),
            })
            if primary_error is None:
                raise


if __name__ == "__main__":
    raise SystemExit(main())
