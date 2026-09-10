#!/usr/bin/env python3
"""Replay one existing final-review application wave on a fresh project clone."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from verified_ida.commands.review import (  # noqa: E402
    _component_revisions,
    _run_application_waves,
    _write_json,
)
from verified_ida.contracts import canonical_json  # noqa: E402
from verified_ida.final_review import (  # noqa: E402
    FinalReviewError,
    clone_verified_project,
    project_component_hashes,
)
from verified_ida.runtime import VerifiedIdaRuntime  # noqa: E402
from verified_ida.source_provenance import describe_source  # noqa: E402
from verified_ida.review_budget import add_review_budget_arguments, run_budgeted_review


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-project-dir", type=Path, required=True)
    parser.add_argument("--source-review-dir", type=Path, required=True)
    parser.add_argument("--source-finding-id", required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument(
        "--model", default=os.environ.get("ANALYSIS_MODEL", "gpt-5.6-sol")
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh"],
        default="xhigh",
    )
    parser.add_argument("--application-runaway-max-turns", type=int, default=128)
    parser.add_argument(
        "--application-no-progress-max-responses", type=int, default=80
    )
    add_review_budget_arguments(parser)
    arguments = parser.parse_args(argv)
    if arguments.application_runaway_max_turns < 16:
        parser.error("--application-runaway-max-turns must be at least 16")
    if arguments.application_no_progress_max_responses < 4:
        parser.error(
            "--application-no-progress-max-responses must be at least 4"
        )
    return arguments


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FinalReviewError("Replay input is missing: %s" % path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise FinalReviewError("Replay input must be a JSON object: %s" % path)
    return value


def _digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _select_wave(
    *,
    review_index: Mapping[str, Any],
    plan: Mapping[str, Any],
    source_finding_id: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    findings = {
        str(row.get("source_finding_id")): dict(row)
        for row in review_index.get("source_findings") or []
    }
    if source_finding_id not in findings:
        raise FinalReviewError(
            "Source finding is absent from the review index: %s"
            % source_finding_id
        )
    waves = [
        dict(wave)
        for wave in plan.get("waves") or []
        if source_finding_id in {
            str(value) for value in wave.get("source_finding_ids") or []
        }
    ]
    if len(waves) != 1:
        raise FinalReviewError(
            "Expected exactly one application wave for %s; found %d"
            % (source_finding_id, len(waves))
        )
    wave = waves[0]
    if [str(value) for value in wave.get("source_finding_ids") or []] != [
        source_finding_id
    ]:
        raise FinalReviewError(
            "Focused replay requires a one-finding atomic source wave"
        )
    replay_plan = {
        "schema": "verified_ida.final_review_wave_replay_plan.v1",
        "assessment": "Focused replay of one unchanged application wave.",
        "source_finding_count": 1,
        "accounted_source_finding_count": 1,
        "application_wave_count": 1,
        "dispositions": [
            dict(row)
            for row in plan.get("dispositions") or []
            if str(row.get("source_finding_id")) == source_finding_id
        ],
        "waves": [wave],
    }
    replay_plan["planning_digest"] = _digest(replay_plan)
    return findings[source_finding_id], replay_plan


def main(argv: list[str] | None = None) -> int:
    arguments = _parse_args(list(argv or sys.argv[1:]))
    return run_budgeted_review(arguments, _run)


def _run(arguments: argparse.Namespace) -> int:
    source_provenance = describe_source(ida_backend="process")
    source_project = arguments.source_project_dir.expanduser().resolve()
    source_review = arguments.source_review_dir.expanduser().resolve()
    run_dir = arguments.run_dir.expanduser().resolve()

    review_index_path = source_review / "consolidation" / "review_index.json"
    plan_path = (
        source_review / "consolidation" / "planning" /
        "experimental_validated_plan.json"
    )
    review_index = _load_json(review_index_path)
    source_plan = _load_json(plan_path)
    finding, replay_plan = _select_wave(
        review_index=review_index,
        plan=source_plan,
        source_finding_id=arguments.source_finding_id,
    )

    source_hashes_before = project_component_hashes(source_project)
    project_dir = run_dir / "project"
    output_dir = run_dir / "review"
    output_dir.mkdir()
    clone_manifest = clone_verified_project(
        source_project,
        project_dir,
        reference_source_binaries=True,
    )
    _write_json(output_dir / "source_finding.json", finding)
    _write_json(output_dir / "replay_plan.json", replay_plan)
    replay_manifest = {
        "schema": "verified_ida.final_review_wave_replay.v1",
        "source_project": str(source_project),
        "source_review": str(source_review),
        "source_review_index": str(review_index_path),
        "source_review_index_sha256": _digest(review_index),
        "source_plan": str(plan_path),
        "source_plan_sha256": _digest(source_plan),
        "source_finding_id": arguments.source_finding_id,
        "source_finding_sha256": _digest(finding),
        "replay_plan_sha256": _digest(replay_plan),
        "model": arguments.model,
        "reasoning_effort": arguments.reasoning_effort,
        "source": source_provenance,
        "application_runaway_max_turns": (
            arguments.application_runaway_max_turns
        ),
        "application_no_progress_max_responses": (
            arguments.application_no_progress_max_responses
        ),
        "fresh_agent_session": True,
        "prior_failed_trace_supplied": False,
        "clone_manifest": clone_manifest,
    }
    _write_json(run_dir / "replay_manifest.json", replay_manifest)

    from agents import set_tracing_disabled  # type: ignore

    set_tracing_disabled(True)
    runtime = VerifiedIdaRuntime.initialize(
        project_dir,
        analysis_feedback_profile="scoped",
    )
    try:
        before = {
            "component_revisions": _component_revisions(runtime),
            "operation_ids": [
                str(row["operation_id"])
                for row in runtime.journal.current_operations()
            ],
        }
        application = _run_application_waves(
            runtime=runtime,
            output_dir=output_dir,
            review_index=review_index,
            plan=replay_plan,
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
            runaway_max_turns=arguments.application_runaway_max_turns,
            no_progress_max_responses=(
                arguments.application_no_progress_max_responses
            ),
        )
        source_hashes_now = project_component_hashes(source_project)
        summary = {
            "schema": "verified_ida.final_review_wave_replay_summary.v1",
            "status": application["status"],
            "source_finding_id": arguments.source_finding_id,
            "source": source_provenance,
            "canonical_source_unchanged": (
                source_hashes_now == source_hashes_before
            ),
            "component_revisions_before": before["component_revisions"],
            "component_revisions_after": _component_revisions(runtime),
            "application": application,
        }
        _write_json(run_dir / "summary.json", summary)
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
        return 0 if summary["status"] == "completed" else 2
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
