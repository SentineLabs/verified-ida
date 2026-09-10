#!/usr/bin/env python3
"""Run isolated final review, verified application, and post-application audit."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from pydantic import BaseModel


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from verified_ida.commands.analyze import (  # noqa: E402
    ToolInvocationState,
    _function_tools,
    _observable_hooks,
    _session,
    _session_identity,
    _usage_dict,
)
from verified_ida.commands.project_review import (  # noqa: E402
    READ_ONLY_REVIEW_TOOLS,
    _environment,
    _segment_id,
    build_final_review_packets,
)
from verified_ida.adapter import VerifiedIdaToolAdapter  # noqa: E402
from verified_ida.model_context import model_run_config  # noqa: E402
from verified_ida.audit import (  # noqa: E402
    ObservableTrace,
    aggregate_usage,
    event_counts,
    write_walkthrough,
)
from verified_ida.contracts import VERIFIED_STATUSES, canonical_json  # noqa: E402
from verified_ida.final_review import (  # noqa: E402
    FinalReviewError,
    ReviewDispositionLedger,
    review_completion_blockers,
    build_lossless_review_index,
    clone_verified_project,
    finding_review_targets,
    bind_application_finding_targets,
    load_current_recorded_closure,
    operation_review_target,
    project_component_hashes,
    review_target_identity,
    semantic_project_snapshot,
    verify_semantic_stage_boundary,
)
from verified_ida.runtime import VerifiedIdaRuntime  # noqa: E402
from verified_ida.review_application_state import (
    application_baseline, application_feedback, focused_application_waves,
)
from verified_ida.source_provenance import describe_source  # noqa: E402
from verified_ida.review_budget import (
    ACTIVE_REVIEW_BUDGET, add_review_budget_arguments, run_budgeted_review,
)
from verified_ida.review_contracts import (  # noqa: E402
    PlanningReport,
    RelationshipReviewTarget as RelationshipReviewTarget,
    ReviewFinding,
    StageReviewReport,
    SystemModelReport,
)


PROMPTS = {
    "claim": ROOT / "prompts" / "final_review" / "verified_ida_final_claim_lane_v1.md",
    "system_model": ROOT / "prompts" / "final_review" / "verified_ida_final_system_model_v1.md",
    "artifact_coverage": ROOT / "prompts" / "final_review" / "verified_ida_final_artifact_coverage_v1.md",
    "guided_artifact": ROOT / "prompts" / "final_review" / "verified_ida_final_guided_artifact_v1.md",
    "planning": ROOT / "prompts" / "final_review" / "verified_ida_final_planning_v2.md",
    "application": ROOT / "prompts" / "final_review" / "verified_ida_final_application_v1.md",
    "application_reconciliation": (
        ROOT
        / "prompts"
        / "final_review"
        / "verified_ida_final_application_reconciliation_v1.md"
    ),
}

CLAIM_LANES = (
    "local_identity",
    "interface_type",
    "relationship",
    "changed_stale",
)

FINAL_REVIEW_READ_ONLY_TOOLS = set(READ_ONLY_REVIEW_TOOLS) - {
    # The final-state packet already contains a current closure snapshot. This
    # same-agent workflow also records a new closure epoch and repeatedly opens
    # child IDBs, so it is neither independent nor cheap in final review.
    "review_analysis_closure",
}

APPLICATION_TOOLS = {
    "read_reversing_log",
    "update_reversing_log_section",
    "append_reversing_log_journal",
    "describe_ida_capabilities",
    "query_ida_functions",
    "query_ida_symbols",
    "query_ida_strings",
    "query_ida_types",
    "inspect_ida_function",
    "read_ida_function_code",
    "inspect_ida",
    "inspect_ida_local",
    "describe_idapython_capabilities",
    "run_idapython_readonly",
    "inspect_ida_relationship",
    "inspect_ida_operation",
    "switch_ida_component",
    "edit_ida",
    "abandon_ida_operation",
    "read_ida_call_flow_scope",
    "disposition_ida_call_flow_node",
    "revalidate_ida_function_claim",
}

APPLICATION_RECONCILIATION_TOOLS = {
    "read_reversing_log",
    "update_reversing_log_section",
    "append_reversing_log_journal",
    "describe_ida_capabilities",
    "query_ida_functions",
    "query_ida_symbols",
    "query_ida_strings",
    "query_ida_types",
    "inspect_ida_function",
    "read_ida_function_code",
    "inspect_ida",
    "inspect_ida_local",
    "inspect_ida_relationship",
    "inspect_ida_operation",
    "switch_ida_component",
    "review_analysis_closure",
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-project-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--resume-application", action="store_true",
                        help="Resume saved application and finalization; do not repeat collection.")
    parser.add_argument("--import-legacy-baseline", action="store_true",
                        help="Explicitly verify/import a pre-resume-contract baseline from the frozen source project.")
    parser.add_argument(
        "--model", default=os.environ.get("ANALYSIS_MODEL", "gpt-5.6-sol")
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh"],
        default="xhigh",
    )
    parser.add_argument("--claim-lane-max-turns", type=int, default=14)
    parser.add_argument("--system-model-max-turns", type=int, default=24)
    parser.add_argument("--artifact-coverage-max-turns", type=int, default=50)
    parser.add_argument(
        "--citation-repair-max-turns",
        type=int,
        default=16,
        help=(
            "One tool-enabled read-only pass for replacing invalid review "
            "citations with current evidence. This is a runaway ceiling for "
            "the repair pass, not a one-query limit."
        ),
    )
    parser.add_argument(
        "--system-guided-artifact",
        action="store_true",
        help="Review only selected system-model gaps and omit broad artifact inventory.",
    )
    parser.add_argument(
        "--guided-system-gap-limit",
        type=int,
        default=1,
        help="Maximum supported system gaps passed to system-guided artifact review.",
    )
    parser.add_argument(
        "--guided-gap-id",
        action="append",
        default=[],
        help=(
            "Exact system-model gap identifier to review. Repeat to select "
            "multiple gaps. Without this option, structured priority and gap "
            "identifier determine selection."
        ),
    )
    parser.add_argument(
        "--questionable-control-file",
        type=Path,
        help="Host-only JSON control whose finding is added after semantic collection.",
    )
    parser.add_argument(
        "--experimental-guided-application",
        action="store_true",
        help="Schedule the questionable control and guided artifact children as closed waves.",
    )
    parser.add_argument(
        "--collection-only",
        action="store_true",
        help="Stop after lossless consolidation and planning without mutating the project.",
    )
    parser.add_argument(
        "--application-runaway-max-turns",
        type=int,
        default=128,
        help="Emergency per-wave request ceiling; ledger state defines completion.",
    )
    parser.add_argument(
        "--application-no-progress-max-responses",
        type=int,
        default=40,
        help="Stop a wave after this many responses without a verified edit or disposition.",
    )
    parser.add_argument("--prepare-only", action="store_true")
    add_review_budget_arguments(parser)
    arguments = parser.parse_args(argv)
    for name in (
        "claim_lane_max_turns",
        "system_model_max_turns",
        "artifact_coverage_max_turns",
    ):
        if getattr(arguments, name) < 2:
            parser.error("--%s must be at least 2" % name.replace("_", "-"))
    if arguments.import_legacy_baseline and not arguments.resume_application:
        parser.error("--import-legacy-baseline requires --resume-application")
    if arguments.resume_application and (arguments.collection_only or arguments.prepare_only):
        parser.error("Application resumption cannot also request collection/preparation only")
    if arguments.citation_repair_max_turns < 4:
        parser.error("--citation-repair-max-turns must be at least 4")
    if arguments.application_runaway_max_turns < 16:
        parser.error("--application-runaway-max-turns must be at least 16")
    if arguments.application_no_progress_max_responses < 4:
        parser.error(
            "--application-no-progress-max-responses must be at least 4"
        )
    if arguments.guided_system_gap_limit < 1:
        parser.error("--guided-system-gap-limit must be at least 1")
    if arguments.experimental_guided_application and not arguments.system_guided_artifact:
        parser.error("--experimental-guided-application requires --system-guided-artifact")
    if arguments.experimental_guided_application and not arguments.questionable_control_file:
        parser.error("--experimental-guided-application requires --questionable-control-file")
    return arguments


def _json_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def _progress(event: str, **details: Any) -> None:
    """Emit sparse, machine-readable progress for long silent SDK requests."""

    print(json.dumps({"event": event, **details}, sort_keys=True), flush=True)


def _output_dict(value: Any, expected: type[BaseModel]) -> dict[str, Any]:
    if isinstance(value, expected):
        return value.model_dump(mode="json")
    if isinstance(value, BaseModel):
        return expected.model_validate(value.model_dump()).model_dump(mode="json")
    if isinstance(value, str):
        return expected.model_validate_json(value).model_dump(mode="json")
    return expected.model_validate(value).model_dump(mode="json")


def _model_settings(reasoning_effort: str, *, compact: bool) -> Any:
    from agents import ModelSettings  # type: ignore
    from openai.types.shared.reasoning import Reasoning  # type: ignore

    return ModelSettings(
        reasoning=Reasoning(effort=reasoning_effort),
        include_usage=True,
        parallel_tool_calls=False,
        store=False,
        context_management=(
            [{"type": "compaction", "compact_threshold": 200_000}]
            if compact else None
        ),
    )


def _candidate_count(packet: Mapping[str, Any]) -> int:
    ranked = packet.get("ranked_candidates") or {}
    if isinstance(ranked, Mapping):
        candidates = ranked.get("candidates")
        if isinstance(candidates, list):
            return len(candidates)
        items = ranked.get("items")
        if isinstance(items, list):
            return len(items)
    return 0


def _select_guided_system_gaps(
    report: Mapping[str, Any],
    *,
    limit: int,
    gap_ids: Iterable[str] = (),
) -> list[dict[str, Any]]:
    """Select a small, explicit system-review frontier for artifact mapping."""

    priority_order = {"high": 0, "medium": 1, "low": 2}
    candidates = [
        dict(row) for row in (report.get("supported_gaps") or [])
        if isinstance(row, Mapping)
    ]
    by_id: dict[str, dict[str, Any]] = {}
    for row in candidates:
        gap_id = str(row.get("gap_id") or "").strip()
        if not gap_id:
            raise FinalReviewError(
                "System-guided artifact review requires every gap to have gap_id"
            )
        if gap_id in by_id:
            raise FinalReviewError(
                "System-guided artifact review received duplicate gap_id %s"
                % gap_id
            )
        by_id[gap_id] = row

    requested = [str(value).strip() for value in gap_ids if str(value).strip()]
    if len(requested) != len(set(requested)):
        raise FinalReviewError("Guided gap identifiers must be unique")
    if requested:
        missing = [value for value in requested if value not in by_id]
        if missing:
            raise FinalReviewError(
                "Unknown guided system gap identifier(s): %s"
                % ", ".join(missing)
            )
        if len(requested) > int(limit):
            raise FinalReviewError(
                "Requested %d guided gaps but the configured limit is %d"
                % (len(requested), int(limit))
            )
        return [by_id[value] for value in requested]

    candidates.sort(key=lambda row: (
        priority_order.get(str(row.get("priority") or "low"), 9),
        str(row.get("gap_id") or ""),
    ))
    selected = candidates[: int(limit)]
    if not selected:
        raise FinalReviewError(
            "System-guided artifact review found no supported system gap"
        )
    return selected


def _guided_artifact_packet(
    base_packet: Mapping[str, Any],
    system_report: Mapping[str, Any],
    *,
    limit: int,
    gap_ids: Iterable[str] = (),
) -> dict[str, Any]:
    """Remove broad inventory and expose only host-selected system gaps."""

    selected = _select_guided_system_gaps(
        system_report, limit=limit, gap_ids=gap_ids
    )
    packet = {
        "schema": "verified_ida.system_guided_artifact.packet.v1",
        "objective": base_packet.get("objective"),
        "review_contract": base_packet.get("review_contract"),
        "components": base_packet.get("components"),
        "notebook": base_packet.get("notebook"),
        "selected_system_gaps": selected,
        "guidance_contract": {
            "selected_gap_count": len(selected),
            "unrelated_project_frontier_omitted": True,
            "atomic_child_findings_required": True,
            "parent_gap_id_required": True,
            "system_gaps_are_navigation_not_application_obligations": True,
        },
    }
    packet["packet_sha256"] = _json_sha256(packet)
    return packet


def _load_questionable_control(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Load a negative-control finding while keeping its expectation host-only."""

    source = path.expanduser().resolve()
    raw = json.loads(source.read_text(encoding="utf-8"))
    finding = dict(raw.get("finding") or {})
    expected = dict(raw.get("host_expectation") or {})
    ReviewFinding.model_validate(finding)
    if not expected:
        raise FinalReviewError("Questionable control is missing host_expectation")
    return finding, {
        "schema": "verified_ida.questionable_control_expectation.v1",
        "source": str(source),
        "finding_id": finding["finding_id"],
        "expected": expected,
    }


def _experimental_guided_plan(
    review_index: Mapping[str, Any],
) -> dict[str, Any]:
    """Schedule one control and atomic children of one system gap as waves."""

    findings = [dict(row) for row in review_index.get("source_findings") or []]
    control_ids = [
        str(row["source_finding_id"])
        for row in findings
        if str(row.get("source") or "") == "claim/experimental_control"
    ]
    guided_rows = [
        row for row in findings
        if row.get("source_kind") == "artifact"
        and str(dict(row.get("payload") or {}).get("parent_gap_id") or "")
    ]
    if len(control_ids) != 1:
        raise FinalReviewError(
            "Experimental guided application requires exactly one questionable control"
        )
    if not guided_rows:
        raise FinalReviewError(
            "Experimental guided application requires at least one guided artifact child"
        )
    parent_ids = {
        str(dict(row.get("payload") or {}).get("parent_gap_id") or "")
        for row in guided_rows
    }
    if len(parent_ids) != 1:
        raise FinalReviewError(
            "Guided artifact children must resolve one selected system gap"
        )

    guided_ids = [str(row["source_finding_id"]) for row in guided_rows]
    candidate_ids = [
        str(row["source_finding_id"])
        for row in findings
        if row.get("application_eligibility") == "candidate"
    ]
    scheduled = list(dict.fromkeys([
        *control_ids,
        *guided_ids,
        *candidate_ids,
    ]))
    system_parent_ids = {
        str(row["source_finding_id"]): str(
            dict(row.get("payload") or {}).get("gap_id") or ""
        )
        for row in findings if row.get("source_kind") == "system_gap"
    }
    parent_gap = next(iter(parent_ids))
    parent_source = next(
        (
            source_id for source_id, gap_id in system_parent_ids.items()
            if gap_id == parent_gap
        ),
        None,
    )
    dispositions = []
    for row in findings:
        source_id = str(row["source_finding_id"])
        payload = dict(row.get("payload") or {})
        if row.get("application_eligibility") == "candidate":
            route = "application_wave"
        else:
            route = "backlog_parent"
        related = []
        if payload.get("parent_gap_id") == parent_gap and parent_source:
            related.append(parent_source)
        if source_id == parent_source:
            related.extend(
                str(child["source_finding_id"]) for child in guided_rows
            )
        dispositions.append({
            "source_finding_id": source_id,
            "route": route,
            "priority": str(payload.get("priority") or "medium"),
            "related_source_finding_ids": sorted(set(related)),
            "rationale": (
                "Scheduled concrete verification target."
                if route == "application_wave"
                else "Retained as a system-model navigation parent."
            ),
        })
    waves = [{
        "wave_id": "wave-questionable-control",
        "source_finding_ids": control_ids,
        "rationale": "Verify that an intentionally questionable claim can be rejected or revised.",
    }]
    for index, row in enumerate(guided_rows, start=1):
        waves.append({
            "wave_id": "wave-guided-artifact-%02d" % index,
            "source_finding_ids": [str(row["source_finding_id"])],
            "rationale": (
                "Verify one atomic artifact child of system gap %s." % parent_gap
            ),
        })
    already_scheduled = set(control_ids) | set(guided_ids)
    for index, source_id in enumerate(
        (value for value in scheduled if value not in already_scheduled),
        start=1,
    ):
        waves.append({
            "wave_id": "wave-additional-candidate-%02d" % index,
            "source_finding_ids": [source_id],
            "rationale": "Verify one additional concrete review finding.",
        })
    return _validate_planning_report(review_index, {
        "assessment": (
            "Experimental plan schedules one questionable control and atomic "
            "artifact children of one selected system gap."
        ),
        "dispositions": dispositions,
        "proposed_waves": waves,
    })


def _field_evidence_refs(
    value: Any,
    *,
    field_names: frozenset[str],
) -> set[str]:
    """Read evidence identifiers only from schema-declared fields.

    The old implementation treated every string beginning with ``evidence-``
    as a citation. That made historical component lineage indistinguishable
    from current report support. New packets and reports establish citation
    intent through field identity instead of text shape.
    """

    refs: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key) in field_names:
                if isinstance(item, list):
                    refs.update(
                        str(reference) for reference in item
                        if str(reference).strip()
                    )
                continue
            refs.update(
                _field_evidence_refs(item, field_names=field_names)
            )
    elif isinstance(value, list):
        for item in value:
            refs.update(
                _field_evidence_refs(item, field_names=field_names)
            )
    return refs


def _report_evidence_refs(value: Any) -> set[str]:
    return _field_evidence_refs(
        value,
        field_names=frozenset({"evidence_refs", "current_evidence_refs"}),
    )


def _packet_current_evidence_refs(value: Any) -> set[str]:
    return _field_evidence_refs(
        value,
        field_names=frozenset({"current_evidence_refs"}),
    )


def _historical_component_evidence_refs(
    runtime: VerifiedIdaRuntime,
) -> set[str]:
    return _field_evidence_refs(
        [component.get("provenance") or {} for component in runtime.journal.components()],
        field_names=frozenset({"evidence_refs", "historical_evidence_refs"}),
    )


def _evidence_registry_for_value(
    runtime: VerifiedIdaRuntime,
    value: Any,
    *,
    stage: str,
    lane: str,
    origin: str,
) -> dict[str, dict[str, Any]]:
    registry = {}
    for evidence_id in sorted(_packet_current_evidence_refs(value)):
        row = runtime.journal.inspection(evidence_id)
        if row is None:
            raise FinalReviewError(
                "Host packet cited unknown evidence: %s" % evidence_id
            )
        component_id = str(row["component_id"])
        current_revision = int(
            runtime.journal.revision(component_id)["revision"]
        )
        evidence_revision = int(row["revision"])
        registry[evidence_id] = {
            "evidence_id": evidence_id,
            "component_id": component_id,
            "revision": evidence_revision,
            "current_revision": current_revision,
            "current": evidence_revision == current_revision,
            "citation_status": (
                "current" if evidence_revision == current_revision else "stale"
            ),
            "query_kind": str(row["query_kind"]),
            "stage": stage,
            "lane": lane,
            "origin": origin,
        }
    return registry


def _validate_review_report_evidence(
    runtime: VerifiedIdaRuntime,
    report: Mapping[str, Any],
    *,
    stage: str,
    lane: str,
    external_evidence_registry: Mapping[str, Mapping[str, Any]] | None = None,
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Validate explicit report citations against the current review project."""

    registry = {
        str(key): dict(value)
        for key, value in dict(external_evidence_registry or {}).items()
    }
    provenance_only = _historical_component_evidence_refs(runtime)
    invalid = []
    for evidence_id in sorted(_report_evidence_refs(report)):
        admitted = registry.get(evidence_id)
        if admitted and admitted.get("kind") == "notebook":
            invalid.append({"evidence_id": evidence_id, "reason": "wrong_evidence_kind",
                            "recovery": "Use notebook_refs for investigator statements; acquire IDA evidence for code claims."})
            continue
        if admitted and admitted.get("citation_status") == "current":
            component_id = str(admitted.get("component_id") or "")
            revision = runtime.journal.revision(component_id)
            if int(admitted.get("revision", -1)) == int(revision["revision"]):
                continue
        row = runtime.journal.inspection(evidence_id)
        if row is None:
            invalid.append({
                "evidence_id": evidence_id,
                "reason": "unknown",
                "recovery": "Reinspect the cited target with a live read-only tool.",
            })
            continue
        if row.get("query_kind") == "notebook.read":
            invalid.append({"evidence_id": evidence_id, "reason": "wrong_evidence_kind",
                            "recovery": "Use notebook_refs for investigator statements; acquire IDA evidence for code claims."})
            continue
        component_id = str(row["component_id"])
        current_revision = int(runtime.journal.revision(component_id)["revision"])
        evidence_revision = int(row["revision"])
        if evidence_id in provenance_only and not (
            admitted and admitted.get("citation_status") == "current"
        ):
            invalid.append({
                "evidence_id": evidence_id,
                "reason": "provenance_only",
                "component_id": component_id,
                "evidence_revision": evidence_revision,
                "current_revision": current_revision,
                "recovery": (
                    "Use the historical reference only to locate the boundary, "
                    "then reacquire current evidence."
                ),
            })
            continue
        if evidence_revision != current_revision:
            invalid.append({
                "evidence_id": evidence_id,
                "reason": "stale",
                "component_id": component_id,
                "evidence_revision": evidence_revision,
                "current_revision": current_revision,
                "recovery": "Reinspect the cited target at the current component revision.",
            })
            continue
        registry[evidence_id] = {
            "evidence_id": evidence_id,
            "component_id": component_id,
            "revision": evidence_revision,
            "query_kind": str(row["query_kind"]),
            "stage": stage,
            "lane": lane,
            "current_revision": current_revision,
            "current": True,
            "citation_status": "current",
            "origin": "review_stage",
        }
    from verified_ida.notebook_evidence import validate_notebook_reference
    for reference in sorted(_field_evidence_refs(report, field_names=frozenset({"notebook_refs"}))):
        record, error = validate_notebook_reference(runtime, reference, registry.get(reference))
        if error:
            invalid.append({"evidence_id": reference, "reason": error,
                            "recovery": "Read reversing_log and copy its issued notebook_ref into notebook_refs."})
        else:
            registry[reference] = record

    def visit(value, path=""):
        if isinstance(value, Mapping):
            for key, child in value.items():
                if key in {"evidence_refs", "current_evidence_refs", "notebook_refs"}:
                    for problem in invalid:
                        if problem["evidence_id"] in (child or []):
                            problem.setdefault("locations", []).append(path + "/" + key)
                elif isinstance(child, (Mapping, list)):
                    visit(child, path + "/" + key)
            if ("supported_behavior" in value or "missing_or_weak_stage" in value
                    or value.get("classification") in {"confirmed_error", "unsupported_claim", "application_gap", "coverage_gap"}):
                if not value.get("evidence_refs"):
                    invalid.append({"evidence_id": "", "reason": "binary_evidence_required", "locations": [path],
                                    "recovery": "Inspect the relevant IDA target; notebook text alone cannot establish this claim."})
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, path + "/" + str(index))
    visit(report)
    return registry, invalid


def _record_readonly_stage_failure(function):
    """Also attest isolation and retain a terminal record on unsuccessful exits."""
    @wraps(function)
    def run(**kwargs):
        source, stage_dir = Path(kwargs["source_project"]), Path(kwargs["stage_dir"])
        source_before = project_component_hashes(source)
        lifecycle = {}
        try:
            return function(**kwargs, _lifecycle=lifecycle)
        except (Exception, KeyboardInterrupt) as exc:
            isolation = {"status": "unavailable", "source_component_hashes_unchanged": None}
            owned_runtime = lifecycle.get("runtime")
            if owned_runtime is not None and owned_runtime.active_component_id is not None:
                try:
                    owned_runtime.close()
                except Exception as cleanup:
                    isolation["cleanup_error"] = {"type": type(cleanup).__name__, "message": str(cleanup)}
            try:
                isolation["source_component_hashes_unchanged"] = (
                    source_before == project_component_hashes(source)
                )
                before_path = stage_dir / "semantic_before.json"
                if before_path.is_file():
                    verifier = VerifiedIdaRuntime.initialize(
                        stage_dir / "project", analysis_feedback_profile="none", read_only_mode=True,
                    )
                    try:
                        after = semantic_project_snapshot(verifier)
                    finally:
                        verifier.close()
                    isolation["semantic_boundary"] = verify_semantic_stage_boundary(
                        json.loads(before_path.read_text(encoding="utf-8")), after,
                    )
                    isolation["status"] = (
                        "verified" if isolation["source_component_hashes_unchanged"] and not isolation.get("cleanup_error") else "failed"
                    )
            except Exception as secondary:
                isolation["error"] = {"type": type(secondary).__name__, "message": str(secondary)}
            try:
                _write_json(stage_dir / "isolation.json", isolation)
                _write_json(stage_dir / "summary.json", {
                    "schema": "verified_ida.final_review_stage_summary.v1",
                    "status": "failed", "stage": kwargs["stage"], "lane": kwargs["lane"],
                    "error": {"type": type(exc).__name__, "message": str(exc)},
                    "isolation": isolation, "report_validated": False,
                })
            except Exception as secondary:
                print("Unable to persist review failure: %s" % secondary, file=sys.stderr)
            raise
    return run


def _citation_scope(report: Mapping[str, Any]) -> dict[str, Any]:
    """Citation repair cannot delete work or silently retarget a finding."""
    scope = {}
    for group, id_field in (("findings", "finding_id"), ("supported_elements", "element_id"),
                            ("supported_gaps", "gap_id")):
        items = {}
        for row in report.get(group) or []:
            identity = row.get(id_field)
            if not identity or identity in items:
                raise FinalReviewError("Citation repair needs unique report item identities")
            items[identity] = {key: row.get(key) for key in (
                "component_id", "related_component_ids", "targets", "classification", "priority", "workflow",
            )}
        scope[group] = items
    return scope


def _collect_then_finalize_repair(collector, finalizer, inputs, *, max_turns, hooks):
    """Reserve the last stage turn for output; the shared budget still applies."""
    from agents import Runner, RunErrorHandlerResult
    if max_turns < 2:
        raise ValueError("Citation repair requires one collection and one finalization turn")
    capped = False

    def reached_cap(_context):
        nonlocal capped
        capped = True
        return RunErrorHandlerResult(final_output="Collection ended. Finalize using only acquired references.")

    collection = Runner.run_sync(collector, inputs, max_turns=max_turns - 1, hooks=hooks,
                                 error_handlers={"max_turns": reached_cap})
    final_input = collection.to_input_list()
    final_input.append({"role": "user", "content": (
        "Citation acquisition is over. Return the complete corrected report now, using only issued "
        "references. Preserve every item ID, component, target, classification, priority and workflow; "
        "do not drop unsupported items or invent references to pass validation."
    )})
    return Runner.run_sync(finalizer, final_input, max_turns=1, hooks=hooks), capped


@_record_readonly_stage_failure
def _run_readonly_review_stage(
    *,
    source_project: Path,
    stage_dir: Path,
    stage: str,
    lane: str,
    packet: Mapping[str, Any],
    prompt_path: Path,
    output_type: type[BaseModel],
    model: str,
    reasoning_effort: str,
    max_turns: int,
    citation_repair_max_turns: int,
    environment: Mapping[str, Any],
    external_evidence_registry: Mapping[str, Mapping[str, Any]] | None = None,
    on_response_end: Callable[[Mapping[str, Any]], None] | None = None,
    _lifecycle: dict[str, Any] | None = None,
) -> dict[str, Any]:
    from agents import (  # type: ignore
        Agent,
        RunErrorHandlerResult,
        Runner,
    )

    stage_dir.mkdir(parents=True, exist_ok=False)
    source_hashes_before = project_component_hashes(source_project)
    stage_project = stage_dir / "project"
    clone_verified_project(source_project, stage_project)
    runtime = VerifiedIdaRuntime.initialize(
        stage_project,
        analysis_feedback_profile="none",
        read_only_mode=True,
    )
    if _lifecycle is not None:
        _lifecycle["runtime"] = runtime
    try:
        semantic_before = semantic_project_snapshot(runtime)
        _write_json(stage_dir / "semantic_before.json", semantic_before)
    except BaseException:
        runtime.close()
        raise
    packet_path = stage_dir / "packet.json"
    _write_json(packet_path, packet)
    instructions = prompt_path.read_text(encoding="utf-8")
    trace = ObservableTrace(stage_dir / "observable_tool_trace.jsonl")
    segment_id = _segment_id()
    trace.append(
        "final_review_stage_started",
        segment_id=segment_id,
        actor="harness",
        stage=stage,
        lane=lane,
        model=model,
        reasoning_effort=reasoning_effort,
        max_turns=max_turns,
        packet_path=str(packet_path),
        packet_sha256=packet.get("packet_sha256") or _json_sha256(packet),
        allowed_tools=sorted(FINAL_REVIEW_READ_ONLY_TOOLS),
        environment=dict(environment),
    )
    _progress(
        "final_review_stage_started",
        stage=stage,
        lane=lane,
        max_turns=max_turns,
    )
    adapter = VerifiedIdaToolAdapter(runtime, read_only=True)
    hit_cap = False

    def _cap_handler(_handler_input: Any) -> RunErrorHandlerResult:
        nonlocal hit_cap
        hit_cap = True
        return RunErrorHandlerResult(
            final_output=(
                "Evidence collection reached its reserved limit. Synthesize "
                "only the evidence already collected."
            )
        )

    collector = Agent(
        name="Verified IDA %s %s Reviewer" % (stage.title(), lane.title()),
        model=model,
        model_settings=_model_settings(reasoning_effort, compact=True),
        instructions=instructions,
        tools=_function_tools(
            adapter,
            trace,
            ToolInvocationState(),
            segment_id,
            allowed_names=FINAL_REVIEW_READ_ONLY_TOOLS,
        ),
    )
    try:
        collection = Runner.run_sync(
            collector,
            (
                "Perform the bounded %s review for lane `%s`. The host packet is:\n\n%s"
                % (stage, lane, json.dumps(packet, sort_keys=True, ensure_ascii=False))
            ),
            max_turns=max_turns - 1,
            hooks=_observable_hooks(
                trace,
                runtime,
                segment_id=segment_id,
                compact_threshold_tokens=200_000,
                on_response_end=on_response_end,
            ),
            error_handlers={"max_turns": _cap_handler},
        )
    except Exception:
        runtime.close()
        raise
    trace.append(
        "final_review_stage_synthesis_started",
        segment_id=segment_id,
        actor="harness",
        stage=stage,
        lane=lane,
        collection_hit_turn_cap=hit_cap,
    )
    finalizer = Agent(
        name="Verified IDA %s %s Finalizer" % (stage.title(), lane.title()),
        model=model,
        model_settings=_model_settings(reasoning_effort, compact=False),
        instructions=(
            instructions
            + "\n\nEvidence collection is over. Return the requested structured "
            "review using only evidence already present in the conversation."
        ),
        tools=[],
        output_type=output_type,
    )
    synthesis_input = collection.to_input_list()
    synthesis_input.append({
        "role": "user",
        "content": "Produce the final structured %s report for lane `%s` now."
        % (stage, lane),
    })
    try:
        result = Runner.run_sync(
            finalizer,
            synthesis_input,
            max_turns=1,
            hooks=_observable_hooks(
                trace,
                runtime,
                segment_id=segment_id,
                compact_threshold_tokens=200_000,
                on_response_end=on_response_end,
            ),
        )
    except Exception:
        runtime.close()
        raise
    report = _output_dict(result.final_output, output_type)
    evidence_registry, invalid_citations = _validate_review_report_evidence(
        runtime,
        report,
        stage=stage,
        lane=lane,
        external_evidence_registry=external_evidence_registry,
    )
    citation_repair = {
        "attempted": False,
        "max_turns": int(citation_repair_max_turns),
        "initial_invalid_citations": invalid_citations,
        "status": "not_needed",
    }
    if invalid_citations:
        citation_repair.update({"attempted": True, "status": "started"})
        _write_json(stage_dir / "report_before_citation_repair.json", report)
        _write_json(stage_dir / "citation_repair_request.json", citation_repair)
        trace.append(
            "final_review_citation_repair_started",
            segment_id=segment_id,
            actor="harness",
            stage=stage,
            lane=lane,
            invalid_citations=invalid_citations,
            max_turns=int(citation_repair_max_turns),
        )
        _progress(
            "final_review_citation_repair_started",
            stage=stage,
            lane=lane,
            invalid_citation_count=len(invalid_citations),
            max_turns=int(citation_repair_max_turns),
        )
        repair_agent = Agent(
            name="Verified IDA %s %s Citation Repair" % (
                stage.title(), lane.title()
            ),
            model=model,
            model_settings=_model_settings(reasoning_effort, compact=False),
            instructions=(
                instructions
                + "\n\nThis is the single citation-repair pass. The previous "
                "structured report is otherwise provisional. Reacquire only the "
                "evidence needed to replace the listed invalid citations. You may "
                "make several bounded read-only tool requests within this pass. "
                "Do not expand the review or copy historical_evidence_refs. "
                "Collect replacement references; a separate tool-free finalizer "
                "will return the corrected report. Use notebook_refs only for "
                "issued notebook references, never as binary evidence_refs."
            ),
            tools=_function_tools(
                adapter,
                trace,
                ToolInvocationState(),
                segment_id,
                allowed_names=FINAL_REVIEW_READ_ONLY_TOOLS,
            ),
        )
        repair_input = collection.to_input_list()
        repair_input.append({
            "role": "user",
            "content": (
                "Correct the report's evidence citations without broadening its "
                "semantic scope. Invalid citations:\n\n%s\n\nProvisional report:\n\n%s"
                % (
                    json.dumps(invalid_citations, sort_keys=True),
                    json.dumps(report, sort_keys=True),
                )
            ),
        })
        try:
            repaired, repair_capped = _collect_then_finalize_repair(
                repair_agent, finalizer, repair_input,
                max_turns=int(citation_repair_max_turns),
                hooks=_observable_hooks(
                    trace,
                    runtime,
                    segment_id=segment_id,
                    compact_threshold_tokens=200_000,
                    on_response_end=on_response_end,
                ),
            )
            citation_repair["collection_hit_turn_cap"] = repair_capped
        except Exception:
            citation_repair["status"] = "failed_during_reacquisition"
            _write_json(stage_dir / "citation_repair.json", citation_repair)
            runtime.close()
            raise
        corrected = _output_dict(repaired.final_output, output_type)
        if _citation_scope(report) != _citation_scope(corrected):
            citation_repair["status"] = "failed_scope_validation"
            _write_json(stage_dir / "citation_repair.json", citation_repair)
            _write_json(stage_dir / "rejected_repair_report.json", corrected)
            runtime.close()
            raise FinalReviewError("Citation repair deleted, introduced, or retargeted report items")
        report = corrected
        evidence_registry, remaining_invalid = _validate_review_report_evidence(
            runtime,
            report,
            stage=stage,
            lane=lane,
            external_evidence_registry=external_evidence_registry,
        )
        citation_repair["remaining_invalid_citations"] = remaining_invalid
        citation_repair["status"] = (
            "repaired" if not remaining_invalid else "failed_closed"
        )
        _write_json(stage_dir / "citation_repair.json", citation_repair)
        trace.append(
            "final_review_citation_repair_completed",
            segment_id=segment_id,
            actor="model_and_host",
            stage=stage,
            lane=lane,
            status=citation_repair["status"],
            remaining_invalid_citations=remaining_invalid,
        )
        if remaining_invalid:
            runtime.close()
            raise FinalReviewError(
                "Review report retained invalid evidence after one citation "
                "repair pass: %s"
                % ", ".join(
                    str(row["evidence_id"]) for row in remaining_invalid
                )
            )
    report_path = stage_dir / "report.json"
    _write_json(report_path, report)
    (stage_dir / "report.md").write_text(
        "# %s: %s\n\n```json\n%s\n```\n"
        % (
            stage.replace("_", " ").title(),
            lane.replace("_", " ").title(),
            json.dumps(report, indent=2, sort_keys=True),
        ),
        encoding="utf-8",
    )
    trace.append(
        "final_review_stage_completed",
        segment_id=segment_id,
        actor="harness",
        stage=stage,
        lane=lane,
        report_path=str(report_path),
        report_sha256=_json_sha256(report),
    )
    runtime.close()
    verifier = VerifiedIdaRuntime.initialize(
        stage_project,
        analysis_feedback_profile="none",
        read_only_mode=True,
    )
    try:
        semantic_after = semantic_project_snapshot(verifier)
    finally:
        verifier.close()
    semantic_boundary = verify_semantic_stage_boundary(
        semantic_before, semantic_after
    )
    source_hashes_after = project_component_hashes(source_project)
    if source_hashes_before != source_hashes_after:
        raise FinalReviewError(
            "Read-only review stage changed its source project"
        )
    isolation = {
        "schema": "verified_ida.final_review_stage_isolation.v1",
        "disposable_project": str(stage_project),
        "source_project": str(source_project),
        "source_component_hashes_unchanged": True,
        "sessions_closed_without_save": True,
        "semantic_boundary": semantic_boundary,
    }
    _write_json(stage_dir / "isolation.json", isolation)
    _write_json(stage_dir / "evidence_registry.json", evidence_registry)
    walkthrough = write_walkthrough(trace, stage_dir / "walkthrough.md")
    events, parse_errors = trace.read()
    summary = {
        "schema": "verified_ida.final_review_stage_summary.v1",
        "status": "completed",
        "stage": stage,
        "lane": lane,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "max_turns": max_turns,
        "collection_hit_turn_cap": hit_cap,
        "citation_repair": citation_repair,
        "usage": aggregate_usage(events),
        "event_counts": event_counts(events),
        "trace_parse_errors": parse_errors,
        "packet": str(packet_path),
        "report": str(report_path),
        "walkthrough": walkthrough,
        "isolation": isolation,
        "evidence_registry": str(stage_dir / "evidence_registry.json"),
    }
    _write_json(stage_dir / "summary.json", summary)
    _progress(
        "final_review_stage_completed",
        stage=stage,
        lane=lane,
        finding_count=len(report.get("findings") or []),
        total_tokens=int(summary["usage"].get("total_tokens") or 0),
    )
    return {
        "report": report,
        "summary": summary,
        "evidence_registry": evidence_registry,
        "citation_repair": citation_repair,
    }


def _validate_planning_report(
    index: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    findings = {
        str(row["source_finding_id"]): dict(row)
        for row in index.get("source_findings") or []
    }
    dispositions = list(report.get("dispositions") or [])
    by_id = {}
    for row in dispositions:
        source_id = str(row.get("source_finding_id") or "")
        if source_id not in findings:
            raise FinalReviewError(
                "Planner referenced unknown source finding: %s" % source_id
            )
        if source_id in by_id:
            raise FinalReviewError(
                "Planner dispositioned a source finding twice: %s" % source_id
            )
        related = list(dict.fromkeys(
            str(value) for value in row.get("related_source_finding_ids") or []
        ))
        if source_id in related or any(value not in findings for value in related):
            raise FinalReviewError(
                "Planner supplied an invalid related-finding reference for %s"
                % source_id
            )
        if (
            findings[source_id]["application_eligibility"] == "navigation_parent"
            and row.get("route") == "application_wave"
        ):
            raise FinalReviewError(
                "System-model navigation parent cannot become an application obligation: %s"
                % source_id
            )
        if (
            findings[source_id]["application_eligibility"] == "candidate"
            and row.get("route") != "application_wave"
        ):
            raise FinalReviewError(
                "Concrete review finding must be scheduled for application: %s"
                % source_id
            )
        if (
            findings[source_id]["application_eligibility"] == "navigation_parent"
            and row.get("route") != "backlog_parent"
        ):
            raise FinalReviewError(
                "System-model navigation parent must remain a parent: %s"
                % source_id
            )
        by_id[source_id] = {**dict(row), "related_source_finding_ids": related}
    missing = sorted(set(findings) - set(by_id))
    if missing:
        raise FinalReviewError(
            "Planner silently omitted source findings: %s" % ", ".join(missing)
        )

    waves = []
    wave_member_to_id = {}
    for raw in report.get("proposed_waves") or []:
        wave = dict(raw)
        wave_id = str(wave.get("wave_id") or "").strip()
        if not wave_id or any(row["wave_id"] == wave_id for row in waves):
            raise FinalReviewError("Planner supplied a missing or duplicate wave ID")
        members = list(dict.fromkeys(
            str(value) for value in wave.get("source_finding_ids") or []
        ))
        if not members:
            raise FinalReviewError("Application wave is empty: %s" % wave_id)
        for source_id in members:
            if source_id not in findings:
                raise FinalReviewError(
                    "Wave %s references unknown finding %s" % (wave_id, source_id)
                )
            if by_id[source_id].get("route") != "application_wave":
                raise FinalReviewError(
                    "Wave %s includes non-wave finding %s" % (wave_id, source_id)
                )
            if source_id in wave_member_to_id:
                raise FinalReviewError(
                    "Finding %s appears in more than one wave" % source_id
                )
            wave_member_to_id[source_id] = wave_id
        waves.append({**wave, "wave_id": wave_id, "source_finding_ids": members})
    expected_wave_members = {
        source_id for source_id, row in by_id.items()
        if row.get("route") == "application_wave"
    }
    if set(wave_member_to_id) != expected_wave_members:
        raise FinalReviewError(
            "Proposed waves do not exactly cover application-wave findings"
        )

    # Shared targets coordinate sequential work; they are not a reason to
    # combine independent decisions into a transitive, unbounded task.
    original_waves = waves
    waves = focused_application_waves(original_waves)
    wave_normalizations = [
        {"kind": "one_finding_per_wave", "source_wave_id": row["wave_id"],
         "source_finding_ids": row["source_finding_ids"]}
        for row in original_waves if len(row["source_finding_ids"]) > 1
    ]

    scheduled_parent_gap_ids = {
        str(dict(findings[source_id].get("payload") or {}).get("parent_gap_id"))
        for source_id in expected_wave_members
        if dict(findings[source_id].get("payload") or {}).get("parent_gap_id")
    }
    unrepresented_high_priority_parent_ids = sorted(
        source_id
        for source_id, finding in findings.items()
        if finding["application_eligibility"] == "navigation_parent"
        and str(dict(finding.get("payload") or {}).get("priority") or "medium")
        == "high"
        and str(dict(finding.get("payload") or {}).get("gap_id") or "")
        not in scheduled_parent_gap_ids
    )
    return {
        "schema": "verified_ida.final_review_validated_plan.v1",
        "assessment": report.get("assessment"),
        "dispositions": [by_id[key] for key in sorted(by_id)],
        "waves": waves,
        "source_finding_count": len(findings),
        "accounted_source_finding_count": len(by_id),
        "application_wave_count": len(waves),
        "wave_normalizations": wave_normalizations,
        "unrepresented_high_priority_parent_ids": (
            unrepresented_high_priority_parent_ids
        ),
        "planning_digest": _json_sha256({
            "dispositions": [by_id[key] for key in sorted(by_id)],
            "waves": waves,
            "wave_normalizations": wave_normalizations,
            "unrepresented_high_priority_parent_ids": (
                unrepresented_high_priority_parent_ids
            ),
        }),
    }


def _run_planning(
    *,
    runtime: VerifiedIdaRuntime,
    stage_dir: Path,
    review_index: Mapping[str, Any],
    model: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    from agents import Agent, Runner  # type: ignore

    stage_dir.mkdir(parents=True, exist_ok=False)
    packet = {
        "schema": "verified_ida.final_review_planning.packet.v1",
        "review_index": review_index,
        "authority": {
            "may_recommend_grouping_and_order": True,
            "may_rewrite_source_findings": False,
            "must_account_for_every_source_finding": True,
            "navigation_parents_are_not_application_obligations": True,
            "all_concrete_findings_require_application_waves": True,
            "cost_cannot_remove_analytical_scope": True,
        },
    }
    packet["packet_sha256"] = _json_sha256(packet)
    _write_json(stage_dir / "packet.json", packet)
    trace = ObservableTrace(stage_dir / "observable_tool_trace.jsonl")
    segment_id = _segment_id()
    trace.append(
        "final_review_planning_started",
        segment_id=segment_id,
        actor="harness",
        stage="planning",
        model=model,
        packet_sha256=packet["packet_sha256"],
    )
    _progress(
        "final_review_planning_started",
    )
    agent = Agent(
        name="Verified IDA Final Review Planner",
        model=model,
        model_settings=_model_settings(reasoning_effort, compact=False),
        instructions=PROMPTS["planning"].read_text(encoding="utf-8"),
        tools=[],
        output_type=PlanningReport,
    )
    result = Runner.run_sync(
        agent,
        "Produce a lossless advisory application plan for this immutable review index:\n\n%s"
        % json.dumps(packet, sort_keys=True, ensure_ascii=False),
        max_turns=1,
        hooks=_observable_hooks(
            trace,
            runtime,
            segment_id=segment_id,
            compact_threshold_tokens=200_000,
        ),
    )
    report = _output_dict(result.final_output, PlanningReport)
    validated = _validate_planning_report(review_index, report)
    _write_json(stage_dir / "advisory_report.json", report)
    _write_json(stage_dir / "validated_plan.json", validated)
    trace.append(
        "final_review_planning_completed",
        segment_id=segment_id,
        actor="harness",
        stage="planning",
        source_finding_count=validated["source_finding_count"],
        application_wave_count=validated["application_wave_count"],
        report_sha256=_json_sha256(validated),
    )
    walkthrough = write_walkthrough(trace, stage_dir / "walkthrough.md")
    events, parse_errors = trace.read()
    summary = {
        "schema": "verified_ida.final_review_planning_summary.v1",
        "status": "completed",
        "stage": "planning",
        "model": model,
        "reasoning_effort": reasoning_effort,
        "usage": aggregate_usage(events),
        "event_counts": event_counts(events),
        "trace_parse_errors": parse_errors,
        "walkthrough": walkthrough,
    }
    if not summary["usage"]["requests"]:
        summary["usage"] = _usage_dict(
            getattr(getattr(result, "context_wrapper", None), "usage", None)
        )
    _write_json(stage_dir / "summary.json", summary)
    _progress(
        "final_review_planning_completed",
        source_finding_count=validated["source_finding_count"],
        application_wave_count=validated["application_wave_count"],
        total_tokens=int(summary["usage"].get("total_tokens") or 0),
    )
    return {"advisory_report": report, "plan": validated, "summary": summary}


def _run_consolidation_stage(
    *,
    source_project: Path,
    output_dir: Path,
    claim_reports: list[Mapping[str, Any]],
    system_model: Mapping[str, Any],
    artifact_coverage: Mapping[str, Any],
    evidence_registry: Mapping[str, Mapping[str, Any]],
    model: str,
    reasoning_effort: str,
) -> dict[str, Any]:
    stage_dir = output_dir / "consolidation"
    stage_dir.mkdir(parents=True, exist_ok=False)
    source_hashes_before = project_component_hashes(source_project)
    stage_project = stage_dir / "project"
    clone_verified_project(source_project, stage_project)
    runtime = VerifiedIdaRuntime.initialize(
        stage_project,
        analysis_feedback_profile="none",
        read_only_mode=True,
    )
    semantic_before = semantic_project_snapshot(runtime)

    def validate_address(component_id: str, address: str) -> dict[str, Any]:
        response = runtime.inspect(
            query="inspect_addr",
            target=address,
            component_id=component_id,
            limit=1,
        )
        result = dict(response.get("result") or {})
        function = dict(result.get("function") or {})
        data_object = dict(result.get("data_object") or {})
        raw_segment = (
            result.get("segment")
            or function.get("segment")
            or data_object.get("segment")
            or {}
        )
        if isinstance(raw_segment, Mapping):
            segment = dict(raw_segment)
        elif raw_segment:
            segment = {"name": str(raw_segment)}
        else:
            segment = {}
        valid = bool(
            result.get("ok")
            and (
                result.get("address")
                or function.get("address")
                or data_object.get("address")
                or segment.get("start")
            )
        )
        return {
            "valid": valid,
            "evidence_id": response.get("evidence_id"),
            "resolved_function": function.get("address"),
            "resolved_data_object": data_object.get("address"),
            "segment": segment.get("name"),
        }

    review_index = build_lossless_review_index(
        claim_reports=claim_reports,
        system_model=system_model,
        artifact_coverage=artifact_coverage,
        component_ids=[
            str(row["component_id"]) for row in runtime.journal.components()
        ],
        evidence_registry=evidence_registry,
        address_validator=validate_address,
    )
    _write_json(stage_dir / "review_index.json", review_index)
    planning = _run_planning(
        runtime=runtime,
        stage_dir=stage_dir / "planning",
        review_index=review_index,
        model=model,
        reasoning_effort=reasoning_effort,
    )
    runtime.close()
    verifier = VerifiedIdaRuntime.initialize(
        stage_project,
        analysis_feedback_profile="none",
        read_only_mode=True,
    )
    try:
        semantic_after = semantic_project_snapshot(verifier)
    finally:
        verifier.close()
    semantic_boundary = verify_semantic_stage_boundary(
        semantic_before, semantic_after
    )
    if source_hashes_before != project_component_hashes(source_project):
        raise FinalReviewError("Consolidation changed its source project")
    isolation = {
        "schema": "verified_ida.final_review_stage_isolation.v1",
        "disposable_project": str(stage_project),
        "source_project": str(source_project),
        "source_component_hashes_unchanged": True,
        "sessions_closed_without_save": True,
        "semantic_boundary": semantic_boundary,
    }
    _write_json(stage_dir / "isolation.json", isolation)
    return {
        "review_index": review_index,
        "plan": planning["plan"],
        "advisory_report": planning["advisory_report"],
        "summary": {**planning["summary"], "isolation": isolation},
    }


def _disposition_tool(
    ledger: ReviewDispositionLedger,
    trace: ObservableTrace,
    segment_id: str,
    *,
    allowed_finding_ids: set[str] | None = None,
) -> Any:
    from agents import FunctionTool  # type: ignore

    async def invoke(_context: Any, arguments_json: str) -> str:
        try:
            arguments = json.loads(arguments_json or "{}")
            if (
                allowed_finding_ids is not None
                and str(arguments.get("finding_id") or "")
                not in allowed_finding_ids
            ):
                raise FinalReviewError(
                    "Finding is outside the current application wave"
                )
            result = ledger.record(
                **arguments,
                active_wave_finding_ids=allowed_finding_ids or (),
            )
            result["next_action"] = (
                "This finding is dispositioned. Update affected Current Project State "
                "sections and append the Investigation Journal result, then return. "
                "Do not begin another finding; the host schedules it."
            )
            trace.append(
                "review_disposition_recorded",
                segment_id=segment_id,
                actor="model_and_host",
                tool="record_review_disposition",
                arguments=arguments,
                ok=True,
                result=result,
            )
            return json.dumps({"ok": True, "result": result}, sort_keys=True)
        except Exception as exc:
            error = {
                "ok": False,
                "error": {
                    "type": type(exc).__name__,
                    "message": str(exc),
                    "recovery": (
                        "Inspect current IDA state, use current evidence, apply "
                        "a verified edit when accepting, and retry only this disposition."
                    ),
                },
            }
            trace.append(
                "review_disposition_failed",
                segment_id=segment_id,
                actor="model_and_host",
                tool="record_review_disposition",
                arguments_sha256=hashlib.sha256(
                    arguments_json.encode("utf-8")
                ).hexdigest(),
                **error,
            )
            return json.dumps(error, sort_keys=True)

    return FunctionTool(
        name="record_review_disposition",
        description=(
            "Record the current-evidence disposition of one current-wave final-review "
            "finding. Accept/revise requires a review-stage verified operation (including "
            "a saved edit from an earlier application attempt); reject/defer "
            "requires current inspection evidence and no claimed operation. When "
            "current evidence identifies one different artifact that must be checked, "
            "follow_up_required records its typed identity and fresh evidence for a "
            "later host-validated wave; it does not authorize an edit now."
        ),
        params_json_schema={
            "type": "object",
            "required": [
                "finding_id", "outcome", "rationale", "evidence_refs", "operation_ids"
            ],
            "properties": {
                "finding_id": {"type": "string", "minLength": 1},
                "outcome": {
                    "enum": [
                        "accept_and_apply",
                        "revise_and_apply",
                        "reject",
                        "defer",
                        "follow_up_required",
                    ]
                },
                "rationale": {"type": "string", "minLength": 1},
                "evidence_refs": {
                    "type": "array",
                    "minItems": 1,
                    "items": {"type": "string", "minLength": 1},
                    "uniqueItems": True,
                },
                "operation_ids": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "uniqueItems": True,
                },
                "follow_up_target": {
                    "type": "object",
                    "required": ["component_id", "kind"],
                    "properties": {
                        "component_id": {"type": "string", "minLength": 1},
                        "kind": {
                            "enum": [
                                "function",
                                "address",
                                "global",
                                "named_type",
                                "relationship",
                                "local_variable",
                            ]
                        },
                        "address": {"type": "string", "minLength": 1},
                        "name": {"type": "string", "minLength": 1},
                        "function_address": {"type": "string", "minLength": 1},
                        "lvar_index": {"type": "integer", "minimum": 0},
                        "current_name": {"type": "string", "minLength": 1},
                        "source_address": {"type": "string", "minLength": 1},
                        "destination_address": {"type": "string", "minLength": 1},
                        "relationship_kind": {"type": "string", "minLength": 1},
                    },
                    "additionalProperties": False,
                },
                "follow_up_evidence_refs": {
                    "type": "array",
                    "items": {"type": "string", "minLength": 1},
                    "uniqueItems": True,
                },
            },
            "additionalProperties": False,
        },
        on_invoke_tool=invoke,
        strict_json_schema=False,
    )


class ApplicationWaveNoProgress(RuntimeError):
    """Raised when a wave consumes responses without durable analytical progress."""


def _application_wave_mechanical_issues(
    runtime: VerifiedIdaRuntime,
    *,
    operation_cutoff: int,
    allowed_target_identities: set[tuple[str, str, str]],
) -> list[dict[str, Any]]:
    """Return unresolved mutations created on targets in the current wave."""

    return [
        row
        for row in runtime.journal.mechanical_issues()
        if int(row["operation_rowid"]) > operation_cutoff
        and operation_review_target(row) in allowed_target_identities
    ]


class _ApplicationWaveToolAdapter:
    """Keep review reads in-wave and writes on declared finding targets."""

    def __init__(
        self,
        adapter: VerifiedIdaToolAdapter,
        *,
        allowed_component_ids: set[str],
        allowed_target_identities: set[tuple[str, str, str]],
        progress_guidance: Any = None,
    ):
        self.adapter = adapter
        self.runtime = adapter.runtime
        self.allowed_component_ids = set(allowed_component_ids)
        self.allowed_target_identities = set(allowed_target_identities)
        self.progress_guidance = progress_guidance

    @property
    def schemas(self) -> Mapping[str, Any]:
        """Expose the wrapped catalog without widening its read/write policy."""
        return self.adapter.schemas

    def invoke(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> Any:
        request = dict(arguments or {})
        requested_component = request.get("component_id")
        if name == "switch_ida_component":
            requested_component = request.get("component_id")
        if (
            requested_component is not None
            and str(requested_component) not in self.allowed_component_ids
        ):
            raise FinalReviewError(
                "Component %s is outside the current application wave; "
                "verify only %s or record one exact typed follow-up target"
                % (
                    requested_component,
                    ", ".join(sorted(self.allowed_component_ids)),
                )
            )
        if name == "edit_ida":
            reference = self.runtime.journal.reference(
                str(request.get("target_ref") or "")
            )
            if reference is None:
                raise FinalReviewError(
                    "The edit target reference is unknown or expired"
                )
            target = dict(reference.get("target") or {})
            identity = operation_review_target({
                "component_id": reference.get("component_id"),
                "request": {"target": target},
            })
            if identity not in self.allowed_target_identities:
                raise FinalReviewError(
                    "The edit target is not declared by a current-wave finding; "
                    "record a typed follow_up_required disposition if another "
                    "artifact must change"
                )
        if name in {
            "read_ida_call_flow_scope",
            "disposition_ida_call_flow_node",
            "revalidate_ida_function_claim",
        }:
            scope = self.runtime.journal.call_flow_scope(
                str(request.get("scope_id") or "")
            )
            if scope is None:
                raise FinalReviewError("The call-flow scope is unknown")
            identity = (
                str(scope["component_id"]),
                "function",
                str(scope["root_address"]),
            )
            if identity not in self.allowed_target_identities:
                raise FinalReviewError(
                    "The call-flow scope is not rooted in a current-wave finding target"
                )
        if (
            name not in {"switch_ida_component"}
            and self.runtime.active_component_id not in self.allowed_component_ids
        ):
            raise FinalReviewError(
                "The active component is outside the current application wave; "
                "switch to one of: %s"
                % ", ".join(sorted(self.allowed_component_ids))
            )
        result = self.adapter.invoke(name, request)
        guidance = (
            self.progress_guidance(name)
            if self.progress_guidance is not None
            else None
        )
        if guidance and isinstance(result, Mapping):
            return {**dict(result), "_application_wave_progress": guidance}
        return result


class _ApplicationWaveProgress:
    def __init__(
        self,
        *,
        runtime: VerifiedIdaRuntime,
        ledger: ReviewDispositionLedger,
        no_progress_limit: int,
        allowed_target_identities: set[tuple[str, str, str]],
        active_finding_ids: Iterable[str] = (),
    ):
        self.runtime = runtime
        self.ledger = ledger
        self.no_progress_limit = int(no_progress_limit)
        self.allowed_target_identities = set(allowed_target_identities)
        self.active_finding_ids = set(active_finding_ids)
        self.active_no_progress_limit = int(no_progress_limit)
        self.response_count = 0
        self.no_progress_responses = 0
        self.last_progress = self._snapshot()
        self.last_progress_response = 0

    def _snapshot(self) -> tuple[frozenset[str], frozenset[str], str]:
        verified_operations = frozenset(
            str(row.get("operation_id"))
            for row in self.runtime.journal.current_operations()
            if (
                operation_review_target(row) in self.allowed_target_identities
                and dict(row.get("receipt") or {}).get("status")
                in VERIFIED_STATUSES
            )
        )
        disposition_ids = frozenset(
            str(finding_id) for finding_id in self.ledger.dispositions
        )
        call_flow_digest = hashlib.sha256(canonical_json(
            self.runtime.journal.call_flow_fingerprint_state()
        ).encode("utf-8")).hexdigest()
        return verified_operations, disposition_ids, call_flow_digest

    def observe_response(self, _response: Mapping[str, Any]) -> None:
        self.response_count += 1

    def observe_tool_end(self, _tool_result: Mapping[str, Any]) -> None:
        self.check()

    def check(self) -> None:
        current = self._snapshot()
        if current != self.last_progress:
            self.last_progress = current
            self.last_progress_response = self.response_count
            self.no_progress_responses = 0
            return
        self.no_progress_responses = (
            self.response_count - self.last_progress_response
        )
        if self.no_progress_responses >= self.active_no_progress_limit:
            raise ApplicationWaveNoProgress(
                "Application wave made no target-bound verified edit or "
                "disposition for %d consecutive responses"
                % self.no_progress_responses
            )

    def model_guidance(self, tool_name: str) -> dict[str, Any] | None:
        if self.active_finding_ids:
            return application_feedback(self.ledger, sorted(self.active_finding_ids))
        no_progress = self.response_count - self.last_progress_response
        remaining = self.active_no_progress_limit - no_progress
        if remaining > 4 or remaining <= 0:
            return None
        return {
            "schema": "verified_ida.application_wave_progress.v1",
            "no_progress_responses": no_progress,
            "responses_remaining_before_stop": remaining,
            "ordinary_inspection_does_not_reset_window": True,
            "required_decision": (
                "Apply a supported edit or record a disposition. If another "
                "artifact must change, record one exact typed follow-up target."
            ),
        }


def _run_application_wave(
    *,
    runtime: VerifiedIdaRuntime,
    stage_dir: Path,
    wave: Mapping[str, Any],
    finding_rows: Mapping[str, Mapping[str, Any]],
    ledger: ReviewDispositionLedger,
    model: str,
    reasoning_effort: str,
    runaway_max_turns: int,
    no_progress_max_responses: int,
    application_session: Any,
    session_state: Mapping[str, Any],
) -> dict[str, Any]:
    from agents import Agent, RunErrorHandlerResult, Runner  # type: ignore

    stage_dir.mkdir(parents=True, exist_ok=False)
    wave_id = str(wave["wave_id"])
    wave_finding_ids = set(str(value) for value in wave["source_finding_ids"])
    findings = [
        (dict(finding_rows[value]) if value in ledger.dispositions else
         bind_application_finding_targets(finding_rows[value], runtime))
        for value in wave["source_finding_ids"]
    ]
    for finding in findings:
        # Permissions, progress accounting and disposition validation must all
        # use these same live-bound identities, not the old collection key.
        ledger.findings[str(finding["finding_id"])] = finding
    ledger._write()
    allowed_targets = [
        target
        for finding in findings
        for target in finding_review_targets(finding)
    ]
    if not allowed_targets:
        raise FinalReviewError(
            "Application wave has no host-validated artifact targets"
        )
    allowed_target_identities = {
        review_target_identity(target) for target in allowed_targets
    }
    allowed_component_ids = {
        str(target["component_id"]) for target in allowed_targets
    }
    if runtime.active_component_id not in allowed_component_ids:
        runtime.switch_component(
            sorted(allowed_component_ids)[0],
            checkpoint_current=True,
            remind=False,
        )
    operation_cutoff = runtime.journal.operation_cutoff()
    trace = ObservableTrace(stage_dir / "observable_tool_trace.jsonl")
    segment_id = _segment_id()
    tool_state = ToolInvocationState()
    hit_runaway_ceiling = False
    progress = _ApplicationWaveProgress(
        runtime=runtime,
        ledger=ledger,
        no_progress_limit=no_progress_max_responses,
        allowed_target_identities=allowed_target_identities,
        active_finding_ids=wave_finding_ids,
    )
    adapter = _ApplicationWaveToolAdapter(
        VerifiedIdaToolAdapter(runtime),
        allowed_component_ids=allowed_component_ids,
        allowed_target_identities=allowed_target_identities,
        progress_guidance=progress.model_guidance,
    )

    def _cap_handler(_handler_input: Any) -> RunErrorHandlerResult:
        nonlocal hit_runaway_ceiling
        hit_runaway_ceiling = True
        return RunErrorHandlerResult(
            final_output=(
                "The application wave reached its emergency request ceiling. "
                "Any undispositioned findings remain open."
            )
        )

    tools = _function_tools(
        adapter,
        trace,
        tool_state,
        segment_id,
        allowed_names=APPLICATION_TOOLS,
    )
    tools.append(_disposition_tool(
        ledger,
        trace,
        segment_id,
        allowed_finding_ids=wave_finding_ids,
    ))
    notebook = runtime.read_reversing_log(journal_limit=3)
    initial_journal_digest = str(
        dict(notebook.get("journal") or {}).get("digest") or ""
    )
    packet = {
        "schema": "verified_ida.final_review_application_wave.packet.v1",
        "wave": dict(wave),
        "objective": runtime.project_objective,
        "component_graph": runtime.list_components()["components"],
        "component_revisions": {
            str(row["component_id"]): int(
                runtime.journal.revision(str(row["component_id"]))["revision"]
            )
            for row in runtime.journal.components()
        },
        "notebook": {
            "document_digest": notebook.get("document_digest"),
            "current_state": notebook.get("current_state"),
            "recent_journal": dict(notebook.get("journal") or {}),
        },
        "session_continuity": dict(session_state),
        "findings": findings,
        "current_finding_state": application_feedback(ledger, wave["source_finding_ids"]),
        "requirements": {
            "all_current_wave_findings_must_be_dispositioned": True,
            "do_not_open_other_review_findings": True,
            "split_or_defer_if_scope_expands": True,
            "typed_follow_up_creates_later_wave": True,
            "live_current_evidence_required": True,
            "canonical_changes_only_through_verified_edits": True,
            "journal_checkpoint_required": True,
            "analysis_feedback_profile": "scoped",
            "done_when": (
                "Every current-wave finding has a recorded disposition and all "
                "accepted edits pass fresh persistence checkpoints, no current-"
                "wave mutation has an unresolved mechanical failure, and the "
                "investigation journal records the verified result."
            ),
            "request_ceiling_is_emergency_only": True,
            "allowed_component_ids": sorted(allowed_component_ids),
            "allowed_target_ids": sorted(
                str(target["target_id"]) for target in allowed_targets
            ),
        },
    }
    packet["packet_sha256"] = _json_sha256(packet)
    _write_json(stage_dir / "packet.json", packet)
    trace.append(
        "final_review_application_wave_started",
        segment_id=segment_id,
        actor="harness",
        stage="application_wave",
        wave_id=wave_id,
        model=model,
        finding_count=len(findings),
        packet_sha256=packet["packet_sha256"],
        allowed_tools=sorted(APPLICATION_TOOLS | {"record_review_disposition"}),
    )
    _progress(
        "final_review_application_wave_started",
        wave_id=wave_id,
        finding_count=len(findings),
        runaway_max_turns=runaway_max_turns,
        no_progress_max_responses=no_progress_max_responses,
    )
    agent = Agent(
        name="Verified IDA Final Review Primary Analyst — %s" % wave_id,
        model=model,
        model_settings=_model_settings(reasoning_effort, compact=True),
        instructions=PROMPTS["application"].read_text(encoding="utf-8"),
        tools=tools,
    )
    runner_input: Any = (
        "Verify and disposition every finding in this wave against current "
        "IDA state. Do not investigate another review finding. Apply only "
        "supported corrections; if current evidence identifies one different "
        "artifact that must be checked, record a typed follow-up for a later "
        "host-validated wave. Defer broader unresolved investigations. Read the current "
        "notebook, reacquire live IDA references, and append a journal entry "
        "after the wave decision. The wave is done only when every finding "
        "has a recorded disposition and the notebook records the result. The "
        "state-restoration and wave packet follows:\n\n%s"
        % json.dumps(packet, sort_keys=True, ensure_ascii=False)
    )
    result = None
    continuation_count = 0
    stop_reason = None
    while True:
        remaining_turns = runaway_max_turns - progress.response_count
        if remaining_turns <= 0:
            hit_runaway_ceiling = True
            stop_reason = "runaway_ceiling"
            break
        try:
            result = Runner.run_sync(
                agent,
                runner_input,
                session=application_session,
                run_config=model_run_config(application_session, trace, segment_id),
                max_turns=remaining_turns,
                hooks=_observable_hooks(
                    trace,
                    runtime,
                    session=application_session,
                    segment_id=segment_id,
                    compact_threshold_tokens=200_000,
                    on_response_end=progress.observe_response,
                    on_tool_end=progress.observe_tool_end,
                ),
                error_handlers={"max_turns": _cap_handler},
            )
            progress.check()
        except Exception as exc:
            cause: BaseException | None = exc
            while (
                cause is not None
                and not isinstance(cause, ApplicationWaveNoProgress)
            ):
                cause = cause.__cause__ or cause.__context__
            if not isinstance(cause, ApplicationWaveNoProgress):
                raise
            stop_reason = "no_progress"
            trace.append(
                "final_review_application_no_progress",
                segment_id=segment_id,
                actor="harness",
                stage="application_wave",
                wave_id=wave_id,
                response_count=progress.response_count,
                no_progress_responses=progress.no_progress_responses,
                message=str(cause),
            )
            break

        open_findings = sorted(
            wave_finding_ids & set(ledger.summary()["open_finding_ids"])
        )
        current_notebook = runtime.read_reversing_log(journal_limit=3)
        current_journal_digest = str(
            dict(current_notebook.get("journal") or {}).get("digest") or ""
        )
        journal_updated = current_journal_digest != initial_journal_digest
        mechanical_issues = _application_wave_mechanical_issues(
            runtime,
            operation_cutoff=operation_cutoff,
            allowed_target_identities=allowed_target_identities,
        )
        if not open_findings and not mechanical_issues and journal_updated:
            stop_reason = "state_complete"
            break
        if hit_runaway_ceiling:
            stop_reason = "runaway_ceiling"
            break

        continuation_count += 1
        current_operations = {
            str(row["operation_id"]): row
            for row in runtime.journal.current_operations()
            if int(row["operation_rowid"]) > operation_cutoff
        }
        continuation_packet = {
            "schema": "verified_ida.final_review_application_progress.v1",
            "wave_id": wave_id,
            "open_finding_ids": open_findings,
            "new_review_operations": [
                {
                    "operation_id": operation_id,
                    "component_id": row.get("component_id"),
                    "kind": row.get("kind"),
                    "target_key": row.get("target_key"),
                    "status": dict(row.get("receipt") or {}).get("status"),
                }
                for operation_id, row in sorted(current_operations.items())
            ],
            "current_wave_mechanical_failures": [
                {
                    "operation_id": row.get("operation_id"),
                    "component_id": row.get("component_id"),
                    "kind": row.get("kind"),
                    "target_key": row.get("target_key"),
                    "status": row.get("status"),
                    "stage": row.get("stage"),
                    "persistence": row.get("persistence"),
                    "recovery": dict(row.get("receipt") or {}).get("recovery"),
                }
                for row in mechanical_issues
            ],
            "responses_used": progress.response_count,
            "emergency_ceiling": runaway_max_turns,
            "journal_checkpoint_required": not journal_updated,
            "current_notebook_digest": current_notebook.get("document_digest"),
            "current_journal_digest": current_journal_digest,
            "done_when": packet["requirements"]["done_when"],
        }
        trace.append(
            "final_review_application_state_continued",
            segment_id=segment_id,
            actor="harness",
            stage="application_wave",
            wave_id=wave_id,
            continuation=continuation_count,
            open_finding_ids=open_findings,
            responses_used=progress.response_count,
        )
        runner_input = (
            "The wave is not done because findings remain undispositioned, a "
            "current-wave mutation still has an unresolved mechanical failure, "
            "or the required investigation-journal checkpoint is missing. "
            "Continue from live IDA state until the done condition is met. "
            "Do not broaden scope. Current host state:\n\n%s"
            % json.dumps(
                continuation_packet, sort_keys=True, ensure_ascii=False
            )
        )
    disposition_summary = ledger.summary()
    open_wave_findings = sorted(
        wave_finding_ids & set(disposition_summary["open_finding_ids"])
    )
    new_operations = runtime.journal.operations_after(operation_cutoff)
    final_notebook = runtime.read_reversing_log(journal_limit=3)
    final_journal_digest = str(
        dict(final_notebook.get("journal") or {}).get("digest") or ""
    )
    journal_updated = final_journal_digest != initial_journal_digest
    unresolved_mechanical_issues = _application_wave_mechanical_issues(
        runtime,
        operation_cutoff=operation_cutoff,
        allowed_target_identities=allowed_target_identities,
    )
    claimed_operation_ids = {
        str(operation_id)
        for finding_id in ledger.dispositions
        for operation_id in (
            ledger.dispositions.get(finding_id, {}).get("operation_ids") or []
        )
    }
    unaccounted_current_operations = [
        row
        for row in runtime.journal.current_operations()
        if str(row["operation_id"]) not in ledger.prior_operation_ids
        and operation_review_target(row) in allowed_target_identities
        and dict(row.get("receipt") or {}).get("status")
        in VERIFIED_STATUSES
        and str(row["operation_id"]) not in claimed_operation_ids
    ]
    affected_components = sorted(allowed_component_ids)
    checkpoints = [
        runtime.checkpoint_component(
            component_id,
            reason="final_review_wave_%s" % wave_id,
        )
        for component_id in affected_components
    ]
    checkpoint_failures = [
        row for row in checkpoints if row.get("status") != "verified"
    ]
    status = (
        "completed"
        if not open_wave_findings
        and not checkpoint_failures
        and not unresolved_mechanical_issues
        and not unaccounted_current_operations
        and journal_updated
        else "incomplete"
    )
    trace.append(
        "final_review_application_wave_completed",
        segment_id=segment_id,
        actor="harness",
        stage="application_wave",
        wave_id=wave_id,
        status=status,
        stop_reason=stop_reason,
        hit_runaway_ceiling=hit_runaway_ceiling,
        response_count=progress.response_count,
        no_progress_responses=progress.no_progress_responses,
        dispositions=disposition_summary,
        open_wave_finding_ids=open_wave_findings,
        checkpoints=checkpoints,
        unaccounted_current_operation_ids=[
            str(row["operation_id"])
            for row in unaccounted_current_operations
        ],
        unresolved_mechanical_operation_ids=[
            str(row["operation_id"]) for row in unresolved_mechanical_issues
        ],
        journal_updated=journal_updated,
        initial_journal_digest=initial_journal_digest,
        final_journal_digest=final_journal_digest,
    )
    walkthrough = write_walkthrough(trace, stage_dir / "walkthrough.md")
    events, parse_errors = trace.read()
    summary = {
        "schema": "verified_ida.final_review_application_wave_summary.v1",
        "status": status,
        "wave_id": wave_id,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "runaway_max_turns": runaway_max_turns,
        "no_progress_max_responses": no_progress_max_responses,
        "response_count": progress.response_count,
        "no_progress_responses": progress.no_progress_responses,
        "active_no_progress_limit": progress.active_no_progress_limit,
        "continuation_count": continuation_count,
        "stop_reason": stop_reason,
        "hit_runaway_ceiling": hit_runaway_ceiling,
        "usage": aggregate_usage(events),
        "event_counts": event_counts(events),
        "trace_parse_errors": parse_errors,
        "dispositions": disposition_summary,
        "open_wave_finding_ids": open_wave_findings,
        "unaccounted_current_operations": [
            {
                "operation_id": row.get("operation_id"),
                "component_id": row.get("component_id"),
                "kind": row.get("kind"),
                "target_key": row.get("target_key"),
                "surface_key": row.get("surface_key"),
            }
            for row in unaccounted_current_operations
        ],
        "unresolved_mechanical_operations": [
            {
                "operation_id": row.get("operation_id"),
                "component_id": row.get("component_id"),
                "kind": row.get("kind"),
                "target_key": row.get("target_key"),
                "status": row.get("status"),
                "stage": row.get("stage"),
                "persistence": row.get("persistence"),
            }
            for row in unresolved_mechanical_issues
        ],
        "notebook_checkpoint": {
            "updated": journal_updated,
            "initial_document_digest": notebook.get("document_digest"),
            "final_document_digest": final_notebook.get("document_digest"),
            "initial_journal_digest": initial_journal_digest,
            "final_journal_digest": final_journal_digest,
            "recent_journal": dict(final_notebook.get("journal") or {}),
        },
        "session_continuity": dict(session_state),
        "operation_history": [
            {
                "operation_id": row.get("operation_id"),
                "component_id": row.get("component_id"),
                "kind": row.get("kind"),
                "target_key": row.get("target_key"),
                "surface_key": row.get("surface_key"),
                "status": dict(row.get("receipt") or {}).get("status"),
            }
            for row in new_operations
        ],
        "new_verified_operations": [
            {
                "operation_id": row.get("operation_id"),
                "component_id": row.get("component_id"),
                "kind": row.get("kind"),
                "target_key": row.get("target_key"),
                "surface_key": row.get("surface_key"),
                "status": dict(row.get("receipt") or {}).get("status"),
            }
            for row in new_operations
            if dict(row.get("receipt") or {}).get("status")
            in VERIFIED_STATUSES
        ],
        "checkpoints": checkpoints,
        "final_output": str(result.final_output or "") if result is not None else "",
        "walkthrough": walkthrough,
    }
    _write_json(stage_dir / "summary.json", summary)
    _progress(
        "final_review_application_wave_completed",
        wave_id=wave_id,
        status=status,
        disposition_count=disposition_summary["disposition_count"],
        open_wave_finding_count=len(open_wave_findings),
        total_tokens=int(summary["usage"].get("total_tokens") or 0),
    )
    return summary


def _retry_reconciliation_checkpoints(
    runtime: VerifiedIdaRuntime, trace: ObservableTrace, segment_id: str,
) -> list[dict[str, Any]]:
    """Refresh known failures before the analyst describes current closure state."""
    results = []
    for previous in runtime.completion_status().get("component_verification_failures") or []:
        budget = ACTIVE_REVIEW_BUDGET.get()
        if budget is not None:
            budget.check("before_reconciliation_checkpoint_retry")
        current = runtime.checkpoint_component(
            str(previous["component_id"]), reason="before_closure_reconciliation",
        )
        result = {"previous_checkpoint_id": previous["checkpoint_id"], "checkpoint": current}
        results.append(result)
        trace.append("final_review_checkpoint_retry", actor="harness",
                     segment_id=segment_id, **result)
        if budget is not None:
            budget.check("after_reconciliation_checkpoint_retry")
        if current.get("status") != "verified":
            raise FinalReviewError(
                "Component %s still fails persistence verification; reconcile its "
                "checkpoint errors before model closure finalization"
                % previous["component_id"]
            )
    return results


def _run_application_reconciliation(
    *,
    runtime: VerifiedIdaRuntime,
    stage_dir: Path,
    ledger: ReviewDispositionLedger,
    model: str,
    reasoning_effort: str,
    application_session: Any,
    session_state: Mapping[str, Any],
    runaway_max_turns: int = 48,
) -> dict[str, Any]:
    """Reconcile completed review waves with the protected closure record."""

    from agents import Agent, RunErrorHandlerResult, Runner  # type: ignore

    stage_dir.mkdir(parents=True, exist_ok=False)
    trace = ObservableTrace(stage_dir / "observable_tool_trace.jsonl")
    segment_id = _segment_id()
    tool_state = ToolInvocationState()
    hit_runaway_ceiling = False
    checkpoint_retries = _retry_reconciliation_checkpoints(runtime, trace, segment_id)

    def _cap_handler(_handler_input: Any) -> RunErrorHandlerResult:
        nonlocal hit_runaway_ceiling
        hit_runaway_ceiling = True
        return RunErrorHandlerResult(
            final_output=(
                "The final closure reconciliation reached its emergency "
                "request ceiling before the host verified completion."
            )
        )

    tools = _function_tools(
        VerifiedIdaToolAdapter(runtime),
        trace,
        tool_state,
        segment_id,
        allowed_names=APPLICATION_RECONCILIATION_TOOLS,
    )
    notebook = runtime.read_reversing_log(journal_limit=3)
    initial_journal_digest = str(
        dict(notebook.get("journal") or {}).get("digest") or ""
    )
    closure = runtime.review_analysis_closure()
    compact_dispositions = [
        {
            "finding_id": finding_id,
            "outcome": row.get("outcome"),
            "rationale": row.get("rationale"),
            "evidence_refs": list(row.get("evidence_refs") or []),
            "operation_ids": list(row.get("operation_ids") or []),
        }
        for finding_id, row in sorted(ledger.dispositions.items())
    ]
    packet = {
        "schema": "verified_ida.final_review_application_reconciliation.packet.v1",
        "objective": runtime.project_objective,
        "component_graph": runtime.list_components()["components"],
        "component_revisions": _component_revisions(runtime),
        "notebook": {
            "document_digest": notebook.get("document_digest"),
            "current_state": notebook.get("current_state"),
            "recent_journal": dict(notebook.get("journal") or {}),
        },
        "session_continuity": dict(session_state),
        "checkpoint_retries": checkpoint_retries,
        "dispositions": compact_dispositions,
        "closure": closure,
        "requirements": {
            "all_review_findings_already_dispositioned": True,
            "do_not_reopen_findings": True,
            "do_not_edit_ida": True,
            "closure_review_updated_after_fresh_packet": True,
            "journal_checkpoint_required": True,
            "mechanical_state_authority": (
                "Use current closure status and checkpoint retry receipts, not "
                "historical failures. Remove resolved mechanical blockers from "
                "Current Project State; preserve their history in the journal. "
                "Final persistence verification still follows reconciliation."
            ),
            "done_when": (
                "The notebook reflects every review disposition, the Closure "
                "Review section reconciles the latest live closure packet, "
                "and the Investigation Journal records final review closure."
            ),
            "request_ceiling_is_emergency_only": True,
        },
    }
    packet["packet_sha256"] = _json_sha256(packet)
    _write_json(stage_dir / "packet.json", packet)
    trace.append(
        "final_review_application_reconciliation_started",
        segment_id=segment_id,
        actor="harness",
        stage="application_reconciliation",
        model=model,
        disposition_count=len(compact_dispositions),
        packet_sha256=packet["packet_sha256"],
        allowed_tools=sorted(APPLICATION_RECONCILIATION_TOOLS),
    )
    _progress(
        "final_review_application_reconciliation_started",
        disposition_count=len(compact_dispositions),
        runaway_max_turns=runaway_max_turns,
    )
    agent = Agent(
        name="Verified IDA Final Review Closure Reconciliation",
        model=model,
        model_settings=_model_settings(reasoning_effort, compact=True),
        instructions=PROMPTS["application_reconciliation"].read_text(
            encoding="utf-8"
        ),
        tools=tools,
    )
    runner_input: Any = (
        "Reconcile the completed review dispositions with the current project "
        "notebook and live IDA state. Do not reopen a finding or make an IDA "
        "edit. Update non-closure analytical state first if it is inaccurate, "
        "then acquire a fresh closure packet, update Closure Review last, and "
        "append one final-review journal entry. The state-restoration packet "
        "follows:\n\n%s"
        % json.dumps(packet, sort_keys=True, ensure_ascii=False)
    )
    result = None
    continuation_count = 0
    completion: dict[str, Any] = runtime.completion_status()
    while True:
        events, _parse_errors = trace.read()
        response_count = sum(
            row.get("event") == "model_response" for row in events
        )
        remaining_turns = runaway_max_turns - response_count
        if remaining_turns <= 0:
            hit_runaway_ceiling = True
            break
        result = Runner.run_sync(
            agent,
            runner_input,
            session=application_session,
            run_config=model_run_config(application_session, trace, segment_id),
            max_turns=remaining_turns,
            hooks=_observable_hooks(
                trace,
                runtime,
                session=application_session,
                segment_id=segment_id,
                compact_threshold_tokens=200_000,
            ),
            error_handlers={"max_turns": _cap_handler},
        )
        final_notebook = runtime.read_reversing_log(journal_limit=3)
        final_journal_digest = str(
            dict(final_notebook.get("journal") or {}).get("digest") or ""
        )
        journal_updated = final_journal_digest != initial_journal_digest
        completion = runtime.complete()
        if completion.get("may_finish") and journal_updated:
            break
        if hit_runaway_ceiling or continuation_count >= 2:
            break
        reconciliation = dict(
            completion.get("closure_reconciliation") or {}
        )
        if reconciliation.get("ready") and not completion.get("may_finish"):
            # A non-closure mechanical blocker cannot be repaired by a prose-only
            # reconciliation stage.
            break
        continuation_count += 1
        closure = runtime.review_analysis_closure()
        runner_input = (
            "The final reconciliation is not current yet. Do not reopen review "
            "findings or edit IDA. Satisfy the exact host next action, update "
            "Closure Review against this fresh packet, and ensure the final "
            "review journal checkpoint exists. Host status:\n\n%s\n\n"
            "Fresh closure packet:\n\n%s"
            % (
                json.dumps(completion, sort_keys=True, ensure_ascii=False),
                json.dumps(closure, sort_keys=True, ensure_ascii=False),
            )
        )

    final_notebook = runtime.read_reversing_log(journal_limit=3)
    final_journal_digest = str(
        dict(final_notebook.get("journal") or {}).get("digest") or ""
    )
    journal_updated = final_journal_digest != initial_journal_digest
    status = (
        "completed"
        if completion.get("may_finish") and journal_updated
        else "incomplete"
    )
    trace.append(
        "final_review_application_reconciliation_completed",
        segment_id=segment_id,
        actor="harness",
        stage="application_reconciliation",
        status=status,
        continuation_count=continuation_count,
        hit_runaway_ceiling=hit_runaway_ceiling,
        journal_updated=journal_updated,
        closure_reconciliation=completion.get("closure_reconciliation"),
    )
    walkthrough = write_walkthrough(trace, stage_dir / "walkthrough.md")
    events, parse_errors = trace.read()
    summary = {
        "schema": "verified_ida.final_review_application_reconciliation_summary.v1",
        "status": status,
        "model": model,
        "reasoning_effort": reasoning_effort,
        "runaway_max_turns": runaway_max_turns,
        "continuation_count": continuation_count,
        "hit_runaway_ceiling": hit_runaway_ceiling,
        "usage": aggregate_usage(events),
        "event_counts": event_counts(events),
        "trace_parse_errors": parse_errors,
        "notebook_checkpoint": {
            "updated": journal_updated,
            "initial_journal_digest": initial_journal_digest,
            "final_journal_digest": final_journal_digest,
        },
        "completion": completion,
        "final_output": str(result.final_output or "") if result is not None else "",
        "walkthrough": walkthrough,
    }
    _write_json(stage_dir / "summary.json", summary)
    _progress(
        "final_review_application_reconciliation_completed",
        status=status,
        continuation_count=continuation_count,
        total_tokens=int(summary["usage"].get("total_tokens") or 0),
    )
    return summary


def _run_application_waves(
    *,
    runtime: VerifiedIdaRuntime,
    output_dir: Path,
    review_index: Mapping[str, Any],
    plan: Mapping[str, Any],
    model: str,
    reasoning_effort: str,
    runaway_max_turns: int,
    no_progress_max_responses: int = 40,
    application_session: Any = None,
    session_state: Mapping[str, Any] | None = None,
    resume: bool = False,
    legacy_operations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    stage_dir = output_dir / "application"
    stage_dir.mkdir(parents=True, exist_ok=resume)
    plan_path = stage_dir / "execution_plan.json"
    if resume:
        if json.loads(plan_path.read_text(encoding="utf-8")) != dict(plan):
            raise FinalReviewError("Cannot replace the saved execution plan on resume")
    else:
        _write_json(plan_path, dict(plan))
    baseline = application_baseline(
        stage_dir / "baseline.json", runtime=runtime, review_index=review_index,
        plan=plan, resume=resume, legacy_operations=legacy_operations,
    )
    attempts_dir = stage_dir / "attempts"
    attempts_dir.mkdir(exist_ok=True)
    attempt_dir = attempts_dir / ("attempt-%03d" % (len(list(attempts_dir.iterdir())) + 1))
    attempt_dir.mkdir(exist_ok=False)
    _write_json(attempt_dir / "started.json", {
        "resume": resume, "source": describe_source(ida_backend="process"),
        "baseline": baseline, "component_hashes": project_component_hashes(runtime.workspace),
    })
    for name in ("dispositions.json", "summary.json", "progress.json"):
        existing = stage_dir / name
        if existing.exists():
            _write_json(attempt_dir / ("prior_" + name), json.loads(existing.read_text()))
    for path, name in ((output_dir.parent / "summary.json", "prior_run_summary.json"),
                       (output_dir / "post_application_audit.json", "prior_post_application_audit.json")):
        if path.exists():
            _write_json(attempt_dir / name, json.loads(path.read_text()))
    identity = _session_identity(runtime.workspace)
    if application_session is None:
        application_session = _session(runtime.workspace)
    initial_message_count = _session_message_count(
        runtime.workspace,
        str(identity["session_id"]),
    )
    effective_session_state = {
        "schema": "verified_ida.final_review_session_continuity.v1",
        "session_id": str(identity["session_id"]),
        "identity_source": str(identity["source"]),
        "session_database": str(
            (runtime.workspace / "model_session.sqlite").resolve()
        ),
        "initial_message_count": initial_message_count,
        "resumed_original_investigation": initial_message_count > 0,
        **dict(session_state or {}),
    }
    source_findings = {
        str(row["source_finding_id"]): dict(row)
        for row in review_index.get("source_findings") or []
    }
    scheduled_ids = [
        source_id
        for wave in plan.get("waves") or []
        for source_id in wave.get("source_finding_ids") or []
    ]
    ledger_findings = [
        {
            "finding_id": source_id,
            "source_finding": source_findings[source_id],
        }
        for source_id in scheduled_ids
    ]
    prior_operation_ids = {row["operation_id"] for row in baseline["operations"]}
    ledger_factory = ReviewDispositionLedger.resume if resume else ReviewDispositionLedger
    ledger = ledger_factory(
        path=stage_dir / "dispositions.json",
        findings=ledger_findings,
        runtime=runtime,
        prior_operation_ids=prior_operation_ids,
        **({"allow_legacy": bool(baseline.get("legacy_import"))} if resume else {}),
    )
    progress_path = stage_dir / "progress.json"
    progress_state = json.loads(progress_path.read_text()) if progress_path.exists() else {"completed_finding_ids": []}
    completed_ids = set(progress_state["completed_finding_ids"])
    if completed_ids - set(ledger.dispositions):
        raise FinalReviewError("Completed application units have missing dispositions")
    wave_rows = []
    stopped_wave_id = None
    pending_waves = focused_application_waves(plan.get("waves") or [])
    initial_execution_unit_count = len(pending_waves)
    scheduled_ids = {
        str(source_id)
        for wave in pending_waves
        for source_id in wave.get("source_finding_ids") or []
    }
    for follow_up_id in ledger.follow_up_finding_ids():
        if follow_up_id not in scheduled_ids:
            scheduled_ids.add(follow_up_id)
            pending_waves.append({"wave_id": "follow-up-%s" % follow_up_id.rsplit(":", 1)[-1],
                                  "source_finding_ids": [follow_up_id], "origin": "application_follow_up"})
    index = 0
    while index < len(pending_waves):
        wave = pending_waves[index]
        index += 1
        wave_id = str(wave["wave_id"])
        if set(wave["source_finding_ids"]) <= completed_ids:
            continue
        safe_name = "%02d-%s" % (
            index,
            "".join(
                character if character.isalnum() or character in "-_" else "-"
                for character in wave_id
            )[:80],
        )
        result = _run_application_wave(
            runtime=runtime,
            stage_dir=attempt_dir / "waves" / safe_name,
            wave=wave,
            finding_rows={
                source_id: ledger.findings[source_id]
                for source_id in wave["source_finding_ids"]
            },
            ledger=ledger,
            model=model,
            reasoning_effort=reasoning_effort,
            runaway_max_turns=runaway_max_turns,
            no_progress_max_responses=no_progress_max_responses,
            application_session=application_session,
            session_state=effective_session_state,
        )
        wave_rows.append(result)
        if result["status"] != "completed":
            stopped_wave_id = wave_id
            break
        completed_ids.update(wave["source_finding_ids"])
        _write_json(progress_path, {"completed_finding_ids": sorted(completed_ids)})
        for follow_up_id in ledger.follow_up_finding_ids():
            if follow_up_id in scheduled_ids:
                continue
            scheduled_ids.add(follow_up_id)
            pending_waves.append({
                "wave_id": "follow-up-%s" % follow_up_id.rsplit(":", 1)[-1],
                "source_finding_ids": [follow_up_id],
                "rationale": (
                    "Host-validated artifact boundary discovered while applying "
                    "an earlier review finding."
                ),
                "origin": "application_follow_up",
            })

    disposition_summary = ledger.summary()
    blocking_finding_ids = review_completion_blockers(ledger.findings, ledger.dispositions, plan)
    reconciliation = None
    completion = runtime.completion_status()
    status = (
        "completed"
        if stopped_wave_id is None and not blocking_finding_ids
        else "incomplete"
    )
    if status == "completed":
        reconciliation = _run_application_reconciliation(
            runtime=runtime,
            stage_dir=attempt_dir / "reconciliation",
            ledger=ledger,
            model=model,
            reasoning_effort=reasoning_effort,
            application_session=application_session,
            session_state=effective_session_state,
        )
        completion = dict(reconciliation.get("completion") or {})
        if reconciliation.get("status") != "completed":
            status = "incomplete"
    effective_session_state["final_message_count"] = _session_message_count(
        runtime.workspace,
        str(effective_session_state["session_id"]),
    )
    summary = {
        "schema": "verified_ida.final_review_application_waves_summary.v1",
        "status": status,
        "attempt_dir": str(attempt_dir),
        "resumed": resume,
        "completed_finding_ids": sorted(completed_ids),
        "model": model,
        "reasoning_effort": reasoning_effort,
        "wave_count_planned": len(pending_waves),
        "wave_count_initial": len(list(plan.get("waves") or [])),
        "execution_unit_count_initial": initial_execution_unit_count,
        "follow_up_wave_count": len(pending_waves) - initial_execution_unit_count,
        "wave_count_completed": sum(row["status"] == "completed" for row in wave_rows),
        "stopped_wave_id": stopped_wave_id,
        "blocking_finding_ids": blocking_finding_ids,
        "waves": wave_rows,
        "reconciliation": reconciliation,
        "dispositions": disposition_summary,
        "completion": completion,
        "session_continuity": effective_session_state,
        "usage": _combined_usage(
            wave_rows + ([reconciliation] if reconciliation is not None else [])
        ),
    }
    _write_json(attempt_dir / "summary.json", summary)
    _write_json(stage_dir / "summary.json", summary)
    return summary


def _component_revisions(runtime: VerifiedIdaRuntime) -> dict[str, int]:
    return {
        str(row["component_id"]): int(
            runtime.journal.revision(str(row["component_id"]))["revision"]
        )
        for row in runtime.journal.components()
    }


def _preflight_summary(preflight: Mapping[str, Any]) -> dict[str, Any]:
    exact = dict(preflight.get("exact_measurements") or {})
    type_rows = list(exact.get("named_type_application") or [])
    relationship_rows = list(exact.get("relationship_endpoint_integrity") or [])
    return {
        "mechanical_failure_count": len(
            list(exact.get("current_mechanical_failures") or [])
        ),
        "named_type_count": len(type_rows),
        "declaration_only_type_count": sum(
            row.get("status") == "declaration_only_currently" for row in type_rows
        ),
        "measured_type_use_count": sum(
            int(row.get("measured_use_count") or 0) for row in type_rows
        ),
        "relationship_count": len(relationship_rows),
        "relationship_measurement_status": (
            "measured" if relationship_rows else "none_submitted"
        ),
        "relationship_missing_endpoint_count": sum(
            row.get("measured_status") == "missing_endpoint"
            for row in relationship_rows
        ),
    }


def _write_post_audit(
    *,
    source_project: Path,
    project_dir: Path,
    output_dir: Path,
    runtime: VerifiedIdaRuntime,
    before: Mapping[str, Any],
    after_packets: Mapping[str, Any],
    application: Mapping[str, Any],
) -> dict[str, Any]:
    after_operation_ids = {
        str(row["operation_id"]): row for row in runtime.journal.current_operations()
    }
    prior_ids = set(before["operation_ids"])
    new_operations = [
        row for operation_id, row in after_operation_ids.items()
        if operation_id not in prior_ids
    ]
    clone_manifest = json.loads(
        (project_dir / "final_review_clone_manifest.json").read_text(encoding="utf-8")
    )
    source_hashes_now = project_component_hashes(source_project)
    source_hashes_expected = {
        "%s:%s" % (row["component_id"], row["kind"]): row["sha256"]
        for row in clone_manifest["source_component_files"]
    }
    audit = {
        "schema": "verified_ida.final_review_post_application_audit.v1",
        "status": (
            "completed"
            if application.get("status") == "completed"
            and source_hashes_now == source_hashes_expected
            else "incomplete"
        ),
        "canonical_source_unchanged": source_hashes_now == source_hashes_expected,
        "component_revisions_before": dict(before["component_revisions"]),
        "component_revisions_after": _component_revisions(runtime),
        "component_hashes_before_application": dict(before["component_hashes"]),
        "component_hashes_after_application": project_component_hashes(project_dir),
        "preflight_before": _preflight_summary(before["preflight"]),
        "preflight_after": _preflight_summary(after_packets["preflight"]),
        "new_verified_operations": [
            {
                "operation_id": row.get("operation_id"),
                "component_id": row.get("component_id"),
                "kind": row.get("kind"),
                "target_kind": row.get("target_kind"),
                "target_key": row.get("target_key"),
                "status": dict(row.get("receipt") or {}).get("status"),
            }
            for row in new_operations
            if dict(row.get("receipt") or {}).get("status") in VERIFIED_STATUSES
        ],
        "application": dict(application),
    }
    _write_json(output_dir / "post_application_audit.json", audit)
    return audit


def _combined_usage(stage_summaries: list[Mapping[str, Any]]) -> dict[str, int]:
    keys = (
        "cached_input_tokens", "input_tokens", "output_tokens",
        "reasoning_output_tokens", "requests", "total_tokens",
    )
    return {
        key: sum(
            int(dict(row.get("usage") or {}).get(key) or 0)
            for row in stage_summaries
        )
        for key in keys
    }


def _session_message_count(project_dir: Path, session_id: str) -> int:
    """Count persisted SDK items without loading the transcript into memory."""

    database = project_dir / "model_session.sqlite"
    if not database.is_file():
        return 0
    with sqlite3.connect(str(database)) as connection:
        table = connection.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type = 'table' AND name = 'agent_messages'"
        ).fetchone()
        if not table:
            return 0
        row = connection.execute(
            "SELECT COUNT(*) FROM agent_messages WHERE session_id = ?",
            (str(session_id),),
        ).fetchone()
    return int(row[0]) if row else 0


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(list(argv or sys.argv[1:]))
    return run_budgeted_review(arguments, _run, resume=arguments.resume_application)


def _run(arguments: argparse.Namespace) -> int:
    lifecycle: dict[str, Any] = {"phase": "initialization"}
    try:
        if getattr(arguments, "resume_application", False):
            return _resume_application(arguments, lifecycle)
        return _run_stages(arguments, lifecycle)
    except (Exception, KeyboardInterrupt) as exc:
        _write_review_failure(arguments, lifecycle, exc)
        raise


def _write_review_failure(
    arguments: argparse.Namespace,
    lifecycle: Mapping[str, Any],
    exc: BaseException,
) -> None:
    """A setup/cleanup failure is not a completed review, even after collection."""
    from verified_ida.safety_budget import SafetyBudgetExceeded

    cause = exc
    seen: set[int] = set()
    budget_stop = False
    while cause is not None and id(cause) not in seen:
        seen.add(id(cause))
        if isinstance(cause, SafetyBudgetExceeded):
            budget_stop = True
            break
        cause = cause.__cause__ or cause.__context__
    run_dir = arguments.run_dir.expanduser().resolve()
    summary = {
        "schema": "verified_ida.final_review_run_summary.v1",
        "status": "stopped_budget" if budget_stop else "failed",
        "phase": lifecycle["phase"],
        "analytical_completion": False,
        "completion": {"may_finish": False},
        "error": {"type": type(exc).__name__, "message": str(exc)},
        "cleanup_errors": list(lifecycle.get("cleanup_errors") or []),
        "source": lifecycle.get("source"),
        "source_project": str(arguments.source_project_dir.expanduser().resolve()),
        "project_dir": str(run_dir / "project"),
        "review_dir": str(run_dir / "review"),
        "outstanding_work": "Retained in review reports and the disposition ledger; not declared resolved.",
    }
    try:
        _write_json(run_dir / "summary.json", summary)
        project_summary_path = run_dir / "project" / "run_summary.json"
        if project_summary_path.is_file():
            prior = json.loads(project_summary_path.read_text(encoding="utf-8"))
            prior.setdefault("pre_review_completion", prior.get("completion"))
            prior.update(status=summary["status"], final_review=summary,
                         completion={"may_finish": False})
            _write_json(project_summary_path, prior)
    except Exception as secondary:
        # Failure reporting must never replace the original exception.
        print("Unable to persist review failure: %s" % secondary, file=sys.stderr)


def _application_resume_summary(
    *, previous: Mapping[str, Any], application: Mapping[str, Any],
    audit: Mapping[str, Any], source: Mapping[str, Any], review_usage: Mapping[str, Any],
) -> dict[str, Any]:
    # The full previous result is archived separately, including setup failures.
    # Do not carry its error into a successfully executed resumed stage, or derive
    # cumulative usage from a failure summary that may contain no usage at all.
    summary = {key: value for key, value in previous.items()
               if key not in {"error", "cleanup_errors", "outstanding_work"}}
    summary.update(status=audit["status"], phase="application_resume",
                   resume_source=dict(source), application=dict(application),
                   post_application_audit=dict(audit),
                   analytical_completion=audit["status"] == "completed",
                   completion={**dict(application.get("completion") or {}),
                               "may_finish": audit["status"] == "completed"},
                   review_usage=dict(review_usage))
    return summary


def _resume_application(arguments: argparse.Namespace, lifecycle: dict[str, Any]) -> int:
    """Continue the saved candidate/session with the original review allowance."""
    from agents import set_tracing_disabled
    from verified_ida.commands.finalize_review import _load_json, _source_is_unchanged

    set_tracing_disabled(True)
    run_dir = arguments.run_dir.expanduser().resolve()
    output_dir = run_dir / "review"
    project_dir = run_dir / "project"
    source_project = arguments.source_project_dir.expanduser().resolve()
    unchanged, recorded_source = _source_is_unchanged(project_dir)
    if not unchanged or source_project != Path(recorded_source):
        raise FinalReviewError("Resume source differs from the frozen reviewed project")
    collection = _load_json(output_dir / "collection_summary.json")
    if collection.get("status") != "completed":
        raise FinalReviewError("Cannot resume application before collection completes")
    review_index = _load_json(output_dir / "consolidation" / "review_index.json")
    plan = _load_json(output_dir / "application" / "execution_plan.json")
    previous = _load_json(run_dir / "summary.json")
    application_record = _load_json(output_dir / "application" / "summary.json")
    if (application_record.get("model") != arguments.model
            or application_record.get("reasoning_effort") != arguments.reasoning_effort):
        raise FinalReviewError("Resume must retain the reviewed model configuration")
    legacy_operations = None
    if not (output_dir / "application" / "baseline.json").exists():
        if not arguments.import_legacy_baseline:
            raise FinalReviewError("Use --import-legacy-baseline after preserving the stopped review")
        database = source_project / "verified_ida.sqlite"
        with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
            connection.row_factory = sqlite3.Row
            legacy_operations = [dict(row) for row in connection.execute(
                "SELECT operation_id, operation_digest FROM operations ORDER BY rowid")]
    lifecycle.update(phase="application_resume", source=describe_source(ida_backend="process"))
    runtime = VerifiedIdaRuntime.initialize(project_dir, analysis_feedback_profile="scoped")
    try:
        checkpoints = [runtime.checkpoint_component(str(row["component_id"]), reason="before_application_resume")
                       for row in runtime.journal.components()]
        if any(row.get("status") != "verified" for row in checkpoints):
            raise FinalReviewError("Saved application candidate failed persistence before resume")
        application = _run_application_waves(
            runtime=runtime, output_dir=output_dir, review_index=review_index, plan=plan,
            model=arguments.model, reasoning_effort=arguments.reasoning_effort,
            runaway_max_turns=arguments.application_runaway_max_turns,
            no_progress_max_responses=arguments.application_no_progress_max_responses,
            resume=True, legacy_operations=legacy_operations,
        )
        baseline = _load_json(output_dir / "application" / "baseline.json")
        prior_audit = _load_json(output_dir / "post_application_audit.json") if (output_dir / "post_application_audit.json").exists() else {}
        before = {
            "operation_ids": [row["operation_id"] for row in baseline["operations"]],
            "component_revisions": prior_audit.get("component_revisions_before", {}),
            "component_hashes": prior_audit.get("component_hashes_before_application", {}),
            "preflight": _load_json(output_dir / "preflight.json"),
        }
        lifecycle["phase"] = "post_application_resume_audit"
        post_closure = load_current_recorded_closure(runtime) or runtime.review_analysis_closure()
        post_packets = build_final_review_packets(runtime, post_closure)
        attempt_dir = Path(application["attempt_dir"])
        _write_json(attempt_dir / "prior_run_summary.json", previous)
        if prior_audit:
            _write_json(attempt_dir / "prior_post_application_audit.json", prior_audit)
        audit = _write_post_audit(source_project=source_project, project_dir=project_dir,
            output_dir=output_dir, runtime=runtime, before=before,
            after_packets=post_packets, application=application)
        summary = _application_resume_summary(
            previous=previous, application=application, audit=audit,
            source=lifecycle["source"],
            review_usage=_load_json(run_dir / "review_safety_budget.json")["usage"],
        )
        _write_json(attempt_dir / "run_summary.json", summary)
        operation_summary = runtime.journal.operation_summary()
        lifecycle["phase"] = "cleanup"
    finally:
        primary_error = sys.exc_info()[1]
        try:
            runtime.close()
        except Exception as cleanup:
            if primary_error is None:
                raise
            lifecycle.setdefault("cleanup_errors", []).append({
                "type": type(cleanup).__name__, "message": str(cleanup),
            })
    _write_json(run_dir / "summary.json", summary)
    project_summary = _load_json(project_dir / "run_summary.json")
    project_summary.update(status="completed" if audit["status"] == "completed" else "stopped",
                           completion=summary["completion"], final_review=summary,
                           operations=operation_summary)
    _write_json(project_dir / "run_summary.json", project_summary)
    print(json.dumps({"status": summary["status"], "application": application}, indent=2))
    return 0 if audit["status"] == "completed" else 2


def _run_stages(arguments: argparse.Namespace, lifecycle: dict[str, Any]) -> int:
    environment = _environment()
    source_provenance = describe_source(ida_backend="process")
    lifecycle.update(phase="clone", source=source_provenance)
    source_project = arguments.source_project_dir.expanduser().resolve()
    run_dir = arguments.run_dir.expanduser().resolve()
    project_dir = run_dir / "project"
    output_dir = run_dir / "review"
    output_dir.mkdir()
    clone_manifest = clone_verified_project(source_project, project_dir)

    from agents import set_tracing_disabled  # type: ignore

    set_tracing_disabled(True)
    runtime = None
    try:
        lifecycle["phase"] = "preflight"
        preflight_stage_dir = output_dir / "preflight_stage"
        preflight_stage_dir.mkdir()
        master_hashes_before = project_component_hashes(project_dir)
        preflight_project = preflight_stage_dir / "project"
        clone_verified_project(project_dir, preflight_project)
        preflight_runtime = VerifiedIdaRuntime.initialize(
            preflight_project,
            analysis_feedback_profile="none",
            read_only_mode=True,
        )
        preflight_semantic_before = semantic_project_snapshot(preflight_runtime)
        try:
            closure = load_current_recorded_closure(preflight_runtime)
            if closure is None:
                closure = preflight_runtime.review_analysis_closure()
            packets = build_final_review_packets(preflight_runtime, closure)
            preflight_evidence_registry = _evidence_registry_for_value(
                preflight_runtime,
                packets,
                stage="preflight",
                lane="host_packet",
                origin="host_preflight_packet",
            )
        finally:
            preflight_runtime.close()
        preflight_verifier = VerifiedIdaRuntime.initialize(
            preflight_project,
            analysis_feedback_profile="none",
            read_only_mode=True,
        )
        try:
            preflight_semantic_after = semantic_project_snapshot(
                preflight_verifier
            )
        finally:
            preflight_verifier.close()
        preflight_semantic_boundary = verify_semantic_stage_boundary(
            preflight_semantic_before, preflight_semantic_after
        )
        master_hashes_after = project_component_hashes(project_dir)
        if master_hashes_before != master_hashes_after:
            raise FinalReviewError(
                "Read-only preflight changed the application project"
            )
        _write_json(output_dir / "preflight.json", packets["preflight"])
        _write_json(
            output_dir / "preflight_evidence_registry.json",
            preflight_evidence_registry,
        )
        _write_json(output_dir / "claim_lane_packets.json", packets["claim_lanes"])
        _write_json(output_dir / "system_model_packet.json", packets["system_model"])
        _write_json(
            output_dir / "artifact_coverage_packet.json",
            packets["artifact_coverage"],
        )
        preparation = {
            "schema": "verified_ida.final_review_preparation.v1",
            "source_project": str(source_project),
            "project_dir": str(project_dir),
            "review_dir": str(output_dir),
            "source": source_provenance,
            "clone": clone_manifest,
            "preflight_sha256": packets["preflight"]["packet_sha256"],
            "preflight_summary": _preflight_summary(packets["preflight"]),
            "isolation": {
                "disposable_project": str(preflight_project),
                "application_project_hashes_unchanged": True,
                "sessions_closed_without_save": True,
                "semantic_boundary": preflight_semantic_boundary,
            },
        }
        _write_json(output_dir / "preparation.json", preparation)
        _progress(
            "final_review_preflight_completed",
            **preparation["preflight_summary"],
        )
        if arguments.prepare_only:
            print(json.dumps(preparation, indent=2, sort_keys=True))
            return 0

        stage_summaries = []
        claim_reports = []
        evidence_registry: dict[str, dict[str, Any]] = {}
        control_expectation = None
        for lane in CLAIM_LANES:
            lifecycle["phase"] = "claim/" + lane
            packet = packets["claim_lanes"][lane]
            if _candidate_count(packet) == 0 and lane == "changed_stale":
                report = StageReviewReport(
                    stage="claim",
                    lane=lane,
                    assessment=(
                        "No current deterministic or ranked candidate was "
                        "presented for this lane."
                    ),
                ).model_dump(mode="json")
                claim_reports.append(report)
                continue
            result = _run_readonly_review_stage(
                source_project=project_dir,
                stage_dir=output_dir / "claim" / lane,
                stage="claim",
                lane=lane,
                packet=packet,
                prompt_path=PROMPTS["claim"],
                output_type=StageReviewReport,
                model=arguments.model,
                reasoning_effort=arguments.reasoning_effort,
                max_turns=arguments.claim_lane_max_turns,
                citation_repair_max_turns=arguments.citation_repair_max_turns,
                environment=environment,
                external_evidence_registry=preflight_evidence_registry,
            )
            claim_reports.append(result["report"])
            stage_summaries.append(result["summary"])
            evidence_registry.update(result["evidence_registry"])

        if arguments.questionable_control_file:
            control_finding, control_expectation = _load_questionable_control(
                arguments.questionable_control_file
            )
            claim_reports.append({
                "stage": "claim",
                "lane": "experimental_control",
                "assessment": (
                    "Host-seeded questionable claim for disposition-path testing."
                ),
                "findings": [control_finding],
                "cleared_targets": [],
                "deferred_questions": [],
            })
            _write_json(
                output_dir / "questionable_control_expectation.json",
                control_expectation,
            )

        lifecycle["phase"] = "system_model"
        system_result = _run_readonly_review_stage(
            source_project=project_dir,
            stage_dir=output_dir / "coverage" / "system_model",
            stage="coverage",
            lane="system_model",
            packet=packets["system_model"],
            prompt_path=PROMPTS["system_model"],
            output_type=SystemModelReport,
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
            max_turns=arguments.system_model_max_turns,
            citation_repair_max_turns=arguments.citation_repair_max_turns,
            environment=environment,
            external_evidence_registry=preflight_evidence_registry,
        )
        stage_summaries.append(system_result["summary"])
        evidence_registry.update(system_result["evidence_registry"])
        if arguments.system_guided_artifact:
            artifact_packet = _guided_artifact_packet(
                packets["artifact_coverage"],
                system_result["report"],
                limit=arguments.guided_system_gap_limit,
                gap_ids=arguments.guided_gap_id,
            )
            artifact_prompt = PROMPTS["guided_artifact"]
            artifact_lane = "system_guided_artifact"
        else:
            artifact_packet = {
                **packets["artifact_coverage"],
                "system_model_report": system_result["report"],
            }
            artifact_packet["packet_sha256"] = _json_sha256(artifact_packet)
            artifact_prompt = PROMPTS["artifact_coverage"]
            artifact_lane = "artifact_coverage"
        _write_json(
            output_dir / "effective_artifact_coverage_packet.json",
            artifact_packet,
        )
        lifecycle["phase"] = "artifact_coverage"
        artifact_result = _run_readonly_review_stage(
            source_project=project_dir,
            stage_dir=output_dir / "coverage" / artifact_lane,
            stage="coverage",
            lane=artifact_lane,
            packet=artifact_packet,
            prompt_path=artifact_prompt,
            output_type=StageReviewReport,
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
            max_turns=arguments.artifact_coverage_max_turns,
            citation_repair_max_turns=arguments.citation_repair_max_turns,
            environment=environment,
            external_evidence_registry={
                **preflight_evidence_registry,
                **system_result["evidence_registry"],
            },
        )
        stage_summaries.append(artifact_result["summary"])
        evidence_registry.update(artifact_result["evidence_registry"])

        lifecycle["phase"] = "consolidation"
        consolidation = _run_consolidation_stage(
            source_project=project_dir,
            output_dir=output_dir,
            claim_reports=claim_reports,
            system_model=system_result["report"],
            artifact_coverage=artifact_result["report"],
            evidence_registry=evidence_registry,
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
        )
        stage_summaries.append(consolidation["summary"])

        if arguments.experimental_guided_application:
            experimental_plan = _experimental_guided_plan(
                consolidation["review_index"]
            )
            _write_json(
                output_dir / "consolidation" / "planning" /
                "experimental_validated_plan.json",
                experimental_plan,
            )
            consolidation["plan"] = experimental_plan

        collection_summary = {
            "schema": "verified_ida.final_review_collection_summary.v1",
            "status": "completed",
            "system_guided_artifact": bool(arguments.system_guided_artifact),
            "guided_gap_ids": list(arguments.guided_gap_id),
            "guided_system_gap_limit": arguments.guided_system_gap_limit,
            "claim_finding_counts": {
                str(report.get("lane") or "unknown"): len(
                    list(report.get("findings") or [])
                )
                for report in claim_reports
            },
            "system_gap_count": len(
                list(system_result["report"].get("supported_gaps") or [])
            ),
            "artifact_finding_count": len(
                list(artifact_result["report"].get("findings") or [])
            ),
            "source_finding_count": consolidation["review_index"][
                "source_finding_count"
            ],
            "usage": _combined_usage(stage_summaries),
        }
        _write_json(output_dir / "collection_summary.json", collection_summary)
        if arguments.collection_only:
            print(json.dumps(collection_summary, indent=2, sort_keys=True))
            return 0

        lifecycle["phase"] = "application_initialization"
        runtime = VerifiedIdaRuntime.initialize(
            project_dir,
            analysis_feedback_profile="scoped",
        )
        before = {
            "component_revisions": _component_revisions(runtime),
            "component_hashes": project_component_hashes(project_dir),
            "operation_ids": [
                str(row["operation_id"]) for row in runtime.journal.current_operations()
            ],
            "preflight": packets["preflight"],
        }
        lifecycle["phase"] = "application"
        application = _run_application_waves(
            runtime=runtime,
            output_dir=output_dir,
            review_index=consolidation["review_index"],
            plan=consolidation["plan"],
            model=arguments.model,
            reasoning_effort=arguments.reasoning_effort,
            runaway_max_turns=arguments.application_runaway_max_turns,
            no_progress_max_responses=(
                arguments.application_no_progress_max_responses
            ),
        )
        lifecycle["phase"] = "post_application_audit"
        post_closure = load_current_recorded_closure(runtime) or runtime.review_analysis_closure()
        post_packets = build_final_review_packets(runtime, post_closure)
        _write_json(
            output_dir / "post_application_preflight.json",
            post_packets["preflight"],
        )
        audit = _write_post_audit(
            source_project=source_project,
            project_dir=project_dir,
            output_dir=output_dir,
            runtime=runtime,
            before=before,
            after_packets=post_packets,
            application=application,
        )
        _progress(
            "final_review_post_audit_completed",
            status=audit["status"],
            new_verified_operation_count=len(audit["new_verified_operations"]),
        )
        summary = {
            "schema": "verified_ida.final_review_run_summary.v1",
            "status": audit["status"],
            "model": arguments.model,
            "reasoning_effort": arguments.reasoning_effort,
            "source": source_provenance,
            "source_project": str(source_project),
            "project_dir": str(project_dir),
            "review_dir": str(output_dir),
            "preflight": preparation["preflight_summary"],
            "claim_report_count": len(claim_reports),
            "system_gap_count": len(
                system_result["report"].get("supported_gaps") or []
            ),
            "artifact_finding_count": len(
                artifact_result["report"].get("findings") or []
            ),
            "source_finding_count": consolidation["review_index"][
                "source_finding_count"
            ],
            "application_wave_count": consolidation["plan"][
                "application_wave_count"
            ],
            "consolidation": {
                "review_index_digest": consolidation["review_index"][
                    "index_digest"
                ],
                "planning_digest": consolidation["plan"]["planning_digest"],
                "accounted_source_finding_count": consolidation["plan"][
                    "accounted_source_finding_count"
                ],
            },
            "application": application,
            "post_application_audit": audit,
            "review_usage": _combined_usage(stage_summaries + [application]),
        }
        _write_json(run_dir / "summary.json", summary)

        prior_run_summary_path = project_dir / "run_summary.json"
        prior_run_summary = (
            json.loads(prior_run_summary_path.read_text(encoding="utf-8"))
            if prior_run_summary_path.is_file() else {}
        )
        prior_run_summary.update({
            "status": "completed" if audit["status"] == "completed" else "stopped",
            "model": arguments.model,
            "reasoning_effort": arguments.reasoning_effort,
            "operations": runtime.journal.operation_summary(),
            "project": runtime.journal.resume_summary(),
            "completion": application.get("completion") or {},
            "final_review": summary,
        })
        _write_json(prior_run_summary_path, prior_run_summary)
        print(json.dumps(summary, indent=2, sort_keys=True, default=str))
        return 0 if audit["status"] == "completed" else 2
    finally:
        if runtime is not None:
            primary_error = sys.exc_info()[1]
            if primary_error is None:
                lifecycle["phase"] = "cleanup"
            try:
                runtime.close()
            except Exception as cleanup:
                if primary_error is None:
                    raise
                lifecycle.setdefault("cleanup_errors", []).append({
                    "type": type(cleanup).__name__, "message": str(cleanup),
                })


if __name__ == "__main__":
    raise SystemExit(main())
