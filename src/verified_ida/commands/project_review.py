#!/usr/bin/env python3
"""Run a read-only, project-scale semantic coverage review on a project copy."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from verified_ida.commands.analyze import (  # noqa: E402
    REQUIRED_AGENTS_SDK,
    ToolInvocationState,
    _function_tools,
    _observable_hooks,
)
from verified_ida.adapter import VerifiedIdaToolAdapter  # noqa: E402
from verified_ida.analysis_feedback import (  # noqa: E402
    measure_type_application,
    model_created_type_names,
)
from verified_ida.audit import (  # noqa: E402
    ObservableTrace,
    aggregate_usage,
    event_counts,
    write_walkthrough,
)
from verified_ida.contracts import VERIFIED_STATUSES, canonical_json  # noqa: E402
from verified_ida.journal import operation_surface_identity  # noqa: E402
from verified_ida.runtime import VerifiedIdaRuntime  # noqa: E402
from verified_ida.source_provenance import describe_source  # noqa: E402


REVIEW_PROMPTS = {
    "narrative_v1": (
        ROOT / "prompts" / "project_review" /
        "verified_ida_project_coverage_review_v1.md"
    ),
    "structural_v2": (
        ROOT / "prompts" / "project_review" /
        "verified_ida_structural_review_v2.md"
    ),
}
READ_ONLY_REVIEW_TOOLS = {
    "read_reversing_log",
    "describe_ida_capabilities",
    "survey_idb",
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
    "review_ida_frontier",
    "read_ida_call_flow_scope",
    "list_ida_components",
    "switch_ida_component",
    "review_analysis_closure",
}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--model", default=os.environ.get("ANALYSIS_MODEL", "gpt-5.6-sol")
    )
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh"],
        default="xhigh",
    )
    parser.add_argument("--max-agent-turns", type=int, default=200)
    parser.add_argument(
        "--review-mode",
        choices=sorted(REVIEW_PROMPTS),
        default="narrative_v1",
    )
    return parser.parse_args(argv)


def _environment() -> dict[str, Any]:
    try:
        sdk_version = version("openai-agents")
    except PackageNotFoundError:
        sdk_version = None
    if sdk_version != REQUIRED_AGENTS_SDK:
        raise SystemExit(
            "Project review requires openai-agents==%s; found %s"
            % (REQUIRED_AGENTS_SDK, sdk_version or "not installed")
        )
    return {
        "python": "%d.%d.%d" % sys.version_info[:3],
        "openai_agents": sdk_version,
        "required_openai_agents": REQUIRED_AGENTS_SDK,
    }


def _segment_id() -> str:
    return "%s-pid%d" % (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        os.getpid(),
    )


def _attention_summary(runtime: VerifiedIdaRuntime) -> dict[str, Any]:
    """Summarize prior attention without turning counts into obligations."""

    inspections = runtime.journal.connection.execute(
        """
        SELECT component_id, target_kind, target_key, query_kind, created_at
        FROM inspections
        WHERE query_kind NOT LIKE 'closure_%'
        ORDER BY rowid
        """
    ).fetchall()
    by_component: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "inspection_count": 0,
            "distinct_inspected_targets": set(),
            "query_kinds": Counter(),
            "first_inspection_at": None,
            "last_inspection_at": None,
        }
    )
    for raw in inspections:
        row = dict(raw)
        summary = by_component[str(row["component_id"])]
        summary["inspection_count"] += 1
        summary["distinct_inspected_targets"].add(
            "%s:%s" % (row["target_kind"], row["target_key"])
        )
        summary["query_kinds"][str(row["query_kind"])] += 1
        summary["first_inspection_at"] = (
            summary["first_inspection_at"] or row["created_at"]
        )
        summary["last_inspection_at"] = row["created_at"]

    for operation in runtime.journal.current_operations():
        receipt = dict(operation.get("receipt") or {})
        if receipt.get("status") not in VERIFIED_STATUSES:
            continue
        component_id = str(operation.get("component_id") or "")
        summary = by_component[component_id]
        summary.setdefault("verified_edit_count", 0)
        summary.setdefault("distinct_edited_targets", set())
        summary.setdefault("edit_kinds", Counter())
        summary["verified_edit_count"] += 1
        summary["distinct_edited_targets"].add(
            "%s:%s"
            % (operation.get("target_kind"), operation.get("target_key"))
        )
        summary["edit_kinds"][str(operation.get("kind") or "")] += 1

    components = []
    for component in runtime.journal.components():
        component_id = str(component["component_id"])
        summary = by_component[component_id]
        components.append({
            "component_id": component_id,
            "parent_component_id": component.get("parent_component_id"),
            "architecture": component.get("architecture"),
            "status": component.get("status"),
            "inspection_count": int(summary.get("inspection_count") or 0),
            "distinct_inspected_target_count": len(
                summary.get("distinct_inspected_targets") or set()
            ),
            "query_kinds": dict(sorted(
                (summary.get("query_kinds") or Counter()).items()
            )),
            "verified_edit_count": int(summary.get("verified_edit_count") or 0),
            "distinct_edited_target_count": len(
                summary.get("distinct_edited_targets") or set()
            ),
            "edit_kinds": dict(sorted(
                (summary.get("edit_kinds") or Counter()).items()
            )),
            "first_inspection_at": summary.get("first_inspection_at"),
            "last_inspection_at": summary.get("last_inspection_at"),
            "suggested_next_sample": runtime.frontier_page(
                collection="suggested_next",
                component_id=component_id,
                limit=8,
            ),
        })
    return {
        "interpretation": (
            "Measured attention and bounded navigation samples; unequal counts "
            "are not themselves evidence of incomplete analysis."
        ),
        "components": components,
    }


def _semantic_states(runtime: VerifiedIdaRuntime) -> dict[str, dict[str, Any]]:
    states: dict[str, dict[str, Any]] = {}
    for component in runtime.journal.components():
        component_id = str(component["component_id"])
        checkpoint = runtime.journal.latest_checkpoint(component_id) or {}
        details = dict(checkpoint.get("details") or {})
        path_text = str(details.get("semantic_export_path") or "")
        path = Path(path_text) if path_text else None
        if path is None or not path.is_file():
            revision = int(checkpoint.get("revision") or 0)
            matches = sorted(
                (runtime.workspace / "semantic_checkpoints" / component_id).glob(
                    "revision-%d-*.json" % revision
                )
            )
            path = matches[-1] if matches else None
        if path is None or not path.is_file():
            states[component_id] = {}
            continue
        document = json.loads(path.read_text(encoding="utf-8"))
        states[component_id] = dict(document.get("state") or {})
    return states


def _verified_current_operations(runtime: VerifiedIdaRuntime) -> list[dict[str, Any]]:
    rows = []
    for operation in runtime.journal.current_operations():
        receipt = dict(operation.get("receipt") or {})
        if receipt.get("status") in VERIFIED_STATUSES:
            rows.append(operation)
    return rows


def _function_maps(
    states: Mapping[str, Mapping[str, Any]],
) -> dict[str, dict[str, dict[str, Any]]]:
    result: dict[str, dict[str, dict[str, Any]]] = {}
    for component_id, state in states.items():
        result[component_id] = {
            str(row.get("address") or "").lower(): dict(row)
            for row in list(state.get("functions") or [])
            if row.get("address")
        }
    return result


def _declared_reference_map(
    closure_result: Mapping[str, Any],
) -> dict[tuple[str, str], list[str]]:
    packet = dict(closure_result.get("packet") or {})
    result: dict[tuple[str, str], list[str]] = {}
    for row in list(packet.get("declared_references") or []):
        key = (
            str(row.get("component_id") or ""),
            str(row.get("address") or "").lower(),
        )
        result[key] = sorted(str(value) for value in row.get("sections") or [])
    return result


def _claim_risk_candidates(
    runtime: VerifiedIdaRuntime,
    states: Mapping[str, Mapping[str, Any]],
    functions: Mapping[str, Mapping[str, Mapping[str, Any]]],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    candidates: list[dict[str, Any]] = []
    for operation in operations:
        kind = str(operation.get("kind") or "")
        if kind not in {
            "named_type.create_or_update",
            "function.prototype.set",
            "relationship.annotate",
        }:
            continue
        component_id = str(operation.get("component_id") or "")
        target_key = str(operation.get("target_key") or "")
        request = dict(operation.get("request") or {})
        evidence_count = len(list(request.get("evidence") or []))
        if kind == "named_type.create_or_update":
            desired = dict(request.get("desired") or {})
            name = str(desired.get("name") or target_key)
            declaration = str(desired.get("declaration") or "")
            measurement = measure_type_application(
                states.get(component_id) or {},
                type_name=name,
                component_id=component_id,
                revision=int(runtime.journal.revision(component_id)["revision"]),
                limit=12,
            )
            prototype_surface = dict(
                dict(measurement.get("surfaces") or {}).get(
                    "function_prototypes"
                ) or {}
            )
            uses = list(prototype_surface.get("examples") or [])
            reasons = [
                "A model-created named type can propagate one interpretation across many functions."
            ]
            if not int(measurement.get("measured_use_count") or 0):
                reasons.append(
                    "No current measured semantic surface uses this named type."
                )
            candidates.append({
                "candidate_id": "claim-type-%s-%s" % (component_id, name),
                "tier": (
                    "A1"
                    if not int(measurement.get("measured_use_count") or 0)
                    else "A2"
                ),
                "kind": "named_type_support",
                "component_id": component_id,
                "target_kind": "named_type",
                "target_key": name,
                "type_kind": desired.get("type_kind"),
                "declaration": declaration,
                "operation_evidence_count": evidence_count,
                "current_prototype_use_count": int(
                    prototype_surface.get("count") or 0
                ),
                "current_prototype_uses": uses[:12],
                "measured_type_application": measurement,
                "deterministic_reasons": reasons,
            })
        elif kind == "function.prototype.set":
            address = target_key.lower()
            function = dict((functions.get(component_id) or {}).get(address) or {})
            receipt = dict(operation.get("receipt") or {})
            effects = dict(receipt.get("effects") or {})
            candidates.append({
                "candidate_id": "claim-prototype-%s-%s" % (
                    component_id, address.removeprefix("0x")
                ),
                "tier": "A2",
                "kind": "prototype_support",
                "component_id": component_id,
                "target_kind": "function",
                "target_key": address,
                "current_name": function.get("name"),
                "current_prototype": function.get("prototype"),
                "operation_evidence_count": evidence_count,
                "decompiler_changed": bool(effects.get("decompiler_changed")),
                "affected_function_count": len(
                    list(effects.get("decompiler_functions") or [])
                ),
                "deterministic_reasons": [
                    "A custom prototype changes caller and decompiler interpretation.",
                    "Validate local parameter use and representative callers independently of mechanical persistence.",
                ],
            })
        else:
            target = dict(request.get("target") or {})
            candidates.append({
                "candidate_id": "claim-relationship-%s-%s" % (
                    component_id,
                    hashlib.sha256(target_key.encode("utf-8")).hexdigest()[:12],
                ),
                "tier": "A2",
                "kind": "relationship_support",
                "component_id": component_id,
                "target_kind": "relationship",
                "target_key": target_key,
                "source": target.get("source"),
                "destination": target.get("destination"),
                "current_description": (
                    dict(request.get("desired") or {}).get("description")
                ),
                "operation_evidence_count": evidence_count,
                "deterministic_reasons": [
                    "A semantic relationship requires both endpoint roles and edge data/control/ownership evidence."
                ],
            })

    order = {"A1": 0, "A2": 1}
    candidates.sort(key=lambda row: (
        order.get(str(row.get("tier")), 9),
        str(row.get("component_id")),
        str(row.get("kind")),
        str(row.get("target_key")),
    ))
    return {
        "interpretation": (
            "Deterministic high-risk claim classes, not findings. The reviewer "
            "must inspect live evidence and may clear every candidate."
        ),
        "total": len(candidates),
        "candidates": candidates,
    }


def _support_boundary_candidates(
    runtime: VerifiedIdaRuntime,
    closure_result: Mapping[str, Any],
    functions: Mapping[str, Mapping[str, Mapping[str, Any]]],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    declared = _declared_reference_map(closure_result)
    edit_kinds: dict[tuple[str, str], set[str]] = defaultdict(set)
    operations_by_id = {
        str(operation.get("operation_id") or ""): operation
        for operation in operations
        if operation.get("operation_id")
    }
    for operation in operations:
        if operation.get("target_kind") != "function":
            continue
        edit_kinds[(
            str(operation.get("component_id") or ""),
            str(operation.get("target_key") or "").lower(),
        )].add(str(operation.get("kind") or ""))

    rows = runtime.journal.connection.execute(
        """
        SELECT candidate_id, component_id, target_kind, target_key, gap_kind,
               priority, tier, origin, operation_id, reasons_json, created_at
        FROM frontier_candidates
        WHERE lane = 'suggested_next' AND state = 'open'
          AND gap_kind IN ('unresolved_callee_neighbor', 'unresolved_caller_neighbor')
        ORDER BY rowid
        """
    ).fetchall()
    by_component: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for raw in rows:
        row = dict(raw)
        component_id = str(row["component_id"])
        reasons = json.loads(str(row.get("reasons_json") or "[]"))
        operation_id = str(row.get("operation_id") or "")
        source_operation = operations_by_id.get(operation_id)
        if source_operation is None and operation_id:
            source_operation = runtime.journal.operation_detail(operation_id)
        source_target = dict(
            dict((source_operation or {}).get("request") or {}).get("target") or {}
        )
        source_address = str(
            source_target.get("address")
            or source_target.get("function_address")
            or source_target.get("source_address")
            or ""
        ).lower()
        if not source_address:
            continue
        source_function = dict(
            (functions.get(component_id) or {}).get(source_address) or {}
        )
        source_sections = declared.get((component_id, source_address), [])
        source_kinds = sorted(edit_kinds.get((component_id, source_address), set()))
        inspected = runtime.journal.connection.execute(
            """
            SELECT COUNT(*) AS count FROM inspections
            WHERE component_id = ? AND target_kind = 'function'
              AND lower(target_key) = ?
            """,
            (component_id, str(row["target_key"]).lower()),
        ).fetchone()
        prior_inspections = int(inspected["count"] if inspected else 0)
        source_rank = (
            0 if source_sections
            else 1 if len(source_kinds) >= 2
            else 2
        )
        by_component[component_id].append({
            "candidate_id": row["candidate_id"],
            "tier": "B1" if source_rank <= 1 else "B2",
            "kind": row["gap_kind"],
            "component_id": component_id,
            "target_kind": row["target_kind"],
            "target_key": str(row["target_key"]).lower(),
            "source_key": source_address,
            "source_name": source_function.get("name"),
            "source_comment": str(source_function.get("comment") or "")[:700],
            "source_notebook_sections": source_sections,
            "source_edit_kinds": source_kinds,
            "target_prior_inspection_count": prior_inspections,
            "deterministic_reasons": reasons + ([
                "The committed source supports a consequential notebook claim."
            ] if source_sections else [
                "The committed source carries multiple durable semantic edits."
            ] if len(source_kinds) >= 2 else []),
            "_rank": (source_rank, prior_inspections, str(row["target_key"])),
        })

    samples = []
    component_summaries = []
    for component_id in sorted(by_component, key=lambda value: (value != "root", value)):
        component_rows = by_component[component_id]
        source_groups: dict[str, dict[str, Any]] = {}
        for row in component_rows:
            source_key = str(row["source_key"])
            group = source_groups.setdefault(source_key, {
                "tier": row["tier"],
                "component_id": component_id,
                "source_key": source_key,
                "source_name": row["source_name"],
                "source_comment": row["source_comment"],
                "source_notebook_sections": row["source_notebook_sections"],
                "source_edit_kinds": row["source_edit_kinds"],
                "neighbors": [],
                "_rank": row["_rank"][0],
            })
            group["_rank"] = min(int(group["_rank"]), int(row["_rank"][0]))
            group["neighbors"].append({
                "candidate_id": row["candidate_id"],
                "kind": row["kind"],
                "target_kind": row["target_kind"],
                "target_key": row["target_key"],
                "target_prior_inspection_count": row[
                    "target_prior_inspection_count"
                ],
                "deterministic_reasons": row["deterministic_reasons"],
            })
        groups = list(source_groups.values())
        for group in groups:
            group["neighbors"].sort(key=lambda row: (
                int(row["target_prior_inspection_count"]),
                str(row["target_key"]),
            ))
            group["neighbor_total"] = len(group["neighbors"])
            group["neighbor_returned"] = min(32, len(group["neighbors"]))
            group["neighbor_has_more"] = len(group["neighbors"]) > 32
            group["neighbors"] = group["neighbors"][:32]
        groups.sort(key=lambda group: (
            int(group["_rank"]),
            -int(group["neighbor_total"]),
            str(group["source_key"]),
        ))
        group_limit = 16 if component_id == "root" else 8
        if component_id == "root":
            directly_declared = [
                group for group in groups if int(group["_rank"]) == 0
            ]
            multiply_edited = [
                group for group in groups if int(group["_rank"]) == 1
            ]
            selected = directly_declared[:8] + multiply_edited[:8]
            selected_ids = {id(group) for group in selected}
            if len(selected) < group_limit:
                selected.extend(
                    group for group in groups
                    if id(group) not in selected_ids
                )
                selected = selected[:group_limit]
        else:
            selected = groups[:group_limit]
        for group in selected:
            group.pop("_rank", None)
        samples.extend(selected)
        component_summaries.append({
            "component_id": component_id,
            "source_group_total": len(groups),
            "source_group_returned": len(selected),
            "source_group_has_more": len(selected) < len(groups),
            "neighbor_total": len(component_rows),
            "neighbor_returned": sum(
                int(group["neighbor_returned"]) for group in selected
            ),
        })
    return {
        "interpretation": (
            "A bounded page of open one-hop neighbors ranked by whether the "
            "committed source appears in current project conclusions and by "
            "prior inspection. Presentation does not make a candidate obligatory."
        ),
        "selection_policy": (
            "Per-component source-group pages prevent a large parent or one "
            "high-degree function from hiding other boundaries. Sources are "
            "ranked by direct notebook references, durable edit breadth, and "
            "prior target inspection. Prose similarity is not used."
        ),
        "components": component_summaries,
        "source_groups": samples,
    }


def _structural_frontier(
    runtime: VerifiedIdaRuntime,
    closure_result: Mapping[str, Any],
) -> dict[str, Any]:
    states = _semantic_states(runtime)
    functions = _function_maps(states)
    operations = _verified_current_operations(runtime)
    return {
        "schema": "verified_ida.structural_review_frontier.v1",
        "claim_risk": _claim_risk_candidates(
            runtime, states, functions, operations
        ),
        "support_boundary": _support_boundary_candidates(
            runtime, closure_result, functions, operations
        ),
        "excluded_signals": [
            "anonymous status alone",
            "function size alone",
            "component size or attention imbalance alone",
            "model self-confidence",
            "hidden benchmark or expert data",
        ],
    }


def _deterministic_preflight_from_state(
    states: Mapping[str, Mapping[str, Any]],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Measure artifact state without assigning malware semantics."""

    functions = _function_maps(states)
    type_facts = []
    prototype_facts = []
    current_failures = []
    for operation in operations:
        component_id = str(operation.get("component_id") or "")
        kind = str(operation.get("kind") or "")
        target_key = str(operation.get("target_key") or "")
        request = dict(operation.get("request") or {})
        receipt = dict(operation.get("receipt") or {})
        status = str(receipt.get("status") or "missing_receipt")
        if status not in VERIFIED_STATUSES:
            if operation.get("resolution_outcome") == "abandoned":
                continue
            current_failures.append({
                "operation_id": operation.get("operation_id"),
                "component_id": component_id,
                "kind": kind,
                "target_kind": operation.get("target_kind"),
                "target_key": target_key,
                "status": status,
                "persistence": receipt.get("persistence"),
                "error": receipt.get("error"),
                "resolution_outcome": operation.get("resolution_outcome"),
            })
            continue
        if kind == "named_type.create_or_update":
            desired = dict(request.get("desired") or {})
            name = str(desired.get("name") or target_key)
            type_kind = str(desired.get("type_kind") or "")
            measurement = measure_type_application(
                states.get(component_id) or {},
                type_name=name,
                component_id=component_id,
                revision=0,
                limit=24,
            )
            prototype_surface = dict(
                dict(measurement.get("surfaces") or {}).get(
                    "function_prototypes"
                ) or {}
            )
            uses = list(prototype_surface.get("examples") or [])
            no_prototype_use = int(prototype_surface.get("count") or 0) == 0
            type_facts.append({
                "fact_id": "type-prototype-use-%s-%s" % (component_id, name),
                "fact_class": "named_type_prototype_application",
                "component_id": component_id,
                "type_name": name,
                "type_kind": type_kind,
                "current_function_prototype_use_count": len(uses),
                "current_function_prototype_uses": uses[:24],
                "measured_status": (
                    "no_current_function_prototype_use"
                    if no_prototype_use
                    else "used_by_current_function_prototype"
                ),
                "direct_application_gap": (
                    no_prototype_use and type_kind not in {"enum", "typedef"}
                ),
                "measurement_scope": (
                    "Current function prototypes in the final semantic export. "
                    "Local-variable typing is not measured by this fact."
                ),
            })
        elif kind == "function.prototype.set":
            function = dict(
                (functions.get(component_id) or {}).get(target_key.lower()) or {}
            )
            effects = dict(receipt.get("effects") or {})
            prototype_facts.append({
                "fact_id": "prototype-application-%s-%s" % (
                    component_id, target_key.lower().removeprefix("0x")
                ),
                "fact_class": "function_prototype_application",
                "component_id": component_id,
                "target_key": target_key.lower(),
                "current_name": function.get("name"),
                "current_prototype": function.get("prototype"),
                "decompiler_changed_at_application": bool(
                    effects.get("decompiler_changed")
                ),
                "affected_function_count_at_application": len(
                    list(effects.get("decompiler_functions") or [])
                ),
                "measured_status": "verified_persistent",
            })

    relationship_facts = []
    for component_id, state in states.items():
        component_functions = functions.get(component_id) or {}
        for relationship in list(state.get("relationships") or []):
            source = str(relationship.get("source_address") or "").lower()
            destination = str(
                relationship.get("destination_address") or ""
            ).lower()
            source_present = source in component_functions
            destination_present = destination in component_functions
            relationship_facts.append({
                "fact_id": "relationship-endpoints-%s-%s" % (
                    component_id,
                    str(relationship.get("relationship_id") or "unknown"),
                ),
                "fact_class": "relationship_endpoint_integrity",
                "component_id": component_id,
                "relationship_id": relationship.get("relationship_id"),
                "source": source,
                "destination": destination,
                "source_present": source_present,
                "destination_present": destination_present,
                "measured_status": (
                    "both_endpoints_present"
                    if source_present and destination_present
                    else "missing_endpoint"
                ),
            })

    direct_type_gaps = [
        row for row in type_facts if row["direct_application_gap"]
    ]
    broken_relationships = [
        row for row in relationship_facts
        if row["measured_status"] == "missing_endpoint"
    ]
    return {
        "schema": "verified_ida.deterministic_review_preflight.v1",
        "provenance": {
            "kind": "host_measured",
            "semantic_judgment": False,
            "interpretation": (
                "These are current artifact facts. Whether an applied type, "
                "prototype, or relationship is semantically correct still "
                "requires code review."
            ),
        },
        "summary": {
            "model_created_named_type_count": len(type_facts),
            "named_struct_or_union_without_prototype_use_count": len(
                direct_type_gaps
            ),
            "custom_prototype_count": len(prototype_facts),
            "relationship_count": len(relationship_facts),
            "relationship_measurement_status": (
                "measured" if relationship_facts else "none_submitted"
            ),
            "relationship_missing_endpoint_count": len(broken_relationships),
            "current_mechanical_failure_count": len(current_failures),
        },
        "named_type_prototype_application": type_facts,
        "function_prototype_application": prototype_facts,
        "relationship_endpoint_integrity": relationship_facts,
        "current_mechanical_failures": current_failures,
    }


def build_deterministic_preflight(
    runtime: VerifiedIdaRuntime,
) -> dict[str, Any]:
    return _deterministic_preflight_from_state(
        _semantic_states(runtime),
        runtime.journal.current_operations(),
    )


def _review_notebook_context(
    closure_result: Mapping[str, Any],
) -> dict[str, Any]:
    packet = dict(closure_result.get("packet") or {})
    notebook = dict(packet.get("notebook") or {})
    current_state = dict(notebook.get("current_state") or {})
    selected = {}
    for key in (
        "objective_and_scope",
        "component_map",
        "established_understanding",
        "changed_conclusions_and_impact",
        "hypotheses_and_uncertainty",
        "deferred_or_nonmaterial_work",
        "closure_review",
    ):
        if key in current_state:
            selected[key] = current_state[key]
    return {
        "document_digest": notebook.get("document_digest"),
        "current_state": selected,
    }


def build_staged_review_packets(
    runtime: VerifiedIdaRuntime,
    closure_result: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Build independent claim and coverage packets from generic signals."""

    states = _semantic_states(runtime)
    model_components = runtime.list_components()["components"]
    functions = _function_maps(states)
    operations = runtime.journal.current_operations()
    verified_operations = [
        row for row in operations
        if dict(row.get("receipt") or {}).get("status") in VERIFIED_STATUSES
    ]
    closure_packet = dict(closure_result.get("packet") or {})
    preflight = _deterministic_preflight_from_state(states, operations)
    common = {
        "objective": runtime.project_objective,
        "review_contract": {
            "read_only": True,
            "current_narrative_is_evidence_not_truth": True,
            "inventory_counts_are_not_completion_quotas": True,
            "report_evidence_refs": "current_live_citations_only",
            "historical_evidence_refs": "provenance_only_not_citeable",
        },
        "components": model_components,
        "notebook": _review_notebook_context(closure_result),
    }
    claim_packet = {
        "schema": "verified_ida.staged_claim_review.packet.v1",
        **common,
        "deterministic_preflight": preflight,
        "claim_risk": _claim_risk_candidates(
            runtime, states, functions, verified_operations
        ),
    }
    coverage_packet = {
        "schema": "verified_ida.staged_coverage_review.packet.v1",
        **common,
        "attention": _attention_summary(runtime),
        "support_boundary": _support_boundary_candidates(
            runtime, closure_result, functions, verified_operations
        ),
        "review_candidates": dict(
            closure_packet.get("review_candidates") or {}
        ),
        "excluded_signals": [
            "anonymous status alone",
            "function size alone",
            "component size or attention imbalance alone",
            "model self-confidence",
        ],
    }
    for packet in (claim_packet, coverage_packet):
        packet["packet_sha256"] = hashlib.sha256(
            canonical_json(packet).encode("utf-8")
        ).hexdigest()
    return {
        "preflight": preflight,
        "claim": claim_packet,
        "coverage": coverage_packet,
    }


def _live_semantic_states(
    runtime: VerifiedIdaRuntime,
) -> dict[str, dict[str, Any]]:
    """Read every accepted component from current IDA state."""

    states = {}
    for component in runtime.journal.components():
        if not component.get("idb_path"):
            continue
        component_id = str(component["component_id"])
        states[component_id] = runtime._closure_semantic_state(component_id)
    return states


def _function_claim_candidates(
    closure_result: Mapping[str, Any],
    functions: Mapping[str, Mapping[str, Mapping[str, Any]]],
    operations: list[dict[str, Any]],
) -> dict[str, Any]:
    """Select bounded persisted function claims without judging their meaning."""

    declared = _declared_reference_map(closure_result)
    relationship_endpoints: set[tuple[str, str]] = set()
    for operation in operations:
        if operation.get("kind") != "relationship.annotate":
            continue
        component_id = str(operation.get("component_id") or "")
        target = dict((operation.get("request") or {}).get("target") or {})
        for key in ("source_address", "destination_address"):
            if target.get(key):
                relationship_endpoints.add(
                    (component_id, str(target[key]).lower())
                )

    by_target: dict[tuple[str, str], dict[str, Any]] = {}
    for operation in operations:
        if operation.get("target_kind") != "function":
            continue
        kind = str(operation.get("kind") or "")
        if kind not in {
            "function.rename", "function.comment.set", "function.prototype.set"
        }:
            continue
        component_id = str(operation.get("component_id") or "")
        address = str(operation.get("target_key") or "").lower()
        key = (component_id, address)
        row = by_target.setdefault(key, {
            "candidate_id": "function-claim-%s-%s" % (
                component_id, address.removeprefix("0x")
            ),
            "component_id": component_id,
            "target_kind": "function",
            "target_key": address,
            "edit_kinds": set(),
            "operation_evidence_count": 0,
        })
        row["edit_kinds"].add(kind)
        row["operation_evidence_count"] += len(
            list((operation.get("request") or {}).get("evidence") or [])
        )

    candidates = []
    for (component_id, address), raw in by_target.items():
        function = dict((functions.get(component_id) or {}).get(address) or {})
        sections = declared.get((component_id, address), [])
        endpoint = (component_id, address) in relationship_endpoints
        kinds = sorted(raw.pop("edit_kinds"))
        score = (
            4 * bool(sections)
            + 3 * endpoint
            + 2 * ("function.prototype.set" in kinds)
            + int(len(kinds) >= 2)
        )
        candidates.append({
            **raw,
            "current_name": function.get("name"),
            "current_comment": str(function.get("comment") or "")[:1600],
            "current_prototype": function.get("prototype"),
            "edit_kinds": kinds,
            "notebook_sections": sections,
            "relationship_endpoint": endpoint,
            "selection_score": score,
            "selection_reasons": [
                reason for enabled, reason in (
                    (bool(sections), "The function is cited by current project state."),
                    (endpoint, "The function is an endpoint of a durable relationship."),
                    (
                        "function.prototype.set" in kinds,
                        "The function carries a model-authored interface.",
                    ),
                    (
                        len(kinds) >= 2,
                        "The function carries more than one durable semantic edit kind.",
                    ),
                ) if enabled
            ] or ["The function carries a durable behavioral claim."],
        })

    candidates.sort(key=lambda row: (
        -int(row["selection_score"]),
        str(row["component_id"] != "root"),
        str(row["component_id"]),
        str(row["target_key"]),
    ))
    selected = []
    for component_id in sorted(
        {str(row["component_id"]) for row in candidates},
        key=lambda value: (value != "root", value),
    ):
        limit = 12 if component_id == "root" else 8
        selected.extend([
            row for row in candidates if row["component_id"] == component_id
        ][:limit])
    return {
        "interpretation": (
            "Host-ranked persisted function claims. Selection is a bounded "
            "review suggestion, not evidence that a claim is wrong."
        ),
        "total": len(candidates),
        "returned": len(selected),
        "has_more": len(selected) < len(candidates),
        "candidates": selected,
    }


def _changed_stale_candidates(
    runtime: VerifiedIdaRuntime,
    closure_candidates: Mapping[str, Any],
) -> dict[str, Any]:
    """Combine notebook revisions with superseded durable edit surfaces.

    A missing notebook entry must not make the changed/stale lane disappear.
    Multiple model-authored operations on one logical edit surface are a
    deterministic reason to review propagation, not evidence that either
    interpretation is wrong.
    """

    closure_items = [
        dict(row)
        for row in (closure_candidates.get("items") or [])
        if isinstance(row, Mapping)
    ]
    rows = runtime.journal.connection.execute(
        """
        SELECT o.rowid AS operation_rowid, o.operation_id, o.component_id,
               o.kind, o.target_kind, o.target_key, o.operation_digest,
               o.request_json
        FROM operations o
        ORDER BY o.rowid
        """
    ).fetchall()
    grouped: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        item = dict(row)
        request = json.loads(str(item.pop("request_json") or "{}"))
        item["request"] = request
        key = operation_surface_identity(
            request,
            component_id=str(item.get("component_id") or ""),
        )
        grouped[key].append(item)

    superseded = []
    for (component_id, kind, target_kind, surface_key), history in sorted(
        grouped.items()
    ):
        if len(history) < 2:
            continue
        digests = list(dict.fromkeys(
            str(row.get("operation_digest") or "") for row in history
        ))
        if len(digests) < 2:
            continue
        superseded.append({
            "candidate_id": "changed-surface-%s-%s" % (
                component_id,
                hashlib.sha256(
                    ("%s|%s|%s" % (kind, target_kind, surface_key)).encode("utf-8")
                ).hexdigest()[:16],
            ),
            "tier": "A1",
            "kind": "superseded_semantic_edit",
            "component_id": component_id,
            "target_kind": target_kind,
            "target_key": str(history[-1].get("target_key") or ""),
            "surface_key": surface_key,
            "edit_kind": kind,
            "operation_ids_oldest_to_newest": [
                str(row["operation_id"]) for row in history
            ],
            "distinct_operation_digest_count": len(digests),
            "current_operation_id": str(history[-1]["operation_id"]),
            "deterministic_reasons": [
                "This logical edit surface received more than one distinct durable operation.",
                "Review whether the newest interpretation propagated to related names, comments, interfaces, types, and relationships.",
            ],
        })

    combined = closure_items + superseded
    return {
        "interpretation": (
            "Notebook revision notes and superseded durable edit surfaces. "
            "These are review candidates, not evidence that the current state is wrong."
        ),
        "total": len(combined),
        "returned": len(combined),
        "has_more": False,
        "items": combined,
        "notebook_candidate_count": len(closure_items),
        "superseded_surface_count": len(superseded),
    }


def _final_type_application(
    runtime: VerifiedIdaRuntime,
    states: Mapping[str, Mapping[str, Any]],
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = []
    for component in runtime.journal.components():
        component_id = str(component["component_id"])
        revision = int(runtime.journal.revision(component_id)["revision"])
        state = states.get(component_id) or {}
        for type_name in model_created_type_names(
            operations, component_id=component_id
        ):
            rows.append(measure_type_application(
                state,
                type_name=type_name,
                component_id=component_id,
                revision=revision,
                limit=8,
            ))
    return rows


def build_final_review_packets(
    runtime: VerifiedIdaRuntime,
    closure_result: Mapping[str, Any],
) -> dict[str, Any]:
    """Build V2-aware facts and independent final-review packets."""

    states = _live_semantic_states(runtime)
    model_components = runtime.list_components()["components"]
    functions = _function_maps(states)
    operations = runtime.journal.current_operations()
    verified_operations = [
        row for row in operations
        if dict(row.get("receipt") or {}).get("status") in VERIFIED_STATUSES
    ]
    closure_packet = dict(closure_result.get("packet") or {})
    base_preflight = _deterministic_preflight_from_state(states, operations)
    type_application = _final_type_application(runtime, states, operations)
    claim_risk = _claim_risk_candidates(
        runtime, states, functions, verified_operations
    )
    function_claims = _function_claim_candidates(
        closure_result, functions, verified_operations
    )
    support_boundary = _support_boundary_candidates(
        runtime, closure_result, functions, verified_operations
    )
    closure_candidates = dict(closure_packet.get("review_candidates") or {})
    changed_stale_candidates = _changed_stale_candidates(
        runtime, closure_candidates
    )
    exact = {
        **base_preflight,
        "schema": "verified_ida.final_review_exact_measurements.v1",
        "named_type_application": type_application,
    }
    ranked = {
        "schema": "verified_ida.final_review_ranked_candidates.v1",
        "semantic_judgment": False,
        "function_claims": function_claims,
        "claim_risk": claim_risk,
        "support_boundary": support_boundary,
        "same_agent_closure_candidates": closure_candidates,
    }
    preflight = {
        "schema": "verified_ida.final_review_preflight.v1",
        "objective": runtime.project_objective,
        "contract": {
            "exact_measurements_are_scope_bound_facts": True,
            "ranked_candidates_are_not_findings": True,
            "semantic_judgment": False,
            "canonical_mutation": False,
            "report_evidence_refs": "current_live_citations_only",
            "historical_evidence_refs": "provenance_only_not_citeable",
        },
        "components": model_components,
        "exact_measurements": exact,
        "ranked_candidates": ranked,
    }
    common = {
        "objective": runtime.project_objective,
        "review_contract": {
            "read_only": True,
            "current_narrative_is_evidence_not_truth": True,
            "inventory_counts_are_not_completion_quotas": True,
            "live_inspection_required_for_semantic_findings": True,
            "report_evidence_refs": "current_live_citations_only",
            "historical_evidence_refs": "provenance_only_not_citeable",
        },
        "components": model_components,
        "notebook": _review_notebook_context(closure_result),
    }
    claim_lanes = {
        "local_identity": {
            "purpose": (
                "Test persisted local behavior, wrapper/callee attribution, "
                "and any numeric roles asserted by function names or comments."
            ),
            "exact_measurements": {
                "current_mechanical_failures": exact["current_mechanical_failures"],
            },
            "ranked_candidates": function_claims,
        },
        "interface_type": {
            "purpose": "Test prototypes, calling conventions, type layouts, extents, and application.",
            "exact_measurements": {
                "named_type_application": type_application,
                "function_prototype_application": exact[
                    "function_prototype_application"
                ],
            },
            "ranked_candidates": {
                "candidates": [
                    row for row in claim_risk["candidates"]
                    if row["kind"] in {"named_type_support", "prototype_support"}
                ]
            },
        },
        "relationship": {
            "purpose": "Test persisted relationship semantics and endpoint roles.",
            "exact_measurements": {
                "relationship_endpoint_integrity": exact[
                    "relationship_endpoint_integrity"
                ],
            },
            "ranked_candidates": {
                "candidates": [
                    row for row in claim_risk["candidates"]
                    if row["kind"] == "relationship_support"
                ]
            },
        },
        "changed_stale": {
            "purpose": "Test revised conclusions, stale annotations, and unsupported specificity.",
            "exact_measurements": {
                "current_mechanical_failures": exact["current_mechanical_failures"],
            },
            "ranked_candidates": changed_stale_candidates,
        },
    }
    claim_packets = {}
    for lane, body in claim_lanes.items():
        packet = {
            "schema": "verified_ida.final_claim_lane.packet.v1",
            **common,
            "lane": lane,
            **body,
        }
        packet["packet_sha256"] = hashlib.sha256(
            canonical_json(packet).encode("utf-8")
        ).hexdigest()
        claim_packets[lane] = packet

    system_model = {
        "schema": "verified_ida.final_system_model.packet.v1",
        **common,
        "attention": _attention_summary(runtime),
        "live_project_summaries": dict(
            closure_packet.get("live_project_summaries") or {}
        ),
        "declared_references": list(
            closure_packet.get("declared_references") or []
        ),
        "instruction": (
            "Build the supported system model before selecting individual "
            "artifacts. Architectural symmetry alone is not evidence of a gap."
        ),
    }
    system_model["packet_sha256"] = hashlib.sha256(
        canonical_json(system_model).encode("utf-8")
    ).hexdigest()
    artifact_coverage = {
        "schema": "verified_ida.final_artifact_coverage.packet.v1",
        **common,
        "attention": _attention_summary(runtime),
        "support_boundary": support_boundary,
        "same_agent_closure_candidates": closure_candidates,
        "excluded_signals": [
            "architectural symmetry without binary evidence",
            "anonymous status alone",
            "function size alone",
            "component attention imbalance alone",
            "model self-confidence",
        ],
    }
    artifact_coverage["packet_sha256"] = hashlib.sha256(
        canonical_json(artifact_coverage).encode("utf-8")
    ).hexdigest()
    preflight["packet_sha256"] = hashlib.sha256(
        canonical_json(preflight).encode("utf-8")
    ).hexdigest()
    return {
        "preflight": preflight,
        "claim_lanes": claim_packets,
        "system_model": system_model,
        "artifact_coverage": artifact_coverage,
    }


def build_review_packet(
    runtime: VerifiedIdaRuntime,
    closure_result: Mapping[str, Any],
    *,
    review_mode: str = "narrative_v1",
) -> dict[str, Any]:
    packet = {
        "schema": "verified_ida.project_coverage_review.packet.v1",
        "objective": runtime.project_objective,
        "review_contract": {
            "read_only": True,
            "gold_blind": True,
            "current_narrative_is_evidence_not_truth": True,
            "inventory_counts_are_not_completion_quotas": True,
        },
        "attention": _attention_summary(runtime),
        "analysis_closure": dict(closure_result.get("packet") or {}),
        "review_mode": review_mode,
    }
    if review_mode == "structural_v2":
        packet["structural_frontier"] = _structural_frontier(
            runtime, closure_result
        )
    packet["packet_sha256"] = hashlib.sha256(
        canonical_json(packet).encode("utf-8")
    ).hexdigest()
    return packet


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv or sys.argv[1:]))
    environment = _environment()
    source_provenance = describe_source(ida_backend="process")
    project_dir = args.project_dir.expanduser().resolve()
    output_dir = args.output_dir.expanduser().resolve()
    if not (project_dir / "verified_ida.sqlite").is_file():
        raise SystemExit("Review requires an existing Verified IDA project copy")
    output_dir.mkdir(parents=True, exist_ok=True)

    from agents import Agent, ModelSettings, Runner, set_tracing_disabled  # type: ignore
    from openai.types.shared.reasoning import Reasoning  # type: ignore

    set_tracing_disabled(True)
    runtime = VerifiedIdaRuntime.initialize(project_dir)
    try:
        closure_result = runtime.review_analysis_closure()
        packet = build_review_packet(
            runtime, closure_result, review_mode=args.review_mode
        )
        packet_path = output_dir / "project_coverage_packet.json"
        packet_path.write_text(
            json.dumps(packet, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        instructions = REVIEW_PROMPTS[args.review_mode].read_text(encoding="utf-8")
        prompt = (
            "Perform the project-scale semantic coverage review described in "
            "your instructions. The host-generated review packet is:\n\n"
            + json.dumps(packet, sort_keys=True, ensure_ascii=False)
        )
        segment_id = _segment_id()
        trace = ObservableTrace(output_dir / "observable_tool_trace.jsonl")
        trace.append(
            "project_coverage_review_started",
            segment_id=segment_id,
            actor="harness",
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            review_mode=args.review_mode,
            source=source_provenance,
            environment=environment,
            project_dir=str(project_dir),
            packet_path=str(packet_path),
            packet_sha256=packet["packet_sha256"],
            allowed_tools=sorted(READ_ONLY_REVIEW_TOOLS),
        )
        adapter = VerifiedIdaToolAdapter(runtime)
        tool_state = ToolInvocationState()
        agent = Agent(
            name="Verified IDA Project Coverage Reviewer",
            model=args.model,
            model_settings=ModelSettings(
                reasoning=Reasoning(effort=args.reasoning_effort),
                include_usage=True,
                parallel_tool_calls=False,
                store=False,
                context_management=[{
                    "type": "compaction",
                    "compact_threshold": 200_000,
                }],
            ),
            instructions=instructions,
            tools=_function_tools(
                adapter,
                trace,
                tool_state,
                segment_id,
                allowed_names=READ_ONLY_REVIEW_TOOLS,
            ),
        )
        result = Runner.run_sync(
            agent,
            prompt,
            max_turns=max(2, int(args.max_agent_turns)),
            hooks=_observable_hooks(
                trace,
                runtime,
                segment_id=segment_id,
                compact_threshold_tokens=200_000,
            ),
        )
        review = str(getattr(result, "final_output", "") or "")
        review_path = output_dir / "review.md"
        review_path.write_text(review.rstrip() + "\n", encoding="utf-8")
        trace.append(
            "project_coverage_review_completed",
            segment_id=segment_id,
            actor="harness",
            review_path=str(review_path),
            review_sha256=hashlib.sha256(review.encode("utf-8")).hexdigest(),
        )
        walkthrough = write_walkthrough(trace, output_dir / "walkthrough.md")
        events, parse_errors = trace.read()
        summary = {
            "schema": "verified_ida.project_coverage_review.summary.v1",
            "status": "completed",
            "model": args.model,
            "reasoning_effort": args.reasoning_effort,
            "review_mode": args.review_mode,
            "source": source_provenance,
            "environment": environment,
            "usage": aggregate_usage(events),
            "event_counts": event_counts(events),
            "trace_parse_errors": parse_errors,
            "project_dir": str(project_dir),
            "packet": str(packet_path),
            "review": str(review_path),
            "walkthrough": walkthrough,
            "read_only_tool_surface": sorted(READ_ONLY_REVIEW_TOOLS),
        }
        (output_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    finally:
        runtime.close()


if __name__ == "__main__":
    raise SystemExit(main())
