"""Bounded, advisory analysis-closure review for a Verified IDA project.

The host does not decide whether an annotation is semantically correct.  It
assembles current project evidence, finds conservative consistency questions on
model-declared or model-edited artifacts, and asks the model to review them.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, Mapping, Sequence

from .contracts import VERIFIED_STATUSES, canonical_json


CLOSURE_REVIEW_SCHEMA = "verified_ida.analysis_closure_review.v1"
MAX_CANDIDATES = 24
MAX_TOUCHED_ARTIFACTS = 120
_QUALIFIED_ADDRESS = re.compile(
    r"(?<![A-Za-z0-9_.-])(?P<component>[A-Za-z0-9_.-]+)(?P<separator>::?)"
    r"(?P<address>0x[0-9A-Fa-f]+)\b"
)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _address(value: Any) -> str | None:
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        return None


def declared_references(
    current_state: Mapping[str, Mapping[str, Any]],
    *,
    component_ids: list[str] | tuple[str, ...] = (),
) -> list[dict[str, Any]]:
    """Extract explicit references and canonicalize the bounded legacy spelling."""

    known_by_casefold: dict[str, list[str]] = {}
    for value in component_ids:
        component_id = str(value or "")
        if component_id:
            known_by_casefold.setdefault(component_id.casefold(), []).append(component_id)
    references: dict[tuple[str, str], set[str]] = {}
    spellings: dict[tuple[str, str], set[str]] = {}
    for section, row in current_state.items():
        content = str((row or {}).get("content") or "")
        for match in _QUALIFIED_ADDRESS.finditer(content):
            source_component = match.group("component")
            matches = known_by_casefold.get(source_component.casefold()) or []
            component_id = matches[0] if len(matches) == 1 else source_component
            key = (component_id, hex(int(match.group("address"), 16)))
            references.setdefault(key, set()).add(str(section))
            spellings.setdefault(key, set()).add(match.group(0))
    return [
        {
            "component_id": component_id,
            "address": address,
            "qualified_address": "%s::%s" % (component_id, address),
            "sections": sorted(sections),
            "source_spellings": sorted(spellings[(component_id, address)]),
            "normalized": any(
                value != "%s::%s" % (component_id, address)
                for value in spellings[(component_id, address)]
            ),
        }
        for (component_id, address), sections in sorted(references.items())
    ]


def _verified_current_operations(
    operations: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    results = []
    for row in operations:
        receipt = dict(row.get("receipt") or {})
        if receipt.get("status") not in VERIFIED_STATUSES:
            continue
        request = dict(row.get("request") or {})
        target = dict(request.get("target") or {})
        results.append({
            "operation_rowid": int(row.get("operation_rowid") or 0),
            "operation_id": str(row.get("operation_id") or ""),
            "component_id": str(row.get("component_id") or ""),
            "kind": str(row.get("kind") or request.get("kind") or ""),
            "target_kind": str(row.get("target_kind") or target.get("kind") or ""),
            "target_key": str(row.get("target_key") or ""),
            "target": target,
            "desired": dict(request.get("desired") or {}),
            "status": str(receipt.get("status") or ""),
            "persistence": str(receipt.get("persistence") or ""),
            "created_at": str(row.get("created_at") or ""),
        })
    return results


def touched_function_addresses(
    operations: list[Mapping[str, Any]],
    references: list[Mapping[str, Any]],
) -> list[tuple[str, str]]:
    values = {
        (str(row["component_id"]), str(row["address"])) for row in references
    }
    for row in _verified_current_operations(operations):
        component = row["component_id"]
        target = row["target"]
        kind = target.get("kind")
        candidates: list[Any] = []
        if kind == "function":
            candidates.append(target.get("address"))
        elif kind == "local_variable":
            candidates.append(target.get("function_address"))
        elif kind == "relationship":
            candidates.extend([
                target.get("source_address"), target.get("destination_address")
            ])
        for candidate in candidates:
            normalized = _address(candidate)
            if normalized:
                values.add((component, normalized))
    return sorted(values)


def build_closure_packet(
    *,
    objective: str,
    notebook: Mapping[str, Any],
    components: list[Mapping[str, Any]],
    revisions: Mapping[str, int],
    operations: list[Mapping[str, Any]],
    frontier: Mapping[str, Any],
    live_project_summaries: Mapping[str, Any],
    live_functions: Mapping[str, Mapping[str, Any]],
    analysis_advisories: Sequence[Mapping[str, Any]] = (),
    call_flow: Mapping[str, Any] | None = None,
) -> tuple[dict[str, Any], str]:
    """Build stable review content and its digest from durable/live state."""

    current_state = dict(notebook.get("current_state") or {})
    references = declared_references(
        current_state,
        component_ids=tuple(
            str(row.get("component_id") or "")
            for row in components
            if row.get("component_id")
        ),
    )
    verified = _verified_current_operations(operations)
    annotated_addresses: set[tuple[str, str]] = set()
    for row in verified:
        target = row["target"]
        addresses: list[Any] = []
        if row["kind"] in {
            "function.rename", "function.comment.set", "function.prototype.set"
        }:
            addresses.append(target.get("address"))
        elif row["kind"] == "relationship.annotate":
            addresses.extend([
                target.get("source_address"), target.get("destination_address")
            ])
        for value in addresses:
            normalized = _address(value)
            if normalized:
                annotated_addresses.add((row["component_id"], normalized))

    candidates: list[dict[str, Any]] = []

    def add(
        code: str,
        *,
        component_id: str,
        target: str,
        evidence: Mapping[str, Any],
        question: str,
    ) -> None:
        if len(candidates) >= MAX_CANDIDATES:
            return
        identity = (code, component_id, target)
        if any(
            (row["code"], row["component_id"], row["target"]) == identity
            for row in candidates
        ):
            return
        candidates.append({
            "candidate_id": "closure-%s" % _digest(identity)[:20],
            "code": code,
            "component_id": component_id,
            "target": target,
            "evidence": dict(evidence),
            "question": question,
            "advisory": True,
        })

    for reference in references:
        key = (reference["component_id"], reference["address"])
        if key not in annotated_addresses:
            add(
                "declared_function_without_recorded_edit",
                component_id=reference["component_id"],
                target=reference["qualified_address"],
                evidence={"notebook_sections": reference["sections"]},
                question=(
                    "The notebook relies on this function, but no current verified "
                    "model edit is recorded for it. Does the live IDB already express "
                    "the relied-upon conclusion, or should a supported annotation be "
                    "added?"
                ),
            )

    relied_functions = touched_function_addresses(operations, references)
    for component_id, address in relied_functions:
        qualified = "%s::%s" % (component_id, address)
        live = dict(live_functions.get(qualified) or {})
        function = dict(live.get("function") or {})
        prototype = str(function.get("prototype") or "")
        backend_unconfirmed_parameters = [
            {
                "index": row.get("index"),
                "name": row.get("name"),
                "type": row.get("type"),
                "has_user_name": row.get("has_user_name"),
                "name_provenance": row.get("name_provenance"),
                "has_user_type": row.get("has_user_type"),
                "type_provenance": row.get("type_provenance"),
            }
            for row in live.get("parameters") or []
            if (
                isinstance(row, Mapping)
                and row.get("is_arg")
                and row.get("has_user_name") is False
                and row.get("has_user_type") is False
            )
        ]
        if prototype and backend_unconfirmed_parameters:
            add(
                "unconfirmed_interface_on_relied_function",
                component_id=component_id,
                target=qualified,
                evidence={
                    "prototype": prototype,
                    "backend_confirmed_unmodified_parameters": (
                        backend_unconfirmed_parameters
                    ),
                    "live_evidence": live.get("evidence"),
                    "parameter_evidence": live.get("parameter_evidence"),
                },
                question=(
                    "IDA reports that this relied-upon function still has one or "
                    "more parameters with neither a user name nor a user type. "
                    "Would a more precise, evidence-supported interface materially "
                    "improve the analysis?"
                ),
            )

    changed_refs = [
        row for row in references
        if "changed_conclusions_and_impact" in row["sections"]
    ]
    for reference in changed_refs:
        relevant = [
            row for row in verified
            if row["component_id"] == reference["component_id"]
            and reference["address"] in {
                _address(row["target"].get("address")),
                _address(row["target"].get("function_address")),
                _address(row["target"].get("source_address")),
                _address(row["target"].get("destination_address")),
            }
        ]
        if not relevant:
            continue
        add(
            "revised_conclusion_propagation_review",
            component_id=reference["component_id"],
            target=reference["qualified_address"],
            evidence={
                "notebook_section": "changed_conclusions_and_impact",
                "current_operation_ids": [row["operation_id"] for row in relevant],
                "live_evidence": (
                    live_functions.get(reference["qualified_address"], {}) or {}
                ).get("evidence"),
            },
            question=(
                "The notebook says a conclusion affecting this function changed. "
                "Does the current name, comment, interface, type use, and any related "
                "annotation consistently reflect the revised interpretation?"
            ),
        )

    boundary_targets: set[tuple[str, str]] = set()
    for row in verified:
        if row["kind"] not in {"function.rename", "function.comment.set"}:
            continue
        address = _address(row["target"].get("address"))
        if address:
            boundary_targets.add((row["component_id"], address))
    for component_id, address in sorted(boundary_targets)[:8]:
        qualified = "%s::%s" % (component_id, address)
        live = dict(live_functions.get(qualified) or {})
        callees = list(live.get("callees") or [])
        if not callees:
            continue
        function = dict(live.get("function") or {})
        add(
            "local_vs_downstream_behavior_review",
            component_id=component_id,
            target=qualified,
            evidence={
                "local": {
                    "name": function.get("name"),
                    "comment": function.get("comment"),
                    "prototype": function.get("prototype"),
                    "evidence": live.get("evidence"),
                },
                "direct_callees": callees[:8],
                "callee_evidence": live.get("callee_evidence"),
                "selection_reason": (
                    "The function has a durable behavioral annotation and at "
                    "least one direct callee."
                ),
            },
            question=(
                "Does this function's name and comment describe behavior performed "
                "locally, rather than merely repeating a callee's action or the "
                "surrounding subsystem's purpose?"
            ),
        )

    operation_components = {row["component_id"] for row in verified}
    for component in components:
        component_id = str(component.get("component_id") or "")
        if (
            component_id
            and component.get("parent_component_id")
            and component.get("idb_path")
            and component_id not in operation_components
        ):
            add(
                "accepted_component_without_durable_analysis",
                component_id=component_id,
                target=component_id,
                evidence={
                    "parent_component_id": component.get("parent_component_id"),
                    "status": component.get("status"),
                    "architecture": component.get("architecture"),
                    "live_summary": live_project_summaries.get(component_id),
                },
                question=(
                    "This accepted executable component has no current verified IDB "
                    "edits. Has its consequential behavior been analyzed and captured, "
                    "or is material component work still outstanding?"
                ),
            )

    touched = verified[-MAX_TOUCHED_ARTIFACTS:]
    touched_summary = [{
        key: row[key]
        for key in (
            "operation_id", "component_id", "kind", "target_kind", "target_key",
            "target", "desired", "status", "persistence",
        )
    } for row in touched]
    component_summary = [{
        "component_id": row.get("component_id"),
        "parent_component_id": row.get("parent_component_id"),
        "depth": row.get("depth"),
        "binary_sha256": row.get("binary_sha256"),
        "architecture": row.get("architecture"),
        "status": row.get("status"),
        "has_idb": bool(row.get("idb_path")),
        "database_revision": int(revisions.get(str(row.get("component_id")), 0)),
    } for row in components]

    packet = {
        "schema": CLOSURE_REVIEW_SCHEMA,
        "policy": {
            "advisory": True,
            "blocks_completion": False,
            "semantic_verdicts": False,
            "scope": (
                "explicit notebook references and current verified model edits; "
                "unseen scanner inventory is not converted into obligations"
            ),
        },
        "objective": str(objective),
        "notebook": {
            "document_digest": notebook.get("document_digest"),
            "current_state": current_state,
            "freshness": notebook.get("freshness") or {},
        },
        "components": component_summary,
        "frontier": dict(frontier),
        "claim_scoped_call_flow": dict(call_flow or {}),
        "analysis_advisories": {
            "advisory": True,
            "completion_blocker": False,
            "total": len(analysis_advisories),
            "items": [dict(row) for row in analysis_advisories],
        },
        "live_project_summaries": dict(live_project_summaries),
        "declared_references": references,
        "touched_artifacts": {
            "total": len(verified),
            "returned": len(touched_summary),
            "has_more": len(verified) > len(touched_summary),
            "items": touched_summary,
        },
        "review_candidates": {
            "total": len(candidates),
            "bounded_at": MAX_CANDIDATES,
            "items": candidates,
        },
        "review_questions": [
            "Does each consequential behavior claim have durable support in the relevant IDB?",
            "Do consequential function names describe local behavior rather than downstream effects?",
            "Would more precise interfaces or shared types materially improve functions already relied upon?",
            "Were revised interpretations propagated through affected durable annotations?",
            "Are parent and child conclusions supported independently in each component IDB?",
            "What important work remains, and is it complete, uncertain, deferred, or nonmaterial?",
        ],
        "requested_action": (
            "Review the evidence and questions against live IDA state. Update the "
            "Closure Review notebook section. Continue analysis if material gaps "
            "remain; otherwise record why the analysis is complete before requesting "
            "mechanical completion."
        ),
    }
    return packet, _digest(packet)
