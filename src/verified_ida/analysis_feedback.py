"""Bounded, host-measured feedback about the effects of one IDA edit.

The measurements in this module describe current artifact state.  They do not
judge whether an annotation or type is semantically correct.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


ANALYSIS_FEEDBACK_SCHEMA = "verified_ida.analysis_feedback.v1"
ANALYSIS_FEEDBACK_SCHEMA_V2 = "verified_ida.analysis_feedback.v2"
ANALYSIS_ADVISORY_SCHEMA = "verified_ida.analysis_advisory.v1"
ANALYSIS_FEEDBACK_PROFILES = ("none", "scoped")
DEFAULT_EXAMPLE_LIMIT = 4
DEFAULT_ADVISORY_LIMIT = 12
MAX_TEXT_LENGTH = 512

TYPE_APPLICATION_OPERATIONS = (
    {
        "tool": "edit_ida",
        "edit_kind": "function.prototype.set",
        "surface": "function_parameter_or_return_type",
        "requires": "an inspected function target_ref and evidence-supported declaration",
    },
    {
        "tool": "edit_ida",
        "edit_kind": "local.type.set",
        "surface": "selected_function_local_or_parameter",
        "requires": "an inspected local target_ref and evidence-supported declaration",
    },
    {
        "tool": "edit_ida",
        "edit_kind": "global.type.set",
        "surface": "global_declaration",
        "requires": "an inspected global target_ref and evidence-supported declaration",
    },
)

_MATERIAL_PROPAGATION_KINDS = frozenset({
    "function.prototype.set",
    "local.type.set",
    "global.type.set",
    "named_type.create_or_update",
})


def _bounded_text(value: Any, limit: int = MAX_TEXT_LENGTH) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _identifier_present(text: Any, name: str) -> bool:
    """Match a C/C++ type identifier without substring false positives."""

    if not name:
        return False
    # A scoped C++ name is one identifier here: Owner::Nested is not Owner.
    token = r"[A-Za-z0-9_$?@:]"
    return bool(re.search(
        r"(?<!%s)%s(?!%s)" % (token, re.escape(name), token),
        str(text or ""),
    ))


def _type_dependency_match(
    row: Mapping[str, Any],
    *,
    rendered_field: str,
    type_name: str,
) -> tuple[bool | None, str]:
    """Prefer tinfo_t traversal and retain exact lexical matching as fallback."""

    dependencies = row.get("type_dependencies")
    if isinstance(dependencies, list):
        if type_name in {str(value) for value in dependencies}:
            return True, "ida_tinfo_dependency"
        if (row.get("type_dependency_scan") or {}).get("complete") is True:
            return False, "ida_tinfo_dependency"
    if _identifier_present(row.get(rendered_field), type_name):
        return True, "exact_identifier_fallback"
    return None, "unavailable_or_incomplete"


def compact_propagation(
    receipt: Mapping[str, Any],
    *,
    component_id: str,
    limit: int = DEFAULT_EXAMPLE_LIMIT,
) -> dict[str, Any] | None:
    """Expose bounded native decompiler effects already present in a receipt."""

    effects = receipt.get("effects") or {}
    if not isinstance(effects, Mapping):
        return None
    rows = [
        dict(row) for row in (effects.get("decompiler_functions") or [])
        if isinstance(row, Mapping)
    ]
    if not rows and effects.get("refresh_count") is None:
        return None
    changed = [row for row in rows if bool(row.get("changed"))]
    examples = []
    for row in rows[: max(0, int(limit))]:
        before = dict(row.get("before") or {})
        after = dict(row.get("after") or {})
        address = str(row.get("address") or "")
        examples.append({
            "target": "%s::%s" % (component_id, address) if address else component_id,
            "changed": bool(row.get("changed")),
            "before": {
                key: before[key]
                for key in ("available", "length", "sha256", "error")
                if key in before
            },
            "after": {
                key: after[key]
                for key in ("available", "length", "sha256", "error")
                if key in after
            },
        })
    return {
        "refreshed_function_count": int(
            effects.get("refresh_count")
            if effects.get("refresh_count") is not None
            else len(rows)
        ),
        "changed_rendering_count": len(changed),
        "examples": examples,
        "examples_truncated": len(rows) > len(examples),
        "interpretation": (
            "A rendering change is a mechanical decompiler observation, not "
            "evidence that the edit improved or correctly interpreted the code."
        ),
    }


def _normalized_address(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        return None


def _operation_function_address(operation: Mapping[str, Any]) -> str | None:
    target = operation.get("target") or {}
    for key in ("function_address", "address"):
        address = _normalized_address(target.get(key))
        if address:
            return address
    return None


def compact_selective_propagation(
    receipt: Mapping[str, Any],
    *,
    operation: Mapping[str, Any],
    component_id: str,
    limit: int = DEFAULT_EXAMPLE_LIMIT,
) -> dict[str, Any] | None:
    """Report only consequential or out-of-target rendering changes.

    A function rename, comment, or local rename normally changes the edited
    function's rendering. Repeating that expected fact caused models to reopen
    the same function without gaining evidence. V2 suppresses that target-local
    noise while retaining downstream changes and effects from interface/type
    operations.
    """

    effects = receipt.get("effects") or {}
    if not isinstance(effects, Mapping):
        return None
    changed = [
        dict(row) for row in (effects.get("decompiler_functions") or [])
        if isinstance(row, Mapping) and bool(row.get("changed"))
    ]
    kind = str(operation.get("kind") or "")
    if kind in _MATERIAL_PROPAGATION_KINDS:
        selected = changed
        scope = "interface_or_type_rendering_changes"
    else:
        target_address = _operation_function_address(operation)
        if not target_address:
            return None
        selected = [
            row for row in changed
            if _normalized_address(row.get("address")) != target_address
        ]
        scope = "out_of_target_rendering_changes_only"
    if not selected:
        return None

    examples = []
    for row in selected[: max(0, int(limit))]:
        before = dict(row.get("before") or {})
        after = dict(row.get("after") or {})
        address = str(row.get("address") or "")
        examples.append({
            "target": "%s::%s" % (component_id, address) if address else component_id,
            "changed": True,
            "before": {
                key: before[key]
                for key in ("available", "length", "sha256", "error")
                if key in before
            },
            "after": {
                key: after[key]
                for key in ("available", "length", "sha256", "error")
                if key in after
            },
        })
    return {
        "scope": scope,
        "reported_changed_rendering_count": len(selected),
        "examples": examples,
        "examples_truncated": len(selected) > len(examples),
        "interpretation": (
            "These are bounded mechanical rendering effects outside routine "
            "target-local rename/comment readback, not evidence that the edit "
            "improved or correctly interpreted the code."
        ),
    }


def load_checkpoint_state(
    checkpoint: Mapping[str, Any] | None,
) -> tuple[dict[str, Any] | None, str | None]:
    """Load one verified semantic checkpoint without exposing its host path."""

    if not checkpoint or checkpoint.get("status") != "verified":
        return None, "verified_checkpoint_unavailable"
    details = checkpoint.get("details") or {}
    if not isinstance(details, Mapping):
        return None, "semantic_checkpoint_details_unavailable"
    source = details.get("semantic_export_path")
    if not source:
        return None, "semantic_export_unavailable"
    path = Path(str(source))
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None, "semantic_export_unreadable"
    state = payload.get("state")
    if not isinstance(state, Mapping):
        return None, "semantic_state_unavailable"
    return dict(state), None


def model_created_type_names(
    operations: Sequence[Mapping[str, Any]],
    *,
    component_id: str,
) -> list[str]:
    names = []
    for row in operations:
        if str(row.get("component_id") or "") != component_id:
            continue
        if row.get("kind") != "named_type.create_or_update":
            continue
        if row.get("resolution_outcome") == "abandoned":
            continue
        receipt = row.get("receipt") or {}
        if not isinstance(receipt, Mapping) or receipt.get("status") not in {
            "verified", "verified_existing"
        }:
            continue
        request = row.get("request") or {}
        target = request.get("target") or {}
        name = str(target.get("name") or target.get("current_name") or "").strip()
        if name and name not in names:
            names.append(name)
    return names


def relevant_type_names(
    operation: Mapping[str, Any],
    *,
    model_type_names: Sequence[str],
) -> list[str]:
    kind = str(operation.get("kind") or "")
    target = operation.get("target") or {}
    desired = operation.get("desired") or {}
    if kind == "named_type.create_or_update":
        name = str(target.get("name") or target.get("current_name") or "").strip()
        return [name] if name else []
    if kind not in {"function.prototype.set", "global.type.set", "local.type.set"}:
        return []
    declaration = str(desired.get("declaration") or "")
    return [
        name for name in model_type_names
        if _identifier_present(declaration, str(name))
    ]


def _type_kind(state: Mapping[str, Any], name: str) -> str | None:
    for collection in ("named_types", "structs", "enums"):
        for raw in state.get(collection) or []:
            row = dict(raw) if isinstance(raw, Mapping) else {}
            if row.get("name") == name:
                return str(row.get("kind") or collection.rstrip("s"))
    return None


def measure_type_application(
    state: Mapping[str, Any],
    *,
    type_name: str,
    component_id: str,
    revision: int,
    limit: int = DEFAULT_EXAMPLE_LIMIT,
) -> dict[str, Any]:
    """Count exact named-type uses on the semantic export's measured surfaces."""

    cap = max(0, int(limit))
    measurement_methods: dict[str, int] = {}
    incomplete_rows = 0
    lexical_candidates = []

    def matched(
        row: Mapping[str, Any],
        *,
        rendered_field: str,
        surface: str,
    ) -> bool:
        nonlocal incomplete_rows
        present, method = _type_dependency_match(
            row,
            rendered_field=rendered_field,
            type_name=type_name,
        )
        if (row.get("type_dependency_scan") or {}).get("complete") is not True:
            incomplete_rows += 1
        if present:
            measurement_methods[method] = measurement_methods.get(method, 0) + 1
            if method == "exact_identifier_fallback":
                lexical_candidates.append({
                    "surface": surface,
                    "address": row.get("address"),
                    "name": row.get("name"),
                    "declaration": _bounded_text(row.get(rendered_field)),
                })
        return present is True and method == "ida_tinfo_dependency"

    functions = []
    for raw in state.get("functions") or []:
        row = dict(raw) if isinstance(raw, Mapping) else {}
        prototype = str(row.get("prototype") or "")
        if matched(row, rendered_field="prototype", surface="function_prototypes"):
            functions.append({
                "target": "%s::%s" % (component_id, row.get("address")),
                "name": row.get("name"),
                "prototype": _bounded_text(prototype),
            })

    globals_ = []
    for raw in state.get("globals") or []:
        row = dict(raw) if isinstance(raw, Mapping) else {}
        declaration = str(row.get("declaration") or "")
        if matched(row, rendered_field="declaration", surface="globals"):
            globals_.append({
                "target": "%s::%s" % (component_id, row.get("address")),
                "name": row.get("name"),
                "declaration": _bounded_text(declaration),
            })

    member_uses = []
    for raw in state.get("structs") or []:
        owner = dict(raw) if isinstance(raw, Mapping) else {}
        for raw_member in owner.get("members") or []:
            member = dict(raw_member) if isinstance(raw_member, Mapping) else {}
            member_type = str(member.get("type") or "")
            if matched(member, rendered_field="type", surface="structure_members"):
                member_uses.append({
                    "owner": owner.get("name"),
                    "member": member.get("name"),
                    "offset": member.get("offset"),
                    "declaration": _bounded_text(member_type),
                })

    declaration_uses = []
    for raw in state.get("named_types") or []:
        row = dict(raw) if isinstance(raw, Mapping) else {}
        if row.get("name") == type_name:
            continue
        declaration = str(row.get("declaration") or "")
        if matched(row, rendered_field="declaration", surface="named_type_declarations"):
            declaration_uses.append({
                "name": row.get("name"),
                "kind": row.get("kind"),
                "declaration": _bounded_text(declaration),
            })

    locals_ = []
    selected_local_functions = 0
    for raw in state.get("functions") or []:
        function = dict(raw) if isinstance(raw, Mapping) else {}
        local_state = function.get("locals")
        if not isinstance(local_state, Mapping):
            continue
        selected_local_functions += 1
        for raw_local in local_state.get("items") or []:
            local = dict(raw_local) if isinstance(raw_local, Mapping) else {}
            declaration = str(local.get("declaration") or "")
            if matched(local, rendered_field="declaration", surface="selected_locals"):
                locals_.append({
                    "target": "%s::%s" % (component_id, function.get("address")),
                    "index": local.get("index"),
                    "name": local.get("name"),
                    "declaration": _bounded_text(declaration),
                })

    surfaces = {
        "function_prototypes": functions,
        "globals": globals_,
        "structure_members": member_uses,
        "named_type_declarations": declaration_uses,
        "selected_locals": locals_,
    }
    total = sum(len(rows) for rows in surfaces.values())
    return {
        "type_name": type_name,
        "type_kind": _type_kind(state, type_name),
        "component_id": component_id,
        "revision": int(revision),
        "status": (
            "applied_on_measured_surfaces" if total
            else "measurement_incomplete" if incomplete_rows
            else "declaration_only_currently"
        ),
        "measured_use_count": total,
        "lexical_candidates": {
            "count": len(lexical_candidates),
            "examples": lexical_candidates[:cap],
            "examples_truncated": len(lexical_candidates) > cap,
            "included_in_measured_use_count": False,
        },
        "measurement_complete": incomplete_rows == 0,
        "incomplete_row_count": incomplete_rows,
        "count_is_lower_bound": incomplete_rows > 0,
        "measurement_provenance": {
            "native_tinfo_dependency_count": measurement_methods.get(
                "ida_tinfo_dependency", 0
            ),
            "exact_identifier_fallback_count": measurement_methods.get(
                "exact_identifier_fallback", 0
            ),
            "fallback_is_advisory": True,
        },
        "surfaces": {
            key: {
                "count": len(rows),
                "examples": rows[:cap],
                "examples_truncated": len(rows) > cap,
            }
            for key, rows in surfaces.items()
        },
        "coverage": {
            "function_prototypes": "complete_for_exported_idb_functions",
            "globals": "complete_for_exported_named_or_typed_globals",
            "structure_members": "complete_for_exported_named_structures",
            "named_type_declarations": "complete_for_exported_named_types",
            "selected_locals": (
                "selected_edited_functions_only:%d" % selected_local_functions
            ),
            "operands_and_casts": "not_measured",
            "arbitrary_stack_locals": "not_measured",
        },
        "interpretation": (
            "Counts describe only the measured surfaces. An incomplete scan cannot "
            "establish absence; lexical matches are candidates, not measured uses. "
            "If this type was intended to clarify the program, inspect and apply it "
            "at evidence-supported sites; declaration-only state can also be intentional."
        ),
    }


def analysis_feedback_schema(profile: str) -> str:
    return (
        ANALYSIS_FEEDBACK_SCHEMA_V2
        if profile == "scoped"
        else ANALYSIS_FEEDBACK_SCHEMA
    )


def build_unapplied_type_advisory(
    *,
    profile: str,
    component_id: str,
    revision: int,
    current_operations: Sequence[Mapping[str, Any]],
    semantic_state: Mapping[str, Any] | None,
    limit: int = DEFAULT_ADVISORY_LIMIT,
) -> dict[str, Any] | None:
    """Reconstruct declaration-only type state without creating obligations."""

    if profile != "scoped" or semantic_state is None:
        return None
    rows = [
        measure_type_application(
            semantic_state,
            type_name=name,
            component_id=component_id,
            revision=revision,
        )
        for name in model_created_type_names(
            current_operations, component_id=component_id
        )
    ]
    unapplied = [
        {
            "type_name": row["type_name"],
            "type_kind": row["type_kind"],
            "status": row["status"],
            "measured_use_count": row["measured_use_count"],
        }
        for row in rows
        if row["status"] == "declaration_only_currently"
    ]
    if not unapplied:
        return None
    cap = max(0, int(limit))
    return {
        "schema": ANALYSIS_ADVISORY_SCHEMA,
        "kind": "declared_but_unapplied_types",
        "profile": profile,
        "provenance": "host_measured",
        "semantic_judgment": False,
        "completion_blocker": False,
        "component_id": component_id,
        "revision": int(revision),
        "total": len(unapplied),
        "returned": min(len(unapplied), cap),
        "has_more": len(unapplied) > cap,
        "items": unapplied[:cap],
        "supported_application_operations": [
            dict(row) for row in TYPE_APPLICATION_OPERATIONS
        ],
        "interpretation": (
            "These model-created types currently have no exact use on the measured "
            "prototype, global, named-member, named-declaration, or selected-local "
            "surfaces. This is advisory: apply a type only where evidence supports "
            "it, or record why declaration-only state is intentional."
        ),
    }


def build_analysis_feedback(
    *,
    profile: str,
    component_id: str,
    revision: int,
    operation: Mapping[str, Any],
    receipt: Mapping[str, Any],
    checkpoint: Mapping[str, Any] | None,
    current_operations: Sequence[Mapping[str, Any]],
) -> dict[str, Any] | None:
    if profile == "none":
        return None
    if profile != "scoped":
        raise ValueError("Unsupported analysis feedback profile: %s" % profile)
    feedback: dict[str, Any] = {
        "schema": analysis_feedback_schema(profile),
        "profile": profile,
        "provenance": "host_measured",
        "semantic_judgment": False,
        "component_id": component_id,
        "revision": int(revision),
    }
    propagation = compact_selective_propagation(
        receipt,
        operation=operation,
        component_id=component_id,
    )
    if propagation is not None:
        feedback["propagation"] = propagation
    semantic_delta = (receipt.get("effects") or {}).get("semantic_delta")
    if isinstance(semantic_delta, Mapping):
        feedback["durable_semantic_delta"] = dict(semantic_delta)

    names = relevant_type_names(
        operation,
        model_type_names=model_created_type_names(
            current_operations, component_id=component_id
        ),
    )[:4]
    if names:
        semantic_state, unavailable = load_checkpoint_state(checkpoint)
        feedback["type_application"] = {
            "measurement_status": (
                "measured" if semantic_state is not None else "unavailable"
            ),
            "types": (
                [
                    measure_type_application(
                        semantic_state,
                        type_name=name,
                        component_id=component_id,
                        revision=revision,
                    )
                    for name in names
                ]
                if semantic_state is not None else []
            ),
            "unavailable_reason": unavailable,
        }
        if profile == "scoped":
            feedback["type_application"]["supported_application_operations"] = [
                dict(row) for row in TYPE_APPLICATION_OPERATIONS
            ]
    if propagation is None and not names and not isinstance(semantic_delta, Mapping):
        return None
    return feedback
