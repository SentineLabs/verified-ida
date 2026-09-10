"""Gold-blind direct-closure checks and nonblocking discovery suggestions."""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .journal import VerifiedIdaJournal, stable_id


DEFAULT_PAGE_SIZE = 8
MAX_PAGE_SIZE = 20
GENERIC_FUNCTION_RE = re.compile(r"^(sub|loc|unknown|function)_[0-9a-f]+$", re.I)
GENERIC_LOCAL_RE = re.compile(r"^(a|v|arg|var)_?\d+$", re.I)
GENERIC_TYPE_NAMES = {
    "",
    "int",
    "unsigned int",
    "long",
    "unsigned long",
    "__int64",
    "unsigned __int64",
    "void *",
    "char *",
    "_qword",
    "_dword",
}
LOW_VALUE_PREFIXES = (
    "j_",
    "nullsub_",
    "__",
    "_purecall",
    "memcpy",
    "memset",
    "strlen",
    "std::",
)
PRIORITIES = {"critical", "high", "medium", "low"}


def _address(value: Any) -> str:
    if value in (None, ""):
        return ""
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        return str(value).strip().lower()


def _text(value: Any) -> str:
    return str(value or "").strip()


def _behavior_comment(value: Any) -> str:
    """Exclude transport markers from analyst-authored behavior text."""

    return "\n".join(
        line
        for line in _text(value).splitlines()
        if not line.startswith("[verified-folder] ")
        and not line.startswith("[verified-relationship:")
        and not line.startswith("[relationship:")
    ).strip()


def _function_view(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    for key in ("function", "context", "result"):
        value = payload.get(key)
        if isinstance(value, Mapping):
            nested = value.get("function")
            if isinstance(nested, Mapping):
                return nested
            if key != "result":
                return value
    return payload


def _candidate(
    *,
    component_id: str,
    target_kind: str,
    target_key: str,
    gap_kind: str,
    reasons: Iterable[str],
    lane: str,
    priority: str,
    tier: int,
    origin: str,
    trigger_revision: int,
    operation_id: str | None = None,
) -> dict[str, Any]:
    priority = priority if priority in PRIORITIES else "medium"
    return {
        "candidate_id": stable_id(
            "candidate", component_id, target_kind, target_key, gap_kind
        ),
        "component_id": component_id,
        "target_kind": target_kind,
        "target_key": target_key,
        "gap_kind": gap_kind,
        "lane": lane,
        "reasons": list(dict.fromkeys(str(reason) for reason in reasons if reason)),
        "priority": priority,
        "tier": int(tier),
        "origin": origin,
        "trigger_revision": int(trigger_revision),
        "operation_id": operation_id,
    }


def _probably_low_value(function: Mapping[str, Any]) -> bool:
    if function.get("is_library") or function.get("is_thunk"):
        return True
    name = _text(function.get("name") or function.get("current_name")).lower()
    if name.startswith(LOW_VALUE_PREFIXES):
        return True
    size = int(function.get("size") or 0)
    callees = function.get("callees") or []
    return bool(size and size <= 12 and not callees)


def _generic_function_name(name: str) -> bool:
    lowered = name.strip().lower()
    return not lowered or lowered.startswith("sub_") or bool(GENERIC_FUNCTION_RE.match(lowered))


def _parameters(function: Mapping[str, Any]) -> list[dict[str, Any]]:
    explicit = function.get("parameters") or function.get("arguments") or []
    if explicit:
        return [dict(row) for row in explicit if isinstance(row, Mapping)]
    return [
        dict(row)
        for row in function.get("locals") or function.get("lvars") or []
        if isinstance(row, Mapping)
        and bool(row.get("is_parameter") or row.get("is_arg"))
    ]


def _user_name_state(value: Mapping[str, Any]) -> bool | None:
    """Return backend name provenance without inferring it from spelling."""

    if value.get("has_user_name") is not None:
        return bool(value.get("has_user_name"))
    provenance = _text(value.get("name_provenance")).lower()
    if provenance == "user":
        return True
    if provenance in {"not_user_supplied", "auto", "generated"}:
        return False
    return None


def _edited_parameter(
    parameters: Iterable[Mapping[str, Any]], target: Mapping[str, Any]
) -> dict[str, Any] | None:
    rows = [dict(row) for row in parameters]
    target_index = target.get("lvar_index")
    if target_index is not None:
        for row in rows:
            row_index = row.get("index", row.get("lvar_index"))
            if row_index is not None:
                try:
                    matches_index = int(str(row_index), 0) == int(
                        str(target_index), 0
                    )
                except ValueError:
                    matches_index = False
                if matches_index:
                    return row
    target_name = _text(target.get("current_name") or target.get("name"))
    if target_name:
        for row in rows:
            if _text(row.get("name") or row.get("current_name")) == target_name:
                return row
    return None


def _pseudocode_text(payload: Mapping[str, Any]) -> str:
    value = payload.get("pseudocode") or {}
    if isinstance(value, Mapping):
        value = value.get("pseudocode") or value.get("lines") or []
    if isinstance(value, list):
        return "\n".join(
            str(row.get("text") or row) if isinstance(row, Mapping) else str(row)
            for row in value
        )
    return str(value or "")


def _native_return_mismatch(native: Mapping[str, Any]) -> bool | None:
    """Use tinfo_t and ctree facts; return None when native facts are absent."""

    function = native.get("function") or {}
    returns = native.get("returns")
    if (
        not isinstance(function, Mapping)
        or function.get("return_type_is_void") is None
        or not isinstance(returns, list)
    ):
        return None
    return bool(
        function.get("return_type_is_void")
        and any(
            isinstance(row, Mapping) and bool(row.get("has_value"))
            for row in returns
        )
    )


def _text_return_mismatch(prototype: str, pseudocode: str) -> bool:
    """Legacy presentation heuristic retained only as a nonblocking fallback."""

    declares_void = bool(re.match(r"^\s*void\b(?!\s*\*)", prototype))
    has_value_return = bool(
        re.search(r"\breturn\s+(?!;|$)[^;\n]+", pseudocode)
    )
    return declares_void and has_value_return


def _callee_addresses(function: Mapping[str, Any]) -> set[str]:
    values = set()
    for row in function.get("callees") or []:
        if not isinstance(row, Mapping):
            continue
        nested = row.get("callee") if isinstance(row.get("callee"), Mapping) else row
        address = _address(
            nested.get("address") or nested.get("start") or nested.get("ea")
        )
        if address:
            values.add(address)
    return values


def post_edit_candidates(
    component_id: str,
    payload: Mapping[str, Any],
    *,
    operation: Mapping[str, Any],
    revision: int,
) -> dict[str, Any]:
    """Return operation-specific closure checks and one-hop suggestions."""

    function = dict(_function_view(payload))
    calls = payload.get("callers_callees") or {}
    if isinstance(calls, Mapping):
        function.setdefault(
            "callers",
            [
                row.get("caller") or row
                for row in calls.get("callers") or []
                if isinstance(row, Mapping)
            ],
        )
        function.setdefault(
            "callees",
            [
                row.get("callee") or row
                for row in calls.get("callees") or []
                if isinstance(row, Mapping)
            ],
        )
    ctree = payload.get("ida_native_summary") or {}
    if isinstance(ctree, Mapping):
        function.setdefault("locals", ctree.get("local_variables") or [])
    target = dict(operation.get("target") or {})
    operation_kind = str(operation.get("kind") or "")
    operation_id = str(operation.get("operation_id") or "")
    target_kind = str(target.get("kind") or "")
    if _probably_low_value(function) and target_kind not in {"named_type", "relationship"}:
        return {"candidates": [], "evaluated_gap_kinds": [], "closure_target": None}
    address = _address(
        function.get("address")
        or function.get("start")
        or function.get("ea")
        or payload.get("address")
    )
    if not address and target_kind not in {"named_type", "relationship"}:
        return {"candidates": [], "evaluated_gap_kinds": [], "closure_target": None}
    name = _text(function.get("name") or function.get("current_name"))
    comments = function.get("comments") or {}
    nonrepeatable_comment = (
        _behavior_comment(comments.get("nonrepeatable"))
        if isinstance(comments, Mapping)
        else ""
    )
    repeatable_comment = (
        _behavior_comment(comments.get("repeatable"))
        if isinstance(comments, Mapping)
        else ""
    )
    # IDA's summary field may prefer a repeatable slot that contains only
    # Verified IDA relationship markers. Filter each source before choosing a
    # fallback so that a valid nonrepeatable behavior comment is not hidden by
    # non-behavior transport metadata in the other slot.
    comment = (
        _behavior_comment(function.get("comment"))
        or _behavior_comment(function.get("function_comment"))
        or nonrepeatable_comment
        or repeatable_comment
    )
    prototype = _text(
        function.get("prototype")
        or function.get("declaration")
        or function.get("type")
    )
    candidates: list[dict[str, Any]] = []
    evaluated: list[str] = []
    closure_kind = "function"
    closure_key = address

    def closure(gap_kind: str, reason: str, *, priority: str = "high") -> None:
        evaluated.append(gap_kind)
        candidates.append(_candidate(
            component_id=component_id,
            target_kind=closure_kind,
            target_key=closure_key,
            gap_kind=gap_kind,
            reasons=[reason],
            lane="must_review",
            priority=priority,
            tier=1,
            origin="direct_closure",
            trigger_revision=revision,
            operation_id=operation_id,
        ))

    def evaluated_without_gap(gap_kind: str) -> None:
        evaluated.append(gap_kind)

    def suggestion(
        gap_kind: str,
        reason: str,
        *,
        origin: str,
        priority: str = "low",
    ) -> None:
        candidates.append(_candidate(
            component_id=component_id,
            target_kind=closure_kind,
            target_key=closure_key,
            gap_kind=gap_kind,
            reasons=[reason],
            lane="suggested_next",
            priority=priority,
            tier=2,
            origin=origin,
            trigger_revision=revision,
            operation_id=operation_id,
        ))

    if operation_kind == "function.rename":
        if not comment:
            closure(
                "missing_behavior_comment",
                "renamed function has no durable local-behavior explanation",
            )
        else:
            evaluated_without_gap("missing_behavior_comment")
        function_name_state = _user_name_state(function)
        if function_name_state is False:
            closure(
                "generic_function_name",
                "IDA reports that the function name is not user-supplied",
            )
        elif function_name_state is None and _generic_function_name(name):
            suggestion(
                "generic_function_name_heuristic",
                "function name looks generated, but IDA name provenance is unavailable",
                origin="fallback_name_heuristic",
            )
            evaluated_without_gap("generic_function_name")
        else:
            evaluated_without_gap("generic_function_name")
    elif operation_kind == "function.comment.set":
        if not comment:
            closure(
                "missing_behavior_comment",
                "function comment mutation left no durable behavior explanation",
            )
        else:
            evaluated_without_gap("missing_behavior_comment")
        function_name_state = _user_name_state(function)
        if function_name_state is False:
            closure(
                "generic_function_name",
                "explained function still has a non-user IDA name",
            )
        elif function_name_state is None and _generic_function_name(name):
            suggestion(
                "generic_function_name_heuristic",
                "explained function has a generated-looking name, but IDA name provenance is unavailable",
                origin="fallback_name_heuristic",
            )
            evaluated_without_gap("generic_function_name")
        else:
            evaluated_without_gap("generic_function_name")
        comments = dict(function.get("comments") or {})
        nonrepeatable = _behavior_comment(comments.get("nonrepeatable"))
        repeatable = _behavior_comment(comments.get("repeatable"))
        if nonrepeatable and repeatable:
            if nonrepeatable == repeatable:
                closure(
                    "duplicate_function_comment_slots",
                    (
                        "repeatable and nonrepeatable function-comment slots "
                        "contain identical behavior text; clear the redundant slot"
                    ),
                )
                evaluated_without_gap("conflicting_function_comment_slots")
            else:
                closure(
                    "conflicting_function_comment_slots",
                    (
                        "repeatable and nonrepeatable function-comment slots "
                        "contain different text; reconcile or clear the stale slot"
                    ),
                )
                evaluated_without_gap("duplicate_function_comment_slots")
        else:
            evaluated_without_gap("duplicate_function_comment_slots")
            evaluated_without_gap("conflicting_function_comment_slots")

    parameters = _parameters(function)
    default_name_rows = [
        row for row in parameters
        if GENERIC_LOCAL_RE.match(
            _text(row.get("name") or row.get("current_name"))
        )
    ]
    native_default_names = [
        _text(row.get("name") or row.get("current_name"))
        for row in default_name_rows
        if _user_name_state(row) is False
    ]
    heuristic_default_names = [
        _text(row.get("name") or row.get("current_name"))
        for row in default_name_rows
        if _user_name_state(row) is None
    ]

    def heuristic_name_suggestion(gap_kind: str, reason: str) -> None:
        suggestion(
            gap_kind,
            reason,
            origin="fallback_name_heuristic",
        )

    edited_parameter = _edited_parameter(parameters, target)
    if operation_kind == "function.prototype.set":
        pseudocode = _pseudocode_text(payload)
        native_mismatch = _native_return_mismatch(
            ctree if isinstance(ctree, Mapping) else {}
        )
        if native_mismatch is True:
            closure(
                "prototype_return_mismatch",
                "native tinfo_t and ctree facts show a void return type with a value-returning statement",
            )
        else:
            evaluated_without_gap("prototype_return_mismatch")
            if native_mismatch is None and _text_return_mismatch(
                prototype, pseudocode
            ):
                suggestion(
                    "prototype_return_mismatch_heuristic",
                    "printed prototype and pseudocode appear inconsistent, but native return facts were unavailable",
                    origin="fallback_rendered_text_heuristic",
                    priority="medium",
                )
        if native_default_names:
            closure(
                "prototype_default_parameter_names",
                "prototype still exposes backend-confirmed non-user parameter names: %s"
                % ", ".join(native_default_names[:8]),
                priority="medium",
            )
        else:
            evaluated_without_gap("prototype_default_parameter_names")
        if heuristic_default_names:
            heuristic_name_suggestion(
                "prototype_generic_parameter_name_heuristic",
                (
                    "prototype exposes generic-looking parameter names without "
                    "backend name provenance: %s"
                ) % ", ".join(heuristic_default_names[:8]),
            )
    elif operation_kind == "local.rename" and target.get("is_parameter"):
        parameter_type = _text(
            (edited_parameter or {}).get("type")
            or (edited_parameter or {}).get("declaration")
            or target.get("current_type")
        ).lower()
        if parameter_type in GENERIC_TYPE_NAMES:
            suggestion(
                "claimed_parameter_role_generic_type",
                "renamed parameter role still has a generic-looking printed type %s"
                % (parameter_type or "<empty>"),
                origin="fallback_type_spelling_heuristic",
                priority="medium",
            )
            evaluated_without_gap("claimed_parameter_role_generic_type")
        else:
            evaluated_without_gap("claimed_parameter_role_generic_type")
    elif operation_kind == "local.type.set" and target.get("is_parameter"):
        parameter_name = _text(
            (edited_parameter or {}).get("name")
            or (edited_parameter or {}).get("current_name")
        )
        user_name_state = _user_name_state(edited_parameter or target)
        if GENERIC_LOCAL_RE.match(parameter_name) and user_name_state is False:
            closure(
                "typed_parameter_generic_name",
                "typed parameter still has backend-confirmed non-user name %s"
                % parameter_name,
                priority="medium",
            )
        else:
            evaluated_without_gap("typed_parameter_generic_name")
        if GENERIC_LOCAL_RE.match(parameter_name) and user_name_state is None:
            heuristic_name_suggestion(
                "typed_parameter_generic_name_heuristic",
                (
                    "typed parameter has generic-looking name %s but the backend "
                    "did not provide name provenance"
                ) % parameter_name,
            )
    elif operation_kind == "named_type.create_or_update":
        declaration = _text(payload.get("declaration") or payload.get("type"))
        closure_kind = "named_type"
        closure_key = str(target.get("name") or "")
        unresolved = re.findall(
            r"\b(?:unresolved|field|gap)_(?:0x)?[0-9a-f]+\b",
            declaration,
            flags=re.I,
        )
        if unresolved:
            suggestion(
                "unresolved_named_type_fields",
                "introduced type contains field names that look analytically unresolved: %s"
                % ", ".join(sorted(set(unresolved))[:8]),
                origin="fallback_member_name_heuristic",
                priority="medium",
            )
            evaluated_without_gap("unresolved_named_type_fields")
        else:
            evaluated_without_gap("unresolved_named_type_fields")
    elif operation_kind == "relationship.annotate":
        closure_kind = "relationship"
        closure_key = VerifiedIdaJournal.target_key(target)
        if target.get("relationship_kind") == "direct_call":
            destination = _address(target.get("destination_address"))
            if destination not in _callee_addresses(function):
                closure(
                    "direct_relationship_edge_not_observed",
                    "annotated direct-call destination was not observed in bounded caller/callee evidence",
                )
            else:
                evaluated_without_gap("direct_relationship_edge_not_observed")

    for direction in ("callers", "callees"):
        for neighbor in function.get(direction) or []:
            if not isinstance(neighbor, Mapping):
                continue
            if _probably_low_value(neighbor):
                continue
            neighbor_address = _address(
                neighbor.get("address") or neighbor.get("start") or neighbor.get("ea")
            )
            neighbor_name = _text(neighbor.get("name"))
            if not neighbor_address or not _generic_function_name(neighbor_name):
                continue
            candidates.append(_candidate(
                component_id=component_id,
                target_kind="function",
                target_key=neighbor_address,
                gap_kind="unresolved_%s_neighbor" % direction[:-1],
                reasons=[
                    "unnamed direct %s of committed function %s"
                    % (direction[:-1], address)
                ],
                lane="suggested_next",
                priority="medium",
                tier=2,
                origin="local_neighborhood",
                trigger_revision=revision,
                operation_id=operation_id,
            ))
    return {
        "candidates": candidates,
        "evaluated_gap_kinds": list(dict.fromkeys(evaluated)),
        "closure_target": {
            "target_kind": closure_kind,
            "target_key": closure_key,
        } if closure_key else None,
    }


def global_candidates(
    component_id: str,
    catalog: Mapping[str, Any],
    *,
    roots: Iterable[str] = (),
    revision: int = 0,
) -> list[dict[str, Any]]:
    """Return a bounded-rankable set of task roots and structural signals."""

    root_set = {_address(value) for value in roots if _address(value)}
    functions = catalog.get("functions") or catalog.get("items") or []
    results: list[dict[str, Any]] = []
    for raw in functions:
        if not isinstance(raw, Mapping):
            continue
        function = _function_view(raw)
        address = _address(
            function.get("address") or function.get("start") or function.get("ea")
        )
        if not address:
            continue
        # An explicit task root is authoritative scope input. Low-value
        # heuristics may suppress scanner suggestions, never a requested root.
        if address not in root_set and _probably_low_value(function):
            continue
        signal = function.get("analysis_signal") or {}
        labels = list(signal.get("static_labels") or []) if isinstance(signal, Mapping) else []
        reasons: list[str] = []
        priority = "medium"
        tier = 3
        if address in root_set:
            reasons.append("task-selected analysis root")
            priority = "critical"
            tier = 1
        for key, label in (
            ("is_entrypoint", "program entry point"),
            ("is_export", "exported function"),
            ("is_callback", "registered callback candidate"),
        ):
            if function.get(key) or key.replace("is_", "") in labels:
                reasons.append(label)
        important_labels = {
            "dispatcher_candidate",
            "orphan_orchestrator_candidate",
            "embedded_data_reference_candidate",
            "callback_candidate",
            "api_capability_candidate",
            "buffer_transform_candidate",
        }
        matched = sorted(important_labels & set(labels))
        if matched:
            reasons.extend("static signal: %s" % value for value in matched)
        behavior = signal.get("behavior_categories") if isinstance(signal, Mapping) else None
        if behavior:
            reasons.append("behavioral anchors: %s" % ", ".join(map(str, behavior)))
        callers = int(function.get("caller_count") or len(function.get("callers") or []))
        callees = int(function.get("callee_count") or len(function.get("callees") or []))
        if callers >= 4 and callees >= 4:
            reasons.append("call-graph bridge (%d callers, %d callees)" % (callers, callees))
        if not reasons:
            continue
        if _generic_function_name(_text(function.get("name"))):
            reasons.append("function remains generically named")
        results.append(_candidate(
            component_id=component_id,
            target_kind="function",
            target_key=address,
            gap_kind="project_discovery_candidate",
            reasons=reasons,
            lane="suggested_next",
            priority=priority,
            tier=tier,
            origin="task_root" if address in root_set else "global_signal",
            trigger_revision=revision,
        ))
    return results


class AnalysisFrontier:
    """Persist scanner output and return bounded model-facing frontier pages."""

    def __init__(self, journal: VerifiedIdaJournal):
        self.journal = journal

    def add(self, candidates: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        # IDA may report the same edge more than once (for example, multiple
        # call sites from one caller).  Preserve the candidate once and merge
        # its human-readable reasons before it reaches the model.
        unique: dict[str, dict[str, Any]] = {}
        for raw in candidates:
            candidate = dict(raw)
            candidate_id = str(candidate.get("candidate_id") or "")
            if candidate_id in unique:
                prior = unique[candidate_id]
                prior["reasons"] = list(dict.fromkeys([
                    *list(prior.get("reasons") or []),
                    *list(candidate.get("reasons") or []),
                ]))
                continue
            unique[candidate_id] = candidate
        return [
            self.journal.upsert_candidate(candidate)
            for candidate in unique.values()
        ]

    def observe_edit(
        self,
        *,
        component_id: str,
        inspection: Mapping[str, Any],
        operation: Mapping[str, Any],
        revision: int,
        evidence_id: str,
    ) -> dict[str, Any]:
        observed = post_edit_candidates(
            component_id,
            inspection,
            operation=operation,
            revision=revision,
        )
        candidates = self.add(observed["candidates"])
        must_review = [
            row for row in candidates
            if row["lane"] == "must_review"
            and row["state"] in {"open", "investigating"}
        ]
        suggested = [
            row for row in candidates
            if row["lane"] == "suggested_next"
            and row["state"] in {"open", "investigating"}
        ]
        closure_target = observed.get("closure_target")
        resolved = []
        if closure_target:
            resolved = self.journal.resolve_evaluated_candidates(
                component_id=component_id,
                target_kind=closure_target["target_kind"],
                target_key=closure_target["target_key"],
                gap_kinds=observed["evaluated_gap_kinds"],
                active_candidate_ids=(row["candidate_id"] for row in candidates),
                evidence_id=evidence_id,
                operation_id=str(operation["operation_id"]),
            )
        target = dict(operation.get("target") or {})
        edited_target_kind = str(target.get("kind") or "")
        edited_target_key = VerifiedIdaJournal.target_key(target)
        if edited_target_kind in {"local_variable", "relationship"}:
            edited_target_kind = "function"
            edited_target_key = _address(
                target.get("function_address") or target.get("source_address")
            )
        resolved_suggestions = self.journal.resolve_target_suggestions(
            component_id=component_id,
            target_kind=edited_target_kind,
            target_key=edited_target_key,
            evidence_id=evidence_id,
            operation_id=str(operation["operation_id"]),
        )
        resolved_suggestions.extend(self.journal.resolve_target_suggestions(
            component_id=component_id,
            target_kind="database",
            target_key=component_id,
            evidence_id=evidence_id,
            operation_id=str(operation["operation_id"]),
        ))
        return {
            "must_review": must_review,
            "suggested_next": suggested,
            "resolved_checks": resolved,
            "resolved_suggestions": resolved_suggestions,
        }

    def seed_project(
        self,
        *,
        component_id: str,
        catalog: Mapping[str, Any],
        roots: Iterable[str] = (),
    ) -> list[dict[str, Any]]:
        revision = int(self.journal.revision(component_id)["revision"])
        return self.add(global_candidates(
            component_id, catalog, roots=roots, revision=revision
        ))

    def suggest_component(self, component_id: str, parent_component_id: str) -> dict[str, Any]:
        revision = int(self.journal.revision(component_id)["revision"])
        return self.add([_candidate(
            component_id=component_id,
            target_kind="database",
            target_key=component_id,
            gap_kind="accepted_component_unreviewed",
            reasons=[
                "accepted child component has not yet received a semantic mutation",
                "parent component: %s" % parent_component_id,
            ],
            lane="suggested_next",
            priority="high",
            tier=2,
            origin="component_attention",
            trigger_revision=revision,
        )])[0]

    def page(
        self,
        *,
        lane: str = "must_review",
        component_id: str | None = None,
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self.journal.review_frontier(
            lane=lane,
            component_id=component_id,
            limit=min(limit, MAX_PAGE_SIZE),
            offset=offset,
        )
