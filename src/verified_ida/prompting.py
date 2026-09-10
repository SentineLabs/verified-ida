"""Deterministic model instructions and compact, provenance-labeled context."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_INSTRUCTIONS_PATH = (
    ROOT / "prompts" / "verified_ida_reverse_engineering_principles.md"
)
PROMPT_SNAPSHOT_SCHEMA = "verified_ida.prompt_snapshot.v1"


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_agent_instructions(
    path: str | Path = DEFAULT_INSTRUCTIONS_PATH,
) -> dict[str, Any]:
    source = Path(path).resolve()
    text = source.read_text(encoding="utf-8").strip() + "\n"
    return {
        "content": text,
        "path": str(source),
        "sha256": _sha256_text(text),
        "utf8_bytes": len(text.encode("utf-8")),
    }


def _json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, default=str)


def _bounded_rows(value: Any, *, limit: int = 8) -> list[Any]:
    if not isinstance(value, list):
        return []
    return [dict(row) if isinstance(row, Mapping) else row for row in value[:limit]]


def _compact_survey(survey: Mapping[str, Any]) -> dict[str, Any]:
    """Allowlist measured IDA facts so unrelated host data cannot leak."""

    result: dict[str, Any] = {}
    for key in ("artifact", "binary", "inventory", "analysis"):
        value = survey.get(key)
        if isinstance(value, Mapping):
            result[key] = dict(value)
    for key in ("segments", "imports", "entrypoints", "exports"):
        rows = _bounded_rows(survey.get(key), limit=12)
        if rows:
            result[key] = rows
    return result


def _compact_capabilities(capabilities: Mapping[str, Any]) -> dict[str, Any]:
    query_families = capabilities.get("query_families") or {}
    compact_families: dict[str, Any] = {}
    if isinstance(query_families, Mapping):
        for name, raw in sorted(query_families.items()):
            definition = dict(raw) if isinstance(raw, Mapping) else {}
            filters = definition.get("filters") or {}
            compact_families[str(name)] = {
                "maximum_page_size": definition.get("maximum_page_size"),
                "orders": list(definition.get("orders") or []),
                "filters": sorted(filters) if isinstance(filters, Mapping) else [],
            }
    function_evidence = capabilities.get("function_evidence") or {}
    extensions = capabilities.get("extensions") or {}
    recovery = capabilities.get("component_recovery") or {}
    analysis_feedback = capabilities.get("analysis_feedback") or {}
    recovery_methods = recovery.get("methods") or {}
    method_contracts = {}
    if isinstance(recovery_methods, Mapping):
        for method, raw in sorted(recovery_methods.items()):
            contract = dict(raw) if isinstance(raw, Mapping) else {}
            method_contracts[str(method)] = {
                key: contract[key]
                for key in (
                    "required_extraction_fields",
                    "optional_extraction_fields",
                    "executes_model_code",
                    "input_contract",
                )
                if key in contract
            }
    return {
        "backend": dict(capabilities.get("backend") or {}),
        "query_families": compact_families,
        "function_representations": list(
            dict(function_evidence).get("representations") or []
        ),
        "supported_mutations": list(capabilities.get("supported_mutations") or []),
        "extensions": dict(extensions) if isinstance(extensions, Mapping) else {},
        "component_recovery": {
            **{
                key: recovery[key]
                for key in (
                    "schema", "supported_methods", "limits", "copy_example",
                    "decision_boundary",
                )
                if isinstance(recovery, Mapping) and key in recovery
            },
            "method_contracts": method_contracts,
        },
        "analysis_feedback": {
            key: analysis_feedback[key]
            for key in (
                "schema", "profile", "provenance", "semantic_judgment",
                "description",
            )
            if isinstance(analysis_feedback, Mapping) and key in analysis_feedback
        },
    }


def _compact_frontier(frontier: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for lane in ("must_review", "suggested_next"):
        page = frontier.get(lane) or {}
        if not isinstance(page, Mapping):
            continue
        candidates = []
        for raw in _bounded_rows(page.get("candidates"), limit=8):
            if not isinstance(raw, Mapping):
                continue
            candidates.append({
                key: raw[key]
                for key in (
                    "candidate_id", "component_id", "target_kind", "target_key",
                    "gap_kind", "priority", "reasons",
                )
                if key in raw
            })
        result[lane] = {
            "blocking": bool(page.get("blocking")),
            "total_active": int(page.get("total_active") or 0),
            "candidates": candidates,
        }
    return result


def _compact_seed(seed: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: seed[key]
        for key in (
            "resumed", "component_id", "function_count", "entrypoint_count",
            "export_count", "candidate_count", "suggested_next_count",
            "task_root_count", "blocking_count", "policy",
        )
        if key in seed
    }


def render_starting_packet(
    *,
    objective: str,
    resumed: bool,
    seed: Mapping[str, Any],
    frontier: Mapping[str, Any],
    survey: Mapping[str, Any],
    capabilities: Mapping[str, Any],
    session_preparation: Mapping[str, Any] | None = None,
    resume_state: Mapping[str, Any] | None = None,
) -> str:
    """Render exact initial context without hidden-reference or scoring data."""

    mode = "resumed persistent investigation" if resumed else "new investigation"
    lines = [
        "# Verified IDA starting packet",
        "",
        "## Objective (user-supplied)",
        "",
        str(objective).strip(),
        "",
        "## Constraints (harness policy)",
        "",
        "- Mode: %s." % mode,
        "- The supplied IDBs and binaries are the only analysis authority.",
        "- IDB mutations require exact references and verified operation receipts.",
        "- Embedded executable children use separate, provenance-linked IDBs.",
        "- Navigation suggestions are heuristic and nonblocking; verify them against code.",
        "",
        "## Measured project facts (host-measured)",
        "",
        "```json",
        _json(_compact_survey(survey)),
        "```",
        "",
        "## Available capabilities (host-advertised)",
        "",
        "Exact request syntax is defined by the SDK tool schemas.",
        "",
        "```json",
        _json(_compact_capabilities(capabilities)),
        "```",
        "",
        "## Navigation suggestions (host-generated, advisory, nonblocking)",
        "",
        "```json",
        _json({"seed": _compact_seed(seed), "frontier": _compact_frontier(frontier)}),
        "```",
    ]
    if resumed and session_preparation is not None:
        allowed = {
            key: session_preparation[key]
            for key in ("action", "session", "capsule", "compaction_error")
            if key in session_preparation
        }
        lines.extend([
            "",
            "## Resume preparation (host-measured)",
            "",
            "```json",
            _json(allowed),
            "```",
        ])
    active_campaign = False
    if resumed and resume_state is not None:
        reconciliation = dict(
            resume_state.get("coverage_reconciliation") or {}
        )
        active_campaign = bool(reconciliation.get("open_count"))
        if active_campaign:
            lines.extend([
                "",
                "## Active frozen reconciliation campaign (host-measured)",
                "",
                (
                    "Resume this exact frozen wave before general project planning. "
                    "The finding set cannot expand and another discovery review will "
                    "not run. Reinspect live IDA state, use the recorded activity as "
                    "provenance rather than semantic truth, and disposition the current "
                    "finding with current evidence."
                ),
                "",
                "```json",
                _json(reconciliation),
                "```",
            ])
    lines.extend([
        "",
        "## Initial planning request (model-authored, revisable)",
        "",
        (
            "Resume the exact frozen finding shown above. Read `reversing_log.md`, "
            "reconcile the recorded activity with live IDA state, and continue that "
            "finding before opening unrelated work."
            if active_campaign
            else
            "Before continuing, read `reversing_log.md`, reconcile it with live IDA "
            "state, and populate or revise Objective and Scope, Component Map, Active "
            "Workstreams, and Next Actions. Choose an evidence-backed route and explain "
            "why. This plan is revisable and does not impose a fixed subsystem order."
            if resumed
            else
            "Before deep analysis, read `reversing_log.md` and populate Objective and "
            "Scope, Component Map, Active Workstreams, and Next Actions. Choose an "
            "evidence-backed route and explain why. This initial plan is revisable and "
            "does not impose a fixed subsystem order."
        ),
        "",
    ])
    return "\n".join(lines)


def write_prompt_snapshots(
    *,
    project_dir: str | Path,
    segment_id: str,
    instructions: Mapping[str, Any],
    starting_packet: str,
) -> dict[str, Any]:
    destination = Path(project_dir) / "prompt_snapshots"
    destination.mkdir(parents=True, exist_ok=True)
    instructions_path = destination / (segment_id + "-instructions.md")
    packet_path = destination / (segment_id + "-starting_packet.md")
    instructions_path.write_text(str(instructions["content"]), encoding="utf-8")
    packet_path.write_text(starting_packet, encoding="utf-8")
    return {
        "schema": PROMPT_SNAPSHOT_SCHEMA,
        "instructions": {
            "source_path": str(instructions["path"]),
            "snapshot_path": str(instructions_path.resolve()),
            "sha256": str(instructions["sha256"]),
            "utf8_bytes": int(instructions["utf8_bytes"]),
        },
        "starting_packet": {
            "snapshot_path": str(packet_path.resolve()),
            "sha256": _sha256_text(starting_packet),
            "utf8_bytes": len(starting_packet.encode("utf-8")),
        },
    }
