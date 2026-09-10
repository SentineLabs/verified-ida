"""Append-only observable trace and deterministic reviewer projections."""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .session_context import item_type


USAGE_KEYS = (
    "requests",
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
    "total_tokens",
)


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _jsonable(model_dump(exclude_unset=True))
    return value


def _json(value: Any) -> str:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


class ObservableTrace:
    """Crash-durable JSONL event stream with monotonic source indexes."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._next_index = 1
        if self.path.exists():
            for line_number, line in enumerate(
                self.path.read_text(encoding="utf-8", errors="replace").splitlines(),
                start=1,
            ):
                self._next_index = max(self._next_index, line_number + 1)
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._next_index = max(
                    self._next_index,
                    int(event.get("event_index") or line_number) + 1,
                )

    def append(self, event: str, **details: Any) -> dict[str, Any]:
        with self._lock:
            payload = {
                "schema": "verified_ida.observable_event.v1",
                "event_index": self._next_index,
                "timestamp": _timestamp(),
                "event": event,
                **details,
            }
            encoded = _json(payload) + "\n"
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            self._next_index += 1
            return payload

    def read(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        events: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        if not self.path.exists():
            return events, errors
        for line_number, line in enumerate(
            self.path.read_text(encoding="utf-8", errors="replace").splitlines(),
            start=1,
        ):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                errors.append({
                    "line": line_number,
                    "error": "%s: %s" % (type(exc).__name__, exc),
                })
                continue
            event["source_line"] = line_number
            events.append(event)
        return events, errors


def _serialized_item(item: Any) -> dict[str, Any]:
    value = _jsonable(item)
    return dict(value) if isinstance(value, Mapping) else {"value": value}


def _message_text(item: Mapping[str, Any]) -> str:
    parts: list[str] = []
    content = item.get("content")
    if isinstance(content, str):
        return content
    for block in content if isinstance(content, list) else []:
        if not isinstance(block, Mapping):
            continue
        text = block.get("text") or block.get("value")
        if isinstance(text, str):
            parts.append(text)
    return "\n".join(parts)


def observable_response_items(items: Iterable[Any]) -> dict[str, Any]:
    raw_items = list(items)
    encoded_output = _json(raw_items).encode("utf-8")
    types: list[str] = []
    messages: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    compactions: list[dict[str, Any]] = []
    for raw in raw_items:
        kind = item_type(raw)
        types.append(kind)
        item = _serialized_item(raw)
        if kind == "message":
            text = _message_text(item)
            if text:
                messages.append({
                    "role": item.get("role") or "assistant",
                    "text": text,
                })
        elif kind in {"function_call", "tool_call"}:
            arguments = item.get("arguments")
            encoded_arguments = _json(arguments) if arguments is not None else ""
            tool_calls.append({
                "name": item.get("name"),
                "call_id": item.get("call_id") or item.get("id"),
                "arguments_bytes": len(encoded_arguments.encode("utf-8")),
                "arguments_sha256": (
                    hashlib.sha256(encoded_arguments.encode("utf-8")).hexdigest()
                    if encoded_arguments
                    else None
                ),
            })
        elif kind == "compaction":
            encoded = _json(item).encode("utf-8")
            compactions.append({
                "bytes": len(encoded),
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "id": item.get("id"),
            })
    return {
        "output_bytes": len(encoded_output),
        "output_sha256": hashlib.sha256(encoded_output).hexdigest(),
        "output_types": types,
        "visible_messages": messages,
        "tool_calls": tool_calls,
        "compactions": compactions,
    }


def observable_tool_arguments(
    tool: str,
    arguments: Mapping[str, Any],
) -> dict[str, Any]:
    """Keep notebook prose out of trace events while retaining its provenance."""

    value = dict(arguments)
    if tool not in {
        "update_reversing_log_section",
        "append_reversing_log_journal",
    }:
        return value
    content = str(value.pop("content", ""))
    value.update({
        "content_utf8_bytes": len(content.encode("utf-8")),
        "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
    })
    return value


def aggregate_usage(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    totals = {key: 0 for key in USAGE_KEYS}
    seen_response_ids: set[str] = set()
    response_count = 0
    legacy_count = 0
    observable_output_bytes = 0
    output_fingerprint_count = 0
    for event in events:
        if event.get("event") == "model_response":
            response_id = str(event.get("response_id") or "")
            if response_id and response_id in seen_response_ids:
                continue
            if response_id:
                seen_response_ids.add(response_id)
            usage = event.get("usage") or {}
            response_count += 1
            if event.get("output_bytes") is not None:
                output_fingerprint_count += 1
                observable_output_bytes += int(event.get("output_bytes") or 0)
        elif event.get("event") == "llm_usage":
            # Compatibility with traces written before Release 3.  New traces
            # use model_response and are never counted through this branch.
            usage = event.get("usage") or {}
            legacy_count += 1
        else:
            continue
        for key in USAGE_KEYS:
            totals[key] += int(usage.get(key) or 0)
    return {
        **totals,
        "unique_response_count": response_count,
        "legacy_usage_event_count": legacy_count,
        "observable_response_output_bytes": observable_output_bytes,
        "observable_response_output_bytes_complete": (
            output_fingerprint_count == response_count
        ),
    }


def segment_usage(events: Iterable[Mapping[str, Any]]) -> dict[str, dict[str, Any]]:
    grouped: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str]] = set()
    for event in events:
        if event.get("event") != "model_response":
            continue
        segment_id = str(event.get("segment_id") or "legacy_or_unknown")
        response_id = str(event.get("response_id") or "")
        key = (segment_id, response_id)
        if response_id and key in seen:
            continue
        if response_id:
            seen.add(key)
        bucket = grouped.setdefault(
            segment_id,
            {
                **{usage_key: 0 for usage_key in USAGE_KEYS},
                "response_count": 0,
                "observable_response_output_bytes": 0,
                "output_fingerprint_count": 0,
            },
        )
        usage = event.get("usage") or {}
        for usage_key in USAGE_KEYS:
            bucket[usage_key] += int(usage.get(usage_key) or 0)
        bucket["response_count"] += 1
        if event.get("output_bytes") is not None:
            bucket["observable_response_output_bytes"] += int(
                event.get("output_bytes") or 0
            )
            bucket["output_fingerprint_count"] += 1
    for bucket in grouped.values():
        bucket["observable_response_output_bytes_complete"] = (
            bucket.pop("output_fingerprint_count") == bucket["response_count"]
        )
    return dict(sorted(grouped.items()))


def compaction_summary(events: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [event for event in events if event.get("event") == "context_compaction"]
    return {
        "count": sum(int(row.get("item_count") or 0) for row in rows),
        "response_count": len(rows),
        "response_ids": [row.get("response_id") for row in rows],
        "thresholds": sorted({
            int(row.get("compact_threshold_tokens") or 0)
            for row in rows
            if row.get("compact_threshold_tokens") is not None
        }),
        "events": [
            {
                "event_index": row.get("event_index"),
                "segment_id": row.get("segment_id"),
                "response_id": row.get("response_id"),
                "item_count": int(row.get("item_count") or 0),
                "usage": dict(row.get("usage") or {}),
                "active_component": row.get("active_component"),
                "database_revision": row.get("database_revision"),
            }
            for row in rows
        ],
    }


def _bounded_json(value: Any, limit: int = 6000) -> str:
    encoded = json.dumps(
        _jsonable(value),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    if len(encoded) <= limit:
        return encoded
    return encoded[:limit] + "\n... [bounded walkthrough projection]"


def _tool_result_details(event: Mapping[str, Any]) -> list[str]:
    tool = str(event.get("tool") or "")
    arguments = event.get("arguments") or {}
    result = event.get("result") or {}
    if not isinstance(arguments, Mapping) or not isinstance(result, Mapping):
        return []
    lines: list[str] = []
    if tool == "update_reversing_log_section":
        lines.extend([
            "",
            "Notebook section `%s` changed from `%s` to `%s` (%s UTF-8 bytes)."
            % (
                result.get("section"),
                result.get("before_digest"),
                result.get("after_digest"),
                result.get("content_utf8_bytes"),
            ),
            "",
            "Notebook update: `%s`; IDB effect: `none`."
            % result.get("update_id"),
        ])
        return lines
    if tool == "append_reversing_log_journal":
        lines.extend([
            "",
            "Appended journal entry `%s`; journal changed from `%s` to `%s` "
            "(%s UTF-8 bytes)."
            % (
                result.get("entry_id"),
                result.get("before_digest"),
                result.get("after_digest"),
                result.get("content_utf8_bytes"),
            ),
            "",
            "Notebook update: `%s`; IDB effect: `none`."
            % result.get("update_id"),
        ])
        return lines
    if tool == "edit_ida":
        lines.extend([
            "",
            "Requested mutation: `%s`." % arguments.get("kind"),
        ])
        if arguments.get("reason"):
            lines.extend(["", "Visible rationale: %s" % arguments.get("reason")])
        if "value" in arguments:
            lines.extend([
                "",
                "Requested value:",
                "",
                "```json",
                _bounded_json(arguments.get("value")),
                "```",
            ])
        lines.extend([
            "",
            "Operation: `%s`; persistence: `%s`; resulting revision: `%s`."
            % (
                result.get("operation_id"),
                result.get("persistence"),
                result.get("database_revision"),
            ),
        ])
        semantic = result.get("semantic_assessment") or {}
        if isinstance(semantic, Mapping) and semantic.get("status"):
            lines.extend([
                "",
                "Host semantic assessment: `%s` (%s)"
                % (semantic.get("status"), semantic.get("message")),
            ])
        reminder = result.get("project_state_reminder") or {}
        if isinstance(reminder, Mapping) and reminder.get("outstanding"):
            lines.extend([
                "",
                "Project-state reminder: advisory and nonblocking; reasons `%s`."
                % ", ".join(map(str, reminder.get("reasons") or [])),
            ])
        if result.get("current") is not None:
            lines.extend([
                "",
                "Verified current state:",
                "",
                "```json",
                _bounded_json(result.get("current")),
                "```",
            ])
        lines.extend([
            "",
            "Direct closure checks returned: `%s`; advisory suggestions returned: `%s`."
            % (
                len(result.get("must_review") or []),
                len(result.get("suggested_next") or []),
            ),
        ])
        return lines

    inner = result.get("result")
    if tool == "inspect_ida_function" and isinstance(inner, Mapping):
        function = inner.get("function") or {}
        relationships = inner.get("relationships") or {}
        references = inner.get("references") or {}
        lines.extend([
            "",
            "Returned function `%s` at `%s`, prototype `%s`, size `%s` bytes."
            % (
                function.get("name"),
                function.get("start") or inner.get("address"),
                function.get("prototype"),
                function.get("size"),
            ),
            "",
            "Evidence: `%s`; callers: `%s`; callees: `%s`; imports: `%s`; strings: `%s`."
            % (
                result.get("evidence_id"),
                relationships.get("caller_count"),
                relationships.get("callee_count"),
                references.get("import_count"),
                references.get("string_count"),
            ),
        ])
        return lines

    if tool == "read_ida_function_code":
        query = result.get("query") or {}
        filters = query.get("filters") or {}
        page = result.get("page") or {}
        lines.extend([
            "",
            "Returned `%s` for `%s`: `%s` of `%s` lines; complete: `%s`; evidence: `%s`."
            % (
                filters.get("representation"),
                filters.get("function"),
                page.get("returned"),
                page.get("total"),
                not bool(page.get("has_more")),
                result.get("evidence_id"),
            ),
        ])
        return lines

    if tool.startswith("query_ida_"):
        page = result.get("page") or {}
        items = result.get("items") or []
        sample = []
        for item in items[:3] if isinstance(items, list) else []:
            if not isinstance(item, Mapping):
                continue
            sample.append({
                key: item.get(key)
                for key in ("address", "name", "kind", "size", "prototype")
                if item.get(key) is not None
            })
        lines.extend([
            "",
            "Returned `%s` of `%s` matching records; more pages: `%s`; evidence: `%s`."
            % (
                page.get("returned"),
                page.get("total"),
                bool(page.get("has_more")),
                result.get("evidence_id"),
            ),
        ])
        if sample:
            lines.extend([
                "",
                "Sample returned identities:",
                "",
                "```json",
                _bounded_json(sample, limit=2000),
                "```",
            ])
        return lines

    if tool == "inspect_ida" and isinstance(inner, Mapping):
        lines.extend([
            "",
            "Bounded result: `%s`; evidence: `%s`."
            % (
                inner.get("error") or ("%s match(es)" % inner.get("count")),
                result.get("evidence_id"),
            ),
        ])
        return lines

    if tool == "complete_ida_investigation":
        lines.extend([
            "",
            "Completion result: may finish `%s`; must-review `%s`; mechanical failures `%s`; checkpoints `%s`."
            % (
                result.get("may_finish"),
                len(result.get("must_review") or []),
                len(result.get("mechanical_failures") or []),
                len(result.get("checkpoints") or []),
            ),
        ])
    if tool == "review_analysis_closure":
        packet = result.get("packet") or {}
        candidates = packet.get("review_candidates") or {}
        lines.extend([
            "",
            "Advisory analysis-closure review epoch `%s` returned `%s` bounded question(s); completion blocking: `%s`."
            % (
                result.get("review_epoch"),
                candidates.get("total"),
                result.get("blocking"),
            ),
            "",
            "Review packet: `%s`; digest: `%s`; IDB effect: `read-only`."
            % (result.get("packet_path"), result.get("packet_digest")),
        ])
    return lines


def render_walkthrough(
    events: Iterable[Mapping[str, Any]],
    *,
    trace_path: str | Path,
) -> str:
    rows = list(events)
    trace_name = Path(trace_path).name
    lines = [
        "# Observable investigation walkthrough",
        "",
        "This document is generated from observable model, host, and harness events. ",
        "It does not claim access to hidden reasoning.",
        "",
    ]
    for row_index, event in enumerate(rows):
        kind = str(event.get("event") or "")
        source = "%s:%s" % (trace_name, event.get("source_line") or "?")
        index = event.get("event_index") or "?"
        if kind in {"investigation_started", "investigation_resumed"}:
            lines.extend([
                "## Event %s — %s" % (index, kind.replace("_", " ").title()),
                "",
                "The harness started a run segment for model `%s` on component `%s`."
                % (event.get("model"), event.get("active_component") or "root"),
                "",
                "Actor: `%s`." % (event.get("actor") or "harness"),
                "",
                "Source: `%s`" % source,
                "",
            ])
        elif kind == "tool_result":
            arguments = event.get("arguments") or {}
            target = (
                arguments.get("address")
                or arguments.get("target")
                or arguments.get("function_ref")
                or arguments.get("target_ref")
                or arguments.get("operation_id")
                or arguments.get("section")
                or arguments.get("title")
            ) if isinstance(arguments, Mapping) else None
            result = event.get("result") or {}
            status = result.get("status") if isinstance(result, Mapping) else None
            changed = bool(
                event.get("tool") == "edit_ida"
                and status in {"verified", "applied"}
            )
            block = [
                "## Event %s — Tool result" % index,
                "",
                "The model requested `%s`%s. The host returned `%s`%s. IDB effect: `%s`."
                % (
                    event.get("tool"),
                    " for `%s`" % target if target else "",
                    "success" if event.get("ok") else "failure",
                    " with status `%s`" % status if status else "",
                    "changed" if changed else "read-only or no verified change",
                ),
            ]
            block.extend(_tool_result_details(event))
            block.extend([
                "",
                "Actor: `%s`. Component: `%s`; revision: `%s`."
                % (
                    event.get("actor") or "model_and_host",
                    event.get("active_component"),
                    event.get("database_revision"),
                ),
                "",
                "Source: `%s`" % source,
                "",
            ])
            lines.extend(block)
        elif kind == "model_response":
            for message in event.get("visible_messages") or []:
                lines.extend([
                    "## Event %s — Visible model statement" % index,
                    "",
                    str(message.get("text") or ""),
                    "",
                    "Actor: `%s`." % (event.get("actor") or "model"),
                    "",
                    "Source: `%s`" % source,
                    "",
                ])
        elif kind == "context_compaction":
            continuation = next(
                (
                    later
                    for later in rows[row_index + 1:]
                    if later.get("event") in {"tool_result", "model_response"}
                ),
                None,
            )
            continuation_text = "No later observable model or tool event is recorded."
            if continuation is not None:
                continuation_kind = str(continuation.get("event"))
                if continuation_kind == "tool_result":
                    continuation_kind += " `%s`" % continuation.get("tool")
                continuation_text = (
                    "Observable continuation: event %s records %s."
                    % (continuation.get("event_index"), continuation_kind)
                )
            lines.extend([
                "## Event %s — Context compaction" % index,
                "",
                "The server emitted %s opaque compaction item(s) after response `%s`. "
                "The request used %s input tokens. The active component was `%s` at "
                "revision `%s`. No hidden reasoning is inferred from the payload."
                % (
                    event.get("item_count"),
                    event.get("response_id"),
                    (event.get("usage") or {}).get("input_tokens"),
                    event.get("active_component"),
                    event.get("database_revision"),
                ),
                "",
                continuation_text,
                "",
                "Actor: `%s`." % (event.get("actor") or "responses_server"),
                "",
                "Source: `%s`" % source,
                "",
            ])
        elif kind in {
            "session_archived_and_pruned",
            "session_prune_failed",
            "session_recovery_handoff",
            "session_recovery_compacted",
        }:
            lines.extend([
                "## Event %s — %s" % (index, kind.replace("_", " ").title()),
                "",
                "The harness recorded session maintenance action `%s`. IDB effect: `none`."
                % kind,
                "",
                "Actor: `%s`." % (event.get("actor") or "harness"),
                "",
                "Source: `%s`" % source,
                "",
            ])
        elif kind in {"run_completed", "run_stopped"}:
            lines.extend([
                "## Event %s — %s" % (index, kind.replace("_", " ").title()),
                "",
                "The harness recorded final status `%s`." % event.get("status"),
                "",
                "Actor: `%s`." % (event.get("actor") or "harness"),
                "",
                "Source: `%s`" % source,
                "",
            ])
        elif kind == "experimental_intervention":
            lines.extend([
                "## Event %s — Experimental intervention" % index,
                "",
                str(event.get("note") or ""),
                "",
                "Actor: `%s`." % (event.get("actor") or "user"),
                "",
                "Source: `%s`" % source,
                "",
            ])
    return "\n".join(lines).rstrip() + "\n"


def write_walkthrough(trace: ObservableTrace, destination: str | Path) -> dict[str, Any]:
    events, errors = trace.read()
    text = render_walkthrough(events, trace_path=trace.path)
    destination_path = Path(destination)
    destination_path.write_text(text, encoding="utf-8")
    return {
        "path": str(destination_path.resolve()),
        "event_count": len(events),
        "parse_errors": errors,
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def event_counts(events: Iterable[Mapping[str, Any]]) -> dict[str, int]:
    counts = Counter(str(event.get("event") or "unknown") for event in events)
    return dict(sorted(counts.items()))
