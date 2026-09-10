"""Request-only context selection. Never mutates the durable session or IDBs."""

from __future__ import annotations

import hashlib
import sqlite3
from typing import Any, Mapping, Sequence

from verified_ida.session_context import (
    compaction_provenance, encoded_items, item_type, items_digest,
    latest_compaction_suffix, complete_function_pairs,
)




def select_request_history(
    items: Sequence[Mapping[str, Any]], provenance: Mapping[str, str], *,
    enabled: bool = True,
) -> tuple[list[Any], dict[str, Any]]:
    """Select an exact suffix; uncertain boundaries retain the complete input."""
    original = list(items)
    selected = latest_compaction_suffix(original, provenance) if enabled else original
    reason = "disabled" if not enabled else "no_verified_latest_server_boundary"
    if len(selected) < len(original):
        if complete_function_pairs(selected):
            reason = "verified_server_suffix"
        else:
            selected = original
            reason = "incomplete_or_unsupported_tool_boundary"
    removed = len(original) - len(selected)
    latest = next((item for item in reversed(original)
                   if item_type(item) == "compaction"), None)
    marker_digest = items_digest([latest]) if latest is not None else None
    metadata = {
        "schema": "verified_ida.model_request_context.v1",
        "policy": "server_compaction_suffix" if enabled else "full_history_control",
        "reason": reason,
        "history_items": len(original), "sent_items": len(selected),
        "omitted_items": removed,
        "history_bytes": len(encoded_items(original)),
        "sent_bytes": len(encoded_items(selected)),
        "history_sha256": items_digest(original),
        "sent_sha256": items_digest(selected),
        "omitted_prefix_sha256": items_digest(original[:removed]),
        "latest_compaction_sha256": marker_digest,
        "latest_compaction_origin": provenance.get(marker_digest, "unknown") if latest is not None else None,
        "durable_history_modified": False,
    }
    return selected, metadata


def model_run_config(session: Any, trace: Any, segment_id: str, *, compact_history: bool = True) -> Any:
    """Pinned SDK stateless-array runner configuration; not previous_response_id.

    The filter returns a view of input, not a replacement session. SQLite and
    archived transcripts remain authoritative audit records. The explicit flag
    supports matched tests without changing analysis prompts or SDK settings.
    """
    from agents import RunConfig
    from agents.run_config import ModelInputData

    def prepare(data: Any) -> Any:
        provenance_error = None
        try:
            provenance = compaction_provenance(session)
        except sqlite3.Error as exc:
            # Optimizing input must not guess a boundary on metadata failure.
            provenance = {}
            provenance_error = type(exc).__name__
        selected, metadata = select_request_history(
            data.model_data.input, provenance, enabled=compact_history,
        )
        if provenance_error:
            metadata["reason"] = "provenance_unavailable"
            metadata["provenance_error_type"] = provenance_error
        instructions = data.model_data.instructions
        trace.append(
            "model_input_prepared", actor="harness", segment_id=segment_id,
            session_id=session.session_id,
            instructions_sha256=hashlib.sha256((instructions or "").encode("utf-8")).hexdigest(),
            **metadata,
        )
        return ModelInputData(input=selected, instructions=instructions)

    return RunConfig(call_model_input_filter=prepare)
