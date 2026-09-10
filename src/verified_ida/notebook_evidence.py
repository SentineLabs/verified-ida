"""Citable investigator statements, deliberately separate from IDA evidence."""
from __future__ import annotations

from typing import Any, Mapping
import hashlib
from .contracts import canonical_json


def register_notebook_read(runtime, result: dict[str, Any]) -> dict[str, Any]:
    rows = [("current_state", key, row, "digest") for key, row in result["current_state"].items()]
    rows.extend(("journal", str(row["entry_id"]), row, "content_digest")
                for row in result["journal"]["entries"])
    for kind, locator, row, digest_key in rows:
        snapshot = {
            "kind": kind, "locator": locator, "document_digest": result["document_digest"],
            "content_digest": row[digest_key], "content": row["content"],
            "root_binary_sha256": runtime.journal.component("root")["binary_sha256"],
            "authority": "investigator_statement_not_binary_evidence",
        }
        digest = hashlib.sha256(canonical_json(snapshot).encode("utf-8")).hexdigest()
        record = runtime.journal.connection.execute(
            "SELECT evidence_id FROM inspections WHERE query_kind = 'notebook.read' "
            "AND result_digest = ? AND component_id = ? LIMIT 1",
            (digest, runtime.active_component_id),
        ).fetchone()
        if record is None:
            record = runtime.journal.record_inspection(
                component_id=runtime.active_component_id, target_kind="notebook",
                target_key=kind + ":" + locator, query_kind="notebook.read", result=snapshot,
            )
        row["notebook_ref"] = record["evidence_id"]
    result["citation_contract"] = {
        "field": "notebook_refs", "authority": "investigator_statement_not_binary_evidence",
        "recovery": "Copy issued notebook_ref values; use current IDA evidence_refs for code claims and edits.",
    }
    return result


def validate_notebook_reference(runtime, reference: str, admitted: Mapping[str, Any] | None = None):
    """A copied stage may admit a prior stage's exact immutable notebook snapshot."""
    from .workspace import read_reversing_log

    row = runtime.journal.inspection(reference)
    snapshot = None
    if row and row.get("query_kind") == "notebook.read":
        snapshot = row["result"]
    elif admitted and admitted.get("kind") == "notebook":
        snapshot = admitted.get("notebook_snapshot")
    if not snapshot:
        return None, "unknown_notebook_reference"
    current = read_reversing_log(runtime.workspace / "reversing_log.md", journal_limit=1)
    if (snapshot["document_digest"] != current["document_digest"]
            or snapshot["root_binary_sha256"] != runtime.journal.component("root")["binary_sha256"]):
        return None, "notebook_snapshot_changed"
    return {"evidence_id": reference, "kind": "notebook", "citation_status": "current",
            "authority": "investigator_statement_not_binary_evidence", "notebook_snapshot": snapshot}, None
