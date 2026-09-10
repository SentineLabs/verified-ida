"""Durable conversation-session maintenance for long Verified IDA runs.

Server compaction protects the model's active context.  These helpers handle a
different concern: identifying the exact active suffix, archiving inactive
history, and restoring the original session if local maintenance fails.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def item_type(item: Any) -> str:
    if isinstance(item, Mapping):
        return str(item.get("type") or item.get("role") or "unknown")
    return str(getattr(item, "type", type(item).__name__))


def complete_function_pairs(items: Iterable[Mapping[str, Any]]) -> bool:
    """Reject suffixes that split tool pairs or contain unsupported tool items."""
    seen: set[str] = set()
    pending: set[str] = set()
    for item in items:
        kind = item_type(item)
        if kind in {"function_call", "function_call_output"}:
            call_id = item.get("call_id")
            if not isinstance(call_id, str) or not call_id:
                return False
            if kind == "function_call":
                if call_id in seen:
                    return False
                seen.add(call_id)
                pending.add(call_id)
            else:
                if call_id not in pending:
                    return False
                pending.remove(call_id)
        elif kind not in {"message", "user", "assistant", "system", "developer",
                          "reasoning", "compaction"}:
            return False
    return not pending


def _jsonable(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _jsonable(model_dump(exclude_unset=True))
    return value


def encoded_items(items: Iterable[Any]) -> bytes:
    return json.dumps(
        _jsonable(list(items)),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")


def items_digest(items: Iterable[Any]) -> str:
    return hashlib.sha256(encoded_items(items)).hexdigest()


@dataclass(frozen=True)
class SessionInventory:
    item_count: int
    encoded_bytes: int
    digest: str
    compaction_count: int
    latest_compaction_index: int | None
    active_item_count: int
    active_encoded_bytes: int
    active_digest: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "item_count": self.item_count,
            "encoded_bytes": self.encoded_bytes,
            "digest": self.digest,
            "compaction_count": self.compaction_count,
            "latest_compaction_index": self.latest_compaction_index,
            "active_item_count": self.active_item_count,
            "active_encoded_bytes": self.active_encoded_bytes,
            "active_digest": self.active_digest,
        }


def latest_compaction_suffix(
    items: Iterable[Any], provenance: Mapping[str, str] | None = None,
) -> list[Any]:
    values = list(items)
    # A later standalone/unknown window must not be trimmed using an older
    # server marker retained inside it. Only the latest marker may authorize it.
    for index in range(len(values) - 1, -1, -1):
        if item_type(values[index]) == "compaction":
            if (provenance or {}).get(items_digest([values[index]])) == "server":
                return values[index:]
            break
    return values


def session_inventory(
    items: Iterable[Any], provenance: Mapping[str, str] | None = None,
) -> SessionInventory:
    values = list(items)
    compaction_indexes = [
        index for index, item in enumerate(values) if item_type(item) == "compaction"
    ]
    latest = compaction_indexes[-1] if compaction_indexes else None
    active = latest_compaction_suffix(values, provenance)
    encoded = encoded_items(values)
    active_encoded = encoded_items(active)
    return SessionInventory(
        item_count=len(values),
        encoded_bytes=len(encoded),
        digest=hashlib.sha256(encoded).hexdigest(),
        compaction_count=len(compaction_indexes),
        latest_compaction_index=latest,
        active_item_count=len(active),
        active_encoded_bytes=len(active_encoded),
        active_digest=hashlib.sha256(active_encoded).hexdigest(),
    )


class SessionMaintenanceError(RuntimeError):
    """Raised when archive/prune cannot safely preserve the original session."""

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        restored: bool,
        archive: str | None = None,
    ):
        super().__init__(message)
        self.stage = stage
        self.restored = restored
        self.archive = archive

    def as_dict(self) -> dict[str, Any]:
        return {
            "type": type(self).__name__,
            "message": str(self),
            "stage": self.stage,
            "restored": self.restored,
            "archive": self.archive,
        }


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def archive_sqlite(source: str | Path, destination: str | Path) -> None:
    source_path = Path(source)
    destination_path = Path(destination)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(str(source_path)) as source_db:
        with sqlite3.connect(str(destination_path)) as destination_db:
            source_db.backup(destination_db)
    with sqlite3.connect(str(destination_path)) as archived:
        row = archived.execute("PRAGMA integrity_check").fetchone()
        if row is None or row[0] != "ok":
            raise SessionMaintenanceError(
                "Archived SQLite session failed integrity_check",
                stage="archive_verify",
                restored=True,
                archive=str(destination_path),
            )


def archive_session_snapshot(
    *,
    sqlite_path: str | Path,
    archive_dir: str | Path,
    segment_id: str,
    items: Iterable[Any],
    reason: str,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create and verify a complete immutable session archive."""

    values = list(items)
    archive_directory = Path(archive_dir)
    archive_directory.mkdir(parents=True, exist_ok=True)
    archive_path = _unique_archive_path(archive_directory, segment_id)
    archive_sqlite(sqlite_path, archive_path)
    archive_digest = sha256_file(archive_path)
    inventory = session_inventory(values)
    manifest = {
        "schema": "verified_ida.session_archive.v1",
        "created_at": utc_timestamp(),
        "segment_id": segment_id,
        "reason": reason,
        "metadata": dict(metadata or {}),
        "source": str(Path(sqlite_path).resolve()),
        "archive": str(archive_path.resolve()),
        "archive_sha256": archive_digest,
        "inventory": inventory.as_dict(),
        "retained": inventory.as_dict(),
    }
    manifest_path = archive_path.with_suffix(".manifest.json")
    _write_manifest(manifest_path, manifest)
    return {
        "archive": str(archive_path.resolve()),
        "manifest": str(manifest_path.resolve()),
        "archive_sha256": archive_digest,
        "inventory": inventory.as_dict(),
    }


def _unique_archive_path(directory: Path, segment_id: str) -> Path:
    safe_segment = "".join(
        character if character.isalnum() or character in "-_" else "-"
        for character in segment_id
    ).strip("-") or "segment"
    stem = "%s-%s" % (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        safe_segment,
    )
    candidate = directory / (stem + ".sqlite")
    counter = 1
    while candidate.exists():
        candidate = directory / ("%s-%02d.sqlite" % (stem, counter))
        counter += 1
    return candidate


def _write_manifest(path: Path, manifest: Mapping[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(dict(manifest), indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    with temporary.open("rb") as handle:
        os.fsync(handle.fileno())
    temporary.replace(path)


def _replacement_fault(stage: str, failure_stage: str | None) -> None:
    """A fault boundary usable by exception and actual process-death tests."""
    if stage == failure_stage:
        raise RuntimeError("Injected failure %s" % stage)


def _write_compaction_provenance(connection: Any, session_id: str, provenance: Mapping[str, str]) -> None:
    connection.execute(
        "CREATE TABLE IF NOT EXISTS verified_ida_compaction_provenance "
        "(session_id TEXT, marker_digest TEXT, mode TEXT NOT NULL, "
        "PRIMARY KEY(session_id, marker_digest))"
    )
    for digest, mode in provenance.items():
        if mode not in {"server", "standalone"}:
            raise ValueError("Unknown compaction provenance")
        connection.execute(
            "INSERT INTO verified_ida_compaction_provenance VALUES (?, ?, ?) "
            "ON CONFLICT(session_id, marker_digest) DO UPDATE SET mode=excluded.mode",
            (session_id, digest, mode),
        )


def compaction_provenance(session: Any) -> dict[str, str]:
    """Host metadata only; unknown/legacy markers never authorize pruning."""
    from agents import SQLiteSession

    if not isinstance(session, SQLiteSession):
        return dict(getattr(session, "compaction_provenance", {}))
    with session._locked_connection() as connection:
        if not connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='verified_ida_compaction_provenance'"
        ).fetchone():
            return {}
        return dict(connection.execute(
            "SELECT marker_digest, mode FROM verified_ida_compaction_provenance WHERE session_id=?",
            (session.session_id,),
        ))


def record_server_compactions(session: Any, output: Iterable[Any]) -> None:
    """Called only for items received from a normal model response."""
    markers = {items_digest([item]): "server" for item in output if item_type(item) == "compaction"}
    if not markers:
        return
    with session._write_connection() as connection:
        _write_compaction_provenance(connection, session.session_id, markers)
        connection.commit()


async def replace_session_items(
    session: Any, items: list[Any], *, failure_stage: str | None = None,
    provenance: Mapping[str, str] | None = None,
) -> None:
    """Replace history in one SQLite transaction using the pinned SDK store.

    This runs only between model turns. No await occurs inside the transaction,
    so cancellation cannot interleave deletion with replacement. SQLite rolls
    back on process death. SDK upgrades must pass the real-store crash tests.
    """
    from agents import SQLiteSession

    if not isinstance(session, SQLiteSession):
        # An alternate store must explicitly implement atomic replacement;
        # never silently fall back to two independent clear/add commits.
        if provenance:
            raise RuntimeError("Session store does not support atomic compaction provenance")
        replace = getattr(session, "replace_items", None)
        if replace is None:
            raise RuntimeError("Session store does not support atomic replacement")
        await replace(items, failure_stage=failure_stage)
        return
    if session.messages_table != "agent_messages" or session.sessions_table != "agent_sessions":
        raise RuntimeError("Unsupported SDK session table layout")
    with session._write_connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        _replacement_fault("before_clear", failure_stage)
        connection.execute("DELETE FROM agent_messages WHERE session_id = ?", (session.session_id,))
        _replacement_fault("after_clear", failure_stage)
        session._insert_items(connection, items)
        if provenance:
            _write_compaction_provenance(connection, session.session_id, provenance)
        _replacement_fault("after_add", failure_stage)
        connection.commit()
        _replacement_fault("after_commit", failure_stage)


async def archive_and_prune_session(
    session: Any,
    *,
    sqlite_path: str | Path,
    archive_dir: str | Path,
    segment_id: str,
    prune_threshold_bytes: int,
    force: bool = False,
    failure_stage: str | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Archive a complete session and retain its latest compacted suffix.

    ``failure_stage`` exists for deterministic fault-injection tests.  The
    production caller leaves it unset.
    """

    original = list(await session.get_items())
    provenance = compaction_provenance(session)
    inventory = session_inventory(original, provenance)
    if inventory.latest_compaction_index is None:
        return {
            "action": "not_pruned",
            "reason": "no_compaction_item",
            "inventory": inventory.as_dict(),
        }
    if not force and inventory.encoded_bytes < max(1, prune_threshold_bytes):
        return {
            "action": "not_pruned",
            "reason": "below_threshold",
            "inventory": inventory.as_dict(),
        }
    suffix = latest_compaction_suffix(original, provenance)
    if len(suffix) == len(original):
        return {
            "action": "not_pruned", "reason": "no_verified_server_compaction_boundary",
            "inventory": inventory.as_dict(),
        }
    if not complete_function_pairs(suffix):
        return {
            "action": "not_pruned",
            "reason": "incomplete_or_unsupported_tool_boundary",
            "inventory": inventory.as_dict(),
        }
    if failure_stage == "before_archive":
        raise SessionMaintenanceError(
            "Injected failure before session archive",
            stage="before_archive",
            restored=True,
        )

    archive_directory = Path(archive_dir)
    archive_directory.mkdir(parents=True, exist_ok=True)
    archive_path = _unique_archive_path(archive_directory, segment_id)
    archive_sqlite(sqlite_path, archive_path)
    archive_digest = sha256_file(archive_path)
    manifest = {
        "schema": "verified_ida.session_archive.v1",
        "created_at": utc_timestamp(),
        "segment_id": segment_id,
        "metadata": dict(metadata or {}),
        "source": str(Path(sqlite_path).resolve()),
        "archive": str(archive_path.resolve()),
        "archive_sha256": archive_digest,
        "inventory": inventory.as_dict(),
        "retained": session_inventory(suffix, provenance).as_dict(),
    }
    manifest_path = archive_path.with_suffix(".manifest.json")
    _write_manifest(manifest_path, manifest)
    if failure_stage == "after_archive":
        raise SessionMaintenanceError(
            "Injected failure after session archive",
            stage="after_archive",
            restored=True,
            archive=str(archive_path),
        )

    stage = "clear"
    try:
        stage = "add_suffix"
        await replace_session_items(session, suffix, failure_stage=failure_stage)
        stage = "verify_suffix"
        observed = list(await session.get_items())
        if items_digest(observed) != items_digest(suffix) or len(observed) != len(suffix):
            raise RuntimeError("Active session suffix did not round-trip exactly")
    except Exception as exc:
        restored = False
        try:
            await replace_session_items(session, original)
            restored_items = list(await session.get_items())
            restored = (
                len(restored_items) == len(original)
                and items_digest(restored_items) == items_digest(original)
            )
        except Exception:
            restored = False
        raise SessionMaintenanceError(
            "%s: %s" % (type(exc).__name__, exc),
            stage=stage,
            restored=restored,
            archive=str(archive_path),
        ) from exc

    retained_inventory = session_inventory(suffix, provenance)
    return {
        "action": "archived_and_pruned",
        "archive": str(archive_path.resolve()),
        "manifest": str(manifest_path.resolve()),
        "archive_sha256": archive_digest,
        "before": inventory.as_dict(),
        "after": retained_inventory.as_dict(),
        "removed_items": inventory.item_count - retained_inventory.item_count,
    }


async def compact_session_atomically(session: Any, *, session_id: str, model: str) -> list[Any]:
    """Let SDK compaction replace temporary state, then commit once to SQLite."""
    from agents import OpenAIResponsesCompactionSession, SQLiteSession

    temporary = SQLiteSession(session_id)
    try:
        await temporary.add_items(list(await session.get_items()))
        compacting = OpenAIResponsesCompactionSession(
            session_id, temporary, model=model, compaction_mode="input",
        )
        await compacting.run_compaction({"force": True, "compaction_mode": "input", "store": False})
        recovered = list(await temporary.get_items())
        if session_inventory(recovered).latest_compaction_index is None:
            raise RuntimeError("Recovery compaction returned no compaction item")
        # The complete endpoint output is canonical. Do not trim standalone
        # compaction output using the server-side suffix-pruning policy.
        await replace_session_items(session, recovered, provenance={
            items_digest([item]): "standalone"
            for item in recovered if item_type(item) == "compaction"
        })
        return recovered
    finally:
        temporary.close()
