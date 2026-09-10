"""Isolation and durable disposition helpers for Verified IDA final review."""

from __future__ import annotations

import hashlib
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Mapping

from .closure_review import declared_references
from .contracts import VERIFIED_STATUSES, canonical_json
from .journal import VerifiedIdaJournal
from .semantic_delta import semantic_state_digest


REVIEW_OUTCOMES = frozenset({
    "accept_and_apply",
    "revise_and_apply",
    "reject",
    "defer",
    "follow_up_required",
})
REVIEW_TARGET_KINDS = frozenset({
    "function",
    "address",
    "global",
    "named_type",
    "relationship",
    "local_variable",
})


class FinalReviewError(ValueError):
    """Raised when review isolation or disposition validation fails."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rebase_path(value: str | None, source: Path, destination: Path) -> str | None:
    if not value:
        return value
    path = Path(str(value)).expanduser()
    try:
        relative = path.resolve().relative_to(source)
    except (OSError, ValueError):
        return str(value)
    return str((destination / relative).resolve())


def _materialize_external_binary(
    *,
    source_binary: str | Path,
    component_id: str,
    destination: Path,
) -> tuple[str, dict[str, Any]]:
    """Copy a registered external input into a self-contained nested clone."""

    source_path = Path(source_binary).expanduser().resolve()
    digest = _sha256_file(source_path)
    component_bucket = hashlib.sha256(
        str(component_id).encode("utf-8")
    ).hexdigest()[:16]
    suffix = source_path.suffix if source_path.suffix else ".bin"
    target = (
        destination
        / "registered_binaries"
        / component_bucket
        / (digest + suffix)
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.is_file():
        if _sha256_file(target) != digest:
            raise FinalReviewError(
                "Existing materialized binary does not match its content address"
            )
    else:
        shutil.copy2(source_path, target)
    return str(target.resolve()), {
        "component_id": str(component_id),
        "source_path": str(source_path),
        "destination_path": str(target.resolve()),
        "sha256": digest,
        "bytes": target.stat().st_size,
    }


def _rebase_checkpoint_details(
    raw: str,
    source: Path,
    destination: Path,
) -> str:
    details = json.loads(raw or "{}")
    if not isinstance(details, dict):
        return raw
    if details.get("semantic_export_path"):
        details["semantic_export_path"] = _rebase_path(
            str(details["semantic_export_path"]), source, destination
        )
    return json.dumps(details, sort_keys=True, separators=(",", ":"))


def _component_files(database: Path) -> list[dict[str, Any]]:
    connection = sqlite3.connect(str(database))
    connection.row_factory = sqlite3.Row
    try:
        rows = connection.execute(
            "SELECT component_id, binary_path, idb_path FROM components ORDER BY component_id"
        ).fetchall()
    finally:
        connection.close()
    result = []
    for row in rows:
        for kind in ("binary", "idb"):
            value = row["binary_path" if kind == "binary" else "idb_path"]
            if not value:
                continue
            path = Path(str(value)).expanduser().resolve()
            if not path.is_file():
                raise FinalReviewError(
                    "Component %s %s is missing: %s"
                    % (row["component_id"], kind, path)
                )
            result.append({
                "component_id": str(row["component_id"]),
                "kind": kind,
                "path": str(path),
                "bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            })
            if kind == "idb":
                for suffix in (".id0", ".id1", ".id2", ".id3", ".nam", ".til"):
                    companion = path.with_suffix(suffix)
                    if not companion.is_file():
                        continue
                    result.append({
                        "component_id": str(row["component_id"]),
                        "kind": "idb_companion:%s" % suffix.removeprefix("."),
                        "path": str(companion),
                        "bytes": companion.stat().st_size,
                        "sha256": _sha256_file(companion),
                    })
    return result


def _connection_database_path(connection: sqlite3.Connection) -> Path:
    rows = connection.execute("PRAGMA database_list").fetchall()
    for row in rows:
        # sqlite3.Row and the default tuple row factory are both supported.
        name = row[1]
        path = row[2]
        if str(name) == "main" and path:
            return Path(str(path)).expanduser().resolve()
    raise FinalReviewError("Live SQLite connection has no file-backed main database")


def clone_verified_project(
    source_project: str | Path,
    destination_project: str | Path,
    *,
    reference_source_binaries: bool = False,
    source_connection: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Clone and rebase one project without touching its source IDBs.

    Offline callers must present a checkpointed journal.  A paused live runtime
    may instead supply its journal connection; SQLite's online-backup API then
    creates a transactionally consistent database snapshot that includes
    committed WAL state without closing the investigator's session.
    """

    source = Path(source_project).expanduser().resolve()
    destination = Path(destination_project).expanduser().resolve()
    if source == destination:
        raise FinalReviewError("Final review requires a separate project copy")
    source_database = source / "verified_ida.sqlite"
    if not source_database.is_file():
        raise FinalReviewError("Source is not a Verified IDA project: %s" % source)
    source_wal = source_database.with_name(source_database.name + "-wal")
    snapshot_mode = "offline_checkpointed_copy"
    if source_connection is not None:
        if source_connection.in_transaction:
            raise FinalReviewError(
                "Live project snapshot requires a committed SQLite connection"
            )
        connected_database = _connection_database_path(source_connection)
        if connected_database != source_database:
            raise FinalReviewError(
                "Live SQLite connection does not belong to the source project"
            )
        snapshot_mode = "sqlite_online_backup"
    elif source_wal.is_file() and source_wal.stat().st_size:
        raise FinalReviewError(
            "Source project has an uncheckpointed SQLite WAL; close its writer "
            "before final review: %s" % source_wal
        )
    if destination.exists():
        raise FinalReviewError("Destination project already exists: %s" % destination)

    from .transaction_recovery import require_settled_transactions
    try:
        require_settled_transactions(source)
    except (ValueError, OSError) as exc:
        raise FinalReviewError(str(exc)) from exc

    source_files_before = _component_files(source_database)
    if source_connection is None:
        shutil.copytree(source, destination)
    else:
        ignored_at_root = {
            source_database.name,
            source_database.name + "-wal",
            source_database.name + "-shm",
            ".reversing_log.md.lock",
        }

        def ignore_live_database(path: str, names: list[str]) -> set[str]:
            if Path(path).resolve() != source:
                return set()
            return ignored_at_root.intersection(names)

        shutil.copytree(source, destination, ignore=ignore_live_database)
        destination_database = destination / "verified_ida.sqlite"
        snapshot_connection = sqlite3.connect(str(destination_database))
        try:
            source_connection.backup(snapshot_connection)
            snapshot_connection.commit()
        finally:
            snapshot_connection.close()
    lock = destination / ".reversing_log.md.lock"
    if lock.exists():
        lock.unlink()

    destination_database = destination / "verified_ida.sqlite"
    snapshot_database_sha256_before_rebase = _sha256_file(destination_database)
    for suffix in ("-wal", "-shm"):
        sidecar = destination_database.with_name(destination_database.name + suffix)
        if sidecar.exists():
            sidecar.unlink()
    materialized_external_binaries: list[dict[str, Any]] = []
    connection = sqlite3.connect(str(destination_database))
    connection.row_factory = sqlite3.Row
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        for row in connection.execute(
            "SELECT component_id, binary_path, idb_path FROM components"
        ).fetchall():
            binary_path = row["binary_path"]
            if not reference_source_binaries and binary_path:
                rebased_binary = _rebase_path(binary_path, source, destination)
                if rebased_binary == str(binary_path):
                    binary_path, materialized = _materialize_external_binary(
                        source_binary=binary_path,
                        component_id=str(row["component_id"]),
                        destination=destination,
                    )
                    materialized_external_binaries.append(materialized)
                else:
                    binary_path = rebased_binary
            connection.execute(
                "UPDATE components SET binary_path = ?, idb_path = ? WHERE component_id = ?",
                (
                    (
                        row["binary_path"]
                        if reference_source_binaries
                        else binary_path
                    ),
                    _rebase_path(row["idb_path"], source, destination),
                    row["component_id"],
                ),
            )
        for row in connection.execute(
            "SELECT extraction_id, artifact_path FROM extractions"
        ).fetchall():
            connection.execute(
                "UPDATE extractions SET artifact_path = ? WHERE extraction_id = ?",
                (
                    _rebase_path(row["artifact_path"], source, destination),
                    row["extraction_id"],
                ),
            )
        for row in connection.execute(
            "SELECT checkpoint_id, details_json FROM checkpoints"
        ).fetchall():
            connection.execute(
                "UPDATE checkpoints SET details_json = ? WHERE checkpoint_id = ?",
                (
                    _rebase_checkpoint_details(
                        row["details_json"], source, destination
                    ),
                    row["checkpoint_id"],
                ),
            )
        for row in connection.execute(
            "SELECT evidence_id, result_path FROM inspections WHERE result_path IS NOT NULL"
        ).fetchall():
            connection.execute(
                "UPDATE inspections SET result_path = ? WHERE evidence_id = ?",
                (
                    _rebase_path(row["result_path"], source, destination),
                    row["evidence_id"],
                ),
            )
        for row in connection.execute(
            "SELECT review_id, packet_path FROM closure_reviews"
        ).fetchall():
            connection.execute(
                "UPDATE closure_reviews SET packet_path = ? WHERE review_id = ?",
                (
                    _rebase_path(row["packet_path"], source, destination),
                    row["review_id"],
                ),
            )
        connection.commit()
    finally:
        connection.close()

    destination_files = _component_files(destination_database)
    expected = {
        (row["component_id"], row["kind"]): row["sha256"]
        for row in source_files_before
    }
    for row in destination_files:
        key = (row["component_id"], row["kind"])
        if expected.get(key) != row["sha256"]:
            raise FinalReviewError(
                "Project clone drifted for %s %s" % key
            )
        expected_root = (
            source
            if reference_source_binaries and row["kind"] == "binary"
            else destination
        )
        try:
            Path(row["path"]).resolve().relative_to(expected_root)
        except ValueError as exc:
            raise FinalReviewError(
                "Cloned component path violates the clone policy: %s"
                % row["path"]
            ) from exc

    source_files_after = _component_files(source_database)
    if [row["sha256"] for row in source_files_before] != [
        row["sha256"] for row in source_files_after
    ]:
        raise FinalReviewError("Source component changed while it was cloned")

    manifest = {
        "schema": "verified_ida.final_review_clone.v2",
        "source_project": str(source),
        "destination_project": str(destination),
        "database_snapshot_mode": snapshot_mode,
        "source_database_sha256": (
            _sha256_file(source_database)
            if source_connection is None else None
        ),
        "snapshot_database_sha256_before_rebase": (
            snapshot_database_sha256_before_rebase
        ),
        "destination_database_sha256_after_rebase": _sha256_file(
            destination_database
        ),
        "source_component_files": source_files_before,
        "destination_component_files": destination_files,
        "binary_path_policy": (
            "immutable_source_reference"
            if reference_source_binaries
            else "self_contained_clone"
        ),
        "materialized_external_binaries": materialized_external_binaries,
        "source_component_files_unchanged": True,
        "canonical_source_mutation_authorized": False,
    }
    (destination / "final_review_clone_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def load_current_recorded_closure(runtime: Any) -> dict[str, Any] | None:
    """Reuse a current recorded closure packet without reopening every child IDB.

    A completed project commonly records a fresh closure packet immediately before
    its final checkpoint.  When no component revision or operation has changed,
    its live IDA summaries remain current.  Notebook and component metadata are
    refreshed from the cloned project so source paths and the final closure note
    are never reused verbatim.
    """

    review = runtime.journal.latest_closure_review()
    if review is None:
        return None
    current_revisions = {
        str(row["component_id"]): int(
            runtime.journal.revision(str(row["component_id"]))["revision"]
        )
        for row in runtime.journal.components()
    }
    recorded_revisions = {
        str(key): int(value)
        for key, value in dict(review.get("component_revisions") or {}).items()
    }
    if recorded_revisions != current_revisions:
        return None
    if runtime.journal.operations_after_closure_review(str(review["review_id"])):
        return None
    objective_digest = hashlib.sha256(
        runtime.project_objective.encode("utf-8")
    ).hexdigest()
    if str(review.get("objective_digest") or "") != objective_digest:
        return None

    packet_path = Path(str(review.get("packet_path") or "")).expanduser()
    if not packet_path.is_file():
        return None
    try:
        packet = json.loads(packet_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(packet, dict):
        return None
    raw_digest = hashlib.sha256(
        canonical_json(packet).encode("utf-8")
    ).hexdigest()
    if raw_digest != str(review.get("packet_digest") or ""):
        return None

    components = runtime.list_components()["components"]
    notebook = runtime.read_reversing_log(journal_limit=3)
    packet["components"] = components
    packet["notebook"] = notebook
    packet["declared_references"] = declared_references(
        dict(notebook.get("current_state") or {}),
        component_ids=tuple(
            str(row.get("component_id") or "")
            for row in components
            if row.get("component_id")
        ),
    )
    packet["recorded_closure_reuse"] = {
        "review_id": str(review["review_id"]),
        "review_epoch": int(review["epoch"]),
        "recorded_packet_digest": raw_digest,
        "component_revisions_verified_current": True,
        "operations_after_recorded_review": 0,
        "refreshed_fields": ["components", "notebook", "declared_references"],
    }
    return {
        "schema": "verified_ida.reused_analysis_closure_review.v1",
        "review_id": str(review["review_id"]),
        "review_epoch": int(review["epoch"]),
        "packet_digest": hashlib.sha256(
            canonical_json(packet).encode("utf-8")
        ).hexdigest(),
        "packet_path": str(packet_path.resolve()),
        "blocking": False,
        "mechanical_completion_status": runtime.journal.completion_status(),
        "packet": packet,
        "reused_current_recorded_packet": True,
    }


def project_component_hashes(project: str | Path) -> dict[str, str]:
    database = Path(project).expanduser().resolve() / "verified_ida.sqlite"
    return {
        "%s:%s" % (row["component_id"], row["kind"]): row["sha256"]
        for row in _component_files(database)
    }


def semantic_project_snapshot(runtime: Any) -> dict[str, Any]:
    """Capture revision-bound semantic state without saving an IDB."""

    components = {}
    for component in sorted(
        runtime.journal.components(), key=lambda row: str(row["component_id"])
    ):
        if not component.get("idb_path"):
            continue
        component_id = str(component["component_id"])
        state = runtime._closure_semantic_state(component_id)
        components[component_id] = {
            "revision": int(runtime.journal.revision(component_id)["revision"]),
            "semantic_digest": semantic_state_digest(state),
            "counts": {
                key: len(list(state.get(key) or []))
                for key in (
                    "functions",
                    "globals",
                    "named_types",
                    "structs",
                    "enums",
                    "relationships",
                )
            },
        }
    return {
        "schema": "verified_ida.final_review_semantic_snapshot.v1",
        "components": components,
        "snapshot_digest": hashlib.sha256(
            canonical_json(components).encode("utf-8")
        ).hexdigest(),
    }


def verify_semantic_stage_boundary(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> dict[str, Any]:
    """Fail when a read-only stage changes a revision or semantic digest."""

    before_components = dict(before.get("components") or {})
    after_components = dict(after.get("components") or {})
    changes = []
    for component_id in sorted(set(before_components) | set(after_components)):
        prior = dict(before_components.get(component_id) or {})
        current = dict(after_components.get(component_id) or {})
        if prior.get("revision") != current.get("revision") or prior.get(
            "semantic_digest"
        ) != current.get("semantic_digest"):
            changes.append({
                "component_id": component_id,
                "before_revision": prior.get("revision"),
                "after_revision": current.get("revision"),
                "before_semantic_digest": prior.get("semantic_digest"),
                "after_semantic_digest": current.get("semantic_digest"),
            })
    result = {
        "schema": "verified_ida.final_review_semantic_boundary.v1",
        "status": "verified" if not changes else "failed",
        "before_snapshot_digest": before.get("snapshot_digest"),
        "after_snapshot_digest": after.get("snapshot_digest"),
        "changes": changes,
    }
    if changes:
        raise FinalReviewError(
            "Read-only review stage changed semantic IDA state: %s"
            % ", ".join(row["component_id"] for row in changes)
        )
    return result


def _finding_source_id(source: str, finding_id: str) -> str:
    return "%s:%s" % (source, finding_id)


def _normalized_address(value: Any, field: str) -> str:
    try:
        address = int(str(value), 0)
    except (TypeError, ValueError) as exc:
        raise FinalReviewError("%s must be an address" % field) from exc
    if address < 0:
        raise FinalReviewError("%s must be a non-negative address" % field)
    return hex(address)


def canonical_review_target(
    raw_target: Mapping[str, Any],
    *,
    component_ids: set[str],
    address_validator: Any | None = None,
) -> dict[str, Any]:
    """Normalize one reviewer target without deriving identity from prose."""

    raw = dict(raw_target)
    component_id = str(raw.get("component_id") or "").strip()
    if component_id not in component_ids:
        raise FinalReviewError(
            "Review target names unknown component %s"
            % (component_id or "<empty>")
        )
    kind = str(raw.get("kind") or "").strip()
    if kind not in REVIEW_TARGET_KINDS:
        raise FinalReviewError("Unsupported review target kind: %s" % kind)

    target: dict[str, Any] = {"kind": kind}
    address_fields: list[str] = []
    if kind in {"function", "address", "global"}:
        address_fields = ["address"]
    elif kind == "named_type":
        name = str(raw.get("name") or "").strip()
        if not name:
            raise FinalReviewError("named_type review targets require name")
        target["name"] = name
    elif kind == "local_variable":
        address_fields = ["function_address"]
        if raw.get("lvar_index") is not None:
            index = raw.get("lvar_index")
            if not isinstance(index, int) or index < 0:
                raise FinalReviewError(
                    "local_variable lvar_index must be a non-negative integer"
                )
            target["lvar_index"] = index
        current_name = str(raw.get("current_name") or "").strip()
        if current_name:
            target["current_name"] = current_name
        if "lvar_index" not in target and "current_name" not in target:
            raise FinalReviewError(
                "local_variable review targets require lvar_index or current_name"
            )
    elif kind == "relationship":
        address_fields = ["source_address", "destination_address"]
        if raw.get("callsite_address") not in (None, ""):
            address_fields.append("callsite_address")
        relationship_kind = str(raw.get("relationship_kind") or "").strip()
        if not relationship_kind:
            raise FinalReviewError(
                "relationship review targets require relationship_kind"
            )
        target["relationship_kind"] = relationship_kind

    address_checks = []
    for field in address_fields:
        address = _normalized_address(raw.get(field), field)
        target[field] = address
        check = {
            "component_id": component_id,
            "address": address,
            "field": field,
            "status": "syntax_validated",
        }
        if address_validator is not None:
            observed = dict(address_validator(component_id, address) or {})
            if not observed.get("valid"):
                raise FinalReviewError(
                    "Review target contains unresolved address %s::%s"
                    % (component_id, address)
                )
            check = {**check, **observed, "status": "resolved"}
        address_checks.append(check)

    target_key = _review_target_key(target)
    if not target_key:
        raise FinalReviewError("Review target identity is incomplete")
    target_id = "review-target-%s" % hashlib.sha256(
        canonical_json([component_id, kind, target_key]).encode("utf-8")
    ).hexdigest()[:24]
    return {
        "target_id": target_id,
        "component_id": component_id,
        "target_kind": kind,
        "target_key": target_key,
        "target": target,
        "address_checks": address_checks,
    }


def finding_review_targets(finding: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Return host-validated targets from an index or wave finding row."""

    direct = finding.get("validated_targets")
    if direct is not None:
        return [dict(row) for row in direct]
    source = finding.get("source_finding")
    if isinstance(source, Mapping):
        return [dict(row) for row in source.get("validated_targets") or []]
    return []


def bind_application_finding_targets(
    finding: Mapping[str, Any], runtime: Any,
) -> dict[str, Any]:
    """Bind collected relationship endpoints to a unique live native callsite.

    Collection records are preserved as provenance. All application consumers
    receive the same exact replacement identity; ambiguity is not permission.
    """
    bound = dict(finding)
    targets = []
    bindings = []
    components = {str(row["component_id"]) for row in runtime.journal.components()}
    for original in finding_review_targets(finding):
        target = dict(original.get("target") or {})
        if target.get("kind") != "relationship":
            targets.append(original)
            continue
        component = str(original["component_id"])
        source = runtime.inspect(
            query="inspect_function", target=target["source_address"],
            component_id=component,
        )
        destination = runtime.inspect(
            query="inspect_function", target=target["destination_address"],
            component_id=component,
        )
        inspected = runtime.inspect_relationship(
            source_ref=source["target_ref"], destination_ref=destination["target_ref"],
            relationship_kind=target["relationship_kind"],
            callsite_address=target.get("callsite_address"),
        )
        reference = runtime.journal.reference(inspected["target_ref"])
        replacement = canonical_review_target(
            {**reference["target"], "component_id": component},
            component_ids=components,
        )
        replacement["native_binding_evidence_id"] = inspected["evidence_id"]
        targets.append(replacement)
        bindings.append({
            "original": original, "bound": replacement,
            "reason": "current IDA-native exact direct-call relationship",
        })
    bound["validated_targets"] = targets
    bound["target_ids"] = [row["target_id"] for row in targets]
    bound["application_target_bindings"] = bindings
    return bound


def _review_target_key(target: Mapping[str, Any]) -> str:
    """Return a stable review identity from one typed mutation target."""

    if str(target.get("kind") or "") == "local_variable":
        function_address = str(target.get("function_address") or "")
        if target.get("lvar_index") is not None:
            return "%s:index:%s" % (
                function_address,
                int(target["lvar_index"]),
            )
        return "%s:name:%s" % (
            function_address,
            str(target.get("current_name") or ""),
        )
    return VerifiedIdaJournal.target_key(target)


def review_target_identity(target: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return the exact component/kind/key identity for a validated target."""

    return (
        str(target.get("component_id") or ""),
        str(target.get("target_kind") or ""),
        str(target.get("target_key") or ""),
    )


def operation_review_target(operation: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return one journal operation's exact artifact identity."""

    request = dict(operation.get("request") or {})
    target = dict(request.get("target") or {})
    return (
        str(operation.get("component_id") or ""),
        str(target.get("kind") or operation.get("target_kind") or ""),
        _review_target_key(target),
    )


def evidence_matches_review_target(
    evidence: Mapping[str, Any],
    target: Mapping[str, Any],
) -> bool:
    """Match current evidence to a target using kind-specific exact identities."""

    component_id, target_kind, target_key = review_target_identity(target)
    if str(evidence.get("component_id") or "") != component_id:
        return False
    evidence_kind = str(evidence.get("target_kind") or "")
    evidence_key = str(evidence.get("target_key") or "")
    if (evidence_kind, evidence_key) == (target_kind, target_key):
        return True
    if target_kind == "local_variable":
        function_address = str(
            dict(target.get("target") or {}).get("function_address") or ""
        )
        return (evidence_kind, evidence_key) == ("function", function_address)
    if target_kind == "relationship":
        source_address = str(
            dict(target.get("target") or {}).get("source_address") or ""
        )
        return (evidence_kind, evidence_key) == ("function", source_address)
    return False


def _source_finding(
    *,
    source: str,
    source_kind: str,
    finding: Mapping[str, Any],
    component_ids: set[str],
    evidence_registry: Mapping[str, Mapping[str, Any]],
    address_validator: Any | None,
) -> dict[str, Any]:
    raw = dict(finding)
    native_id = str(
        raw.get("finding_id") or raw.get("gap_id") or raw.get("fact_id") or ""
    ).strip()
    if not native_id:
        raise FinalReviewError("Review finding is missing its source identifier")
    component_id = str(raw.get("component_id") or "").strip()
    if component_id not in component_ids:
        raise FinalReviewError(
            "Review finding %s names unknown component %s"
            % (native_id, component_id or "<empty>")
        )
    related_component_ids = list(dict.fromkeys(
        str(value).strip()
        for value in (raw.get("related_component_ids") or [])
        if str(value).strip()
    ))
    invalid_related_components = [
        value for value in related_component_ids
        if value not in component_ids or value == component_id
    ]
    if invalid_related_components:
        raise FinalReviewError(
            "Review finding %s names invalid related components: %s"
            % (native_id, ", ".join(invalid_related_components))
        )
    evidence_refs = list(dict.fromkeys(
        str(value) for value in (raw.get("evidence_refs") or []) if str(value)
    ))
    missing_evidence = [
        value for value in evidence_refs
        if value.startswith("evidence-") and value not in evidence_registry
    ]
    if missing_evidence:
        raise FinalReviewError(
            "Review finding %s contains unknown evidence: %s"
            % (native_id, ", ".join(missing_evidence))
        )

    validated_targets = []
    if source_kind in {"claim", "artifact"}:
        raw_targets = raw.get("targets") or []
        if not raw_targets:
            raise FinalReviewError(
                "Review finding %s requires at least one structured target"
                % native_id
            )
        seen_target_ids = set()
        for raw_target in raw_targets:
            target = canonical_review_target(
                raw_target,
                component_ids=component_ids,
                address_validator=address_validator,
            )
            target_id = str(target["target_id"])
            if target_id in seen_target_ids:
                raise FinalReviewError(
                    "Review finding %s contains duplicate target %s"
                    % (native_id, target_id)
                )
            seen_target_ids.add(target_id)
            validated_targets.append(target)
    elif raw.get("targets"):
        raise FinalReviewError(
            "System gap %s is a navigation parent and must not carry targets"
            % native_id
        )

    source_id = _finding_source_id(source, native_id)
    return {
        "source_finding_id": source_id,
        "source": source,
        "source_kind": source_kind,
        "native_finding_id": native_id,
        "component_id": component_id,
        "related_component_ids": related_component_ids,
        "application_eligibility": (
            "candidate" if source_kind in {"claim", "artifact"}
            else "navigation_parent"
        ),
        "evidence_refs": evidence_refs,
        "validated_targets": validated_targets,
        "target_ids": [row["target_id"] for row in validated_targets],
        "payload_sha256": hashlib.sha256(
            canonical_json(raw).encode("utf-8")
        ).hexdigest(),
        "payload": raw,
    }


def build_lossless_review_index(
    *,
    claim_reports: Iterable[Mapping[str, Any]],
    system_model: Mapping[str, Any],
    artifact_coverage: Mapping[str, Any],
    component_ids: Iterable[str],
    evidence_registry: Mapping[str, Mapping[str, Any]] | None = None,
    address_validator: Any | None = None,
) -> dict[str, Any]:
    """Preserve every reviewer output and add only host-validated metadata."""

    components = {str(value) for value in component_ids}
    registry = dict(evidence_registry or {})
    findings = []
    for report in claim_reports:
        lane = str(report.get("lane") or "unknown")
        for finding in report.get("findings") or []:
            findings.append(_source_finding(
                source="claim/%s" % lane,
                source_kind="claim",
                finding=finding,
                component_ids=components,
                evidence_registry=registry,
                address_validator=address_validator,
            ))
    for gap in system_model.get("supported_gaps") or []:
        findings.append(_source_finding(
            source="coverage/system_model",
            source_kind="system_gap",
            finding=gap,
            component_ids=components,
            evidence_registry=registry,
            address_validator=address_validator,
        ))
    for finding in artifact_coverage.get("findings") or []:
        findings.append(_source_finding(
            source="coverage/artifact",
            source_kind="artifact",
            finding=finding,
            component_ids=components,
            evidence_registry=registry,
            address_validator=address_validator,
        ))

    by_id = {}
    for finding in findings:
        source_id = str(finding["source_finding_id"])
        if source_id in by_id:
            raise FinalReviewError("Duplicate source finding ID: %s" % source_id)
        by_id[source_id] = finding

    target_groups: dict[tuple[str, ...], list[str]] = {}
    for finding in findings:
        target_ids = tuple(sorted(
            str(value) for value in finding["target_ids"]
        ))
        if target_ids:
            target_groups.setdefault(target_ids, []).append(
                str(finding["source_finding_id"])
            )
    shared_target_groups = [
        {
            "group_id": "shared-target-%03d" % (index + 1),
            "relationship": "shared_targets",
            "source_finding_ids": sorted(values),
        }
        for index, values in enumerate(
            sorted(
                (values for values in target_groups.values() if len(values) > 1),
                key=lambda values: tuple(sorted(values)),
            )
        )
    ]
    findings.sort(key=lambda row: str(row["source_finding_id"]))
    return {
        "schema": "verified_ida.final_review_lossless_index.v1",
        "contract": {
            "source_payloads_immutable": True,
            "silent_omission_forbidden": True,
            "provenance_escalation_forbidden": True,
            "model_planning_advisory_only": True,
        },
        "source_finding_count": len(findings),
        "application_candidate_count": sum(
            row["application_eligibility"] == "candidate" for row in findings
        ),
        "navigation_parent_count": sum(
            row["application_eligibility"] == "navigation_parent"
            for row in findings
        ),
        "source_findings": findings,
        "deterministic_relationships": shared_target_groups,
        "index_digest": hashlib.sha256(
            canonical_json([
                (row["source_finding_id"], row["payload_sha256"])
                for row in findings
            ]).encode("utf-8")
        ).hexdigest(),
    }


def finding_priority(finding: Mapping[str, Any]) -> str:
    """Read the documented finding shapes without discarding a high priority."""
    source = finding.get("source_finding") or {}
    payload = source.get("payload") or {}
    values = {value for value in (finding.get("priority"), source.get("priority"), payload.get("priority"))
              if value is not None}
    if values - {"low", "medium", "high"} or len(values) > 1:
        raise FinalReviewError("Invalid or conflicting persisted finding priority")
    return next(iter(values), "medium")


def review_completion_blockers(
    findings: Mapping[str, Any], dispositions: Mapping[str, Any], plan: Mapping[str, Any],
) -> list[str]:
    """One eligibility policy for normal application and finalization retries."""
    if "waves" not in plan or "unrepresented_high_priority_parent_ids" not in plan:
        raise FinalReviewError("Completion requires the complete validated application plan")
    unknown = set(dispositions) - set(findings)
    if unknown:
        raise FinalReviewError("Disposition has no registered finding: %s" % sorted(unknown))
    blockers = set(findings) - set(dispositions)
    blockers.update(plan["unrepresented_high_priority_parent_ids"])
    dependencies = _follow_up_dependencies(findings, dispositions)
    priorities = effective_finding_priorities(findings, dispositions)
    for finding_id, row in dispositions.items():
        if row.get("outcome") not in REVIEW_OUTCOMES:
            raise FinalReviewError("Invalid persisted disposition outcome")
        if row.get("outcome") == "follow_up_required":
            follow_up = row.get("follow_up") or {}
            if not follow_up.get("finding_id") or follow_up["finding_id"] not in findings:
                raise FinalReviewError("Required follow-up finding is missing from the ledger")
        priority = priorities[finding_id]
        if row["outcome"] == "defer" and priority == "high":
            blockers.add(finding_id)
    # Redirecting work is not resolving it. Every ancestor retains its
    # obligation until the dependent finding has an acceptable resolution.
    for finding_id in findings:
        child = dependencies.get(finding_id)
        while child is not None:
            if child in blockers:
                blockers.add(finding_id)
                break
            child = dependencies.get(child)
    return sorted(blockers)


def _follow_up_dependencies(
    findings: Mapping[str, Any], dispositions: Mapping[str, Any],
) -> dict[str, str]:
    dependencies = {}
    for finding_id, row in dispositions.items():
        if row.get("outcome") == "follow_up_required":
            child = (row.get("follow_up") or {}).get("finding_id")
            if finding_id not in findings or child not in findings:
                raise FinalReviewError("Required follow-up finding is missing from the ledger")
            dependencies[finding_id] = child
    for start in dependencies:
        seen = set()
        current = start
        while current in dependencies:
            if current in seen:
                raise FinalReviewError("Cyclic follow-up dependencies cannot resolve review work")
            seen.add(current)
            current = dependencies[current]
    return dependencies


def effective_finding_priorities(
    findings: Mapping[str, Any], dispositions: Mapping[str, Any],
) -> dict[str, str]:
    """Preserve inherited urgency, including redirects to existing findings."""
    dependencies = _follow_up_dependencies(findings, dispositions)
    priorities = {key: finding_priority(value) for key, value in findings.items()}
    rank = {"low": 0, "medium": 1, "high": 2}
    for parent in findings:
        child = dependencies.get(parent)
        while child is not None:
            if rank[priorities[parent]] > rank[priorities[child]]:
                priorities[child] = priorities[parent]
            child = dependencies.get(child)
    return priorities


class ReviewDispositionLedger:
    """Validate and persist primary-analyst dispositions incrementally."""

    def __init__(
        self,
        *,
        path: str | Path,
        findings: Iterable[Mapping[str, Any]],
        runtime: Any,
        prior_operation_ids: Iterable[str],
    ):
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise FinalReviewError("Disposition ledger exists; resume it instead of replacing it")
        self.findings = {
            str(row.get("finding_id")): dict(row)
            for row in findings
            if str(row.get("finding_id") or "").strip()
        }
        self.runtime = runtime
        self.prior_operation_ids = {str(value) for value in prior_operation_ids}
        self.dispositions: dict[str, dict[str, Any]] = {}
        self._write()

    @classmethod
    def resume(cls, *, path: str | Path, runtime: Any,
               findings: Iterable[Mapping[str, Any]], prior_operation_ids: Iterable[str],
               allow_legacy: bool = False) -> "ReviewDispositionLedger":
        """Load without reclassifying prior application edits or erasing decisions."""
        saved = json.loads(Path(path).read_text(encoding="utf-8"))
        result = cls.__new__(cls)
        result.path = Path(path).resolve()
        result.runtime = runtime
        result.prior_operation_ids = set(prior_operation_ids)
        if saved.get("prior_operation_ids") is None and not allow_legacy:
            raise FinalReviewError("Disposition ledger lacks its original operation baseline")
        if saved.get("prior_operation_ids") is not None and set(saved["prior_operation_ids"]) != result.prior_operation_ids:
            raise FinalReviewError("Disposition operation baseline changed")
        rows = saved.get("findings") or []
        decisions = saved.get("dispositions") or []
        result.findings = {str(row["finding_id"]): row for row in rows}
        result.dispositions = {str(row["finding_id"]): row for row in decisions}
        expected = {str(row["finding_id"]): dict(row) for row in findings}
        followups = {str(row["follow_up"]["finding_id"]) for row in decisions if row.get("follow_up")}
        if (len(result.findings) != len(rows) or len(result.dispositions) != len(decisions)
                or set(result.findings) != set(expected) | followups
                or set(result.dispositions) - set(result.findings)
                or saved.get("finding_count") != len(rows)
                or saved.get("disposition_count") != len(decisions)
                or set(saved.get("open_finding_ids", [])) != set(result.findings) - set(result.dispositions)):
            raise FinalReviewError("Persisted findings, decisions and plan disagree")
        for key, row in expected.items():
            if result.findings[key].get("source_finding") != row.get("source_finding"):
                raise FinalReviewError("Immutable source finding changed: %s" % key)
            original_ids = {review_target_identity(target) for target in finding_review_targets(row)}
            saved_ids = {review_target_identity(target)
                         for target in finding_review_targets(result.findings[key])}
            # Unstarted findings still carry collection identities. Their wave
            # will bind the exact native callsite before granting edit access.
            # Only an already-persisted enrichment needs comparison here.
            if saved_ids != original_ids:
                bound = bind_application_finding_targets(row, runtime)
                if {review_target_identity(target) for target in finding_review_targets(bound)} != saved_ids:
                    raise FinalReviewError("Saved finding target identity changed: %s" % key)
        for key, row in result.dispositions.items():
            if row.get("finding") != result.findings[key] or row.get("outcome") not in REVIEW_OUTCOMES:
                raise FinalReviewError("Persisted disposition identity changed: %s" % key)
            result._validate_operations(row.get("operation_ids", []),
                                        targets=finding_review_targets(result.findings[key]))
            if not row.get("evidence_refs") or any(runtime.journal.inspection(ref) is None for ref in row["evidence_refs"]):
                raise FinalReviewError("Persisted disposition evidence is missing: %s" % key)
            if row["outcome"] in {"accept_and_apply", "revise_and_apply"} and not row.get("operation_ids"):
                raise FinalReviewError("Applied disposition has no operations: %s" % key)
            if row["outcome"] in {"reject", "defer", "follow_up_required"} and row.get("operation_ids"):
                raise FinalReviewError("Unapplied disposition claims edits: %s" % key)
        # Validate follow-up references/cycles and inherited priorities before use.
        effective_finding_priorities(result.findings, result.dispositions)
        result._write()
        return result

    def _write(self) -> None:
        payload = {
            "schema": "verified_ida.final_review_dispositions.v1",
            "prior_operation_ids": sorted(self.prior_operation_ids),
            "finding_count": len(self.findings),
            "disposition_count": len(self.dispositions),
            "findings": [self.findings[key] for key in sorted(self.findings)],
            "open_finding_ids": sorted(set(self.findings) - set(self.dispositions)),
            "dispositions": [
                self.dispositions[key] for key in sorted(self.dispositions)
            ],
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def _validate_address(self, component_id: str, address: str) -> dict[str, Any]:
        response = self.runtime.inspect(
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
        segment = (
            dict(raw_segment)
            if isinstance(raw_segment, Mapping)
            else ({"name": str(raw_segment)} if raw_segment else {})
        )
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

    def _validate_follow_up(
        self,
        *,
        parent_finding_id: str,
        raw_target: Mapping[str, Any] | None,
        evidence_refs: Iterable[str],
        current_targets: Iterable[Mapping[str, Any]],
        active_wave_finding_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        if not isinstance(raw_target, Mapping):
            raise FinalReviewError(
                "follow_up_required requires one structured follow_up_target"
            )
        component_ids = {
            str(row["component_id"]) for row in self.runtime.journal.components()
        }
        target = canonical_review_target(
            raw_target,
            component_ids=component_ids,
            address_validator=self._validate_address,
        )
        identity = review_target_identity(target)
        current_identities = {
            review_target_identity(row) for row in current_targets
        }
        if identity in current_identities:
            raise FinalReviewError(
                "Follow-up target is already authorized by the current finding"
            )
        evidence = self._validate_evidence(evidence_refs, targets=[target])
        existing_finding_id = None
        for finding_id, finding in self.findings.items():
            if identity in {
                review_target_identity(row)
                for row in finding_review_targets(finding)
            }:
                existing_finding_id = finding_id
                break
        if existing_finding_id is None:
            digest = hashlib.sha256(
                canonical_json([parent_finding_id, list(identity)]).encode("utf-8")
            ).hexdigest()[:24]
            follow_up_finding_id = "application/follow_up:%s" % digest
            self.findings[follow_up_finding_id] = {
                "finding_id": follow_up_finding_id,
                "priority": effective_finding_priorities(
                    self.findings, self.dispositions,
                )[parent_finding_id],
                "component_id": str(target["component_id"]),
                "validated_targets": [target],
                "source_finding": {
                    "source_finding_id": follow_up_finding_id,
                    "source": "application/follow_up",
                    "source_kind": "application_follow_up",
                    "component_id": str(target["component_id"]),
                    "application_eligibility": "candidate",
                    "evidence_refs": [
                        str(row["evidence_id"]) for row in evidence
                    ],
                    "validated_targets": [target],
                    "target_ids": [str(target["target_id"])],
                    "payload": {
                        "finding_id": follow_up_finding_id,
                        "parent_finding_id": parent_finding_id,
                        "classification": "application_follow_up",
                        "component_id": str(target["component_id"]),
                        "targets": [dict(target["target"])],
                    },
                },
            }
            deduplicated = False
        else:
            follow_up_finding_id = existing_finding_id
            deduplicated = True
        _follow_up_dependencies(self.findings, {
            **self.dispositions,
            parent_finding_id: {
                "outcome": "follow_up_required",
                "follow_up": {"finding_id": follow_up_finding_id},
            },
        })
        if follow_up_finding_id in {
            str(value) for value in active_wave_finding_ids
        }:
            raise FinalReviewError(
                "Follow-up target already belongs to a finding in the active wave"
            )
        return {
            "finding_id": follow_up_finding_id,
            "parent_finding_id": parent_finding_id,
            "target": target,
            "evidence_refs": [str(row["evidence_id"]) for row in evidence],
            "deduplicated": deduplicated,
        }

    def _targets_for_finding(self, finding: Mapping[str, Any]) -> list[dict[str, Any]]:
        targets = finding_review_targets(finding)
        if not targets:
            raise FinalReviewError(
                "Review finding has no host-validated artifact targets"
            )
        return targets

    def _validate_evidence(
        self,
        refs: Iterable[str],
        *,
        targets: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        values = list(dict.fromkeys(str(value) for value in refs if str(value)))
        if not values:
            raise FinalReviewError(
                "Every disposition requires current live inspection evidence"
            )
        rows = []
        for evidence_id in values:
            row = self.runtime.journal.inspection(evidence_id)
            if row is None:
                raise FinalReviewError("Unknown evidence reference: %s" % evidence_id)
            current = int(
                self.runtime.journal.revision(str(row["component_id"]))["revision"]
            )
            if int(row["revision"]) != current:
                raise FinalReviewError(
                    "Stale evidence reference %s: revision %s, current %s"
                    % (evidence_id, row["revision"], current)
                )
            rows.append(row)
        target_rows = [dict(row) for row in targets]
        if not any(
            evidence_matches_review_target(evidence, target)
            for evidence in rows
            for target in target_rows
        ):
            raise FinalReviewError(
                "Disposition evidence does not inspect a finding target"
            )
        return rows

    def _validate_operations(
        self,
        operation_ids: Iterable[str],
        *,
        targets: Iterable[Mapping[str, Any]],
    ) -> list[dict[str, Any]]:
        values = list(dict.fromkeys(
            str(value) for value in operation_ids if str(value)
        ))
        rows = []
        allowed_identities = {
            review_target_identity(row) for row in targets
        }
        for operation_id in values:
            if operation_id in self.prior_operation_ids:
                raise FinalReviewError(
                    "Disposition cannot claim a pre-review operation: %s"
                    % operation_id
                )
            detail = self.runtime.journal.operation_detail(operation_id)
            if detail is None:
                raise FinalReviewError("Unknown operation ID: %s" % operation_id)
            receipts = list(detail.get("receipts") or [])
            if not receipts or receipts[-1].get("status") not in {
                "verified", "verified_existing"
            }:
                raise FinalReviewError(
                    "Disposition requires a verified review-stage operation: %s"
                    % operation_id
                )
            if operation_review_target(detail) not in allowed_identities:
                raise FinalReviewError(
                    "Disposition operation %s does not edit a finding target"
                    % operation_id
                )
            rows.append(detail)
        return rows

    def record(
        self,
        *,
        finding_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Iterable[str],
        operation_ids: Iterable[str] = (),
        follow_up_target: Mapping[str, Any] | None = None,
        follow_up_evidence_refs: Iterable[str] = (),
        active_wave_finding_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        finding_key = str(finding_id)
        if finding_key not in self.findings:
            raise FinalReviewError("Unknown review finding: %s" % finding_key)
        if finding_key in self.dispositions:
            raise FinalReviewError("Finding already dispositioned: %s" % finding_key)
        outcome_key = str(outcome)
        if outcome_key not in REVIEW_OUTCOMES:
            raise FinalReviewError("Unsupported review outcome: %s" % outcome_key)
        rationale_text = str(rationale or "").strip()
        if not rationale_text:
            raise FinalReviewError("Disposition rationale is required")
        finding = self.findings[finding_key]
        targets = self._targets_for_finding(finding)
        evidence = self._validate_evidence(evidence_refs, targets=targets)
        operations = self._validate_operations(operation_ids, targets=targets)
        supplied_operation_ids = {
            str(item["operation_id"]) for item in operations
        }
        already_claimed = {
            str(operation_id)
            for disposition in self.dispositions.values()
            for operation_id in disposition.get("operation_ids") or []
        }
        target_identities = {
            review_target_identity(target) for target in targets
        }
        required_current = {
            str(item["operation_id"])
            for item in self.runtime.journal.current_operations()
            if str(item["operation_id"]) not in self.prior_operation_ids
            and str(item["operation_id"]) not in already_claimed
            and operation_review_target(item) in target_identities
            and dict(item.get("receipt") or {}).get("status")
            in VERIFIED_STATUSES
        }
        missing_operations = sorted(
            required_current - supplied_operation_ids
        )
        if missing_operations:
            raise FinalReviewError(
                "Disposition omits current review-stage mutations on this "
                "finding's targets: %s"
                % ", ".join(missing_operations)
            )
        if outcome_key in {"accept_and_apply", "revise_and_apply"} and not operations:
            raise FinalReviewError(
                "%s requires at least one new verified operation" % outcome_key
            )
        if outcome_key in {"reject", "defer"} and operations:
            raise FinalReviewError(
                "%s must not claim an applied correction" % outcome_key
            )
        follow_up = None
        if outcome_key == "follow_up_required":
            if operations:
                raise FinalReviewError(
                    "follow_up_required must not claim an applied correction"
                )
            follow_up = self._validate_follow_up(
                parent_finding_id=finding_key,
                raw_target=follow_up_target,
                evidence_refs=follow_up_evidence_refs,
                current_targets=targets,
                active_wave_finding_ids=active_wave_finding_ids,
            )
        elif follow_up_target is not None or list(follow_up_evidence_refs):
            raise FinalReviewError(
                "Follow-up fields are valid only for follow_up_required"
            )
        row = {
            "finding_id": finding_key,
            "outcome": outcome_key,
            "rationale": rationale_text,
            "evidence_refs": [str(item["evidence_id"]) for item in evidence],
            "operation_ids": [
                str(item["operation_id"]) for item in operations
            ],
            "finding": self.findings[finding_key],
            "follow_up": follow_up,
        }
        self.dispositions[finding_key] = row
        self._write()
        return {
            "schema": "verified_ida.final_review_disposition_result.v1",
            **row,
            "remaining_finding_ids": sorted(
                set(self.findings) - set(self.dispositions)
            ),
            "all_findings_dispositioned": len(self.dispositions) == len(self.findings),
        }

    def follow_up_finding_ids(self) -> list[str]:
        return sorted({
            str(follow_up["finding_id"])
            for disposition in self.dispositions.values()
            for follow_up in [disposition.get("follow_up")]
            if isinstance(follow_up, Mapping)
        })

    def summary(self) -> dict[str, Any]:
        deferred_finding_ids = sorted(
            finding_id
            for finding_id, row in self.dispositions.items()
            if row["outcome"] == "defer"
        )
        priority_by_id = effective_finding_priorities(self.findings, self.dispositions)
        high_priority_deferred_finding_ids = sorted(
            finding_id
            for finding_id in deferred_finding_ids
            if priority_by_id[finding_id] == "high"
        )
        return {
            "finding_count": len(self.findings),
            "disposition_count": len(self.dispositions),
            "open_finding_ids": sorted(set(self.findings) - set(self.dispositions)),
            "deferred_finding_ids": deferred_finding_ids,
            "high_priority_deferred_finding_ids": (
                high_priority_deferred_finding_ids
            ),
            "outcome_counts": {
                outcome: sum(
                    row["outcome"] == outcome
                    for row in self.dispositions.values()
                )
                for outcome in sorted(REVIEW_OUTCOMES)
            },
            "path": str(self.path),
        }
