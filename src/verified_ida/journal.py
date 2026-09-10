"""SQLite-backed operational history for an interactive IDA investigation.

The IDB is authoritative for the current program analysis.  This journal is
authoritative for how the model and host reached that state: inspections,
mutation receipts, persistence checkpoints, component provenance, and frontier
decisions.  It deliberately contains no campaign phases or semantic approval
gate.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from .contracts import VERIFIED_STATUSES, canonical_json, operation_digest, utc_now
from .review_contracts import (
    RECONCILIATION_MAX_FINDINGS,
    RECONCILIATION_MAX_TARGETS_PER_FINDING,
)


SCHEMA_VERSION = 10
SUPPORTED_SCHEMA_VERSIONS = {8, 9, 10}
FRONTIER_OUTCOMES = {"addressed", "nonmaterial", "deferred", "uncertain"}
FRONTIER_LANES = {"must_review", "suggested_next"}
CALL_FLOW_NODE_OUTCOMES = {
    "supports_parent_claim",
    "unresolved_boundary",
    "contradicts_parent_claim",
    "nonmaterial",
    "deferred",
    "uncertain",
}
CALL_FLOW_TERMINAL_OUTCOMES = CALL_FLOW_NODE_OUTCOMES - {"unresolved_boundary"}
CALL_FLOW_PARENT_OUTCOMES = {"confirmed", "revised", "narrowed", "open_uncertainty"}
CALL_FLOW_CODE_EVIDENCE_QUERIES = {
    "inspect_function",
    "retrieve_disassembly",
    "retrieve_pseudocode",
}
RECONCILIATION_FINDING_OUTCOMES = {
    "applied", "rejected", "revised", "deferred",
}


class JournalError(ValueError):
    """Raised when journal history would become ambiguous or contradictory."""


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load(value: str | None, default: Any) -> Any:
    if not value:
        return default
    return json.loads(value)


def stable_id(prefix: str, *parts: Any, length: int = 24) -> str:
    material = "\0".join(canonical_json(part) for part in parts)
    return "%s-%s" % (
        prefix,
        hashlib.sha256(material.encode("utf-8")).hexdigest()[:length],
    )


def operation_surface_identity(
    operation: Mapping[str, Any],
    *,
    component_id: str = "",
) -> tuple[str, str, str, str]:
    """Identify one independently mutable IDA surface.

    IDA stores repeatable and nonrepeatable comments independently. Treating
    both as one surface hides a still-persisted write when the model switches
    slots. Other operations retain their kind-qualified target identity.
    """

    kind = str(operation.get("kind") or "")
    target = dict(operation.get("target") or {})
    target_kind = str(target.get("kind") or "")
    target_key = VerifiedIdaJournal.target_key(target)
    if target_kind == "local_variable":
        target_key = "%s:%s:%s" % (
            target.get("function_address"),
            target.get("lvar_index"),
            canonical_json(target.get("location") or {}),
        )
    if kind in {"function.comment.set", "address.comment.set"}:
        desired = dict(operation.get("desired") or {})
        slot = "repeatable" if desired.get("repeatable") else "nonrepeatable"
        target_key = "%s#comment:%s" % (target_key, slot)
    return str(component_id), kind, target_kind, target_key


class VerifiedIdaJournal:
    """Small durable state store shared by the host tools and run controller."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(str(self.path), timeout=30.0)
        self.connection.row_factory = sqlite3.Row
        try:
            existing_version = self._existing_schema_version()
            if (
                existing_version is not None
                and existing_version not in SUPPORTED_SCHEMA_VERSIONS
            ):
                raise JournalError(
                    "Unsupported journal schema version: %s" % existing_version
                )
            self.connection.execute("PRAGMA foreign_keys = ON")
            self.connection.execute("PRAGMA journal_mode = WAL")
            self.connection.execute("PRAGMA synchronous = FULL")
            self._create_schema(existing_version=existing_version)
        except Exception:
            self.connection.close()
            raise

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "VerifiedIdaJournal":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()

    @contextlib.contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        try:
            self.connection.execute("BEGIN IMMEDIATE")
            yield self.connection
            self.connection.commit()
        except Exception:
            self.connection.rollback()
            raise

    def _existing_schema_version(self) -> int | None:
        metadata_exists = self.connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'metadata'"
        ).fetchone()
        if not metadata_exists:
            return None
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
        if row is None:
            raise JournalError("Journal metadata has no schema_version")
        return int(row["value"])

    def _create_schema(self, *, existing_version: int | None) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS components (
                component_id TEXT PRIMARY KEY,
                parent_component_id TEXT REFERENCES components(component_id),
                depth INTEGER NOT NULL,
                binary_sha256 TEXT NOT NULL,
                binary_path TEXT NOT NULL,
                idb_path TEXT,
                architecture TEXT,
                status TEXT NOT NULL,
                provenance_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS revisions (
                component_id TEXT PRIMARY KEY REFERENCES components(component_id),
                revision INTEGER NOT NULL DEFAULT 0,
                verified_since_checkpoint INTEGER NOT NULL DEFAULT 0,
                last_checkpoint_at TEXT,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS inspections (
                evidence_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                target_kind TEXT NOT NULL,
                target_key TEXT NOT NULL,
                revision INTEGER NOT NULL,
                query_kind TEXT NOT NULL,
                result_digest TEXT NOT NULL,
                result_json TEXT,
                result_path TEXT,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS inspections_target_idx
                ON inspections(component_id, target_kind, target_key, created_at);

            CREATE TABLE IF NOT EXISTS readonly_idapython_requests (
                request_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                revision INTEGER NOT NULL,
                purpose TEXT NOT NULL,
                capability_gap TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                source_text TEXT NOT NULL,
                parameters_json TEXT NOT NULL,
                validation_json TEXT NOT NULL,
                status TEXT NOT NULL,
                result_digest TEXT,
                result_json TEXT,
                error_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS readonly_idapython_component_idx
                ON readonly_idapython_requests(component_id, revision, created_at);

            CREATE TABLE IF NOT EXISTS target_references (
                reference_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                target_kind TEXT NOT NULL,
                target_key TEXT NOT NULL,
                target_json TEXT NOT NULL,
                evidence_id TEXT NOT NULL REFERENCES inspections(evidence_id),
                issued_revision INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                kind TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                target_key TEXT NOT NULL,
                operation_digest TEXT NOT NULL,
                request_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                status TEXT NOT NULL,
                stage TEXT NOT NULL,
                persistence TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS receipts_operation_idx
                ON receipts(operation_id, created_at);

            CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                revision INTEGER NOT NULL,
                idb_sha256 TEXT,
                status TEXT NOT NULL,
                details_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS frontier_candidates (
                candidate_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                target_kind TEXT NOT NULL,
                target_key TEXT NOT NULL,
                gap_kind TEXT NOT NULL,
                lane TEXT NOT NULL,
                priority TEXT NOT NULL,
                tier INTEGER NOT NULL,
                origin TEXT NOT NULL,
                trigger_revision INTEGER NOT NULL,
                operation_id TEXT REFERENCES operations(operation_id),
                reasons_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(component_id, target_kind, target_key, gap_kind)
            );
            CREATE INDEX IF NOT EXISTS frontier_active_idx
                ON frontier_candidates(lane, state, tier, priority, component_id);

            CREATE TABLE IF NOT EXISTS frontier_presentations (
                presentation_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL REFERENCES frontier_candidates(candidate_id),
                batch_id TEXT NOT NULL,
                presented_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS frontier_dispositions (
                disposition_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL REFERENCES frontier_candidates(candidate_id),
                outcome TEXT NOT NULL,
                rationale TEXT NOT NULL,
                evidence_refs_json TEXT NOT NULL,
                operation_ids_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS call_flow_scopes (
                scope_id TEXT PRIMARY KEY,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                root_address TEXT NOT NULL,
                triggering_operation_id TEXT NOT NULL REFERENCES operations(operation_id),
                root_claim_digest TEXT NOT NULL,
                generation INTEGER NOT NULL,
                trigger_revision INTEGER NOT NULL,
                root_function_byte_hash TEXT NOT NULL,
                edge_set_digest TEXT NOT NULL,
                inventory_complete INTEGER NOT NULL,
                state TEXT NOT NULL,
                parent_candidate_id TEXT REFERENCES frontier_candidates(candidate_id),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(component_id, root_address)
            );
            CREATE INDEX IF NOT EXISTS call_flow_scopes_state_idx
                ON call_flow_scopes(state, component_id, root_address);

            CREATE TABLE IF NOT EXISTS call_flow_edges (
                edge_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES call_flow_scopes(scope_id),
                generation INTEGER NOT NULL,
                source_address TEXT NOT NULL,
                callsite_address TEXT NOT NULL,
                destination_address TEXT,
                edge_kind TEXT NOT NULL,
                classification_source TEXT NOT NULL,
                source_function_byte_hash TEXT,
                destination_function_byte_hash TEXT,
                discovery_evidence_id TEXT NOT NULL REFERENCES inspections(evidence_id),
                wave INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(
                    scope_id, generation, source_address, callsite_address,
                    destination_address, edge_kind
                )
            );
            CREATE INDEX IF NOT EXISTS call_flow_edges_scope_idx
                ON call_flow_edges(
                    scope_id, generation, wave, source_address, callsite_address
                );

            CREATE TABLE IF NOT EXISTS call_flow_nodes (
                node_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES call_flow_scopes(scope_id),
                generation INTEGER NOT NULL,
                function_address TEXT NOT NULL,
                admitted_by_edge_id TEXT REFERENCES call_flow_edges(edge_id),
                depth INTEGER NOT NULL,
                wave INTEGER NOT NULL,
                state TEXT NOT NULL,
                expanded INTEGER NOT NULL DEFAULT 0,
                function_byte_hash TEXT,
                edge_set_digest TEXT,
                frontier_candidate_id TEXT REFERENCES frontier_candidates(candidate_id),
                evidence_refs_json TEXT NOT NULL,
                rationale TEXT NOT NULL,
                boundary_question TEXT NOT NULL DEFAULT '',
                claim_impact TEXT NOT NULL DEFAULT '',
                evidence_gap TEXT NOT NULL DEFAULT '',
                expected_evidence TEXT NOT NULL DEFAULT '',
                boundary_callees_json TEXT NOT NULL DEFAULT '[]',
                resolution TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(scope_id, generation, function_address)
            );
            CREATE INDEX IF NOT EXISTS call_flow_nodes_state_idx
                ON call_flow_nodes(
                    scope_id, generation, state, wave, depth, function_address
                );

            CREATE TABLE IF NOT EXISTS call_flow_parent_reviews (
                review_id TEXT PRIMARY KEY,
                scope_id TEXT NOT NULL REFERENCES call_flow_scopes(scope_id),
                generation INTEGER NOT NULL,
                outcome TEXT NOT NULL,
                rationale TEXT NOT NULL,
                parent_evidence_id TEXT NOT NULL REFERENCES inspections(evidence_id),
                operation_ids_json TEXT NOT NULL,
                resulting_claim_digest TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS call_flow_parent_reviews_scope_idx
                ON call_flow_parent_reviews(scope_id, generation, created_at);

            CREATE TABLE IF NOT EXISTS reconciliation_rounds (
                round_id TEXT PRIMARY KEY,
                semantic_digest TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                state TEXT NOT NULL,
                review_path TEXT,
                report_digest TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS reconciliation_rounds_state_idx
                ON reconciliation_rounds(state, created_at);

            CREATE TABLE IF NOT EXISTS reconciliation_findings (
                finding_id TEXT PRIMARY KEY,
                round_id TEXT NOT NULL REFERENCES reconciliation_rounds(round_id),
                source_finding_id TEXT NOT NULL,
                parent_gap_id TEXT,
                classification TEXT NOT NULL,
                priority TEXT NOT NULL,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                wave INTEGER NOT NULL,
                title TEXT NOT NULL,
                current_claim TEXT NOT NULL,
                evidence_summary TEXT NOT NULL,
                consequence TEXT NOT NULL,
                recommended_verification TEXT NOT NULL,
                targets_json TEXT NOT NULL,
                review_evidence_refs_json TEXT NOT NULL,
                state TEXT NOT NULL,
                rationale TEXT NOT NULL DEFAULT '',
                resolution_evidence_refs_json TEXT NOT NULL DEFAULT '[]',
                operation_ids_json TEXT NOT NULL DEFAULT '[]',
                call_flow_scope_id TEXT REFERENCES call_flow_scopes(scope_id),
                revision_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(round_id, source_finding_id)
            );
            CREATE INDEX IF NOT EXISTS reconciliation_findings_state_idx
                ON reconciliation_findings(round_id, state, wave, priority);

            CREATE TABLE IF NOT EXISTS reconciliation_activity (
                activity_id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL REFERENCES reconciliation_findings(finding_id),
                activity_kind TEXT NOT NULL,
                external_id TEXT NOT NULL,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                target_kind TEXT NOT NULL,
                target_key TEXT NOT NULL,
                status TEXT NOT NULL,
                provenance TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(finding_id, activity_kind, external_id)
            );
            CREATE INDEX IF NOT EXISTS reconciliation_activity_finding_idx
                ON reconciliation_activity(finding_id, created_at, activity_id);

            CREATE TABLE IF NOT EXISTS reconciliation_audits (
                audit_id TEXT PRIMARY KEY,
                round_id TEXT NOT NULL UNIQUE REFERENCES reconciliation_rounds(round_id),
                finding_set_digest TEXT NOT NULL,
                completion_digest TEXT NOT NULL,
                checkpoint_json TEXT NOT NULL,
                details_json TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS run_attempts (
                attempt_id TEXT PRIMARY KEY,
                segment_id TEXT NOT NULL UNIQUE,
                phase TEXT NOT NULL,
                status TEXT NOT NULL,
                active_round_id TEXT,
                active_finding_id TEXT,
                active_wave INTEGER,
                last_event_kind TEXT,
                last_response_id TEXT,
                last_tool TEXT,
                error_json TEXT NOT NULL DEFAULT '{}',
                started_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                ended_at TEXT
            );
            CREATE INDEX IF NOT EXISTS run_attempts_status_idx
                ON run_attempts(status, heartbeat_at);

            CREATE TABLE IF NOT EXISTS operation_resolutions (
                operation_id TEXT PRIMARY KEY REFERENCES operations(operation_id),
                outcome TEXT NOT NULL,
                rationale TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS extractions (
                extraction_id TEXT PRIMARY KEY,
                parent_component_id TEXT NOT NULL REFERENCES components(component_id),
                child_component_id TEXT REFERENCES components(component_id),
                request_json TEXT NOT NULL,
                status TEXT NOT NULL,
                artifact_sha256 TEXT,
                artifact_path TEXT,
                validation_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notebook_updates (
                update_id TEXT PRIMARY KEY,
                action TEXT NOT NULL,
                section TEXT NOT NULL,
                before_digest TEXT NOT NULL,
                after_digest TEXT NOT NULL,
                component_id TEXT NOT NULL REFERENCES components(component_id),
                revision INTEGER NOT NULL,
                tool_result_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS notebook_updates_created_idx
                ON notebook_updates(created_at, update_id);

            CREATE TABLE IF NOT EXISTS closure_reviews (
                review_id TEXT PRIMARY KEY,
                epoch INTEGER NOT NULL UNIQUE,
                active_component_id TEXT NOT NULL REFERENCES components(component_id),
                operation_cutoff_rowid INTEGER NOT NULL,
                objective_digest TEXT NOT NULL,
                notebook_digest TEXT NOT NULL,
                closure_section_digest TEXT NOT NULL,
                component_revisions_json TEXT NOT NULL,
                packet_digest TEXT NOT NULL,
                packet_path TEXT NOT NULL,
                candidate_count INTEGER NOT NULL,
                closure_update_id TEXT REFERENCES notebook_updates(update_id),
                closure_update_digest TEXT,
                created_at TEXT NOT NULL,
                closure_updated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS closure_reviews_created_idx
                ON closure_reviews(epoch, created_at);

            CREATE TABLE IF NOT EXISTS notebook_reminder_state (
                singleton_id INTEGER PRIMARY KEY CHECK(singleton_id = 1),
                outstanding INTEGER NOT NULL DEFAULT 0,
                material_count INTEGER NOT NULL DEFAULT 0,
                reasons_json TEXT NOT NULL DEFAULT '[]',
                components_json TEXT NOT NULL DEFAULT '[]',
                first_triggered_at TEXT,
                last_triggered_at TEXT,
                last_cleared_at TEXT,
                last_update_id TEXT REFERENCES notebook_updates(update_id),
                updated_at TEXT NOT NULL
            );
            """
        )
        if existing_version is None:
            self.connection.execute(
                "INSERT INTO metadata(key, value) VALUES('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )
        elif existing_version < SCHEMA_VERSION:
            self.connection.execute(
                "UPDATE metadata SET value = ? WHERE key = 'schema_version'",
                (str(SCHEMA_VERSION),),
            )
        now = utc_now()
        self.connection.execute(
            """
            INSERT INTO notebook_reminder_state(
                singleton_id, outstanding, material_count, reasons_json,
                components_json, updated_at
            ) VALUES(1, 0, 0, '[]', '[]', ?)
            ON CONFLICT(singleton_id) DO NOTHING
            """,
            (now,),
        )
        self.connection.commit()

    def register_component(
        self,
        *,
        component_id: str,
        binary_sha256: str,
        binary_path: str | Path,
        idb_path: str | Path | None,
        parent_component_id: str | None = None,
        architecture: str | None = None,
        status: str = "analysis_ready",
        provenance: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        parent = None
        depth = 0
        if parent_component_id:
            parent = self.component(parent_component_id)
            if parent is None:
                raise JournalError("Unknown parent component: %s" % parent_component_id)
            depth = int(parent["depth"]) + 1
        existing = self.component(component_id)
        if existing and existing["binary_sha256"] != binary_sha256.lower():
            raise JournalError("component_id was reused for different bytes")
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO components(
                    component_id, parent_component_id, depth, binary_sha256,
                    binary_path, idb_path, architecture, status,
                    provenance_json, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(component_id) DO UPDATE SET
                    idb_path = excluded.idb_path,
                    architecture = COALESCE(excluded.architecture, components.architecture),
                    status = excluded.status,
                    provenance_json = excluded.provenance_json,
                    updated_at = excluded.updated_at
                """,
                (
                    component_id,
                    parent_component_id,
                    depth,
                    binary_sha256.lower(),
                    str(Path(binary_path).resolve()),
                    str(Path(idb_path).resolve()) if idb_path else None,
                    architecture,
                    status,
                    _json(dict(provenance or {})),
                    existing["created_at"] if existing else now,
                    now,
                ),
            )
            connection.execute(
                """
                INSERT INTO revisions(
                    component_id, revision, verified_since_checkpoint,
                    last_checkpoint_at, updated_at
                ) VALUES(?, 0, 0, NULL, ?)
                ON CONFLICT(component_id) DO NOTHING
                """,
                (component_id, now),
            )
        return self.component(component_id) or {}

    @staticmethod
    def _component_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["provenance"] = _load(result.pop("provenance_json"), {})
        return result

    def component(self, component_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM components WHERE component_id = ?", (component_id,)
        ).fetchone()
        return self._component_row(row) if row else None

    def components(self) -> list[dict[str, Any]]:
        return [
            self._component_row(row)
            for row in self.connection.execute(
                "SELECT * FROM components ORDER BY depth, component_id"
            )
        ]

    def project_objective(self) -> str | None:
        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'project_objective'"
        ).fetchone()
        return str(row["value"]) if row else None

    def bind_project_objective(self, objective: str | None) -> str:
        """Persist the initial objective; resumes keep the original wording."""

        supplied = str(objective or "").strip()
        existing = self.project_objective()
        if existing is not None:
            return existing
        if not supplied:
            raise JournalError("A new Verified IDA project requires an objective")
        self.connection.execute(
            "INSERT INTO metadata(key, value) VALUES('project_objective', ?)",
            (supplied,),
        )
        self.connection.commit()
        return supplied

    def bind_coverage_reconciliation(self, enabled: bool | None) -> bool:
        """Persist the experimental completion policy across resumed sessions."""

        row = self.connection.execute(
            "SELECT value FROM metadata WHERE key = 'coverage_reconciliation'"
        ).fetchone()
        if row is not None:
            existing = str(row["value"]) == "1"
            if enabled is True and not existing:
                rounds = int(self.connection.execute(
                    "SELECT COUNT(*) AS count FROM reconciliation_rounds"
                ).fetchone()["count"])
                if rounds:
                    raise JournalError(
                        "Coverage-reconciliation policy cannot change after a round"
                    )
                self.connection.execute(
                    "UPDATE metadata SET value = '1' "
                    "WHERE key = 'coverage_reconciliation'"
                )
                self.connection.commit()
                return True
            if enabled is False and existing:
                raise JournalError(
                    "Coverage reconciliation cannot be disabled after it is enabled"
                )
            return existing
        selected = bool(enabled)
        self.connection.execute(
            "INSERT INTO metadata(key, value) VALUES('coverage_reconciliation', ?)",
            ("1" if selected else "0",),
        )
        self.connection.commit()
        return selected

    def record_notebook_update(
        self,
        *,
        action: str,
        section: str,
        before_digest: str,
        after_digest: str,
        component_id: str,
        revision: int,
        tool_result: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Record notebook operation metadata without copying analytical prose."""

        if action not in {"section_update", "journal_append"}:
            raise JournalError("Unsupported notebook action: %s" % action)
        if self.component(component_id) is None:
            raise JournalError("Unknown notebook component: %s" % component_id)
        now = utc_now()
        metadata_keys = {
            "status", "action", "path", "section", "entry_id",
            "before_digest", "after_digest", "document_before_digest",
            "document_after_digest", "content_digest", "content_utf8_bytes",
        }
        compact_result = {
            key: value for key, value in dict(tool_result).items()
            if key in metadata_keys
        }
        update_id = stable_id(
            "notebook",
            action,
            section,
            before_digest,
            after_digest,
            component_id,
            int(revision),
            now,
        )
        self.connection.execute(
            """
            INSERT INTO notebook_updates(
                update_id, action, section, before_digest, after_digest,
                component_id, revision, tool_result_json, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                update_id,
                action,
                section,
                before_digest,
                after_digest,
                component_id,
                int(revision),
                _json(compact_result),
                now,
            ),
        )
        self.connection.commit()
        return self.notebook_update(update_id) or {}

    @staticmethod
    def _notebook_update_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["tool_result"] = _load(result.pop("tool_result_json"), {})
        return result

    def notebook_update(self, update_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM notebook_updates WHERE update_id = ?",
            (update_id,),
        ).fetchone()
        return self._notebook_update_row(row) if row else None

    def notebook_updates(self, *, limit: int = 100) -> list[dict[str, Any]]:
        bounded = max(1, min(int(limit), 1000))
        return [
            self._notebook_update_row(row)
            for row in self.connection.execute(
                """
                SELECT * FROM notebook_updates
                ORDER BY rowid LIMIT ?
                """,
                (bounded,),
            )
        ]

    def notebook_reminder_state(self) -> dict[str, Any]:
        """Return project-level transport state for the bounded notebook nudge."""

        row = self.connection.execute(
            "SELECT * FROM notebook_reminder_state WHERE singleton_id = 1"
        ).fetchone()
        if row is None:
            raise JournalError("Notebook reminder state is missing")
        result = dict(row)
        result["outstanding"] = bool(result["outstanding"])
        result["reasons"] = _load(result.pop("reasons_json"), [])
        result["components"] = _load(result.pop("components_json"), [])
        return result

    def note_notebook_material_event(
        self,
        *,
        event_kind: str,
        component_id: str,
        immediate: bool = False,
        threshold: int = 3,
    ) -> dict[str, Any] | None:
        """Issue at most one advisory reminder until current state is updated."""

        if self.component(component_id) is None:
            raise JournalError("Unknown reminder component: %s" % component_id)
        event_kind = str(event_kind or "").strip()
        if not event_kind:
            raise JournalError("Notebook reminder event_kind is required")
        bounded_threshold = max(1, int(threshold))
        now = utc_now()
        with self.transaction() as connection:
            row = connection.execute(
                "SELECT * FROM notebook_reminder_state WHERE singleton_id = 1"
            ).fetchone()
            if row is None:
                raise JournalError("Notebook reminder state is missing")
            reasons = list(dict.fromkeys([
                *_load(row["reasons_json"], []),
                event_kind,
            ]))[-6:]
            components = list(dict.fromkeys([
                *_load(row["components_json"], []),
                component_id,
            ]))[-6:]
            count = int(row["material_count"]) + 1
            already_outstanding = bool(row["outstanding"])
            should_issue = not already_outstanding and (
                bool(immediate) or count >= bounded_threshold
            )
            connection.execute(
                """
                UPDATE notebook_reminder_state
                SET outstanding = ?, material_count = ?, reasons_json = ?,
                    components_json = ?, first_triggered_at = ?,
                    last_triggered_at = ?, updated_at = ?
                WHERE singleton_id = 1
                """,
                (
                    int(already_outstanding or should_issue),
                    count,
                    _json(reasons),
                    _json(components),
                    row["first_triggered_at"] or (now if should_issue else None),
                    now,
                    now,
                ),
            )
        if not should_issue:
            return None
        state = self.notebook_reminder_state()
        return {
            "status": "advisory",
            "blocking": False,
            "outstanding": True,
            "reasons": state["reasons"],
            "components": state["components"],
            "message": (
                "Material project state changed. Update the relevant Current "
                "Project State section in reversing_log.md after reconciling "
                "this change with live IDA state. Append journal history only "
                "when the analytical revision is important to preserve."
            ),
        }

    def clear_notebook_reminder(self, *, update_id: str) -> dict[str, Any]:
        """A successful Current Project State update acknowledges the reminder."""

        update = self.notebook_update(update_id)
        if update is None or update["action"] != "section_update":
            raise JournalError(
                "Only a recorded Current Project State update clears the reminder"
            )
        now = utc_now()
        self.connection.execute(
            """
            UPDATE notebook_reminder_state
            SET outstanding = 0, material_count = 0, reasons_json = '[]',
                components_json = '[]', first_triggered_at = NULL,
                last_cleared_at = ?, last_update_id = ?, updated_at = ?
            WHERE singleton_id = 1
            """,
            (now, update_id, now),
        )
        self.connection.commit()
        return self.notebook_reminder_state()

    def set_component_status(
        self,
        component_id: str,
        status: str,
        *,
        idb_path: str | Path | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        fields = ["status = ?", "updated_at = ?"]
        values: list[Any] = [str(status), now]
        if idb_path is not None:
            fields.append("idb_path = ?")
            values.append(str(Path(idb_path).resolve()))
        values.append(component_id)
        cursor = self.connection.execute(
            "UPDATE components SET %s WHERE component_id = ?" % ", ".join(fields),
            values,
        )
        self.connection.commit()
        if cursor.rowcount != 1:
            raise JournalError("Unknown component: %s" % component_id)
        return self.component(component_id) or {}

    def has_verified_target(self, component_id: str, target_key: str) -> bool:
        row = self.connection.execute(
            """
            SELECT 1
            FROM operations o
            JOIN receipts r ON r.operation_id = o.operation_id
            WHERE o.component_id = ? AND o.target_key = ?
              AND r.status IN ('verified', 'verified_existing')
            LIMIT 1
            """,
            (component_id, target_key),
        ).fetchone()
        return row is not None

    def revision(self, component_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM revisions WHERE component_id = ?", (component_id,)
        ).fetchone()
        if row is None:
            raise JournalError("Unknown component revision: %s" % component_id)
        return dict(row)

    @staticmethod
    def _advance_revision_in_transaction(
        connection: sqlite3.Connection,
        component_id: str,
        *,
        verified: bool,
        now: str,
    ) -> dict[str, Any]:
        cursor = connection.execute(
            """
            UPDATE revisions SET
                revision = revision + 1,
                verified_since_checkpoint = verified_since_checkpoint + ?,
                updated_at = ?
            WHERE component_id = ?
            """,
            (1 if verified else 0, now, component_id),
        )
        if cursor.rowcount != 1:
            raise JournalError("Unknown component revision: %s" % component_id)
        row = connection.execute(
            "SELECT * FROM revisions WHERE component_id = ?", (component_id,)
        ).fetchone()
        if row is None:
            raise JournalError("Unknown component revision: %s" % component_id)
        return dict(row)

    def advance_revision(self, component_id: str, *, verified: bool) -> dict[str, Any]:
        now = utc_now()
        with self.transaction() as connection:
            return self._advance_revision_in_transaction(
                connection, component_id, verified=verified, now=now
            )

    def record_inspection(
        self,
        *,
        component_id: str,
        target_kind: str,
        target_key: str,
        query_kind: str,
        result: Any,
        result_path: str | Path | None = None,
        revision: int | None = None,
    ) -> dict[str, Any]:
        current_revision = (
            int(revision)
            if revision is not None
            else int(self.revision(component_id)["revision"])
        )
        digest = hashlib.sha256(canonical_json(result).encode("utf-8")).hexdigest()
        now = utc_now()
        evidence_id = stable_id(
            "evidence",
            component_id,
            target_kind,
            target_key,
            query_kind,
            current_revision,
            digest,
            now,
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO inspections(
                    evidence_id, component_id, target_kind, target_key, revision,
                    query_kind, result_digest, result_json, result_path, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence_id,
                    component_id,
                    target_kind,
                    target_key,
                    current_revision,
                    query_kind,
                    digest,
                    canonical_json(result),
                    str(result_path) if result_path else None,
                    now,
                ),
            )
            finding = self.active_reconciliation_finding()
            if finding is not None and query_kind != "notebook.read":
                self._record_reconciliation_activity_in_transaction(
                    connection,
                    finding_id=str(finding["finding_id"]),
                    activity_kind="inspection",
                    external_id=evidence_id,
                    component_id=component_id,
                    target_kind=target_kind,
                    target_key=target_key,
                    status="recorded",
                    provenance="host_active_wave",
                    now=now,
                )
        recorded = dict(
            self.connection.execute(
                "SELECT * FROM inspections WHERE evidence_id = ?", (evidence_id,)
            ).fetchone()
        )
        return recorded

    def inspection(self, evidence_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM inspections WHERE evidence_id = ?", (evidence_id,)
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["result"] = _load(result.pop("result_json"), None)
        return result

    def inspection_count(self) -> int:
        row = self.connection.execute(
            "SELECT COUNT(*) AS count FROM inspections"
        ).fetchone()
        return int(row["count"] if row is not None else 0)

    @staticmethod
    def _readonly_idapython_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["parameters"] = _load(result.pop("parameters_json"), {})
        result["validation"] = _load(result.pop("validation_json"), {})
        result["result"] = _load(result.pop("result_json"), None)
        result["error"] = _load(result.pop("error_json"), None)
        return result

    def record_readonly_idapython(
        self,
        *,
        request_id: str,
        component_id: str,
        revision: int,
        purpose: str,
        capability_gap: str,
        source: str,
        parameters: Mapping[str, Any],
        validation: Mapping[str, Any] | None,
        status: str,
        result: Any = None,
        error: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Journal one capability-gap script from request through completion."""

        allowed_statuses = {"rejected", "validated", "completed", "failed"}
        if status not in allowed_statuses:
            raise JournalError("Unsupported read-only IDAPython status: %s" % status)
        purpose_text = str(purpose or "").strip()
        gap_text = str(capability_gap or "").strip()
        if not purpose_text or not gap_text:
            raise JournalError(
                "Read-only IDAPython requires a purpose and capability gap"
            )
        source_text = str(source)
        source_sha256 = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        existing = self.connection.execute(
            "SELECT * FROM readonly_idapython_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        if existing:
            if (
                existing["component_id"] != component_id
                or int(existing["revision"]) != int(revision)
                or existing["source_sha256"] != source_sha256
            ):
                raise JournalError(
                    "read-only IDAPython request_id was reused for different content"
                )
        now = utc_now()
        result_text = canonical_json(result) if result is not None else None
        result_digest = (
            hashlib.sha256(result_text.encode("utf-8")).hexdigest()
            if result_text is not None
            else None
        )
        self.connection.execute(
            """
            INSERT INTO readonly_idapython_requests(
                request_id, component_id, revision, purpose, capability_gap,
                source_sha256, source_text, parameters_json, validation_json,
                status, result_digest, result_json, error_json, created_at,
                completed_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(request_id) DO UPDATE SET
                validation_json = excluded.validation_json,
                status = excluded.status,
                result_digest = excluded.result_digest,
                result_json = excluded.result_json,
                error_json = excluded.error_json,
                completed_at = excluded.completed_at
            """,
            (
                request_id,
                component_id,
                int(revision),
                purpose_text,
                gap_text,
                source_sha256,
                source_text,
                canonical_json(dict(parameters)),
                canonical_json(dict(validation or {})),
                status,
                result_digest,
                result_text,
                canonical_json(dict(error or {})),
                existing["created_at"] if existing else now,
                now if status in {"rejected", "completed", "failed"} else None,
            ),
        )
        self.connection.commit()
        return self.readonly_idapython_request(request_id) or {}

    def readonly_idapython_request(self, request_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM readonly_idapython_requests WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        return self._readonly_idapython_row(row) if row else None

    def readonly_idapython_requests(
        self, component_id: str | None = None
    ) -> list[dict[str, Any]]:
        if component_id:
            rows = self.connection.execute(
                "SELECT * FROM readonly_idapython_requests "
                "WHERE component_id = ? ORDER BY created_at, request_id",
                (component_id,),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM readonly_idapython_requests "
                "ORDER BY created_at, request_id"
            ).fetchall()
        return [self._readonly_idapython_row(row) for row in rows]

    def issue_reference(
        self,
        *,
        component_id: str,
        target: Mapping[str, Any],
        evidence_id: str,
    ) -> dict[str, Any]:
        """Bind a model-facing opaque reference to inspected live anchors."""

        evidence = self.inspection(evidence_id)
        if evidence is None or evidence["component_id"] != component_id:
            raise JournalError("Target references require matching inspection evidence")
        target_value = dict(target)
        target_kind = str(target_value.get("kind") or "")
        target_key = self.target_key(target_value)
        if not target_kind or not target_key:
            raise JournalError("Target reference identity is incomplete")
        revision = int(self.revision(component_id)["revision"])
        if int(evidence["revision"]) != revision:
            raise JournalError("Target references require current-revision inspection evidence")
        reference_id = stable_id(
            "ref", component_id, target_kind, target_key, evidence_id, target_value
        )
        now = utc_now()
        self.connection.execute(
            """
            INSERT OR IGNORE INTO target_references(
                reference_id, component_id, target_kind, target_key,
                target_json, evidence_id, issued_revision, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                reference_id,
                component_id,
                target_kind,
                target_key,
                canonical_json(target_value),
                evidence_id,
                revision,
                now,
            ),
        )
        self.connection.commit()
        return self.reference(reference_id) or {}

    def reference(self, reference_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM target_references WHERE reference_id = ?",
            (reference_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["target"] = _load(result.pop("target_json"), {})
        return result

    def record_operation(
        self,
        *,
        component_id: str,
        operation: Mapping[str, Any],
        receipt: Mapping[str, Any],
        advance_revision: bool = False,
    ) -> dict[str, Any] | None:
        operation_id = str(operation.get("operation_id") or "")
        receipt_id = str(receipt.get("receipt_id") or "")
        if not operation_id or not receipt_id:
            raise JournalError("Operation and receipt identities are required")
        target = dict(operation.get("target") or {})
        target_kind = str(target.get("kind") or "")
        target_key = self.target_key(target)
        request_text = canonical_json(operation)
        request_digest = operation_digest(operation)
        now = utc_now()
        revision: dict[str, Any] | None = None
        with self.transaction() as connection:
            prior = connection.execute(
                "SELECT operation_digest FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
            if prior and prior["operation_digest"] != request_digest:
                raise JournalError("operation_id was reused for different content")
            connection.execute(
                """
                INSERT OR IGNORE INTO operations(
                    operation_id, component_id, kind, target_kind, target_key,
                    operation_digest, request_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    operation_id,
                    component_id,
                    operation.get("kind"),
                    target_kind,
                    target_key,
                    request_digest,
                    request_text,
                    now,
                ),
            )
            prior_receipt = connection.execute(
                "SELECT receipt_json FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            receipt_text = canonical_json(receipt)
            if prior_receipt and prior_receipt["receipt_json"] != receipt_text:
                raise JournalError("receipt_id was reused for different content")
            connection.execute(
                """
                INSERT OR IGNORE INTO receipts(
                    receipt_id, operation_id, status, stage, persistence,
                    receipt_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    operation_id,
                    receipt.get("status"),
                    receipt.get("stage"),
                    receipt.get("persistence") or "not_checked",
                    receipt_text,
                    now,
                ),
            )
            connection.execute(
                "DELETE FROM operation_resolutions WHERE operation_id = ?",
                (operation_id,),
            )
            finding = self.active_reconciliation_finding()
            work_item_id = str(operation.get("work_item_id") or "")
            if finding is not None and work_item_id == str(finding["finding_id"]):
                self._record_reconciliation_activity_in_transaction(
                    connection,
                    finding_id=work_item_id,
                    activity_kind="operation",
                    external_id=operation_id,
                    component_id=component_id,
                    target_kind=target_kind,
                    target_key=target_key,
                    status=str(receipt.get("status") or "unknown"),
                    provenance="host_active_wave",
                    now=now,
                )
            if advance_revision:
                revision = self._advance_revision_in_transaction(
                    connection,
                    component_id,
                    verified=True,
                    now=now,
                )
        return revision

    def operation_detail(self, operation_id: str) -> dict[str, Any] | None:
        operation = self.connection.execute(
            "SELECT * FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if operation is None:
            return None
        receipts = self.connection.execute(
            """
            SELECT receipt_json FROM receipts
            WHERE operation_id = ? ORDER BY rowid
            """,
            (operation_id,),
        ).fetchall()
        resolution = self.connection.execute(
            "SELECT * FROM operation_resolutions WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        row = dict(operation)
        row["request"] = _load(row.pop("request_json"), {})
        row["receipts"] = [
            _load(receipt["receipt_json"], {}) for receipt in receipts
        ]
        row["resolution"] = dict(resolution) if resolution else None
        return row

    @staticmethod
    def target_key(target: Mapping[str, Any]) -> str:
        kind = str(target.get("kind") or "")
        if kind == "relationship":
            return "%s@%s->%s:%s" % (
                target.get("source_address"),
                target.get("callsite_address") or "legacy",
                target.get("destination_address"),
                target.get("relationship_kind"),
            )
        if kind == "local_variable":
            return "%s:%s:%s" % (
                target.get("function_address"),
                target.get("lvar_index"),
                target.get("current_name"),
            )
        if kind == "named_type":
            return str(target.get("name") or target.get("current_name") or "")
        return str(
            target.get("address")
            or target.get("function_address")
            or target.get("name")
            or ""
        )

    def mechanical_issues(self, component_id: str | None = None) -> list[dict[str, Any]]:
        results = []
        for item in self.current_operations():
            if component_id and item["component_id"] != component_id:
                continue
            receipt = dict(item.get("receipt") or {})
            if (
                receipt.get("status") in VERIFIED_STATUSES
                and receipt.get("persistence") != "failed"
            ):
                continue
            if item.get("resolution_outcome") == "abandoned":
                continue
            results.append({
                **item,
                "receipt_id": receipt.get("receipt_id"),
                "status": receipt.get("status"),
                "stage": receipt.get("stage"),
                "persistence": receipt.get("persistence"),
            })
        return results

    def pending_persistence_operations(self, component_id: str) -> list[dict[str, Any]]:
        """Return verified operations whose newest receipt is not persistence-verified."""

        return [
            {
                "operation": row["request"],
                "receipt": row["receipt"],
            }
            for row in self.current_operations()
            if row["component_id"] == component_id
            and dict(row.get("receipt") or {}).get("status")
            in VERIFIED_STATUSES
            and dict(row.get("receipt") or {}).get("persistence")
            != "verified"
        ]

    def record_checkpoint(
        self,
        *,
        component_id: str,
        revision: int,
        status: str,
        details: Mapping[str, Any],
        idb_sha256: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        checkpoint_id = stable_id(
            "checkpoint", component_id, revision, status, details, now
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT INTO checkpoints(
                    checkpoint_id, component_id, revision, idb_sha256,
                    status, details_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    checkpoint_id,
                    component_id,
                    revision,
                    idb_sha256,
                    status,
                    _json(dict(details)),
                    now,
                ),
            )
            if status == "verified":
                connection.execute(
                    """
                    UPDATE revisions SET verified_since_checkpoint = 0,
                        last_checkpoint_at = ?, updated_at = ?
                    WHERE component_id = ?
                    """,
                    (now, now, component_id),
                )
        return {
            "checkpoint_id": checkpoint_id,
            "component_id": component_id,
            "revision": revision,
            "status": status,
            "idb_sha256": idb_sha256,
            "details": dict(details),
            "created_at": now,
        }

    def latest_checkpoint(self, component_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM checkpoints WHERE component_id = ? ORDER BY rowid DESC LIMIT 1",
            (component_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _load(result.pop("details_json"), {})
        return result

    def latest_verified_checkpoint(
        self, component_id: str, *, revision: int | None = None
    ) -> dict[str, Any] | None:
        parameters: list[Any] = [component_id]
        revision_clause = ""
        if revision is not None:
            revision_clause = "AND revision = ?"
            parameters.append(int(revision))
        row = self.connection.execute(
            "SELECT * FROM checkpoints WHERE component_id = ? "
            "AND status = 'verified' %s ORDER BY rowid DESC LIMIT 1"
            % revision_clause,
            parameters,
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["details"] = _load(result.pop("details_json"), {})
        return result

    def unresolved_semantic_drift(self, component_id: str) -> list[dict[str, Any]]:
        """A later failed check cannot hide drift; only verification clears it."""
        rows = self.connection.execute(
            "SELECT details_json FROM checkpoints WHERE component_id = ? AND rowid > "
            "COALESCE((SELECT MAX(rowid) FROM checkpoints WHERE component_id = ? "
            "AND status = 'verified'), 0)", (component_id, component_id),
        ).fetchall()
        codes = {"semantic_state_changed_without_revision", "semantic_state_changed_across_export_migration",
                 "semantic_export_migration_unverifiable", "unresolved_semantic_drift"}
        return [error for row in rows for error in _load(row[0], {}).get("errors", [])
                if error.get("code") in codes]

    def semantic_local_functions(self, component_id: str) -> list[str]:
        """Return functions whose local state was deliberately changed by this run."""

        rows = self.connection.execute(
            """
            SELECT request_json FROM operations
            WHERE component_id = ? AND kind IN ('local.rename', 'local.type.set')
            ORDER BY created_at, operation_id
            """,
            (component_id,),
        ).fetchall()
        addresses = set()
        for row in rows:
            operation = _load(row["request_json"], {})
            address = (operation.get("target") or {}).get("function_address")
            if address not in (None, ""):
                try:
                    addresses.add(hex(int(str(address), 0)))
                except (TypeError, ValueError):
                    continue
        return sorted(addresses, key=lambda value: int(value, 0))

    def semantic_global_addresses(self, component_id: str) -> list[str]:
        """Return globals whose durable state was deliberately changed by this run."""

        rows = self.connection.execute(
            """
            SELECT request_json FROM operations
            WHERE component_id = ? AND kind IN ('global.rename', 'global.type.set')
            ORDER BY created_at, operation_id
            """,
            (component_id,),
        ).fetchall()
        addresses = set()
        for row in rows:
            operation = _load(row["request_json"], {})
            address = (operation.get("target") or {}).get("address")
            if address not in (None, ""):
                try:
                    addresses.add(hex(int(str(address), 0)))
                except (TypeError, ValueError):
                    continue
        return sorted(addresses, key=lambda value: int(value, 0))

    def upsert_candidate(self, candidate: Mapping[str, Any]) -> dict[str, Any]:
        component_id = str(candidate.get("component_id") or "")
        target_kind = str(candidate.get("target_kind") or "")
        target_key = str(candidate.get("target_key") or "")
        gap_kind = str(candidate.get("gap_kind") or "")
        if not all((component_id, target_kind, target_key, gap_kind)):
            raise JournalError("Frontier candidate identity is incomplete")
        candidate_id = str(candidate.get("candidate_id") or stable_id(
            "candidate", component_id, target_kind, target_key, gap_kind
        ))
        priority = str(candidate.get("priority") or "medium")
        if priority not in {"critical", "high", "medium", "low"}:
            raise JournalError("Unsupported frontier priority: %s" % priority)
        requested_lane = str(candidate.get("lane") or "suggested_next")
        if requested_lane not in FRONTIER_LANES:
            raise JournalError("Unsupported frontier lane: %s" % requested_lane)
        lane = requested_lane
        trigger_revision = int(
            candidate.get("trigger_revision")
            if candidate.get("trigger_revision") is not None
            else self.revision(component_id)["revision"]
        )
        operation_id = candidate.get("operation_id")
        now = utc_now()
        existing = self.connection.execute(
            "SELECT state, lane, trigger_revision, created_at "
            "FROM frontier_candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        state = str(candidate.get("state") or "open")
        if existing:
            existing_state = str(existing["state"])
            existing_lane = str(existing["lane"])
            if existing_lane == "must_review":
                lane = "must_review"
            should_reopen = (
                requested_lane == "must_review"
                and (
                    existing_lane == "suggested_next"
                    or trigger_revision > int(existing["trigger_revision"])
                )
            )
            state = "open" if should_reopen else existing_state
        self.connection.execute(
            """
            INSERT INTO frontier_candidates(
                candidate_id, component_id, target_kind, target_key, gap_kind,
                lane, priority, tier, origin, trigger_revision, operation_id,
                reasons_json, state, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(candidate_id) DO UPDATE SET
                lane = excluded.lane,
                priority = excluded.priority,
                tier = excluded.tier,
                origin = excluded.origin,
                trigger_revision = excluded.trigger_revision,
                operation_id = excluded.operation_id,
                reasons_json = excluded.reasons_json,
                state = excluded.state,
                updated_at = excluded.updated_at
            """,
            (
                candidate_id,
                component_id,
                target_kind,
                target_key,
                gap_kind,
                lane,
                priority,
                int(candidate.get("tier") or 3),
                str(candidate.get("origin") or "scanner"),
                trigger_revision,
                str(operation_id) if operation_id else None,
                _json(list(candidate.get("reasons") or [])),
                state,
                existing["created_at"] if existing else now,
                now,
            ),
        )
        self.connection.commit()
        return self.candidate(candidate_id) or {}

    @staticmethod
    def _candidate_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["reasons"] = _load(result.pop("reasons_json"), [])
        return result

    def candidate(self, candidate_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM frontier_candidates WHERE candidate_id = ?",
            (candidate_id,),
        ).fetchone()
        return self._candidate_row(row) if row else None

    def resolve_evaluated_candidates(
        self,
        *,
        component_id: str,
        target_kind: str,
        target_key: str,
        gap_kinds: Iterable[str],
        active_candidate_ids: Iterable[str],
        evidence_id: str,
        operation_id: str,
    ) -> list[str]:
        """Close direct checks that a current post-edit inspection disproved."""

        gaps = list(dict.fromkeys(str(value) for value in gap_kinds if str(value)))
        if not gaps:
            return []
        active = {str(value) for value in active_candidate_ids}
        placeholders = ",".join("?" for _ in gaps)
        rows = self.connection.execute(
            "SELECT * FROM frontier_candidates WHERE component_id = ? "
            "AND target_kind = ? AND target_key = ? AND origin = 'direct_closure' "
            "AND lane = 'must_review' AND state IN ('open', 'investigating') "
            "AND gap_kind IN (%s)" % placeholders,
            [component_id, target_kind, target_key, *gaps],
        ).fetchall()
        resolved = [row for row in rows if str(row["candidate_id"]) not in active]
        if not resolved:
            return []
        now = utc_now()
        with self.transaction() as connection:
            for row in resolved:
                candidate_id = str(row["candidate_id"])
                disposition_id = stable_id(
                    "disposition", candidate_id, "addressed", evidence_id, operation_id
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO frontier_dispositions(
                        disposition_id, candidate_id, outcome, rationale,
                        evidence_refs_json, operation_ids_json, created_at
                    ) VALUES(?, ?, 'addressed', ?, ?, ?, ?)
                    """,
                    (
                        disposition_id,
                        candidate_id,
                        "Current post-edit inspection no longer exhibits this closure gap.",
                        _json([evidence_id]),
                        _json([operation_id]),
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE frontier_candidates SET state = 'addressed', updated_at = ? "
                    "WHERE candidate_id = ?",
                    (now, candidate_id),
                )
        return [str(row["candidate_id"]) for row in resolved]

    def resolve_target_suggestions(
        self,
        *,
        component_id: str,
        target_kind: str,
        target_key: str,
        evidence_id: str,
        operation_id: str,
    ) -> list[str]:
        """Close navigation hints once the model deliberately edits their target."""

        rows = self.connection.execute(
            "SELECT * FROM frontier_candidates WHERE component_id = ? "
            "AND target_kind = ? AND target_key = ? AND lane = 'suggested_next' "
            "AND state IN ('open', 'investigating')",
            (component_id, target_kind, target_key),
        ).fetchall()
        if not rows:
            return []
        now = utc_now()
        with self.transaction() as connection:
            for row in rows:
                candidate_id = str(row["candidate_id"])
                disposition_id = stable_id(
                    "disposition", candidate_id, "addressed", operation_id
                )
                connection.execute(
                    """
                    INSERT OR IGNORE INTO frontier_dispositions(
                        disposition_id, candidate_id, outcome, rationale,
                        evidence_refs_json, operation_ids_json, created_at
                    ) VALUES(?, ?, 'addressed', ?, ?, ?, ?)
                    """,
                    (
                        disposition_id,
                        candidate_id,
                        "The model deliberately edited this suggested target.",
                        _json([evidence_id]),
                        _json([operation_id]),
                        now,
                    ),
                )
                connection.execute(
                    "UPDATE frontier_candidates SET state = 'addressed', updated_at = ? "
                    "WHERE candidate_id = ?",
                    (now, candidate_id),
                )
        return [str(row["candidate_id"]) for row in rows]

    def review_frontier(
        self,
        *,
        lane: str = "must_review",
        component_id: str | None = None,
        limit: int = 8,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Page one collection without changing its blocking semantics."""

        lane = str(lane)
        if lane not in FRONTIER_LANES:
            raise JournalError("Unsupported frontier lane: %s" % lane)
        limit = max(1, min(int(limit), 20))
        offset = max(0, int(offset))
        clauses = ["lane = ?", "state IN ('open', 'investigating')"]
        parameters: list[Any] = [lane]
        if component_id:
            clauses.append("component_id = ?")
            parameters.append(component_id)
        where = " AND ".join(clauses)
        count = int(self.connection.execute(
            "SELECT COUNT(*) AS total FROM frontier_candidates WHERE " + where,
            parameters,
        ).fetchone()["total"])
        priority_order = (
            "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
            "WHEN 'medium' THEN 2 ELSE 3 END"
        )
        rows = self.connection.execute(
            """
            SELECT * FROM frontier_candidates WHERE %s
            ORDER BY tier, %s, created_at, candidate_id
            LIMIT ? OFFSET ?
            """ % (where, priority_order),
            [*parameters, limit, offset],
        ).fetchall()
        now = utc_now()
        batch_id = stable_id("frontier", lane, component_id, offset, limit, now)
        with self.transaction() as connection:
            for row in rows:
                connection.execute(
                    """
                    INSERT INTO frontier_presentations(
                        presentation_id, candidate_id, batch_id, presented_at
                    ) VALUES(?, ?, ?, ?)
                    """,
                    (
                        stable_id("presentation", row["candidate_id"], batch_id),
                        row["candidate_id"],
                        batch_id,
                        now,
                    ),
                )
        return {
            "collection": lane,
            "candidates": [self._candidate_row(row) for row in rows],
            "offset": offset,
            "limit": limit,
            "total_active": count,
            "next_offset": offset + len(rows) if offset + len(rows) < count else None,
            "blocking": lane == "must_review",
            "policy": "two_lane_frontier",
        }

    def promote_candidate(self, candidate_id: str, rationale: str) -> dict[str, Any]:
        candidate = self.candidate(candidate_id)
        if candidate is None:
            raise JournalError("Unknown frontier candidate: %s" % candidate_id)
        if candidate["lane"] != "suggested_next":
            raise JournalError("Only suggested_next candidates can be promoted")
        reason = str(rationale or "").strip()
        if not reason:
            raise JournalError("Promotion requires a rationale")
        reasons = list(candidate["reasons"])
        reasons.append("model promotion: %s" % reason)
        now = utc_now()
        self.connection.execute(
            "UPDATE frontier_candidates SET lane = 'must_review', state = 'open', "
            "reasons_json = ?, updated_at = ? WHERE candidate_id = ?",
            (_json(reasons), now, candidate_id),
        )
        self.connection.commit()
        return self.candidate(candidate_id) or candidate

    def mark_investigating(self, candidate_id: str, evidence_id: str) -> dict[str, Any]:
        candidate = self._validated_candidate_evidence(candidate_id, [evidence_id])
        now = utc_now()
        self.connection.execute(
            "UPDATE frontier_candidates SET state = 'investigating', updated_at = ? WHERE candidate_id = ?",
            (now, candidate_id),
        )
        self.connection.commit()
        return self.candidate(candidate_id) or candidate

    def _validated_candidate_evidence(
        self, candidate_id: str, evidence_refs: Iterable[str]
    ) -> dict[str, Any]:
        candidate = self.candidate(candidate_id)
        if candidate is None:
            raise JournalError("Unknown frontier candidate: %s" % candidate_id)
        refs = [str(value) for value in evidence_refs if str(value or "").strip()]
        if not refs:
            raise JournalError("A current matching inspection is required")
        current_revision = int(self.revision(candidate["component_id"])["revision"])
        matches = []
        for evidence_id in refs:
            row = self.inspection(evidence_id)
            if not row:
                raise JournalError("Unknown evidence reference: %s" % evidence_id)
            if row["component_id"] != candidate["component_id"]:
                continue
            if int(row["revision"]) != current_revision:
                continue
            if (
                row["target_kind"] == candidate["target_kind"]
                and self._normalized_frontier_key(
                    candidate["target_kind"], row["target_key"]
                )
                == self._normalized_frontier_key(
                    candidate["target_kind"], candidate["target_key"]
                )
            ):
                matches.append(row)
        if not matches:
            raise JournalError(
                "Disposition requires a current-revision inspection of the exact target"
            )
        return candidate

    @staticmethod
    def _normalized_frontier_key(target_kind: str, value: Any) -> str:
        text = str(value or "").strip()
        if target_kind in {"function", "global", "address"}:
            try:
                return hex(int(text, 0))
            except (TypeError, ValueError):
                return text
        return text

    def disposition_candidate(
        self,
        *,
        candidate_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Iterable[str],
        operation_ids: Iterable[str] = (),
    ) -> dict[str, Any]:
        outcome = str(outcome).strip().lower()
        if outcome not in FRONTIER_OUTCOMES:
            raise JournalError("Unsupported frontier outcome: %s" % outcome)
        rationale = str(rationale or "").strip()
        if not rationale:
            raise JournalError("Frontier disposition requires a rationale")
        refs = [str(value) for value in evidence_refs]
        self._validated_candidate_evidence(candidate_id, refs)
        operations = [str(value) for value in operation_ids if str(value or "").strip()]
        if outcome == "addressed" and operations:
            placeholders = ",".join("?" for _ in operations)
            rows = self.connection.execute(
                "SELECT operation_id FROM operations WHERE operation_id IN (%s)" % placeholders,
                operations,
            ).fetchall()
            missing = sorted(set(operations) - {str(row["operation_id"]) for row in rows})
            if missing:
                raise JournalError("Unknown addressed operation(s): %s" % ", ".join(missing))
        now = utc_now()
        disposition_id = stable_id(
            "disposition", candidate_id, outcome, rationale, refs, operations
        )
        with self.transaction() as connection:
            connection.execute(
                """
                INSERT OR IGNORE INTO frontier_dispositions(
                    disposition_id, candidate_id, outcome, rationale,
                    evidence_refs_json, operation_ids_json, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    disposition_id,
                    candidate_id,
                    outcome,
                    rationale,
                    _json(refs),
                    _json(operations),
                    now,
                ),
            )
            connection.execute(
                "UPDATE frontier_candidates SET state = ?, updated_at = ? WHERE candidate_id = ?",
                (outcome, now, candidate_id),
            )
        return {
            "disposition_id": disposition_id,
            "candidate": self.candidate(candidate_id),
            "outcome": outcome,
            "rationale": rationale,
            "evidence_refs": refs,
            "operation_ids": operations,
            "created_at": now,
        }

    @staticmethod
    def _call_flow_scope_row(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    @staticmethod
    def _call_flow_node_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["evidence_refs"] = _load(item.pop("evidence_refs_json"), [])
        item["boundary_callees"] = _load(
            item.pop("boundary_callees_json"), []
        )
        item["expanded"] = bool(item["expanded"])
        return item

    @staticmethod
    def _call_flow_edge_row(row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def call_flow_scope(self, scope_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM call_flow_scopes WHERE scope_id = ?", (scope_id,)
        ).fetchone()
        return self._call_flow_scope_row(row) if row else None

    def call_flow_scope_for_root(
        self, component_id: str, root_address: str
    ) -> dict[str, Any] | None:
        normalized = self._normalized_frontier_key("function", root_address)
        row = self.connection.execute(
            "SELECT * FROM call_flow_scopes "
            "WHERE component_id = ? AND root_address = ?",
            (component_id, normalized),
        ).fetchone()
        return self._call_flow_scope_row(row) if row else None

    def active_call_flow_scope_for_function(
        self, component_id: str, function_address: str
    ) -> dict[str, Any] | None:
        """Return an active containing scope for a non-root function claim."""

        normalized = self._normalized_frontier_key("function", function_address)
        row = self.connection.execute(
            "SELECT s.* FROM call_flow_scopes s "
            "JOIN call_flow_nodes n ON n.scope_id = s.scope_id "
            "AND n.generation = s.generation "
            "WHERE s.component_id = ? AND n.function_address = ? "
            "AND s.root_address != ? "
            "AND s.state NOT IN ('closed', 'closed_no_internal_calls') "
            "ORDER BY n.depth DESC, s.updated_at DESC LIMIT 1",
            (component_id, normalized, normalized),
        ).fetchone()
        return self._call_flow_scope_row(row) if row else None

    def _call_flow_nodes(
        self, scope_id: str, generation: int
    ) -> list[dict[str, Any]]:
        return [
            self._call_flow_node_row(row)
            for row in self.connection.execute(
                "SELECT * FROM call_flow_nodes "
                "WHERE scope_id = ? AND generation = ? "
                "ORDER BY wave, depth, function_address, node_id",
                (scope_id, int(generation)),
            ).fetchall()
        ]

    def call_flow_node(
        self, scope_id: str, node_id: str
    ) -> dict[str, Any] | None:
        scope = self.call_flow_scope(scope_id)
        if scope is None:
            return None
        row = self.connection.execute(
            "SELECT * FROM call_flow_nodes WHERE scope_id = ? "
            "AND generation = ? AND node_id = ?",
            (scope_id, int(scope["generation"]), node_id),
        ).fetchone()
        return self._call_flow_node_row(row) if row else None

    def _call_flow_edges(
        self, scope_id: str, generation: int
    ) -> list[dict[str, Any]]:
        return [
            self._call_flow_edge_row(row)
            for row in self.connection.execute(
                "SELECT * FROM call_flow_edges "
                "WHERE scope_id = ? AND generation = ? "
                "ORDER BY wave, source_address, callsite_address, edge_id",
                (scope_id, int(generation)),
            ).fetchall()
        ]

    @staticmethod
    def _inventory_function(inventory: Mapping[str, Any]) -> dict[str, Any]:
        value = inventory.get("function") or {}
        return dict(value) if isinstance(value, Mapping) else {}

    def _validate_call_flow_discovery_evidence(
        self,
        *,
        component_id: str,
        function_address: str,
        evidence_id: str,
        function_byte_hash: str,
    ) -> dict[str, Any]:
        evidence = self.inspection(evidence_id)
        if evidence is None:
            raise JournalError("Unknown call-flow evidence: %s" % evidence_id)
        normalized = self._normalized_frontier_key("function", function_address)
        if evidence["component_id"] != component_id:
            raise JournalError("Call-flow evidence belongs to a different component")
        if evidence["target_kind"] not in {
            "function", "function_code", "call_flow_inventory"
        }:
            raise JournalError("Call-flow evidence is not bound to a function")
        result = dict(evidence.get("result") or {})
        function = self._inventory_function(result)
        evidence_address = function.get("start") or function.get("address")
        if evidence_address in (None, ""):
            raise JournalError("Call-flow evidence lacks native function identity")
        if self._normalized_frontier_key(
            "function", evidence_address
        ) != normalized:
            raise JournalError("Call-flow evidence belongs to a different function")
        observed_hash = str(function.get("function_byte_hash") or "")
        if not observed_hash:
            raise JournalError("Call-flow evidence lacks a native function byte identity")
        if function_byte_hash and observed_hash != function_byte_hash:
            raise JournalError("Call-flow evidence function identity does not match live IDA")
        return evidence

    def _retire_call_flow_frontier(
        self, scope_id: str, generation: int
    ) -> None:
        origin = "claim_call_flow:%s:%d" % (scope_id, int(generation))
        self.connection.execute(
            "UPDATE frontier_candidates SET state = 'superseded', updated_at = ? "
            "WHERE origin = ? AND state IN ('open', 'investigating')",
            (utc_now(), origin),
        )
        self.connection.commit()

    def _upsert_call_flow_node_candidate(
        self,
        *,
        scope: Mapping[str, Any],
        node_id: str,
        function_address: str,
        operation_id: str,
        wave: int,
    ) -> str:
        generation = int(scope["generation"])
        candidate_id = stable_id(
            "candidate", "claim_call_flow", scope["scope_id"], generation, node_id
        )
        self.upsert_candidate({
            "candidate_id": candidate_id,
            "component_id": scope["component_id"],
            "target_kind": "function",
            "target_key": function_address,
            "gap_kind": "claim_call_flow_node:%s:%d" % (
                scope["scope_id"], generation
            ),
            "lane": "must_review",
            "reasons": [
                "direct internal callee admitted by committed function claim %s"
                % scope["root_address"],
                "inspect and disposition this callee before parent revalidation",
            ],
            "priority": "high",
            "tier": max(1, int(wave)),
            "origin": "claim_call_flow:%s:%d" % (
                scope["scope_id"], generation
            ),
            "trigger_revision": int(scope["trigger_revision"]),
            "operation_id": operation_id,
        })
        return candidate_id

    def _upsert_call_flow_parent_candidate(
        self, scope: Mapping[str, Any]
    ) -> str:
        generation = int(scope["generation"])
        candidate_id = stable_id(
            "candidate", "claim_call_flow_parent", scope["scope_id"], generation
        )
        self.upsert_candidate({
            "candidate_id": candidate_id,
            "component_id": scope["component_id"],
            "target_kind": "function",
            "target_key": scope["root_address"],
            "gap_kind": "claim_call_flow_parent:%s:%d" % (
                scope["scope_id"], generation
            ),
            "lane": "must_review",
            "reasons": [
                "reinspect the committed parent after downstream call-flow review",
                "confirm, revise, narrow, or explicitly preserve uncertainty",
            ],
            "priority": "critical",
            "tier": 1,
            "origin": "claim_call_flow:%s:%d" % (
                scope["scope_id"], generation
            ),
            "trigger_revision": int(scope["trigger_revision"]),
            "operation_id": scope["triggering_operation_id"],
        })
        self.connection.execute(
            "UPDATE call_flow_scopes SET parent_candidate_id = ?, updated_at = ? "
            "WHERE scope_id = ?",
            (candidate_id, utc_now(), scope["scope_id"]),
        )
        self.connection.commit()
        return candidate_id

    def _insert_call_flow_inventory(
        self,
        *,
        scope: Mapping[str, Any],
        source_address: str,
        source_depth: int,
        inventory: Mapping[str, Any],
        discovery_evidence_id: str,
        operation_id: str,
        allowed_destinations: Iterable[str] | None = None,
    ) -> list[str]:
        generation = int(scope["generation"])
        wave = int(source_depth) + 1
        source_function = self._inventory_function(inventory)
        source_hash = str(source_function.get("function_byte_hash") or "")
        created_nodes: list[str] = []
        admitted: dict[str, tuple[str, str]] = {}
        allowed = (
            {
                self._normalized_frontier_key("function", value)
                for value in allowed_destinations
            }
            if allowed_destinations is not None else None
        )
        for raw in inventory.get("edges") or []:
            if not isinstance(raw, Mapping):
                continue
            edge = dict(raw)
            callsite = self._normalized_frontier_key(
                "address", edge.get("callsite")
            )
            destination = (
                self._normalized_frontier_key("function", edge.get("destination"))
                if edge.get("destination") not in (None, "")
                else None
            )
            edge_kind = str(edge.get("edge_kind") or "unknown")
            classification_source = str(
                edge.get("classification_source") or "unknown"
            )
            destination_function = dict(edge.get("destination_function") or {})
            destination_hash = str(
                destination_function.get("function_byte_hash") or ""
            )
            edge_id = stable_id(
                "call-edge",
                scope["scope_id"], generation, source_address,
                callsite, destination, edge_kind,
            )
            self.connection.execute(
                """
                INSERT OR IGNORE INTO call_flow_edges(
                    edge_id, scope_id, generation, source_address,
                    callsite_address, destination_address, edge_kind,
                    classification_source, source_function_byte_hash,
                    destination_function_byte_hash, discovery_evidence_id,
                    wave, created_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    edge_id, scope["scope_id"], generation, source_address,
                    callsite, destination, edge_kind, classification_source,
                    source_hash, destination_hash, discovery_evidence_id,
                    wave, utc_now(),
                ),
            )
            if (
                edge_kind == "direct_internal"
                and classification_source == "ida_instruction_feature"
                and destination
                and destination != scope["root_address"]
                and (allowed is None or destination in allowed)
            ):
                admitted.setdefault(destination, (edge_id, destination_hash))
        self.connection.commit()
        for destination, (edge_id, destination_hash) in admitted.items():
            existing = self.connection.execute(
                "SELECT node_id FROM call_flow_nodes "
                "WHERE scope_id = ? AND generation = ? AND function_address = ?",
                (scope["scope_id"], generation, destination),
            ).fetchone()
            if existing:
                continue
            node_id = stable_id(
                "call-node", scope["scope_id"], generation, destination
            )
            candidate_id = self._upsert_call_flow_node_candidate(
                scope=scope,
                node_id=node_id,
                function_address=destination,
                operation_id=operation_id,
                wave=wave,
            )
            now = utc_now()
            self.connection.execute(
                """
                INSERT INTO call_flow_nodes(
                    node_id, scope_id, generation, function_address,
                    admitted_by_edge_id, depth, wave, state, expanded,
                    function_byte_hash, edge_set_digest,
                    frontier_candidate_id, evidence_refs_json, rationale,
                    boundary_question, claim_impact, evidence_gap,
                    expected_evidence, boundary_callees_json, resolution,
                    created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, 'awaiting_triage', 0,
                         ?, NULL, ?, '[]', '', '', '', '', '', '[]', '', ?, ?)
                """,
                (
                    node_id, scope["scope_id"], generation, destination,
                    edge_id, wave, wave, destination_hash, candidate_id,
                    now, now,
                ),
            )
            self.connection.commit()
            created_nodes.append(node_id)
        return created_nodes

    def open_call_flow_scope(
        self,
        *,
        component_id: str,
        root_address: str,
        operation_id: str,
        root_claim_digest: str,
        trigger_revision: int,
        inventory: Mapping[str, Any],
        discovery_evidence_id: str,
        allowed_destinations: Iterable[str] | None = None,
    ) -> dict[str, Any]:
        """Open or refresh the deterministic scope for one committed claim."""

        normalized_root = self._normalized_frontier_key("function", root_address)
        operation = self.connection.execute(
            "SELECT component_id FROM operations WHERE operation_id = ?",
            (operation_id,),
        ).fetchone()
        if operation is None or operation["component_id"] != component_id:
            raise JournalError("Call-flow scope requires its verified triggering operation")
        function = self._inventory_function(inventory)
        root_hash = str(function.get("function_byte_hash") or "")
        edge_digest = str(inventory.get("edge_set_digest") or "")
        if not root_hash or not edge_digest:
            raise JournalError("Call-flow inventory lacks stable function or edge identity")
        self._validate_call_flow_discovery_evidence(
            component_id=component_id,
            function_address=normalized_root,
            evidence_id=discovery_evidence_id,
            function_byte_hash=root_hash,
        )
        scope_id = stable_id("call-scope", component_id, normalized_root)
        existing = self.call_flow_scope(scope_id)
        graph_changed = bool(existing and (
            existing["root_function_byte_hash"] != root_hash
            or existing["edge_set_digest"] != edge_digest
        ))
        if existing and allowed_destinations is not None and not graph_changed:
            selected = {
                self._normalized_frontier_key("function", value)
                for value in allowed_destinations
            }
            existing_roots = {
                row["function_address"]
                for row in self._call_flow_nodes(
                    scope_id, int(existing["generation"])
                )
                if int(row["depth"]) == 1
            }
            graph_changed = selected != existing_roots
        generation = int(existing["generation"] + 1) if graph_changed else int(
            existing["generation"] if existing else 1
        )
        claim_changed = bool(
            existing and existing["root_claim_digest"] != root_claim_digest
        )
        if graph_changed and existing:
            self._retire_call_flow_frontier(scope_id, int(existing["generation"]))
        now = utc_now()
        initial_state = "open" if inventory.get("complete") else "inventory_incomplete"
        if existing and not graph_changed:
            initial_state = str(existing["state"])
            if claim_changed and initial_state.startswith("closed"):
                initial_state = "parent_revalidation_required"
        self.connection.execute(
            """
            INSERT INTO call_flow_scopes(
                scope_id, component_id, root_address, triggering_operation_id,
                root_claim_digest, generation, trigger_revision,
                root_function_byte_hash, edge_set_digest, inventory_complete,
                state, parent_candidate_id, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            ON CONFLICT(scope_id) DO UPDATE SET
                triggering_operation_id = excluded.triggering_operation_id,
                root_claim_digest = excluded.root_claim_digest,
                generation = excluded.generation,
                trigger_revision = excluded.trigger_revision,
                root_function_byte_hash = excluded.root_function_byte_hash,
                edge_set_digest = excluded.edge_set_digest,
                inventory_complete = excluded.inventory_complete,
                state = excluded.state,
                parent_candidate_id = CASE
                    WHEN call_flow_scopes.generation = excluded.generation
                    THEN call_flow_scopes.parent_candidate_id ELSE NULL END,
                updated_at = excluded.updated_at
            """,
            (
                scope_id, component_id, normalized_root, operation_id,
                root_claim_digest, generation, int(trigger_revision), root_hash,
                edge_digest, 1 if inventory.get("complete") else 0,
                initial_state, existing["created_at"] if existing else now, now,
            ),
        )
        self.connection.commit()
        scope = self.call_flow_scope(scope_id) or {}
        if not inventory.get("complete"):
            candidate_id = self._upsert_call_flow_parent_candidate(scope)
            self.connection.execute(
                "UPDATE frontier_candidates SET reasons_json = ?, updated_at = ? "
                "WHERE candidate_id = ?",
                (
                    _json(["direct-call inventory was truncated", "reacquire a complete bounded inventory before continuing"]),
                    utc_now(), candidate_id,
                ),
            )
            self.connection.commit()
            return self.read_call_flow_scope(scope_id=scope_id)
        if not existing or graph_changed:
            self._insert_call_flow_inventory(
                scope=scope,
                source_address=normalized_root,
                source_depth=0,
                inventory=inventory,
                discovery_evidence_id=discovery_evidence_id,
                operation_id=operation_id,
                allowed_destinations=allowed_destinations,
            )
        nodes = self._call_flow_nodes(scope_id, generation)
        if not nodes:
            self.connection.execute(
                "UPDATE call_flow_scopes SET state = 'closed_no_internal_calls', "
                "updated_at = ? WHERE scope_id = ?",
                (utc_now(), scope_id),
            )
            self.connection.commit()
        elif claim_changed and not graph_changed and all(
            row["state"] != "awaiting_triage" for row in nodes
        ):
            self.connection.execute(
                "UPDATE call_flow_scopes SET state = 'parent_revalidation_required', "
                "updated_at = ? WHERE scope_id = ?",
                (utc_now(), scope_id),
            )
            self.connection.commit()
            self._upsert_call_flow_parent_candidate(
                self.call_flow_scope(scope_id) or scope
            )
        return self.read_call_flow_scope(scope_id=scope_id)

    @staticmethod
    def _call_flow_active_step(nodes: list[dict[str, Any]]) -> dict[str, Any]:
        """Select one depth-first frame without turning support into recursion."""

        pending = [
            row for row in nodes
            if row["state"] in {"awaiting_triage", "stale"}
        ]
        boundaries = [
            row for row in nodes if row["state"] == "unresolved_boundary"
        ]
        if boundaries:
            boundary = max(
                boundaries,
                key=lambda row: (int(row["depth"]), str(row["updated_at"])),
            )
            descendants = [
                row for row in pending
                if int(row["depth"]) > int(boundary["depth"])
            ]
            if descendants:
                active_depth = max(int(row["depth"]) for row in descendants)
                return {
                    "action": "inspect_and_disposition_open_node",
                    "active_depth": active_depth,
                    "nodes": [
                        row for row in descendants
                        if int(row["depth"]) == active_depth
                    ],
                    "boundary_node": boundary,
                }
            return {
                "action": "reconcile_boundary",
                "active_depth": int(boundary["depth"]),
                "nodes": [boundary],
                "boundary_node": boundary,
            }
        if pending:
            active_depth = max(int(row["depth"]) for row in pending)
            return {
                "action": "inspect_and_disposition_open_node",
                "active_depth": active_depth,
                "nodes": [
                    row for row in pending if int(row["depth"]) == active_depth
                ],
                "boundary_node": None,
            }
        return {
            "action": "revalidate_parent",
            "active_depth": 0,
            "nodes": [],
            "boundary_node": None,
        }

    def _advance_call_flow_scope(self, scope_id: str) -> dict[str, Any]:
        scope = self.call_flow_scope(scope_id)
        if scope is None:
            raise JournalError("Unknown call-flow scope: %s" % scope_id)
        nodes = self._call_flow_nodes(scope_id, int(scope["generation"]))
        step = self._call_flow_active_step(nodes)
        if step["action"] != "revalidate_parent":
            state = (
                "boundary_reconciliation_required"
                if step["action"] == "reconcile_boundary"
                else "expanding"
                if step["boundary_node"]
                else "open"
            )
            self.connection.execute(
                "UPDATE call_flow_scopes SET state = ?, updated_at = ? WHERE scope_id = ?",
                (state, utc_now(), scope_id),
            )
            self.connection.commit()
            return self.read_call_flow_scope(scope_id=scope_id)
        self.connection.execute(
            "UPDATE call_flow_scopes SET state = 'parent_revalidation_required', "
            "updated_at = ? WHERE scope_id = ?",
            (utc_now(), scope_id),
        )
        self.connection.commit()
        self._upsert_call_flow_parent_candidate(
            self.call_flow_scope(scope_id) or scope
        )
        return self.read_call_flow_scope(scope_id=scope_id)

    def disposition_call_flow_node(
        self,
        *,
        scope_id: str,
        node_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Iterable[str],
        live_inventory: Mapping[str, Any],
        discovery_evidence_id: str,
        boundary_question: str = "",
        claim_impact: str = "",
        evidence_gap: str = "",
        expected_evidence: str = "",
        boundary_callees: Iterable[str] = (),
    ) -> dict[str, Any]:
        outcome = str(outcome or "").strip().lower()
        if outcome not in CALL_FLOW_NODE_OUTCOMES:
            raise JournalError("Unsupported call-flow outcome: %s" % outcome)
        reason = str(rationale or "").strip()
        if not reason:
            raise JournalError("Call-flow disposition requires a rationale")
        scope = self.call_flow_scope(scope_id)
        if scope is None:
            raise JournalError("Unknown call-flow scope: %s" % scope_id)
        row = self.connection.execute(
            "SELECT * FROM call_flow_nodes WHERE node_id = ? AND scope_id = ? "
            "AND generation = ?",
            (node_id, scope_id, int(scope["generation"])),
        ).fetchone()
        if row is None:
            raise JournalError("Unknown current call-flow node: %s" % node_id)
        node = self._call_flow_node_row(row)
        nodes = self._call_flow_nodes(scope_id, int(scope["generation"]))
        step = self._call_flow_active_step(nodes)
        active_ids = {item["node_id"] for item in step["nodes"]}
        if node_id not in active_ids:
            raise JournalError(
                "Call-flow scope is depth-first; finish the active boundary path first"
            )
        reconciling = (
            step["action"] == "reconcile_boundary"
            and node["state"] == "unresolved_boundary"
        )
        if not reconciling and node["state"] not in {"awaiting_triage", "stale"}:
            raise JournalError("Call-flow node has already been dispositioned")
        if reconciling and outcome not in CALL_FLOW_TERMINAL_OUTCOMES:
            raise JournalError(
                "Boundary reconciliation requires a terminal supported outcome"
            )
        refs = list(dict.fromkeys(str(value) for value in evidence_refs if str(value)))
        if not refs:
            raise JournalError("Call-flow disposition requires current function evidence")
        function = self._inventory_function(live_inventory)
        live_hash = str(function.get("function_byte_hash") or "")
        semantic_evidence = []
        for evidence_id in refs:
            raw_evidence = self.inspection(evidence_id)
            if raw_evidence is not None:
                raw_result = dict(raw_evidence.get("result") or {})
                raw_function = self._inventory_function(raw_result)
                raw_address = raw_function.get("start") or raw_function.get("address")
                if (
                    raw_evidence.get("component_id") == scope["component_id"]
                    and raw_address not in (None, "")
                    and self._normalized_frontier_key(
                        "function", raw_address
                    ) != node["function_address"]
                ):
                    routed_address = self._normalized_frontier_key(
                        "function", raw_address
                    )
                    if reconciling:
                        raise JournalError(
                            "Evidence %s belongs to resolved descendant %s, not "
                            "the active boundary node %s. The descendant "
                            "disposition already retains its own evidence. "
                            "Reconcile the existing boundary with current-node "
                            "code evidence and summarize the descendant result "
                            "in the rationale; do not open another boundary."
                            % (
                                evidence_id, routed_address,
                                node["function_address"],
                            )
                        )
                    raise JournalError(
                        "Evidence %s belongs to downstream function %s, not the "
                        "active node %s. Do not drop evidence that the conclusion "
                        "depends on: submit unresolved_boundary with current-node "
                        "code evidence and boundary_callees including %s; after the "
                        "host admits it, use this evidence on that child."
                        % (
                            evidence_id, routed_address,
                            node["function_address"], routed_address,
                        )
                    )
            evidence = self._validate_call_flow_discovery_evidence(
                component_id=scope["component_id"],
                function_address=node["function_address"],
                evidence_id=evidence_id,
                function_byte_hash=live_hash,
            )
            if evidence["query_kind"] in CALL_FLOW_CODE_EVIDENCE_QUERIES:
                semantic_evidence.append(evidence_id)
        if not semantic_evidence:
            raise JournalError(
                "Call-flow disposition requires direct disassembly or pseudocode evidence"
            )
        self._validate_call_flow_discovery_evidence(
            component_id=scope["component_id"],
            function_address=node["function_address"],
            evidence_id=discovery_evidence_id,
            function_byte_hash=live_hash,
        )
        if not live_inventory.get("complete"):
            raise JournalError(
                "A call-flow disposition requires complete direct-call inventory"
            )
        question = str(boundary_question or "").strip()
        impact = str(claim_impact or "").strip()
        gap = str(evidence_gap or "").strip()
        expected = str(expected_evidence or "").strip()
        selected_callees = list(dict.fromkeys(
            self._normalized_frontier_key("function", value)
            for value in boundary_callees
            if str(value or "").strip()
        ))
        if not reconciling and outcome == "unresolved_boundary" and not all(
            (question, impact, gap, expected)
        ):
            raise JournalError(
                "Boundary expansion requires an open question, claim impact, "
                "evidence gap, and expected evidence"
            )
        if not reconciling and outcome == "unresolved_boundary":
            if not selected_callees:
                raise JournalError(
                    "Boundary expansion requires at least one exact direct callee"
                )
        if (not reconciling and outcome == "unresolved_boundary") or reconciling:
            required_callees = (
                list(node.get("boundary_callees") or [])
                if reconciling else selected_callees
            )
            if reconciling:
                selected_callees = list(required_callees)
            if not required_callees:
                raise JournalError(
                    "Boundary reconciliation cannot proceed without its durable "
                    "selected-callee set"
                )
            available_callees = {
                self._normalized_frontier_key("function", edge.get("destination"))
                for edge in live_inventory.get("edges") or []
                if isinstance(edge, Mapping)
                and edge.get("edge_kind") == "direct_internal"
                and edge.get("classification_source") == "ida_instruction_feature"
                and edge.get("destination") not in (None, "")
                and self._normalized_frontier_key(
                    "function", edge.get("destination")
                ) != scope["root_address"]
            }
            invalid_callees = sorted(set(required_callees) - available_callees)
            if invalid_callees:
                raise JournalError(
                    "Boundary callee is not a current IDA-native direct internal "
                    "destination: %s. Available destinations: %s"
                    % (
                        ", ".join(invalid_callees),
                        ", ".join(sorted(available_callees)) or "none",
                    )
                )
            if reconciling:
                durable_callees = {
                    row["function_address"]
                    for row in self._call_flow_nodes(
                        scope_id, int(scope["generation"])
                    )
                }
                missing_callees = sorted(
                    set(required_callees) - durable_callees
                )
                if missing_callees:
                    created_nodes = self._insert_call_flow_inventory(
                        scope=scope,
                        source_address=node["function_address"],
                        source_depth=int(node["depth"]),
                        inventory=live_inventory,
                        discovery_evidence_id=discovery_evidence_id,
                        operation_id=scope["triggering_operation_id"],
                        allowed_destinations=required_callees,
                    )
                    recovered_callees = {
                        row["function_address"]
                        for row in self._call_flow_nodes(
                            scope_id, int(scope["generation"])
                        )
                    }
                    still_missing = sorted(
                        set(required_callees) - recovered_callees
                    )
                    if still_missing:
                        raise JournalError(
                            "Boundary expansion recovery could not materialize "
                            "selected callees: %s" % ", ".join(still_missing)
                        )
                    self.connection.execute(
                        "UPDATE call_flow_nodes SET expanded = 1, updated_at = ? "
                        "WHERE node_id = ?",
                        (utc_now(), node_id),
                    )
                    self.connection.commit()
                    advanced = self._advance_call_flow_scope(scope_id)
                    return {
                        "scope": advanced,
                        "node_id": node_id,
                        "outcome": "unresolved_boundary",
                        "phase": "boundary_expansion_recovered",
                        "created_node_ids": created_nodes,
                        "selected_boundary_callees": required_callees,
                    }
        if reconciling:
            self.connection.execute(
                "UPDATE call_flow_nodes SET state = ?, function_byte_hash = ?, "
                "edge_set_digest = ?, evidence_refs_json = ?, resolution = ?, "
                "updated_at = ? WHERE node_id = ?",
                (
                    outcome, live_hash,
                    str(live_inventory.get("edge_set_digest") or ""),
                    _json(refs), reason, utc_now(), node_id,
                ),
            )
        else:
            self.connection.execute(
                "UPDATE call_flow_nodes SET state = ?, function_byte_hash = ?, "
                "edge_set_digest = ?, evidence_refs_json = ?, rationale = ?, "
                "boundary_question = ?, claim_impact = ?, evidence_gap = ?, "
                "expected_evidence = ?, boundary_callees_json = ?, "
                "updated_at = ? WHERE node_id = ?",
                (
                    outcome, live_hash,
                    str(live_inventory.get("edge_set_digest") or ""),
                    _json(refs), reason, question, impact, gap, expected,
                    _json(selected_callees), utc_now(), node_id,
                ),
            )
        self.connection.commit()
        created_nodes: list[str] = []
        if not reconciling and outcome == "unresolved_boundary":
            self.connection.execute(
                "UPDATE frontier_candidates SET state = 'investigating', "
                "updated_at = ? WHERE candidate_id = ?",
                (utc_now(), node["frontier_candidate_id"]),
            )
            self.connection.commit()
            created_nodes = self._insert_call_flow_inventory(
                scope=scope,
                source_address=node["function_address"],
                source_depth=int(node["depth"]),
                inventory=live_inventory,
                discovery_evidence_id=discovery_evidence_id,
                operation_id=scope["triggering_operation_id"],
                allowed_destinations=selected_callees,
            )
            self.connection.execute(
                "UPDATE call_flow_nodes SET expanded = 1, updated_at = ? "
                "WHERE node_id = ?",
                (utc_now(), node_id),
            )
            self.connection.commit()
        else:
            frontier_outcome = (
                outcome
                if outcome in {"nonmaterial", "deferred", "uncertain"}
                else "addressed"
            )
            self.disposition_candidate(
                candidate_id=node["frontier_candidate_id"],
                outcome=frontier_outcome,
                rationale=reason,
                evidence_refs=[discovery_evidence_id],
            )
        advanced = self._advance_call_flow_scope(scope_id)
        return {
            "scope": advanced,
            "node_id": node_id,
            "outcome": outcome,
            "phase": "boundary_reconciliation" if reconciling else "triage",
            "created_node_ids": created_nodes,
            "selected_boundary_callees": selected_callees,
        }

    def revalidate_call_flow_parent(
        self,
        *,
        scope_id: str,
        outcome: str,
        rationale: str,
        parent_evidence_id: str,
        parent_inventory_evidence_id: str,
        operation_ids: Iterable[str],
        resulting_claim_digest: str,
        live_function_byte_hash: str,
    ) -> dict[str, Any]:
        outcome = str(outcome or "").strip().lower()
        if outcome not in CALL_FLOW_PARENT_OUTCOMES:
            raise JournalError("Unsupported parent revalidation outcome: %s" % outcome)
        reason = str(rationale or "").strip()
        if not reason:
            raise JournalError("Parent revalidation requires a rationale")
        scope = self.call_flow_scope(scope_id)
        if scope is None:
            raise JournalError("Unknown call-flow scope: %s" % scope_id)
        if scope["state"] not in {"parent_revalidation_required", "open_uncertainty"}:
            raise JournalError("Downstream scope is not ready for parent revalidation")
        parent_evidence = self._validate_call_flow_discovery_evidence(
            component_id=scope["component_id"],
            function_address=scope["root_address"],
            evidence_id=parent_evidence_id,
            function_byte_hash=live_function_byte_hash,
        )
        if parent_evidence["query_kind"] not in CALL_FLOW_CODE_EVIDENCE_QUERIES:
            raise JournalError(
                "Parent revalidation requires direct disassembly or pseudocode evidence"
            )
        nodes = self._call_flow_nodes(scope_id, int(scope["generation"]))
        unresolved = [
            row for row in nodes
            if row["state"] in {
                "uncertain", "deferred", "contradicts_parent_claim"
            }
        ]
        if outcome == "confirmed" and unresolved:
            raise JournalError(
                "A parent with uncertain, deferred, or contradicting callees "
                "must be revised, narrowed, or left open"
            )
        operations = list(dict.fromkeys(
            str(value) for value in operation_ids if str(value or "").strip()
        ))
        if outcome in {"revised", "narrowed"} and not operations:
            raise JournalError("Revised or narrowed parent claims require operation IDs")
        for operation_id in operations:
            row = self.connection.execute(
                """
                SELECT o.component_id, o.target_kind, o.target_key, r.status
                FROM operations o
                LEFT JOIN receipts r ON r.rowid = (
                    SELECT r2.rowid FROM receipts r2
                    WHERE r2.operation_id = o.operation_id
                    ORDER BY r2.rowid DESC LIMIT 1
                )
                WHERE o.operation_id = ?
                """,
                (operation_id,),
            ).fetchone()
            if (
                row is None
                or row["component_id"] != scope["component_id"]
                or row["target_kind"] != "function"
                or self._normalized_frontier_key("function", row["target_key"])
                != scope["root_address"]
                or row["status"] not in VERIFIED_STATUSES
            ):
                raise JournalError(
                    "Parent revalidation operation is not a verified edit of the scoped parent"
                )
        review_id = stable_id(
            "call-parent-review", scope_id, scope["generation"], outcome,
            parent_evidence_id, operations, resulting_claim_digest,
        )
        now = utc_now()
        self.connection.execute(
            """
            INSERT OR IGNORE INTO call_flow_parent_reviews(
                review_id, scope_id, generation, outcome, rationale,
                parent_evidence_id, operation_ids_json,
                resulting_claim_digest, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id, scope_id, int(scope["generation"]), outcome, reason,
                parent_evidence_id, _json(operations), resulting_claim_digest, now,
            ),
        )
        next_state = "open_uncertainty" if outcome == "open_uncertainty" else "closed"
        self.connection.execute(
            "UPDATE call_flow_scopes SET state = ?, root_claim_digest = ?, "
            "updated_at = ? WHERE scope_id = ?",
            (next_state, resulting_claim_digest, now, scope_id),
        )
        self.connection.commit()
        candidate_id = scope.get("parent_candidate_id")
        if candidate_id:
            if outcome == "open_uncertainty":
                self.connection.execute(
                    "UPDATE frontier_candidates SET state = 'investigating', "
                    "updated_at = ? WHERE candidate_id = ?",
                    (now, candidate_id),
                )
                self.connection.commit()
            else:
                self.disposition_candidate(
                    candidate_id=candidate_id,
                    outcome="addressed",
                    rationale=reason,
                    evidence_refs=[parent_inventory_evidence_id],
                    operation_ids=operations,
                )
        return {
            "review_id": review_id,
            "outcome": outcome,
            "scope": self.read_call_flow_scope(scope_id=scope_id),
        }

    def read_call_flow_scope(
        self,
        *,
        scope_id: str,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        scope = self.call_flow_scope(scope_id)
        if scope is None:
            raise JournalError("Unknown call-flow scope: %s" % scope_id)
        generation = int(scope["generation"])
        all_nodes = self._call_flow_nodes(scope_id, generation)
        all_edges = self._call_flow_edges(scope_id, generation)
        page_limit = max(1, min(int(limit), 50))
        page_offset = max(0, int(offset))
        step = self._call_flow_active_step(all_nodes)
        active_nodes = list(step["nodes"])
        page = active_nodes[page_offset:page_offset + page_limit]
        counts: dict[str, int] = {}
        for row in all_nodes:
            counts[row["state"]] = counts.get(row["state"], 0) + 1
        edge_counts: dict[str, int] = {}
        for row in all_edges:
            edge_counts[row["edge_kind"]] = edge_counts.get(row["edge_kind"], 0) + 1
        open_boundaries = sorted(
            (
                row for row in all_nodes
                if row["state"] == "unresolved_boundary"
            ),
            key=lambda row: (int(row["depth"]), row["function_address"]),
        )
        return {
            "schema": "verified_ida.call_flow_scope.v3",
            "scope": scope,
            "node_counts": dict(sorted(counts.items())),
            "edge_counts": dict(sorted(edge_counts.items())),
            "open_nodes": page,
            "active_path": [
                {
                    "node_id": row["node_id"],
                    "function_address": row["function_address"],
                    "depth": int(row["depth"]),
                    "boundary_question": row["boundary_question"],
                    "claim_impact": row["claim_impact"],
                    "boundary_callees": row["boundary_callees"],
                }
                for row in open_boundaries
            ],
            "active_depth": int(step["active_depth"]),
            "page": {
                "offset": page_offset,
                "limit": page_limit,
                "returned": len(page),
                "total": len(active_nodes),
                "has_more": page_offset + len(page) < len(active_nodes),
                "next_offset": (
                    page_offset + len(page)
                    if page_offset + len(page) < len(active_nodes) else None
                ),
            },
            "pending_node_count": sum(
                1 for row in all_nodes
                if row["state"] in {"awaiting_triage", "stale"}
            ),
            "advisory_topology": {
                key: edge_counts.get(key, 0)
                for key in (
                    "direct_import", "direct_thunk", "direct_library", "tail_call",
                    "unresolved_direct", "unresolved_indirect",
                )
                if edge_counts.get(key, 0)
            },
            "next_action": (
                "none"
                if scope["state"] in {"closed", "closed_no_internal_calls"}
                else "resolve_inventory"
                if scope["state"] == "inventory_incomplete"
                else step["action"]
            ),
        }

    def call_flow_summary(self) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT state, COUNT(*) AS count FROM call_flow_scopes GROUP BY state"
        ).fetchall()
        active = self.connection.execute(
            "SELECT scope_id, component_id, root_address, generation, state "
            "FROM call_flow_scopes WHERE state NOT IN ('closed', 'closed_no_internal_calls') "
            "ORDER BY component_id, root_address"
        ).fetchall()
        return {
            "scope_count": int(sum(int(row["count"]) for row in rows)),
            "state_counts": {
                str(row["state"]): int(row["count"]) for row in rows
            },
            "active_scopes": [dict(row) for row in active],
        }

    def call_flow_fingerprint_state(self) -> dict[str, Any]:
        """Return current-generation state used to invalidate closure review."""

        scopes = self.connection.execute(
            "SELECT scope_id, component_id, root_address, generation, "
            "root_claim_digest, root_function_byte_hash, edge_set_digest, "
            "inventory_complete, state FROM call_flow_scopes "
            "ORDER BY scope_id"
        ).fetchall()
        values = []
        for raw_scope in scopes:
            scope = dict(raw_scope)
            nodes = self.connection.execute(
                "SELECT node_id, function_address, depth, wave, state, expanded, "
                "function_byte_hash, edge_set_digest, rationale, "
                "boundary_question, claim_impact, evidence_gap, "
                "expected_evidence, boundary_callees_json, resolution "
                "FROM call_flow_nodes WHERE scope_id = ? AND generation = ? "
                "ORDER BY node_id",
                (scope["scope_id"], int(scope["generation"])),
            ).fetchall()
            review = self.connection.execute(
                "SELECT outcome, parent_evidence_id, operation_ids_json, "
                "resulting_claim_digest FROM call_flow_parent_reviews "
                "WHERE scope_id = ? AND generation = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (scope["scope_id"], int(scope["generation"])),
            ).fetchone()
            values.append({
                **scope,
                "nodes": [dict(row) for row in nodes],
                "parent_review": (
                    {
                        **dict(review),
                        "operation_ids": _load(review["operation_ids_json"], []),
                    }
                    if review else None
                ),
            })
            if values[-1]["parent_review"]:
                values[-1]["parent_review"].pop("operation_ids_json", None)
        return {"scopes": values}

    def call_flow_review_state(
        self, *, scope_limit: int = 32, node_limit: int = 160
    ) -> dict[str, Any]:
        """Return bounded current decisions for analytical closure challenge."""

        rows = self.connection.execute(
            "SELECT * FROM call_flow_scopes ORDER BY "
            "CASE WHEN state IN ('closed', 'closed_no_internal_calls') "
            "THEN 1 ELSE 0 END, updated_at DESC, scope_id "
            "LIMIT ?",
            (max(1, min(int(scope_limit), 64)),),
        ).fetchall()
        remaining_nodes = max(1, min(int(node_limit), 400))
        scopes = []
        for raw in rows:
            scope = self._call_flow_scope_row(raw)
            nodes = self._call_flow_nodes(
                scope["scope_id"], int(scope["generation"])
            )[:remaining_nodes]
            remaining_nodes -= len(nodes)
            scopes.append({
                "scope_id": scope["scope_id"],
                "component_id": scope["component_id"],
                "root_address": scope["root_address"],
                "generation": int(scope["generation"]),
                "state": scope["state"],
                "inventory_complete": bool(scope["inventory_complete"]),
                "nodes": [{
                    key: node[key]
                    for key in (
                        "node_id", "function_address", "depth", "wave",
                        "state", "expanded", "rationale", "boundary_question",
                        "claim_impact", "evidence_gap", "expected_evidence",
                        "boundary_callees", "resolution",
                    )
                } for node in nodes],
                "nodes_truncated": len(self._call_flow_nodes(
                    scope["scope_id"], int(scope["generation"])
                )) > len(nodes),
            })
            if remaining_nodes <= 0:
                break
        summary = self.call_flow_summary()
        return {
            **summary,
            "returned_scope_count": len(scopes),
            "scopes_truncated": summary["scope_count"] > len(scopes),
            "scopes": scopes,
            "review_instruction": (
                "Challenge terminal support decisions and unresolved boundaries "
                "against live IDA; do not treat a recorded disposition as a "
                "semantic verdict."
            ),
        }

    def operation_supersession(self, operation_id: str) -> dict[str, Any]:
        detail = self.operation_detail(operation_id)
        if detail is None:
            raise JournalError("Unknown operation ID: %s" % operation_id)
        identity = operation_surface_identity(detail["request"], component_id=detail["component_id"])
        current = next(row for row in self.current_operations()
                       if operation_surface_identity(row["request"], component_id=row["component_id"]) == identity)
        replaced_failures = []
        for row in self.operations_after(0):
            if row["operation_id"] == current["operation_id"]:
                continue
            if operation_surface_identity(row["request"], component_id=row["component_id"]) != identity:
                continue
            receipt = row.get("receipt") or {}
            if receipt.get("status") not in VERIFIED_STATUSES:
                replaced_failures.append(row["operation_id"])
        receipt = current.get("receipt") or {}
        return {
            "current_operation_id": current["operation_id"],
            "superseded": operation_id != current["operation_id"],
            "superseded_failure_ids": replaced_failures,
            "mechanical_blocker_remaining": (
                receipt.get("status") not in VERIFIED_STATUSES or receipt.get("persistence") == "failed"
            ) and current.get("resolution_outcome") != "abandoned",
        }

    def abandon_operation(self, operation_id: str, rationale: str) -> dict[str, Any]:
        operation_id = str(operation_id or "").strip()
        reason = str(rationale or "").strip()
        if not operation_id or not reason:
            raise JournalError("Abandoning an operation requires its ID and rationale")
        issue = next(
            (
                row for row in self.mechanical_issues()
                if row["operation_id"] == operation_id
            ),
            None,
        )
        if issue is None:
            supersession = self.operation_supersession(operation_id)
            if supersession["superseded"]:
                return {"operation_id": operation_id, "outcome": "already_superseded", **supersession,
                        "message": "No abandonment was recorded. The newer same-surface operation superseded this attempt."}
            raise JournalError("Operation is not a current mechanical blocker")
        now = utc_now()
        self.connection.execute(
            """
            INSERT INTO operation_resolutions(operation_id, outcome, rationale, created_at)
            VALUES(?, 'abandoned', ?, ?)
            ON CONFLICT(operation_id) DO UPDATE SET
                outcome = excluded.outcome,
                rationale = excluded.rationale,
                created_at = excluded.created_at
            """,
            (operation_id, reason, now),
        )
        self.connection.commit()
        return {
            "operation_id": operation_id,
            "outcome": "abandoned",
            "rationale": reason,
            "receipt_id": issue.get("receipt_id"),
            "created_at": now,
        }

    def operation_summary(self) -> dict[str, Any]:
        """Return cumulative mutation and receipt counts for run reporting."""

        rows = self.connection.execute(
            """
            SELECT o.rowid AS operation_rowid, o.operation_id,
                   o.component_id, o.kind, o.target_kind,
                   o.target_key, o.request_json,
                   r.status, r.stage, r.persistence,
                   resolution.outcome AS resolution_outcome
            FROM operations o
            LEFT JOIN receipts r ON r.rowid = (
                SELECT r2.rowid FROM receipts r2
                WHERE r2.operation_id = o.operation_id
                ORDER BY r2.rowid DESC LIMIT 1
            )
            LEFT JOIN operation_resolutions resolution
                ON resolution.operation_id = o.operation_id
            ORDER BY o.rowid
            """
        ).fetchall()
        status_counts: dict[str, int] = {}
        persistence_counts: dict[str, int] = {}
        historical_status_counts: dict[str, int] = {}
        historical_persistence_counts: dict[str, int] = {}
        component_counts: dict[str, int] = {}
        kind_counts: dict[str, int] = {}
        abandoned = 0
        without_receipt = 0
        latest_owner: dict[tuple[str, str, str, str], int] = {}
        for row in rows:
            operation = _load(row["request_json"], {})
            logical_target = operation_surface_identity(
                operation,
                component_id=str(row["component_id"]),
            )
            latest_owner[logical_target] = int(row["operation_rowid"])
        superseded = 0
        for row in rows:
            status = str(row["status"] or "no_receipt")
            persistence = str(row["persistence"] or "no_receipt")
            component = str(row["component_id"])
            kind = str(row["kind"])
            historical_status_counts[status] = historical_status_counts.get(status, 0) + 1
            historical_persistence_counts[persistence] = (
                historical_persistence_counts.get(persistence, 0) + 1
            )
            component_counts[component] = component_counts.get(component, 0) + 1
            kind_counts[kind] = kind_counts.get(kind, 0) + 1
            if row["resolution_outcome"] == "abandoned":
                abandoned += 1
            if row["status"] is None:
                without_receipt += 1
            operation = _load(row["request_json"], {})
            logical_target = operation_surface_identity(
                operation,
                component_id=component,
            )
            owner_rowid = latest_owner.get(logical_target)
            if int(row["operation_rowid"]) != owner_rowid:
                superseded += 1
                continue
            status_counts[status] = status_counts.get(status, 0) + 1
            persistence_counts[persistence] = persistence_counts.get(persistence, 0) + 1
        return {
            "operation_count": len(rows),
            "current_operation_count": len(rows) - superseded,
            "superseded_operation_count": superseded,
            "latest_status_counts": dict(sorted(status_counts.items())),
            "latest_persistence_counts": dict(sorted(persistence_counts.items())),
            "historical_latest_status_counts": dict(
                sorted(historical_status_counts.items())
            ),
            "historical_latest_persistence_counts": dict(
                sorted(historical_persistence_counts.items())
            ),
            "component_counts": dict(sorted(component_counts.items())),
            "kind_counts": dict(sorted(kind_counts.items())),
            "abandoned_count": abandoned,
            "without_receipt_count": without_receipt,
            "current_mechanical_failure_count": len(self.mechanical_issues()),
        }

    def current_operations(self) -> list[dict[str, Any]]:
        """Return the newest operation and receipt for each logical edit surface."""

        rows = self.connection.execute(
            """
            SELECT o.rowid AS operation_rowid, o.*, r.receipt_json,
                   resolution.outcome AS resolution_outcome
            FROM operations o
            LEFT JOIN receipts r ON r.rowid = (
                SELECT r2.rowid FROM receipts r2
                WHERE r2.operation_id = o.operation_id
                ORDER BY r2.rowid DESC LIMIT 1
            )
            LEFT JOIN operation_resolutions resolution
                ON resolution.operation_id = o.operation_id
            ORDER BY o.rowid
            """
        ).fetchall()
        by_surface: dict[tuple[str, str, str, str], dict[str, Any]] = {}
        for row in rows:
            item = dict(row)
            item["request"] = _load(item.pop("request_json"), {})
            item["receipt"] = _load(item.pop("receipt_json"), None)
            identity = operation_surface_identity(
                item["request"],
                component_id=str(item["component_id"]),
            )
            item["surface_key"] = identity[3]
            by_surface[identity] = item
        return sorted(
            by_surface.values(), key=lambda row: int(row["operation_rowid"])
        )

    def operation_cutoff(self) -> int:
        row = self.connection.execute(
            "SELECT COALESCE(MAX(rowid), 0) AS cutoff FROM operations"
        ).fetchone()
        return int(row["cutoff"] if row else 0)

    def operations_after(self, cutoff: int) -> list[dict[str, Any]]:
        """Return every operation after a cutoff, including superseded writes."""

        rows = self.connection.execute(
            """
            SELECT o.rowid AS operation_rowid, o.*, r.receipt_json,
                   resolution.outcome AS resolution_outcome
            FROM operations o
            LEFT JOIN receipts r ON r.rowid = (
                SELECT r2.rowid FROM receipts r2
                WHERE r2.operation_id = o.operation_id
                ORDER BY r2.rowid DESC LIMIT 1
            )
            LEFT JOIN operation_resolutions resolution
                ON resolution.operation_id = o.operation_id
            WHERE o.rowid > ?
            ORDER BY o.rowid
            """,
            (int(cutoff),),
        ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["request"] = _load(item.pop("request_json"), {})
            item["receipt"] = _load(item.pop("receipt_json"), None)
            item["surface_key"] = operation_surface_identity(
                item["request"],
                component_id=str(item["component_id"]),
            )[3]
            results.append(item)
        return results

    def latest_inspection_for_target(
        self,
        *,
        component_id: str,
        target_kind: str,
        target_key: str,
    ) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT * FROM inspections
            WHERE component_id = ? AND target_kind = ? AND target_key = ?
            ORDER BY rowid DESC LIMIT 1
            """,
            (component_id, target_kind, target_key),
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["result"] = _load(item.pop("result_json"), None)
        return item

    @staticmethod
    def _closure_review_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["component_revisions"] = _load(
            item.pop("component_revisions_json"), {}
        )
        return item

    def record_closure_review(
        self,
        *,
        active_component_id: str,
        objective_digest: str,
        notebook_digest: str,
        closure_section_digest: str,
        component_revisions: Mapping[str, int],
        packet_digest: str,
        packet_path: str | Path,
        candidate_count: int,
    ) -> dict[str, Any]:
        """Record one advisory review epoch without creating a completion gate."""

        if self.component(active_component_id) is None:
            raise JournalError("Unknown closure-review component: %s" % active_component_id)
        epoch = int(self.connection.execute(
            "SELECT COALESCE(MAX(epoch), 0) + 1 AS value FROM closure_reviews"
        ).fetchone()["value"])
        operation_cutoff = int(self.connection.execute(
            "SELECT COALESCE(MAX(rowid), 0) AS value FROM operations"
        ).fetchone()["value"])
        now = utc_now()
        review_id = stable_id(
            "closure-review", epoch, packet_digest, active_component_id, now
        )
        self.connection.execute(
            """
            INSERT INTO closure_reviews(
                review_id, epoch, active_component_id, operation_cutoff_rowid,
                objective_digest, notebook_digest, closure_section_digest,
                component_revisions_json, packet_digest, packet_path,
                candidate_count, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                review_id,
                epoch,
                active_component_id,
                operation_cutoff,
                objective_digest,
                notebook_digest,
                closure_section_digest,
                _json(dict(component_revisions)),
                packet_digest,
                str(Path(packet_path).resolve()),
                int(candidate_count),
                now,
            ),
        )
        self.connection.commit()
        return self.closure_review(review_id) or {}

    def closure_review(self, review_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM closure_reviews WHERE review_id = ?", (review_id,)
        ).fetchone()
        return self._closure_review_row(row) if row else None

    def latest_closure_review(self) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM closure_reviews ORDER BY epoch DESC LIMIT 1"
        ).fetchone()
        return self._closure_review_row(row) if row else None

    def attach_closure_update(
        self,
        *,
        update_id: str,
        closure_digest: str,
    ) -> dict[str, Any] | None:
        review = self.latest_closure_review()
        if review is None:
            return None
        now = utc_now()
        self.connection.execute(
            """
            UPDATE closure_reviews
            SET closure_update_id = ?, closure_update_digest = ?,
                closure_updated_at = ?
            WHERE review_id = ?
            """,
            (update_id, closure_digest, now, review["review_id"]),
        )
        self.connection.commit()
        return self.closure_review(str(review["review_id"]))

    def operations_after_closure_review(self, review_id: str) -> list[dict[str, Any]]:
        review = self.closure_review(review_id)
        if review is None:
            raise JournalError("Unknown closure review: %s" % review_id)
        rows = self.connection.execute(
            """
            SELECT rowid AS operation_rowid, operation_id, component_id, kind,
                   target_kind, target_key, created_at
            FROM operations WHERE rowid > ? ORDER BY rowid
            """,
            (int(review["operation_cutoff_rowid"]),),
        ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _reconciliation_finding_row(row: sqlite3.Row) -> dict[str, Any]:
        item = dict(row)
        item["targets"] = _load(item.pop("targets_json"), [])
        item["review_evidence_refs"] = _load(
            item.pop("review_evidence_refs_json"), []
        )
        item["resolution_evidence_refs"] = _load(
            item.pop("resolution_evidence_refs_json"), []
        )
        item["operation_ids"] = _load(item.pop("operation_ids_json"), [])
        return item

    def begin_reconciliation_round(
        self,
        *,
        semantic_digest: str,
        checkpoint: Mapping[str, Any],
        review_path: str | None = None,
    ) -> dict[str, Any]:
        digest = str(semantic_digest or "").strip()
        if not digest:
            raise JournalError("Reconciliation requires a semantic digest")
        round_id = stable_id("reconciliation-round", digest, utc_now())
        now = utc_now()
        self.connection.execute(
            """
            INSERT INTO reconciliation_rounds(
                round_id, semantic_digest, checkpoint_json, state,
                review_path, report_digest, created_at, updated_at
            ) VALUES(?, ?, ?, 'collecting', ?, NULL, ?, ?)
            """,
            (round_id, digest, _json(dict(checkpoint)), review_path, now, now),
        )
        self.connection.commit()
        return self.reconciliation_round(round_id) or {}

    def reconciliation_round(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM reconciliation_rounds WHERE round_id = ?", (round_id,)
        ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["checkpoint"] = _load(item.pop("checkpoint_json"), {})
        return item

    def latest_reconciliation_round(self) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT round_id FROM reconciliation_rounds "
            "ORDER BY created_at DESC, round_id DESC LIMIT 1"
        ).fetchone()
        return self.reconciliation_round(str(row["round_id"])) if row else None

    def fail_reconciliation_round(self, round_id: str) -> dict[str, Any]:
        row = self.reconciliation_round(round_id)
        if row is None:
            raise JournalError("Unknown reconciliation round: %s" % round_id)
        if row["state"] == "failed":
            return row
        if row["state"] != "collecting":
            raise JournalError(
                "Only a collecting reconciliation round may fail"
            )
        self.connection.execute(
            "UPDATE reconciliation_rounds SET state = 'failed', updated_at = ? "
            "WHERE round_id = ?",
            (utc_now(), round_id),
        )
        self.connection.commit()
        return self.reconciliation_round(round_id) or {}

    @staticmethod
    def _reconciliation_wave_key(finding: Mapping[str, Any]) -> tuple[Any, ...]:
        priority_order = {"high": 0, "medium": 1, "low": 2}
        return (
            priority_order.get(str(finding.get("priority") or "low"), 9),
            str(finding.get("parent_gap_id") or finding.get("finding_id") or ""),
            str(finding.get("component_id") or ""),
            str(finding.get("finding_id") or ""),
        )

    @staticmethod
    def _reconciliation_target_identity(target: Mapping[str, Any]) -> str:
        """Return the immutable exact anchor of one review target."""

        def address_identity(value: Any) -> str:
            raw = str(value or "").strip().lower()
            try:
                return hex(int(raw, 0))
            except (TypeError, ValueError):
                return raw

        kind = str(target.get("kind") or "")
        value: dict[str, Any] = {
            "kind": kind,
            "component_id": str(target.get("component_id") or ""),
        }
        if kind in {"function", "address", "global"}:
            value["address"] = address_identity(target.get("address"))
        elif kind == "named_type":
            value["name"] = str(target.get("name") or "")
        elif kind == "local_variable":
            value["function_address"] = address_identity(
                target.get("function_address")
            )
            value["lvar_index"] = target.get("lvar_index")
            value["current_name"] = str(target.get("current_name") or "")
        elif kind == "relationship":
            value["source_address"] = address_identity(
                target.get("source_address")
            )
            value["callsite_address"] = address_identity(
                target.get("callsite_address")
            )
            value["destination_address"] = address_identity(
                target.get("destination_address")
            )
            value["relationship_kind"] = str(
                target.get("relationship_kind") or ""
            )
        return canonical_json(value)

    def record_reconciliation_findings(
        self,
        *,
        round_id: str,
        findings: Iterable[Mapping[str, Any]],
        report_digest: str,
        review_path: str,
    ) -> dict[str, Any]:
        round_row = self.reconciliation_round(round_id)
        if round_row is None or round_row["state"] != "collecting":
            raise JournalError("Reconciliation round is not collecting")
        normalized = [dict(row) for row in findings]
        if len(normalized) > RECONCILIATION_MAX_FINDINGS:
            raise JournalError(
                "Reconciliation campaign exceeds the %d-finding limit"
                % RECONCILIATION_MAX_FINDINGS
            )
        for finding in normalized:
            targets = list(finding.get("targets") or [])
            if not targets or len(targets) > RECONCILIATION_MAX_TARGETS_PER_FINDING:
                raise JournalError(
                    "Reconciliation findings require 1-%d exact targets"
                    % RECONCILIATION_MAX_TARGETS_PER_FINDING
                )
        wave_keys = sorted({self._reconciliation_wave_key(row) for row in normalized})
        waves = {key: index + 1 for index, key in enumerate(wave_keys)}
        now = utc_now()
        actionable = 0
        semantic_digest = str(round_row["semantic_digest"])
        for finding in normalized:
            priority = str(finding.get("priority") or "low")
            initial_state = "open" if priority in {"high", "medium"} else "advisory"
            source_id = str(finding.get("finding_id") or "").strip()
            if not source_id:
                raise JournalError("Reconciliation finding lacks finding_id")
            prior = self.connection.execute(
                """
                SELECT f.state, f.rationale, f.resolution_evidence_refs_json,
                       f.operation_ids_json
                FROM reconciliation_findings f
                JOIN reconciliation_rounds r ON r.round_id = f.round_id
                WHERE r.semantic_digest = ? AND f.source_finding_id = ?
                  AND f.round_id != ?
                  AND f.state IN ('applied', 'rejected', 'deferred')
                ORDER BY f.updated_at DESC LIMIT 1
                """,
                (semantic_digest, source_id, round_id),
            ).fetchone()
            if prior is not None and initial_state == "open":
                initial_state = str(prior["state"])
            actionable += initial_state == "open"
            finding_id = stable_id(
                "reconciliation-finding", round_id, source_id,
                finding.get("component_id"), finding.get("targets"),
            )
            self.connection.execute(
                """
                INSERT INTO reconciliation_findings(
                    finding_id, round_id, source_finding_id, parent_gap_id,
                    classification, priority, component_id, wave, title,
                    current_claim, evidence_summary, consequence,
                    recommended_verification, targets_json,
                    review_evidence_refs_json, state, created_at, updated_at
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding_id, round_id, source_id,
                    finding.get("parent_gap_id"),
                    str(finding.get("classification") or "coverage_gap"),
                    priority, str(finding.get("component_id")),
                    waves[self._reconciliation_wave_key(finding)],
                    str(finding.get("title") or source_id),
                    str(finding.get("current_claim") or ""),
                    str(finding.get("evidence_summary") or ""),
                    str(finding.get("consequence") or ""),
                    str(finding.get("recommended_verification") or ""),
                    _json(list(finding.get("targets") or [])),
                    _json(list(finding.get("evidence_refs") or [])), initial_state,
                    now, now,
                ),
            )
            if prior is not None and initial_state in {
                "applied", "rejected", "deferred"
            }:
                self.connection.execute(
                    "UPDATE reconciliation_findings SET rationale = ?, "
                    "resolution_evidence_refs_json = ?, operation_ids_json = ?, "
                    "updated_at = ? WHERE finding_id = ?",
                    (
                        "Carried from an identical finding at the same semantic digest: "
                        + str(prior["rationale"]),
                        str(prior["resolution_evidence_refs_json"]),
                        str(prior["operation_ids_json"]), now, finding_id,
                    ),
                )
        state = "open" if actionable else "clear"
        self.connection.execute(
            "UPDATE reconciliation_rounds SET state = ?, review_path = ?, "
            "report_digest = ?, updated_at = ? WHERE round_id = ?",
            (state, str(review_path), str(report_digest), now, round_id),
        )
        self.connection.commit()
        return self.reconciliation_status()

    def reconciliation_finding(self, finding_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM reconciliation_findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        return self._reconciliation_finding_row(row) if row else None

    def link_reconciliation_call_flow(
        self, *, finding_id: str, scope_id: str
    ) -> dict[str, Any]:
        finding = self.reconciliation_finding(finding_id)
        if finding is None or finding["state"] not in {"open", "investigating"}:
            raise JournalError("Reconciliation finding is not active")
        self.connection.execute(
            "UPDATE reconciliation_findings SET state = 'investigating', "
            "call_flow_scope_id = ?, updated_at = ? WHERE finding_id = ?",
            (scope_id, utc_now(), finding_id),
        )
        self.connection.commit()
        return self.reconciliation_finding(finding_id) or {}

    def disposition_reconciliation_finding(
        self,
        *,
        finding_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Iterable[str],
        operation_ids: Iterable[str] = (),
        revised_title: str = "",
        revised_verification: str = "",
        revised_targets: Iterable[Mapping[str, Any]] = (),
    ) -> dict[str, Any]:
        finding = self.reconciliation_finding(finding_id)
        if finding is None or finding["state"] not in {"open", "investigating"}:
            raise JournalError("Reconciliation finding is not active")
        selected = str(outcome or "").strip().lower()
        if selected not in RECONCILIATION_FINDING_OUTCOMES:
            raise JournalError("Unsupported reconciliation outcome: %s" % selected)
        reason = str(rationale or "").strip()
        refs = list(dict.fromkeys(str(value) for value in evidence_refs if value))
        operations = list(dict.fromkeys(str(value) for value in operation_ids if value))
        if not reason or not refs:
            raise JournalError("Reconciliation disposition requires rationale and evidence")
        disposition_id = stable_id(
            "reconciliation-disposition", finding_id, selected, refs, operations
        )
        now = utc_now()
        with self.transaction() as connection:
            if selected == "revised":
                title = str(revised_title or "").strip()
                verification = str(revised_verification or "").strip()
                targets = [dict(row) for row in revised_targets]
                if not title or not verification or not targets:
                    raise JournalError(
                        "Revised findings require a title, verification question, and targets"
                    )
                if len(targets) > RECONCILIATION_MAX_TARGETS_PER_FINDING:
                    raise JournalError(
                        "Revised finding exceeds the %d-target limit"
                        % RECONCILIATION_MAX_TARGETS_PER_FINDING
                    )
                original_identities = {
                    self._reconciliation_target_identity(row)
                    for row in finding.get("targets") or []
                }
                revised_identities = {
                    self._reconciliation_target_identity(row) for row in targets
                }
                if not revised_identities.issubset(original_identities):
                    raise JournalError(
                        "A frozen reconciliation finding may be narrowed but cannot "
                        "introduce new targets"
                    )
                scope_id = finding.get("call_flow_scope_id")
                scope = self.call_flow_scope(str(scope_id)) if scope_id else None
                if scope and scope["state"] not in {
                    "closed", "closed_no_internal_calls",
                }:
                    raise JournalError(
                        "An active linked call-flow scope must be resolved before "
                        "the finding can be revised"
                    )
                connection.execute(
                    "UPDATE reconciliation_findings SET title = ?, "
                    "recommended_verification = ?, targets_json = ?, state = 'open', "
                    "rationale = ?, resolution_evidence_refs_json = ?, "
                    "operation_ids_json = '[]', call_flow_scope_id = NULL, "
                    "revision_count = revision_count + 1, updated_at = ? "
                    "WHERE finding_id = ?",
                    (title, verification, _json(targets), reason, _json(refs),
                     now, finding_id),
                )
            else:
                if selected == "applied" and not operations:
                    scope_id = finding.get("call_flow_scope_id")
                    scope = self.call_flow_scope(str(scope_id)) if scope_id else None
                    if not scope or scope["state"] not in {
                        "closed", "closed_no_internal_calls",
                    }:
                        raise JournalError(
                            "Applied findings require verified operations or a closed linked call-flow scope"
                        )
                connection.execute(
                    "UPDATE reconciliation_findings SET state = ?, rationale = ?, "
                    "resolution_evidence_refs_json = ?, operation_ids_json = ?, "
                    "updated_at = ? WHERE finding_id = ?",
                    (selected, reason, _json(refs), _json(operations), now, finding_id),
                )
            active = connection.execute(
                "SELECT COUNT(*) AS count FROM reconciliation_findings "
                "WHERE round_id = ? AND state IN ('open', 'investigating')",
                (finding["round_id"],),
            ).fetchone()
            if int(active["count"]) == 0:
                connection.execute(
                    "UPDATE reconciliation_rounds SET state = 'addressed', updated_at = ? "
                    "WHERE round_id = ?",
                    (now, finding["round_id"]),
                )
            self._record_reconciliation_activity_in_transaction(
                connection,
                finding_id=finding_id,
                activity_kind="disposition",
                external_id=disposition_id,
                component_id=str(finding["component_id"]),
                target_kind="finding",
                target_key=finding_id,
                status=selected,
                provenance="model_evidence_disposition",
                now=now,
            )
        return self.reconciliation_status()

    def reconciliation_status(self) -> dict[str, Any]:
        round_row = self.latest_reconciliation_round()
        if round_row is None:
            return {
                "enabled": True,
                "state": "not_run",
                "round": None,
                "current_wave": None,
                "findings": [],
                "open_count": 0,
            }
        rows = [
            self._reconciliation_finding_row(row)
            for row in self.connection.execute(
                "SELECT * FROM reconciliation_findings WHERE round_id = ? "
                "ORDER BY wave, priority, finding_id",
                (round_row["round_id"],),
            ).fetchall()
        ]
        for row in rows:
            finding_id = str(row["finding_id"])
            activity = self.reconciliation_activity(finding_id, limit=40)
            counts = {
                str(item["activity_kind"]): int(item["count"])
                for item in self.connection.execute(
                    "SELECT activity_kind, COUNT(*) AS count FROM "
                    "reconciliation_activity WHERE finding_id = ? "
                    "GROUP BY activity_kind",
                    (finding_id,),
                ).fetchall()
            }
            failed_operations = int(self.connection.execute(
                "SELECT COUNT(*) AS count FROM reconciliation_activity "
                "WHERE finding_id = ? AND activity_kind = 'operation' "
                "AND status NOT IN ('verified', 'verified_existing')",
                (finding_id,),
            ).fetchone()["count"])
            last_activity = self.connection.execute(
                "SELECT created_at FROM reconciliation_activity "
                "WHERE finding_id = ? ORDER BY created_at DESC, activity_id DESC "
                "LIMIT 1",
                (finding_id,),
            ).fetchone()
            row["activity"] = activity
            row["activity_summary"] = {
                "inspection_count": counts.get("inspection", 0),
                "operation_count": counts.get("operation", 0),
                "disposition_count": counts.get("disposition", 0),
                "failed_operation_count": failed_operations,
                "last_activity_at": (
                    last_activity["created_at"] if last_activity else None
                ),
                "activity_tail_count": len(activity),
                "activity_tail_limit": 40,
            }
        active = [row for row in rows if row["state"] in {"open", "investigating"}]
        mandatory = [row for row in rows if row["state"] != "advisory"]
        terminal = [
            row for row in mandatory
            if row["state"] in {"applied", "rejected", "deferred"}
        ]
        current_wave = min((int(row["wave"]) for row in active), default=None)
        visible = [row for row in active if int(row["wave"]) == current_wave]
        finding_set_digest = hashlib.sha256(canonical_json([
            {
                "source_finding_id": row["source_finding_id"],
                "priority": row["priority"],
                "component_id": row["component_id"],
                "targets": row["targets"],
            }
            for row in rows
        ]).encode("utf-8")).hexdigest()
        audit = self.reconciliation_audit(str(round_row["round_id"]))
        return {
            "enabled": True,
            "state": round_row["state"],
            "round": round_row,
            "current_wave": current_wave,
            "findings": visible,
            "open_count": len(active),
            "total_count": len(rows),
            "resolution_audit": {
                "finding_set_frozen": round_row["state"] != "collecting",
                "finding_set_digest": finding_set_digest,
                "mandatory_count": len(mandatory),
                "terminal_count": len(terminal),
                "active_finding_ids": [row["finding_id"] for row in active],
                "all_mandatory_findings_resolved": (
                    round_row["state"] in {"clear", "addressed"} and not active
                ),
                "durable_audit": audit,
            },
            "next_action": (
                "run_read_only_reconciliation"
                if round_row["state"] == "collecting"
                else "resolve_current_wave"
                if active else "none"
            ),
        }

    def reconciliation_audit(self, round_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM reconciliation_audits WHERE round_id = ?",
            (round_id,),
        ).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["checkpoints"] = _load(result.pop("checkpoint_json"), {})
        result["details"] = _load(result.pop("details_json"), {})
        return result

    def record_reconciliation_audit(
        self,
        *,
        round_id: str,
        finding_set_digest: str,
        completion_digest: str,
        checkpoints: Mapping[str, Any],
        details: Mapping[str, Any],
        state: str = "verified",
    ) -> dict[str, Any]:
        round_row = self.reconciliation_round(round_id)
        if round_row is None or round_row["state"] not in {"clear", "addressed"}:
            raise JournalError("Only a resolved reconciliation round can be audited")
        existing = self.reconciliation_audit(round_id)
        if existing is not None:
            if (
                existing["finding_set_digest"] != finding_set_digest
                or existing["completion_digest"] != completion_digest
            ):
                raise JournalError("Reconciliation audit identity changed")
            return existing
        now = utc_now()
        audit_id = stable_id(
            "reconciliation-audit",
            round_id,
            finding_set_digest,
            completion_digest,
        )
        self.connection.execute(
            """
            INSERT INTO reconciliation_audits(
                audit_id, round_id, finding_set_digest, completion_digest,
                checkpoint_json, details_json, state, created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                audit_id,
                round_id,
                finding_set_digest,
                completion_digest,
                _json(dict(checkpoints)),
                _json(dict(details)),
                state,
                now,
            ),
        )
        self.connection.commit()
        return self.reconciliation_audit(round_id) or {}

    def reconciliation_history(self, *, limit: int = 80) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            """
            SELECT f.*, r.semantic_digest
            FROM reconciliation_findings f
            JOIN reconciliation_rounds r ON r.round_id = f.round_id
            WHERE f.state IN ('applied', 'rejected', 'deferred')
            ORDER BY f.updated_at DESC, f.finding_id DESC LIMIT ?
            """,
            (max(1, min(int(limit), 200)),),
        ).fetchall()
        history = []
        for row in rows:
            item = self._reconciliation_finding_row(row)
            history.append({
                key: item.get(key)
                for key in (
                    "finding_id", "round_id", "source_finding_id",
                    "semantic_digest", "component_id", "priority", "title",
                    "targets", "state", "rationale", "operation_ids",
                )
            })
        return history

    def completion_status(self) -> dict[str, Any]:
        rows = self.connection.execute(
            """
            SELECT * FROM frontier_candidates
            WHERE lane = 'must_review' AND state IN ('open', 'investigating')
            ORDER BY tier, candidate_id
            """
        ).fetchall()
        blockers = [self._candidate_row(row) for row in rows]
        suggested_count = int(self.connection.execute(
            "SELECT COUNT(*) AS count FROM frontier_candidates "
            "WHERE lane = 'suggested_next' AND state IN ('open', 'investigating')"
        ).fetchone()["count"])
        mechanical = self.mechanical_issues()
        component_decisions = [
            self._extraction_row(row)
            for row in self.connection.execute(
                """
                SELECT * FROM extractions
                WHERE status IN ('pending_model_decision', 'failed')
                ORDER BY created_at, extraction_id
                """
            ).fetchall()
        ]
        call_flow = self.call_flow_summary()
        call_flow_blockers = list(call_flow["active_scopes"])
        reconciliation = self.reconciliation_status()
        reconciliation_blockers = list(reconciliation.get("findings") or [])
        checkpoint_failures = []
        for component in self.components():
            if component.get("idb_path"):
                checkpoint = self.latest_checkpoint(str(component["component_id"]))
                if checkpoint and checkpoint["status"] != "verified":
                    checkpoint_failures.append(checkpoint)
        ready_for_checkpoint = not (
            blockers or mechanical or component_decisions
            or call_flow_blockers or reconciliation_blockers
        )
        return {
            "may_finish": ready_for_checkpoint and not checkpoint_failures,
            "ready_for_checkpoint": ready_for_checkpoint,
            "component_verification_failures": checkpoint_failures,
            "must_review": blockers,
            "suggested_next_count": suggested_count,
            "mechanical_failures": mechanical,
            "component_decisions_required": component_decisions,
            "call_flow": call_flow,
            "call_flow_scopes_required": call_flow_blockers,
            "coverage_reconciliation": reconciliation,
            "reconciliation_findings_required": reconciliation_blockers,
            "policy": (
                "require_open_must_review_disposition, component recovery decision, "
                "closed selected claim-scoped call flow, resolved reconciliation wave, "
                "and no current mechanical or component checkpoint failure; "
                "suggested_next is nonblocking"
            ),
        }

    def record_extraction(
        self,
        *,
        extraction_id: str,
        parent_component_id: str,
        request: Mapping[str, Any],
        status: str,
        validation: Mapping[str, Any] | None = None,
        artifact_sha256: str | None = None,
        artifact_path: str | Path | None = None,
        child_component_id: str | None = None,
    ) -> dict[str, Any]:
        now = utc_now()
        existing = self.connection.execute(
            "SELECT created_at FROM extractions WHERE extraction_id = ?",
            (extraction_id,),
        ).fetchone()
        self.connection.execute(
            """
            INSERT INTO extractions(
                extraction_id, parent_component_id, child_component_id,
                request_json, status, artifact_sha256, artifact_path,
                validation_json, created_at, updated_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(extraction_id) DO UPDATE SET
                child_component_id = excluded.child_component_id,
                status = excluded.status,
                artifact_sha256 = excluded.artifact_sha256,
                artifact_path = excluded.artifact_path,
                validation_json = excluded.validation_json,
                updated_at = excluded.updated_at
            """,
            (
                extraction_id,
                parent_component_id,
                child_component_id,
                canonical_json(request),
                status,
                artifact_sha256,
                str(Path(artifact_path).resolve()) if artifact_path else None,
                canonical_json(dict(validation or {})),
                existing["created_at"] if existing else now,
                now,
            ),
        )
        self.connection.commit()
        return self._extraction_row(self.connection.execute(
            "SELECT * FROM extractions WHERE extraction_id = ?", (extraction_id,)
        ).fetchone())

    @staticmethod
    def _extraction_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["request"] = _load(result.pop("request_json"), {})
        result["validation"] = _load(result.pop("validation_json"), {})
        return result

    def active_reconciliation_finding(self) -> dict[str, Any] | None:
        """Return the one finding whose wave currently owns application work."""

        round_row = self.latest_reconciliation_round()
        if round_row is None or round_row["state"] not in {"open", "addressed"}:
            return None
        row = self.connection.execute(
            "SELECT * FROM reconciliation_findings WHERE round_id = ? "
            "AND state IN ('open', 'investigating') ORDER BY wave, priority, "
            "finding_id LIMIT 1",
            (round_row["round_id"],),
        ).fetchone()
        return self._reconciliation_finding_row(row) if row else None

    def _record_reconciliation_activity_in_transaction(
        self,
        connection: sqlite3.Connection,
        *,
        finding_id: str,
        activity_kind: str,
        external_id: str,
        component_id: str,
        target_kind: str,
        target_key: str,
        status: str,
        provenance: str,
        now: str,
    ) -> dict[str, Any]:
        finding = connection.execute(
            "SELECT 1 FROM reconciliation_findings WHERE finding_id = ?",
            (finding_id,),
        ).fetchone()
        if finding is None:
            raise JournalError("Unknown reconciliation finding: %s" % finding_id)
        component = connection.execute(
            "SELECT 1 FROM components WHERE component_id = ?", (component_id,)
        ).fetchone()
        if component is None:
            raise JournalError("Unknown reconciliation activity component")
        allowed = {"inspection", "operation", "disposition", "call_flow"}
        if activity_kind not in allowed:
            raise JournalError("Unsupported reconciliation activity kind")
        activity_id = stable_id(
            "reconciliation-activity",
            finding_id,
            activity_kind,
            external_id,
        )
        connection.execute(
            """
            INSERT INTO reconciliation_activity(
                activity_id, finding_id, activity_kind, external_id,
                component_id, target_kind, target_key, status, provenance,
                created_at
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(finding_id, activity_kind, external_id) DO UPDATE SET
                status = excluded.status,
                provenance = excluded.provenance
            """,
            (
                activity_id,
                finding_id,
                activity_kind,
                external_id,
                component_id,
                target_kind,
                target_key,
                status,
                provenance,
                now,
            ),
        )
        row = connection.execute(
            "SELECT * FROM reconciliation_activity WHERE activity_id = ?",
            (activity_id,),
        ).fetchone()
        return dict(row) if row else {}

    def record_reconciliation_activity(
        self,
        *,
        finding_id: str,
        activity_kind: str,
        external_id: str,
        component_id: str,
        target_kind: str,
        target_key: str,
        status: str,
        provenance: str,
    ) -> dict[str, Any]:
        with self.transaction() as connection:
            return self._record_reconciliation_activity_in_transaction(
                connection,
                finding_id=finding_id,
                activity_kind=activity_kind,
                external_id=external_id,
                component_id=component_id,
                target_kind=target_kind,
                target_key=target_key,
                status=status,
                provenance=provenance,
                now=utc_now(),
            )

    def reconciliation_activity(
        self, finding_id: str, *, limit: int = 500
    ) -> list[dict[str, Any]]:
        return [
            dict(row)
            for row in self.connection.execute(
                "SELECT * FROM (SELECT * FROM reconciliation_activity "
                "WHERE finding_id = ? ORDER BY created_at DESC, activity_id DESC "
                "LIMIT ?) ORDER BY created_at, activity_id",
                (finding_id, max(1, min(int(limit), 2000))),
            ).fetchall()
        ]

    def backfill_active_reconciliation_activity(self) -> dict[str, Any]:
        """Conservatively bind pre-v10 exact-target work in an interrupted wave."""

        finding = self.active_reconciliation_finding()
        if finding is None:
            return {"finding_id": None, "operation_count": 0, "inspection_count": 0}
        prior = self.connection.execute(
            "SELECT MAX(updated_at) AS cutoff FROM reconciliation_findings "
            "WHERE round_id = ? AND state IN ('applied', 'rejected', 'deferred')",
            (finding["round_id"],),
        ).fetchone()
        cutoff = str((prior or {})["cutoff"] or finding["created_at"])
        target_keys = {
            self._reconciliation_target_identity(dict(target))
            for target in finding.get("targets") or []
        }
        operation_count = 0
        for row in self.connection.execute(
            "SELECT * FROM operations WHERE created_at > ? ORDER BY rowid",
            (cutoff,),
        ).fetchall():
            request = _load(row["request_json"], {})
            target = dict(request.get("target") or {})
            target.setdefault("component_id", str(row["component_id"]))
            if self._reconciliation_target_identity(target) not in target_keys:
                continue
            receipt = self.connection.execute(
                "SELECT status FROM receipts WHERE operation_id = ? "
                "ORDER BY rowid DESC LIMIT 1",
                (row["operation_id"],),
            ).fetchone()
            self.record_reconciliation_activity(
                finding_id=str(finding["finding_id"]),
                activity_kind="operation",
                external_id=str(row["operation_id"]),
                component_id=str(row["component_id"]),
                target_kind=str(row["target_kind"]),
                target_key=str(row["target_key"]),
                status=str(receipt["status"] if receipt else "unknown"),
                provenance="host_exact_target_backfill",
            )
            operation_count += 1
        inspection_count = 0
        for row in self.connection.execute(
            "SELECT * FROM inspections WHERE created_at > ? ORDER BY rowid",
            (cutoff,),
        ).fetchall():
            if str(row["component_id"]) != str(finding["component_id"]):
                continue
            self.record_reconciliation_activity(
                finding_id=str(finding["finding_id"]),
                activity_kind="inspection",
                external_id=str(row["evidence_id"]),
                component_id=str(row["component_id"]),
                target_kind=str(row["target_kind"]),
                target_key=str(row["target_key"]),
                status="recorded",
                provenance="host_active_wave_backfill",
            )
            inspection_count += 1
        return {
            "finding_id": finding["finding_id"],
            "operation_count": operation_count,
            "inspection_count": inspection_count,
        }

    def extraction(self, extraction_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM extractions WHERE extraction_id = ?", (extraction_id,)
        ).fetchone()
        if row is None:
            return None
        return self._extraction_row(row)

    @staticmethod
    def _run_attempt_row(row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        result["error"] = _load(result.pop("error_json"), {})
        return result

    def begin_run_attempt(self, *, segment_id: str, phase: str) -> dict[str, Any]:
        """Start an attempt after the caller acquired the exclusive project lock.

        Rows are provenance, not process leases. Runtime ownership establishes
        that any previous controller is gone before these rows are recovered.
        """

        now = utc_now()
        stale = self.connection.execute(
            "SELECT attempt_id FROM run_attempts WHERE status = 'running'"
        ).fetchall()
        for row in stale:
            self.connection.execute(
                "UPDATE run_attempts SET status = 'interrupted', ended_at = ?, "
                "heartbeat_at = ?, error_json = ? WHERE attempt_id = ?",
                (
                    now,
                    now,
                    _json({
                        "code": "stale_running_attempt",
                        "message": (
                            "A later invocation found this attempt without a "
                            "terminal record. The prior process ended uncleanly."
                        ),
                    }),
                    row["attempt_id"],
                ),
            )
        finding = self.active_reconciliation_finding()
        round_row = self.latest_reconciliation_round()
        attempt_id = stable_id("run-attempt", segment_id, now)
        self.connection.execute(
            """
            INSERT INTO run_attempts(
                attempt_id, segment_id, phase, status, active_round_id,
                active_finding_id, active_wave, last_event_kind,
                last_response_id, last_tool, error_json, started_at,
                heartbeat_at, ended_at
            ) VALUES(?, ?, ?, 'running', ?, ?, ?, 'attempt_started',
                     NULL, NULL, '{}', ?, ?, NULL)
            """,
            (
                attempt_id,
                segment_id,
                phase,
                round_row.get("round_id") if round_row else None,
                finding.get("finding_id") if finding else None,
                int(finding["wave"]) if finding else None,
                now,
                now,
            ),
        )
        self.connection.commit()
        return self.run_attempt(attempt_id) or {}

    def run_attempt(self, attempt_id: str) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM run_attempts WHERE attempt_id = ?", (attempt_id,)
        ).fetchone()
        return self._run_attempt_row(row) if row else None

    def heartbeat_run_attempt(
        self,
        attempt_id: str,
        *,
        phase: str,
        event_kind: str,
        response_id: str | None = None,
        tool: str | None = None,
    ) -> dict[str, Any]:
        attempt = self.run_attempt(attempt_id)
        if attempt is None or attempt["status"] != "running":
            raise JournalError("Run attempt is not active")
        finding = self.active_reconciliation_finding()
        round_row = self.latest_reconciliation_round()
        now = utc_now()
        self.connection.execute(
            """
            UPDATE run_attempts SET phase = ?, active_round_id = ?,
                active_finding_id = ?, active_wave = ?, last_event_kind = ?,
                last_response_id = COALESCE(?, last_response_id),
                last_tool = COALESCE(?, last_tool), heartbeat_at = ?
            WHERE attempt_id = ?
            """,
            (
                phase,
                round_row.get("round_id") if round_row else None,
                finding.get("finding_id") if finding else None,
                int(finding["wave"]) if finding else None,
                event_kind,
                response_id,
                tool,
                now,
                attempt_id,
            ),
        )
        self.connection.commit()
        return self.run_attempt(attempt_id) or {}

    def finish_run_attempt(
        self,
        attempt_id: str,
        *,
        status: str,
        phase: str,
        error: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        allowed = {
            "completed", "interrupted", "failed", "safety_budget_exceeded",
            "completion_policy_unsatisfied",
        }
        if status not in allowed:
            raise JournalError("Unsupported terminal attempt status")
        attempt = self.run_attempt(attempt_id)
        if attempt is None:
            raise JournalError("Unknown run attempt")
        now = utc_now()
        self.connection.execute(
            "UPDATE run_attempts SET phase = ?, status = ?, error_json = ?, "
            "last_event_kind = 'attempt_finished', heartbeat_at = ?, ended_at = ? "
            "WHERE attempt_id = ?",
            (phase, status, _json(dict(error or {})), now, now, attempt_id),
        )
        self.connection.commit()
        return self.run_attempt(attempt_id) or {}

    def run_attempts(self, *, limit: int = 20) -> list[dict[str, Any]]:
        return [
            self._run_attempt_row(row)
            for row in self.connection.execute(
                "SELECT * FROM run_attempts ORDER BY started_at DESC LIMIT ?",
                (max(1, min(int(limit), 100)),),
            ).fetchall()
        ]

    def resume_summary(self) -> dict[str, Any]:
        active = self.connection.execute(
            """
            SELECT lane, state, COUNT(*) AS count FROM frontier_candidates
            WHERE state IN ('open', 'investigating')
            GROUP BY lane, state
            """
        ).fetchall()
        closure = self.latest_closure_review()
        closure_summary = None
        if closure:
            closure_summary = {
                key: closure.get(key)
                for key in (
                    "review_id", "epoch", "active_component_id", "packet_digest",
                    "candidate_count", "closure_update_id", "created_at",
                    "closure_updated_at",
                )
            }
            closure_summary["subsequent_operation_count"] = len(
                self.operations_after_closure_review(str(closure["review_id"]))
            )
        return {
            "components": self.components(),
            "active_frontier": {
                "%s:%s" % (row["lane"], row["state"]): int(row["count"])
                for row in active
            },
            "completion": self.completion_status(),
            "mechanical_issues": self.mechanical_issues(),
            "analysis_closure": closure_summary,
            "call_flow": self.call_flow_summary(),
            "coverage_reconciliation": self.reconciliation_status(),
            "run_attempts": self.run_attempts(limit=5),
            "readonly_idapython": {
                "request_count": int(self.connection.execute(
                    "SELECT COUNT(*) AS count FROM readonly_idapython_requests"
                ).fetchone()["count"]),
                "failed_or_rejected_count": int(self.connection.execute(
                    "SELECT COUNT(*) AS count FROM readonly_idapython_requests "
                    "WHERE status IN ('failed', 'rejected')"
                ).fetchone()["count"]),
            },
        }
