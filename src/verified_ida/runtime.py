"""Interactive Verified IDA runtime.

One model investigation spans a graph of binaries.  Each component owns a
separate IDB and at most one persistent IDA worker is active at a time.  The
IDB stores analysis, SQLite stores operational history, and reversing_log.md
stores model-authored current project state and material analytical revisions.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from readonly_ida_script import (
    MAX_WALL_SECONDS,
    ReadonlyScriptValidationError,
    capability_catalog,
    validate_readonly_script,
    write_readonly_wrapper,
)

from .contracts import (
    VERIFIED_STATUSES,
    build_receipt,
    canonical_json,
    operation_digest,
    utc_now,
    validate_operation,
)
from .closure_review import (
    build_closure_packet,
    declared_references,
    touched_function_addresses,
)
from .components import ComponentRecoveryService
from .child_environment import child_environment
from .errors import OperationError
from .project_lock import ProjectLock
from .frontier import AnalysisFrontier
from .journal import (
    CALL_FLOW_NODE_OUTCOMES,
    CALL_FLOW_PARENT_OUTCOMES,
    VerifiedIdaJournal,
    stable_id,
)
from .model_tools import READ_ONLY_QUERIES, READ_ONLY_QUERY_LIMITS
from .query_contract import (
    QUERY_FAMILIES,
    QueryContractError,
    capability_manifest,
    decode_cursor,
    encode_cursor,
    normalize_query,
    query_digest,
)
from .session import (
    PersistentIdaSession,
    atomic_promote_packed_ida_database,
    copy_packed_ida_database,
    retain_packed_ida_database,
)
from .semantic_delta import (
    classify_semantic_delta,
    migrated_checkpoint_digest,
    semantic_digest_exclusions,
    semantic_state_digest,
)
from .workspace import (
    append_reversing_log_journal as append_notebook_journal,
    ensure_reversing_log,
    read_reversing_log as read_notebook,
    update_reversing_log_section as update_notebook_section,
)
from static_extractor_script import validate_static_extractor_script
from component_extraction import recovery_capability_manifest
from .analysis_feedback import (
    ANALYSIS_FEEDBACK_COMPATIBILITY_PROFILES,
    ANALYSIS_FEEDBACK_PROFILES,
    analysis_feedback_schema,
    build_analysis_feedback,
    build_unapplied_type_advisory,
    load_checkpoint_state,
)


GLOBAL_IMPACT_KINDS = {
    "function.prototype.set",
    "global.rename",
    "global.type.set",
    "named_type.create_or_update",
}
MODEL_VISIBLE_SUGGESTION_LIMIT = 6
DISPOSABLE_RENDER_MEASUREMENT_KINDS = {
    "function.rename",
    "function.prototype.set",
    "local.type.set",
    "global.rename",
    "global.type.set",
}
DISPOSABLE_RENDER_MEASUREMENT_LIMIT = 16
SEMANTIC_DELTA_MEASUREMENT_KINDS = {
    "function.prototype.set",
    "local.type.set",
    "global.type.set",
    "named_type.create_or_update",
}


class RuntimeError(OperationError):
    """An actionable runtime or reference error."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json_atomic(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        handle.write(json.dumps(dict(payload), indent=2, sort_keys=True) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory_fd = os.open(str(path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _receipt_with_transaction(
    receipt: Mapping[str, Any], transaction: Mapping[str, Any]
) -> dict[str, Any]:
    enriched = dict(receipt)
    enriched["transaction"] = dict(transaction)
    return enriched


def _address(value: Any) -> str:
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        raise RuntimeError("Expected an integer or hexadecimal address") from None


def _compact_local(row: Mapping[str, Any]) -> dict[str, Any]:
    """Keep a local editable without returning its entire ctree history."""

    compact = dict(row)
    for key in ("use_sites", "assignment_sites"):
        if isinstance(compact.get(key), list):
            compact[key] = compact[key][:12]
    return compact


def _model_visible_result(query: str, result: Mapping[str, Any]) -> dict[str, Any]:
    """Bound high-volume IDA evidence while retaining the full journal copy."""

    visible = dict(result)
    if query == "inspect_function":
        native = visible.get("ida_native_summary")
        if isinstance(native, Mapping):
            native = dict(native)
            native.pop("local_variables", None)
            for key in (
                "assignments",
                "calls",
                "constants",
                "data_refs",
                "suspicious_expressions",
            ):
                if isinstance(native.get(key), list):
                    native[key] = native[key][:32]
            visible["ida_native_summary"] = native
    if query == "inspect_stack_frame":
        visible["local_variables"] = [
            _compact_local(row)
            for row in (visible.get("local_variables") or [])
            if isinstance(row, Mapping)
        ]
    return visible


def _compact_refresh(
    refreshed: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Return exact current metadata and frontier feedback, not another code dump."""

    if not refreshed:
        return None
    return {
        key: value
        for key, value in {
            "evidence_id": refreshed.get("evidence_id"),
            "target_ref": refreshed.get("target_ref"),
            "must_review": [
                _compact_frontier_candidate(row)
                for row in (refreshed.get("must_review") or [])
            ],
            "suggested_next": [
                _compact_frontier_candidate(row)
                for row in (refreshed.get("suggested_next") or [])
            ],
            "frontier_summary": refreshed.get("frontier_summary"),
        }.items()
        if value is not None
    }


def _compact_frontier_candidate(row: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: row[key]
        for key in (
            "candidate_id",
            "component_id",
            "target_kind",
            "target_key",
            "gap_kind",
            "lane",
            "priority",
            "reasons",
            "state",
        )
        if key in row
    }


def _value_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _text_state(value: Any) -> dict[str, Any]:
    text = str(value or "")
    return {
        "present": bool(text),
        "length": len(text),
        "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
    }


def _behavior_comment(value: Any) -> str:
    return "\n".join(
        line
        for line in str(value or "").strip().splitlines()
        if not line.startswith("[verified-folder] ")
        and not line.startswith("[verified-relationship:")
        and not line.startswith("[relationship:")
    ).strip()


def _compact_target(target: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: target[key]
        for key in (
            "kind",
            "address",
            "function_address",
            "lvar_index",
            "current_name",
            "name",
            "source_address",
            "callsite_address",
            "destination_address",
            "relationship_kind",
        )
        if key in target
    }


def _compact_observed_state(
    operation: Mapping[str, Any],
    receipt: Mapping[str, Any],
) -> dict[str, Any]:
    kind = str(operation.get("kind") or "")
    observed = dict(receipt.get("observed") or {})
    target = dict(operation.get("target") or {})
    if kind == "named_type.create_or_update":
        signature = observed.get("signature")
        if isinstance(signature, Mapping):
            members = signature.get("members") or []
            return {
                "name": observed.get("name") or target.get("name"),
                "type_kind": (
                    signature.get("udt_kind")
                    or (operation.get("desired") or {}).get("type_kind")
                    or signature.get("kind")
                ),
                "size": signature.get("size"),
                "member_count": len(members),
                "signature_sha256": _value_digest(signature),
            }
        return {
            "name": observed.get("name") or target.get("name"),
            "type_kind": (operation.get("desired") or {}).get("type_kind"),
            "declaration": _text_state(observed.get("declaration")),
        }
    if kind == "function.comment.set":
        comments = {
            key: str(value or "")
            for key, value in dict(observed.get("comments") or {}).items()
        }
        nonrepeatable = _behavior_comment(
            comments.get("nonrepeatable", "")
        )
        repeatable = _behavior_comment(comments.get("repeatable", ""))
        slot_relation = (
            "duplicate"
            if nonrepeatable and nonrepeatable == repeatable
            else "conflicting"
            if nonrepeatable and repeatable
            else "single"
            if nonrepeatable or repeatable
            else "empty"
        )
        return {
            "name": observed.get("name") or target.get("current_name"),
            "comment": _text_state(observed.get("comment")),
            "repeatable": observed.get("repeatable"),
            "comments": {
                key: _text_state(value)
                for key, value in comments.items()
            },
            "slot_relation": slot_relation,
        }
    if kind == "relationship.annotate":
        record = observed.get("record")
        return dict(record) if isinstance(record, Mapping) else observed
    return observed


def _compact_semantic_delta(delta: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not delta:
        return None
    result = dict(delta)
    for key, value in delta.items():
        if isinstance(value, list):
            result[key] = value[:12]
            result[key + "_count"] = len(value)
            result[key + "_truncated"] = len(value) > 12
    return result


def _compact_checkpoint(checkpoint: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not checkpoint:
        return None
    details = dict(checkpoint.get("details") or {})
    return {
        key: value
        for key, value in {
            "checkpoint_id": checkpoint.get("checkpoint_id"),
            "component_id": checkpoint.get("component_id"),
            "revision": checkpoint.get("revision"),
            "status": checkpoint.get("status"),
            "semantic_digest": details.get("semantic_digest"),
        }.items()
        if value is not None
    }


def _edit_result(
    *,
    component_id: str,
    operation: Mapping[str, Any],
    receipt: Mapping[str, Any],
    persistence_receipt: Mapping[str, Any] | None,
    database_revision: int,
    refreshed: Mapping[str, Any] | None,
    checkpoint: Mapping[str, Any] | None,
    analysis_feedback: Mapping[str, Any] | None = None,
    call_flow_feedback: Mapping[str, Any] | None = None,
    project_state_reminder: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    compact_refresh = _compact_refresh(refreshed) or {}
    effective_receipt = dict(persistence_receipt or receipt)
    status = str(effective_receipt.get("status") or "")
    result = {
        "schema": "verified_ida.edit_result.v1",
        "operation_id": operation["operation_id"],
        "component_id": component_id,
        "kind": operation["kind"],
        "target": _compact_target(operation.get("target") or {}),
        "status": status,
        "stage": effective_receipt.get("stage"),
        "persistence": effective_receipt.get("persistence"),
        "semantic_assessment": {
            "status": "not_assessed_by_host",
            "message": (
                "Host status and persistence fields assess only the requested "
                "IDA state; the model remains responsible for analytical correctness."
            ),
        },
        "database_revision": database_revision,
        "current": _compact_observed_state(operation, receipt),
        "decompiler_changed": (
            None
            if (receipt.get("effects") or {}).get("decompiler_changed") is None
            else bool((receipt.get("effects") or {}).get("decompiler_changed"))
        ),
        "decompiler_observation": {
            key: value
            for key, value in {
                "status": (receipt.get("effects") or {}).get("measurement"),
                "reason": (receipt.get("effects") or {}).get(
                    "measurement_reason"
                ),
                "rendering_complete": (receipt.get("effects") or {}).get("rendering_complete"),
            }.items()
            if value is not None
        },
        "checkpoint": _compact_checkpoint(checkpoint),
        "transaction": dict(receipt.get("transaction") or {}),
        "semantic_verification": _compact_semantic_delta((receipt.get("effects") or {}).get("semantic_delta")),
        "detail": {
            "tool": "inspect_ida_operation",
            "operation_id": operation["operation_id"],
        },
        **compact_refresh,
    }
    if project_state_reminder:
        result["project_state_reminder"] = dict(project_state_reminder)
    if analysis_feedback:
        result["analysis_feedback"] = dict(analysis_feedback)
    if call_flow_feedback:
        key = (
            "call_flow_advisory"
            if str(call_flow_feedback.get("schema") or "").startswith(
                "verified_ida.call_flow_advisory."
            )
            else "call_flow_feedback"
        )
        result[key] = dict(call_flow_feedback)
    if status not in VERIFIED_STATUSES:
        result["failure"] = {
            "errors": effective_receipt.get("errors") or [],
            "recovery": effective_receipt.get("recovery"),
            "desired": effective_receipt.get("desired"),
            "observed": effective_receipt.get("observed"),
            "normalization": effective_receipt.get("normalization") or {},
            "execution": effective_receipt.get("execution") or {},
        }
    return result


class VerifiedIdaRuntime:
    """Own persistent IDA lifecycle and immediate verified edit feedback."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        launcher: str | Path | None = None,
        worker_script: str | Path | None = None,
        session_factory: Callable[[Mapping[str, Any]], Any] | None = None,
        readonly_executor: Callable[..., Mapping[str, Any]] | None = None,
        readonly_runner: str | Path | None = None,
        checkpoint_interval: int = 8,
        project_objective: str | None = None,
        analysis_feedback_profile: str = "none",
        component_handoff_policy: str = "advisory",
        coverage_reconciliation: bool | None = None,
        read_only_mode: bool = False,
    ):
        self.workspace = Path(workspace).expanduser().resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self._project_lock = ProjectLock(self.workspace)
        try:
            self._initialize(
                launcher=launcher, worker_script=worker_script,
                session_factory=session_factory, readonly_executor=readonly_executor,
                readonly_runner=readonly_runner, checkpoint_interval=checkpoint_interval,
                project_objective=project_objective,
                analysis_feedback_profile=analysis_feedback_profile,
                component_handoff_policy=component_handoff_policy,
                coverage_reconciliation=coverage_reconciliation,
                read_only_mode=read_only_mode,
            )
        except BaseException:
            if hasattr(self, "journal"):
                self.journal.close()
            self._project_lock.close()
            raise

    def _initialize(
        self, *, launcher, worker_script, session_factory, readonly_executor,
        readonly_runner, checkpoint_interval, project_objective,
        analysis_feedback_profile, component_handoff_policy,
        coverage_reconciliation, read_only_mode,
    ) -> None:
        ensure_reversing_log(self.workspace)
        self.journal = VerifiedIdaJournal(self.workspace / "verified_ida.sqlite")
        self.project_objective = self.journal.bind_project_objective(
            project_objective
            or (
                "Reverse engineer the supplied program to a complete, "
                "evidence-supported understanding of its behavior and structure, "
                "and capture that understanding accurately in the IDA databases."
            )
        )
        self.coverage_reconciliation_enabled = (
            self.journal.bind_coverage_reconciliation(coverage_reconciliation)
        )
        self.frontier = AnalysisFrontier(self.journal)
        self.components = ComponentRecoveryService(self)
        self.launcher = Path(launcher).resolve() if launcher else (
            Path(__file__).resolve().parents[2] / "scripts" / "launch_ida_no_network.sh"
        )
        self.worker_script = Path(worker_script).resolve() if worker_script else (
            Path(__file__).resolve().parents[2] / "scripts" / "verified_ida_session_ida.py"
        )
        self.checkpoint_interval = max(1, int(checkpoint_interval))
        accepted_feedback_profiles = (
            ANALYSIS_FEEDBACK_PROFILES
            + ANALYSIS_FEEDBACK_COMPATIBILITY_PROFILES
        )
        if analysis_feedback_profile not in accepted_feedback_profiles:
            raise RuntimeError(
                "Unsupported analysis feedback profile: %s (choose %s)"
                % (
                    analysis_feedback_profile,
                    ", ".join(accepted_feedback_profiles),
                )
            )
        self.analysis_feedback_profile = analysis_feedback_profile
        if component_handoff_policy not in {"none", "advisory", "required"}:
            raise RuntimeError(
                "Unsupported component handoff policy: %s"
                % component_handoff_policy
            )
        self.component_handoff_policy = component_handoff_policy
        self.read_only_mode = bool(read_only_mode)
        self._session_factory = session_factory or self._default_session_factory
        self._readonly_executor = readonly_executor or self._default_readonly_executor
        self.readonly_runner = Path(readonly_runner).resolve() if readonly_runner else (
            Path(__file__).resolve().parents[2]
            / "scripts"
            / "run_ida_script_readonly_sandbox.sh"
        )
        self._session: Any | None = None
        self.active_component_id: str | None = None
        self._pending_analysis_advisories: list[dict[str, Any]] = []
        self._recover_mutation_transactions()

    def _recover_mutation_transactions(self) -> None:
        """Rollback or finish any transaction interrupted before journal commit."""

        root = self.workspace / "mutation_transactions"
        if not root.is_dir():
            return
        from .transaction_recovery import (
            TERMINAL_TRANSACTION_STATES, has_committed_attempt, recovery_paths,
        )
        for path in sorted(root.glob("*.json")):
            try:
                manifest = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(
                    "Unreadable mutation transaction manifest %s: %s" % (path, exc)
                ) from exc
            status = str(manifest.get("status") or "")
            if status in TERMINAL_TRANSACTION_STATES:
                continue
            if self.read_only_mode:
                raise RuntimeError("Read-only startup cannot recover an unsettled mutation")
            operation_id = str(manifest.get("operation_id") or "")
            component = self.journal.component(str(manifest.get("component_id") or ""))
            if component is None or path != self._mutation_manifest_path(operation_id):
                raise RuntimeError("Mutation recovery has an unknown component or manifest identity")
            try:
                canonical, rollback, candidate = recovery_paths(self.workspace, component, manifest)
            except ValueError as exc:
                raise RuntimeError(str(exc)) from exc
            transaction_dir = rollback.parent
            detail = self.journal.operation_detail(operation_id) if operation_id else None
            if status in {"prepared", "candidate_verified", "promotion_intent", "promoted_pending_journal"}:
                before_hash = manifest.get("canonical_before_sha256")
                after_hash = manifest.get("candidate_sha256")
                actual_hash = _sha256_file(canonical) if canonical.is_file() else None
                if has_committed_attempt(detail, manifest):
                    operation = detail.get("request") or {}
                    component_id = str(manifest.get("component_id") or "")
                    expected_revision = int(
                        ((operation.get("artifact") or {}).get("database_revision") or 0)
                    ) + 1
                    current_revision = int(
                        self.journal.revision(component_id)["revision"]
                    )
                    if current_revision < expected_revision or actual_hash != after_hash:
                        raise RuntimeError(
                            "Mutation %s journal/revision/IDB disagree; recovery "
                            "material retained for manual inspection" % operation_id
                        )
                    manifest["status"] = "committed"
                    manifest["recovery"] = "journal_commit_already_present"
                elif actual_hash == before_hash and before_hash:
                    manifest["status"] = "recovered_discard"
                    manifest["recovery"] = "canonical_matches_pre_mutation_hash"
                elif actual_hash == after_hash and after_hash:
                    if not rollback.is_file() or _sha256_file(rollback) != before_hash:
                        raise RuntimeError(
                            "Interrupted mutation %s has no verified rollback IDB; "
                            "recovery material retained" % operation_id
                        )
                    atomic_promote_packed_ida_database(rollback, canonical)
                    manifest["status"] = "recovered_rollback"
                    manifest["recovery"] = "promotion_had_no_journal_commit"
                    manifest["canonical_final_sha256"] = _sha256_file(canonical)
                else:
                    raise RuntimeError(
                        "Interrupted mutation %s has ambiguous canonical bytes; "
                        "recovery material retained" % operation_id
                    )
            else:
                raise RuntimeError(
                    "Unknown incomplete mutation transaction state %r in %s"
                    % (status, path)
                )
            _write_json_atomic(path, manifest)
            if candidate.is_file():
                candidate.unlink()
            shutil.rmtree(transaction_dir, ignore_errors=True)

    @classmethod
    def initialize(
        cls,
        workspace: str | Path,
        *,
        binary_path: str | Path | None = None,
        clean_idb_path: str | Path | None = None,
        **kwargs: Any,
    ) -> "VerifiedIdaRuntime":
        runtime = cls(workspace, **kwargs)
        try:
            runtime._initialize_root(binary_path=binary_path, clean_idb_path=clean_idb_path)
        except BaseException:
            runtime.close()
            raise
        return runtime

    def _initialize_root(self, *, binary_path, clean_idb_path) -> None:
        runtime = self
        if runtime.journal.component("root") is None:
            if binary_path is None or clean_idb_path is None:
                raise RuntimeError(
                    "A new project requires both the root binary and clean IDB"
                )
            source_binary = Path(binary_path).expanduser().resolve()
            source_idb = Path(clean_idb_path).expanduser().resolve()
            if not source_binary.is_file() or not source_idb.is_file():
                raise RuntimeError("Root binary and clean IDB must exist")
            root_dir = runtime.workspace / "components" / "root"
            root_dir.mkdir(parents=True, exist_ok=True)
            working_binary = root_dir / source_binary.name
            working_idb = root_dir / source_idb.name
            if working_binary != source_binary:
                shutil.copy2(source_binary, working_binary)
            if working_idb != source_idb:
                shutil.copy2(source_idb, working_idb)
            runtime.journal.register_component(
                component_id="root",
                binary_sha256=_sha256_file(working_binary),
                binary_path=working_binary,
                idb_path=working_idb,
                status="analysis_ready",
                provenance={
                    "kind": "initial_root",
                    "source_binary": str(source_binary),
                    "source_idb": str(source_idb),
                },
            )
        runtime.switch_component("root", checkpoint_current=False)

    def _default_session_factory(self, component: Mapping[str, Any]) -> PersistentIdaSession:
        log_dir = self.workspace / "ida_logs"
        return PersistentIdaSession(
            idb_path=component["idb_path"],
            input_binary_path=component.get("binary_path"),
            launcher=self.launcher,
            worker_script=self.worker_script,
            log_path=log_dir / (str(component["component_id"]) + ".log"),
            disposable_copy=self.read_only_mode,
        )

    @property
    def session(self) -> Any:
        if self._session is None or self.active_component_id is None:
            raise RuntimeError("No IDA component is active")
        return self._session

    def artifact(self, component_id: str | None = None) -> dict[str, Any]:
        component_key = component_id or self.active_component_id
        if not component_key:
            raise RuntimeError("No IDA component is active")
        component = self.journal.component(component_key)
        if component is None:
            raise RuntimeError("Unknown component: %s" % component_key)
        revision = self.journal.revision(component_key)
        return {
            "binary_sha256": component["binary_sha256"],
            "database_id": component_key,
            "database_revision": int(revision["revision"]),
        }

    @classmethod
    def _model_provenance(cls, value: Any) -> Any:
        """Preserve component lineage without presenting it as live evidence.

        Component provenance intentionally keeps the inspection identifiers that
        justified recovery.  Those identifiers remain useful for audit, but may
        be stale after the parent IDB advances.  Model-facing component views
        therefore give them an explicit provenance-only field instead of the
        ordinary live-evidence spelling used by current tool requests.
        """

        if isinstance(value, Mapping):
            result: dict[str, Any] = {}
            for key, item in value.items():
                projected_key = (
                    "historical_evidence_refs"
                    if str(key) == "evidence_refs"
                    else str(key)
                )
                result[projected_key] = cls._model_provenance(item)
            return result
        if isinstance(value, list):
            return [cls._model_provenance(item) for item in value]
        return value

    @classmethod
    def _model_component(cls, component: Mapping[str, Any]) -> dict[str, Any]:
        result = dict(component)
        result["provenance"] = cls._model_provenance(
            dict(component.get("provenance") or {})
        )
        result["evidence_contract"] = {
            "historical_evidence_refs": "provenance_only_not_citeable",
            "current_evidence_source": "acquire_with_live_read_only_tools",
        }
        return result

    def list_components(self) -> dict[str, Any]:
        return {
            "active_component_id": self.active_component_id,
            "components": [
                self._model_component(component)
                for component in self.journal.components()
            ],
        }

    def describe_ida_capabilities(self) -> dict[str, Any]:
        """Return the model-facing query and mutation contract for this backend."""

        response = self.session.query({"task_type": "describe_query_runtime"})
        survey = response.get("result", response)
        runtime = dict(survey.get("runtime") or {}) if isinstance(survey, Mapping) else {}
        binary = dict(survey.get("binary") or {}) if isinstance(survey, Mapping) else {}
        manifest = capability_manifest({
            **runtime,
            "architecture": binary.get("architecture"),
            "processor": binary.get("processor"),
            "decompiler_available": (
                (survey.get("analysis") or {}).get("decompiler_available")
                if isinstance(survey, Mapping)
                else None
            ),
        })
        manifest["artifact"] = self.artifact()
        manifest["function_comment_limits"] = survey.get("function_comment_limits") or {"status": "unavailable"}
        manifest["component_recovery"] = recovery_capability_manifest()
        manifest["component_handoff"] = {
            "schema": "verified_ida.component_handoff.capabilities.v1",
            "policy": self.component_handoff_policy,
            "default_behavior": (
                "Parent-to-child transitions report whether a fresh notebook "
                "bookmark was recorded after component acceptance."
            ),
            "required_profile_experimental": True,
        }
        manifest["analysis_feedback"] = {
            "schema": analysis_feedback_schema(self.analysis_feedback_profile),
            "profile": self.analysis_feedback_profile,
            "available_profiles": list(ANALYSIS_FEEDBACK_PROFILES),
            "provenance": "host_measured",
            "semantic_judgment": False,
            "description": (
                "When enabled, verified edit results may report bounded rendering "
                "propagation and current named-type application on measured semantic "
                "surfaces. scoped suppresses routine target-local rename and "
                "comment rendering noise, retains interface/type effects, and may "
                "re-present declaration-only type state at component transitions and "
                "closure. These facts do not establish analytical correctness or "
                "create completion obligations."
            ),
        }
        manifest["claim_scoped_call_flow"] = {
            "schema": "verified_ida.call_flow.capabilities.v4",
            "profile": "reconciliation_selected",
            "ordinary_edit_behavior": "nonblocking_direct_call_advisory",
            "trigger": "validated_coverage_reconciliation_finding",
            "blocking_edges": (
                "decoded direct calls to internal non-library non-thunk functions"
            ),
            "advisory_edges": [
                "direct_import", "direct_thunk", "direct_library",
                "tail_call", "unresolved_direct", "unresolved_indirect",
            ],
            "node_outcomes": sorted(CALL_FLOW_NODE_OUTCOMES),
            "parent_outcomes": sorted(CALL_FLOW_PARENT_OUTCOMES),
            "completion_policy": (
                "selected direct callees require evidence-backed dispositions; only an "
                "explicit unresolved boundary admits selected direct callees "
                "along one depth-first path; "
                "the parent requires bottom-up revalidation; ordinary annotations "
                "never create scopes automatically"
            ),
        }
        manifest["coverage_reconciliation"] = {
            "schema": "verified_ida.coverage_reconciliation.capabilities.v1",
            "enabled": self.coverage_reconciliation_enabled,
            "stage": "after_provisional_completion_before_final_completion",
            "review_mode": "frozen_read_only_system_then_artifact",
            "application": "bounded_waves_in_original_investigation_session",
        }
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="capability",
            target_key="ida_query_contract",
            query_kind="describe_ida_capabilities",
            result=manifest,
        )
        return {"ok": True, "evidence_id": evidence["evidence_id"], **manifest}

    def survey_idb(self, *, component_id: str | None = None) -> dict[str, Any]:
        """Return an IDA-window-like inventory without dumping collection contents."""

        if component_id and component_id != self.active_component_id:
            self._ensure_component_active(component_id)
        response = self.session.query({"task_type": "survey_idb"})
        result = dict(response.get("result", response))
        result["artifact"] = self.artifact()
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="database",
            target_key=str(self.active_component_id),
            query_kind="survey_idb",
            result=result,
        )
        return {"evidence_id": evidence["evidence_id"], **result}

    def query_ida_collection(
        self,
        *,
        family: str,
        filters: Mapping[str, Any] | None = None,
        order: str | None = None,
        limit: int = 100,
        cursor: str | None = None,
        component_id: str | None = None,
    ) -> dict[str, Any]:
        """Return one uniform, revision-bound page of an IDA collection."""

        if component_id and component_id != self.active_component_id:
            self._ensure_component_active(component_id)
        try:
            query = normalize_query(family, filters, order)
            definition = QUERY_FAMILIES[family]
            page_limit = max(1, min(int(limit), int(definition["maximum_page_size"])))
            artifact = self.artifact()
            offset = 0
            if cursor:
                offset = decode_cursor(
                    cursor,
                    component_id=str(self.active_component_id),
                    revision=int(artifact["database_revision"]),
                    query=query,
                )
        except QueryContractError as exc:
            return {"ok": False, "error": exc.as_dict()}
        response = self.session.query({
            "task_type": "query_%s" % family,
            "filters": query["filters"],
            "order": query["order"],
            "limit": page_limit,
            "offset": offset,
        })
        result = dict(response.get("result", response))
        if not result.get("ok"):
            return result
        result["artifact"] = artifact
        result["query"] = query
        page = dict(result.get("page") or {})
        next_offset = page.pop("next_offset", None)
        page["truncated"] = bool(page.get("has_more"))
        page["next_cursor"] = (
            encode_cursor(
                component_id=str(self.active_component_id),
                revision=int(artifact["database_revision"]),
                query=query,
                offset=int(next_offset),
            )
            if page.get("has_more") and next_offset is not None
            else None
        )
        result["page"] = page
        suggestions = [
            "Continue with next_cursor to preserve this exact query."
        ] if page.get("has_more") else []
        if page.get("has_more") and definition.get("filters"):
            suggestions.append(
                "Narrow the result with one or more advertised filters: %s."
                % ", ".join(sorted(definition["filters"]))
            )
        result["narrowing"] = {
            "available_filters": sorted(definition.get("filters") or {}),
            "suggestions": suggestions,
        }
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="collection",
            target_key="%s:%s" % (family, query_digest(query)),
            query_kind="query_%s" % family,
            result=result,
        )
        return {"evidence_id": evidence["evidence_id"], **result}

    def inspect_ida_function(self, *, address: Any) -> dict[str, Any]:
        """Return neutral function metadata; code representations remain explicit."""

        response = self.session.query({
            "task_type": "inspect_function_summary",
            "target": _address(address),
            "limit": 12,
        })
        result = dict(response.get("result", response))
        target_kind, target_key = self._inspection_identity(
            "inspect_function_summary", address, result
        )
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind=target_kind,
            target_key=target_key,
            query_kind="inspect_function_summary",
            result=result,
        )
        reference = self._reference_for_result(
            "inspect_function_summary", result, evidence["evidence_id"],
            requested_target=address,
        )
        payload = {
            "evidence_id": evidence["evidence_id"],
            "artifact": self.artifact(),
            "result": result,
        }
        if reference:
            payload["function_ref"] = reference["reference_id"]
        return payload

    def read_ida_function_code(
        self,
        *,
        function_ref: str,
        representation: str,
        limit: int = 200,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        """Read one explicitly selected code representation with stable paging."""

        reference = self._resolve_reference(function_ref, expected_kind="function")
        self._activate_reference(reference)
        if representation not in {"disassembly", "pseudocode"}:
            return {
                "ok": False,
                "error": {
                    "code": "unsupported_representation",
                    "message": "representation must be disassembly or pseudocode",
                    "recovery": "Choose a representation advertised by describe_ida_capabilities.",
                },
            }
        artifact = self.artifact()
        query = {
            "family": "function_code",
            "filters": {
                "function": reference["target"]["address"],
                "representation": representation,
            },
            "order": "source_order",
        }
        try:
            offset = (
                decode_cursor(
                    cursor,
                    component_id=str(self.active_component_id),
                    revision=int(artifact["database_revision"]),
                    query=query,
                )
                if cursor
                else 0
            )
        except QueryContractError as exc:
            return {"ok": False, "error": exc.as_dict()}
        page_limit = max(1, min(int(limit), 500))
        task_type = (
            "retrieve_disassembly"
            if representation == "disassembly"
            else "retrieve_pseudocode"
        )
        response = self.session.query({
            "task_type": task_type,
            "target": reference["target"]["address"],
            "limit": page_limit,
            "offset": offset,
        })
        raw = dict(response.get("result", response))
        if not raw.get("ok"):
            return raw
        items = raw.get("lines") if representation == "disassembly" else raw.get("pseudocode")
        total = int(raw.get("total_line_count") or len(items or []))
        next_offset = int(raw.get("next_offset") or 0)
        has_more = bool(raw.get("has_more"))
        result = {
            "ok": True,
            "artifact": artifact,
            "query": query,
            # Keep the code page bound to the exact native function identity.
            # The journal can then accept this evidence for semantic call-flow
            # dispositions without confusing a code view with a bare address.
            "function": dict(raw.get("function") or {}),
            "page": {
                "returned": len(items or []),
                "limit": page_limit,
                "total": total,
                "total_relation": "exact",
                "has_more": has_more,
                "truncated": has_more,
                "next_cursor": (
                    encode_cursor(
                        component_id=str(self.active_component_id),
                        revision=int(artifact["database_revision"]),
                        query=query,
                        offset=next_offset,
                    )
                    if has_more
                    else None
                ),
            },
            "scan": {"complete": True},
            "narrowing": {
                "available_filters": [],
                "suggestions": (
                    ["Continue with next_cursor to preserve this exact code view."]
                    if has_more else []
                ),
            },
            "items": items or [],
        }
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="function_code",
            target_key="%s:%s" % (reference["target"]["address"], representation),
            query_kind=task_type,
            result=result,
        )
        return {"evidence_id": evidence["evidence_id"], **result}

    def _inspect_direct_call_inventory(
        self, address: Any
    ) -> tuple[dict[str, Any], str]:
        """Capture one exact native call-edge snapshot in the existing journal."""

        normalized = _address(address)
        response = self.session.query({
            "task_type": "inspect_direct_call_edges",
            "target": normalized,
            "limit": 4096,
        })
        result = dict(response.get("result", response))
        if not result.get("ok"):
            raise RuntimeError(
                "Unable to inventory direct calls for %s: %s"
                % (normalized, result.get("error") or "unknown IDA error")
            )
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="function",
            target_key=normalized,
            query_kind="inspect_direct_call_edges",
            result=result,
        )
        return result, str(evidence["evidence_id"])

    @staticmethod
    def _committed_claim_digest(
        inventory: Mapping[str, Any]
    ) -> str | None:
        function = dict(inventory.get("function") or {})
        comments = dict(function.get("comments") or {})
        comment = str(
            comments.get("repeatable")
            or comments.get("nonrepeatable")
            or function.get("comment")
            or ""
        ).strip()
        if not bool(function.get("has_user_name")) or not comment:
            return None
        claim = {
            "name": str(function.get("name") or ""),
            "comment": comment,
        }
        return hashlib.sha256(
            canonical_json(claim).encode("utf-8")
        ).hexdigest()

    def _observe_committed_function_claim(
        self,
        *,
        operation: Mapping[str, Any],
        revision: int,
    ) -> dict[str, Any] | None:
        target = dict(operation.get("target") or {})
        if (
            operation.get("kind") not in {"function.rename", "function.comment.set"}
            or target.get("kind") != "function"
        ):
            return None
        inventory, evidence_id = self._inspect_direct_call_inventory(
            target.get("address")
        )
        claim_digest = self._committed_claim_digest(inventory)
        if claim_digest is None:
            return None
        containing_scope = self.journal.active_call_flow_scope_for_function(
            str(self.active_component_id), str(target.get("address"))
        )
        if containing_scope:
            detail = self.journal.read_call_flow_scope(
                scope_id=str(containing_scope["scope_id"]), limit=50, offset=0
            )
            return {
                "schema": "verified_ida.call_flow_feedback.v3",
                "trigger": "claim_attached_to_active_scope",
                "scope_id": containing_scope["scope_id"],
                "root": "%s::%s" % (
                    self.active_component_id, containing_scope["root_address"]
                ),
                "attached_function": _address(target.get("address")),
                "state": containing_scope["state"],
                "node_counts": detail["node_counts"],
                "active_path": detail["active_path"],
                "open_nodes": detail["open_nodes"][:6],
                "next_action": detail["next_action"],
                "note": (
                    "This nested claim remains in the containing scope and did "
                    "not create an independent recursive scope."
                ),
            }
        edge_counts: dict[str, int] = {}
        internal = []
        for raw in inventory.get("edges") or []:
            edge = dict(raw) if isinstance(raw, Mapping) else {}
            kind = str(edge.get("edge_kind") or "unknown")
            edge_counts[kind] = edge_counts.get(kind, 0) + 1
            if (
                kind == "direct_internal"
                and edge.get("classification_source") == "ida_instruction_feature"
                and edge.get("destination") not in (None, "")
            ):
                internal.append({
                    "callsite": edge.get("callsite"),
                    "destination": edge.get("destination"),
                })
        return {
            "schema": "verified_ida.call_flow_advisory.v1",
            "trigger": "persisted_function_claim",
            "root": "%s::%s" % (
                self.active_component_id, _address(target.get("address"))
            ),
            "claim_digest": claim_digest,
            "inventory_evidence_id": evidence_id,
            "inventory_complete": bool(inventory.get("complete")),
            "edge_set_digest": inventory.get("edge_set_digest"),
            "edge_counts": dict(sorted(edge_counts.items())),
            "direct_internal_edges": internal[:12],
            "direct_internal_total": len(internal),
            "has_more_internal_edges": len(internal) > 12,
            "blocking": False,
            "note": (
                "This topology is navigation evidence, not an immediate completion "
                "obligation. Consequential boundaries may be selected by coverage "
                "reconciliation after provisional completion."
            ),
        }

    def switch_component(
        self,
        component_id: str,
        *,
        checkpoint_current: bool = True,
        remind: bool = True,
    ) -> dict[str, Any]:
        component = self.journal.component(component_id)
        if component is None or not component.get("idb_path"):
            raise RuntimeError("Component is not analysis-ready: %s" % component_id)
        if self.active_component_id == component_id and self._session is not None:
            return self._model_component(component)
        prior_component_id = self.active_component_id
        handoff = self._component_handoff_status(
            prior_component_id=str(prior_component_id or ""),
            arriving_component=component,
        )
        if (
            self.component_handoff_policy == "required"
            and handoff is not None
            and handoff["checkpoint_status"] == "missing"
            and not self.read_only_mode
        ):
            return {
                "status": "component_handoff_checkpoint_required",
                "switch_performed": False,
                "active_component_id": prior_component_id,
                "requested_component_id": component_id,
                "component_handoff": handoff,
            }
        if self.read_only_mode:
            checkpoint_current = False
            remind = False
        departing_advisory = None
        if self._session is not None and self.active_component_id:
            checkpoint = None
            if checkpoint_current:
                checkpoint = self.checkpoint(reason="component_switch")
            departing_advisory = self._unapplied_type_advisory(
                str(prior_component_id), checkpoint=checkpoint
            )
            # Verified mutations save before returning their receipts.  The
            # remaining session state comes from inspection and decompiler
            # activity, so it must not cross a component boundary.
            self._session.close(save=False)
            self._session = None
            self.journal.set_component_status(prior_component_id, "analysis_ready")
        self._session = self._start_component_session(component)
        self.active_component_id = component_id
        identity = getattr(self._session, "input_identity", None)
        if identity:
            self.journal.record_inspection(
                component_id=component_id, target_kind="database",
                target_key=component_id, query_kind="input_identity",
                result=identity, revision=self.artifact(component_id)["database_revision"],
            )
        self.journal.set_component_status(component_id, "active")
        result = self._model_component(
            self.journal.component(component_id) or component
        )
        arriving_advisory = self._unapplied_type_advisory(component_id)
        self._queue_analysis_advisories(
            [departing_advisory, arriving_advisory],
            reason="component_transition",
        )
        if remind and prior_component_id and prior_component_id != component_id:
            reminder = self.journal.note_notebook_material_event(
                event_kind="active_component_changed",
                component_id=component_id,
                immediate=True,
            )
            if reminder:
                result = {**result, "project_state_reminder": reminder}
        if handoff is not None and self.component_handoff_policy != "none":
            result = {
                **result,
                "switch_performed": True,
                "component_handoff": handoff,
            }
        return result

    def _component_handoff_status(
        self,
        *,
        prior_component_id: str,
        arriving_component: Mapping[str, Any],
    ) -> dict[str, Any] | None:
        """Describe whether a parent-to-child transition has a fresh bookmark."""

        child_component_id = str(arriving_component.get("component_id") or "")
        parent_component_id = str(
            arriving_component.get("parent_component_id") or ""
        )
        if not (
            prior_component_id
            and child_component_id
            and parent_component_id == prior_component_id
        ):
            return None
        reminder = self.journal.notebook_reminder_state()
        missing = bool(
            reminder.get("outstanding")
            and "component_accepted" in (reminder.get("reasons") or [])
            and child_component_id in (reminder.get("components") or [])
        )
        return {
            "schema": "verified_ida.component_handoff.v1",
            "policy": self.component_handoff_policy,
            "checkpoint_status": "missing" if missing else "recorded",
            "parent_component_id": parent_component_id,
            "child_component_id": child_component_id,
            "blocking": self.component_handoff_policy == "required" and missing,
            "required_content": [
                "parent artifact or function that exposed or constructed the child",
                "accepted child identity and byte provenance",
                "supported parent-side selection, invocation, and communication role",
                "remaining parent-side uncertainty",
                "exact parent target or workstream to resume",
            ],
            "instruction": (
                "Before a long child investigation, persist supported parent-side "
                "conclusions in the parent IDB and record the transition and exact "
                "resume point in reversing_log.md. If evidence does not support an "
                "IDA annotation, record the unresolved boundary instead of inventing one."
            ),
        }

    def _unapplied_type_advisory(
        self,
        component_id: str,
        *,
        checkpoint: Mapping[str, Any] | None = None,
        semantic_state: Mapping[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        if self.analysis_feedback_profile != "scoped":
            return None
        revision = int(self.journal.revision(component_id)["revision"])
        if semantic_state is None:
            selected = checkpoint or self.journal.latest_verified_checkpoint(
                component_id, revision=revision
            )
            semantic_state, _unavailable = load_checkpoint_state(selected)
        return build_unapplied_type_advisory(
            profile=self.analysis_feedback_profile,
            component_id=component_id,
            revision=revision,
            current_operations=self.journal.current_operations(),
            semantic_state=semantic_state,
        )

    def _queue_analysis_advisories(
        self,
        advisories: Sequence[Mapping[str, Any] | None],
        *,
        reason: str,
    ) -> None:
        for raw in advisories:
            if not raw:
                continue
            row = {**dict(raw), "presentation_reason": reason}
            identity = (
                row.get("kind"), row.get("component_id"), row.get("revision")
            )
            self._pending_analysis_advisories = [
                existing for existing in self._pending_analysis_advisories
                if (
                    existing.get("kind"),
                    existing.get("component_id"),
                    existing.get("revision"),
                ) != identity
            ]
            self._pending_analysis_advisories.append(row)

    def attach_pending_analysis_advisories(self, result: Any) -> Any:
        """Attach transition advisories once to the next model-facing result."""

        if not self._pending_analysis_advisories or not isinstance(result, Mapping):
            return result
        advisories = self._pending_analysis_advisories
        self._pending_analysis_advisories = []
        return {
            **dict(result),
            "analysis_advisories": {
                "schema": "verified_ida.analysis_advisories.v1",
                "advisory": True,
                "completion_blocker": False,
                "items": advisories,
            },
        }

    def inspect(
        self,
        *,
        query: str,
        target: Any = None,
        component_id: str | None = None,
        limit: int = 120,
        options: Mapping[str, Any] | None = None,
        closure_operation: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        query = str(query or "").strip()
        if query not in READ_ONLY_QUERIES:
            raise RuntimeError("Unsupported bounded IDA query: %s" % query)
        if component_id and component_id != self.active_component_id:
            self._ensure_component_active(component_id)
        requested_limit = max(1, int(limit))
        effective_limit = min(requested_limit, READ_ONLY_QUERY_LIMITS[query])
        task = {"task_type": query, "limit": effective_limit}
        task.update(dict(options or {}))
        if target not in (None, ""):
            task["target"] = target
        response = self.session.query(task)
        result = response.get("result", response)
        target_kind, target_key = self._inspection_identity(query, target, result)
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind=target_kind,
            target_key=target_key,
            query_kind=query,
            result=result,
        )
        payload: dict[str, Any] = {
            "evidence_id": evidence["evidence_id"],
            "artifact": self.artifact(),
            "result": _model_visible_result(query, result),
            "query_bounds": {
                "requested_limit": requested_limit,
                "effective_limit": effective_limit,
                "maximum_limit": READ_ONLY_QUERY_LIMITS[query],
            },
        }
        reference = self._reference_for_result(
            query, result, evidence["evidence_id"], requested_target=target
        )
        if reference:
            payload["target_ref"] = reference["reference_id"]
        if closure_operation:
            frontier = self.frontier.observe_edit(
                component_id=str(self.active_component_id),
                inspection=result,
                operation=closure_operation,
                revision=int(self.journal.revision(str(self.active_component_id))["revision"]),
                evidence_id=evidence["evidence_id"],
            )
            payload["must_review"] = frontier["must_review"]
            payload["suggested_next"] = frontier["suggested_next"][
                :MODEL_VISIBLE_SUGGESTION_LIMIT
            ]
            payload["frontier_summary"] = {
                "must_review_count": len(frontier["must_review"]),
                "suggested_next_count": len(frontier["suggested_next"]),
                "suggested_next_returned": min(
                    len(frontier["suggested_next"]), MODEL_VISIBLE_SUGGESTION_LIMIT
                ),
                "resolved_checks": frontier["resolved_checks"],
                "resolved_suggestions": frontier["resolved_suggestions"],
                "policy": "operation_specific_closure_and_nonblocking_discovery",
            }
        return payload

    def seed_frontier(self, *, roots: list[str] | None = None) -> dict[str, Any]:
        """Build the initial benchmark-independent frontier from live project state."""

        functions = []
        offset = 0
        while True:
            page = self.session.query({
                "task_type": "list_functions",
                "limit": 1000,
                "offset": offset,
            }).get("result", {})
            rows = page.get("functions") or []
            functions.extend(rows)
            if len(rows) < 1000:
                break
            offset += len(rows)
        entries = self.session.query({
            "task_type": "list_entrypoints", "limit": 1000
        }).get("result", {})
        exports = self.session.query({
            "task_type": "list_exports", "limit": 1000
        }).get("result", {})
        entry_addresses = {
            _address(row.get("address"))
            for row in entries.get("entry_points") or []
            if row.get("address")
        }
        export_addresses = {
            _address(row.get("address"))
            for row in exports.get("exports") or []
            if row.get("address")
        }
        for row in functions:
            address = _address(row.get("address"))
            row["is_entrypoint"] = address in entry_addresses
            row["is_export"] = address in export_addresses
        candidates = self.frontier.seed_project(
            component_id=str(self.active_component_id),
            catalog={"functions": functions},
            roots=roots or [],
        )
        task_roots = [row for row in candidates if row.get("origin") == "task_root"]
        return {
            "component_id": self.active_component_id,
            "function_count": len(functions),
            "entrypoint_count": len(entry_addresses),
            "export_count": len(export_addresses),
            "candidate_count": len(candidates),
            "suggested_next_count": len(candidates),
            "task_root_count": len(task_roots),
            "blocking_count": 0,
            "policy": "project_discovery_is_nonblocking",
        }

    @staticmethod
    def _inspection_identity(
        query: str, target: Any, result: Mapping[str, Any]
    ) -> tuple[str, str]:
        function = result.get("function") if isinstance(result, Mapping) else None
        if isinstance(function, Mapping) and function.get("start"):
            return "function", _address(function["start"])
        if query == "inspect_struct":
            return "named_type", str(target or result.get("name") or "")
        if query in {"inspect_addr", "inspect_global_users"}:
            return "global", _address(target)
        if target not in (None, ""):
            try:
                return "address", _address(target)
            except RuntimeError:
                return "query", str(target)
        return "query", query

    def _reference_for_result(
        self,
        query: str,
        result: Mapping[str, Any],
        evidence_id: str,
        *,
        requested_target: Any = None,
    ) -> dict[str, Any] | None:
        function = result.get("function") if isinstance(result, Mapping) else None
        if isinstance(function, Mapping) and function.get("start"):
            target = {
                "kind": "function",
                "address": _address(function["start"]),
                "current_name": str(function.get("name") or ""),
            }
            if function.get("function_byte_hash"):
                target["function_byte_hash"] = function["function_byte_hash"]
            return self.journal.issue_reference(
                component_id=str(self.active_component_id),
                target=target,
                evidence_id=evidence_id,
            )
        if query in {"inspect_addr", "inspect_global_users"} and result.get("address"):
            target = {
                "kind": "global",
                "address": _address(result["address"]),
                "current_name": str(result.get("name") or ""),
                "current_type": str(result.get("type") or ""),
            }
            return self.journal.issue_reference(
                component_id=str(self.active_component_id),
                target=target,
                evidence_id=evidence_id,
            )
        if query == "inspect_struct":
            struct = result.get("struct")
            name = result.get("name") or result.get("query") or requested_target
            if isinstance(struct, Mapping):
                name = struct.get("name") or name
            if not str(name or "").strip():
                return None
            target = {"kind": "named_type", "name": str(name)}
            return self.journal.issue_reference(
                component_id=str(self.active_component_id),
                target=target,
                evidence_id=evidence_id,
            )
        return None

    def inspect_local(
        self,
        *,
        function_ref: str,
        current_name: str | None = None,
        lvar_index: int | None = None,
    ) -> dict[str, Any]:
        reference = self._resolve_reference(function_ref, expected_kind="function")
        self._activate_reference(reference)
        function_address = reference["target"]["address"]
        inspected = self.inspect(query="inspect_stack_frame", target=function_address)
        rows = inspected["result"].get("local_variables") or []
        matches = []
        for row in rows:
            if lvar_index is not None and int(row.get("index", -1)) != int(lvar_index):
                continue
            if current_name is not None and str(row.get("name") or "") != current_name:
                continue
            matches.append(row)
        if len(matches) != 1:
            raise RuntimeError("Local inspection resolved %d matches; provide a unique live anchor" % len(matches))
        row = matches[0]
        target = {
            "kind": "local_variable",
            "function_address": _address(function_address),
            "current_name": str(row.get("name") or ""),
            "lvar_index": int(row["index"]),
            "is_parameter": bool(row.get("is_arg")),
            "location": dict(row.get("location") or {}),
            "current_type": str(row.get("type") or ""),
        }
        use_sites = row.get("use_sites") or []
        if use_sites:
            target["use_site"] = use_sites[0]
        local_ref = self.journal.issue_reference(
            component_id=str(self.active_component_id),
            target=target,
            evidence_id=inspected["evidence_id"],
        )
        return {
            "evidence_id": inspected["evidence_id"],
            "function": inspected["result"].get("function"),
            "local": row,
            "target_ref": local_ref["reference_id"],
        }

    def inspect_relationship(
        self,
        *,
        source_ref: str,
        destination_ref: str,
        relationship_kind: str,
        callsite_address: str | None = None,
    ) -> dict[str, Any]:
        source = self._resolve_reference(source_ref, expected_kind="function")
        destination = self._resolve_reference(destination_ref, expected_kind="function")
        if source["component_id"] != destination["component_id"]:
            raise RuntimeError("Direct IDA relationships must stay within one component IDB")
        self._activate_reference(source)
        source_address = _address(source["target"]["address"])
        destination_address = _address(destination["target"]["address"])
        inventory, inventory_evidence_id = self._inspect_direct_call_inventory(
            source_address
        )
        matches = [
            edge for edge in inventory.get("edges") or []
            if isinstance(edge, Mapping)
            and edge.get("edge_kind") == "direct_internal"
            and _address(edge.get("destination")) == destination_address
        ]
        requested_callsite = (
            _address(callsite_address)
            if callsite_address not in (None, "") else None
        )
        if requested_callsite is not None:
            matches = [
                edge for edge in matches
                if _address(edge.get("callsite")) == requested_callsite
            ]
        if not matches:
            raise RuntimeError(
                "IDA does not show the requested exact direct-call relationship"
            )
        if len(matches) > 1:
            raise RuntimeError(
                "The source calls this destination at multiple sites; choose one "
                "callsite_address from: %s"
                % ", ".join(
                    sorted(_address(edge.get("callsite")) for edge in matches)
                )
            )
        selected_callsite = _address(matches[0].get("callsite"))
        source_inspection = self.inspect(
            query="inspect_function", target=source_address
        )
        destination_inspection = self.inspect(
            query="inspect_function", target=destination_address
        )
        target = {
            "kind": "relationship",
            "source_address": source_address,
            "callsite_address": selected_callsite,
            "destination_address": destination_address,
            "relationship_kind": str(relationship_kind),
        }
        relationship_ref = self.journal.issue_reference(
            component_id=str(self.active_component_id),
            target=target,
            evidence_id=self.journal.record_inspection(
                component_id=str(self.active_component_id),
                target_kind="relationship",
                target_key=self.journal.target_key(target),
                query_kind="inspect_relationship",
                result={
                    "target": target,
                    "call_inventory_evidence_id": inventory_evidence_id,
                    "source": source_inspection["result"],
                    "destination": destination_inspection["result"],
                },
            )["evidence_id"],
        )
        return {
            "target_ref": relationship_ref["reference_id"],
            "evidence_id": relationship_ref["evidence_id"],
            "source": {
                "evidence_id": source_inspection["evidence_id"],
                "function": source_inspection["result"].get("function"),
            },
            "destination": {
                "evidence_id": destination_inspection["evidence_id"],
                "function": destination_inspection["result"].get("function"),
            },
        }

    def describe_idapython_capabilities(
        self,
        *,
        topic: str | None = None,
    ) -> dict[str, Any]:
        """Return version-matched documentation for the escape hatch."""

        response = self.session.query({"task_type": "inspect_idb_meta", "limit": 200})
        metadata = response.get("result", response)
        runtime = dict(metadata.get("runtime") or {}) if isinstance(metadata, Mapping) else {}
        catalog = capability_catalog(topic, runtime=runtime, allow_decompiler=True)
        evidence = self.journal.record_inspection(
            component_id=str(self.active_component_id),
            target_kind="capability",
            target_key=str(topic or "all"),
            query_kind="describe_idapython_capabilities",
            result=catalog,
        )
        return {"evidence_id": evidence["evidence_id"], **catalog}

    def _default_readonly_executor(
        self,
        *,
        request_id: str,
        source: str,
        parameters: Mapping[str, Any],
        allow_decompiler: bool,
    ) -> Mapping[str, Any]:
        """Run validated code against a disposable copy of the current IDB."""

        component = self.journal.component(str(self.active_component_id)) or {}
        current_idb = Path(str(component.get("idb_path") or ""))
        if not current_idb.is_file():
            raise RuntimeError("Active component IDB is unavailable for snapshot execution")
        if not self.readonly_runner.is_file():
            raise RuntimeError("Read-only IDAPython sandbox runner is unavailable")
        scratch_parent = self.workspace / "readonly_idapython"
        scratch_parent.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix=request_id.replace(":", "_") + ".",
            dir=str(scratch_parent),
        ) as value:
            scratch = Path(value)
            snapshot = scratch / "snapshot.i64"
            wrapper = scratch / "readonly_wrapper.py"
            output = scratch / "result.json"
            log = scratch / "ida.log"
            shutil.copy2(current_idb, snapshot)
            write_readonly_wrapper(
                source=source,
                destination=wrapper,
                output_path=output,
                parameters=parameters,
                allow_decompiler=allow_decompiler,
            )
            try:
                process = subprocess.run(
                    [
                        str(self.readonly_runner),
                        "--log",
                        str(log),
                        str(snapshot),
                        str(wrapper),
                    ],
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    env={
                        **child_environment(),
                        "READONLY_IDA_TIMEOUT_SECONDS": str(MAX_WALL_SECONDS),
                    },
                    timeout=MAX_WALL_SECONDS + 30,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                return {
                    "ok": False,
                    "stage": "sandbox_timeout",
                    "error": {
                        "type": "TimeoutExpired",
                        "message": "Read-only IDAPython exceeded the host timeout",
                    },
                    "stderr": str(exc.stderr or "")[-4096:],
                }
            payload: dict[str, Any]
            if output.is_file():
                try:
                    payload = json.loads(output.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    payload = {
                        "ok": False,
                        "stage": "result_transport",
                        "error": {"type": type(exc).__name__, "message": str(exc)},
                    }
            else:
                payload = {
                    "ok": False,
                    "stage": "result_transport",
                    "error": {
                        "type": "MissingResult",
                        "message": "IDA exited without producing a structured result",
                    },
                }
            payload["process"] = {
                "returncode": int(process.returncode),
                "stdout_tail": process.stdout[-4096:],
                "stderr_tail": process.stderr[-4096:],
            }
            if not payload.get("ok") and log.is_file():
                retained = self.workspace / "ida_logs" / (request_id + ".log")
                retained.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(log, retained)
                payload["diagnostic_log"] = str(retained)
            return payload

    def run_readonly_idapython(
        self,
        *,
        source: str,
        parameters: Mapping[str, Any] | None,
        purpose: str,
        capability_gap: str,
    ) -> dict[str, Any]:
        """Validate, execute, and journal one model-authored aggregate query."""

        parameter_values = dict(parameters or {})
        try:
            json.dumps(parameter_values, sort_keys=True, ensure_ascii=True)
        except (TypeError, ValueError) as exc:
            return {
                "ok": False,
                "status": "rejected",
                "errors": [{
                    "code": "invalid_parameters",
                    "message": "parameters must be JSON-compatible: %s" % exc,
                    "recovery": "Pass only strings, numbers, booleans, nulls, arrays, and objects.",
                }],
            }
        component_id = str(self.active_component_id)
        revision = int(self.journal.revision(component_id)["revision"])
        request_id = stable_id(
            "readonly",
            component_id,
            revision,
            source,
            parameter_values,
            purpose,
            capability_gap,
            utc_now(),
        )
        try:
            validation = validate_readonly_script(source, allow_decompiler=True)
        except ReadonlyScriptValidationError as exc:
            validation = {
                "schema": "verified_ida.readonly_idapython.validation.v1",
                "errors": exc.errors,
            }
            self.journal.record_readonly_idapython(
                request_id=request_id,
                component_id=component_id,
                revision=revision,
                purpose=purpose,
                capability_gap=capability_gap,
                source=source,
                parameters=parameter_values,
                validation=validation,
                status="rejected",
                error={"errors": exc.errors},
            )
            return {
                "ok": False,
                "request_id": request_id,
                "status": "rejected",
                "errors": exc.errors,
            }
        try:
            if self.read_only_mode:
                snapshot_checkpoint = self.journal.latest_verified_checkpoint(
                    component_id,
                    revision=revision,
                )
                if snapshot_checkpoint is None:
                    raise RuntimeError(
                        "Read-only review requires a verified persisted checkpoint"
                    )
            else:
                snapshot_checkpoint = self.checkpoint(
                    reason="readonly_idapython_snapshot"
                )
        except Exception as exc:
            error = {
                "code": "snapshot_checkpoint_failed",
                "message": str(exc),
                "recovery": "Repair IDB persistence before running aggregate IDAPython.",
            }
            self.journal.record_readonly_idapython(
                request_id=request_id,
                component_id=component_id,
                revision=revision,
                purpose=purpose,
                capability_gap=capability_gap,
                source=source,
                parameters=parameter_values,
                validation=validation,
                status="failed",
                error=error,
            )
            return {
                "ok": False,
                "request_id": request_id,
                "status": "failed",
                "errors": [error],
            }
        if str(snapshot_checkpoint.get("status") or "") != "verified":
            details = dict(snapshot_checkpoint.get("details") or {})
            error = {
                "code": "snapshot_checkpoint_failed",
                "message": (
                    "Read-only aggregate execution was blocked because the "
                    "semantic snapshot checkpoint was not verified"
                ),
                "checkpoint_id": snapshot_checkpoint.get("checkpoint_id"),
                "checkpoint_status": snapshot_checkpoint.get("status"),
                "checkpoint_errors": details.get("errors") or [],
                "recovery": (
                    "Repair or explicitly reconcile semantic persistence before "
                    "running aggregate IDAPython."
                ),
            }
            self.journal.record_readonly_idapython(
                request_id=request_id,
                component_id=component_id,
                revision=revision,
                purpose=purpose,
                capability_gap=capability_gap,
                source=source,
                parameters=parameter_values,
                validation=validation,
                status="failed",
                error=error,
            )
            return {
                "ok": False,
                "request_id": request_id,
                "status": "failed",
                "errors": [error],
            }
        revision = int(self.journal.revision(component_id)["revision"])
        request_id = stable_id(
            "readonly",
            component_id,
            revision,
            source,
            parameter_values,
            purpose,
            capability_gap,
            utc_now(),
        )
        self.journal.record_readonly_idapython(
            request_id=request_id,
            component_id=component_id,
            revision=revision,
            purpose=purpose,
            capability_gap=capability_gap,
            source=source,
            parameters=parameter_values,
            validation=validation,
            status="validated",
        )
        try:
            execution = dict(self._readonly_executor(
                request_id=request_id,
                source=source,
                parameters=parameter_values,
                allow_decompiler=True,
            ))
        except Exception as exc:
            execution = {
                "ok": False,
                "stage": "host_execution",
                "error": {"type": type(exc).__name__, "message": str(exc)},
            }
        if not execution.get("ok"):
            error = dict(execution.get("error") or {})
            error["stage"] = execution.get("stage") or "execution"
            self.journal.record_readonly_idapython(
                request_id=request_id,
                component_id=component_id,
                revision=revision,
                purpose=purpose,
                capability_gap=capability_gap,
                source=source,
                parameters=parameter_values,
                validation=validation,
                status="failed",
                error=error,
            )
            return {
                "ok": False,
                "request_id": request_id,
                "status": "failed",
                "validation": validation,
                "execution": execution,
                "recovery": "Correct the reported script or result error; durable IDA changes still require edit_ida.",
            }
        result = execution.get("result")
        record = self.journal.record_readonly_idapython(
            request_id=request_id,
            component_id=component_id,
            revision=revision,
            purpose=purpose,
            capability_gap=capability_gap,
            source=source,
            parameters=parameter_values,
            validation=validation,
            status="completed",
            result=result,
        )
        evidence = self.journal.record_inspection(
            component_id=component_id,
            target_kind="readonly_report",
            target_key=request_id,
            query_kind="readonly_idapython",
            result=result,
            revision=revision,
        )
        return {
            "ok": True,
            "request_id": request_id,
            "status": "completed",
            "evidence_id": evidence["evidence_id"],
            "artifact": self.artifact(),
            "snapshot_checkpoint": snapshot_checkpoint,
            "validation": validation,
            "result_digest": record.get("result_digest"),
            "result": result,
            "runtime": execution.get("runtime"),
            "output_bytes": execution.get("output_bytes"),
            "execution_isolation": "disposable_current_idb_copy",
        }

    def _resolve_reference(self, reference_id: str, *, expected_kind: str | None = None) -> dict[str, Any]:
        reference = self.journal.reference(str(reference_id))
        if reference is None:
            raise RuntimeError("Unknown or expired target reference")
        if expected_kind and reference["target_kind"] != expected_kind:
            raise RuntimeError("Reference is %s, not %s" % (reference["target_kind"], expected_kind))
        current = int(self.journal.revision(reference["component_id"])["revision"])
        if int(reference["issued_revision"]) != current:
            raise RuntimeError(
                "Target reference was issued at revision %s; current revision is %s."
                % (reference["issued_revision"], current),
                code="stale_target_reference",
                details={"target_ref": reference_id, "component_id": reference["component_id"],
                         "issued_revision": reference["issued_revision"], "current_revision": current},
                recovery="Inspect the target again or use the fresh reference returned by the latest edit.",
            )
        self._validate_current_evidence([reference["evidence_id"]])
        return reference

    def _validate_current_evidence(self, evidence_ids: Sequence[str]) -> None:
        # Supporting evidence may concern another function/component, but must
        # name a real inspection at that component's current revision.
        for evidence_id in evidence_ids:
            evidence = self.journal.inspection(evidence_id)
            if evidence is None:
                raise RuntimeError(
                    "Unknown inspection evidence: %s" % evidence_id,
                    code="unknown_evidence",
                    recovery="Acquire evidence with a live inspection and cite its returned evidence_id.",
                )
            if evidence.get("query_kind") == "notebook.read":
                raise RuntimeError(
                    "Notebook references record investigator statements, not binary evidence.",
                    code="wrong_evidence_kind", recovery="Inspect the relevant IDA target and cite its evidence_id.",
                )
            current = int(self.journal.revision(evidence["component_id"])["revision"])
            if int(evidence["revision"]) != current:
                raise RuntimeError(
                    "Inspection %s is historical, not current evidence." % evidence_id,
                    code="stale_evidence",
                    details={"component_id": evidence["component_id"],
                             "evidence_revision": evidence["revision"], "current_revision": current},
                    recovery="Reacquire this supporting evidence at the current component revision.",
                )

    def _ensure_component_active(self, component_id: str, *, remind: bool = False) -> None:
        """A refused switch must never redirect a query or edit to the old IDB."""
        if component_id == self.active_component_id and self._session is not None:
            return
        result = self.switch_component(component_id, remind=remind)
        if component_id != self.active_component_id or self._session is None:
            raise RuntimeError(
                "Requested component %s did not become active; the operation was not attempted."
                % component_id,
                code=str(result.get("status") or "component_activation_failed"),
                details=result,
                recovery=(
                    "Record the requested parent/child context in reversing_log.md, "
                    "then switch to the requested component and retry the operation."
                ),
            )

    def _activate_reference(self, reference: Mapping[str, Any]) -> None:
        self._ensure_component_active(str(reference["component_id"]))

    @staticmethod
    def _desired(kind: str, value: Mapping[str, Any], target: Mapping[str, Any]) -> dict[str, Any]:
        if kind in {"function.rename", "local.rename", "global.rename"}:
            return {"name": value.get("name") or value.get("new_name")}
        if kind in {"function.comment.set"}:
            return {
                "comment": value.get("comment"),
                "repeatable": bool(value.get("repeatable", True)),
            }
        if kind in {"function.prototype.set", "local.type.set", "global.type.set"}:
            return {"declaration": value.get("declaration")}
        if kind == "named_type.create_or_update":
            return {
                "type_kind": value.get("type_kind"),
                "name": target.get("name"),
                "declaration": value.get("declaration"),
            }
        if kind == "relationship.annotate":
            desired = {
                "relationship_kind": target.get("relationship_kind"),
                "description": value.get("description"),
            }
            for key in ("flow", "ownership"):
                if key in value:
                    desired[key] = value[key]
            return desired
        raise RuntimeError("Unsupported edit kind: %s" % kind)

    def _start_component_session(self, component: Mapping[str, Any]) -> Any:
        binary = Path(str(component.get("binary_path") or ""))
        if not binary.is_file() or _sha256_file(binary) != component.get("binary_sha256"):
            raise RuntimeError(
                "Registered component input is missing or its bytes have changed.",
                code="component_input_changed",
                recovery="Restore the registered immutable input; use a new project for a different sample.",
            )
        session = self._session_factory(component)
        return session.start() if hasattr(session, "start") else session

    def _mutation_manifest_path(self, operation_id: str) -> Path:
        return self.workspace / "mutation_transactions" / (operation_id + ".json")

    def _transactional_apply(
        self,
        *,
        component: Mapping[str, Any],
        operation: Mapping[str, Any],
        artifact: Mapping[str, Any],
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        """Apply one operation to a candidate IDB and promote only after readback."""

        canonical = Path(str(component.get("idb_path") or "")).resolve()
        if not canonical.is_file():
            raise RuntimeError("Component IDB is missing: %s" % canonical)
        manifest_path = self._mutation_manifest_path(str(operation["operation_id"]))
        if manifest_path.exists() or self.journal.operation_detail(str(operation["operation_id"])):
            raise RuntimeError("Mutation attempt ID already exists; do not overwrite its history")
        self._require_accepted_mutation_base(component)
        transaction_dir = Path(tempfile.mkdtemp(
            prefix=".verified_ida_txn_%s_" % str(operation["operation_id"])[-12:],
            dir=str(canonical.parent),
        ))
        rollback = transaction_dir / ("before" + canonical.suffix)
        candidate = transaction_dir / ("candidate" + canonical.suffix)
        retain_packed_ida_database(canonical, rollback)
        copy_packed_ida_database(canonical, candidate)
        # Recovery relies on the rollback file and directory existing before
        # the write-ahead manifest permits canonical replacement.
        with rollback.open("rb") as handle:
            os.fsync(handle.fileno())
        for directory in (transaction_dir, canonical.parent):
            directory_fd = os.open(str(directory), os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        before_sha256 = _sha256_file(canonical)
        manifest: dict[str, Any] = {
            "schema": "verified_ida.mutation_transaction.v1",
            "operation_id": operation["operation_id"],
            "operation_digest": operation_digest(operation),
            "logical_edit_id": (operation.get("metadata") or {}).get("logical_edit_id"),
            "component_id": component.get("component_id"),
            "status": "prepared",
            "canonical_idb": str(canonical),
            "canonical_before_sha256": before_sha256,
            "candidate_idb": str(candidate),
            "rollback_idb": str(rollback),
        }
        _write_json_atomic(manifest_path, manifest)
        candidate_component = {
            **dict(component),
            "idb_path": str(candidate),
            "_session_label": "%s-transaction" % component.get("component_id"),
        }
        candidate_session = None
        promoted = False
        try:
            candidate_session = self._start_component_session(candidate_component)
            native_candidate_session = isinstance(
                candidate_session, PersistentIdaSession
            )
            response = candidate_session.apply(operation, artifact)
            batch = response.get("result", response)
            receipts = batch.get("receipts") or []
            if len(receipts) != 1:
                raise RuntimeError("IDA did not return exactly one edit receipt")
            receipt = dict(receipts[0])
            candidate_session.close(save=False)
            candidate_session = None

            status = str(receipt.get("status") or "")
            fresh_readback = None
            if status in VERIFIED_STATUSES:
                verification_session = self._start_component_session(candidate_component)
                try:
                    fresh_readback = dict(verification_session.read_operation(operation))
                finally:
                    verification_session.close(save=False)
                if not fresh_readback.get("matches"):
                    receipt = build_receipt(
                        operation,
                        "ineffective",
                        "transaction_verification",
                        observed=fresh_readback.get("observed"),
                        normalization=fresh_readback.get("normalization"),
                        persistence="not_checked",
                        errors=[{
                            "code": "candidate_fresh_readback_failed",
                            "message": (
                                "A fresh process did not observe the requested "
                                "state in the candidate IDB"
                            ),
                        }],
                        recovery=(
                            "Re-inspect the canonical IDB and submit a corrected "
                            "operation; the failed candidate was discarded."
                        ),
                    )
                    status = "ineffective"

            if (
                status == "verified"
                and native_candidate_session
                and str(operation.get("kind") or "") in (
                    DISPOSABLE_RENDER_MEASUREMENT_KINDS
                    | SEMANTIC_DELTA_MEASUREMENT_KINDS
                )
            ):
                original_effects = dict(receipt.get("effects") or {})
                addresses = list(
                    original_effects.get(
                        "affected_function_addresses"
                    ) or []
                )
                dependency_artifacts = dict(
                    original_effects.get("semantic_dependency_artifacts") or {}
                )
                try:
                    receipt["effects"] = self._measure_disposable_rendering_effects(
                        component=component,
                        operation=operation,
                        before_idb=rollback,
                        after_idb=candidate,
                        addresses=addresses,
                        dependency_artifacts=dependency_artifacts,
                    )
                except Exception as exc:
                    receipt["effects"] = {
                        "decompiler_functions": [],
                        "decompiler_changed": None,
                        "refresh_count": None,
                        "measurement": "disposable_measurement_unavailable",
                        "measurement_reason": str(exc),
                        "affected_function_addresses": addresses[
                            :DISPOSABLE_RENDER_MEASUREMENT_LIMIT
                        ],
                        "affected_function_count": len(addresses),
                        "affected_functions_truncated": (
                            len(addresses) > DISPOSABLE_RENDER_MEASUREMENT_LIMIT
                        ),
                        "semantic_dependency_artifacts": dependency_artifacts,
                    }
                semantic_delta = (receipt.get("effects") or {}).get(
                    "semantic_delta"
                ) or {}
                required_measurement_missing = (
                    str(operation.get("kind") or "") in SEMANTIC_DELTA_MEASUREMENT_KINDS
                    and semantic_delta.get("status") not in {"permitted", "unexpected_collateral_change"}
                )
                if required_measurement_missing or semantic_delta.get("unexpected_paths"):
                    receipt = build_receipt(
                        operation,
                        "unverified",
                        "transaction_semantic_delta",
                        before=receipt.get("before"),
                        observed=receipt.get("observed"),
                        normalization=receipt.get("normalization"),
                        effects=receipt.get("effects"),
                        persistence="not_checked",
                        errors=[{
                            "code": ("semantic_verification_incomplete" if required_measurement_missing
                                     else "unexpected_collateral_semantic_change"),
                            "message": (
                                "Required semantic/dependency verification was incomplete"
                                if required_measurement_missing else
                                "The candidate changed durable semantic surfaces "
                                "outside the operation-specific permitted delta"
                            ),
                            "unexpected_paths": semantic_delta.get(
                                "unexpected_paths"
                            ),
                        }],
                        recovery=(
                            "The canonical IDB is unchanged. Reinspect the reported paths "
                            "or retry the failed measurement. Keep evidence-supported types; "
                            "do not weaken the declaration to avoid verification."
                        ),
                    )
                    status = "unverified"

            candidate_sha256 = _sha256_file(candidate)
            transaction = {
                "schema": "verified_ida.mutation_transaction_result.v1",
                "status": "discarded",
                "canonical_before_sha256": before_sha256,
                "candidate_sha256": candidate_sha256,
                "fresh_readback": bool(
                    fresh_readback and fresh_readback.get("matches")
                ),
                "promoted": False,
            }
            if status == "verified":
                manifest.update({
                    "status": "candidate_verified",
                    "candidate_sha256": candidate_sha256,
                    "candidate_receipt_id": receipt["receipt_id"],
                })
                _write_json_atomic(manifest_path, manifest)
                manifest["status"] = "promotion_intent"
                _write_json_atomic(manifest_path, manifest)
                atomic_promote_packed_ida_database(candidate, canonical)
                promoted = True
                promoted_sha256 = _sha256_file(canonical)
                manifest.update({
                    "status": "promoted_pending_journal",
                    "canonical_after_sha256": promoted_sha256,
                })
                _write_json_atomic(manifest_path, manifest)
                transaction.update({
                    "status": "promoted_pending_journal",
                    "canonical_after_sha256": promoted_sha256,
                    "promoted": True,
                })
            elif status == "verified_existing":
                transaction["status"] = "already_satisfied"
                manifest.update({
                    "status": "already_satisfied",
                    "candidate_sha256": candidate_sha256,
                })
                _write_json_atomic(manifest_path, manifest)
            else:
                manifest.update({
                    "status": "discarded",
                    "candidate_sha256": candidate_sha256,
                    "receipt_status": status,
                })
                _write_json_atomic(manifest_path, manifest)
            return _receipt_with_transaction(receipt, transaction), {
                "manifest_path": manifest_path,
                "manifest": manifest,
                "transaction_dir": transaction_dir,
                "rollback_path": rollback,
                "canonical_path": canonical,
                "promoted": promoted,
            }
        except Exception:
            if candidate_session is not None:
                candidate_session.close(save=False)
            # os.replace may have succeeded even if directory fsync raised.
            # Decide from bytes, not an in-process flag set after the call.
            actual_hash = _sha256_file(canonical) if canonical.is_file() else None
            if actual_hash != before_sha256:
                if (
                    actual_hash != manifest.get("candidate_sha256")
                    or not rollback.is_file()
                    or _sha256_file(rollback) != before_sha256
                ):
                    raise RuntimeError(
                        "Mutation outcome is ambiguous; preserved transaction and rollback for recovery."
                    )
                atomic_promote_packed_ida_database(rollback, canonical)
                promoted = False
            manifest.update({"status": "rolled_back_after_error"})
            _write_json_atomic(manifest_path, manifest)
            shutil.rmtree(transaction_dir, ignore_errors=True)
            raise

    @staticmethod
    def _render_pseudocode(session: PersistentIdaSession, address: str) -> dict[str, Any]:
        lines: list[str] = []
        offset = 0
        try:
            while True:
                response = session.query({
                    "task_type": "retrieve_pseudocode",
                    "target": address,
                    "limit": 400,
                    "offset": offset,
                })
                result = dict(response.get("result", response))
                page = result.get("pseudocode") or []
                lines.extend(str(value) for value in page)
                if not result.get("has_more"):
                    break
                next_offset = int(result.get("next_offset") or (offset + len(page)))
                if next_offset <= offset:
                    raise RuntimeError("Pseudocode pagination did not advance")
                offset = next_offset
            rendered = "\n".join(lines)
            return {
                "available": bool(result.get("ok", True)),
                "length": len(rendered),
                "sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
            }
        except Exception as exc:
            return {"available": False, "error": str(exc)}

    def _measure_disposable_rendering_effects(
        self,
        *,
        component: Mapping[str, Any],
        operation: Mapping[str, Any],
        before_idb: Path,
        after_idb: Path,
        addresses: Sequence[str],
        dependency_artifacts: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Compare decompiler output on disposable packed pre/post IDB copies."""

        dependencies = dict(dependency_artifacts or {})
        selected = list(dict.fromkeys([
            *(str(value) for value in addresses if value),
            *(
                str(value)
                for value in dependencies.get("function_addresses") or []
                if value
            ),
        ]))
        truncated = len(selected) > DISPOSABLE_RENDER_MEASUREMENT_LIMIT
        selected = selected[:DISPOSABLE_RENDER_MEASUREMENT_LIMIT]
        sessions = []
        try:
            for label, idb_path in (("before", before_idb), ("after", after_idb)):
                session = PersistentIdaSession(
                    idb_path=idb_path,
                    input_binary_path=component.get("binary_path"),
                    launcher=self.launcher,
                    worker_script=self.worker_script,
                    log_path=(
                        self.workspace
                        / "ida_logs"
                        / ("%s-render-%s.log" % (component.get("component_id"), label))
                    ),
                    disposable_copy=True,
                ).start()
                sessions.append(session)
            rows = []
            effects = {
                "decompiler_functions": rows,
                "decompiler_changed": any(row["changed"] for row in rows),
                "refresh_count": len(rows),
                "measurement": "disposable_packed_before_after",
                "measurement_reason": (
                    "Decompiler effects were measured on disposable packed-IDB "
                    "copies after exact candidate readback. Neither comparison "
                    "session can modify the candidate or canonical IDB."
                ),
                "affected_function_addresses": selected,
                "affected_function_count": len(addresses),
                "affected_functions_truncated": truncated,
                "semantic_dependency_artifacts": dependencies,
            }
            if str(operation.get("kind") or "") in SEMANTIC_DELTA_MEASUREMENT_KINDS:
                selected_locals = list(dict.fromkeys(
                    str(value)
                    for value in dependencies.get("function_addresses") or []
                    if value
                ))
                selected_globals = list(dict.fromkeys(
                    str(value)
                    for value in dependencies.get("global_addresses") or []
                    if value
                ))
                if operation.get("kind") == "local.type.set":
                    selected_locals.append(str(
                        (operation.get("target") or {}).get("function_address")
                    ))
                if operation.get("kind") == "global.type.set":
                    selected_globals.append(str(
                        (operation.get("target") or {}).get("address")
                    ))
                selected_locals = list(dict.fromkeys(selected_locals))
                selected_globals = list(dict.fromkeys(selected_globals))
                before_export = sessions[0].semantic_export(
                    selected_local_functions=selected_locals,
                    selected_global_addresses=selected_globals,
                )
                after_export = sessions[1].semantic_export(
                    selected_local_functions=selected_locals,
                    selected_global_addresses=selected_globals,
                )
                before_state = before_export.get("state")
                after_state = after_export.get("state")
                if not before_export.get("ok") or not after_export.get("ok") or not isinstance(before_state, Mapping) or not isinstance(
                    after_state, Mapping
                ):
                    raise RuntimeError(
                        "Disposable semantic delta export did not return state"
                    )
                for label, state in (("before", before_state), ("after", after_state)):
                    functions = {str(row.get("address") or "").lower(): row for row in state.get("functions") or []}
                    unavailable = [address for address in selected_locals
                                   if (functions.get(address.lower(), {}).get("locals") or {}).get("available") is not True]
                    if unavailable:
                        details = [
                            "%s (%s)" % (address, dict(
                                functions.get(address.lower(), {}).get("locals") or {}
                            ).get("message") or "native decompilation unavailable")
                            for address in unavailable
                        ]
                        raise RuntimeError("Required %s local-state measurement unavailable: %s" % (label, ", ".join(details)))
                effects["semantic_delta"] = classify_semantic_delta(
                    operation,
                    before_state,
                    after_state,
                    dependency_artifacts=dependencies,
                )
            # The durable oracle is captured before optional decompilation can
            # infer types in these disposable sessions. Rendering is feedback,
            # not permission to skip a mandatory semantic comparison.
            for address in selected:
                rendered = []
                for session in sessions:
                    try:
                        rendered.append(self._render_pseudocode(session, address))
                    except Exception as exc:
                        rendered.append({"available": False, "error": str(exc)})
                before, after = rendered
                rows.append({
                    "address": address, "before": before, "after": after,
                    "changed": (before.get("sha256") != after.get("sha256"))
                    if before.get("available") and after.get("available") else None,
                })
            effects.update(
                decompiler_functions=rows,
                decompiler_changed=(True if any(row["changed"] for row in rows)
                                    else False if all(row["changed"] is not None for row in rows) else None),
                refresh_count=len(rows),
                rendering_complete=all(row["changed"] is not None for row in rows),
            )
            return effects
        finally:
            for session in sessions:
                session.close(save=False)

    def _finish_mutation_transaction(
        self,
        transaction_state: Mapping[str, Any],
        *,
        committed: bool,
    ) -> dict[str, Any]:
        manifest_path = Path(str(transaction_state["manifest_path"]))
        manifest = dict(transaction_state["manifest"])
        canonical = Path(str(transaction_state["canonical_path"]))
        rollback = Path(str(transaction_state["rollback_path"]))
        promoted = bool(transaction_state.get("promoted"))
        if committed:
            manifest["status"] = "committed" if promoted else manifest.get("status")
            if canonical.is_file():
                manifest["canonical_final_sha256"] = _sha256_file(canonical)
        elif promoted and rollback.is_file():
            atomic_promote_packed_ida_database(rollback, canonical)
            manifest.update({
                "status": "rolled_back_after_journal_failure",
                "canonical_final_sha256": _sha256_file(canonical),
            })
        _write_json_atomic(manifest_path, manifest)
        shutil.rmtree(
            Path(str(transaction_state["transaction_dir"])),
            ignore_errors=True,
        )
        return manifest

    def _require_writable(self) -> None:
        if self.read_only_mode:
            raise RuntimeError(
                "Read-only runtime cannot apply IDB edits or create components.", code="read_only",
                recovery="Return a review finding; only the investigation writer may apply changes.",
            )

    def _require_accepted_mutation_base(self, component: Mapping[str, Any]) -> None:
        """Do not use a new revision to adopt unexplained canonical state."""
        component_id = str(component["component_id"])
        if self.journal.unresolved_semantic_drift(component_id):
            raise RuntimeError(
                "Unresolved semantic drift blocks edits; restore the accepted IDB and checkpoint before retrying.",
                code="unresolved_semantic_drift",
            )
        self._require_accepted_database_bytes(component)

    def _require_accepted_database_bytes(self, component: Mapping[str, Any]) -> None:
        """Compare canonical bytes without preventing verification of restoration."""
        component_id = str(component["component_id"])
        revision = int(self.journal.revision(component_id)["revision"])
        accepted = self.journal.latest_verified_checkpoint(component_id, revision=revision)
        expected_hash = accepted.get("idb_sha256") if accepted else None
        if expected_hash is None:
            # Every accepted revision has either a checkpoint or its own
            # verified transaction receipt, including already-satisfied edits.
            for path in (self.workspace / "mutation_transactions").glob("*.json"):
                manifest = json.loads(path.read_text(encoding="utf-8"))
                if manifest.get("component_id") != component_id or manifest.get("status") not in {"committed", "already_satisfied"}:
                    continue
                detail = self.journal.operation_detail(str(manifest.get("operation_id")))
                prior_revision = (((detail or {}).get("request") or {}).get("artifact") or {}).get("database_revision")
                if prior_revision is not None and int(prior_revision) + 1 == revision:
                    expected_hash = manifest.get("canonical_final_sha256") or manifest.get("canonical_after_sha256") or manifest.get("canonical_before_sha256")
                    break
        if expected_hash is None and revision != 0:
            raise RuntimeError(
                "No accepted database identity exists for this revision; recovery is required.",
                code="unresolved_semantic_drift",
            )
        if expected_hash is not None and _sha256_file(Path(component["idb_path"])) != expected_hash:
            raise RuntimeError(
                "Canonical IDB bytes differ from the accepted mutation base; restore and checkpoint before editing.",
                code="unresolved_semantic_drift",
            )

    def apply_edit(
        self,
        *,
        target_ref: str,
        kind: str,
        value: Mapping[str, Any],
        evidence_refs: list[str] | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        self._require_writable()
        reference = self._resolve_reference(target_ref)
        self._validate_current_evidence(evidence_refs or [])
        self._activate_reference(reference)
        target = dict(reference["target"])
        self._enforce_reconciliation_edit_scope(
            component_id=str(reference["component_id"]),
            target=target,
        )
        desired = self._desired(kind, value, target)
        artifact = self.artifact()
        material = {
            "component": self.active_component_id,
            "target": target,
            "kind": kind,
            "desired": desired,
            "revision": artifact["database_revision"],
        }
        evidence = list(dict.fromkeys([
            reference["evidence_id"],
            *(evidence_refs or []),
        ]))
        active_finding = self.journal.active_reconciliation_finding()
        work_item_id = (
            str(active_finding["finding_id"])
            if active_finding is not None else None
        )
        operation = validate_operation({
            "schema": "verified_ida.operation.v1",
            # A retry is a new execution, even when its desired state is the
            # same. Link the intent without reusing its immutable attempt ID.
            "operation_id": "operation-" + uuid.uuid4().hex,
            "work_item_id": work_item_id,
            "kind": kind,
            "artifact": artifact,
            "target": target,
            "desired": desired,
            "preconditions": {},
            "evidence": [
                {"kind": "inspection", "source": evidence_id}
                for evidence_id in evidence
            ],
            "depends_on": [],
            "metadata": {
                "transport": "verified_ida.runtime.v1",
                "target_ref": target_ref,
                "reason": reason,
                "logical_edit_id": stable_id("edit", material),
            },
        })
        # Inspection and Hex-Rays decompilation can refine IDA's in-memory
        # types. Discard that session, apply to a packed-IDB candidate, verify
        # the candidate in a fresh process, and promote it only on success.
        component = self.journal.component(str(self.active_component_id)) or {}
        self._session.close(save=False)
        self._session = None
        try:
            receipt, transaction_state = self._transactional_apply(
                component=component,
                operation=operation,
                artifact=artifact,
            )
        except Exception:
            # A rejected or failed candidate must not strand the analytical
            # runtime without an active IDA process. _transactional_apply
            # already discards the candidate (and restores a promoted
            # canonical IDB when necessary); reopen the canonical component so
            # the exact failing operation can be inspected and retried.
            current_component = (
                self.journal.component(str(self.active_component_id))
                or component
            )
            self._session = self._start_component_session(current_component)
            raise
        verified = receipt.get("status") in VERIFIED_STATUSES
        committed = False
        final_transaction_manifest = None
        try:
            committed_revision = self.journal.record_operation(
                component_id=str(self.active_component_id),
                operation=operation,
                receipt=receipt,
                advance_revision=verified,
            )
            if verified:
                if committed_revision is None:
                    raise RuntimeError(
                        "Verified mutation committed without a component revision"
                    )
                revision = committed_revision
            else:
                revision = self.journal.revision(str(self.active_component_id))
            committed = True
        except Exception:
            final_transaction_manifest = self._finish_mutation_transaction(
                transaction_state,
                committed=False,
            )
            current_component = (
                self.journal.component(str(self.active_component_id))
                or component
            )
            self._session = self._start_component_session(current_component)
            raise
        finally:
            if final_transaction_manifest is None:
                final_transaction_manifest = self._finish_mutation_transaction(
                    transaction_state,
                    committed=committed,
                )
        transaction_result = dict(receipt.get("transaction") or {})
        transaction_result.update({
            "status": str(final_transaction_manifest.get("status") or ""),
            "journal_committed": committed,
        })
        if transaction_result.get("promoted"):
            transaction_result["promotion_status"] = "promoted"
        if final_transaction_manifest.get("canonical_final_sha256"):
            transaction_result["canonical_final_sha256"] = (
                final_transaction_manifest["canonical_final_sha256"]
            )
        receipt = {**receipt, "transaction": transaction_result}
        component = self.journal.component(str(self.active_component_id)) or component
        self._session = self._start_component_session(component)
        refreshed = self._post_edit_inspection(
            target,
            operation=operation if verified else None,
        )
        checkpoint = None
        if verified and (
            int(revision["verified_since_checkpoint"]) >= self.checkpoint_interval
            or kind in GLOBAL_IMPACT_KINDS
            or (
                self.analysis_feedback_profile == "scoped"
                and kind == "local.type.set"
            )
        ):
            checkpoint = self.checkpoint(reason="edit_policy:%s" % kind)
        persistence_receipt = None
        if checkpoint:
            detail = self.journal.operation_detail(operation["operation_id"])
            persistence_receipt = (detail or {}).get("receipts", [receipt])[-1]
        reminder = None
        if verified:
            immediate = kind in {
                "function.rename",
                "function.comment.set",
                "named_type.create_or_update",
            }
            material = immediate or kind in {
                "function.prototype.set",
                "global.rename",
                "global.type.set",
                "relationship.annotate",
            }
            if material:
                reminder = self.journal.note_notebook_material_event(
                    event_kind=(
                        "function_interpretation_changed"
                        if kind in {"function.rename", "function.comment.set"}
                        else "named_type_changed"
                        if kind == "named_type.create_or_update"
                        else "several_material_ida_changes"
                    ),
                    component_id=str(self.active_component_id),
                    immediate=immediate,
                )
        analysis_feedback = None
        call_flow_feedback = None
        if verified:
            analysis_feedback = build_analysis_feedback(
                profile=self.analysis_feedback_profile,
                component_id=str(self.active_component_id),
                revision=int(revision["revision"]),
                operation=operation,
                receipt=receipt,
                checkpoint=checkpoint,
                current_operations=self.journal.current_operations(),
            )
            if kind in {"function.rename", "function.comment.set"}:
                try:
                    call_flow_feedback = self._observe_committed_function_claim(
                        operation=operation,
                        revision=int(revision["revision"]),
                    )
                except Exception as exc:
                    target_address = _address(target.get("address"))
                    candidate = self.journal.upsert_candidate({
                        "candidate_id": stable_id(
                            "candidate", "claim_call_flow_inventory_failed",
                            self.active_component_id, target_address,
                        ),
                        "component_id": str(self.active_component_id),
                        "target_kind": "function",
                        "target_key": target_address,
                        "gap_kind": "claim_call_flow_inventory_failed",
                        "lane": "suggested_next",
                        "reasons": [
                            "host could not capture the committed function's direct-call inventory",
                            "%s: %s" % (type(exc).__name__, exc),
                        ],
                        "priority": "medium",
                        "tier": 3,
                        "origin": "claim_call_flow_advisory",
                        "trigger_revision": int(revision["revision"]),
                        "operation_id": operation["operation_id"],
                    })
                    call_flow_feedback = {
                        "schema": "verified_ida.call_flow_advisory.v1",
                        "status": "inventory_failed",
                        "blocking": False,
                        "candidate": candidate,
                        "recovery": (
                            "Reinspect the exact function and retry a supported rename "
                            "or behavior-comment edit after correcting the IDA query failure; "
                            "this advisory does not block the primary investigation."
                        ),
                    }
        result = _edit_result(
            component_id=str(self.active_component_id),
            operation=operation,
            receipt=receipt,
            persistence_receipt=persistence_receipt,
            database_revision=int(revision["revision"]),
            refreshed=refreshed,
            checkpoint=checkpoint,
            analysis_feedback=analysis_feedback,
            call_flow_feedback=call_flow_feedback,
            project_state_reminder=reminder,
        )
        result["operation_resolution"] = self.journal.operation_supersession(operation["operation_id"])
        return result

    def inspect_operation(self, operation_id: str) -> dict[str, Any]:
        detail = self.journal.operation_detail(str(operation_id))
        if detail is None:
            raise RuntimeError("Unknown operation ID: %s" % operation_id)
        result = {
            "schema": "verified_ida.operation_detail.v1",
            **detail,
        }
        manifest_path = (
            self.workspace
            / "mutation_transactions"
            / ("%s.json" % str(operation_id))
        )
        if manifest_path.is_file():
            try:
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                result["transaction_lifecycle"] = {
                    key: manifest.get(key)
                    for key in (
                        "status",
                        "component_id",
                        "canonical_before_sha256",
                        "candidate_sha256",
                        "canonical_after_sha256",
                        "canonical_final_sha256",
                    )
                    if manifest.get(key) is not None
                }
            except (OSError, json.JSONDecodeError):
                result["transaction_lifecycle"] = {
                    "status": "manifest_unreadable"
                }
        return result

    @staticmethod
    def _review_target_matches_edit_target(
        target: Mapping[str, Any],
        review_target: Mapping[str, Any],
    ) -> bool:
        """Match only the exact mutable anchor authorized by a review finding."""

        kind = str(review_target.get("kind") or "")
        if str(target.get("kind") or "") != kind:
            return False
        if kind in {"function", "address", "global"}:
            return _address(target.get("address")) == _address(
                review_target.get("address")
            )
        if kind == "named_type":
            return str(target.get("name") or "") == str(
                review_target.get("name") or ""
            )
        if kind == "local_variable":
            if _address(target.get("function_address")) != _address(
                review_target.get("function_address")
            ):
                return False
            expected_index = review_target.get("lvar_index")
            expected_name = str(review_target.get("current_name") or "")
            return (
                expected_index is not None
                and int(target.get("lvar_index", -1)) == int(expected_index)
            ) or (
                bool(expected_name)
                and str(target.get("current_name") or "") == expected_name
            )
        if kind == "relationship":
            endpoints_match = (
                _address(target.get("source_address"))
                == _address(review_target.get("source_address"))
                and _address(target.get("destination_address"))
                == _address(review_target.get("destination_address"))
                and str(target.get("relationship_kind") or "")
                == str(review_target.get("relationship_kind") or "")
            )
            expected_callsite = review_target.get("callsite_address")
            return endpoints_match and (
                expected_callsite in (None, "")
                or _address(target.get("callsite_address"))
                == _address(expected_callsite)
            )
        return False

    def _enforce_reconciliation_edit_scope(
        self,
        *,
        component_id: str,
        target: Mapping[str, Any],
    ) -> None:
        """Reject side edits while one immutable reconciliation wave is active."""

        if not self.coverage_reconciliation_enabled:
            return
        status = self.journal.reconciliation_status()
        findings = list(status.get("findings") or [])
        if not findings:
            return
        for finding in findings:
            for review_target in finding.get("targets") or []:
                if (
                    str(review_target.get("component_id") or finding["component_id"])
                    == component_id
                    and self._review_target_matches_edit_target(target, review_target)
                ):
                    return
        raise RuntimeError(
            "The edit target is outside the current immutable reconciliation "
            "wave. Verify or disposition the current finding; preserve unrelated "
            "discoveries as advisory notebook backlog."
        )

    def _post_edit_inspection(
        self,
        target: Mapping[str, Any],
        *,
        operation: Mapping[str, Any] | None,
    ) -> dict[str, Any] | None:
        kind = target.get("kind")
        if kind == "function":
            return self.inspect(
                query="inspect_function",
                target=target["address"],
                closure_operation=operation,
            )
        if kind == "local_variable":
            return self.inspect(
                query="inspect_function",
                target=target["function_address"],
                closure_operation=operation,
            )
        if kind == "global":
            return self.inspect(
                query="inspect_addr",
                target=target["address"],
                closure_operation=operation,
            )
        if kind == "named_type":
            return self.inspect(
                query="inspect_struct",
                target=target["name"],
                closure_operation=operation,
            )
        if kind == "relationship":
            return self.inspect(
                query="inspect_function",
                target=target["source_address"],
                closure_operation=operation,
            )
        return None

    def checkpoint(self, *, reason: str) -> dict[str, Any]:
        component_id = self.active_component_id
        if not component_id or self._session is None:
            raise RuntimeError("No active component to checkpoint")
        component = self.journal.component(component_id) or {}
        # Every verified mutation is durably saved by the IDA worker before its
        # receipt is returned.  Discard the analytical session here so Hex-Rays
        # refinements caused by read-only inspection cannot become unjournaled
        # database changes.
        self._session.close(save=False)
        self._session = None
        session = self._session_factory(component)
        self._session = session.start() if hasattr(session, "start") else session
        return self._verify_component_checkpoint(
            component_id=component_id,
            component=component,
            session=self._session,
            reason=reason,
        )

    def checkpoint_component(self, component_id: str, *, reason: str) -> dict[str, Any]:
        """Freshly verify one component without changing the active component."""

        if component_id == self.active_component_id:
            return self.checkpoint(reason=reason)
        component = self.journal.component(component_id)
        if component is None:
            raise RuntimeError("Unknown component: %s" % component_id)
        idb_path = Path(str(component.get("idb_path") or ""))
        if not idb_path.is_file():
            return self.journal.record_checkpoint(
                component_id=component_id,
                revision=int(self.journal.revision(component_id)["revision"]),
                status="failed",
                idb_sha256=None,
                details={
                    "reason": reason,
                    "fresh_process": False,
                    "errors": [{
                        "code": "component_idb_missing",
                        "message": "Component IDB is missing and cannot be freshly verified",
                        "path": str(idb_path),
                    }],
                },
            )
        session = self._session_factory(component)
        session = session.start() if hasattr(session, "start") else session
        try:
            return self._verify_component_checkpoint(
                component_id=component_id,
                component=component,
                session=session,
                reason=reason,
            )
        finally:
            session.close(save=False)

    def _verify_component_checkpoint(
        self,
        *,
        component_id: str,
        component: Mapping[str, Any],
        session: Any,
        reason: str,
    ) -> dict[str, Any]:
        pending = self.journal.pending_persistence_operations(component_id)
        failures = []
        verified_ids = []
        for row in pending:
            operation = row["operation"]
            try:
                readback = session.read_operation(operation)
                matches = bool(readback.get("matches"))
                persistence_receipt = build_receipt(
                    operation,
                    "verified" if matches else "ineffective",
                    "persistence",
                    observed=readback.get("observed"),
                    normalization=readback.get("normalization"),
                    persistence="verified" if matches else "failed",
                    errors=[] if matches else [{
                        "code": "persistence_mismatch",
                        "message": "Fresh IDA process did not observe the intended state",
                    }],
                    recovery=None if matches else "Re-inspect and repair the persisted IDB state.",
                )
            except Exception as exc:
                matches = False
                persistence_receipt = build_receipt(
                    operation,
                    "failed",
                    "persistence",
                    persistence="failed",
                    errors=[{"code": "persistence_read_failed", "message": str(exc)}],
                    recovery="Repair fresh-process readback before relying on this edit.",
                )
            self.journal.record_operation(
                component_id=component_id,
                operation=operation,
                receipt=persistence_receipt,
            )
            if matches:
                verified_ids.append(operation["operation_id"])
            else:
                failures.append(operation["operation_id"])
        semantic_errors = []
        try:
            self._require_accepted_database_bytes(component)
        except Exception as exc:
            semantic_errors.append({
                "code": "unresolved_semantic_drift", "message": str(exc),
            })
        semantic_export = None
        selected_locals = self.journal.semantic_local_functions(component_id)
        selected_globals = self.journal.semantic_global_addresses(component_id)
        try:
            semantic_export = dict(session.semantic_export(
                selected_local_functions=selected_locals,
                selected_global_addresses=selected_globals,
            ))
            semantic_state = semantic_export.get("state")
            semantic_digest = str(semantic_export.get("semantic_digest") or "")
            if not semantic_export.get("ok") or not isinstance(semantic_state, Mapping):
                raise RuntimeError("Fresh IDA process did not return semantic state")
            excluded_fields = semantic_digest_exclusions(semantic_export)
            host_digest = semantic_state_digest(
                semantic_state,
                excluded_fields=excluded_fields,
            )
            if host_digest != semantic_digest:
                raise RuntimeError(
                    "Semantic export digest mismatch (IDA=%s host=%s)"
                    % (semantic_digest, host_digest)
                )
        except Exception as exc:
            semantic_errors.append({
                "code": "semantic_export_failed",
                "message": str(exc),
            })
            semantic_export = None

        revision = int(self.journal.revision(component_id)["revision"])
        idb_path = Path(str(component["idb_path"]))
        current_idb_sha256 = (
            _sha256_file(idb_path) if idb_path.is_file() else None
        )
        previous = self.journal.latest_verified_checkpoint(
            component_id, revision=revision
        )
        if semantic_export and previous:
            prior_digest = str((previous.get("details") or {}).get("semantic_digest") or "")
            prior_export_version = int(
                (previous.get("details") or {}).get("semantic_export_version") or 0
            )
            current_export_version = int(semantic_export.get("export_version") or 0)
            if (
                previous.get("status") == "verified"
                and prior_export_version != current_export_version
            ):
                prior_path = Path(str(
                    (previous.get("details") or {}).get("semantic_export_path") or ""
                ))
                try:
                    prior_export = json.loads(prior_path.read_text(encoding="utf-8"))
                    if int(prior_export.get("export_version") or 0) != prior_export_version:
                        raise RuntimeError("Prior export version differs from its checkpoint")
                    projected_digest = migrated_checkpoint_digest(
                        semantic_state, prior_export, prior_digest,
                    )
                    if projected_digest != prior_digest:
                        semantic_errors.append({
                            "code": "semantic_state_changed_across_export_migration",
                            "message": (
                                "Facts represented by the prior semantic export "
                                "changed without a Verified IDA revision"
                            ),
                            "prior_export_version": prior_export_version,
                            "current_export_version": current_export_version,
                            "expected_digest": prior_digest,
                            "observed_projected_digest": projected_digest,
                        })
                except Exception as exc:
                    semantic_errors.append({
                        "code": "semantic_export_migration_unverifiable",
                        "message": str(exc),
                        "prior_export_version": prior_export_version,
                        "current_export_version": current_export_version,
                    })
            if (
                previous.get("status") == "verified"
                and prior_digest
                and prior_export_version == current_export_version
                and prior_digest != semantic_export["semantic_digest"]
            ):
                semantic_errors.append({
                    "code": "semantic_state_changed_without_revision",
                    "message": (
                        "Semantic IDA state changed since the prior checkpoint "
                        "without a Verified IDA revision"
                    ),
                    "expected_digest": prior_digest,
                    "observed_digest": semantic_export["semantic_digest"],
                })

        export_path = None
        if semantic_export:
            export_dir = self.workspace / "semantic_checkpoints" / component_id
            export_dir.mkdir(parents=True, exist_ok=True)
            export_path = export_dir / (
                "revision-%d-%s.json"
                % (revision, semantic_export["semantic_digest"][:16])
            )
            export_path.write_text(
                json.dumps(semantic_export, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        status = "verified" if not failures and not semantic_errors else "failed"
        return self.journal.record_checkpoint(
            component_id=component_id,
            revision=revision,
            status=status,
            idb_sha256=current_idb_sha256,
            details={
                "reason": reason,
                "verified_operations": verified_ids,
                "failed_operations": failures,
                "fresh_process": True,
                "semantic_export_version": (
                    semantic_export.get("export_version") if semantic_export else None
                ),
                "semantic_digest": (
                    semantic_export.get("semantic_digest") if semantic_export else None
                ),
                "semantic_counts": (
                    semantic_export.get("counts") if semantic_export else None
                ),
                "semantic_export_path": str(export_path) if export_path else None,
                "selected_local_functions": selected_locals,
                "selected_global_addresses": selected_globals,
                "errors": semantic_errors,
            },
        )

    def frontier_page(
        self,
        *,
        collection: str = "must_review",
        component_id: str | None = None,
        limit: int = 8,
        offset: int = 0,
    ) -> dict[str, Any]:
        return self.frontier.page(
            lane=collection,
            component_id=component_id,
            limit=limit,
            offset=offset,
        )

    def disposition_candidate(self, **kwargs: Any) -> dict[str, Any]:
        candidate_id = str(kwargs.get("candidate_id") or "")
        candidate = self.journal.candidate(candidate_id)
        if candidate and str(candidate.get("origin") or "").startswith(
            "claim_call_flow:"
        ):
            raise RuntimeError(
                "Claim-scoped call-flow work must use "
                "disposition_ida_call_flow_node or revalidate_ida_function_claim"
            )
        return self.journal.disposition_candidate(**kwargs)

    def read_call_flow_scope(
        self,
        *,
        scope_id: str | None = None,
        limit: int = 20,
        offset: int = 0,
    ) -> dict[str, Any]:
        if not scope_id:
            return self.journal.call_flow_review_state(
                scope_limit=min(max(1, int(limit)), 50),
                node_limit=200,
            )
        return self.journal.read_call_flow_scope(
            scope_id=scope_id,
            limit=limit,
            offset=offset,
        )

    def disposition_call_flow_node(
        self,
        *,
        scope_id: str,
        node_id: str,
        outcome: str,
        rationale: str,
        evidence_refs: Sequence[str],
        boundary_question: str = "",
        claim_impact: str = "",
        evidence_gap: str = "",
        expected_evidence: str = "",
        boundary_callees: Sequence[str] = (),
    ) -> dict[str, Any]:
        scope = self.journal.call_flow_scope(scope_id)
        if scope is None:
            raise RuntimeError("Unknown call-flow scope: %s" % scope_id)
        if scope["component_id"] != self.active_component_id:
            self._ensure_component_active(str(scope["component_id"]), remind=True)
        detail = self.journal.read_call_flow_scope(
            scope_id=scope_id, limit=50, offset=0
        )
        node = self.journal.call_flow_node(scope_id, str(node_id))
        if node is None:
            raise RuntimeError("Unknown current call-flow node: %s" % node_id)
        if str(outcome or "").strip().lower() == "unresolved_boundary":
            finding = self._reconciliation_finding_for_scope(scope_id)
            if finding is not None:
                component_id = str(scope["component_id"])
                allowed_edges = self._reconciliation_direct_edges(
                    finding, component_id
                )
                requested_edges = {
                    (_address(node["function_address"]), _address(destination))
                    for destination in boundary_callees
                }
                invalid = sorted(requested_edges - allowed_edges)
                if invalid:
                    formatted = ", ".join(
                        "%s->%s" % edge for edge in invalid
                    )
                    raise RuntimeError(
                        "Reconciliation call-flow expansion is limited to the "
                        "reviewer's exact direct-call targets; revise the finding "
                        "before adding: %s" % formatted
                    )
        inventory, discovery_evidence_id = self._inspect_direct_call_inventory(
            node["function_address"]
        )
        live_hash = str(
            dict(inventory.get("function") or {}).get("function_byte_hash") or ""
        )
        if node.get("function_byte_hash") and node["function_byte_hash"] != live_hash:
            self.journal.connection.execute(
                "UPDATE call_flow_nodes SET state = 'stale', updated_at = ? "
                "WHERE node_id = ?",
                (utc_now(), node_id),
            )
            self.journal.connection.commit()
            raise RuntimeError(
                "Call-flow node identity changed; refresh the parent scope before disposition"
            )
        result = self.journal.disposition_call_flow_node(
            scope_id=scope_id,
            node_id=node_id,
            outcome=outcome,
            rationale=rationale,
            evidence_refs=evidence_refs,
            live_inventory=inventory,
            discovery_evidence_id=discovery_evidence_id,
            boundary_question=boundary_question,
            claim_impact=claim_impact,
            evidence_gap=evidence_gap,
            expected_evidence=expected_evidence,
            boundary_callees=boundary_callees,
        )
        result["live_inventory_evidence_id"] = discovery_evidence_id
        result["prior_scope_page"] = detail["page"]
        return result

    def revalidate_function_claim(
        self,
        *,
        scope_id: str,
        outcome: str,
        parent_evidence_ref: str,
        rationale: str,
        operation_ids: Sequence[str] = (),
    ) -> dict[str, Any]:
        scope = self.journal.call_flow_scope(scope_id)
        if scope is None:
            raise RuntimeError("Unknown call-flow scope: %s" % scope_id)
        if scope["component_id"] != self.active_component_id:
            self._ensure_component_active(str(scope["component_id"]), remind=True)
        inventory, inventory_evidence = self._inspect_direct_call_inventory(
            scope["root_address"]
        )
        claim_digest = self._committed_claim_digest(inventory)
        if claim_digest is None:
            raise RuntimeError(
                "The scoped parent no longer has both a user name and behavior comment"
            )
        live_hash = str(
            dict(inventory.get("function") or {}).get("function_byte_hash") or ""
        )
        if (
            live_hash != scope["root_function_byte_hash"]
            or str(inventory.get("edge_set_digest") or "") != scope["edge_set_digest"]
        ):
            raise RuntimeError(
                "The parent call topology changed; refresh its committed claim before revalidation"
            )
        return self.journal.revalidate_call_flow_parent(
            scope_id=scope_id,
            outcome=outcome,
            rationale=rationale,
            parent_evidence_id=parent_evidence_ref,
            parent_inventory_evidence_id=inventory_evidence,
            operation_ids=operation_ids,
            resulting_claim_digest=claim_digest,
            live_function_byte_hash=live_hash,
        )

    @staticmethod
    def _reconciliation_target_addresses(
        finding: Mapping[str, Any], component_id: str
    ) -> set[str]:
        addresses: set[str] = set()
        for raw in finding.get("targets") or []:
            target = dict(raw) if isinstance(raw, Mapping) else {}
            if str(target.get("component_id") or finding.get("component_id")) != component_id:
                continue
            for key in (
                "address", "function_address", "source_address",
                "destination_address",
            ):
                if target.get(key) not in (None, ""):
                    addresses.add(_address(target[key]))
        return addresses

    @staticmethod
    def _reconciliation_evidence_matches_target(
        evidence: Mapping[str, Any],
        target: Mapping[str, Any],
        *,
        default_component_id: str,
    ) -> bool:
        component_id = str(
            target.get("component_id") or default_component_id
        )
        if str(evidence.get("component_id") or "") != component_id:
            return False
        evidence_kind = str(evidence.get("target_kind") or "")
        evidence_key = str(evidence.get("target_key") or "")

        def same_address(value: Any) -> bool:
            if value in (None, ""):
                return False
            try:
                return _address(evidence_key.split(":", 1)[0]) == _address(value)
            except RuntimeError:
                return False

        kind = str(target.get("kind") or "")
        if kind in {"function", "address", "global"}:
            return same_address(target.get("address"))
        if kind == "named_type":
            return (
                evidence_kind == "named_type"
                and evidence_key == str(target.get("name") or "")
            )
        if kind == "local_variable":
            # Stack-frame evidence is stored against the owning function; the
            # requested local identity is validated separately by the edit.
            return same_address(target.get("function_address"))
        if kind == "relationship":
            # A native direct-edge inventory is stored against its source
            # function. Code evidence for either endpoint is also relevant to
            # the frozen relationship question.
            return any(
                same_address(target.get(key))
                for key in (
                    "source_address", "destination_address", "callsite_address",
                )
            )
        return False

    @staticmethod
    def _reconciliation_direct_edges(
        finding: Mapping[str, Any], component_id: str
    ) -> set[tuple[str, str]]:
        edges: set[tuple[str, str]] = set()
        for raw in finding.get("targets") or []:
            target = dict(raw) if isinstance(raw, Mapping) else {}
            if str(target.get("component_id") or finding.get("component_id")) != component_id:
                continue
            if (
                target.get("kind") != "relationship"
                or target.get("relationship_kind") != "direct_call"
            ):
                continue
            source = target.get("source_address")
            destination = target.get("destination_address")
            if source not in (None, "") and destination not in (None, ""):
                edges.add((_address(source), _address(destination)))
        return edges

    def _reconciliation_finding_for_scope(
        self, scope_id: str
    ) -> dict[str, Any] | None:
        row = self.journal.connection.execute(
            "SELECT finding_id FROM reconciliation_findings "
            "WHERE call_flow_scope_id = ? ORDER BY updated_at DESC LIMIT 1",
            (scope_id,),
        ).fetchone()
        if row is None:
            return None
        return self.journal.reconciliation_finding(str(row["finding_id"]))

    def read_reconciliation(self) -> dict[str, Any]:
        if not self.coverage_reconciliation_enabled:
            return {
                "enabled": False,
                "state": "disabled",
                "findings": [],
                "open_count": 0,
            }
        return self.journal.reconciliation_status()

    def finalize_reconciliation_audit(
        self, *, completion: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Persist the one fixed-set audit that authorizes final completion."""

        status = self.journal.reconciliation_status()
        round_row = dict(status.get("round") or {})
        resolution = dict(status.get("resolution_audit") or {})
        if not round_row or not resolution.get("all_mandatory_findings_resolved"):
            raise RuntimeError("Reconciliation finding set is not resolved")
        if status.get("open_count"):
            raise RuntimeError("Reconciliation still has an active wave")
        call_flow = self.journal.call_flow_summary()
        if call_flow.get("active_scopes"):
            raise RuntimeError("Reconciliation call-flow scope remains active")
        mechanical = self.journal.mechanical_issues()
        if mechanical:
            raise RuntimeError("Mechanical failures remain before reconciliation audit")

        checkpoints = list(completion.get("checkpoints") or [])
        expected_components = {
            str(row["component_id"]): int(
                self.journal.revision(str(row["component_id"]))["revision"]
            )
            for row in self.journal.components()
            if row.get("idb_path")
        }
        observed_components = {
            str(row.get("component_id")): int(row.get("revision", -1))
            for row in checkpoints
            if row.get("status") == "verified"
        }
        if observed_components != expected_components:
            raise RuntimeError(
                "Final reconciliation checkpoints do not match current component revisions"
            )
        for row in checkpoints:
            component_id = str(row.get("component_id") or "")
            revision = int(row.get("revision", -1))
            persisted = self.journal.latest_verified_checkpoint(
                component_id,
                revision=revision,
            )
            if (
                persisted is None
                or str(persisted.get("checkpoint_id") or "")
                != str(row.get("checkpoint_id") or "")
            ):
                raise RuntimeError(
                    "Final reconciliation audit requires journal-backed current "
                    "component checkpoints"
                )
        completion_digest = hashlib.sha256(
            canonical_json([
                {
                    "component_id": row.get("component_id"),
                    "revision": row.get("revision"),
                    "idb_sha256": row.get("idb_sha256"),
                    "semantic_digest": dict(row.get("details") or {}).get(
                        "semantic_digest"
                    ),
                    "status": row.get("status"),
                }
                for row in sorted(
                    checkpoints, key=lambda item: str(item.get("component_id"))
                )
            ]).encode("utf-8")
        ).hexdigest()
        details = {
            "mandatory_count": resolution.get("mandatory_count"),
            "terminal_count": resolution.get("terminal_count"),
            "active_finding_ids": resolution.get("active_finding_ids") or [],
            "active_call_flow_scope_count": 0,
            "mechanical_failure_count": 0,
            "component_revisions": expected_components,
            "finding_operation_links": {
                str(row["finding_id"]): list(row.get("operation_ids") or [])
                for row in self.journal.reconciliation_history(limit=200)
                if str(row.get("round_id") or "")
                == str(round_row.get("round_id") or "")
            },
        }
        return self.journal.record_reconciliation_audit(
            round_id=str(round_row["round_id"]),
            finding_set_digest=str(resolution["finding_set_digest"]),
            completion_digest=completion_digest,
            checkpoints={"checkpoints": checkpoints},
            details=details,
        )

    def open_reconciliation_call_flow(
        self,
        *,
        finding_id: str,
        root_address: str,
        boundary_callees: Sequence[str],
    ) -> dict[str, Any]:
        """Open exact downstream work selected by one reconciliation finding."""

        if not self.coverage_reconciliation_enabled:
            raise RuntimeError("Coverage reconciliation is not enabled")
        finding = self.journal.reconciliation_finding(str(finding_id))
        if finding is None or finding["state"] not in {"open", "investigating"}:
            raise RuntimeError("Reconciliation finding is not active")
        status = self.journal.reconciliation_status()
        visible = {row["finding_id"] for row in status.get("findings") or []}
        if finding["finding_id"] not in visible:
            raise RuntimeError("Finding is outside the current reconciliation wave")
        component_id = str(finding["component_id"])
        normalized_root = _address(root_address)
        selected = list(dict.fromkeys(_address(value) for value in boundary_callees))
        if not selected:
            raise RuntimeError("A selected reconciliation scope requires exact callees")
        target_addresses = self._reconciliation_target_addresses(
            finding, component_id
        )
        if normalized_root not in target_addresses:
            raise RuntimeError("Scope root is not an exact target of this finding")
        if not set(selected).issubset(target_addresses):
            raise RuntimeError(
                "Every selected callee must be an exact target of this finding"
            )
        selected_edges = {(normalized_root, destination) for destination in selected}
        finding_edges = self._reconciliation_direct_edges(finding, component_id)
        if not selected_edges.issubset(finding_edges):
            raise RuntimeError(
                "Every selected boundary must be an explicit direct-call "
                "relationship target of this finding"
            )
        if component_id != self.active_component_id:
            self._ensure_component_active(component_id, remind=True)
        inventory, evidence_id = self._inspect_direct_call_inventory(normalized_root)
        direct = {
            _address(edge["destination"])
            for edge in inventory.get("edges") or []
            if isinstance(edge, Mapping)
            and edge.get("edge_kind") == "direct_internal"
            and edge.get("classification_source") == "ida_instruction_feature"
            and edge.get("destination") not in (None, "")
        }
        invalid = sorted(set(selected) - direct)
        if invalid:
            raise RuntimeError(
                "Selected boundary is not a current IDA-native direct callee: %s"
                % ", ".join(invalid)
            )
        claim_digest = self._committed_claim_digest(inventory)
        if claim_digest is None:
            raise RuntimeError(
                "The selected parent needs a persisted user name and behavior comment "
                "before its claim can be revalidated"
            )
        row = self.journal.connection.execute(
            """
            SELECT o.operation_id FROM operations o
            JOIN receipts r ON r.rowid = (
                SELECT r2.rowid FROM receipts r2
                WHERE r2.operation_id = o.operation_id
                ORDER BY r2.rowid DESC LIMIT 1
            )
            WHERE o.component_id = ? AND o.target_kind = 'function'
              AND o.target_key = ?
              AND o.kind IN ('function.rename', 'function.comment.set')
              AND r.status IN ('verified', 'already_satisfied')
            ORDER BY o.rowid DESC LIMIT 1
            """,
            (component_id, normalized_root),
        ).fetchone()
        if row is None:
            raise RuntimeError(
                "No verified model operation establishes the selected parent claim"
            )
        scope = self.journal.open_call_flow_scope(
            component_id=component_id,
            root_address=normalized_root,
            operation_id=str(row["operation_id"]),
            root_claim_digest=claim_digest,
            trigger_revision=int(self.journal.revision(component_id)["revision"]),
            inventory=inventory,
            discovery_evidence_id=evidence_id,
            allowed_destinations=selected,
        )
        linked = self.journal.link_reconciliation_call_flow(
            finding_id=str(finding_id),
            scope_id=str(scope["scope"]["scope_id"]),
        )
        return {
            "schema": "verified_ida.reconciliation_call_flow.v1",
            "finding": linked,
            "scope": scope,
            "selected_boundaries": selected,
        }

    def disposition_reconciliation_finding(self, **kwargs: Any) -> dict[str, Any]:
        finding = self.journal.reconciliation_finding(
            str(kwargs.get("finding_id") or "")
        )
        if finding is None:
            raise RuntimeError("Unknown reconciliation finding")
        status = self.journal.reconciliation_status()
        visible = {row["finding_id"] for row in status.get("findings") or []}
        if finding["finding_id"] not in visible:
            raise RuntimeError("Finding is outside the current reconciliation wave")
        refs = list(kwargs.get("evidence_refs") or [])
        if not refs:
            raise RuntimeError("Reconciliation disposition requires current evidence")
        current_components = set()
        matching_evidence = set()
        finding_targets = [dict(row) for row in finding.get("targets") or []]
        for evidence_id in refs:
            evidence = self.journal.inspection(str(evidence_id))
            if evidence is None:
                raise RuntimeError("Unknown reconciliation evidence: %s" % evidence_id)
            component_id = str(evidence["component_id"])
            revision = int(self.journal.revision(component_id)["revision"])
            if int(evidence["revision"]) != revision:
                raise RuntimeError(
                    "Reconciliation evidence is stale: %s" % evidence_id
                )
            current_components.add(component_id)
            if any(
                self._reconciliation_evidence_matches_target(
                    evidence,
                    target,
                    default_component_id=str(finding["component_id"]),
                )
                for target in finding_targets
            ):
                matching_evidence.add(str(evidence_id))
        if str(finding["component_id"]) not in current_components:
            raise RuntimeError(
                "Disposition needs current evidence from the finding's primary component"
            )
        if not matching_evidence:
            raise RuntimeError(
                "Disposition needs current evidence for at least one exact frozen target"
            )
        activity = self.journal.reconciliation_activity(
            str(finding["finding_id"]), limit=2000
        )
        active_evidence = {
            str(row["external_id"])
            for row in activity
            if row.get("activity_kind") == "inspection"
        }
        if not matching_evidence.intersection(active_evidence):
            raise RuntimeError(
                "Disposition target evidence was not acquired under the active finding"
            )
        if str(kwargs.get("outcome") or "").lower() == "revised":
            from pydantic import TypeAdapter
            from .review_contracts import ReviewTarget

            normalized_targets = TypeAdapter(list[ReviewTarget]).validate_python(
                list(kwargs.get("revised_targets") or [])
            )
            kwargs["revised_targets"] = [
                row.model_dump(mode="json") for row in normalized_targets
            ]
            for target in kwargs["revised_targets"]:
                component_id = str(
                    target.get("component_id") or finding["component_id"]
                )
                if self.journal.component(component_id) is None:
                    raise RuntimeError(
                        "Revised target names unknown component %s" % component_id
                    )
                if target["kind"] == "named_type":
                    page = self.query_ida_collection(
                        family="types",
                        filters={"name_prefix": target["name"]},
                        limit=20,
                        component_id=component_id,
                    )
                    if not any(
                        str(row.get("name") or "") == target["name"]
                        for row in page.get("items") or []
                    ):
                        raise RuntimeError("Revised named-type target does not exist")
                    continue
                for address in self._reconciliation_target_addresses(
                    {"component_id": component_id, "targets": [target]},
                    component_id,
                ):
                    result = self.inspect(
                        query="inspect_addr",
                        target=address,
                        component_id=component_id,
                        limit=1,
                    )
                    if not dict(result.get("result") or {}).get("ok"):
                        raise RuntimeError(
                            "Revised target does not resolve: %s::%s"
                            % (component_id, address)
                        )
        operation_ids = list(kwargs.get("operation_ids") or [])
        current_operations = {
            str(row["operation_id"]): row
            for row in self.journal.current_operations()
            if dict(row.get("receipt") or {}).get("status") in VERIFIED_STATUSES
        }
        invalid_operations = sorted(set(operation_ids) - set(current_operations))
        if invalid_operations:
            raise RuntimeError(
                "Disposition cites non-current verified operations: %s"
                % ", ".join(invalid_operations)
            )
        active_operations = {
            str(row["external_id"])
            for row in activity
            if row.get("activity_kind") == "operation"
        }
        for operation_id in operation_ids:
            operation = current_operations[operation_id]
            request = dict(operation.get("request") or {})
            if (
                str(request.get("work_item_id") or "")
                != str(finding["finding_id"])
                or operation_id not in active_operations
            ):
                raise RuntimeError(
                    "Disposition operation was not applied under the active finding: %s"
                    % operation_id
                )
            target = dict(request.get("target") or {})
            component_id = str(operation.get("component_id") or "")
            matched = False
            for review_target in finding_targets:
                if str(review_target.get("component_id") or finding["component_id"]) != component_id:
                    continue
                kind = str(review_target.get("kind") or "")
                operation_kind = str(target.get("kind") or "")
                # A mixed finding is a union of typed targets, not a sequence
                # of address parsers. Never read another target kind's fields.
                if kind == "address":
                    if operation_kind not in {"address", "function", "global"}:
                        continue
                elif operation_kind != kind:
                    continue
                if kind in {"function", "address", "global"}:
                    operation_address = target.get("address")
                    matched = (
                        operation_address not in (None, "")
                        and _address(operation_address)
                        == _address(review_target.get("address"))
                    )
                elif kind == "named_type":
                    matched = (
                        str(target.get("name") or "")
                        == str(review_target.get("name") or "")
                    )
                elif kind == "local_variable":
                    matched = (
                        _address(target.get("function_address"))
                        == _address(review_target.get("function_address"))
                        and (
                            review_target.get("lvar_index") is None
                            or int(target.get("lvar_index", -1))
                            == int(review_target["lvar_index"])
                        )
                    )
                elif kind == "relationship":
                    matched = (
                        _address(target.get("source_address"))
                        == _address(review_target.get("source_address"))
                        and _address(target.get("destination_address"))
                        == _address(review_target.get("destination_address"))
                        and (
                            review_target.get("callsite_address") in (None, "")
                            or _address(target.get("callsite_address"))
                            == _address(review_target.get("callsite_address"))
                        )
                        and str(target.get("relationship_kind") or "")
                        == str(review_target.get("relationship_kind") or "")
                    )
                if matched:
                    break
            if not matched:
                raise RuntimeError(
                    "Disposition operation is outside the finding's exact targets: %s"
                    % operation_id
                )
        return self.journal.disposition_reconciliation_finding(**kwargs)

    def promote_candidate(self, **kwargs: Any) -> dict[str, Any]:
        return self.journal.promote_candidate(**kwargs)

    def abandon_operation(self, **kwargs: Any) -> dict[str, Any]:
        return self.journal.abandon_operation(**kwargs)

    def completion_status(self) -> dict[str, Any]:
        return self.journal.completion_status()

    def _closure_input_fingerprint(
        self,
        *,
        notebook: Mapping[str, Any] | None = None,
        components: Sequence[Mapping[str, Any]] | None = None,
        revisions: Mapping[str, int] | None = None,
    ) -> str:
        """Fingerprint semantic state that a closure review must reconcile.

        The Closure Review section and journal are deliberately excluded so
        recording the reconciliation does not invalidate itself.
        """

        notebook_view = dict(notebook or self.read_reversing_log(journal_limit=1))
        current_state = dict(notebook_view.get("current_state") or {})
        analytical_sections = {
            key: str(dict(value or {}).get("digest") or "")
            for key, value in current_state.items()
            if key != "closure_review"
        }
        component_rows = list(components or self.journal.components())
        revision_map = dict(revisions or {
            str(row["component_id"]): int(
                self.journal.revision(str(row["component_id"]))["revision"]
            )
            for row in component_rows
        })
        component_state = [{
            "component_id": str(row.get("component_id") or ""),
            "parent_component_id": row.get("parent_component_id"),
            "binary_sha256": row.get("binary_sha256"),
            "architecture": row.get("architecture"),
            "status": row.get("status"),
            "has_idb": bool(row.get("idb_path")),
            "revision": int(revision_map.get(str(row.get("component_id")), 0)),
        } for row in component_rows]
        extraction_state = [
            {
                "extraction_id": str(row["extraction_id"]),
                "parent_component_id": str(row["parent_component_id"]),
                "child_component_id": row["child_component_id"],
                "status": str(row["status"]),
                "artifact_sha256": row["artifact_sha256"],
            }
            for row in self.journal.connection.execute(
                "SELECT extraction_id, parent_component_id, child_component_id, "
                "status, artifact_sha256 FROM extractions ORDER BY extraction_id"
            ).fetchall()
        ]
        material = {
            "objective_sha256": hashlib.sha256(
                self.project_objective.encode("utf-8")
            ).hexdigest(),
            "analytical_current_state": analytical_sections,
            "components": component_state,
            "component_recovery_decisions": extraction_state,
            "claim_scoped_call_flow": self.journal.call_flow_fingerprint_state(),
        }
        return hashlib.sha256(
            canonical_json(material).encode("utf-8")
        ).hexdigest()

    def _closure_reconciliation_status(self) -> dict[str, Any]:
        review = self.journal.latest_closure_review()
        if review is None:
            return {
                "status": "required",
                "ready": False,
                "code": "closure_review_required",
                "next_action": (
                    "Read reversing_log.md, call review_analysis_closure, compare "
                    "its bounded questions with live IDA state, and update the "
                    "Closure Review section."
                ),
            }
        if not review.get("closure_update_id"):
            return {
                "status": "required",
                "ready": False,
                "code": "closure_review_update_required",
                "review_id": review["review_id"],
                "review_epoch": review["epoch"],
                "next_action": (
                    "Update the protected Closure Review section after reconciling "
                    "the latest closure packet with live IDA state."
                ),
            }
        packet_path = Path(str(review.get("packet_path") or ""))
        try:
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError) as exc:
            return {
                "status": "required",
                "ready": False,
                "code": "closure_review_packet_unavailable",
                "review_id": review["review_id"],
                "error": type(exc).__name__,
                "next_action": "Call review_analysis_closure again and record its result.",
            }
        expected = str(
            dict(packet.get("reconciliation") or {}).get("input_fingerprint")
            or ""
        )
        current = self._closure_input_fingerprint()
        notebook = self.read_reversing_log(journal_limit=1)
        current_closure_digest = str(
            dict(dict(notebook.get("current_state") or {}).get("closure_review") or {}).get(
                "digest"
            )
            or ""
        )
        if not expected or expected != current:
            return {
                "status": "stale",
                "ready": False,
                "code": "closure_review_stale",
                "review_id": review["review_id"],
                "review_epoch": review["epoch"],
                "expected_input_fingerprint": expected or None,
                "current_input_fingerprint": current,
                "next_action": (
                    "Material IDB, component, or analytical notebook state changed "
                    "after the review. Call review_analysis_closure again and update "
                    "the Closure Review section."
                ),
            }
        if current_closure_digest != str(review.get("closure_update_digest") or ""):
            return {
                "status": "stale",
                "ready": False,
                "code": "closure_review_section_changed",
                "review_id": review["review_id"],
                "next_action": (
                    "The Closure Review section no longer matches the recorded "
                    "reconciliation. Re-run closure review and record the current result."
                ),
            }
        return {
            "status": "current",
            "ready": True,
            "code": "closure_reconciliation_current",
            "review_id": review["review_id"],
            "review_epoch": review["epoch"],
            "input_fingerprint": current,
            "closure_update_id": review["closure_update_id"],
        }

    def _closure_query_component(
        self,
        component_id: str,
        task: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Run one read-only closure query without switching or saving the IDB."""

        component = self.journal.component(component_id)
        if component is None or not component.get("idb_path"):
            raise RuntimeError("Component is not analysis-ready: %s" % component_id)
        temporary = component_id != self.active_component_id
        session = self.session if not temporary else self._session_factory(component)
        if temporary and hasattr(session, "start"):
            session = session.start()
        try:
            response = session.query(dict(task))
            return dict(response.get("result", response))
        finally:
            if temporary and hasattr(session, "close"):
                session.close(save=False)

    def _closure_semantic_state(self, component_id: str) -> dict[str, Any]:
        """Read current semantic state without saving or switching the IDB."""

        component = self.journal.component(component_id)
        if component is None or not component.get("idb_path"):
            raise RuntimeError("Component is not analysis-ready: %s" % component_id)
        temporary = component_id != self.active_component_id
        session = self.session if not temporary else self._session_factory(component)
        if temporary and hasattr(session, "start"):
            session = session.start()
        try:
            export = dict(session.semantic_export(
                selected_local_functions=self.journal.semantic_local_functions(
                    component_id
                ),
                selected_global_addresses=self.journal.semantic_global_addresses(
                    component_id
                ),
            ))
            state = export.get("state")
            if not export.get("ok") or not isinstance(state, Mapping):
                raise RuntimeError("IDA did not return current semantic state")
            return dict(state)
        finally:
            if temporary and hasattr(session, "close"):
                session.close(save=False)

    @staticmethod
    def _compact_closure_survey(result: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "ok": result.get("ok"),
            "binary": dict(result.get("binary") or {}),
            "inventory": dict(result.get("inventory") or {}),
            "analysis": dict(result.get("analysis") or {}),
            "segments": [
                {
                    key: row.get(key)
                    for key in ("name", "start", "end", "permissions")
                    if row.get(key) is not None
                }
                for row in (result.get("segments") or [])[:16]
                if isinstance(row, Mapping)
            ],
        }

    def review_analysis_closure(self) -> dict[str, Any]:
        """Return a bounded advisory review packet and record its review epoch."""

        notebook = self.read_reversing_log(journal_limit=3)
        notebook["freshness"] = {
            "project_state_reminder": self.journal.notebook_reminder_state(),
            "recent_updates": self.journal.notebook_updates(limit=12)[-12:],
        }
        components = self.journal.components()
        revisions = {
            str(row["component_id"]): int(
                self.journal.revision(str(row["component_id"]))["revision"]
            )
            for row in components
        }
        operations = self.journal.current_operations()

        live_project_summaries: dict[str, Any] = {}
        analysis_advisories: list[dict[str, Any]] = []
        for component in components:
            component_id = str(component["component_id"])
            if not component.get("idb_path"):
                continue
            try:
                result = self._closure_query_component(
                    component_id, {"task_type": "survey_idb"}
                )
                compact = self._compact_closure_survey(result)
                evidence = self.journal.record_inspection(
                    component_id=component_id,
                    target_kind="database",
                    target_key=component_id,
                    query_kind="closure_survey_idb",
                    result=compact,
                    revision=revisions[component_id],
                )
                live_project_summaries[component_id] = {
                    **compact,
                    "evidence": {
                        "query": "closure_survey_idb",
                        "revision": revisions[component_id],
                        "result_digest": evidence["result_digest"],
                    },
                }
            except Exception as exc:
                live_project_summaries[component_id] = {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                }
            if self.analysis_feedback_profile == "scoped":
                try:
                    advisory = self._unapplied_type_advisory(
                        component_id,
                        semantic_state=self._closure_semantic_state(component_id),
                    )
                    if advisory:
                        analysis_advisories.append({
                            **advisory,
                            "presentation_reason": "analysis_closure_review",
                        })
                except Exception as exc:
                    analysis_advisories.append({
                        "schema": "verified_ida.analysis_advisory.v1",
                        "kind": "declared_but_unapplied_types",
                        "component_id": component_id,
                        "revision": revisions[component_id],
                        "measurement_status": "unavailable",
                        "error": type(exc).__name__,
                        "message": str(exc),
                        "advisory": True,
                        "completion_blocker": False,
                        "presentation_reason": "analysis_closure_review",
                    })

        references = declared_references(notebook.get("current_state") or {})
        live_functions: dict[str, Any] = {}
        declared_targets = [
            (str(row["component_id"]), str(row["address"])) for row in references
        ]
        all_targets = touched_function_addresses(operations, references)
        targets = list(dict.fromkeys([
            *declared_targets,
            *reversed(all_targets),
        ]))[:64]
        for component_id, address in targets:
            qualified = "%s::%s" % (component_id, address)
            if self.journal.component(component_id) is None:
                live_functions[qualified] = {
                    "ok": False,
                    "error": "unknown_component",
                }
                continue
            try:
                summary = self._closure_query_component(component_id, {
                    "task_type": "inspect_function_summary",
                    "target": address,
                    "limit": 12,
                })
                evidence = self.journal.record_inspection(
                    component_id=component_id,
                    target_kind="function",
                    target_key=address,
                    query_kind="closure_inspect_function_summary",
                    result=summary,
                    revision=revisions[component_id],
                )
                entry = {
                    "ok": summary.get("ok"),
                    "function": dict(summary.get("function") or {}),
                    "relationships": dict(summary.get("relationships") or {}),
                    "references": dict(summary.get("references") or {}),
                    "cfg": dict(summary.get("cfg") or {}),
                    "evidence": {
                        "query": "closure_inspect_function_summary",
                        "revision": revisions[component_id],
                        "result_digest": evidence["result_digest"],
                    },
                }
                try:
                    parameter_result = self._closure_query_component(
                        component_id,
                        {
                            "task_type": "inspect_stack_frame",
                            "target": address,
                            "limit": 32,
                        },
                    )
                    parameter_evidence = self.journal.record_inspection(
                        component_id=component_id,
                        target_kind="function",
                        target_key=address,
                        query_kind="closure_inspect_parameter_provenance",
                        result=parameter_result,
                        revision=revisions[component_id],
                    )
                    entry["parameters"] = [
                        {
                            key: row.get(key)
                            for key in (
                                "index",
                                "name",
                                "type",
                                "is_arg",
                                "has_user_name",
                                "name_provenance",
                                "has_user_type",
                                "type_provenance",
                                "location",
                            )
                        }
                        for row in list(
                            parameter_result.get("local_variables") or []
                        )[:32]
                        if isinstance(row, Mapping) and row.get("is_arg")
                    ]
                    entry["parameter_evidence"] = {
                        "query": "closure_inspect_parameter_provenance",
                        "revision": revisions[component_id],
                        "result_digest": parameter_evidence["result_digest"],
                    }
                except Exception as exc:
                    entry["parameters"] = []
                    entry["parameter_evidence"] = {
                        "query": "closure_inspect_parameter_provenance",
                        "revision": revisions[component_id],
                        "status": "unavailable",
                        "error": type(exc).__name__,
                    }
                callee_result = self._closure_query_component(component_id, {
                    "task_type": "inspect_callees",
                    "target": address,
                    "limit": 8,
                })
                callee_evidence = self.journal.record_inspection(
                    component_id=component_id,
                    target_kind="function",
                    target_key=address,
                    query_kind="closure_inspect_callees",
                    result=callee_result,
                    revision=revisions[component_id],
                )
                entry["callees"] = list(callee_result.get("callees") or [])[:8]
                entry["callee_count"] = int(callee_result.get("callee_count") or 0)
                entry["callee_evidence"] = {
                    "query": "closure_inspect_callees",
                    "revision": revisions[component_id],
                    "result_digest": callee_evidence["result_digest"],
                }
                live_functions[qualified] = entry
            except Exception as exc:
                live_functions[qualified] = {
                    "ok": False,
                    "error": type(exc).__name__,
                    "message": str(exc),
                }

        completion = self.journal.completion_status()
        frontier = {
            "must_review": completion["must_review"],
            "must_review_count": len(completion["must_review"]),
            "suggested_next_count": int(completion["suggested_next_count"]),
            "mechanical_failure_count": len(completion["mechanical_failures"]),
            "component_decision_count": len(
                completion["component_decisions_required"]
            ),
            "policy": "current obligations plus advisory inventory counts only",
        }
        packet_components = [
            self._model_component(component) for component in components
        ]
        packet, packet_digest = build_closure_packet(
            objective=self.project_objective,
            notebook=notebook,
            components=packet_components,
            revisions=revisions,
            operations=operations,
            frontier=frontier,
            live_project_summaries=live_project_summaries,
            live_functions=live_functions,
            analysis_advisories=analysis_advisories,
            call_flow=self.journal.call_flow_review_state(),
        )
        packet["reconciliation"] = {
            "schema": "verified_ida.closure_reconciliation_input.v1",
            "input_fingerprint": self._closure_input_fingerprint(
                notebook=notebook,
                components=components,
                revisions=revisions,
            ),
            "excludes": [
                "closure_review_section",
                "investigation_journal",
                "transport_bookkeeping",
            ],
            "instruction": (
                "Compare consequential notebook claims and workstreams with live "
                "IDA state. Persist, revise, or explicitly classify material gaps, "
                "then update the Closure Review section."
            ),
        }
        packet_digest = hashlib.sha256(
            canonical_json(packet).encode("utf-8")
        ).hexdigest()
        directory = self.workspace / "closure_reviews"
        directory.mkdir(parents=True, exist_ok=True)
        packet_path = directory / ("packet-%s.json" % packet_digest[:20])
        encoded = json.dumps(packet, indent=2, sort_keys=True) + "\n"
        if not packet_path.exists():
            temporary = packet_path.with_suffix(".json.tmp")
            temporary.write_text(encoded, encoding="utf-8")
            temporary.replace(packet_path)
        closure_state = notebook["current_state"]["closure_review"]
        review = self.journal.record_closure_review(
            active_component_id=str(self.active_component_id),
            objective_digest=hashlib.sha256(
                self.project_objective.encode("utf-8")
            ).hexdigest(),
            notebook_digest=str(notebook["document_digest"]),
            closure_section_digest=str(closure_state["digest"]),
            component_revisions=revisions,
            packet_digest=packet_digest,
            packet_path=packet_path,
            candidate_count=int(packet["review_candidates"]["total"]),
        )
        return {
            "schema": "verified_ida.analysis_closure_review_result.v1",
            "review_id": review["review_id"],
            "review_epoch": review["epoch"],
            "packet_digest": packet_digest,
            "packet_path": str(packet_path.resolve()),
            "blocking": False,
            "mechanical_completion_status": self.journal.completion_status(),
            "packet": packet,
        }

    def recover_component(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        self._require_writable()
        return self.components.recover(payload)

    def decide_component(self, **kwargs: Any) -> dict[str, Any]:
        self._require_writable()
        result = self.components.decide(**kwargs)
        component = result.get("component")
        if isinstance(component, Mapping):
            result["suggested_next"] = self.frontier.suggest_component(
                str(component["component_id"]),
                str(component.get("parent_component_id") or "root"),
            )
            reminder = self.journal.note_notebook_material_event(
                event_kind="component_accepted",
                component_id=str(component["component_id"]),
                immediate=True,
            )
            if reminder:
                result["project_state_reminder"] = reminder
            result["component_handoff"] = {
                "schema": "verified_ida.component_handoff.v1",
                "policy": self.component_handoff_policy,
                "checkpoint_status": "requested",
                "parent_component_id": str(
                    component.get("parent_component_id") or "root"
                ),
                "child_component_id": str(component["component_id"]),
                "blocking": False,
                "required_content": [
                    "parent artifact or function that exposed or constructed the child",
                    "accepted child identity and byte provenance",
                    "supported parent-side selection, invocation, and communication role",
                    "remaining parent-side uncertainty",
                    "exact parent target or workstream to resume",
                ],
                "instruction": (
                    "Checkpoint the parent-to-child transition before switching. "
                    "Persist supported parent conclusions in its IDB and update "
                    "reversing_log.md with the exact parent resume point."
                ),
            }
            result["component"] = self._model_component(component)
        return result

    def read_reversing_log(
        self,
        *,
        journal_limit: int = 3,
        journal_cursor: str | None = None,
    ) -> dict[str, Any]:
        path = self.workspace / "reversing_log.md"
        from .notebook_evidence import register_notebook_read
        result = read_notebook(
            path,
            journal_limit=journal_limit,
            journal_cursor=journal_cursor,
        )
        return register_notebook_read(self, result)

    def _record_notebook_update(self, result: Mapping[str, Any]) -> dict[str, Any]:
        component_id = self.active_component_id
        revision = int(self.journal.revision(component_id)["revision"])
        update = self.journal.record_notebook_update(
            action=str(result["action"]),
            section=str(result["section"]),
            before_digest=str(result["before_digest"]),
            after_digest=str(result["after_digest"]),
            component_id=component_id,
            revision=revision,
            tool_result=result,
        )
        recorded_result = {
            **dict(result),
            "update_id": update["update_id"],
            "active_component": component_id,
            "database_revision": revision,
            "recorded_at": update["created_at"],
        }
        if result["section"] == "closure_review":
            closure = self.journal.attach_closure_update(
                update_id=update["update_id"],
                closure_digest=str(result["after_digest"]),
            )
            if closure:
                recorded_result["closure_review_epoch"] = closure["epoch"]
                recorded_result["closure_review_id"] = closure["review_id"]
        return recorded_result

    def update_reversing_log_section(
        self,
        *,
        section: str,
        content: str,
        expected_digest: str,
    ) -> dict[str, Any]:
        path = self.workspace / "reversing_log.md"
        result = update_notebook_section(
            path,
            section=section,
            content=content,
            expected_digest=expected_digest,
        )
        recorded = self._record_notebook_update(result)
        self.journal.clear_notebook_reminder(update_id=recorded["update_id"])
        return {**recorded, "project_state_reminder_cleared": True}

    def append_reversing_log_journal(
        self,
        *,
        title: str,
        content: str,
        expected_journal_digest: str,
    ) -> dict[str, Any]:
        path = self.workspace / "reversing_log.md"
        result = append_notebook_journal(
            path,
            title=title,
            content=content,
            expected_journal_digest=expected_journal_digest,
        )
        return self._record_notebook_update(result)

    def write_static_extractor(self, *, relative_path: str, source: str) -> dict[str, Any]:
        self._require_writable()
        relative = Path(str(relative_path))
        if (
            len(relative.parts) != 2
            or relative.parts[0] != "extractors"
            or relative.suffix != ".py"
        ):
            raise RuntimeError("Static extractor path must be extractors/<name>.py")
        validation = validate_static_extractor_script(str(source))
        path = (self.workspace / relative).resolve()
        if self.workspace not in path.parents:
            raise RuntimeError("Static extractor path escapes the workspace")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(source), encoding="utf-8")
        return {"path": str(relative), "validation": validation}

    def complete(self) -> dict[str, Any]:
        status = self.completion_status()
        # A failed checkpoint stays visible until verification succeeds, but
        # must not prevent a verification-only retry once other work is closed.
        if not status.get("ready_for_checkpoint", status["may_finish"]):
            return status
        reconciliation = self._closure_reconciliation_status()
        if not reconciliation["ready"]:
            return {
                **status,
                "may_finish": False,
                "closure_reconciliation": reconciliation,
                "policy": (
                    str(status.get("policy") or "")
                    + "; require a fresh notebook-to-IDB closure reconciliation"
                ),
            }
        components = [
            row for row in self.journal.components() if row.get("idb_path")
        ]
        components.sort(key=lambda row: row["component_id"] == self.active_component_id)
        checkpoints = [
            self.checkpoint_component(
                str(component["component_id"]), reason="final_completion"
            )
            for component in components
        ]
        final_status = self.completion_status()
        checkpoint_failures = [
            row for row in checkpoints if row.get("status") != "verified"
        ]
        return {
            **final_status,
            "may_finish": bool(final_status["may_finish"] and not checkpoint_failures),
            "closure_reconciliation": self._closure_reconciliation_status(),
            "checkpoints": checkpoints,
            "component_verification_failures": checkpoint_failures,
            "components": self.list_components()["components"],
        }

    def close(self) -> None:
        try:
            self._close()
        finally:
            self._project_lock.close()

    def _close(self) -> None:
        if self._session is not None:
            # Mutations are saved synchronously by apply().  Closing the
            # workbench only discards query/decompiler side effects.
            self._session.close(save=False)
            self._session = None
        if self.active_component_id:
            self.journal.set_component_status(
                self.active_component_id, "analysis_ready"
            )
        self.active_component_id = None
        self.journal.close()

    def __enter__(self) -> "VerifiedIdaRuntime":
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()
