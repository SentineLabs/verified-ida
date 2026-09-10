"""Pure-Python validation and receipt helpers for the Verified IDA standard."""

from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping


OPERATION_SCHEMA = "verified_ida.operation.v1"
RECEIPT_SCHEMA = "verified_ida.receipt.v1"

SUPPORTED_KINDS = {
    "function.rename",
    "function.comment.set",
    "address.comment.set",
    "function.folder.set",
    "function.prototype.set",
    "local.rename",
    "local.type.set",
    "global.rename",
    "global.type.set",
    "named_type.create_or_update",
    "relationship.annotate",
}

TARGET_KINDS = {
    "function",
    "address",
    "global",
    "local_variable",
    "named_type",
    "relationship",
    "folder_entry",
}

RECEIPT_STATUSES = {
    "rejected",
    "conflict",
    "blocked",
    "failed",
    "ineffective",
    "unverified",
    "verified",
    "verified_existing",
}
VERIFIED_STATUSES = {"verified", "verified_existing"}
RECEIPT_STAGES = {
    "validation",
    "execution",
    "readback",
    "rerender",
    "persistence",
    "semantic_review",
    # Host-owned transaction checks run after the IDA worker's ordinary
    # readback but before a candidate database can replace the canonical IDB.
    # Keep them explicit so a failed fresh-process readback and an unexpected
    # semantic side effect are distinguishable to the model and audit log.
    "transaction_verification",
    "transaction_semantic_delta",
}
PERSISTENCE_STATES = {"not_checked", "pending", "verified", "failed"}
SEMANTIC_STATES = {"unreviewed", "accepted", "rejected", "superseded"}

OPERATION_FIELDS = {
    "schema", "operation_id", "work_item_id", "kind", "artifact", "target",
    "desired", "preconditions", "evidence", "depends_on", "metadata",
}
ARTIFACT_FIELDS = {"binary_sha256", "database_id", "database_revision", "image_base"}
TARGET_FIELDS = {
    "kind", "address", "function_address", "source_address", "destination_address",
    "callsite_address",
    "current_name", "name", "is_parameter", "lvar_index", "location", "current_type",
    "use_site", "type_ordinal", "declaration_digest", "relationship_kind", "current_folder",
    "function_byte_hash",
}
DESIRED_ALLOWED_FIELDS = {
    "name", "comment", "repeatable", "folder", "declaration", "type_kind",
    "relationship_kind", "description", "flow", "ownership",
}
EVIDENCE_FIELDS = {"kind", "source", "event_index", "address", "query_id", "digest", "note"}
PRECONDITION_FIELDS = {
    "database_revision", "current_name", "name", "current_type", "type",
    "declaration", "comment_digest", "declaration_digest", "repeatable", "folder",
}

DESIRED_FIELDS = {
    "function.rename": ("name",),
    "function.comment.set": ("comment", "repeatable"),
    "address.comment.set": ("comment", "repeatable"),
    "function.folder.set": ("folder",),
    "function.prototype.set": ("declaration",),
    "local.rename": ("name",),
    "local.type.set": ("declaration",),
    "global.rename": ("name",),
    "global.type.set": ("declaration",),
    "named_type.create_or_update": ("type_kind", "name", "declaration"),
    "relationship.annotate": ("relationship_kind", "description"),
}

EXPECTED_TARGET_KINDS = {
    "function.rename": {"function"},
    "function.comment.set": {"function"},
    "address.comment.set": {"address"},
    "function.folder.set": {"function", "folder_entry"},
    "function.prototype.set": {"function"},
    "local.rename": {"local_variable"},
    "local.type.set": {"local_variable"},
    "global.rename": {"global"},
    "global.type.set": {"global"},
    "named_type.create_or_update": {"named_type"},
    "relationship.annotate": {"relationship"},
}

# Model-facing requirements are deliberately smaller than the internal
# operation schema. The host supplies artifact identity, target identity, and
# defaults such as repeatable comments; the model supplies semantic intent.
MODEL_MUTATION_CONTRACTS = {
    "function.rename": {
        "target_kinds": ["function"],
        "required_value_fields": ["name"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida_function", "inspect_ida"],
    },
    "function.comment.set": {
        "target_kinds": ["function"],
        "required_value_fields": ["comment"],
        "optional_value_fields": ["repeatable"],
        "target_ref_from": ["inspect_ida_function", "inspect_ida"],
        "note": (
            "IDA has independent repeatable and nonrepeatable comment slots. "
            "An empty comment clears behavior text from the selected slot; "
            "durable Verified IDA markers are preserved. Inspect both slots "
            "in the returned current.comments object."
        ),
    },
    "function.prototype.set": {
        "target_kinds": ["function"],
        "required_value_fields": ["declaration"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida_function", "inspect_ida"],
    },
    "local.rename": {
        "target_kinds": ["local_variable"],
        "required_value_fields": ["name"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida_local"],
    },
    "local.type.set": {
        "target_kinds": ["local_variable"],
        "required_value_fields": ["declaration"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida_local"],
    },
    "global.rename": {
        "target_kinds": ["global"],
        "required_value_fields": ["name"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida"],
    },
    "global.type.set": {
        "target_kinds": ["global"],
        "required_value_fields": ["declaration"],
        "optional_value_fields": [],
        "target_ref_from": ["inspect_ida"],
    },
    "named_type.create_or_update": {
        "target_kinds": ["named_type"],
        "required_value_fields": ["type_kind", "declaration"],
        "optional_value_fields": ["name"],
        "field_values": {
            "type_kind": ["struct", "union", "enum", "typedef"],
        },
        "target_ref_from": ["inspect_ida(query=inspect_struct, target=<type-name>)"],
        "note": "The target reference binds the type name; value.name, when supplied, must match it.",
    },
    "relationship.annotate": {
        "target_kinds": ["relationship"],
        "required_value_fields": ["description"],
        "optional_value_fields": ["flow", "ownership"],
        "target_ref_from": ["inspect_ida_relationship"],
    },
}


class ContractError(ValueError):
    """Raised when a Verified IDA object violates the v1 contract."""

    def __init__(self, code: str, message: str, *, field: str | None = None):
        super().__init__(message)
        self.code = code
        self.field = field

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": str(self), "field": self.field}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def operation_digest(operation: Mapping[str, Any]) -> str:
    """Return a stable digest used for idempotency and conflict detection."""

    stable = copy.deepcopy(dict(operation))
    metadata = stable.get("metadata")
    if isinstance(metadata, dict):
        metadata.pop("submitted_at", None)
    artifact = stable.get("artifact")
    if isinstance(artifact, dict):
        # The revision is an execution precondition, not part of the logical
        # operation identity. This lets the host recognize an exact retry after
        # the first application changed and saved the IDB.
        artifact.pop("database_revision", None)
    return hashlib.sha256(canonical_json(stable).encode("utf-8")).hexdigest()


def _require_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ContractError("invalid_type", "%s must be an object" % field, field=field)
    return value


def _reject_unknown_fields(value: Mapping[str, Any], allowed: set[str], field: str) -> None:
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ContractError("unknown_field", "%s contains unsupported fields: %s" % (field, ", ".join(unknown)), field=field)


def _require_text(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ContractError("missing_field", "%s must be a non-empty string" % field, field=field)
    return text


def _parse_address(value: Any, field: str) -> int:
    try:
        if isinstance(value, str):
            address = int(value.strip(), 0)
        else:
            address = int(value)
    except (TypeError, ValueError):
        raise ContractError("invalid_address", "%s must be an integer or hexadecimal string" % field, field=field)
    if address < 0 or address > 0xFFFFFFFFFFFFFFFF:
        raise ContractError("invalid_address", "%s is outside the 64-bit address range" % field, field=field)
    return address


def _validate_artifact(artifact: Mapping[str, Any]) -> None:
    _reject_unknown_fields(artifact, ARTIFACT_FIELDS, "artifact")
    binary_sha256 = _require_text(artifact.get("binary_sha256"), "artifact.binary_sha256")
    if len(binary_sha256) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in binary_sha256):
        raise ContractError("invalid_sha256", "artifact.binary_sha256 must contain 64 hexadecimal characters", field="artifact.binary_sha256")
    _require_text(artifact.get("database_id"), "artifact.database_id")
    if artifact.get("database_revision") in (None, ""):
        raise ContractError("missing_field", "artifact.database_revision is required", field="artifact.database_revision")


def _validate_target(kind: str, target: Mapping[str, Any]) -> None:
    _reject_unknown_fields(target, TARGET_FIELDS, "target")
    target_kind = _require_text(target.get("kind"), "target.kind")
    if target_kind not in TARGET_KINDS:
        raise ContractError("unsupported_target", "Unsupported target kind: %s" % target_kind, field="target.kind")
    if target_kind not in EXPECTED_TARGET_KINDS[kind]:
        raise ContractError(
            "target_kind_mismatch",
            "%s requires target kind %s, not %s" % (kind, sorted(EXPECTED_TARGET_KINDS[kind]), target_kind),
            field="target.kind",
        )
    if target_kind in {"function", "address", "global", "folder_entry"}:
        _parse_address(target.get("address") if target.get("address") is not None else target.get("function_address"), "target.address")
    elif target_kind == "local_variable":
        _parse_address(target.get("function_address"), "target.function_address")
        anchors = [
            target.get("current_name"),
            target.get("lvar_index"),
            target.get("location"),
            target.get("use_site"),
        ]
        if not any(value not in (None, "", {}) for value in anchors):
            raise ContractError("ambiguous_target", "local_variable targets require at least one live anchor", field="target")
        if target.get("lvar_index") is not None:
            if not isinstance(target.get("lvar_index"), int) or int(target["lvar_index"]) < 0:
                raise ContractError("invalid_local_index", "target.lvar_index must be a non-negative integer", field="target.lvar_index")
        if target.get("use_site") is not None:
            _parse_address(target.get("use_site"), "target.use_site")
    elif target_kind == "named_type":
        _require_text(target.get("name"), "target.name")
    elif target_kind == "relationship":
        _parse_address(target.get("source_address"), "target.source_address")
        _parse_address(target.get("destination_address"), "target.destination_address")
        if target.get("callsite_address") not in (None, ""):
            _parse_address(target.get("callsite_address"), "target.callsite_address")
    function_byte_hash = target.get("function_byte_hash")
    if function_byte_hash not in (None, ""):
        digest = str(function_byte_hash)
        if len(digest) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in digest):
            raise ContractError(
                "invalid_sha256",
                "target.function_byte_hash must contain 64 hexadecimal characters",
                field="target.function_byte_hash",
            )


def validate_operation(
    operation: Mapping[str, Any],
    *,
    expected_artifact: Mapping[str, Any] | None = None,
    rebind_database_revision: bool = False,
) -> dict[str, Any]:
    """Validate and normalize a v1 operation without importing IDA modules.

    ``rebind_database_revision`` is reserved for a trusted executor
    after it has proved that the request is an exact logical retry of an
    operation already recorded as verified. It records the earlier revision
    and binds the returned operation to the current revision for readback.
    """

    operation = _require_mapping(operation, "operation")
    _reject_unknown_fields(operation, OPERATION_FIELDS, "operation")
    if operation.get("schema") != OPERATION_SCHEMA:
        raise ContractError("unsupported_schema", "schema must be %s" % OPERATION_SCHEMA, field="schema")
    operation_id = _require_text(operation.get("operation_id"), "operation_id")
    if len(operation_id) > 160:
        raise ContractError("invalid_operation_id", "operation_id exceeds 160 characters", field="operation_id")
    kind = _require_text(operation.get("kind"), "kind")
    if kind not in SUPPORTED_KINDS:
        raise ContractError("unsupported_operation", "Unsupported operation kind: %s" % kind, field="kind")
    work_item_id = operation.get("work_item_id")
    if work_item_id is not None:
        work_item_text = _require_text(work_item_id, "work_item_id")
        if len(work_item_text) > 160:
            raise ContractError("invalid_work_item_id", "work_item_id exceeds 160 characters", field="work_item_id")

    artifact = _require_mapping(operation.get("artifact"), "artifact")
    _validate_artifact(artifact)
    if expected_artifact:
        for key in ("binary_sha256", "database_id", "database_revision"):
            if key == "database_revision" and rebind_database_revision:
                continue
            actual_value = str(artifact.get(key))
            expected_value = str(expected_artifact.get(key))
            if key == "binary_sha256":
                actual_value = actual_value.lower()
                expected_value = expected_value.lower()
            if actual_value != expected_value:
                raise ContractError("artifact_conflict", "Open database does not match operation %s" % key, field="artifact.%s" % key)

    target = _require_mapping(operation.get("target"), "target")
    _validate_target(kind, target)
    desired = _require_mapping(operation.get("desired"), "desired")
    _reject_unknown_fields(desired, DESIRED_ALLOWED_FIELDS, "desired")
    for field in DESIRED_FIELDS[kind]:
        allow_empty_comment = (
            field == "comment"
            and kind in {"function.comment.set", "address.comment.set"}
            and field in desired
        )
        if not allow_empty_comment and desired.get(field) in (None, ""):
            raise ContractError("missing_field", "desired.%s is required for %s" % (field, kind), field="desired.%s" % field)
    if kind in {"function.comment.set", "address.comment.set"} and not isinstance(desired.get("repeatable"), bool):
        raise ContractError("invalid_type", "desired.repeatable must be boolean", field="desired.repeatable")
    if kind == "named_type.create_or_update" and desired.get("type_kind") not in {"struct", "union", "enum", "typedef"}:
        raise ContractError("invalid_type_kind", "desired.type_kind must be struct, union, enum, or typedef", field="desired.type_kind")
    if kind == "relationship.annotate" and target.get("relationship_kind") not in (None, desired.get("relationship_kind")):
        raise ContractError(
            "relationship_kind_conflict",
            "target.relationship_kind must match desired.relationship_kind",
            field="target.relationship_kind",
        )

    preconditions = _require_mapping(
        operation.get("preconditions", {}),
        "preconditions",
    )
    _reject_unknown_fields(preconditions, PRECONDITION_FIELDS, "preconditions")
    _require_mapping(operation.get("metadata", {}), "metadata")

    depends_on = operation.get("depends_on") or []
    if not isinstance(depends_on, list) or any(not str(item or "").strip() for item in depends_on):
        raise ContractError("invalid_dependencies", "depends_on must contain non-empty operation identifiers", field="depends_on")
    if operation_id in depends_on:
        raise ContractError("cyclic_dependency", "An operation cannot depend on itself", field="depends_on")
    if len(set(str(item) for item in depends_on)) != len(depends_on):
        raise ContractError("duplicate_dependency", "depends_on identifiers must be unique", field="depends_on")

    evidence = operation.get("evidence") or []
    if not isinstance(evidence, list):
        raise ContractError("invalid_type", "evidence must be an array", field="evidence")
    for index, item in enumerate(evidence):
        item = _require_mapping(item, "evidence[%d]" % index)
        _reject_unknown_fields(item, EVIDENCE_FIELDS, "evidence[%d]" % index)
        _require_text(item.get("kind"), "evidence[%d].kind" % index)
        _require_text(item.get("source"), "evidence[%d].source" % index)

    normalized = copy.deepcopy(dict(operation))
    normalized.setdefault("work_item_id", None)
    normalized.setdefault("preconditions", {})
    normalized.setdefault("evidence", [])
    normalized.setdefault("depends_on", [])
    normalized.setdefault("metadata", {})
    normalized["artifact"]["binary_sha256"] = str(normalized["artifact"]["binary_sha256"]).lower()
    if (
        expected_artifact
        and rebind_database_revision
        and normalized["artifact"]["database_revision"]
        != expected_artifact["database_revision"]
    ):
        prior_revision = normalized["artifact"]["database_revision"]
        normalized["artifact"]["database_revision"] = expected_artifact[
            "database_revision"
        ]
        normalized["metadata"].update(
            {
                "exact_retry_rebound": True,
                "rebound_from_database_revision": prior_revision,
            }
        )
    return normalized


def build_receipt(
    operation: Mapping[str, Any],
    status: str,
    stage: str,
    *,
    before: Any = None,
    observed: Any = None,
    execution: Mapping[str, Any] | None = None,
    normalization: Mapping[str, Any] | None = None,
    effects: Mapping[str, Any] | None = None,
    persistence: str = "not_checked",
    semantic_review: str = "unreviewed",
    errors: Iterable[Mapping[str, Any]] = (),
    recovery: str | None = None,
    implementation: Mapping[str, Any] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Build a complete per-operation receipt."""

    if status not in RECEIPT_STATUSES:
        raise ContractError("invalid_receipt_status", "Unsupported receipt status: %s" % status, field="status")
    if stage not in RECEIPT_STAGES:
        raise ContractError("invalid_receipt_stage", "Unsupported receipt stage: %s" % stage, field="stage")
    if persistence not in PERSISTENCE_STATES:
        raise ContractError("invalid_persistence", "Unsupported persistence state: %s" % persistence, field="persistence")
    if semantic_review not in SEMANTIC_STATES:
        raise ContractError("invalid_semantic_review", "Unsupported semantic review state: %s" % semantic_review, field="semantic_review")

    op = dict(operation)
    operation_id = _require_text(op.get("operation_id"), "operation_id")
    stamp = timestamp or utc_now()
    receipt_material = "%s:%s:%s:%s" % (operation_id, status, stage, stamp)
    receipt_id = "receipt_%s" % hashlib.sha256(receipt_material.encode("utf-8")).hexdigest()[:24]
    return {
        "schema": RECEIPT_SCHEMA,
        "receipt_id": receipt_id,
        "operation_id": operation_id,
        "work_item_id": op.get("work_item_id"),
        "kind": op.get("kind"),
        "artifact": copy.deepcopy(op.get("artifact") or {}),
        "target": copy.deepcopy(op.get("target") or {}),
        "status": status,
        "stage": stage,
        "before": copy.deepcopy(before),
        "desired": copy.deepcopy(op.get("desired")),
        "observed": copy.deepcopy(observed),
        "execution": dict(execution or {}),
        "normalization": dict(normalization or {}),
        "effects": dict(effects or {}),
        "persistence": persistence,
        "semantic_review": semantic_review,
        "errors": [dict(item) for item in errors],
        "evidence": copy.deepcopy(op.get("evidence") or []),
        "recovery": recovery,
        "implementation": dict(implementation or {"name": "ida-harness", "standard_version": "0.1"}),
        "timestamp": stamp,
    }


def summarize_receipts(receipts: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    rows = [dict(item) for item in receipts]
    by_status = {status: 0 for status in sorted(RECEIPT_STATUSES)}
    for row in rows:
        status = str(row.get("status") or "")
        if status not in RECEIPT_STATUSES:
            raise ContractError("invalid_receipt_status", "Unknown receipt status in batch: %s" % status, field="status")
        by_status[status] += 1
    verified = sum(by_status[status] for status in VERIFIED_STATUSES)
    if not rows:
        batch_status = "empty"
    elif verified == len(rows):
        batch_status = "verified"
    elif verified:
        batch_status = "partial"
    else:
        batch_status = "failed"
    return {
        "schema": "verified_ida.receipt_batch_summary.v1",
        "status": batch_status,
        "total": len(rows),
        "verified": verified,
        "non_verified": len(rows) - verified,
        "by_status": by_status,
        "receipt_ids": [row.get("receipt_id") for row in rows],
    }
