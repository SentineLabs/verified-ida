"""Ownership rules shared by project cloning and crash recovery."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping


TERMINAL_TRANSACTION_STATES = frozenset({
    "committed", "already_satisfied", "discarded", "rolled_back_after_error",
    "rolled_back_after_journal_failure", "recovered_discard", "recovered_rollback",
})


def has_committed_attempt(
    detail: Mapping[str, Any] | None, manifest: Mapping[str, Any],
) -> bool:
    """Require a verified receipt for these exact promoted candidate bytes.

    A historical operation row may contain only failed receipts. Its existence
    is not a commit. New manifests additionally bind the immutable request and
    exact receipt; older manifests must still prove the candidate's hashes.
    """
    if detail is None:
        return False
    if manifest.get("operation_digest") and manifest["operation_digest"] != detail.get("operation_digest"):
        raise RuntimeError("Mutation recovery request digest disagrees with its journal")
    verified = [row for row in detail.get("receipts") or [] if row.get("status") == "verified"]
    for receipt in verified:
        expected_receipt = manifest.get("candidate_receipt_id")
        if expected_receipt and receipt.get("receipt_id") != expected_receipt:
            continue
        transaction = receipt.get("transaction") or {}
        if (transaction.get("promoted") is True
                and transaction.get("canonical_before_sha256") == manifest.get("canonical_before_sha256")
                and transaction.get("candidate_sha256") == manifest.get("candidate_sha256")
                and manifest.get("canonical_before_sha256")
                and manifest.get("candidate_sha256")):
            return True
    if verified:
        raise RuntimeError("Mutation recovery has no verified receipt matching this candidate; retain recovery material")
    return False


def require_settled_transactions(project: Path) -> None:
    """Reject a snapshot whose recovery would still require a writable owner."""
    for path in sorted((project / "mutation_transactions").glob("*.json")):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        if manifest.get("status") not in TERMINAL_TRANSACTION_STATES:
            raise ValueError("Unsettled mutation transaction; recover the source first: %s" % path)


def recovery_paths(
    project: Path, component: Mapping[str, Any], manifest: Mapping[str, Any],
) -> tuple[Path, Path, Path]:
    """Bind every destructive recovery path to this project and transaction."""
    canonical = Path(str(manifest.get("canonical_idb") or "")).resolve()
    registered = Path(str(component.get("idb_path") or "")).resolve()
    rollback = Path(str(manifest.get("rollback_idb") or "")).resolve()
    candidate = Path(str(manifest.get("candidate_idb") or "")).resolve()
    operation_id = str(manifest.get("operation_id") or "")
    directory = rollback.parent
    if (
        not operation_id or canonical != registered or project not in canonical.parents
        or directory.parent != canonical.parent
        or not directory.name.startswith(".verified_ida_txn_%s_" % operation_id[-12:])
        or rollback.name != "before" + canonical.suffix
        or candidate != directory / ("candidate" + canonical.suffix)
    ):
        raise ValueError("Recovery paths do not belong to the current project/transaction")
    return canonical, rollback, candidate
