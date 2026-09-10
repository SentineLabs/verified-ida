"""Canonical comparison helpers shared by IDA adapters and tests."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Mapping


_SPACE = re.compile(r"\s+")
_DECL_PUNCT = re.compile(r"\s*([*(),;{}\[\]])\s*")


def canonical_text(value: Any) -> str:
    return str(value or "").replace("\r\n", "\n").replace("\r", "\n").strip()


def canonical_name(value: Any) -> str:
    return str(value or "").strip()


def canonical_declaration(value: Any) -> str:
    """Provide a deterministic fallback when IDA's tinfo printer is unavailable."""

    text = canonical_text(value).rstrip(";")
    text = _SPACE.sub(" ", text)
    text = _DECL_PUNCT.sub(r"\1", text)
    return text.strip()


def canonical_folder(value: Any) -> str:
    return "/".join(part for part in str(value or "").strip().strip("/").split("/") if part)


def relationship_key(
    source: Any,
    destination: Any,
    kind: Any,
    callsite: Any | None = None,
) -> str:
    """Identify one qualified edge independently of its mutable description."""

    identity = {
        "source": hex(int(str(source), 0)),
        "destination": hex(int(str(destination), 0)),
        "kind": canonical_name(kind),
    }
    if callsite not in (None, ""):
        identity["callsite"] = hex(int(str(callsite), 0))
    material = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def upsert_prefixed_line(existing: Any, prefix: str, line: str) -> str:
    """Return text containing exactly one current line for a durable marker."""

    kept = [value for value in canonical_text(existing).splitlines() if not value.startswith(prefix)]
    kept.append(str(line))
    return "\n".join(kept).strip()


def compare_desired(kind: str, desired: Mapping[str, Any], observed: Mapping[str, Any]) -> tuple[bool, dict[str, Any]]:
    """Compare desired and read-back state and report the normalization used."""

    if kind in {"function.rename", "local.rename", "global.rename"}:
        expected = canonical_name(desired.get("name"))
        actual = canonical_name(observed.get("name"))
        mode = "name"
    elif kind in {"function.comment.set", "address.comment.set"}:
        expected = canonical_text(desired.get("comment"))
        actual = canonical_text(observed.get("comment"))
        mode = (
            "repeatable_comment_slot"
            if desired.get("repeatable")
            else "nonrepeatable_comment_slot"
        )
    elif kind == "function.folder.set":
        expected = canonical_folder(desired.get("folder"))
        actual = canonical_folder(observed.get("folder"))
        mode = "folder"
    elif kind in {"function.prototype.set", "local.type.set", "global.type.set"}:
        expected = canonical_declaration(desired.get("declaration"))
        actual = canonical_declaration(observed.get("declaration"))
        mode = "declaration_fallback"
    elif kind == "named_type.create_or_update":
        expected = canonical_declaration(desired.get("declaration"))
        actual = canonical_declaration(observed.get("declaration"))
        mode = "named_declaration_fallback"
    elif kind == "relationship.annotate":
        keys = ["relationship_kind", "description"]
        keys.extend(key for key in ("flow", "ownership") if key in desired)
        expected = {key: desired.get(key) for key in keys}
        actual_record = observed.get("record") if isinstance(observed.get("record"), Mapping) else observed
        actual = {key: actual_record.get(key) for key in keys}
        expected["description"] = canonical_text(expected.get("description"))
        actual["description"] = canonical_text(actual.get("description"))
        mode = "structured_relationship"
    else:
        return False, {"mode": "unsupported", "expected": desired, "actual": observed}
    return expected == actual, {"mode": mode, "expected": expected, "actual": actual}
