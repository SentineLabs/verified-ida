"""Portable metadata and paging contract for model-facing binary queries."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any, Mapping

from .contracts import MODEL_MUTATION_CONTRACTS


QUERY_FAMILIES: dict[str, dict[str, Any]] = {
    "functions": {
        "maximum_page_size": 500,
        "default_order": "address",
        "orders": ["address", "name", "size_ascending", "size_descending"],
        "filters": {
            "segment": "exact segment name",
            "name_class": "all, anonymous, or named",
            "name_prefix": "case-sensitive function-name prefix",
            "address_start": "inclusive function-start address",
            "address_end": "exclusive function-start address",
            "minimum_size": "minimum function size in bytes",
            "maximum_size": "maximum function size in bytes",
            "minimum_callers": "minimum distinct direct caller count",
            "minimum_callees": "minimum distinct direct callee count",
            "minimum_xrefs": "minimum references to the function start",
            "has_comment": "true or false",
            "has_prototype": "true or false",
        },
    },
    "symbols": {
        "maximum_page_size": 500,
        "default_order": "address",
        "orders": ["address", "name"],
        "filters": {
            "kind": "names, imports, exports, entrypoints, or globals",
            "name_prefix": "case-sensitive symbol-name prefix",
            "module": "exact import module",
            "segment": "exact segment name",
        },
    },
    "strings": {
        "maximum_page_size": 500,
        "default_order": "address",
        "orders": ["address", "length_descending", "text"],
        "filters": {
            "needle": "case-insensitive substring",
            "segment": "exact segment name",
            "minimum_length": "minimum decoded string length",
            "referenced": "true for referenced strings, false for unreferenced strings",
        },
    },
    "types": {
        "maximum_page_size": 500,
        "default_order": "name",
        "orders": ["name", "kind"],
        "filters": {
            "kind": "all, struct, or enum",
            "name_prefix": "case-sensitive local-type name prefix",
        },
    },
}

MUTATION_TOOLS = list(MODEL_MUTATION_CONTRACTS)


class QueryContractError(ValueError):
    """Actionable cursor or query-contract error."""

    def __init__(self, code: str, message: str, recovery: str):
        self.code = code
        self.recovery = recovery
        super().__init__(message)

    def as_dict(self) -> dict[str, str]:
        return {"code": self.code, "message": str(self), "recovery": self.recovery}


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def normalize_query(family: str, filters: Mapping[str, Any] | None, order: str | None) -> dict[str, Any]:
    if family not in QUERY_FAMILIES:
        raise QueryContractError(
            "unsupported_query_family",
            "Unsupported query family: %s" % family,
            "Use describe_ida_capabilities to select a supported family.",
        )
    definition = QUERY_FAMILIES[family]
    normalized_filters = {
        str(key): value
        for key, value in sorted(dict(filters or {}).items())
        if value is not None and value != ""
    }
    unknown = sorted(set(normalized_filters) - set(definition["filters"]))
    if unknown:
        raise QueryContractError(
            "unsupported_filter",
            "%s does not support filters: %s" % (family, ", ".join(unknown)),
            "Use describe_ida_capabilities for the exact filters on this family.",
        )
    selected_order = str(order or definition["default_order"])
    if selected_order not in definition["orders"]:
        raise QueryContractError(
            "unsupported_order",
            "%s does not support order %s" % (family, selected_order),
            "Choose one of: %s" % ", ".join(definition["orders"]),
        )
    return {
        "family": family,
        "filters": normalized_filters,
        "order": selected_order,
    }


def query_digest(query: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(dict(query)).encode("utf-8")).hexdigest()


def encode_cursor(
    *,
    component_id: str,
    revision: int,
    query: Mapping[str, Any],
    offset: int,
) -> str:
    payload = {
        "v": 1,
        "component": str(component_id),
        "revision": int(revision),
        "query_digest": query_digest(query),
        "offset": max(0, int(offset)),
    }
    return base64.urlsafe_b64encode(_canonical(payload).encode("utf-8")).decode("ascii").rstrip("=")


def decode_cursor(
    value: str,
    *,
    component_id: str,
    revision: int,
    query: Mapping[str, Any],
) -> int:
    try:
        text = str(value or "")
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        payload = json.loads(raw.decode("utf-8"))
    except Exception:
        raise QueryContractError(
            "invalid_cursor",
            "The query cursor is malformed.",
            "Restart the collection query without a cursor.",
        ) from None
    expected = {
        "component": str(component_id),
        "revision": int(revision),
        "query_digest": query_digest(query),
    }
    for key, expected_value in expected.items():
        if payload.get(key) != expected_value:
            code = "stale_cursor" if key == "revision" else "cursor_query_mismatch"
            raise QueryContractError(
                code,
                "The cursor is not valid for the current component, revision, and query.",
                "Restart the collection query without a cursor after inspecting current IDA state.",
            )
    try:
        return max(0, int(payload["offset"]))
    except (KeyError, TypeError, ValueError):
        raise QueryContractError(
            "invalid_cursor",
            "The query cursor has no valid continuation offset.",
            "Restart the collection query without a cursor.",
        ) from None


def capability_manifest(runtime: Mapping[str, Any] | None = None) -> dict[str, Any]:
    return {
        "schema": "verified_ida.query_capabilities.v1",
        "backend": {
            "name": "native_idapython",
            **dict(runtime or {}),
        },
        "query_families": QUERY_FAMILIES,
        "function_evidence": {
            "summary": "Neutral metadata; code is not returned implicitly.",
            "representations": ["disassembly", "pseudocode"],
            "paging": "revision-bound opaque cursor",
        },
        "supported_mutations": MUTATION_TOOLS,
        "mutation_contracts": MODEL_MUTATION_CONTRACTS,
        "extensions": {
            "legacy_structural_queries": True,
            "readonly_idapython_fallback": True,
            "separate_component_idbs": True,
        },
    }
