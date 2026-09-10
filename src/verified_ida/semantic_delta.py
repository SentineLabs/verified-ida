"""Canonical, operation-scoped semantic IDB delta classification."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping


DERIVED_SEMANTIC_FIELDS = frozenset({"type_dependencies", "type_dependency_scan", "native_has_user_name", "native_saved_user_name", "native_argument_names", "native_callback_parameters", "native_call_arguments"})
SEMANTIC_VERSION_FIELDS = frozenset({"schema", "export_version"})


def _semantic_list_identity(item: Mapping[str, Any]) -> tuple[Any, ...] | None:
    for field in ("address", "relationship_id", "ordinal"):
        if item.get(field) not in (None, ""):
            return (field, item.get(field))
    if item.get("offset") not in (None, ""):
        return (
            "member",
            item.get("offset"),
            item.get("name"),
            item.get("type"),
            item.get("end_offset"),
        )
    if item.get("index") not in (None, ""):
        return ("index", item.get("index"))
    if item.get("name") not in (None, ""):
        return ("name", item.get("name"))
    return None


def durable_semantic_state(
    value: Any,
    *,
    excluded_fields: frozenset[str] = DERIVED_SEMANTIC_FIELDS,
) -> Any:
    """Remove host-approved derived measurements from semantic digest input."""

    if isinstance(value, Mapping):
        return {
            key: durable_semantic_state(
                item,
                excluded_fields=excluded_fields,
            )
            for key, item in value.items()
            if key not in excluded_fields
        }
    if isinstance(value, list):
        return [
            durable_semantic_state(item, excluded_fields=excluded_fields)
            for item in value
        ]
    return value


def semantic_state_digest(
    state: Mapping[str, Any],
    *,
    excluded_fields: frozenset[str] = DERIVED_SEMANTIC_FIELDS,
) -> str:
    encoded = json.dumps(
        durable_semantic_state(state, excluded_fields=excluded_fields),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def semantic_digest_exclusions(export: Mapping[str, Any]) -> frozenset[str]:
    """Validate an export's recorded digest policy, including legacy exports."""
    policy = export.get("digest_policy", {})
    if not isinstance(policy, Mapping):
        raise ValueError("Semantic digest policy must be an object")
    fields = policy.get("derived_fields_excluded", [])
    if not isinstance(fields, list) or any(not isinstance(x, str) for x in fields):
        raise ValueError("Semantic digest exclusions must be a list of field names")
    exclusions = frozenset(fields)
    unknown = exclusions - DERIVED_SEMANTIC_FIELDS
    if unknown:
        raise ValueError(
            "Semantic export requested unsupported digest exclusions: %s"
            % ", ".join(sorted(unknown))
        )
    return exclusions


def migrated_checkpoint_digest(
    current_state: Mapping[str, Any],
    prior_export: Mapping[str, Any],
    expected_digest: str,
) -> str:
    """Authenticate the old snapshot, then compare using its recorded policy.

    The trusted digest comes from the verified journal checkpoint, not the export
    file. New measurements cannot change which old facts participate in hashing.
    """
    prior_state = prior_export.get("state")
    if not isinstance(prior_state, Mapping):
        raise ValueError("Prior semantic export did not contain state")
    exclusions = semantic_digest_exclusions(prior_export)
    if (
        not expected_digest
        or prior_export.get("semantic_digest") != expected_digest
        or semantic_state_digest(prior_state, excluded_fields=exclusions) != expected_digest
    ):
        raise ValueError("Prior semantic export does not match its verified checkpoint")
    projected = project_semantic_state_to_template(current_state, prior_state)
    return semantic_state_digest(projected, excluded_fields=exclusions)


def project_semantic_state_to_template(current: Any, template: Any, *, _path: tuple[str, ...] = ()) -> Any:
    """Project current state onto every fact visible in an older export.

    Newly selected globals are measurements, not a full inventory. Other list
    surfaces already inventoried by the old exporter must retain additions.
    """

    if (isinstance(template, Mapping) and isinstance(current, Mapping)
            and template.get("schema") in {"verified_ida.semantic_state.v1", "verified_ida.semantic_state.v2"}
            and int(template.get("export_version") or 0) < 4
            and int(current.get("export_version") or 0) >= 4):
        # <=3 treated IDA 9.3's is_arg_var property as a method, reporting
        # false. Compare legacy checkpoints without treating that corrected
        # derived role flag as a new analyst mutation. Names/types/prototypes
        # still compare normally; new-to-new snapshots retain the real flag.
        current = {**current, "functions": [dict(row) for row in current.get("functions") or []]}
        old_functions = {row.get("address"): row for row in template.get("functions") or []}
        for row in current["functions"]:
            prior = old_functions.get(row.get("address"), {})
            old_locals = {item.get("index"): item for item in (prior.get("locals") or {}).get("items") or []}
            if row.get("locals"):
                row["locals"] = {**row["locals"], "items": [dict(item) for item in row["locals"].get("items") or []]}
                for item in row["locals"]["items"]:
                    if item.get("index") in old_locals:
                        item["is_argument"] = old_locals[item["index"]].get("is_argument")
    if isinstance(template, Mapping):
        current_mapping = current if isinstance(current, Mapping) else {}
        return {
            key: (
                value
                if key in SEMANTIC_VERSION_FIELDS
                else project_semantic_state_to_template(
                    current_mapping.get(key, {"__missing__": key}),
                    value,
                    _path=(*_path, key),
                )
            )
            for key, value in template.items()
        }
    if isinstance(template, list):
        current_list = current if isinstance(current, list) else []
        projected = []
        matched = set()
        for index, template_item in enumerate(template):
            current_item = None
            if isinstance(template_item, Mapping):
                identity = _semantic_list_identity(template_item)
                if identity is not None:
                    match = next(
                        (
                            (position, item) for position, item in enumerate(current_list)
                            if isinstance(item, Mapping)
                            and _semantic_list_identity(item) == identity
                        ),
                        None,
                    )
                    if match is not None:
                        matched.add(match[0])
                        current_item = match[1]
            elif index < len(current_list):
                current_item = current_list[index]
                matched.add(index)
            if current_item is None:
                current_item = {"__missing__": index}
            projected.append(
                project_semantic_state_to_template(current_item, template_item, _path=(*_path, "[]"))
            )
        if _path != ("globals",):
            projected.extend(item for index, item in enumerate(current_list) if index not in matched)
        return projected
    return current


def indexed_semantic_state(state: Mapping[str, Any]) -> dict[str, Any]:
    functions: dict[str, Any] = {}
    for raw in state.get("functions") or []:
        row = dict(raw)
        address = str(row.get("address") or "").lower()
        local_state = row.get("locals") or {}
        locals_by_index = {
            str(local.get("index")): {
                key: local.get(key)
                for key in ("name", "declaration", "is_argument", "location")
            }
            for local in (local_state.get("items") or [])
            if isinstance(local, Mapping)
        }
        functions[address] = {
            key: row.get(key)
            for key in ("name", "prototype", "comment", "repeatable_comment")
        }
        if locals_by_index:
            functions[address]["locals"] = locals_by_index
    return {
        "functions": functions,
        "globals": {
            str(row.get("address") or "").lower(): {
                key: row.get(key)
                for key in ("name", "declaration", "comment", "repeatable_comment")
            }
            for row in state.get("globals") or []
            if isinstance(row, Mapping)
        },
        "named_types": {
            str(row.get("name") or ""): durable_semantic_state(row)
            for row in state.get("named_types") or []
            if isinstance(row, Mapping)
        },
        "structs": {
            str(row.get("name") or ""): durable_semantic_state(row)
            for row in state.get("structs") or []
            if isinstance(row, Mapping)
        },
        "enums": {
            str(row.get("name") or ""): dict(row)
            for row in state.get("enums") or []
            if isinstance(row, Mapping)
        },
        "relationships": {
            str(row.get("relationship_id") or index): dict(row)
            for index, row in enumerate(state.get("relationships") or [])
            if isinstance(row, Mapping)
        },
    }


def flatten_semantic_state(value: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key in sorted(value):
            path = "%s.%s" % (prefix, key) if prefix else str(key)
            result.update(flatten_semantic_state(value[key], path))
        return result
    if isinstance(value, list):
        result = {}
        for index, item in enumerate(value):
            result.update(flatten_semantic_state(
                item,
                "%s[%d]" % (prefix, index),
            ))
        return result
    return {prefix: value}


def semantic_changed_paths(
    before: Mapping[str, Any], after: Mapping[str, Any]
) -> list[str]:
    left = flatten_semantic_state(indexed_semantic_state(before))
    right = flatten_semantic_state(indexed_semantic_state(after))
    return sorted(
        path for path in set(left) | set(right) if left.get(path) != right.get(path)
    )


def permitted_semantic_prefixes(operation: Mapping[str, Any]) -> list[str]:
    kind = str(operation.get("kind") or "")
    target = operation.get("target") or {}
    address = str(
        target.get("function_address") or target.get("address") or ""
    ).lower()
    if kind == "function.rename":
        return ["functions.%s.name" % address]
    if kind == "function.comment.set":
        slot = (
            "repeatable_comment"
            if (operation.get("desired") or {}).get("repeatable")
            else "comment"
        )
        return ["functions.%s.%s" % (address, slot)]
    if kind == "function.prototype.set":
        return ["functions.%s.prototype" % address]
    if kind in {"local.rename", "local.type.set"}:
        index = str(target.get("lvar_index"))
        field = "name" if kind == "local.rename" else "declaration"
        prefixes = ["functions.%s.locals.%s.%s" % (address, index, field)]
        if target.get("is_parameter"):
            prefixes.append("functions.%s.prototype" % address)
        return prefixes
    if kind == "global.rename":
        return ["globals.%s.name" % address]
    if kind == "global.type.set":
        return ["globals.%s.declaration" % address]
    if kind == "named_type.create_or_update":
        name = str(target.get("name") or "")
        return [
            "named_types.%s" % name,
            "structs.%s" % name,
            "enums.%s" % name,
        ]
    return []


def _type_dependency_materializations(
    operation: Mapping[str, Any],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> tuple[list[str], list[str]]:
    """Return new native dependencies and incomplete measurements for this edit.

    IDA can materialize referenced typedefs from its type libraries while it
    parses a new structure. Those rows are a direct consequence of the
    requested declaration, not unrelated analyst work. Permit only rows that
    were absent before the operation and are reachable through IDA's native
    ``type_dependencies`` graph after it. Existing dependency definitions
    remain protected from collateral modification.
    """

    kind = str(operation.get("kind") or "")
    target = operation.get("target") or {}
    target_name = str(target.get("name") or "") if kind == "named_type.create_or_update" else ""
    address = str(target.get("function_address") or target.get("address") or "").lower()

    before_names = {
        str(row.get("name") or "")
        for row in before.get("named_types") or []
        if isinstance(row, Mapping)
    }
    after_rows = {
        str(row.get("name") or ""): dict(row)
        for row in after.get("named_types") or []
        if isinstance(row, Mapping) and row.get("name")
    }
    if not set(after_rows) - before_names - {target_name}:
        return [], []
    if kind == "named_type.create_or_update":
        seed = after_rows.get(target_name) or {}
    elif kind in {"function.prototype.set", "local.type.set"}:
        seed = next((row for row in after.get("functions") or []
                     if str(row.get("address") or "").lower() == address), {})
        if kind == "local.type.set":
            seed = next((row for row in (seed.get("locals") or {}).get("items") or []
                         if row.get("index") == target.get("lvar_index")), {})
    elif kind == "global.type.set":
        seed = next((row for row in after.get("globals") or []
                     if str(row.get("address") or "").lower() == address), {})
    else:
        return [], []
    incomplete = []

    def references(row, label):
        scan = row.get("type_dependency_scan") or {}
        if scan.get("complete") is not True:
            incomplete.append(label)
        return list(row.get("type_dependencies") or [])

    pending = references(seed, "target")
    reached: set[str] = set()
    while pending:
        name = str(pending.pop())
        if not name or name == target_name or name in reached:
            continue
        reached.add(name)
        if name in after_rows:
            pending.extend(references(after_rows[name], name))
    return sorted(name for name in reached if name not in before_names), sorted(set(incomplete))


def classify_semantic_delta(
    operation: Mapping[str, Any],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    *,
    dependency_artifacts: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    changed = semantic_changed_paths(before, after)
    permitted = permitted_semantic_prefixes(operation)
    dependency_materializations, incomplete = _type_dependency_materializations(
        operation,
        before,
        after,
    )
    for name in dependency_materializations:
        permitted.extend([
            "named_types.%s" % name,
            "structs.%s" % name,
            "enums.%s" % name,
        ])
    dependencies = dict(dependency_artifacts or {})
    callback_bindings = []
    callback_names: dict[str, set[str]] = {}
    target_address = str((operation.get("target") or {}).get("address") or "").lower()
    if operation.get("kind") == "function.prototype.set":
        target_row = next((row for row in after.get("functions") or []
                           if str(row.get("address") or "").lower() == target_address), {})
        slots = {row["index"]: row.get("name")
                 for row in target_row.get("native_callback_parameters") or []}
        for caller in before.get("functions") or []:
            if caller.get("address") not in dependencies.get("function_addresses", []):
                continue
            for binding in (caller.get("locals") or {}).get("native_call_arguments") or []:
                if binding.get("callee") != target_address or binding.get("argument_index") not in slots:
                    continue
                callback = str(binding["function"]).lower()
                callback_bindings.append({"caller": caller["address"], **binding})
                callback_names.setdefault(callback, set()).add(slots[binding["argument_index"]])
        dependencies["function_addresses"] = list(dict.fromkeys([
            *dependencies.get("function_addresses", []), *callback_names,
        ]))
    dependency_prefixes = list(dict.fromkeys([
        *(
            "functions.%s.prototype" % str(address).lower()
            for address in dependencies.get("function_addresses") or []
            if address
        ),
        *(
            "globals.%s.declaration" % str(address).lower()
            for address in dependencies.get("global_addresses") or []
            if address
        ),
    ]))
    for row in after.get("functions") or []:
        address = str(row.get("address") or "").lower()
        if address in {str(ea).lower() for ea in dependencies.get("function_addresses") or []}:
            dependency_prefixes.extend(
                "functions.%s.locals.%s.declaration" % (address, item["index"])
                for item in (row.get("locals") or {}).get("items") or []
            )
    permitted.extend(dependency_prefixes)
    # Type propagation may change IDA-generated labels. This is not authority
    # to rename analyst state: require native provenance and measured type
    # propagation on this artifact or its directly referenced callee.
    automatic_names = []
    name_observations = []
    propagated_argument_names = set()
    target = operation.get("target") or {}
    if operation.get("kind") == "function.prototype.set" or (
        operation.get("kind") == "local.type.set" and target.get("is_parameter")
    ):
        target_address = str(target.get("function_address") or target.get("address") or "").lower()
        target_row = next((row for row in after.get("functions") or []
                           if str(row.get("address") or "").lower() == target_address), {})
        names = target_row.get("native_argument_names") or {}
        if names.get("available") is True:
            propagated_argument_names.update(names.get("names") or [])
    if str(operation.get("kind")) in {
        "function.prototype.set", "local.type.set", "global.type.set", "named_type.create_or_update"
    }:
        for surface in ("globals", "functions"):
            previous = {str(row.get("address") or "").lower(): row for row in before.get(surface) or []}
            for row in after.get(surface) or []:
                address = str(row.get("address") or "").lower()
                old = previous.get(address) or {}
                function_name_path = "functions.%s.name" % address
                if surface == "functions" and function_name_path in changed:
                    fields = ("name", "prototype", "native_has_user_name")
                    name_observations.append({
                        "path": function_name_path,
                        "before": {key: old.get(key) for key in fields},
                        "after": {key: row.get(key) for key in fields},
                    })
                if (surface == "functions" and address in callback_names
                        and function_name_path in changed
                        and old.get("native_has_user_name") is False
                        and isinstance(row.get("native_has_user_name"), bool)
                        and row.get("name") in callback_names[address]
                        and "functions.%s.prototype" % address in changed):
                    automatic_names.append(function_name_path)
                pairs = [("globals.%s" % address, old, row)] if surface == "globals" else [
                    ("functions.%s.locals.%s" % (address, item["index"]),
                     next((entry for entry in (old.get("locals") or {}).get("items") or []
                           if entry.get("index") == item["index"]), {}), item)
                    for item in (row.get("locals") or {}).get("items") or []
                ]
                for prefix, left, right in pairs:
                    declaration = prefix + ".declaration"
                    direct_callee_changed = (
                        surface == "functions"
                        and operation.get("kind") == "function.prototype.set"
                        and "functions.%s.prototype" % target_address in changed
                        and any(edge.get("kind") == "prototype_target_reference"
                                and edge.get("from") == target_address
                                and edge.get("to") == address
                                for edge in dependencies.get("edges") or [])
                    )
                    if prefix + ".name" in changed:
                        name_observations.append({"path": prefix + ".name", "before": {
                            key: left.get(key) for key in ("name", "declaration", "native_has_user_name", "native_saved_user_name")
                        }, "after": {key: right.get(key) for key in ("name", "declaration", "native_has_user_name", "native_saved_user_name")}})
                    if (left.get("native_has_user_name") is False
                            and (right.get("native_has_user_name") is False
                                 or (surface == "functions" and right.get("native_has_user_name") is True
                                     and right.get("name") in propagated_argument_names
                                     and right.get("native_saved_user_name") is not True))
                            and prefix + ".name" in changed
                            and (declaration in changed or direct_callee_changed)
                            and declaration in permitted
                            and left.get("is_argument") == right.get("is_argument")
                            and left.get("location") == right.get("location")):
                        automatic_names.append(prefix + ".name")
        permitted.extend(automatic_names)
    unexpected = [
        path for path in changed
        if not any(path == prefix or path.startswith(prefix + ".") for prefix in permitted)
    ]
    return {
        "schema": "verified_ida.semantic_delta.v1",
        "changed_paths": changed,
        "permitted_prefixes": permitted,
        "permitted_dependency_materializations": dependency_materializations,
        "permitted_native_dependency_prefixes": dependency_prefixes,
        "permitted_generated_name_changes": automatic_names,
        "name_change_observations": name_observations,
        "native_callback_bindings": callback_bindings,
        "native_dependency_source": dependencies.get("source"),
        "unexpected_paths": unexpected,
        "incomplete_dependency_measurements": incomplete,
        "status": ("verification_incomplete" if incomplete else
                   "unexpected_collateral_change" if unexpected else "permitted"),
        "interpretation": (
            "This classifies durable exported semantic state, not whether the "
            "requested analysis is behaviorally correct."
        ),
    }
