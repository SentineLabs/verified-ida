"""Read-only project coverage reconciliation before final completion."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Callable, Mapping

from .contracts import canonical_json
from .final_review import clone_verified_project
from .review_contracts import (
    RECONCILIATION_MAX_TARGETS_PER_FINDING,
    ReconciliationArtifactReport,
    ReconciliationSystemModelReport,
)
from .runtime import VerifiedIdaRuntime


ROOT = Path(__file__).resolve().parents[2]
SYSTEM_PROMPT = (
    ROOT / "prompts" / "reconciliation" /
    "verified_ida_reconciliation_system_v1.md"
)
ARTIFACT_PROMPT = (
    ROOT / "prompts" / "reconciliation" /
    "verified_ida_reconciliation_artifact_v1.md"
)


def _digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _address(value: Any) -> str:
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        raise RuntimeError("Expected an integer or hexadecimal address") from None


def completion_semantic_digest(completion: Mapping[str, Any]) -> str:
    checkpoints = []
    for row in completion.get("checkpoints") or []:
        detail = dict(row.get("details") or {})
        checkpoints.append({
            "component_id": row.get("component_id"),
            "revision": row.get("revision"),
            "idb_sha256": row.get("idb_sha256"),
            "semantic_digest": detail.get("semantic_digest"),
            "status": row.get("status"),
        })
    if not checkpoints or any(row["status"] != "verified" for row in checkpoints):
        raise RuntimeError(
            "Coverage reconciliation requires verified completion checkpoints"
        )
    checkpoints.sort(key=lambda row: str(row["component_id"]))
    return _digest(checkpoints)


def _target_addresses(target: Mapping[str, Any]) -> list[str]:
    values = []
    for key in (
        "address", "function_address", "source_address", "callsite_address",
        "destination_address",
    ):
        if target.get(key) not in (None, ""):
            values.append(str(target[key]))
    return values


def _application_endpoint_target(
    *,
    component_id: str,
    address: str,
    inspection: Mapping[str, Any],
) -> dict[str, Any]:
    """Map one relationship endpoint to an application-supported target.

    Durable relationship annotations currently bind two function references.
    A reviewer may still find a meaningful relationship from a vtable slot,
    global, or other address to a function.  Preserve that evidence as exact
    endpoint work rather than freezing an impossible relationship target.
    """

    normalized = _address(address)
    function = dict(inspection.get("function") or {})
    function_address = function.get("address") or function.get("start")
    if function_address not in (None, ""):
        return {
            "kind": "function",
            "component_id": component_id,
            "address": _address(function_address),
        }
    return {
        "kind": "address",
        "component_id": component_id,
        "address": normalized,
    }


def _deduplicate_targets(targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    result = []
    for target in targets:
        key = canonical_json(target)
        if key in seen:
            continue
        seen.add(key)
        result.append(target)
    return result


def _validate_exact_targets(
    source_project: Path,
    validation_dir: Path,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    project = validation_dir / "project"
    clone_verified_project(source_project, project)
    runtime = VerifiedIdaRuntime.initialize(
        project,
        analysis_feedback_profile="none",
        read_only_mode=True,
    )
    try:
        components = {
            str(row["component_id"]) for row in runtime.journal.components()
        }
        validated = []
        direct_call_cache: dict[
            tuple[str, str], tuple[dict[str, list[str]], str]
        ] = {}
        for finding in findings:
            primary = str(finding.get("component_id") or "")
            if primary not in components:
                raise RuntimeError(
                    "Reconciliation finding names unknown component %s" % primary
                )
            targets = list(finding.get("targets") or [])
            if not targets:
                raise RuntimeError("Reconciliation finding has no exact targets")
            target_evidence = []
            normalized_targets: list[dict[str, Any]] = []
            target_normalizations: list[dict[str, Any]] = []
            for raw in targets:
                target = dict(raw)
                component_id = str(target.get("component_id") or primary)
                if component_id not in components:
                    raise RuntimeError(
                        "Reconciliation target names unknown component %s"
                        % component_id
                    )
                addresses = _target_addresses(target)
                if target.get("kind") != "named_type" and not addresses:
                    raise RuntimeError(
                        "Reconciliation target lacks an exact address anchor"
                    )
                address_results: dict[str, dict[str, Any]] = {}
                for address in addresses:
                    response = runtime.inspect(
                        query="inspect_addr",
                        target=address,
                        component_id=component_id,
                        limit=1,
                    )
                    result = dict(response.get("result") or {})
                    if not result.get("ok"):
                        raise RuntimeError(
                            "Reconciliation target does not resolve: %s::%s"
                            % (component_id, address)
                        )
                    address_results[_address(address)] = result
                    target_evidence.append(response.get("evidence_id"))
                if target.get("kind") == "relationship":
                    source = _address(target.get("source_address"))
                    destination = _address(target.get("destination_address"))
                    source_target = _application_endpoint_target(
                        component_id=component_id,
                        address=source,
                        inspection=address_results[source],
                    )
                    destination_target = _application_endpoint_target(
                        component_id=component_id,
                        address=destination,
                        inspection=address_results[destination],
                    )
                    if (
                        source_target["kind"] != "function"
                        or destination_target["kind"] != "function"
                    ):
                        normalized_targets.extend([
                            source_target, destination_target,
                        ])
                        target_normalizations.append({
                            "reason": (
                                "relationship endpoints are not both functions; "
                                "the durable relationship tool cannot bind them"
                            ),
                            "original": target,
                            "replacement_targets": [
                                source_target, destination_target,
                            ],
                        })
                        continue
                    target["source_address"] = source_target["address"]
                    target["destination_address"] = destination_target["address"]
                if target.get("kind") == "relationship":
                    raw_source = target.get("source_address")
                    raw_destination = target.get("destination_address")
                    if raw_source in (None, "") or raw_destination in (None, ""):
                        raise RuntimeError(
                            "Reconciliation relationship target lacks both endpoints"
                        )
                    source = _address(raw_source)
                    destination = _address(raw_destination)
                    cache_key = (component_id, source)
                    if cache_key not in direct_call_cache:
                        if runtime.active_component_id != component_id:
                            runtime.switch_component(component_id)
                        inventory, evidence_id = runtime._inspect_direct_call_inventory(
                            source
                        )
                        destinations: dict[str, list[str]] = {}
                        for edge in inventory.get("edges") or []:
                            if not (
                                isinstance(edge, Mapping)
                                and edge.get("edge_kind") == "direct_internal"
                                and edge.get("classification_source")
                                == "ida_instruction_feature"
                            ):
                                continue
                            destination_key = _address(edge.get("destination"))
                            destinations.setdefault(destination_key, []).append(
                                _address(edge.get("callsite"))
                            )
                        direct_call_cache[cache_key] = (
                            destinations, str(evidence_id)
                        )
                    destinations, evidence_id = direct_call_cache[cache_key]
                    if destination in destinations:
                        target_evidence.append(evidence_id)
                        callsites = sorted(set(destinations[destination]))
                        requested_callsite = target.get("callsite_address")
                        if requested_callsite not in (None, ""):
                            normalized_callsite = _address(requested_callsite)
                            if normalized_callsite not in callsites:
                                raise RuntimeError(
                                    "Reconciliation relationship callsite is not "
                                    "a current IDA-native edge: %s::%s"
                                    % (component_id, normalized_callsite)
                                )
                            target["callsite_address"] = normalized_callsite
                        elif len(callsites) == 1:
                            original = dict(target)
                            target["callsite_address"] = callsites[0]
                            target_normalizations.append({
                                "reason": (
                                    "IDA topology identified the unique exact callsite"
                                ),
                                "original": original,
                                "replacement_targets": [dict(target)],
                            })
                        else:
                            raise RuntimeError(
                                "Reconciliation relationship has multiple exact "
                                "callsites; the reviewer must select one: %s"
                                % ", ".join(callsites)
                            )
                        if target.get("relationship_kind") != "direct_call":
                            original = dict(target)
                            target["relationship_kind"] = "direct_call"
                            target_normalizations.append({
                                "reason": (
                                    "decoded IDA instruction features prove this "
                                    "function relationship is a direct call"
                                ),
                                "original": original,
                                "replacement_targets": [dict(target)],
                            })
                    elif target.get("relationship_kind") == "direct_call":
                        raise RuntimeError(
                            "Reconciliation direct-call target is not a current "
                            "IDA-native edge: %s::%s->%s"
                            % (component_id, source, destination)
                        )
                if target.get("kind") == "named_type":
                    name = str(target.get("name") or "")
                    page = runtime.query_ida_collection(
                        family="types",
                        filters={"name_prefix": name},
                        limit=20,
                        component_id=component_id,
                    )
                    if not any(
                        str(row.get("name") or "") == name
                        for row in page.get("items") or []
                    ):
                        raise RuntimeError(
                            "Reconciliation named type does not resolve: %s::%s"
                            % (component_id, name)
                        )
                normalized_targets.append(target)
            normalized_targets = _deduplicate_targets(normalized_targets)
            if len(normalized_targets) > RECONCILIATION_MAX_TARGETS_PER_FINDING:
                raise RuntimeError(
                    "Reconciliation target normalization exceeds the %d-target "
                    "application limit"
                    % RECONCILIATION_MAX_TARGETS_PER_FINDING
                )
            validated.append({
                **finding,
                "targets": normalized_targets,
                "target_validation_evidence_refs": target_evidence,
                "target_normalizations": target_normalizations,
            })
        return validated
    finally:
        runtime.close()


def run_coverage_reconciliation(
    *,
    runtime: VerifiedIdaRuntime,
    completion: Mapping[str, Any],
    output_root: Path,
    model: str,
    reasoning_effort: str,
    environment: Mapping[str, Any],
    system_model_max_turns: int,
    artifact_coverage_max_turns: int,
    citation_repair_max_turns: int,
    on_response_end: Callable[[Mapping[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Collect one frozen system-to-artifact reconciliation round."""

    # Imported lazily to avoid a module cycle: the shared reviewer uses the
    # analyze command's SDK adapters and observable hooks.
    from .commands.project_review import build_final_review_packets
    from .commands.review import _run_readonly_review_stage

    semantic_digest = completion_semantic_digest(completion)
    prior = runtime.journal.latest_reconciliation_round()
    if prior and prior["state"] not in {"collecting", "failed"}:
        # One project-wide discovery pass creates one immutable worklist.  IDB
        # edits necessarily change the completion digest; that must not cause
        # another open-ended project review.  Later verification is scoped to
        # the findings already frozen in this campaign.
        return runtime.journal.reconciliation_status()
    if prior and prior["state"] == "collecting":
        # A process interruption can leave a read-only collection round open.
        # Its partial output is retained for audit but can never become work.
        runtime.journal.fail_reconciliation_round(str(prior["round_id"]))

    next_index = int(runtime.journal.connection.execute(
        "SELECT COUNT(*) AS count FROM reconciliation_rounds"
    ).fetchone()["count"]) + 1
    round_dir = output_root / ("round-%03d" % next_index)
    round_dir.mkdir(parents=True, exist_ok=False)
    round_row = runtime.journal.begin_reconciliation_round(
        semantic_digest=semantic_digest,
        checkpoint={"checkpoints": list(completion.get("checkpoints") or [])},
        review_path=str(round_dir),
    )
    # Freeze the project through SQLite's online-backup API.  The investigator
    # is paused, but its journal connection must remain open so the original
    # Agents SDK session can receive and resolve the resulting findings.
    frozen_project = round_dir / "frozen_project"
    clone_verified_project(
        runtime.workspace,
        frozen_project,
        source_connection=runtime.journal.connection,
    )
    closure_row = runtime.journal.latest_closure_review()
    if closure_row is None:
        raise RuntimeError(
            "Coverage reconciliation requires the investigator's current closure review"
        )
    closure_path = Path(str(closure_row["packet_path"]))
    if not closure_path.is_file():
        raise RuntimeError("Current closure-review packet is missing")
    closure = {"packet": json.loads(closure_path.read_text(encoding="utf-8"))}
    packets = build_final_review_packets(runtime, closure)
    scope_contract = {
        "schema": "verified_ida.coverage_reconciliation_scope.v1",
        "user_objective": runtime.project_objective,
        "authority": "user_supplied_project_objective",
        "supporting_context_does_not_expand_scope": True,
    }
    system_packet = {
        **packets["system_model"],
        "coverage_reconciliation_scope": scope_contract,
    }
    system_packet["packet_sha256"] = _digest(system_packet)
    system = _run_readonly_review_stage(
        source_project=frozen_project,
        stage_dir=round_dir / "system_model",
        stage="coverage_reconciliation",
        lane="system_model",
        packet=system_packet,
        prompt_path=SYSTEM_PROMPT,
        output_type=ReconciliationSystemModelReport,
        model=model,
        reasoning_effort=reasoning_effort,
        max_turns=system_model_max_turns,
        citation_repair_max_turns=citation_repair_max_turns,
        environment=environment,
        on_response_end=on_response_end,
    )
    artifact_packet = {
        **packets["artifact_coverage"],
        "system_model_report": system["report"],
        "coverage_reconciliation_scope": scope_contract,
        "prior_reconciliation_dispositions": (
            runtime.journal.reconciliation_history(limit=80)
        ),
        "reconciliation_contract": {
            "system_gaps_are_not_obligations": True,
            "exact_artifact_findings_required": True,
            "high_and_medium_findings_are_actionable": True,
            "low_findings_are_advisory": True,
        },
    }
    artifact_packet["packet_sha256"] = _digest(artifact_packet)
    artifact = _run_readonly_review_stage(
        source_project=frozen_project,
        stage_dir=round_dir / "artifact_mapping",
        stage="coverage_reconciliation",
        lane="artifact_mapping",
        packet=artifact_packet,
        prompt_path=ARTIFACT_PROMPT,
        output_type=ReconciliationArtifactReport,
        model=model,
        reasoning_effort=reasoning_effort,
        max_turns=artifact_coverage_max_turns,
        citation_repair_max_turns=citation_repair_max_turns,
        environment=environment,
        external_evidence_registry=system["evidence_registry"],
        on_response_end=on_response_end,
    )
    findings = _validate_exact_targets(
        frozen_project,
        round_dir / "target_validation",
        [dict(row) for row in artifact["report"].get("findings") or []],
    )
    collection_hit_turn_cap = bool(
        system["summary"].get("collection_hit_turn_cap")
        or artifact["summary"].get("collection_hit_turn_cap")
    )
    if collection_hit_turn_cap and not findings:
        runtime.journal.fail_reconciliation_round(str(round_row["round_id"]))
        raise RuntimeError(
            "A turn-capped coverage review cannot certify a clear project; "
            "retry the interrupted discovery campaign or disable reconciliation"
        )
    report = {
        "schema": "verified_ida.coverage_reconciliation.report.v1",
        "round_id": round_row["round_id"],
        "semantic_digest": semantic_digest,
        "system_model": system["report"],
        "artifact_findings": findings,
        "collection_hit_turn_cap": collection_hit_turn_cap,
        "stage_summaries": [system["summary"], artifact["summary"]],
    }
    report_path = round_dir / "report.json"
    report_path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return runtime.journal.record_reconciliation_findings(
        round_id=str(round_row["round_id"]),
        findings=findings,
        report_digest=_digest(report),
        review_path=str(report_path),
    )
