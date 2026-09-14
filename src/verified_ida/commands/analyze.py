#!/usr/bin/env python3
"""Run one stateful, receipt-verified IDA investigation."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
import sqlite3
import sys
import time
import traceback
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Callable, Mapping


ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from verified_ida.adapter import VerifiedIdaToolAdapter  # noqa: E402
from verified_ida.audit import (  # noqa: E402
    ObservableTrace,
    aggregate_usage,
    compaction_summary,
    event_counts,
    observable_response_items,
    observable_tool_arguments,
    segment_usage,
    write_walkthrough,
)
from verified_ida.model_tools import model_tool_declarations  # noqa: E402
from verified_ida.model_context import model_run_config  # noqa: E402
from verified_ida.prompting import (  # noqa: E402
    load_agent_instructions,
    render_starting_packet,
    write_prompt_snapshots,
)
from verified_ida.runtime import VerifiedIdaRuntime, _write_json_atomic  # noqa: E402
from verified_ida.safety_budget import (  # noqa: E402
    RunSafetyBudget,
    SafetyBudgetExceeded,
)
from verified_ida.source_provenance import describe_source  # noqa: E402
from verified_ida.session_context import (  # noqa: E402
    SessionMaintenanceError,
    archive_and_prune_session,
    archive_session_snapshot,
    compaction_provenance,
    encoded_items,
    items_digest,
    record_server_compactions,
    session_inventory,
    sha256_file,
)


REQUIRED_AGENTS_SDK = "0.20.0"
DEFAULT_COMPACT_THRESHOLD_TOKENS = 200_000
DEFAULT_SESSION_PRUNE_BYTES = 4_000_000
DEFAULT_STANDALONE_COMPACT_MAX_BYTES = 1_000_000
DEFAULT_MAX_TOTAL_TOKENS = 250_000_000
DEFAULT_MAX_TOTAL_REQUESTS = 2_500
DEFAULT_MAX_ELAPSED_SECONDS = 14_400


class RunInterrupted(RuntimeError):
    """Raised when the controller receives a catchable termination signal."""

    def __init__(self, signum: int):
        self.signum = int(signum)
        super().__init__("controller received signal %d" % self.signum)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a persistent, receipt-verified IDA analysis."
    )
    parser.add_argument("--sample")
    parser.add_argument("--clean-idb")
    parser.add_argument("--project-dir", required=True)
    parser.add_argument("--model", default=os.environ.get("ANALYSIS_MODEL", "gpt-5.6-sol"))
    parser.add_argument(
        "--instructions-path",
        help=(
            "Optional replacement analysis instructions; "
            "the exact content is copied into prompt_snapshots."
        ),
    )
    parser.add_argument(
        "--objective",
        default=(
            "Reverse engineer the supplied program to a complete, evidence-supported "
            "understanding of its behavior and structure, and capture that "
            "understanding accurately in the IDA databases."
        ),
    )
    parser.add_argument("--analysis-root", action="append", default=[])
    parser.add_argument(
        "--reasoning-effort",
        choices=["none", "minimal", "low", "medium", "high", "xhigh"],
        default="xhigh",
    )
    parser.add_argument("--initial-frontier-size", type=int, default=8)
    parser.add_argument(
        "--analysis-feedback",
        choices=["none", "scoped"],
        default=os.environ.get("VERIFIED_IDA_ANALYSIS_FEEDBACK", "scoped"),
        help=(
            "Bounded host-measured edit feedback. scoped reports relevant "
            "propagation and nonblocking type-application advisories; none "
            "disables that additional feedback."
        ),
    )
    parser.add_argument(
        "--component-handoff-policy",
        choices=["none", "advisory"],
        default="advisory",
        help=(
            "Parent-to-child context checkpoint policy. Advisory records a "
            "specific warning without preventing a switch."
        ),
    )
    parser.add_argument(
        "--coverage-reconciliation",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Experimental: run a frozen system-to-artifact coverage review after "
            "provisional completion, then return bounded findings to this session. "
            "The selection persists across resumed runs."
        ),
    )
    parser.add_argument("--reconciliation-system-max-turns", type=int, default=24)
    parser.add_argument("--reconciliation-artifact-max-turns", type=int, default=50)
    parser.add_argument("--reconciliation-citation-repair-max-turns", type=int, default=16)
    parser.add_argument(
        "--reconciliation-max-continuations",
        type=int,
        default=6,
        help=(
            "Runaway ceiling reserved for reconciliation/application segments; "
            "it is not an analytical completion quota."
        ),
    )
    parser.add_argument("--max-agent-turns", type=int, default=400)
    parser.add_argument("--max-continuations", type=int, default=6)
    parser.add_argument(
        "--max-total-tokens",
        type=int,
        default=DEFAULT_MAX_TOTAL_TOKENS,
        help="Shared investigator-and-reviewer safety ceiling; zero disables it.",
    )
    parser.add_argument(
        "--max-total-requests",
        type=int,
        default=DEFAULT_MAX_TOTAL_REQUESTS,
        help="Shared model-response safety ceiling; zero disables it.",
    )
    parser.add_argument(
        "--max-elapsed-seconds",
        type=int,
        default=DEFAULT_MAX_ELAPSED_SECONDS,
        help="Shared wall-clock safety ceiling; zero disables it.",
    )
    parser.add_argument(
        "--compact-threshold-tokens",
        type=int,
        default=int(
            os.environ.get(
                "VERIFIED_IDA_COMPACT_THRESHOLD_TOKENS",
                DEFAULT_COMPACT_THRESHOLD_TOKENS,
            )
        ),
        help="Responses server-compaction threshold; zero disables it.",
    )
    parser.add_argument(
        "--session-prune-bytes",
        type=int,
        default=DEFAULT_SESSION_PRUNE_BYTES,
        help="Archive and prune a healthy compacted SQLite session above this size.",
    )
    parser.add_argument(
        "--standalone-compact-max-bytes",
        type=int,
        default=DEFAULT_STANDALONE_COMPACT_MAX_BYTES,
        help="Maximum uncompacted stored history eligible for recovery compaction.",
    )
    parser.add_argument("--enable-sdk-tracing", action="store_true")
    parser.add_argument(
        "--intervention-note",
        action="append",
        default=[],
        help="Record an operator intervention in the investigation trace.",
    )
    parser.add_argument("--print-tool-contract", action="store_true")
    return parser.parse_args(argv)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)


def _sdk_environment(*, enforce: bool = True) -> dict[str, Any]:
    try:
        sdk_version = version("openai-agents")
    except PackageNotFoundError:
        sdk_version = None
    environment = {
        "python": "%d.%d.%d" % sys.version_info[:3],
        "openai_agents": sdk_version,
        "required_openai_agents": REQUIRED_AGENTS_SDK,
    }
    if not enforce:
        return environment
    if sys.version_info < (3, 10):
        raise SystemExit("Verified IDA requires Python 3.10 or newer")
    if sdk_version != REQUIRED_AGENTS_SDK:
        raise SystemExit(
            "Verified IDA requires openai-agents==%s; found %s"
            % (REQUIRED_AGENTS_SDK, sdk_version or "not installed")
        )
    return environment


def _agent_instructions() -> str:
    """Return the exact, human-reviewable default instruction document."""

    return str(load_agent_instructions()["content"])


@dataclass
class ToolInvocationState:
    """Remember the final model-facing tool result in one SDK segment."""

    last_tool: str | None = None
    last_result: Any = None

    def reset(self) -> None:
        self.last_tool = None
        self.last_result = None

    def record(self, tool_name: str, result: Any) -> None:
        self.last_tool = tool_name
        self.last_result = result


def _completion_after_agent(
    runtime: VerifiedIdaRuntime,
    tool_state: ToolInvocationState,
) -> tuple[dict[str, Any], bool]:
    """Reuse a final successful model completion; otherwise verify now."""

    status = runtime.completion_status()
    if not status["may_finish"]:
        return status, False
    if (
        tool_state.last_tool == "complete_ida_investigation"
        and isinstance(tool_state.last_result, dict)
        and tool_state.last_result.get("may_finish") is True
    ):
        return tool_state.last_result, True
    return runtime.complete(), False


def _runtime_position(runtime: VerifiedIdaRuntime) -> dict[str, Any]:
    component = runtime.active_component_id
    try:
        artifact = runtime.artifact(component)
    except Exception:
        artifact = {}
    return {
        "active_component": component,
        "database_revision": artifact.get("database_revision"),
    }


def _function_tools(
    adapter: VerifiedIdaToolAdapter,
    trace: ObservableTrace,
    tool_state: ToolInvocationState,
    segment_id: str,
    *,
    allowed_names: set[str] | None = None,
):
    from agents import FunctionTool  # type: ignore

    tools = []
    for declaration in model_tool_declarations():
        name = declaration["name"]
        if name not in adapter.schemas:
            continue
        if allowed_names is not None and name not in allowed_names:
            continue

        async def invoke(_context: Any, arguments_json: str, *, tool_name=name) -> str:
            arguments: dict[str, Any] = {}
            try:
                arguments = json.loads(arguments_json or "{}")
                result = adapter.invoke(tool_name, arguments)
                tool_state.record(tool_name, result)
                trace.append(
                    "tool_result",
                    segment_id=segment_id,
                    actor="model_and_host",
                    tool=tool_name,
                    arguments=observable_tool_arguments(tool_name, arguments),
                    ok=True,
                    result=result,
                    **_runtime_position(adapter.runtime),
                )
                return _json({"ok": True, "result": result})
            except Exception as exc:
                tool_state.record(tool_name, None)
                from verified_ida.errors import tool_error
                error = {"ok": False, "error": tool_error(exc)}
                trace.append(
                    "tool_result",
                    segment_id=segment_id,
                    actor="model_and_host",
                    tool=tool_name,
                    arguments=(
                        observable_tool_arguments(tool_name, arguments)
                        if arguments
                        else {
                            "arguments_utf8_bytes": len(
                                arguments_json.encode("utf-8")
                            ),
                            "arguments_sha256": hashlib.sha256(
                                arguments_json.encode("utf-8")
                            ).hexdigest(),
                        }
                    ),
                    **error,
                    **_runtime_position(adapter.runtime),
                )
                return _json(error)

        tools.append(FunctionTool(
            name=name,
            description=declaration["description"],
            params_json_schema=declaration["input_schema"],
            on_invoke_tool=invoke,
            strict_json_schema=False,
        ))
    return tools


def _usage_dict(value: Any) -> dict[str, int]:
    input_details = getattr(value, "input_tokens_details", None)
    output_details = getattr(value, "output_tokens_details", None)
    return {
        "requests": int(getattr(value, "requests", 0) or 0),
        "input_tokens": int(getattr(value, "input_tokens", 0) or 0),
        "cached_input_tokens": int(
            getattr(input_details, "cached_tokens", 0) or 0
        ),
        "output_tokens": int(getattr(value, "output_tokens", 0) or 0),
        "reasoning_output_tokens": int(
            getattr(output_details, "reasoning_tokens", 0) or 0
        ),
        "total_tokens": int(getattr(value, "total_tokens", 0) or 0),
    }


def _observable_hooks(
    trace: ObservableTrace,
    runtime: VerifiedIdaRuntime,
    *,
    segment_id: str,
    compact_threshold_tokens: int,
    on_response_end: Callable[[Mapping[str, Any]], None] | None = None,
    on_tool_end: Callable[[Mapping[str, Any]], None] | None = None,
    session: Any = None,
):
    from agents.lifecycle import RunHooksBase  # type: ignore

    class ObservableHooks(RunHooksBase):
        async def on_llm_start(self, _context, _agent, _system_prompt, _input_items) -> None:
            from verified_ida.review_budget import ACTIVE_REVIEW_BUDGET
            budget = ACTIVE_REVIEW_BUDGET.get()
            if budget is not None:
                budget.check("before_model_request:%s" % segment_id)
            self.request_id = "request-" + uuid.uuid4().hex
            self.request_started = time.monotonic()
            self.request_input_digest = items_digest(_input_items)
            trace.append(
                "model_request_started", actor="harness", segment_id=segment_id,
                model_request_id=self.request_id,
                input_items=len(_input_items), input_bytes=len(encoded_items(_input_items)),
                input_sha256=self.request_input_digest,
                instructions_sha256=hashlib.sha256((_system_prompt or "").encode("utf-8")).hexdigest(),
                **_runtime_position(runtime),
            )

        async def on_llm_end(self, _context: Any, _agent: Any, response: Any) -> None:
            output = list(getattr(response, "output", None) or [])
            if session is not None:
                record_server_compactions(session, output)
            observations = observable_response_items(output)
            usage = _usage_dict(getattr(response, "usage", None))
            response_id = getattr(response, "response_id", None)
            position = _runtime_position(runtime)
            trace.append(
                "model_response",
                segment_id=segment_id,
                actor="model",
                response_id=response_id,
                model_request_id=getattr(self, "request_id", None),
                request_elapsed_seconds=(round(time.monotonic() - self.request_started, 6)
                                         if hasattr(self, "request_started") else None),
                input_sha256=getattr(self, "request_input_digest", None),
                usage=usage,
                output_bytes=observations["output_bytes"],
                output_sha256=observations["output_sha256"],
                output_types=observations["output_types"],
                visible_messages=observations["visible_messages"],
                tool_calls=observations["tool_calls"],
                **position,
            )
            if observations["compactions"]:
                trace.append(
                    "context_compaction",
                    segment_id=segment_id,
                    actor="responses_server",
                    response_id=response_id,
                    compact_threshold_tokens=compact_threshold_tokens,
                    item_count=len(observations["compactions"]),
                    items=observations["compactions"],
                    usage=usage,
                    **position,
                )
            from verified_ida.review_budget import ACTIVE_REVIEW_BUDGET
            budget = ACTIVE_REVIEW_BUDGET.get()
            if budget is not None:
                budget.observe_response(
                    {"response_id": response_id, "usage": usage},
                    phase="model_response:%s" % segment_id,
                )
            if on_response_end is not None:
                on_response_end({
                    "response_id": response_id,
                    "usage": usage,
                    "observations": observations,
                    "position": position,
                })

        async def on_tool_end(
            self,
            _context: Any,
            _agent: Any,
            tool: Any,
            result: object,
        ) -> None:
            if on_tool_end is not None:
                on_tool_end({
                    "tool": getattr(tool, "name", type(tool).__name__),
                    "result": result,
                    "position": _runtime_position(runtime),
                })

    return ObservableHooks()


def _session_identity(project_dir: Path) -> dict[str, Any]:
    """Return the stable Agents SDK session identity owned by a project.

    Final review clones projects into a directory with a different name.  The
    SQLite file alone is not sufficient to resume its history because the SDK
    also selects rows by logical session ID.  New projects persist that ID in
    metadata; older projects are recovered conservatively from a database that
    contains exactly one session.
    """

    metadata_path = project_dir / "model_session.json"
    database_path = project_dir / "model_session.sqlite"

    def database_session_ids() -> list[str]:
        if not database_path.is_file():
            return []
        with sqlite3.connect(str(database_path)) as connection:
            table = connection.execute(
                "SELECT 1 FROM sqlite_master "
                "WHERE type = 'table' AND name = 'agent_sessions'"
            ).fetchone()
            if not table:
                return []
            return [
                str(row[0])
                for row in connection.execute(
                    "SELECT session_id FROM agent_sessions ORDER BY session_id"
                ).fetchall()
            ]

    if metadata_path.is_file():
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        session_id = str(metadata.get("session_id") or "").strip()
        if not session_id:
            raise RuntimeError(
                "Agents SDK session metadata has no session_id: %s"
                % metadata_path
            )
        recorded_session_ids = database_session_ids()
        if len(recorded_session_ids) > 1:
            raise RuntimeError(
                "Verified IDA project contains multiple Agents SDK sessions; "
                "refusing ambiguous continuation: %s"
                % ", ".join(recorded_session_ids)
            )
        if recorded_session_ids and session_id not in recorded_session_ids:
            raise RuntimeError(
                "Agents SDK session metadata does not match the persisted "
                "investigation session: metadata=%s database=%s"
                % (session_id, ", ".join(recorded_session_ids))
            )
        return {
            "session_id": session_id,
            "source": "metadata",
            "metadata_path": str(metadata_path),
        }

    session_ids = database_session_ids()
    if len(session_ids) > 1:
        raise RuntimeError(
            "Verified IDA project contains multiple Agents SDK sessions; "
            "refusing to guess which investigation to resume: %s"
            % ", ".join(session_ids)
        )
    session_id = (
        session_ids[0]
        if session_ids
        else "verified-ida-%s" % project_dir.name
    )
    metadata = {
        "schema": "verified_ida.model_session.v1",
        "session_id": session_id,
        "database": "model_session.sqlite",
        "recovered_from": "agent_sessions" if session_ids else "new_project",
    }
    temporary = metadata_path.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(metadata_path)
    return {
        "session_id": session_id,
        "source": metadata["recovered_from"],
        "metadata_path": str(metadata_path),
    }


def _session(project_dir: Path):
    from agents import SQLiteSession  # type: ignore

    identity = _session_identity(project_dir)
    return SQLiteSession(
        str(identity["session_id"]),
        db_path=project_dir / "model_session.sqlite",
    )


def _segment_id() -> str:
    return "%s-pid%d" % (
        datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ"),
        os.getpid(),
    )


def _recovery_capsule(
    *,
    runtime: VerifiedIdaRuntime,
    objective: str,
) -> dict[str, Any]:
    completion = runtime.completion_status()
    log_path = runtime.workspace / "reversing_log.md"
    return {
        "kind": "verified_ida_context_recovery",
        "objective": objective,
        "constraints": [
            "Treat live IDA state and operation receipts as authoritative.",
            "Re-read the reversing log and re-inspect targets instead of trusting stale code dumps.",
            "Resolve only the exact operational blockers listed here before completion.",
        ],
        "active_artifact": runtime.artifact(),
        "open_blockers": {
            "must_review": completion.get("must_review") or [],
            "mechanical_failures": completion.get("mechanical_failures") or [],
            "component_decisions_required": (
                completion.get("component_decisions_required") or []
            ),
            "call_flow_scopes_required": (
                completion.get("call_flow_scopes_required") or []
            ),
            "reconciliation_findings_required": (
                completion.get("reconciliation_findings_required") or []
            ),
        },
        "call_flow": completion.get("call_flow") or {},
        "coverage_reconciliation": (
            completion.get("coverage_reconciliation") or {}
        ),
        "reversing_log": {
            "path": str(log_path.resolve()),
            "sha256": sha256_file(log_path),
        },
    }


async def _replace_with_recovery_capsule(
    session: Any,
    *,
    original_items: list[Any],
    capsule: Mapping[str, Any],
    archive: str,
) -> None:
    replacement = [{"role": "user", "content": _json(dict(capsule))}]
    stage = "clear"
    try:
        from verified_ida.session_context import replace_session_items
        stage = "add_capsule"
        await replace_session_items(session, replacement)
        stage = "verify_capsule"
        observed = list(await session.get_items())
        if len(observed) != 1 or items_digest(observed) != items_digest(replacement):
            raise RuntimeError("Recovery capsule did not round-trip exactly")
    except Exception as exc:
        restored = False
        try:
            await replace_session_items(session, list(original_items))
            restored_items = list(await session.get_items())
            restored = (
                len(restored_items) == len(original_items)
                and items_digest(restored_items) == items_digest(original_items)
            )
        except Exception:
            restored = False
        raise SessionMaintenanceError(
            "%s: %s" % (type(exc).__name__, exc),
            stage=stage,
            restored=restored,
            archive=archive,
        ) from exc


def _prepare_resumed_session(
    session: Any,
    *,
    project_dir: Path,
    runtime: VerifiedIdaRuntime,
    trace: ObservableTrace,
    model: str,
    objective: str,
    segment_id: str,
    prune_threshold_bytes: int,
    standalone_compact_max_bytes: int,
) -> dict[str, Any]:
    """Select a compaction-aware resume path without changing IDA state."""

    items = list(asyncio.run(session.get_items()))
    inventory = session_inventory(items, compaction_provenance(session))
    trace.append(
        "session_inventory",
        segment_id=segment_id,
        actor="harness",
        inventory=inventory.as_dict(),
        **_runtime_position(runtime),
    )
    if not items:
        if any((project_dir / "session_archives").glob("*.manifest.json")):
            raise SessionMaintenanceError(
                "Empty active session has archived history; explicit recovery is required",
                stage="resume_empty_archived_session", restored=False,
            )
        return {"action": "empty", "inventory": inventory.as_dict()}

    sqlite_path = project_dir / "model_session.sqlite"
    archive_dir = project_dir / "session_archives"
    archive_metadata = {
        **_sdk_environment(enforce=False),
        "model": model,
        "store": False,
    }
    if inventory.latest_compaction_index is not None:
        maintenance: dict[str, Any]
        try:
            maintenance = asyncio.run(archive_and_prune_session(
                session,
                sqlite_path=sqlite_path,
                archive_dir=archive_dir,
                segment_id=segment_id,
                prune_threshold_bytes=max(1, prune_threshold_bytes),
                metadata=archive_metadata,
            ))
            if maintenance.get("action") == "archived_and_pruned":
                trace.append(
                    "session_archived_and_pruned",
                    segment_id=segment_id,
                    actor="harness",
                    maintenance=maintenance,
                    **_runtime_position(runtime),
                )
        except SessionMaintenanceError as exc:
            trace.append(
                "session_prune_failed",
                segment_id=segment_id,
                actor="harness",
                failure=exc.as_dict(),
                **_runtime_position(runtime),
            )
            if exc.restored:
                return {
                    "action": "resume_compacted_session",
                    "inventory": inventory.as_dict(),
                    "maintenance": exc.as_dict(),
                }
            capsule = _recovery_capsule(runtime=runtime, objective=objective)
            asyncio.run(_replace_with_recovery_capsule(
                session,
                original_items=items,
                capsule=capsule,
                archive=str(exc.archive or ""),
            ))
            result = {
                "action": "state_derived_recovery_handoff",
                "inventory": inventory.as_dict(),
                "archive": exc.archive,
                "prune_failure": exc.as_dict(),
            }
            trace.append(
                "session_recovery_handoff",
                segment_id=segment_id,
                actor="harness",
                recovery=result,
                **_runtime_position(runtime),
            )
            return result
        return {
            "action": "resume_compacted_session",
            "inventory": inventory.as_dict(),
            "maintenance": maintenance,
        }

    compaction_error: str | None = None
    if inventory.encoded_bytes <= max(1, standalone_compact_max_bytes):
        try:
            from verified_ida.session_context import compact_session_atomically

            recovery_archive = archive_session_snapshot(
                sqlite_path=sqlite_path, archive_dir=archive_dir, segment_id=segment_id,
                items=items, reason="standalone_recovery_compaction", metadata=archive_metadata,
            )
            recovered = asyncio.run(compact_session_atomically(
                session, session_id="verified-ida-%s" % project_dir.name, model=model,
            ))
            recovered_inventory = session_inventory(recovered)
            if recovered_inventory.latest_compaction_index is None:
                raise RuntimeError("Recovery compaction returned no persisted compaction item")
            result = {
                "action": "standalone_recovery_compaction",
                "archive": recovery_archive,
                "before": inventory.as_dict(),
                "after": recovered_inventory.as_dict(),
            }
            trace.append(
                "session_recovery_compacted",
                segment_id=segment_id,
                actor="responses_server_and_harness",
                recovery=result,
                **_runtime_position(runtime),
            )
            return result
        except Exception as exc:
            compaction_error = "%s: %s" % (type(exc).__name__, exc)
    else:
        compaction_error = "stored history exceeds standalone recovery envelope"

    archive = archive_session_snapshot(
        sqlite_path=sqlite_path,
        archive_dir=archive_dir,
        segment_id=segment_id,
        items=items,
        reason="state_derived_recovery_handoff",
        metadata=archive_metadata,
    )
    capsule = _recovery_capsule(runtime=runtime, objective=objective)
    asyncio.run(_replace_with_recovery_capsule(
        session,
        original_items=items,
        capsule=capsule,
        archive=archive["archive"],
    ))
    result = {
        "action": "state_derived_recovery_handoff",
        "inventory": inventory.as_dict(),
        "archive": archive,
        "compaction_error": compaction_error,
        "capsule": {
            "active_artifact": capsule["active_artifact"],
            "reversing_log": capsule["reversing_log"],
            "blocker_counts": {
                key: len(value)
                for key, value in capsule["open_blockers"].items()
            },
        },
    }
    trace.append(
        "session_recovery_handoff",
        segment_id=segment_id,
        actor="harness",
        recovery=result,
        **_runtime_position(runtime),
    )
    return result


def _write_summary(
    *,
    project_dir: Path,
    trace: ObservableTrace,
    runtime: VerifiedIdaRuntime,
    status: str,
    args: argparse.Namespace,
    environment: Mapping[str, Any],
    segment_id: str,
    completion: Mapping[str, Any],
    final_output: str,
    continuations: int,
    prompt_provenance: Mapping[str, Any],
    source_provenance: Mapping[str, Any],
    attempt_id: str,
    phase: str,
    error: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    runtime.journal.finish_run_attempt(
        attempt_id,
        status=status,
        phase=phase,
        error=error,
    )
    terminal_event = "run_completed" if status == "completed" else "run_stopped"
    trace.append(
        terminal_event,
        segment_id=segment_id,
        actor="harness",
        status=status,
        completion=dict(completion),
        **_runtime_position(runtime),
    )
    walkthrough = write_walkthrough(trace, project_dir / "walkthrough.md")
    events, parse_errors = trace.read()
    summary = {
        "schema": "verified_ida.run_summary.v1",
        "status": status,
        "model": args.model,
        "reasoning_effort": args.reasoning_effort,
        "source": dict(source_provenance),
        "run_attempt": runtime.journal.run_attempt(attempt_id),
        "environment": dict(environment),
        "session_policy": {
            "type": "responses_server_compaction",
            "store": False,
            "compact_threshold_tokens": args.compact_threshold_tokens,
            "prune_threshold_bytes": args.session_prune_bytes,
            "standalone_recovery_max_bytes": args.standalone_compact_max_bytes,
            "analysis_feedback": args.analysis_feedback,
            "component_handoff_policy": args.component_handoff_policy,
            "coverage_reconciliation": runtime.coverage_reconciliation_enabled,
            "ida_session_backend": "process",
            "safety_budget": {
                "max_total_tokens": args.max_total_tokens,
                "max_total_requests": args.max_total_requests,
                "max_elapsed_seconds": args.max_elapsed_seconds,
            },
        },
        "usage": aggregate_usage(events),
        "segment_usage": segment_usage(events),
        "usage_complete": not parse_errors,
        "compaction": compaction_summary(events),
        "event_counts": event_counts(events),
        "trace_parse_errors": parse_errors,
        "operations": runtime.journal.operation_summary(),
        "project": runtime.journal.resume_summary(),
        "completion": dict(completion),
        "coverage_reconciliation": (
            runtime.journal.reconciliation_status()
            if runtime.coverage_reconciliation_enabled
            else {"enabled": False, "state": "disabled"}
        ),
        "final_output": final_output,
        "error": dict(error or {}),
        "continuations": continuations,
        "prompts": dict(prompt_provenance),
        "artifacts": {
            "observable_trace": str(trace.path.resolve()),
            "walkthrough": walkthrough,
            "coverage_reconciliation": (
                str(
                    project_dir.parent
                    / (project_dir.name + "-coverage-reconciliation")
                )
                if runtime.coverage_reconciliation_enabled else None
            ),
        },
    }
    budget_path = project_dir / "safety_budget.json"
    if budget_path.is_file():
        summary["safety_budget"] = json.loads(
            budget_path.read_text(encoding="utf-8")
        )
    destination = project_dir / "run_summary.json"
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(summary, indent=2, sort_keys=True, default=str) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return summary


def _write_failure_summary(exc: BaseException, state: Mapping[str, Any]) -> dict[str, Any]:
    """Preserve the initiating error even if normal summary collection fails."""
    error = {
        "type": type(exc).__name__, "message": str(exc),
        "traceback": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-16000:],
    }
    status = "interrupted" if isinstance(exc, (RunInterrupted, KeyboardInterrupt)) else "failed"
    phase = (state.get("phase_state") or {}).get("value", "initialization")
    runtime = state.get("runtime")
    summary = {
        "schema": "verified_ida.run_summary.v1", "status": status,
        "phase": phase, "error": error, "completion": {"may_finish": False},
        "source": dict(state.get("source_provenance") or {}),
        "partial_result_directory": str(state["project_dir"]),
        "summary_complete": False,
    }
    try:
        if runtime is not None and state.get("attempt_id"):
            runtime.journal.finish_run_attempt(
                state["attempt_id"], status=status, phase=phase, error=error,
            )
        required = ("trace", "segment_id", "attempt_id", "prompt_provenance", "args", "environment")
        if runtime is not None and all(name in state for name in required):
            completion = {**runtime.completion_status(), "may_finish": False}
            return _write_summary(
                project_dir=state["project_dir"], trace=state["trace"], runtime=runtime,
                status=status, args=state["args"], environment=state["environment"],
                segment_id=state["segment_id"], completion=completion,
                final_output=(state.get("outputs") or [""])[-1],
                continuations=state.get("continuation", 0),
                prompt_provenance=state["prompt_provenance"],
                source_provenance=state.get("source_provenance") or {},
                attempt_id=state["attempt_id"], phase=phase, error=error,
            )
    except Exception as secondary:
        summary["summary_error"] = {"type": type(secondary).__name__, "message": str(secondary)}
    _write_json_atomic(state["project_dir"] / "run_summary.json", summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    args = parse_args(list(argv or sys.argv[1:]))
    if args.print_tool_contract:
        print(json.dumps(model_tool_declarations(), indent=2))
        return 0
    environment = _sdk_environment()
    source_provenance = describe_source(ida_backend="process")
    from agents import (  # type: ignore
        Agent,
        ModelSettings,
        Runner,
        set_tracing_disabled,
    )
    from agents.exceptions import MaxTurnsExceeded  # type: ignore
    from openai.types.shared.reasoning import Reasoning  # type: ignore

    project_dir = Path(args.project_dir).expanduser().resolve()
    is_resume = (project_dir / "verified_ida.sqlite").is_file()
    if not is_resume and (not args.sample or not args.clean_idb):
        raise SystemExit(
            "A new project requires --sample and --clean-idb; an existing "
            "project can resume with --project-dir alone."
        )
    if not args.enable_sdk_tracing:
        set_tracing_disabled(True)
    runtime = VerifiedIdaRuntime.initialize(
        project_dir,
        binary_path=args.sample,
        clean_idb_path=args.clean_idb,
        project_objective=args.objective,
        analysis_feedback_profile=args.analysis_feedback,
        component_handoff_policy=args.component_handoff_policy,
        coverage_reconciliation=args.coverage_reconciliation,
    )
    try:
        args.objective = runtime.project_objective
        adapter = VerifiedIdaToolAdapter(runtime)
        seed = (
            {"resumed": True, "component_id": runtime.active_component_id}
            if is_resume
            else runtime.seed_frontier(roots=args.analysis_root)
        )
        initial_limit = max(1, min(args.initial_frontier_size, 20))
        initial = {
            "must_review": runtime.frontier_page(
                collection="must_review",
                component_id="root",
                limit=initial_limit,
            ),
            "suggested_next": runtime.frontier_page(
                collection="suggested_next",
                component_id="root",
                limit=initial_limit,
            ),
        }
        trace = ObservableTrace(project_dir / "observable_tool_trace.jsonl")
        safety_budget = RunSafetyBudget(
            project_dir / "safety_budget.json",
            max_total_tokens=args.max_total_tokens,
            max_requests=args.max_total_requests,
            max_elapsed_seconds=args.max_elapsed_seconds,
        )
        segment_id = _segment_id()
        reconciliation_backfill = (
            runtime.journal.backfill_active_reconciliation_activity()
            if is_resume and runtime.coverage_reconciliation_enabled
            else None
        )
        active_finding = runtime.journal.active_reconciliation_finding()
        phase_state = {
            "value": (
                "reconciliation_application"
                if active_finding is not None else "primary_investigation"
            )
        }
        attempt = runtime.journal.begin_run_attempt(
            segment_id=segment_id,
            phase=phase_state["value"],
        )
        attempt_id = str(attempt["attempt_id"])

        prior_signal_handlers: dict[int, Any] = {}

        def interrupt_handler(signum: int, _frame: Any) -> None:
            raise RunInterrupted(signum)

        for signum in (signal.SIGTERM, signal.SIGINT):
            prior_signal_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupt_handler)
        start_event = "investigation_resumed" if is_resume else "investigation_started"
        trace.append(
            start_event,
            segment_id=segment_id,
            actor="harness",
            model=args.model,
            reasoning_effort=args.reasoning_effort,
            objective=args.objective,
            source=source_provenance,
            environment=environment,
            session_policy={
                "type": "responses_server_compaction",
                "store": False,
                "compact_threshold_tokens": args.compact_threshold_tokens,
                "prune_threshold_bytes": args.session_prune_bytes,
                "standalone_recovery_max_bytes": args.standalone_compact_max_bytes,
                "analysis_feedback": args.analysis_feedback,
                "component_handoff_policy": args.component_handoff_policy,
                "coverage_reconciliation": runtime.coverage_reconciliation_enabled,
                "ida_session_backend": "process",
            },
            seed=seed,
            frontier=initial,
            attempt_id=attempt_id,
            reconciliation_backfill=reconciliation_backfill,
            **_runtime_position(runtime),
        )
        for note in args.intervention_note:
            trace.append(
                "experimental_intervention",
                segment_id=segment_id,
                actor="user",
                note=str(note),
                **_runtime_position(runtime),
            )
        session = _session(project_dir)
        preparation = None
        if is_resume:
            preparation = _prepare_resumed_session(
                session,
                project_dir=project_dir,
                runtime=runtime,
                trace=trace,
                model=args.model,
                objective=args.objective,
                segment_id=segment_id,
                prune_threshold_bytes=args.session_prune_bytes,
                standalone_compact_max_bytes=args.standalone_compact_max_bytes,
            )
        instructions = (
            load_agent_instructions(args.instructions_path)
            if args.instructions_path else load_agent_instructions()
        )
        capabilities = runtime.describe_ida_capabilities()
        survey = runtime.survey_idb(component_id="root")
        prompt = render_starting_packet(
            objective=args.objective,
            resumed=is_resume,
            seed=seed,
            frontier=initial,
            survey=survey,
            capabilities=capabilities,
            session_preparation=preparation,
            resume_state=(runtime.journal.resume_summary() if is_resume else None),
        )
        prompt_provenance = write_prompt_snapshots(
            project_dir=project_dir,
            segment_id=segment_id,
            instructions=instructions,
            starting_packet=prompt,
        )
        trace.append(
            "prompt_composed",
            segment_id=segment_id,
            actor="harness",
            prompts=prompt_provenance,
            starting_packet=prompt,
            **_runtime_position(runtime),
        )
        context_management = None
        if args.compact_threshold_tokens > 0:
            context_management = [{
                "type": "compaction",
                "compact_threshold": args.compact_threshold_tokens,
            }]
        tool_state = ToolInvocationState()
        agent = Agent(
            name="Verified IDA Reverse Engineer",
            model=args.model,
            model_settings=ModelSettings(
                reasoning=Reasoning(effort=args.reasoning_effort),
                include_usage=True,
                parallel_tool_calls=False,
                store=False,
                context_management=context_management,
            ),
            instructions=str(instructions["content"]),
            tools=_function_tools(adapter, trace, tool_state, segment_id),
        )
        def observe_investigator_response(event: Mapping[str, Any]) -> None:
            safety_budget.observe_response(event, phase=phase_state["value"])
            runtime.journal.heartbeat_run_attempt(
                attempt_id,
                phase=phase_state["value"],
                event_kind="model_response",
                response_id=str(event.get("response_id") or "") or None,
            )

        def observe_investigator_tool(event: Mapping[str, Any]) -> None:
            runtime.journal.heartbeat_run_attempt(
                attempt_id,
                phase=phase_state["value"],
                event_kind="tool_result",
                tool=str(event.get("tool") or "") or None,
            )

        hooks = _observable_hooks(
            trace,
            runtime,
            segment_id=segment_id,
            compact_threshold_tokens=args.compact_threshold_tokens,
            on_response_end=observe_investigator_response,
            on_tool_end=observe_investigator_tool,
            session=session,
        )
        outputs: list[str] = []
        continuation_limit = max(1, args.max_continuations + 1)
        if runtime.coverage_reconciliation_enabled:
            continuation_limit += max(1, args.reconciliation_max_continuations)
        for continuation in range(continuation_limit):
            tool_state.reset()
            try:
                safety_budget.check("primary_segment_start")
                result = Runner.run_sync(
                    agent,
                    prompt,
                    session=session,
                    run_config=model_run_config(session, trace, segment_id),
                    max_turns=max(2, args.max_agent_turns),
                    hooks=hooks,
                )
            except SafetyBudgetExceeded as exc:
                completion = runtime.completion_status()
                trace.append(
                    "safety_budget_exceeded",
                    segment_id=segment_id,
                    actor="harness",
                    continuation=continuation,
                    safety_budget=exc.snapshot,
                    **_runtime_position(runtime),
                )
                summary = _write_summary(
                    project_dir=project_dir,
                    trace=trace,
                    runtime=runtime,
                    status="safety_budget_exceeded",
                    args=args,
                    environment=environment,
                    segment_id=segment_id,
                    completion=completion,
                    final_output=outputs[-1] if outputs else "",
                    continuations=continuation,
                    prompt_provenance=prompt_provenance,
                    source_provenance=source_provenance,
                    attempt_id=attempt_id,
                    phase=phase_state["value"],
                )
                print(json.dumps(summary, indent=2, default=str))
                return 3
            except MaxTurnsExceeded as exc:
                status = runtime.completion_status()
                preparation = _prepare_resumed_session(
                    session,
                    project_dir=project_dir,
                    runtime=runtime,
                    trace=trace,
                    model=args.model,
                    objective=args.objective,
                    segment_id=segment_id,
                    prune_threshold_bytes=args.session_prune_bytes,
                    standalone_compact_max_bytes=args.standalone_compact_max_bytes,
                )
                trace.append(
                    "segment_turn_limit",
                    segment_id=segment_id,
                    actor="harness",
                    continuation=continuation,
                    error=str(exc),
                    completion=status,
                    session_preparation=preparation,
                    **_runtime_position(runtime),
                )
                prompt = (
                    "The SDK segment ended at its turn limit. Resume from the "
                    "persisted conversation and live IDA state. Resolve or "
                    "evidence-disposition these exact operational blockers, then "
                    "call complete_ida_investigation:\n"
                    + _json({"completion": status, "session": preparation})
                )
                continue
            outputs.append(str(getattr(result, "final_output", "") or ""))
            trace.append(
                "agent_output",
                segment_id=segment_id,
                actor="model",
                continuation=continuation,
                output=outputs[-1],
                **_runtime_position(runtime),
            )
            final, reused = _completion_after_agent(runtime, tool_state)
            if reused:
                trace.append(
                    "model_completion_reused",
                    segment_id=segment_id,
                    actor="harness",
                    continuation=continuation,
                    checkpoints=[
                        row.get("checkpoint_id")
                        for row in final.get("checkpoints", [])
                    ],
                    **_runtime_position(runtime),
                )
            if final["may_finish"] and runtime.coverage_reconciliation_enabled:
                from verified_ida.reconciliation import run_coverage_reconciliation

                phase_state["value"] = "coverage_reconciliation"
                runtime.journal.heartbeat_run_attempt(
                    attempt_id,
                    phase=phase_state["value"],
                    event_kind="coverage_reconciliation_started",
                )
                trace.append(
                    "coverage_reconciliation_started",
                    segment_id=segment_id,
                    actor="harness",
                    continuation=continuation,
                    **_runtime_position(runtime),
                )
                try:
                    safety_budget.check("coverage_reconciliation_start")
                    reconciliation = run_coverage_reconciliation(
                        runtime=runtime,
                        completion=final,
                        output_root=(
                            project_dir.parent
                            / (project_dir.name + "-coverage-reconciliation")
                        ),
                        model=args.model,
                        reasoning_effort=args.reasoning_effort,
                        environment=environment,
                        on_response_end=lambda event: (
                            safety_budget.observe_response(
                                event, phase="coverage_reconciliation"
                            ),
                            runtime.journal.heartbeat_run_attempt(
                                attempt_id,
                                phase="coverage_reconciliation",
                                event_kind="reviewer_response",
                                response_id=(
                                    str(event.get("response_id") or "") or None
                                ),
                            ),
                        ),
                        system_model_max_turns=max(
                            3, int(args.reconciliation_system_max_turns)
                        ),
                        artifact_coverage_max_turns=max(
                            3, int(args.reconciliation_artifact_max_turns)
                        ),
                        citation_repair_max_turns=max(
                            2, int(args.reconciliation_citation_repair_max_turns)
                        ),
                    )
                except Exception as exc:
                    latest_round = runtime.journal.latest_reconciliation_round()
                    if latest_round and latest_round["state"] == "collecting":
                        runtime.journal.fail_reconciliation_round(
                            str(latest_round["round_id"])
                        )
                    trace.append(
                        "coverage_reconciliation_failed",
                        segment_id=segment_id,
                        actor="harness",
                        continuation=continuation,
                        error={"type": type(exc).__name__, "message": str(exc)},
                        **_runtime_position(runtime),
                    )
                    if isinstance(exc, SafetyBudgetExceeded):
                        summary = _write_summary(
                            project_dir=project_dir,
                            trace=trace,
                            runtime=runtime,
                            status="safety_budget_exceeded",
                            args=args,
                            environment=environment,
                            segment_id=segment_id,
                            completion=runtime.completion_status(),
                            final_output=outputs[-1] if outputs else "",
                            continuations=continuation,
                            prompt_provenance=prompt_provenance,
                            source_provenance=source_provenance,
                            attempt_id=attempt_id,
                            phase=phase_state["value"],
                        )
                        print(json.dumps(summary, indent=2, default=str))
                        return 3
                    raise
                trace.append(
                    "coverage_reconciliation_completed",
                    segment_id=segment_id,
                    actor="harness",
                    continuation=continuation,
                    reconciliation=reconciliation,
                    **_runtime_position(runtime),
                )
                if reconciliation.get("open_count"):
                    phase_state["value"] = "reconciliation_application"
                    runtime.journal.heartbeat_run_attempt(
                        attempt_id,
                        phase=phase_state["value"],
                        event_kind="reconciliation_wave_ready",
                    )
                    prompt = (
                        "The initial investigation reached provisional completion. "
                        "An independent read-only coverage reconciliation found the "
                        "following fixed campaign and bounded current wave. Resume this "
                        "same investigation "
                        "and verify each finding against live IDA. Apply, reject, revise, "
                        "or defer every finding with current evidence; update the project "
                        "notebook when the system understanding changes. Open a call-flow "
                        "scope only when the finding names an exact decisive direct-call "
                        "boundary. Edits are restricted to the current finding's exact "
                        "targets. Preserve unrelated discoveries as advisory notebook "
                        "backlog; they cannot expand this campaign. The host will not run "
                        "another whole-project discovery review after this fixed finding "
                        "set is dispositioned. Then request completion again:\n"
                        + _json(reconciliation)
                    )
                    continue
                phase_state["value"] = "reconciliation_finalization"
                audit = runtime.finalize_reconciliation_audit(completion=final)
                reconciliation = runtime.journal.reconciliation_status()
                durable_audit = dict(
                    dict(reconciliation.get("resolution_audit") or {}).get(
                        "durable_audit"
                    ) or {}
                )
                if durable_audit.get("state") != "verified":
                    raise RuntimeError(
                        "Reconciliation final audit did not persist as verified"
                    )
                final = {
                    **final,
                    "coverage_reconciliation": reconciliation,
                    "reconciliation_final_audit": audit,
                    "completion_kind": "reconciliation_clear",
                }
            if final["may_finish"]:
                summary = _write_summary(
                    project_dir=project_dir,
                    trace=trace,
                    runtime=runtime,
                    status="completed",
                    args=args,
                    environment=environment,
                    segment_id=segment_id,
                    completion=final,
                    final_output=outputs[-1],
                    continuations=continuation,
                    prompt_provenance=prompt_provenance,
                    source_provenance=source_provenance,
                    attempt_id=attempt_id,
                    phase=phase_state["value"],
                )
                print(json.dumps(summary, indent=2, default=str))
                return 0
            prompt = (
                "You returned while the Verified IDA project still has these exact "
                "operational blockers. Continue the same investigation: repair or "
                "abandon failed operations, decide attempted recoveries, and "
                "evidence-disposition the listed must_review checks. Then call "
                "complete_ida_investigation again:\n"
                + _json(final)
            )
        completion = runtime.completion_status()
        summary = _write_summary(
            project_dir=project_dir,
            trace=trace,
            runtime=runtime,
            status="completion_policy_unsatisfied",
            args=args,
            environment=environment,
            segment_id=segment_id,
            completion=completion,
            final_output=outputs[-1] if outputs else "",
            continuations=continuation_limit,
            prompt_provenance=prompt_provenance,
            source_provenance=source_provenance,
            attempt_id=attempt_id,
            phase=phase_state["value"],
        )
        print(json.dumps(summary, indent=2, default=str))
        return 2
    except (Exception, KeyboardInterrupt) as exc:
        failure_state = locals().copy()
        summary = _write_failure_summary(exc, failure_state)
        print(json.dumps(summary, indent=2, default=str))
        return 4
    finally:
        if "prior_signal_handlers" in locals():
            for signum, handler in prior_signal_handlers.items():
                signal.signal(signum, handler)
        if "safety_budget" in locals():
            try:
                safety_budget.pause(
                    "controller_exit:%s"
                    % (
                        phase_state["value"]
                        if "phase_state" in locals() else "initialization"
                    )
                )
            except Exception:
                pass
        try:
            runtime.close()
        except Exception as cleanup_error:
            if "failure_state" not in locals():
                _write_failure_summary(cleanup_error, locals().copy())
                raise
            _write_json_atomic(project_dir / "cleanup_failure.json", {
                "type": type(cleanup_error).__name__, "message": str(cleanup_error),
                "original_failure": summary.get("error"),
            })


if __name__ == "__main__":
    raise SystemExit(main())
