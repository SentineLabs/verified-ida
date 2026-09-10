"""Durable whole-campaign safety accounting for model responses."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Callable, Mapping


class SafetyBudgetExceeded(RuntimeError):
    """Raised after persisting the exact whole-campaign limit that was crossed."""

    def __init__(self, snapshot: Mapping[str, Any]):
        self.snapshot = dict(snapshot)
        super().__init__(
            "Verified IDA safety budget exceeded: %s"
            % self.snapshot.get("exceeded_reason")
        )


class RunSafetyBudget:
    """Count investigator and reviewer responses against the same limits."""

    SCHEMA = "verified_ida.run_safety_budget.v2"
    LEGACY_SCHEMA = "verified_ida.run_safety_budget.v1"

    def __init__(
        self,
        path: str | Path,
        *,
        max_total_tokens: int,
        max_requests: int,
        max_elapsed_seconds: int,
        clock: Callable[[], float] = time.time,
    ):
        self.path = Path(path)
        self._clock = clock
        now = float(self._clock())
        limits = {
            "max_total_tokens": max(0, int(max_total_tokens)),
            "max_requests": max(0, int(max_requests)),
            "max_elapsed_seconds": max(0, int(max_elapsed_seconds)),
        }
        if self.path.is_file():
            state = json.loads(self.path.read_text(encoding="utf-8"))
            if state.get("schema") not in {self.SCHEMA, self.LEGACY_SCHEMA}:
                raise RuntimeError("Unsupported safety-budget state")
            if dict(state.get("limits") or {}) != limits:
                raise RuntimeError(
                    "A resumed investigation must retain its original safety limits"
                )
            if state.get("schema") == self.LEGACY_SCHEMA:
                last_write = min(now, float(self.path.stat().st_mtime))
                started = float(state.get("started_epoch") or last_write)
                state = {
                    **state,
                    "schema": self.SCHEMA,
                    "active_elapsed_seconds": max(0.0, last_write - started),
                    "migration": {
                        "from_schema": self.LEGACY_SCHEMA,
                        "basis": "last_budget_write_minus_started_epoch",
                    },
                }
            self.state = state
            self.state["active_session_started_epoch"] = now
            self.state["last_accounted_epoch"] = now
            self._write()
        else:
            self.state = {
                "schema": self.SCHEMA,
                "started_epoch": now,
                "active_session_started_epoch": now,
                "last_accounted_epoch": now,
                "active_elapsed_seconds": 0.0,
                "limits": limits,
                "usage": {
                    "requests": 0,
                    "input_tokens": 0,
                    "cached_input_tokens": 0,
                    "output_tokens": 0,
                    "reasoning_output_tokens": 0,
                    "total_tokens": 0,
                },
                "exceeded": False,
                "exceeded_reason": None,
                "last_phase": "initialized",
            }
            self._write()

    def _accrue_active_time(self) -> None:
        now = float(self._clock())
        prior = self.state.get("last_accounted_epoch")
        if prior is not None:
            self.state["active_elapsed_seconds"] = float(
                self.state.get("active_elapsed_seconds") or 0.0
            ) + max(0.0, now - float(prior))
        self.state["last_accounted_epoch"] = now

    def _write(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(
            json.dumps(self.state, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.path)

    def snapshot(self) -> dict[str, Any]:
        result = json.loads(json.dumps(self.state))
        result["elapsed_seconds"] = max(
            0.0, float(self.state.get("active_elapsed_seconds") or 0.0)
        )
        result["elapsed_accounting"] = "active_controller_time"
        return result

    def _reason(self) -> str | None:
        snapshot = self.snapshot()
        limits = snapshot["limits"]
        usage = snapshot["usage"]
        checks = (
            ("total_tokens", limits["max_total_tokens"], usage["total_tokens"]),
            ("requests", limits["max_requests"], usage["requests"]),
            (
                "elapsed_seconds",
                limits["max_elapsed_seconds"],
                snapshot["elapsed_seconds"],
            ),
        )
        for name, limit, observed in checks:
            if int(limit) > 0 and float(observed) >= int(limit):
                return "%s=%s reached limit=%s" % (name, observed, limit)
        return None

    def check(self, phase: str) -> dict[str, Any]:
        self._accrue_active_time()
        self.state["last_phase"] = str(phase)
        reason = self._reason()
        if reason:
            self.state["exceeded"] = True
            self.state["exceeded_reason"] = reason
            self._write()
            raise SafetyBudgetExceeded(self.snapshot())
        self._write()
        return self.snapshot()

    def pause(self, phase: str = "controller_paused") -> dict[str, Any]:
        """Close the active-time interval without resetting cumulative usage."""

        self._accrue_active_time()
        self.state["last_phase"] = str(phase)
        self.state["last_accounted_epoch"] = None
        self._write()
        return self.snapshot()

    def observe_response(self, event: Mapping[str, Any], *, phase: str) -> None:
        usage = dict(event.get("usage") or {})
        accumulated = self.state["usage"]
        for key in accumulated:
            value = int(usage.get(key) or 0)
            if key == "requests" and value <= 0:
                value = 1
            accumulated[key] += value
        self.check(phase)
