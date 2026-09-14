"""One durable allowance across all stages of an independent review command."""

from __future__ import annotations

from contextvars import ContextVar
import json
from pathlib import Path
from typing import Any, Callable

from .project_lock import ProjectLock
from .safety_budget import RunSafetyBudget, SafetyBudgetExceeded


ACTIVE_REVIEW_BUDGET: ContextVar[RunSafetyBudget | None] = ContextVar(
    "verified_ida_independent_review_budget", default=None
)
DEFAULT_LIMITS = {
    "max_total_tokens": 250_000_000,
    "max_requests": 2500,
    "max_elapsed_seconds": 14_400,
}


def add_review_budget_arguments(parser: Any) -> None:
    for key, default in DEFAULT_LIMITS.items():
        parser.add_argument(
            "--" + key.replace("_", "-"), type=int, default=None,
            help=(
                "Whole independent-review allowance; default %s. "
                "Finalization retains the stored allowance. Zero disables this limit."
            ) % default,
        )


def run_budgeted_review(
    arguments: Any, action: Callable[[Any], int], *, resume: bool = False,
) -> int:
    """Wrap CLI lifecycle, not semantic policy. Retries do not reset usage."""
    run_dir = arguments.run_dir.expanduser().resolve()
    if resume:
        if not run_dir.is_dir():
            raise RuntimeError("Review run directory does not exist: %s" % run_dir)
    else:
        # Atomic creation also prevents concurrent new invocations.
        run_dir.mkdir(parents=True, exist_ok=False)
    lock = ProjectLock(run_dir)
    budget = None
    context_token = None
    try:
        path = run_dir / "review_safety_budget.json"
        if resume and not path.is_file():
            raise RuntimeError(
                "Historical review has no aggregate budget ledger. Start a new "
                "explicitly budgeted review; do not silently reset usage."
            )
        stored = json.loads(path.read_text())["limits"] if path.is_file() else DEFAULT_LIMITS
        limits = {}
        for key in DEFAULT_LIMITS:
            requested = getattr(arguments, key, None)
            limits[key] = stored[key] if requested is None else requested
            if limits[key] < 0:
                raise ValueError("Safety limits cannot be negative: %s" % key)
        budget = RunSafetyBudget(path, **limits)
        context_token = ACTIVE_REVIEW_BUDGET.set(budget)
        budget.check("review_controller_start")
        return action(arguments)
    except Exception as exc:
        cause: BaseException | None = exc
        while cause is not None and not isinstance(cause, SafetyBudgetExceeded):
            cause = cause.__cause__ or cause.__context__
        if not isinstance(cause, SafetyBudgetExceeded):
            raise
        stop = {
            "status": "stopped_budget", "analytical_completion": False,
            "safety_budget": cause.snapshot,
            "outstanding_work": "Retained in the review reports and disposition ledger.",
        }
        (run_dir / "review_budget_stop.json").write_text(json.dumps(stop, indent=2) + "\n")
        print(json.dumps(stop, indent=2))
        return 2
    finally:
        if context_token is not None:
            ACTIVE_REVIEW_BUDGET.reset(context_token)
        try:
            if budget is not None:
                budget.pause("review_controller_exit")
        finally:
            lock.close()
