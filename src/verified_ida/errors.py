"""Safe transport representation of known, actionable host contract failures."""

from __future__ import annotations

from typing import Any

from .contracts import ContractError
from .query_contract import QueryContractError


class OperationError(ValueError):
    def __init__(
        self, message: str, *, code: str = "operation_contract",
        recovery: str = "Re-inspect the target and retry only the failed operation.",
        details: dict[str, Any] | None = None,
    ):
        super().__init__(message)
        self.code = code
        self.recovery = recovery
        self.details = details or {}


def tool_error(exc: Exception) -> dict[str, Any]:
    result: dict[str, Any] = {
        "type": type(exc).__name__,
        "message": str(exc),
        "recovery": "Re-inspect live state and retry only the failed operation.",
    }
    if isinstance(exc, (ContractError, QueryContractError)):
        result.update(exc.as_dict())
    if isinstance(exc, OperationError):
        result.update(code=exc.code, recovery=exc.recovery, details=exc.details)
    if isinstance(exc, ContractError):
        result["recovery"] = (
            "Correct the reported field using describe_ida_capabilities; "
            "only resubmit the rejected operation."
        )
    return result
