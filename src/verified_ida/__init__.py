"""Verified IDA contracts and compact stateful runtime."""

from .contracts import (
    VERIFIED_STATUSES,
    ContractError,
    build_receipt,
    operation_digest,
    summarize_receipts,
    validate_operation,
)
from .journal import JournalError, VerifiedIdaJournal
from .runtime import VerifiedIdaRuntime
from .version import __version__

__all__ = [
    "VERIFIED_STATUSES",
    "ContractError",
    "JournalError",
    "VerifiedIdaJournal",
    "VerifiedIdaRuntime",
    "build_receipt",
    "operation_digest",
    "summarize_receipts",
    "validate_operation",
    "__version__",
]
