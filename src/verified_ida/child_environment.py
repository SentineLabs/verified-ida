"""Explicit launcher configuration; never forward controller credentials."""

from __future__ import annotations

import os


def child_environment() -> dict[str, str]:
    """Allow only runtime paths/settings needed by isolated analysis tools."""
    allowed = (
        "HOME", "IDA_PATH", "IDA_IDAT", "IDA_LICENSE_FILE", "IDA_REG_FILE",
        "STATIC_EXTRACTOR_PYTHON", "STATIC_EXTRACTOR_TIMEOUT_SECONDS",
        "STATIC_EXTRACTOR_MEMORY_KB", "READONLY_IDA_TIMEOUT_SECONDS",
    )
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
            **{name: os.environ[name] for name in allowed if name in os.environ}}
