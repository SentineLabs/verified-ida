"""
IDA Backend — Abstraction over idalib (library) vs idat (headless batch).

Supports three execution modes:
  - "idalib": IDA 9+ Python library mode (recommended)
  - "idat": Classic idat64 -A -S headless batch
  - "embedded": Running inside IDA GUI (IDAPython console/plugin)

Usage:
    from ida_backend import open_database, save_database, get_mode

    open_database("/path/to/binary")  # Auto-detects mode
    # ... use ida_* APIs ...
    save_database("/path/to/output.i64")
"""

import os
import sys


def detect_mode() -> str:
    """Detect which IDA execution mode we're running in.

    Returns:
        "idalib" | "idat" | "embedded"
    """
    # Check if we're inside IDA (GUI or idat)
    try:
        import idaapi
        # If idaapi is importable, we're either embedded or in idat
        if hasattr(idaapi, "get_kernel_version"):
            return "embedded"
    except ImportError:
        pass

    # Check if idalib is available
    try:
        import idalib
        return "idalib"
    except ImportError:
        pass

    # Check environment for explicit mode
    mode = os.environ.get("IDA_HEADLESS_MODE", "").lower()
    if mode in ("idalib", "idat", "embedded"):
        return mode

    return "idalib"  # Default to idalib for IDA 9+


_current_mode = None


def get_mode() -> str:
    """Get the current execution mode (cached)."""
    global _current_mode
    if _current_mode is None:
        _current_mode = detect_mode()
    return _current_mode


def open_database(path: str, auto_analysis: bool = True) -> None:
    """Open a binary or IDB database for analysis.

    In idalib mode: loads the file using idalib APIs.
    In embedded mode: assumes database is already open.

    Args:
        path: Path to binary or .idb/.i64 file
        auto_analysis: Wait for auto-analysis to complete (default True)
    """
    mode = get_mode()

    if mode == "embedded":
        # Already inside IDA, database should be open
        if auto_analysis:
            import ida_auto
            ida_auto.auto_wait()
        return

    if mode == "idalib":
        import idalib

        # Determine if this is an existing database or a new binary
        if path.endswith((".idb", ".i64")):
            idalib.open_database(path, run_auto_analysis=auto_analysis)
        else:
            idalib.open_database(path, run_auto_analysis=auto_analysis)
        return

    raise RuntimeError(
        f"Cannot open database in mode '{mode}'. "
        "Use idalib or run inside IDA."
    )


def save_database(path: str = None) -> None:
    """Save the current IDA database.

    Args:
        path: Output path. If None, saves to current IDB path.
    """
    import idc

    if path is None:
        path = idc.get_idb_path()

    idc.save_database(path)


def close_database() -> None:
    """Close the current database (idalib mode only)."""
    mode = get_mode()
    if mode == "idalib":
        try:
            import idalib
            idalib.close_database()
        except (ImportError, AttributeError):
            pass


def get_ida_version() -> str:
    """Get the IDA Pro version string."""
    try:
        import idaapi
        return idaapi.get_kernel_version()
    except (ImportError, AttributeError):
        return "unknown"
