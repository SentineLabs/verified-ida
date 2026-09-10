"""Measured backend limits, not guesses about untested IDA releases."""


def function_comment_limits(ida_version, native_maxstr):
    # Native 9.3 round-trip probe: 1024 ASCII/UTF-8 bytes per line survive;
    # 1025 do not. Two 800-byte lines survive. Both function-comment slots.
    verified = str(ida_version) == "9.3" and native_maxstr == 1024
    return {
        "status": "measured" if verified else "unmeasured",
        "ida_version": ida_version,
        "native_maxstr": native_maxstr,
        "max_utf8_bytes_per_line": 1024 if verified else None,
        "total_comment_limit": None,
        "applies_to": ["function.comment.set"],
        "recovery": "Split long lines with line breaks; do not silently truncate analytical content.",
    }


def validate_function_comment(text, limits):
    maximum = limits.get("max_utf8_bytes_per_line")
    if maximum is not None:
        for index, line in enumerate(text.splitlines(), 1):
            size = len(line.encode("utf-8"))
            if size > maximum:
                raise ValueError(
                    "Function comment line %d is %d UTF-8 bytes; this backend preserves at most %d per line. "
                    "Split the line with line breaks and retry; no text was truncated."
                    % (index, size, maximum)
                )
