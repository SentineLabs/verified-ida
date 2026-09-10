"""Small, deterministic Unicorn runner for localized RE questions."""

from __future__ import annotations

from typing import Any


MAX_CODE_BYTES = 4096
MAX_MEMORY_BYTES = 1024 * 1024
MAX_INSTRUCTIONS = 100_000
PAGE_SIZE = 0x1000


def _align_down(value: int) -> int:
    return value & ~(PAGE_SIZE - 1)


def _align_up(value: int) -> int:
    return (value + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1)


def _parse_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    return int(str(value), 0)


def emulate_x86(payload: dict[str, Any], code: bytes) -> dict[str, Any]:
    try:
        from unicorn import (  # type: ignore
            Uc,
            UC_ARCH_X86,
            UC_HOOK_CODE,
            UC_HOOK_MEM_INVALID,
            UC_MEM_READ_UNMAPPED,
            UC_MEM_WRITE_UNMAPPED,
            UC_MODE_32,
            UC_MODE_64,
        )
        from unicorn import x86_const  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "bounded emulation requires the optional unicorn package"
        ) from exc

    if not code or len(code) > MAX_CODE_BYTES:
        raise ValueError("code must contain 1..%d bytes" % MAX_CODE_BYTES)
    mode_name = str(payload.get("mode") or "").lower()
    if mode_name not in {"x86_32", "x86_64"}:
        raise ValueError("mode must be x86_32 or x86_64")
    mode = UC_MODE_64 if mode_name == "x86_64" else UC_MODE_32
    base = _parse_int(payload.get("base"))
    start = _parse_int(payload.get("start", base))
    instruction_limit = min(
        max(1, int(payload.get("instruction_limit") or 10_000)),
        MAX_INSTRUCTIONS,
    )

    register_names = (
        ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "rip")
        if mode_name == "x86_64"
        else ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")
    )
    register_map = {
        name: getattr(x86_const, "UC_X86_REG_%s" % name.upper())
        for name in register_names
    }
    uc = Uc(UC_ARCH_X86, mode)
    mapped: list[tuple[int, int]] = []

    def map_region(address: int, size: int) -> None:
        region_start = _align_down(address)
        region_end = _align_up(address + size)
        for existing_start, existing_end in mapped:
            if region_start >= existing_start and region_end <= existing_end:
                return
            if max(region_start, existing_start) < min(region_end, existing_end):
                raise ValueError("overlapping emulation mappings are not supported")
        uc.mem_map(region_start, region_end - region_start)
        mapped.append((region_start, region_end))

    map_region(base, len(code))
    uc.mem_write(base, code)
    total_memory = _align_up(len(code))
    for row in payload.get("memory") or []:
        if not isinstance(row, dict):
            raise ValueError("memory rows must be objects")
        address = _parse_int(row.get("address"))
        data_hex = str(row.get("data_hex") or "")
        data = bytes.fromhex(data_hex) if data_hex else b""
        size = max(len(data), int(row.get("size") or 0))
        if size <= 0:
            raise ValueError("memory mapping requires size or data_hex")
        total_memory += _align_up(size)
        if total_memory > MAX_MEMORY_BYTES:
            raise ValueError("emulation memory exceeds %d bytes" % MAX_MEMORY_BYTES)
        map_region(address, size)
        if data:
            uc.mem_write(address, data)

    for name, value in (payload.get("registers") or {}).items():
        normalized = str(name).lower()
        if normalized not in register_map:
            raise ValueError("unsupported register %r" % name)
        uc.reg_write(register_map[normalized], _parse_int(value))

    trace: list[str] = []
    invalid_memory: list[dict[str, Any]] = []

    def on_code(_uc: Any, address: int, _size: int, _user: Any) -> None:
        if len(trace) < 4096:
            trace.append(hex(address))

    def on_invalid(
        _uc: Any,
        access: int,
        address: int,
        size: int,
        value: int,
        _user: Any,
    ) -> bool:
        invalid_memory.append(
            {
                "access": (
                    "read_unmapped"
                    if access == UC_MEM_READ_UNMAPPED
                    else "write_unmapped"
                    if access == UC_MEM_WRITE_UNMAPPED
                    else str(access)
                ),
                "address": hex(address),
                "size": size,
                "value": hex(value),
            }
        )
        return False

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_INVALID, on_invalid)
    stopped = "completed"
    error = None
    end = _parse_int(payload.get("end", base + len(code)))
    try:
        uc.emu_start(start, end, count=instruction_limit)
    except Exception as exc:
        stopped = "emulation_error"
        error = "%s: %s" % (type(exc).__name__, exc)

    registers = {
        name: hex(uc.reg_read(register_id))
        for name, register_id in register_map.items()
    }
    readback = []
    for row in payload.get("readback") or []:
        if not isinstance(row, dict):
            raise ValueError("readback rows must be objects")
        address = _parse_int(row.get("address"))
        size = int(row.get("size") or 0)
        if size <= 0 or size > MAX_MEMORY_BYTES:
            raise ValueError("readback size must be 1..%d bytes" % MAX_MEMORY_BYTES)
        try:
            data = bytes(uc.mem_read(address, size))
        except Exception as exc:
            raise ValueError("readback region is not mapped: %s" % exc) from None
        readback.append({
            "address": hex(address),
            "size": size,
            "data_hex": data.hex(),
        })
    return {
        "ok": stopped == "completed",
        "mode": mode_name,
        "base": hex(base),
        "start": hex(start),
        "end": hex(end),
        "instruction_limit": instruction_limit,
        "executed_instruction_count": len(trace),
        "trace": trace,
        "trace_truncated": len(trace) >= 4096,
        "registers": registers,
        "invalid_memory": invalid_memory,
        "readback": readback,
        "stopped": stopped,
        "error": error,
    }
