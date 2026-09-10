"""Safe, bounded recovery of model-identified child binary artifacts."""

from __future__ import annotations

import base64
import binascii
import bz2
import gzip
import hashlib
import json
import lzma
import re
import shutil
import struct
import sys
import zlib
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from pe_inventory import build_pe_inventory


REQUEST_SCHEMA = "ida_harness.binary_components.semantic_request.v2"
RESULT_SCHEMA = "ida_harness.binary_components.extraction_result.v2"
REVIEW_SCHEMA = "ida_harness.binary_components.semantic_review.v1"
DISCOVERY_MODES = (
    "model_led_baseline",
    "soft_reinforcement",
    "operational_assisted",
)
EXTRACTION_METHODS = (
    "copy",
    "raw",
    "xor",
    "zlib",
    "gzip",
    "bz2",
    "lzma",
    "base64",
    "hex",
    "bounded_emulation",
    "python_static",
)
ARTIFACT_KINDS = (
    "pe",
    "elf",
    "macho",
    "shellcode",
    "archive",
    "script",
    "bytecode",
    "config",
    "data",
)
MAX_SOURCE_BYTES = 64 * 1024 * 1024
MAX_OUTPUT_BYTES = 64 * 1024 * 1024


def recovery_capability_manifest() -> dict[str, Any]:
    """Describe the bounded recovery contract without requiring a failed call."""

    from ctypes.util import find_library
    from static_extractor_script import APPROVED_MEMBERS
    static_available = (sys.platform.startswith("linux") and bool(shutil.which("bwrap"))
                        and bool(find_library("seccomp")))
    return {
        "schema": "verified_ida.component_recovery.capabilities.v1",
        "supported_methods": list(EXTRACTION_METHODS),
        "limits": {
            "source_regions": 16,
            "source_bytes": MAX_SOURCE_BYTES,
            "output_bytes": MAX_OUTPUT_BYTES,
            "static_additional_inputs": 15,
        },
        "methods": {
            "copy": {
                "purpose": "Concatenate one or more parent byte ranges in declared order.",
                "required_extraction_fields": ["method"],
                "optional_extraction_fields": [],
                "executes_model_code": False,
            },
            "raw": {
                "purpose": "Legacy single- or multi-range identity copy; copy is preferred.",
                "required_extraction_fields": ["method"],
                "optional_extraction_fields": ["parameters.strip_prefix"],
                "executes_model_code": False,
            },
            "xor": {
                "purpose": "XOR source bytes with a repeated key.",
                "required_extraction_fields": ["method", "parameters.key_hex"],
                "optional_extraction_fields": ["parameters.key_phase", "parameters.strip_prefix"],
                "executes_model_code": False,
            },
            **{
                method: {
                    "purpose": "Bounded built-in %s decompression." % method,
                    "required_extraction_fields": ["method"],
                    "optional_extraction_fields": ["parameters.strip_prefix"],
                    "executes_model_code": False,
                }
                for method in ("zlib", "gzip", "bz2", "lzma")
            },
            **{
                method: {
                    "purpose": "Decode one %s-encoded source range." % method,
                    "required_extraction_fields": ["method"],
                    "optional_extraction_fields": ["parameters.strip_prefix"],
                    "executes_model_code": False,
                }
                for method in ("base64", "hex")
            },
            "bounded_emulation": {
                "purpose": "Emulate a bounded decoder only when a direct transform is insufficient.",
                "required_extraction_fields": [
                    "method", "parameters.code_hex", "parameters.decoder_ea",
                    "parameters.source_address", "parameters.output_address",
                    "parameters.output_size",
                ],
                "optional_extraction_fields": [
                    "parameters.mode", "parameters.start", "parameters.end",
                    "parameters.instruction_limit", "parameters.registers",
                    "parameters.memory",
                ],
                "executes_model_code": False,
                "executes_recovered_malware": "bounded_decoder_in_emulator_only",
            },
            "python_static": {
                "purpose": "Apply a genuine bounded static byte transform after built-in methods are insufficient.",
                "required_extraction_fields": ["method", "script_path"],
                "optional_extraction_fields": ["parameters", "inputs"],
                "input_contract": (
                    "The primary locator bytes are inputs['source']; additional named "
                    "inputs come from extraction.inputs; parameters is the submitted object; "
                    "the script must assign bytes or bytearray to artifact."
                ),
                "executes_model_code": True,
                "malware_execution_allowed": False,
                "available": static_available,
                "host_requirement": "Linux with bubblewrap (bwrap) and libseccomp.so.2",
                "approved_members": {name: members.split() for name, members in APPROVED_MEMBERS.items()},
                "execution_policy": "In-memory byte transforms only; kernel denies file opening, networking, process creation, and executable mappings.",
            },
        },
        "available_methods": [
            method
            for method in EXTRACTION_METHODS
            if method != "python_static" or static_available
        ],
        "copy_example": {
            "parent_component_id": "root",
            "locators": [{"kind": "idb_ea", "ea": "0x140010000", "size": 4096}],
            "extraction": {"method": "copy"},
            "expected_result": {"artifact_kind": "pe", "architecture": "x86_64"},
            "loader_decoder": {
                "function_ea": "0x140001000",
                "summary": "Observed direct copy into the child image buffer.",
            },
            "evidence_refs": ["evidence-..."],
        },
        "decision_boundary": (
            "The host validates bytes and loadability; the model must separately accept, "
            "revise, reject, or defer the artifact's semantic role."
        ),
    }


class ExtractionFailure(ValueError):
    """An actionable, model-facing extraction failure."""

    def __init__(
        self,
        stage: str,
        reason: str,
        *,
        code: str | None = None,
        **details: Any,
    ):
        super().__init__(reason)
        self.stage = stage
        self.reason = reason
        self.code = code or "%s_failed" % stage
        self.details = details

    def result(self, *, request_id: str) -> dict[str, Any]:
        return {
            "schema": RESULT_SCHEMA,
            "status": "extraction_failed",
            "request_id": request_id,
            "stage": self.stage,
            "code": self.code,
            "reason": self.reason,
            **self.details,
        }


def _parse_int(value: Any, *, field: str, minimum: int = 0) -> int:
    try:
        parsed = int(str(value), 0)
    except (TypeError, ValueError):
        raise ValueError("%s is invalid" % field) from None
    if parsed < minimum:
        raise ValueError("%s must be at least %d" % (field, minimum))
    return parsed


def _optional_size(value: Any, *, field: str) -> int | None:
    if value in (None, ""):
        return None
    parsed = _parse_int(value, field=field, minimum=1)
    if parsed > MAX_SOURCE_BYTES:
        raise ValueError("%s exceeds the %d-byte safety limit" % (field, MAX_SOURCE_BYTES))
    return parsed


def _stable_request_id(payload: Mapping[str, Any]) -> str:
    identity = {
        key: value
        for key, value in payload.items()
        if key not in {"request_id", "schema"}
    }
    encoded = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "extraction:%s" % hashlib.sha256(encoded).hexdigest()[:20]


def _normalize_evidence_refs(values: Any) -> list[Any]:
    """Preserve structured model evidence while dropping empty references."""
    refs: list[Any] = []
    for value in values or []:
        if isinstance(value, Mapping):
            normalized = {
                str(key): item
                for key, item in value.items()
                if item not in (None, "", [], {})
            }
            if normalized:
                refs.append(normalized)
            continue
        text = str(value).strip()
        if text:
            refs.append(text)
    return refs


def _normalize_script_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if (
        not text
        or path.is_absolute()
        or ".." in path.parts
        or path.suffix.lower() != ".py"
    ):
        raise ValueError("python_static requires a relative extraction.script_path ending in .py")
    return str(path)


def _normalize_static_inputs(values: Any) -> list[dict[str, Any]]:
    if values in (None, []):
        return []
    if not isinstance(values, list) or len(values) > 15:
        raise ValueError("python_static extraction.inputs must contain at most 15 records")
    normalized = []
    names = {"source"}
    for raw in values:
        if not isinstance(raw, Mapping):
            raise ValueError("python_static extraction inputs must be JSON objects")
        name = str(raw.get("name") or "").strip()
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) or name in names:
            raise ValueError("python_static input names must be unique identifiers other than source")
        locator = raw.get("locator") or raw
        if not isinstance(locator, Mapping):
            raise ValueError("python_static input requires a locator")
        kind = str(locator.get("kind") or "").strip().lower()
        if kind not in {"idb_ea", "file_offset"}:
            raise ValueError("python_static input locator kind must be idb_ea or file_offset")
        raw_location = locator.get("ea" if kind == "idb_ea" else "file_offset")
        if raw_location in (None, ""):
            raw_location = locator.get("ea_or_file_offset")
        if raw_location in (None, ""):
            raw_location = locator.get("value")
        location = _parse_int(raw_location, field="python_static input locator", minimum=0)
        size = _optional_size(
            raw.get("source_size") or locator.get("size"),
            field="python_static input size",
        )
        normalized.append({
            "name": name,
            "locator": {
                "kind": kind,
                ("ea" if kind == "idb_ea" else "file_offset"): hex(location),
                "size": size,
            },
        })
        names.add(name)
    return normalized


def normalize_semantic_request(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize semantic model evidence while generating host bookkeeping."""
    if not isinstance(payload, Mapping):
        raise ValueError("component request must be one JSON object")
    parent_component_id = str(payload.get("parent_component_id") or "root").strip().lower()
    if parent_component_id != "root" and not re.fullmatch(
        r"component-[0-9a-f]{16}", parent_component_id
    ):
        raise ValueError("invalid parent_component_id")

    locators = payload.get("locators")
    if locators is not None:
        if not isinstance(locators, list) or not 1 <= len(locators) <= 16:
            raise ValueError("locators must contain 1..16 source regions")
        locator = locators[0]
    else:
        locator = payload.get("locator")
    if not isinstance(locator, Mapping):
        raise ValueError("semantic component request requires locator")
    locator_kind = str(locator.get("kind") or "").strip().lower()
    if locator_kind not in {"idb_ea", "file_offset"}:
        raise ValueError("locator kind must be idb_ea or file_offset")
    raw_location = (
        locator.get("ea")
        if locator_kind == "idb_ea"
        else locator.get("file_offset")
    )
    if raw_location in (None, ""):
        raw_location = locator.get("ea_or_file_offset")
    if raw_location in (None, ""):
        raw_location = locator.get("value")
    location = _parse_int(
        raw_location,
        field="locator %s" % locator_kind,
        minimum=0,
    )
    locator_size = _optional_size(locator.get("size"), field="locator size")

    extraction = payload.get("extraction") or payload.get("transform") or {}
    if isinstance(extraction, str):
        extraction = {"method": extraction}
    if not isinstance(extraction, Mapping):
        raise ValueError("extraction must be one JSON object")
    method = str(extraction.get("method") or "raw").strip().lower()
    if method not in EXTRACTION_METHODS:
        raise ValueError("unsupported extraction method: %s" % method)
    source_size = _optional_size(
        extraction.get("source_size") or locator_size,
        field="extraction source_size",
    )
    parameters = extraction.get("parameters") or {}
    if not isinstance(parameters, Mapping):
        raise ValueError("extraction parameters must be one JSON object")
    if method == "copy" and parameters:
        raise ValueError(
            "copy extraction does not accept parameters; use a transform method instead"
        )
    if method != "python_static" and (
        extraction.get("script_path")
        or extraction.get("script")
        or extraction.get("inputs")
    ):
        raise ValueError(
            "script_path and inputs are only valid for python_static extraction"
        )
    script_path = None
    static_inputs: list[dict[str, Any]] = []
    if method == "python_static":
        script_path = _normalize_script_path(
            extraction.get("script_path") or extraction.get("script")
        )
        static_inputs = _normalize_static_inputs(extraction.get("inputs"))

    expected = payload.get("expected_result") or {}
    if isinstance(expected, str):
        expected = {"artifact_kind": expected}
    if not isinstance(expected, Mapping):
        raise ValueError("expected_result must be text or one JSON object")
    artifact_kind = str(
        expected.get("artifact_kind") or expected.get("format") or "pe"
    ).strip().lower()
    if artifact_kind not in ARTIFACT_KINDS:
        raise ValueError(
            "expected artifact_kind must be one of %s" % ", ".join(ARTIFACT_KINDS)
        )
    base_address = expected.get("base_address")
    normalized_base = (
        hex(_parse_int(base_address, field="expected base_address"))
        if base_address not in (None, "") else None
    )
    entry_offset = expected.get("entry_offset")
    normalized_entry = (
        hex(_parse_int(entry_offset, field="expected entry_offset"))
        if entry_offset not in (None, "") else None
    )

    evidence_refs = _normalize_evidence_refs(payload.get("evidence_refs"))
    if not evidence_refs:
        raise ValueError("semantic component request requires evidence_refs")
    loader = payload.get("loader_decoder") or {}
    if not isinstance(loader, Mapping):
        raise ValueError("loader_decoder must be one JSON object")
    loader_summary = str(loader.get("summary") or "").strip()
    loader_ea = str(loader.get("function_ea") or loader.get("ea") or "").strip()
    if not loader_summary or not loader_ea:
        raise ValueError(
            "loader_decoder requires function_ea and an evidence-based summary"
        )

    request_id = str(payload.get("request_id") or "").strip()
    if request_id and not re.fullmatch(r"[A-Za-z0-9_.:-]{1,160}", request_id):
        raise ValueError("component request_id is invalid")
    normalized = {
        "schema": REQUEST_SCHEMA,
        "request_id": request_id,
        "parent_component_id": parent_component_id,
        "locator": {
            "kind": locator_kind,
            ("ea" if locator_kind == "idb_ea" else "file_offset"): hex(location),
            "size": source_size,
        },
        "extraction": {
            "method": method,
            "source_size": source_size,
            "parameters": dict(parameters),
            **({"script_path": script_path, "inputs": static_inputs}
               if method == "python_static" else {}),
        },
        "expected_result": {
            "artifact_kind": artifact_kind,
            "architecture": str(expected.get("architecture") or "").strip().lower() or None,
            "description": str(expected.get("description") or "").strip(),
            "base_address": normalized_base,
            "entry_offset": normalized_entry,
        },
        "loader_decoder": {
            "function_ea": loader_ea,
            "summary": loader_summary,
            "evidence_refs": _normalize_evidence_refs(loader.get("evidence_refs")),
        },
        "evidence_refs": evidence_refs,
        "reason": str(payload.get("reason") or "").strip(),
        "priority": str(payload.get("priority") or "high").strip().lower(),
        "revises_request_id": str(payload.get("revises_request_id") or "").strip() or None,
    }
    if locators is not None:
        normalized_regions = []
        for index, raw_locator in enumerate(locators):
            if not isinstance(raw_locator, Mapping):
                raise ValueError("locators[%d] must be an object" % index)
            region_kind = str(raw_locator.get("kind") or "").strip().lower()
            if region_kind not in {"idb_ea", "file_offset"}:
                raise ValueError("locators[%d] kind is invalid" % index)
            field = "ea" if region_kind == "idb_ea" else "file_offset"
            location_value = raw_locator.get(field)
            if location_value in (None, ""):
                location_value = raw_locator.get("value")
            region_size = _optional_size(
                raw_locator.get("size"), field="locators[%d] size" % index
            )
            if region_size is None:
                raise ValueError("each multi-range locator requires size")
            normalized_regions.append({
                "kind": region_kind,
                field: hex(_parse_int(
                    location_value,
                    field="locators[%d] %s" % (index, field),
                    minimum=0,
                )),
                "size": region_size,
            })
        normalized["source_regions"] = normalized_regions
    normalized["request_id"] = request_id or _stable_request_id(normalized)
    return normalized


def _rva_to_file_offset(inventory: Mapping[str, Any], rva: int) -> tuple[int, int]:
    for section in inventory.get("sections") or []:
        virtual_address = int(str(section.get("virtual_address") or "0"), 0)
        virtual_size = int(section.get("virtual_size") or 0)
        raw_size = int(section.get("raw_size") or 0)
        raw_ptr = int(str(section.get("raw_ptr") or "0"), 0)
        if virtual_address <= rva < virtual_address + max(virtual_size, raw_size):
            delta = rva - virtual_address
            if delta >= raw_size:
                raise ExtractionFailure(
                    "source_resolution",
                    "IDB address maps to virtual data not present in the file",
                    rva=hex(rva),
                    section=section.get("name"),
                )
            return raw_ptr + delta, raw_size - delta
    raise ExtractionFailure(
        "source_resolution",
        "IDB address does not map to a file-backed PE section",
        rva=hex(rva),
    )


def resolve_source_region(
    parent_path: Path,
    request: Mapping[str, Any],
    *,
    require_exact_size: bool = False,
) -> tuple[bytes, dict[str, Any]]:
    data = parent_path.read_bytes()
    locator = request["locator"]
    kind = locator["kind"]
    available = len(data)
    if kind == "file_offset":
        offset = int(locator["file_offset"], 0)
        available = len(data) - offset
        resolved_from = {"kind": "file_offset", "file_offset": hex(offset)}
    else:
        ea = int(locator["ea"], 0)
        inventory = build_pe_inventory(parent_path)
        if not inventory.get("is_pe"):
            raise ExtractionFailure(
                "source_resolution",
                "IDB EA resolution requires a PE parent",
            )
        image_base = int(str(inventory.get("image_base") or "0"), 0)
        if ea < image_base:
            raise ExtractionFailure(
                "source_resolution",
                "IDB address precedes the parent image base",
                ea=hex(ea),
                image_base=hex(image_base),
            )
        offset, available = _rva_to_file_offset(inventory, ea - image_base)
        resolved_from = {
            "kind": "idb_ea",
            "ea": hex(ea),
            "image_base": hex(image_base),
            "file_offset": hex(offset),
        }
    if offset < 0 or offset >= len(data):
        raise ExtractionFailure(
            "source_resolution",
            "resolved source starts outside the parent binary",
            file_offset=hex(offset),
            parent_size=len(data),
        )
    requested_size = request["extraction"].get("source_size")
    if require_exact_size and requested_size and int(requested_size) > available:
        raise ExtractionFailure(
            "source_resolution",
            "requested source range extends beyond the parent binary",
            code="source_range_out_of_bounds",
            file_offset=hex(offset),
            requested_size=int(requested_size),
            available_size=max(0, available),
            parent_size=len(data),
        )
    size = min(
        int(requested_size) if requested_size else available,
        available,
        MAX_SOURCE_BYTES,
    )
    if size <= 0:
        raise ExtractionFailure(
            "source_resolution",
            "resolved source region is empty",
            file_offset=hex(offset),
        )
    return data[offset:offset + size], {
        **resolved_from,
        "requested_size": requested_size,
        "source_size": size,
        "available_size": available,
    }


def _bounded_decompress(method: str, data: bytes) -> bytes:
    try:
        if method in {"zlib", "gzip"}:
            window = 16 + zlib.MAX_WBITS if method == "gzip" else zlib.MAX_WBITS
            decoder = zlib.decompressobj(window)
            output = decoder.decompress(data, MAX_OUTPUT_BYTES + 1)
            if decoder.unconsumed_tail or len(output) > MAX_OUTPUT_BYTES:
                raise ExtractionFailure(
                    "transformation",
                    "decompressed output exceeds the safety limit",
                    output_limit=MAX_OUTPUT_BYTES,
                )
            output += decoder.flush(MAX_OUTPUT_BYTES + 1 - len(output))
            return output
        if method == "bz2":
            return bz2.BZ2Decompressor().decompress(data, max_length=MAX_OUTPUT_BYTES + 1)
        if method == "lzma":
            return lzma.LZMADecompressor().decompress(data, max_length=MAX_OUTPUT_BYTES + 1)
    except ExtractionFailure:
        raise
    except (OSError, EOFError, zlib.error, lzma.LZMAError) as exc:
        raise ExtractionFailure(
            "transformation",
            "%s decompression failed: %s" % (method, exc),
            source_size=len(data),
        ) from None
    raise AssertionError("unsupported decompression method")


def transform_source(
    source: bytes,
    extraction: Mapping[str, Any],
    *,
    bounded_emulator: Callable[[bytes, Mapping[str, Any]], bytes] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    method = str(extraction.get("method") or "raw")
    parameters = extraction.get("parameters") or {}
    if method in {"copy", "raw"}:
        output = source
    elif method == "xor":
        key_hex = str(parameters.get("key_hex") or "").strip()
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            key = b""
        if not key:
            raise ExtractionFailure(
                "transformation",
                "xor extraction requires a non-empty parameters.key_hex",
            )
        phase = int(parameters.get("key_phase") or 0) % len(key)
        output = bytes(
            value ^ key[(index + phase) % len(key)]
            for index, value in enumerate(source)
        )
    elif method in {"zlib", "gzip", "bz2", "lzma"}:
        output = _bounded_decompress(method, source)
    elif method == "base64":
        try:
            output = base64.b64decode(source, validate=True)
        except binascii.Error as exc:
            raise ExtractionFailure(
                "transformation", "base64 decoding failed: %s" % exc
            ) from None
    elif method == "hex":
        try:
            output = bytes.fromhex(source.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise ExtractionFailure(
                "transformation", "hex decoding failed: %s" % exc
            ) from None
    elif method == "bounded_emulation":
        if bounded_emulator is None:
            raise ExtractionFailure(
                "bounded_emulation",
                "bounded emulation is unavailable in this execution context",
            )
        output = bounded_emulator(source, extraction)
    else:
        raise ExtractionFailure(
            "transformation",
            "unsupported extraction method",
            code="unsupported_extraction_method",
            method=method,
        )

    strip_prefix = int(parameters.get("strip_prefix") or 0)
    if strip_prefix:
        if strip_prefix >= len(output):
            raise ExtractionFailure(
                "transformation",
                "strip_prefix removes the complete recovered output",
                output_size=len(output),
                strip_prefix=strip_prefix,
            )
        output = output[strip_prefix:]
    if not output:
        raise ExtractionFailure("transformation", "transformation produced no bytes")
    if len(output) > MAX_OUTPUT_BYTES:
        raise ExtractionFailure(
            "transformation",
            "recovered output exceeds the safety limit",
            output_size=len(output),
            output_limit=MAX_OUTPUT_BYTES,
        )
    return output, {
        "method": method,
        "parameters": dict(parameters),
        "input_size": len(source),
        "output_size": len(output),
    }


def _pe_architecture(machine: int) -> str:
    return {
        0x14C: "x86",
        0x8664: "x86_64",
        0x1C0: "arm",
        0xAA64: "arm64",
    }.get(machine, "machine_%04x" % machine)


def _validate_elf_bytes(data: bytes) -> dict[str, Any]:
    if len(data) < 0x34 or data[:4] != b"\x7fELF":
        raise ExtractionFailure(
            "artifact_validation", "recovered buffer has no valid ELF header",
            source_size=len(data),
        )
    elf_class = data[4]
    endian = data[5]
    if elf_class not in {1, 2} or endian not in {1, 2}:
        raise ExtractionFailure("artifact_validation", "unsupported ELF class or byte order")
    order = "<" if endian == 1 else ">"
    machine = struct.unpack_from(order + "H", data, 18)[0]
    entry = struct.unpack_from(order + ("I" if elf_class == 1 else "Q"), data, 24)[0]
    architecture = {
        3: "x86",
        40: "arm",
        62: "x86_64",
        183: "arm64",
    }.get(machine, "machine_%04x" % machine)
    return {
        "valid": True,
        "artifact_kind": "elf",
        "architecture": architecture,
        "machine": hex(machine),
        "bitness": 32 if elf_class == 1 else 64,
        "byte_order": "little" if endian == 1 else "big",
        "entrypoint": hex(entry),
        "required_size": len(data),
        "loadable": True,
    }


def _validate_macho_bytes(data: bytes) -> dict[str, Any]:
    if len(data) < 28:
        raise ExtractionFailure(
            "artifact_validation", "recovered buffer is smaller than a Mach-O header",
            source_size=len(data),
        )
    magic = data[:4]
    formats = {
        b"\xce\xfa\xed\xfe": ("<", 32),
        b"\xcf\xfa\xed\xfe": ("<", 64),
        b"\xfe\xed\xfa\xce": (">", 32),
        b"\xfe\xed\xfa\xcf": (">", 64),
    }
    if magic in {b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}:
        return {
            "valid": True,
            "artifact_kind": "macho",
            "architecture": "universal",
            "bitness": None,
            "required_size": len(data),
            "loadable": True,
        }
    if magic not in formats:
        raise ExtractionFailure("artifact_validation", "recovered buffer has no Mach-O magic")
    order, bitness = formats[magic]
    cpu_type = struct.unpack_from(order + "I", data, 4)[0]
    architecture = {
        7: "x86",
        0x01000007: "x86_64",
        12: "arm",
        0x0100000C: "arm64",
    }.get(cpu_type, "cpu_%08x" % cpu_type)
    return {
        "valid": True,
        "artifact_kind": "macho",
        "architecture": architecture,
        "cpu_type": hex(cpu_type),
        "bitness": bitness,
        "required_size": len(data),
        "loadable": True,
    }


def _archive_format(data: bytes) -> str | None:
    signatures = (
        (b"PK\x03\x04", "zip"),
        (b"7z\xbc\xaf\x27\x1c", "7z"),
        (b"\x1f\x8b", "gzip"),
        (b"BZh", "bzip2"),
        (b"\xfd7zXZ\x00", "xz"),
        (b"MSCF", "cab"),
    )
    for signature, name in signatures:
        if data.startswith(signature):
            return name
    if len(data) > 265 and data[257:262] == b"ustar":
        return "tar"
    return None


def validate_pe_bytes(data: bytes) -> tuple[bytes, dict[str, Any]]:
    if len(data) < 0x40:
        raise ExtractionFailure(
            "pe_validation", "recovered buffer is smaller than a DOS header", source_size=len(data)
        )
    if data[:2] != b"MZ":
        raise ExtractionFailure(
            "pe_validation", "recovered buffer has no MZ signature", source_size=len(data)
        )
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        raise ExtractionFailure(
            "pe_validation",
            "recovered buffer has no valid PE signature",
            source_size=len(data),
            e_lfanew=hex(e_lfanew),
        )
    machine, section_count, _timestamp, _symptr, _symcount, optional_size, characteristics = struct.unpack_from(
        "<HHIIIHH", data, e_lfanew + 4
    )
    optional_offset = e_lfanew + 0x18
    section_table = optional_offset + optional_size
    required_headers = section_table + section_count * 40
    if required_headers > len(data):
        raise ExtractionFailure(
            "pe_validation",
            "section table extends beyond recovered buffer",
            source_size=len(data),
            required_size=required_headers,
        )
    magic = struct.unpack_from("<H", data, optional_offset)[0] if optional_size >= 2 else 0
    if magic not in {0x10B, 0x20B}:
        raise ExtractionFailure(
            "pe_validation", "unsupported or missing PE optional header", optional_magic=hex(magic)
        )
    entrypoint_rva = struct.unpack_from("<I", data, optional_offset + 16)[0]
    sections = []
    required_size = required_headers
    entrypoint_section = None
    for index in range(section_count):
        offset = section_table + index * 40
        name = data[offset:offset + 8].split(b"\0", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, offset + 8
        )
        section_end = raw_ptr + raw_size
        required_size = max(required_size, section_end)
        characteristics_value = struct.unpack_from("<I", data, offset + 36)[0]
        if virtual_address <= entrypoint_rva < virtual_address + max(virtual_size, raw_size):
            entrypoint_section = name
        sections.append({
            "name": name,
            "virtual_address": hex(virtual_address),
            "virtual_size": virtual_size,
            "raw_ptr": raw_ptr,
            "raw_size": raw_size,
            "characteristics": hex(characteristics_value),
        })
    if required_size > len(data):
        raise ExtractionFailure(
            "pe_validation",
            "section extends beyond recovered buffer",
            source_size=len(data),
            required_size=required_size,
        )
    architecture = _pe_architecture(machine)
    overlay_size = len(data) - required_size
    return data, {
        "valid": True,
        "artifact_kind": "pe",
        "architecture": architecture,
        "machine": hex(machine),
        "bitness": 64 if magic == 0x20B else 32,
        "characteristics": hex(characteristics),
        "section_count": section_count,
        "sections": sections,
        "entrypoint_rva": hex(entrypoint_rva),
        "entrypoint_section": entrypoint_section,
        "required_size": required_size,
        "file_size": len(data),
        "overlay_offset": required_size,
        "overlay_size": overlay_size,
        "overlay_present": overlay_size > 0,
        "loadable": entrypoint_rva == 0 or entrypoint_section is not None,
    }


def validate_recovered_artifact(
    data: bytes,
    expected: Mapping[str, Any],
) -> tuple[bytes, dict[str, Any]]:
    if len(data) > MAX_OUTPUT_BYTES:
        raise ExtractionFailure(
            "artifact_validation",
            "recovered artifact exceeds the output safety limit",
            output_size=len(data),
            output_limit=MAX_OUTPUT_BYTES,
        )
    kind = str(expected.get("artifact_kind") or "pe")
    if kind == "pe":
        artifact, validation = validate_pe_bytes(data)
    elif kind == "elf":
        artifact, validation = data, _validate_elf_bytes(data)
    elif kind == "macho":
        artifact, validation = data, _validate_macho_bytes(data)
    elif kind == "archive":
        archive_format = _archive_format(data)
        if archive_format is None:
            raise ExtractionFailure(
                "artifact_validation", "recovered buffer has no recognized archive signature",
                source_size=len(data),
            )
        artifact, validation = data, {
            "valid": True,
            "artifact_kind": "archive",
            "archive_format": archive_format,
            "architecture": None,
            "required_size": len(data),
            "loadable": False,
        }
    else:
        if not data:
            raise ExtractionFailure("artifact_validation", "recovered artifact is empty")
        if kind == "script":
            try:
                data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ExtractionFailure(
                    "artifact_validation", "recovered script is not valid UTF-8",
                    source_size=len(data),
                ) from exc
        artifact = data
        validation = {
            "valid": True,
            "artifact_kind": kind,
            "architecture": expected.get("architecture"),
            "required_size": len(data),
            "loadable": kind == "shellcode" and bool(expected.get("architecture")),
            "base_address": expected.get("base_address"),
            "entry_offset": expected.get("entry_offset"),
        }
        if kind == "shellcode" and not expected.get("architecture"):
            raise ExtractionFailure(
                "artifact_validation",
                "shellcode validation requires an expected architecture",
                source_size=len(data),
            )
        if kind == "shellcode" and expected.get("entry_offset") is not None:
            entry_offset = int(str(expected["entry_offset"]), 0)
            if entry_offset >= len(data):
                raise ExtractionFailure(
                    "artifact_validation", "shellcode entry_offset is outside the artifact",
                    source_size=len(data),
                    entry_offset=entry_offset,
                )
    expected_arch = str(expected.get("architecture") or "").lower()
    if expected_arch and validation.get("architecture") != expected_arch:
        raise ExtractionFailure(
            "artifact_validation",
            "recovered architecture does not match the model hypothesis",
            expected_architecture=expected_arch,
            observed_architecture=validation.get("architecture"),
        )
    return artifact, validation


def execute_semantic_extraction(
    *,
    parent_path: Path,
    parent_sha256: str,
    request: Mapping[str, Any],
    bounded_emulator: Callable[[bytes, Mapping[str, Any]], bytes] | None = None,
    static_script_runner: Callable[
        [Mapping[str, bytes], Mapping[str, Any]],
        tuple[bytes, Mapping[str, Any]],
    ] | None = None,
) -> tuple[bytes, dict[str, Any]]:
    source_regions = request.get("source_regions") or []
    if source_regions:
        chunks = []
        resolutions = []
        for locator in source_regions:
            chunk, resolution = resolve_source_region(
                parent_path,
                {
                    "locator": locator,
                    "extraction": {"source_size": locator.get("size")},
                },
                require_exact_size=True,
            )
            chunks.append(chunk)
            resolutions.append(resolution)
        file_ranges = sorted(
            (
                int(str(row["file_offset"]), 0),
                int(str(row["file_offset"]), 0) + int(row["source_size"]),
            )
            for row in resolutions
        )
        for previous, current in zip(file_ranges, file_ranges[1:]):
            if current[0] < previous[1]:
                raise ExtractionFailure(
                    "source_resolution",
                    "source ranges overlap after resolving to parent file offsets",
                    code="source_ranges_overlap",
                    first={"start": hex(previous[0]), "end": hex(previous[1])},
                    second={"start": hex(current[0]), "end": hex(current[1])},
                )
        source = b"".join(chunks)
        if len(source) > MAX_SOURCE_BYTES:
            raise ExtractionFailure(
                "source_resolution",
                "combined source regions exceed the safety limit",
                source_size=len(source),
                source_limit=MAX_SOURCE_BYTES,
            )
        source_resolution = {
            "kind": "ordered_regions",
            "regions": resolutions,
            "source_size": len(source),
        }
    else:
        source, source_resolution = resolve_source_region(
            parent_path,
            request,
            require_exact_size=bool(request["extraction"].get("source_size")),
        )
    extraction = request["extraction"]
    input_resolutions = {"source": source_resolution}
    if extraction.get("method") == "python_static":
        if static_script_runner is None:
            raise ExtractionFailure(
                "static_script_execution",
                "model-authored static extraction is unavailable in this context",
            )
        script_inputs = {"source": source}
        total_input_size = len(source)
        for row in extraction.get("inputs") or []:
            input_request = {
                "locator": row["locator"],
                "extraction": {"source_size": row["locator"].get("size")},
            }
            value, resolution = resolve_source_region(parent_path, input_request)
            script_inputs[row["name"]] = value
            input_resolutions[row["name"]] = resolution
            total_input_size += len(value)
            if total_input_size > MAX_SOURCE_BYTES:
                raise ExtractionFailure(
                    "source_resolution",
                    "combined static extractor inputs exceed the safety limit",
                    input_size=total_input_size,
                    input_limit=MAX_SOURCE_BYTES,
                )
        transformed, execution = static_script_runner(script_inputs, extraction)
        transformation = {
            "method": "python_static",
            "script_path": extraction.get("script_path"),
            "parameters": dict(extraction.get("parameters") or {}),
            "input_size": total_input_size,
            "output_size": len(transformed),
            "execution": dict(execution),
        }
    else:
        transformed, transformation = transform_source(
            source,
            extraction,
            bounded_emulator=bounded_emulator,
        )
        transformation["malware_executed"] = False
    artifact, validation = validate_recovered_artifact(
        transformed,
        request["expected_result"],
    )
    if artifact != transformed:
        raise ExtractionFailure(
            "artifact_validation",
            "structural validation modified recovered artifact bytes",
            code="validation_modified_artifact",
            transformed_size=len(transformed),
            validated_size=len(artifact),
            transformed_sha256=hashlib.sha256(transformed).hexdigest(),
            validated_sha256=hashlib.sha256(artifact).hexdigest(),
        )
    declared_transformation_size = int(
        transformation.get("output_size") or 0
    )
    if declared_transformation_size != len(transformed):
        raise ExtractionFailure(
            "artifact_validation",
            "transformation output size does not match recovered bytes",
            code="transformation_size_mismatch",
            declared_output_size=declared_transformation_size,
            actual_output_size=len(transformed),
        )
    output_sha256 = hashlib.sha256(artifact).hexdigest()
    provenance = {
        "parent_component_id": request["parent_component_id"],
        "parent_sha256": parent_sha256,
        "locator": dict(request["locator"]),
        "source_resolution": source_resolution,
        "input_resolutions": input_resolutions,
        "transformation": transformation,
        "expected_result": dict(request["expected_result"]),
        "evidence_refs": list(request.get("evidence_refs") or []),
        "loader_decoder": dict(request.get("loader_decoder") or {}),
        "output_sha256": output_sha256,
        "output_size": len(artifact),
        "validation_preserved_bytes": True,
    }
    return artifact, {
        "schema": RESULT_SCHEMA,
        "status": "validated",
        "request_id": request["request_id"],
        "provenance": provenance,
        "structural_validation": validation,
    }


def enrich_pe_validation(path: Path, validation: Mapping[str, Any]) -> dict[str, Any]:
    if validation.get("artifact_kind") != "pe":
        return dict(validation)
    inventory = build_pe_inventory(path)
    return {
        **dict(validation),
        "headers": {
            "is_pe": inventory.get("is_pe"),
            "image_base": inventory.get("image_base"),
            "size_of_image": inventory.get("size_of_image"),
        },
        "imports": inventory.get("imports") or [],
        "exports": inventory.get("exports") or {},
        "tls": inventory.get("tls") or {},
        "entrypoint_va": inventory.get("entry_point_va"),
    }


def semantic_review_template(
    *,
    component_id: str,
    request: Mapping[str, Any],
    extraction_result: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "schema": REVIEW_SCHEMA,
        "component_id": component_id,
        "request_id": request["request_id"],
        "status": "pending_model_review",
        "host_validation": {
            "provenance": extraction_result.get("provenance"),
            "structural_validation": extraction_result.get("structural_validation"),
        },
        "model_review": {
            "decision": None,
            "parent_behavior": "",
            "artifact_observations": [],
            "loader_decoder_consistency": "",
            "evidence_refs": [],
            "contradictions": [],
            "next_request": None,
        },
    }


def validate_semantic_review(payload: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {"passed": False, "errors": ["semantic extraction review is missing"]}
    review = payload.get("model_review") or {}
    decision = str(review.get("decision") or "").strip().lower()
    errors = []
    if decision not in {"accept", "revise", "reject"}:
        errors.append("semantic review decision must be accept, revise, or reject")
    if not str(review.get("parent_behavior") or "").strip():
        errors.append("semantic review parent_behavior is missing")
    if not (review.get("artifact_observations") or []):
        errors.append("semantic review artifact_observations are missing")
    if not str(review.get("loader_decoder_consistency") or "").strip():
        errors.append("semantic review loader_decoder_consistency is missing")
    if not (review.get("evidence_refs") or []):
        errors.append("semantic review evidence_refs are missing")
    if decision == "revise" and not review.get("next_request"):
        errors.append("a revise decision requires next_request")
    return {
        "passed": not errors and decision == "accept",
        "decision": decision or None,
        "errors": errors,
        "evidence_ref_count": len(review.get("evidence_refs") or []),
        "artifact_observation_count": len(
            review.get("artifact_observations") or []
        ),
        "contradiction_count": len(review.get("contradictions") or []),
    }


def filter_model_component_registry(
    registry: Mapping[str, Any],
    *,
    discovery_mode: str,
) -> dict[str, Any]:
    """Remove hidden-oracle locations from the model-facing registry."""
    if discovery_mode not in DISCOVERY_MODES:
        raise ValueError("unsupported component discovery mode")
    filtered = json.loads(json.dumps(registry))
    if discovery_mode == "operational_assisted":
        return filtered
    for component in filtered.get("components") or []:
        validation = component.get("validation") or {}
        pending = [
            child
            for child in validation.get("embedded_children") or []
            if child.get("status") == "pending"
        ]
        if discovery_mode == "model_led_baseline":
            validation.pop("embedded_children", None)
        else:
            validation["embedded_children"] = [
                {
                    "status": "suspected_hidden_child",
                    "reason": "host oracle indicates unresolved nested executable evidence",
                }
                for _child in pending
            ]
        component["validation"] = validation
    return filtered
