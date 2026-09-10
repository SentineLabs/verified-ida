"""Safe parent/child artifact recovery for the interactive runtime."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Mapping

from bounded_unicorn import emulate_x86
from component_extraction import (
    ExtractionFailure,
    RESULT_SCHEMA,
    execute_semantic_extraction,
    normalize_semantic_request,
)
from static_extractor_script import stage_static_extractor

from .journal import JournalError, stable_id
from .child_environment import child_environment


def _bounded_component_emulator(
    source: bytes, extraction: Mapping[str, Any]
) -> bytes:
    parameters = dict(extraction.get("parameters") or {})
    code_hex = str(parameters.get("code_hex") or "")
    decoder_ea = parameters.get("decoder_ea") or parameters.get("base")
    source_address = parameters.get("source_address")
    output_address = parameters.get("output_address")
    output_size = int(parameters.get("output_size") or 0)
    if not code_hex or decoder_ea in (None, ""):
        raise ExtractionFailure(
            "bounded_emulation", "code_hex and decoder_ea are required"
        )
    if source_address in (None, "") or output_address in (None, ""):
        raise ExtractionFailure(
            "bounded_emulation", "source_address and output_address are required"
        )
    if output_size <= 0 or output_size > 1024 * 1024:
        raise ExtractionFailure(
            "bounded_emulation", "output_size must be 1..1048576"
        )
    code = bytes.fromhex(code_hex)
    request = {
        "mode": parameters.get("mode"),
        "base": decoder_ea,
        "start": parameters.get("start") or decoder_ea,
        "end": parameters.get("end") or hex(int(str(decoder_ea), 0) + len(code)),
        "instruction_limit": parameters.get("instruction_limit") or 100_000,
        "registers": dict(parameters.get("registers") or {}),
        "memory": [
            {"address": source_address, "size": len(source), "data_hex": source.hex()},
            {"address": output_address, "size": output_size},
            *list(parameters.get("memory") or []),
        ],
        "readback": [{"address": output_address, "size": output_size}],
    }
    result = emulate_x86(request, code)
    readback = result.get("readback") or []
    if not readback:
        raise ExtractionFailure(
            "bounded_emulation",
            "emulation produced no output readback",
            stopped=result.get("stopped"),
            error=result.get("error"),
        )
    return bytes.fromhex(str(readback[0].get("data_hex") or ""))


class ComponentRecoveryService:
    """Recover, validate, review, and prepare child binaries without an oracle."""

    def __init__(
        self,
        runtime: Any,
        *,
        idb_preparer: Callable[[Path, Path], Mapping[str, Any]] | None = None,
    ):
        self.runtime = runtime
        self.idb_preparer = idb_preparer or self._prepare_idb

    def _static_runner(
        self,
        request_id: str,
        inputs: Mapping[str, bytes],
        extraction: Mapping[str, Any],
    ) -> tuple[bytes, Mapping[str, Any]]:
        relative = Path(str(extraction.get("script_path") or ""))
        script_path = (self.runtime.workspace / relative).resolve()
        if self.runtime.workspace not in script_path.parents or not script_path.is_file():
            raise ExtractionFailure(
                "static_script_validation",
                "script_path must name an existing workspace Python file",
            )
        scratch = self.runtime.workspace / "static_extractors" / request_id.replace(":", "_")
        try:
            staged = stage_static_extractor(
                source=script_path.read_text(encoding="utf-8"),
                scratch_dir=scratch,
                inputs=inputs,
                parameters=extraction.get("parameters") or {},
            )
        except (SyntaxError, ValueError) as exc:
            raise ExtractionFailure(
                "static_script_validation", "%s: %s" % (type(exc).__name__, exc)
            ) from None
        command = [
            str(Path(__file__).resolve().parents[2] / "scripts" / "run_static_extractor_sandbox.sh"),
            str(scratch),
            str(staged["wrapper_path"]),
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=120,
            check=False,
            env=child_environment(),
        )
        result = {}
        if staged["result_path"].is_file():
            result = json.loads(staged["result_path"].read_text(encoding="utf-8"))
        if completed.returncode != 0 or not result.get("ok"):
            raise ExtractionFailure(
                "static_script_execution",
                str(result.get("error") or "static extractor process failed"),
                returncode=completed.returncode,
                output=completed.stdout[-4000:],
            )
        artifact = staged["artifact_path"].read_bytes()
        return artifact, {
            "sandbox": "no_network_static_process",
            "malware_executed": False,
            "script_sha256": staged["validation"]["script_sha256"],
            "inputs": staged["inputs"],
            "report": result.get("report"),
        }

    def recover(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        try:
            request = normalize_semantic_request(payload)
        except ValueError as exc:
            message = str(exc)
            if message.startswith("unsupported extraction method"):
                code = "unsupported_extraction_method"
            elif "locator" in message:
                code = "invalid_source_locator"
            elif "python_static" in message or "script_path" in message:
                code = "invalid_static_extractor_binding"
            else:
                code = "invalid_component_request"
            return {
                "schema": RESULT_SCHEMA,
                "status": "rejected",
                "stage": "request_validation",
                "code": code,
                "reason": message,
                "recovery": "Use describe_ida_capabilities.component_recovery and resubmit the corrected request.",
            }
        parent = self.runtime.journal.component(request["parent_component_id"])
        if parent is None:
            raise JournalError("Unknown extraction parent component")
        for evidence_ref in request.get("evidence_refs") or []:
            if isinstance(evidence_ref, str):
                evidence = self.runtime.journal.inspection(evidence_ref)
                if evidence is None or evidence["component_id"] != parent["component_id"]:
                    raise JournalError("Extraction evidence must belong to the parent IDB")
        extraction_id = stable_id("extraction", request["request_id"], request)
        try:
            artifact, result = execute_semantic_extraction(
                parent_path=Path(parent["binary_path"]),
                parent_sha256=parent["binary_sha256"],
                request=request,
                bounded_emulator=_bounded_component_emulator,
                static_script_runner=lambda inputs, extraction: self._static_runner(
                    request["request_id"], inputs, extraction
                ),
            )
        except ExtractionFailure as exc:
            failure = exc.result(request_id=request["request_id"])
            self.runtime.journal.record_extraction(
                extraction_id=extraction_id,
                parent_component_id=parent["component_id"],
                request=request,
                status="failed",
                validation=failure,
            )
            return {"extraction_id": extraction_id, **failure}
        digest = hashlib.sha256(artifact).hexdigest()
        provenance = dict(result.get("provenance") or {})
        transformation = dict(provenance.get("transformation") or {})
        declared_size = int(provenance.get("output_size") or 0)
        transformed_size = int(transformation.get("output_size") or 0)
        declared_digest = str(provenance.get("output_sha256") or "")
        if (
            declared_size != len(artifact)
            or transformed_size != len(artifact)
            or declared_digest != digest
        ):
            failure = ExtractionFailure(
                "artifact_registration",
                "validated extraction provenance does not match artifact bytes",
                code="artifact_provenance_mismatch",
                declared_output_size=declared_size,
                transformed_output_size=transformed_size,
                actual_output_size=len(artifact),
                declared_sha256=declared_digest,
                actual_sha256=digest,
            ).result(request_id=request["request_id"])
            self.runtime.journal.record_extraction(
                extraction_id=extraction_id,
                parent_component_id=parent["component_id"],
                request=request,
                status="failed",
                validation=failure,
            )
            return {"extraction_id": extraction_id, **failure}
        kind = str(result["structural_validation"].get("artifact_kind") or "data")
        # Recovered components are analysis artifacts, not launchable files.
        # Keep the validated container kind visible without using executable-
        # looking suffixes that endpoint security may quarantine before IDA can
        # ingest them. IDA identifies these artifacts from their contents.
        suffix = {
            "pe": ".pe.bin",
            "elf": ".elf.bin",
            "macho": ".macho.bin",
        }.get(kind, ".bin")
        artifact_dir = self.runtime.workspace / "artifacts" / "sha256" / digest
        artifact_dir.mkdir(parents=True, exist_ok=True)
        artifact_path = artifact_dir / ("artifact" + suffix)
        if not artifact_path.exists():
            artifact_path.write_bytes(artifact)
        self.runtime.journal.record_extraction(
            extraction_id=extraction_id,
            parent_component_id=parent["component_id"],
            request=request,
            status="pending_model_decision",
            validation=result,
            artifact_sha256=digest,
            artifact_path=artifact_path,
        )
        return {
            "extraction_id": extraction_id,
            "status": "pending_model_decision",
            "artifact_sha256": digest,
            "artifact_path": str(artifact_path),
            "validation": result,
            "required_decision": ["accept", "revise", "reject", "defer"],
        }

    def decide(
        self,
        *,
        extraction_id: str,
        decision: str,
        rationale: str,
        evidence_refs: list[str],
        next_request: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        row = self.runtime.journal.extraction(extraction_id)
        if row is None:
            raise JournalError("Unknown extraction: %s" % extraction_id)
        decision = str(decision).lower().strip()
        if decision not in {"accept", "revise", "reject", "defer"}:
            raise JournalError("Unsupported extraction decision")
        if not str(rationale or "").strip() or not evidence_refs:
            raise JournalError("Extraction decision requires rationale and evidence")
        for evidence_ref in evidence_refs:
            evidence = self.runtime.journal.inspection(str(evidence_ref))
            if (
                evidence is None
                or evidence["component_id"] != row["parent_component_id"]
            ):
                raise JournalError(
                    "Extraction decision evidence must belong to the parent IDB"
                )
        review = {
            "decision": decision,
            "rationale": str(rationale),
            "evidence_refs": list(evidence_refs),
            "host_validation": row["validation"],
        }
        if decision == "revise":
            if not next_request:
                raise JournalError("A revise decision requires next_request")
            updated = self.runtime.journal.record_extraction(
                extraction_id=extraction_id,
                parent_component_id=row["parent_component_id"],
                request=row["request"],
                status="revision_requested",
                validation=review,
                artifact_sha256=row.get("artifact_sha256"),
                artifact_path=row.get("artifact_path"),
            )
            return {"review": review, "extraction": updated, "next": self.recover(next_request)}
        if decision in {"reject", "defer"}:
            status = "rejected" if decision == "reject" else "deferred"
            updated = self.runtime.journal.record_extraction(
                extraction_id=extraction_id,
                parent_component_id=row["parent_component_id"],
                request=row["request"],
                status=status,
                validation=review,
                artifact_sha256=row.get("artifact_sha256"),
                artifact_path=row.get("artifact_path"),
            )
            return {"review": review, "extraction": updated}
        artifact_path = Path(str(row.get("artifact_path") or ""))
        validation = (row["validation"].get("structural_validation") or {})
        if not validation.get("loadable"):
            raise JournalError("Accepted artifact is not loadable as a separate IDB")
        component_id = "component-%s" % str(row["artifact_sha256"])[:16]
        component_dir = self.runtime.workspace / "components" / component_id
        component_dir.mkdir(parents=True, exist_ok=True)
        child_binary = component_dir / artifact_path.name
        if not child_binary.exists():
            child_binary.write_bytes(artifact_path.read_bytes())
        child_idb = component_dir / "analysis.i64"
        prepare_result = dict(self.idb_preparer(child_binary, child_idb))
        component = self.runtime.journal.register_component(
            component_id=component_id,
            parent_component_id=row["parent_component_id"],
            binary_sha256=row["artifact_sha256"],
            binary_path=child_binary,
            idb_path=child_idb,
            architecture=validation.get("architecture"),
            status="analysis_ready",
            provenance={
                "extraction_id": extraction_id,
                "request": row["request"],
                "review": review,
                "prepare": prepare_result,
            },
        )
        self.runtime.journal.record_extraction(
            extraction_id=extraction_id,
            parent_component_id=row["parent_component_id"],
            request=row["request"],
            status="accepted",
            validation=review,
            artifact_sha256=row["artifact_sha256"],
            artifact_path=artifact_path,
            child_component_id=component_id,
        )
        return {"review": review, "component": component, "prepare": prepare_result}

    def _prepare_idb(self, binary_path: Path, idb_path: Path) -> Mapping[str, Any]:
        script_root = Path(__file__).resolve().parents[2] / "scripts"
        order_path = idb_path.with_name("analysis_order.json")
        log_path = idb_path.with_name("prepare_analysis.ida.log")
        command = [
            str(script_root / "run_ida_script_no_network.sh"),
            "--log",
            str(log_path),
            str(binary_path),
            str(script_root / "prepare_analysis.py"),
            "--max",
            "5000",
            "--save-as",
            str(idb_path),
            "--output",
            str(order_path),
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=1800,
            check=False,
        )
        if completed.returncode != 0 or not idb_path.is_file():
            raise RuntimeError(
                "IDA child preparation failed (%d): %s"
                % (completed.returncode, completed.stdout[-4000:])
            )
        return {
            "returncode": completed.returncode,
            "order_path": str(order_path),
            "log_path": str(log_path),
        }
