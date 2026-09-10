"""Disposable-IDB annotation export with source drift detection."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from typing import Any, Callable


EXPORT_PROVENANCE_SCHEMA = "verified_ida.safe_annotation_export.v1"
IdaExecutor = Callable[[str, Path, Path, Path], dict[str, Any]]


class SafeExportError(RuntimeError):
    """Raised when disposable export or source-integrity verification fails."""

    def __init__(self, message: str, *, provenance: dict[str, Any]):
        super().__init__(message)
        self.provenance = provenance


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(".%s.tmp-%d" % (path.name, os.getpid()))
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise RuntimeError("IDA export did not return a JSON object: %s" % path)
    return value


def subprocess_ida_executor(
    *,
    runner: Path,
    annotation_script: Path,
    semantic_script: Path,
) -> IdaExecutor:
    """Return the production no-network IDA executor."""

    for label, path in (("runner", runner), ("annotation worker", annotation_script),
                        ("semantic worker", semantic_script)):
        if not path.is_file():
            raise FileNotFoundError("Missing safe-export %s: %s" % (label, path))
    if not os.access(runner, os.X_OK):
        raise PermissionError("Safe-export runner is not executable: %s" % runner)

    def execute(kind: str, idb: Path, output: Path, log: Path) -> dict[str, Any]:
        if kind not in {"annotations", "semantic"}:
            raise ValueError("Unknown export kind: %s" % kind)
        script = annotation_script if kind == "annotations" else semantic_script
        completed = subprocess.run(
            [
                str(runner),
                "--log",
                str(log),
                str(idb),
                str(script),
                "--output",
                str(output),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        result = {
            "kind": kind,
            "returncode": completed.returncode,
            "stdout_tail": completed.stdout[-2000:],
            "stderr_tail": completed.stderr[-2000:],
            "log_ephemeral_path": str(log),
        }
        if log.is_file():
            log_text = log.read_text(encoding="utf-8", errors="replace")
            result.update({
                "log_sha256": _sha256(log),
                "log_tail": log_text[-4000:],
            })
        if completed.returncode != 0 or not output.is_file():
            raise RuntimeError(
                "%s export failed with exit code %d: %s"
                % (kind, completed.returncode, completed.stderr[-2000:])
            )
        return result

    return execute


def _next_failure_directory(provenance_path: Path) -> Path:
    base = provenance_path.parent / (provenance_path.stem + ".failure")
    if not base.exists():
        return base
    for index in range(1, 10_000):
        candidate = provenance_path.parent / (
            "%s.failure-%04d" % (provenance_path.stem, index)
        )
        if not candidate.exists():
            return candidate
    raise RuntimeError("Unable to allocate a unique export-failure directory")


def safe_export_annotations(
    *,
    source_idb: str | Path,
    annotations_path: str | Path,
    provenance_path: str | Path,
    execute: IdaExecutor,
    overwrite: bool = False,
) -> dict[str, Any]:
    """Export annotations from a clone and prove the source did not drift."""

    source = Path(source_idb).expanduser().resolve()
    annotations = Path(annotations_path).expanduser().resolve()
    provenance_output = Path(provenance_path).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError("Candidate IDB not found: %s" % source)
    if not overwrite and (annotations.exists() or provenance_output.exists()):
        raise FileExistsError(
            "Safe export output exists; select a new path or request overwrite"
        )
    annotations.parent.mkdir(parents=True, exist_ok=True)
    provenance_output.parent.mkdir(parents=True, exist_ok=True)
    workspace = Path(tempfile.mkdtemp(
        prefix=".verified-ida-safe-export-",
        dir=str(annotations.parent),
    ))
    prior_annotations = workspace / "prior-candidate.annotations.json"
    prior_provenance = workspace / "prior-provenance.json"
    if annotations.exists():
        shutil.copy2(annotations, prior_annotations)
    if provenance_output.exists():
        shutil.copy2(provenance_output, prior_provenance)
    source_before = workspace / ("source-before" + source.suffix)
    export_clone = workspace / ("annotation-export" + source.suffix)
    source_after = workspace / ("source-after" + source.suffix)
    semantic_before_path = workspace / "semantic-before.json"
    semantic_after_path = workspace / "semantic-after.json"
    temporary_annotations = workspace / "candidate.annotations.json"
    source_before_sha = _sha256(source)
    source_before_size = source.stat().st_size
    provenance: dict[str, Any] = {
        "schema": EXPORT_PROVENANCE_SCHEMA,
        "status": "started",
        "started_at": _utc_now(),
        "execution_isolation": "disposable_candidate_idb_copies",
        "source": {
            "path": str(source),
            "bytes_before": source_before_size,
            "sha256_before": source_before_sha,
        },
        "outputs": {
            "annotations": str(annotations),
            "provenance": str(provenance_output),
        },
        "executions": [],
    }
    try:
        shutil.copy2(source, source_before)
        shutil.copy2(source, export_clone)
        if _sha256(source_before) != source_before_sha:
            raise RuntimeError("Pre-export source snapshot does not match the source IDB")
        if _sha256(export_clone) != source_before_sha:
            raise RuntimeError("Annotation export clone does not match the source IDB")

        provenance["executions"].append(execute(
            "semantic",
            source_before,
            semantic_before_path,
            workspace / "semantic-before.ida.log",
        ))
        provenance["executions"].append(execute(
            "annotations",
            export_clone,
            temporary_annotations,
            workspace / "annotations.ida.log",
        ))

        source_after_sha = _sha256(source)
        source_after_size = source.stat().st_size
        shutil.copy2(source, source_after)
        provenance["executions"].append(execute(
            "semantic",
            source_after,
            semantic_after_path,
            workspace / "semantic-after.ida.log",
        ))

        semantic_before = _read_json(semantic_before_path)
        semantic_after = _read_json(semantic_after_path)
        annotations_payload = _read_json(temporary_annotations)
        semantic_before_digest = str(semantic_before.get("semantic_digest") or "")
        semantic_after_digest = str(semantic_after.get("semantic_digest") or "")
        if not semantic_before_digest or not semantic_after_digest:
            raise RuntimeError("Semantic snapshot omitted its canonical digest")
        raw_unchanged = (
            source_before_sha == source_after_sha
            and source_before_size == source_after_size
        )
        semantic_unchanged = semantic_before_digest == semantic_after_digest
        provenance["source"].update({
            "bytes_after": source_after_size,
            "sha256_after": source_after_sha,
            "raw_unchanged": raw_unchanged,
            "semantic_digest_before": semantic_before_digest,
            "semantic_digest_after": semantic_after_digest,
            "semantic_unchanged": semantic_unchanged,
        })
        provenance["disposable_export"] = {
            "idb_sha256_before": source_before_sha,
            "idb_sha256_after": _sha256(export_clone),
            "annotations_sha256": _sha256(temporary_annotations),
            "annotations_schema": annotations_payload.get("schema"),
            "semantic_before_output_sha256": _sha256(semantic_before_path),
            "semantic_after_output_sha256": _sha256(semantic_after_path),
        }
        if not raw_unchanged:
            raise RuntimeError("Candidate deliverable changed during annotation export")
        if not semantic_unchanged:
            raise RuntimeError("Candidate semantic state changed during annotation export")

        output_temporary = annotations.with_name(
            ".%s.tmp-%d" % (annotations.name, os.getpid())
        )
        shutil.copy2(temporary_annotations, output_temporary)
        os.replace(output_temporary, annotations)
        provenance.update({
            "status": "verified",
            "completed_at": _utc_now(),
            "failure_artifacts": None,
        })
        _write_json(provenance_output, provenance)
        shutil.rmtree(workspace)
        return provenance
    except Exception as exc:
        if source.exists():
            try:
                shutil.copy2(source, source_after)
                provenance["source"].update({
                    "bytes_after": source.stat().st_size,
                    "sha256_after": _sha256(source),
                })
            except Exception:
                pass
        failure_directory = _next_failure_directory(provenance_output)
        shutil.move(str(workspace), str(failure_directory))
        saved_annotations = failure_directory / prior_annotations.name
        saved_provenance = failure_directory / prior_provenance.name
        if saved_annotations.exists():
            shutil.copy2(saved_annotations, annotations)
        elif annotations.exists():
            annotations.unlink()
        if saved_provenance.exists():
            shutil.copy2(saved_provenance, provenance_output)
        provenance.update({
            "status": "failed",
            "completed_at": _utc_now(),
            "error": {"type": type(exc).__name__, "message": str(exc)},
            "failure_artifacts": str(failure_directory),
        })
        failure_receipt = failure_directory / "failed-export-provenance.json"
        _write_json(failure_receipt, provenance)
        if not saved_provenance.exists():
            _write_json(provenance_output, provenance)
        raise SafeExportError(str(exc), provenance=provenance) from exc
