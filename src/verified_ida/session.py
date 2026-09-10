"""Host-side lifecycle for one persistent, sandboxed IDA database worker."""

from __future__ import annotations

import json
import hashlib
import os
import select
import signal
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Mapping


class IdaSessionError(RuntimeError):
    pass


def verify_input_identity(identity: Mapping[str, Any], binary: Path) -> dict[str, Any]:
    """Compare IDA's loader-recorded digest, never a host-supplied IDB label."""
    digest = hashlib.sha256()
    with binary.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    native_hash = identity.get("sha256")
    if not native_hash:
        raise IdaSessionError(
            "IDB has no loader-recorded SHA-256. Recreate the clean IDB from "
            "the original sample before analysis; identity cannot be inferred."
        )
    if native_hash != digest.hexdigest():
        raise IdaSessionError(
            "Sample/IDB input SHA-256 mismatch. Supply the IDB created from this "
            "exact original sample; rebasing does not require a different input."
        )
    return {**dict(identity), "verified": True, "sample_sha256": digest.hexdigest()}


IDA_DATABASE_COMPANION_SUFFIXES = (
    ".id0", ".id1", ".id2", ".id3", ".nam", ".til",
)


def remove_ida_database_companions(database: str | Path) -> None:
    """Remove IDA's unpacked working files while preserving the packed IDB.

    IDA writes its companion files while a database is open, including for
    decompiler-driven type refinement that the user did not explicitly save.
    The packed ``.i64``/``.idb`` is the durable boundary used by Verified IDA.
    Removing only the known companion files after killing a discarded worker
    makes the next worker reopen that durable boundary instead of inheriting
    unjournaled analytical state.
    """

    database_path = Path(database).expanduser().resolve()
    for suffix in IDA_DATABASE_COMPANION_SUFFIXES:
        companion = database_path.with_suffix(suffix)
        try:
            companion.unlink()
        except FileNotFoundError:
            pass


def copy_ida_database(source: str | Path, destination: str | Path) -> Path:
    """Copy a packed IDB and any live companion files under one new basename."""

    source_path = Path(source).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    if not source_path.is_file():
        raise IdaSessionError("IDA database not found: %s" % source_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination_path)
    for suffix in IDA_DATABASE_COMPANION_SUFFIXES:
        companion = source_path.with_suffix(suffix)
        if companion.is_file():
            shutil.copy2(companion, destination_path.with_suffix(suffix))
    return destination_path


def copy_packed_ida_database(source: str | Path, destination: str | Path) -> Path:
    """Copy only the canonical packed IDB, never live companion state."""

    source_path = Path(source).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    if not source_path.is_file():
        raise IdaSessionError("IDA database not found: %s" % source_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_path, destination_path)
    remove_ida_database_companions(destination_path)
    return destination_path


def retain_packed_ida_database(source: str | Path, destination: str | Path) -> Path:
    """Retain the current packed IDB for rollback, preferring a hard link."""

    source_path = Path(source).expanduser().resolve()
    destination_path = Path(destination).expanduser().resolve()
    if not source_path.is_file():
        raise IdaSessionError("IDA database not found: %s" % source_path)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(source_path, destination_path)
    except OSError:
        shutil.copy2(source_path, destination_path)
    return destination_path


def atomic_promote_packed_ida_database(
    candidate: str | Path,
    canonical: str | Path,
) -> Path:
    """Atomically replace one packed IDB with a verified same-filesystem copy."""

    candidate_path = Path(candidate).expanduser().resolve()
    canonical_path = Path(canonical).expanduser().resolve()
    if not candidate_path.is_file():
        raise IdaSessionError("Candidate IDA database not found: %s" % candidate_path)
    if candidate_path.parent.stat().st_dev != canonical_path.parent.stat().st_dev:
        raise IdaSessionError("Candidate and canonical IDBs must share a filesystem")
    remove_ida_database_companions(candidate_path)
    remove_ida_database_companions(canonical_path)
    with candidate_path.open("rb") as handle:
        os.fsync(handle.fileno())
    os.replace(candidate_path, canonical_path)
    directory_fd = os.open(str(canonical_path.parent), os.O_RDONLY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return canonical_path


class PersistentIdaSession:
    """Serialize requests to a single IDB-owning IDA process."""

    MAX_FRAME_BYTES = 64 * 1024 * 1024

    def __init__(
        self,
        *,
        idb_path: str | Path,
        launcher: str | Path,
        worker_script: str | Path,
        log_path: str | Path,
        startup_timeout: float = 90.0,
        request_timeout: float = 180.0,
        disposable_copy: bool = False,
        input_binary_path: str | Path | None = None,
    ):
        self.idb_path = Path(idb_path).expanduser().resolve()
        self.launcher = Path(launcher).expanduser().resolve()
        self.worker_script = Path(worker_script).expanduser().resolve()
        self.log_path = Path(log_path).expanduser().resolve()
        self.startup_timeout = float(startup_timeout)
        self.request_timeout = float(request_timeout)
        self.disposable_copy = bool(disposable_copy)
        self.input_binary_path = (
            Path(input_binary_path).expanduser().resolve()
            if input_binary_path is not None
            else None
        )
        self.process: subprocess.Popen | None = None
        self._temp_root: Path | None = None
        self._request_stream = None
        self._response_stream = None
        self._request_id = 0
        self._lock = threading.RLock()
        self.input_identity: dict[str, Any] | None = None

    @property
    def running(self) -> bool:
        return bool(self.process is not None and self.process.poll() is None)

    def start(self) -> "PersistentIdaSession":
        if self.running:
            return self
        if not self.idb_path.is_file():
            raise IdaSessionError("IDA database not found: %s" % self.idb_path)
        if not self.launcher.is_file() or not self.worker_script.is_file():
            raise IdaSessionError("IDA launcher or session worker is unavailable")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._temp_root = Path(tempfile.mkdtemp(prefix="verified_ida_session."))
        session_idb_path = self.idb_path
        if self.disposable_copy:
            # Read-only/disposable analysis must begin from the same canonical
            # packed boundary as a verified mutation, not from live companion
            # files that may contain unsaved Hex-Rays inference.
            session_idb_path = copy_packed_ida_database(
                self.idb_path,
                self._temp_root / "database" / self.idb_path.name,
            )
        request_fifo = self._temp_root / "requests.fifo"
        response_fifo = self._temp_root / "responses.fifo"
        os.mkfifo(request_fifo, 0o600)
        os.mkfifo(response_fifo, 0o600)
        worker_args = [
            str(self.worker_script),
            str(session_idb_path),
            "--request-fifo",
            str(request_fifo),
            "--response-fifo",
            str(response_fifo),
        ]
        if self.input_binary_path is not None:
            worker_args.extend(["--input-binary", str(self.input_binary_path)])
        script_spec = shlex.join(worker_args)
        try:
            self.process = subprocess.Popen(
                [
                    str(self.launcher),
                    "--idat",
                    "--",
                    "-A",
                    "-L%s" % self.log_path,
                    "-S%s" % script_spec,
                    str(session_idb_path),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                start_new_session=True,
            )
            self._request_stream, self._response_stream = self._open_fifo_pair(
                request_fifo, response_fifo
            )
            response = self.request("ping", {}, timeout=self.startup_timeout)
            if not response.get("ok"):
                raise IdaSessionError("IDA session ping failed")
            if self.input_binary_path is not None:
                self.input_identity = verify_input_identity(
                    response.get("input_identity") or {}, self.input_binary_path
                )
        except BaseException:
            self.close(force=True)
            raise
        return self

    def _open_fifo_pair(self, request_fifo: Path, response_fifo: Path):
        deadline = time.monotonic() + max(1.0, self.startup_timeout)
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            request_fd = None
            response_fd = None
            try:
                if self.process is not None and self.process.poll() is not None:
                    raise IdaSessionError(
                        "IDA exited during startup with status %d" % self.process.returncode
                    )
                request_fd = os.open(request_fifo, os.O_WRONLY | os.O_NONBLOCK)
                response_fd = os.open(response_fifo, os.O_RDONLY | os.O_NONBLOCK)
                request_stream = os.fdopen(request_fd, "w", encoding="utf-8")
                request_fd = None
                response_stream = os.fdopen(response_fd, "r", encoding="utf-8")
                response_fd = None
                return request_stream, response_stream
            except Exception as exc:
                last_error = exc
                if request_fd is not None:
                    os.close(request_fd)
                if response_fd is not None:
                    os.close(response_fd)
                if isinstance(exc, IdaSessionError):
                    raise
                time.sleep(0.1)
        raise IdaSessionError("Timed out opening IDA session FIFOs: %s" % last_error)

    def request(
        self,
        method: str,
        params: Mapping[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            if not self.running or self._request_stream is None or self._response_stream is None:
                raise IdaSessionError("IDA session is not running")
            self._request_id += 1
            request_id = self._request_id
            deadline = time.monotonic() + (self.request_timeout if timeout is None else float(timeout))
            try:
                frame = (json.dumps(
                    {"id": request_id, "method": method, "params": dict(params or {})},
                    separators=(",", ":"),
                ) + "\n").encode("utf-8")
                response = self._exchange_frame(frame, deadline)
                if response.get("id") != request_id:
                    raise IdaSessionError("IDA session response identity mismatch")
            except TimeoutError as exc:
                self.close(force=True)
                raise IdaSessionError("IDA session request timed out: %s" % method) from exc
            except Exception:
                self.close(force=True)
                raise
            if response.get("error"):
                error = response["error"]
                raise IdaSessionError(
                    "%s: %s" % (error.get("type") or "IDA error", error.get("message"))
                )
            result = response.get("result")
            if not isinstance(result, dict):
                raise IdaSessionError("IDA session returned a non-object result")
            return result

    def _exchange_frame(self, frame: bytes, deadline: float) -> dict[str, Any]:
        """One deadline covers backpressure, partial reads, and full framing."""
        if len(frame) > self.MAX_FRAME_BYTES:
            raise IdaSessionError("IDA request exceeds the transport frame limit")
        write_fd = self._request_stream.fileno()
        read_fd = self._response_stream.fileno()
        os.set_blocking(write_fd, False)
        os.set_blocking(read_fd, False)
        offset = 0
        response = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Incomplete IDA exchange")
            reading = offset == len(frame)
            ready_r, ready_w, _ = select.select(
                [read_fd] if reading else [], [] if reading else [write_fd], [], remaining,
            )
            if not ready_r and not ready_w:
                raise TimeoutError("Incomplete IDA exchange")
            try:
                if not reading:
                    offset += os.write(write_fd, frame[offset:offset + 65536])
                    continue
                block = os.read(read_fd, 65536)
            except BlockingIOError:
                continue
            if not block:
                raise IdaSessionError("IDA session closed during response")
            response.extend(block)
            if len(response) > self.MAX_FRAME_BYTES:
                raise IdaSessionError("IDA response exceeds the transport frame limit")
            if b"\n" in block:
                if not response.endswith(b"\n") or response.count(b"\n") != 1:
                    raise IdaSessionError("IDA session returned invalid response framing")
                result = json.loads(response)
                if time.monotonic() >= deadline:
                    raise TimeoutError("Response completed after deadline")
                if not isinstance(result, dict):
                    raise IdaSessionError("IDA session returned a non-object response")
                return result

    def query(self, task: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("query", {"task": dict(task)})

    def apply(
        self,
        operation: Mapping[str, Any],
        artifact: Mapping[str, Any],
        *,
        replace_existing_named_types: bool = False,
    ) -> dict[str, Any]:
        return self.request(
            "apply",
            {
                "operation": dict(operation),
                "artifact": dict(artifact),
                "replace_existing_named_types": replace_existing_named_types,
            },
        )

    def read_operation(self, operation: Mapping[str, Any]) -> dict[str, Any]:
        return self.request("read_operation", {"operation": dict(operation)})

    def save(self) -> dict[str, Any]:
        return self.request("save")

    def semantic_export(
        self,
        *,
        selected_local_functions: list[str] | None = None,
        selected_global_addresses: list[str] | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "semantic_export",
            {
                "selected_local_functions": list(selected_local_functions or []),
                "selected_global_addresses": list(selected_global_addresses or []),
            },
        )

    def close(self, *, force: bool = False, save: bool = True) -> None:
        with self._lock:
            discard = bool(force or not save)
            if self.running and not discard:
                try:
                    self.request("close", timeout=30.0)
                except Exception:
                    discard = True
            if self.process is not None:
                # Do not let IDA perform normal-exit cleanup for a discarded
                # workbench: that cleanup can flush Hex-Rays refinements into
                # the unpacked companion files.  Kill first, then remove only
                # those known working files so the packed IDB remains canonical.
                self._stop_process_group(discard=discard)
            for stream in (self._request_stream, self._response_stream):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
            self._request_stream = None
            self._response_stream = None
            if self.process is not None and self.process.poll() is None:
                self.process.terminate()
                try:
                    self.process.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=5.0)
            self.process = None
            if discard and not self.disposable_copy:
                remove_ida_database_companions(self.idb_path)
            if self._temp_root is not None:
                shutil.rmtree(self._temp_root, ignore_errors=True)
            self._temp_root = None

    def _stop_process_group(self, *, discard: bool) -> None:
        """Reap our launcher and stop every owned worker before file cleanup."""
        process = self.process
        if process is None:
            return
        group = process.pid
        if group == os.getpgrp():
            raise IdaSessionError("Refusing to signal the controller process group")
        try:
            if process.poll() is None and os.getpgid(group) != group:
                raise IdaSessionError("Worker was not launched in its own process group")
        except ProcessLookupError:
            pass  # The launcher can exit between poll() and getpgid().
        try:
            os.killpg(group, signal.SIGKILL if discard else signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            os.killpg(group, signal.SIGKILL)
            process.wait(timeout=5.0)
        deadline = time.monotonic() + 5.0
        while True:
            # A killed grandchild may await reaping by init. Zombies cannot
            # touch files; any still-executing group member prevents cleanup.
            rows = subprocess.check_output(
                ["ps", "-axo", "pgid=,stat="], text=True, timeout=5,
            ).splitlines()
            alive = any(
                fields[0] == str(group) and not fields[1].startswith(("Z", "X"))
                for row in rows if len(fields := row.split()) >= 2
            )
            if not alive:
                return
            if time.monotonic() >= deadline:
                raise IdaSessionError("Worker group did not terminate; recovery files retained")
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                pass
            time.sleep(0.05)

    def __enter__(self) -> "PersistentIdaSession":
        return self.start()

    def __exit__(self, *_exc: Any) -> None:
        self.close()
