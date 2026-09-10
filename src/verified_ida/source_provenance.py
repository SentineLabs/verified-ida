"""Describe the exact Verified IDA source used for a run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any
from urllib.parse import urlsplit, urlunsplit


SCHEMA = "verified_ida.source_provenance.v1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_remote(value: str | None) -> str | None:
    """Remove URL credentials while retaining repository identity."""

    remote = str(value or "").strip()
    if not remote:
        return None
    parsed = urlsplit(remote)
    if parsed.scheme and parsed.hostname:
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        if parsed.port:
            host = "%s:%d" % (host, parsed.port)
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    return remote


def _git(root: Path, *arguments: str) -> str | None:
    try:
        result = subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def describe_source(
    *,
    root: Path | None = None,
    ida_backend: str = "process",
) -> dict[str, Any]:
    """Return auditable source and backend identity for a run.

    Build provenance is historical. Current bytes and a repository rooted at
    this checkout are reported independently; ambient parent Git is ignored.
    """

    source_root = (root or Path(__file__).resolve().parents[2]).resolve()
    base: dict[str, Any] = {
        "schema": SCHEMA,
        "source_root": str(source_root),
        "ida_backend": str(ida_backend),
    }

    manifest_path = source_root / "BUNDLE_MANIFEST.json"
    bundle: dict[str, Any] = {}
    if manifest_path.is_file():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        provenance = dict(manifest.get("source_provenance") or {})
        provenance["git_remote"] = _safe_remote(provenance.get("git_remote"))
        bundle = {
            "build_provenance": provenance,
            "bundle_manifest": str(manifest_path),
            "bundle_manifest_sha256": _sha256(manifest_path),
            "bundle_version": manifest.get("version"),
            "bundle_file_count": manifest.get("file_count"),
        }
        rows = manifest.get("files") or []
        observed = []
        modified, missing = [], []
        for row in rows:
            relative = Path(row["path"])
            path = source_root / relative
            if (
                relative.is_absolute() or ".." in relative.parts
                or not path.resolve().is_relative_to(source_root)
                or any(source_root.joinpath(*relative.parts[:i]).is_symlink()
                       for i in range(1, len(relative.parts) + 1))
            ):
                raise ValueError("Unsafe source manifest path: %s" % relative)
            if path.is_file():
                digest = _sha256(path)
                if digest != row["sha256"]:
                    modified.append(str(relative))
            else:
                digest = None
                missing.append(str(relative))
            observed.append({"path": str(relative), "sha256": digest})
        listed = {row["path"] for row in observed}
        additional = []
        for name in ("constraints.txt", "pyproject.toml", "README.md", ".gitignore", ".env.example", "config.sh"):
            path = source_root / name
            if name not in listed and path.is_file():
                if path.is_symlink():
                    raise ValueError("Source tree contains a symlink: %s" % path)
                additional.append(name)
                observed.append({"path": name, "sha256": _sha256(path)})
        for tree in ("src", "scripts", "prompts", "schemas", "tests", "docs", "codex_skills", ".github"):
            if (source_root / tree).is_symlink():
                raise ValueError("Source tree contains a symlink: %s" % tree)
            for path in sorted((source_root / tree).rglob("*")):
                if any(part in {"__pycache__", ".pytest_cache"} or part.endswith(".egg-info") for part in path.parts):
                    continue
                if path.is_symlink():
                    raise ValueError("Source tree contains a symlink: %s" % path)
                relative = path.relative_to(source_root).as_posix()
                if path.is_file() and relative not in listed:
                    additional.append(relative)
                    observed.append({"path": relative, "sha256": _sha256(path)})
        integrity = bool(rows) and not (modified or missing or additional) and len(rows) == manifest.get("file_count")
        bundle["bundle_integrity"] = {
            "matches": integrity, "modified": modified, "missing": missing,
            "additional": additional, "manifest_has_inventory": bool(rows),
        }
        bundle["current_source_sha256"] = hashlib.sha256(
            json.dumps(sorted(observed, key=lambda row: row["path"]), sort_keys=True).encode()
        ).hexdigest()

    git_root = _git(source_root, "rev-parse", "--show-toplevel")
    commit = (
        _git(source_root, "rev-parse", "--verify", "HEAD")
        if git_root and Path(git_root).resolve() == source_root else None
    )
    if commit:
        status = _git(
            source_root,
            "status",
            "--porcelain=v1",
            "--untracked-files=normal",
        )
        return {
            **base,
            **bundle,
            "kind": "git_worktree",
            "git_commit": commit,
            "git_remote": _safe_remote(
                _git(source_root, "remote", "get-url", "origin")
            ),
            "worktree_dirty": None if status is None else bool(status),
        }

    if bundle:
        return {
            **base, **bundle, "kind": "source_bundle",
            "git_commit": provenance.get("git_commit"),
            "git_remote": provenance.get("git_remote"),
            "worktree_dirty": (
                bool(provenance.get("worktree_dirty")) or not integrity
                if rows else None
            ),
        }

    release_marker = source_root / "RELEASE_COMMIT"
    if release_marker.is_file():
        return {
            **base,
            "kind": "release_tree",
            "git_commit": release_marker.read_text(encoding="utf-8").strip() or None,
            "git_remote": None,
            "worktree_dirty": None,
        }

    return {
        **base,
        "kind": "unversioned_source_tree",
        "git_commit": None,
        "git_remote": None,
        "worktree_dirty": None,
    }
