"""Build a reproducible text-only source archive from the explicit inventory."""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def build(output_dir):
    if Path(git("rev-parse", "--show-toplevel")).resolve() != ROOT:
        raise RuntimeError("Build from this project's own Git checkout")
    if git("status", "--porcelain=v1", "--untracked-files=normal"):
        raise RuntimeError("Commit changes before building a release archive")
    version_tree = ast.parse((ROOT / "src/verified_ida/version.py").read_text())
    version = next(ast.literal_eval(n.value) for n in version_tree.body
                   if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "__version__" for t in n.targets))
    bundle_root = "verified-ida-harness-" + version
    inventory = json.loads((ROOT / "scripts/release_files.json").read_text())
    names = inventory["files"]
    if len(names) != len(set(names)):
        raise RuntimeError("Duplicate source inventory path")
    payloads = []
    for name in sorted(names):
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts:
            raise RuntimeError("Unsafe inventory path: " + name)
        if any(p in {"tests", "deprecated", "runs", ".git", ".venv", "__pycache__"} for p in relative.parts):
            raise RuntimeError("Non-release tree in inventory: " + name)
        path = ROOT / relative
        if any(ROOT.joinpath(*relative.parts[:i]).is_symlink() for i in range(1, len(relative.parts) + 1)):
            raise RuntimeError("Symlink in source inventory: " + name)
        if relative.suffix not in {".py", ".md", ".json", ".toml", ".sh", ".sb", ".txt", ".c"} and name not in {".gitignore", ".env.example", "LICENSE"}:
            raise RuntimeError("Unapproved source file: " + name)
        data = path.read_bytes()
        data.decode("utf-8")
        if b"\0" in data:
            raise RuntimeError("Binary data in source inventory: " + name)
        payloads.append((name, data, path.stat().st_mode & 0o777))
    manifest = {
        "schema": "verified_ida.source_bundle_manifest.v1", "version": version,
        "product": "Verified IDA Model Interface and Reference Harness", "bundle_root": bundle_root,
        "source_provenance": {"kind": "git_worktree", "git_commit": git("rev-parse", "HEAD"),
                              "git_remote": None, "worktree_dirty": False},
        "file_count": len(payloads),
        "files": [{"path": name, "sha256": sha(data), "size": len(data)} for name, data, _ in payloads],
    }
    payloads.append(("BUNDLE_MANIFEST.json", (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(), 0o644))
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / (bundle_root + "-source.zip")
    if archive.exists() or archive.with_suffix(".zip.sha256").exists():
        raise FileExistsError("Choose a new output directory; package already exists")
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name, data, mode in payloads:
            info = zipfile.ZipInfo(bundle_root + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, data)
    archive.with_suffix(".zip.sha256").write_text(sha(archive.read_bytes()) + "  " + archive.name + "\n")
    return archive


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist")
    print(build(parser.parse_args().output_dir.resolve()))
