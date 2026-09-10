#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <scratch-dir> <trusted-wrapper.py>" >&2
  exit 2
fi

SCRATCH_DIR="$(cd -- "$1" && pwd)"
WRAPPER_PATH="$(cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")"
TIMEOUT_SECONDS="${STATIC_EXTRACTOR_TIMEOUT_SECONDS:-120}"
MEMORY_KB="${STATIC_EXTRACTOR_MEMORY_KB:-1048576}"
PYTHON_BIN="${STATIC_EXTRACTOR_PYTHON:-/usr/bin/python3}"

if [[ "$(dirname -- "$WRAPPER_PATH")" != "$SCRATCH_DIR" || ! -f "$WRAPPER_PATH" ]]; then
  echo "trusted wrapper must be a regular file in the scratch directory" >&2
  exit 2
fi

ulimit -v "$MEMORY_KB" 2>/dev/null || true
ulimit -f 131072 2>/dev/null || true

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "model-authored static extraction requires the Linux bwrap sandbox" >&2
  exit 2
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "bwrap is required for model-authored static extraction on Linux" >&2
  exit 2
fi
if [[ ! -x "$PYTHON_BIN" ]]; then
  echo "static extractor Python not found: $PYTHON_BIN" >&2
  exit 2
fi

bind_if_present=()
for path in /lib /lib64 /usr /etc/ld.so.cache; do
  if [[ -e "$path" ]]; then
    bind_if_present+=(--ro-bind "$path" "$path")
  fi
done

exec timeout --signal=TERM --kill-after=5 "$TIMEOUT_SECONDS" bwrap \
  --die-with-parent \
  --new-session \
  --unshare-all \
  --unshare-net \
  --clearenv \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  "${bind_if_present[@]}" \
  --bind "$SCRATCH_DIR" "$SCRATCH_DIR" \
  --setenv HOME "$SCRATCH_DIR" \
  --setenv PATH /usr/bin:/bin \
  --setenv PYTHONHASHSEED 0 \
  --chdir "$SCRATCH_DIR" \
  "$PYTHON_BIN" -I -B "$WRAPPER_PATH"
