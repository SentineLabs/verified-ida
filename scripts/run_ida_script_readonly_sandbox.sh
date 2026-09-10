#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
IDA_PATH="${IDA_PATH:-/opt/ida-pro-9.3}"
IDA_BIN="${IDA_IDAT:-$IDA_PATH/idat}"
IDA_LICENSE_FILE="${IDA_LICENSE_FILE:-$HOME/.idapro/ida.hexlic}"
IDA_REG_FILE="${IDA_REG_FILE:-$HOME/.idapro/ida.reg}"
TIMEOUT_SECONDS="${READONLY_IDA_TIMEOUT_SECONDS:-180}"
LOG_PATH=""

usage() {
  cat <<'EOF'
Usage:
  scripts/run_ida_script_readonly_sandbox.sh [--log ida.log] <snapshot.i64> <validated-wrapper.py>

Runs a validated model-authored read-only IDAPython wrapper. On Linux, IDA is
placed in a bwrap mount/network namespace that exposes only runtime files and
the wrapper's scratch directory. The input must be a disposable snapshot.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --log)
      LOG_PATH="${2:?missing path after --log}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -ne 2 ]]; then
  usage >&2
  exit 2
fi

INPUT_PATH="$(cd -- "$(dirname -- "$1")" && pwd)/$(basename -- "$1")"
WRAPPER_PATH="$(cd -- "$(dirname -- "$2")" && pwd)/$(basename -- "$2")"
SCRATCH_DIR="$(dirname -- "$WRAPPER_PATH")"
if [[ "$(dirname -- "$INPUT_PATH")" != "$SCRATCH_DIR" ]]; then
  echo "snapshot and wrapper must share one scratch directory" >&2
  exit 2
fi
if [[ ! -f "$INPUT_PATH" || ! -f "$WRAPPER_PATH" ]]; then
  echo "snapshot or wrapper missing" >&2
  exit 2
fi
if [[ -z "$LOG_PATH" ]]; then
  LOG_PATH="$SCRATCH_DIR/ida-readonly.log"
fi
if [[ "$(dirname -- "$LOG_PATH")" != "$SCRATCH_DIR" ]]; then
  echo "sandbox log must stay in the scratch directory" >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  exec "$SCRIPT_DIR/run_ida_script_no_network.sh" \
    --log "$LOG_PATH" "$INPUT_PATH" "$WRAPPER_PATH"
fi

if ! command -v bwrap >/dev/null 2>&1; then
  echo "bwrap is required for model-authored read-only IDAPython" >&2
  exit 2
fi
if [[ ! -x "$IDA_BIN" ]]; then
  echo "IDA headless binary not found: $IDA_BIN" >&2
  exit 2
fi

SANDBOX_HOME="$SCRATCH_DIR/home"
mkdir -p "$SANDBOX_HOME/.idapro"
cp "$IDA_LICENSE_FILE" "$SANDBOX_HOME/.idapro/ida.hexlic"
chmod 600 "$SANDBOX_HOME/.idapro/ida.hexlic"
if [[ -f "$IDA_REG_FILE" ]]; then
  cp "$IDA_REG_FILE" "$SANDBOX_HOME/.idapro/ida.reg"
  chmod 600 "$SANDBOX_HOME/.idapro/ida.reg"
fi

bind_if_present=()
for path in /lib /lib64 /usr /etc/ld.so.cache /etc/fonts /etc/passwd /etc/group /etc/nsswitch.conf; do
  if [[ -e "$path" ]]; then
    bind_if_present+=(--ro-bind "$path" "$path")
  fi
done

script_spec=$(printf '%q ' "$WRAPPER_PATH" "$INPUT_PATH")
script_spec="${script_spec% }"

exec timeout --signal=TERM --kill-after=15 "$TIMEOUT_SECONDS" bwrap \
  --die-with-parent \
  --new-session \
  --unshare-all \
  --unshare-net \
  --clearenv \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --dir /home \
  --ro-bind "$IDA_PATH" "$IDA_PATH" \
  "${bind_if_present[@]}" \
  --bind "$SCRATCH_DIR" "$SCRATCH_DIR" \
  --setenv HOME "$SANDBOX_HOME" \
  --setenv PATH /usr/bin:/bin \
  --chdir "$SCRATCH_DIR" \
  "$IDA_BIN" \
  "-Olicense:keyfile=$SANDBOX_HOME/.idapro/ida.hexlic" \
  -A \
  "-L$LOG_PATH" \
  "-S$script_spec" \
  "$INPUT_PATH"
