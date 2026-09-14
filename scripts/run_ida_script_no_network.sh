#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HARNESS_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
LOG_PATH=""

usage() {
  cat <<'EOF'
Usage:
  scripts/run_ida_script_no_network.sh [--log ida.log] <input-binary-or-i64> <script.py> [script args...]

Runs an IDAPython script under sandboxed idat with network syscalls denied.
The input is loaded by IDA and is also passed as argv[1] to the script.

Example:
  scripts/run_ida_script_no_network.sh sample.exe scripts/prepare_analysis.py \
    --save-as /path/to/output/sample.i64 \
    --output /path/to/output/preparation.json
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
    --)
      shift
      break
      ;;
    *)
      break
      ;;
  esac
done

if [[ $# -lt 2 ]]; then
  usage >&2
  exit 2
fi

INPUT_PATH="$1"
SCRIPT_PATH="$2"
shift 2

if [[ ! -f "$INPUT_PATH" ]]; then
  echo "input not found: $INPUT_PATH" >&2
  exit 2
fi

if [[ ! -f "$SCRIPT_PATH" ]]; then
  if [[ -f "$HARNESS_DIR/$SCRIPT_PATH" ]]; then
    SCRIPT_PATH="$HARNESS_DIR/$SCRIPT_PATH"
  else
    echo "script not found: $SCRIPT_PATH" >&2
    exit 2
  fi
fi

if [[ -z "$LOG_PATH" ]]; then
  VERIFIED_IDA_LOG_ROOT="${VERIFIED_IDA_RUN_ROOT:-${TMPDIR:-/tmp}/verified-ida-runs}"
  mkdir -p "$VERIFIED_IDA_LOG_ROOT"
  LOG_PATH="$VERIFIED_IDA_LOG_ROOT/ida_script_$(date +%Y%m%d_%H%M%S).log"
fi

mkdir -p "$(dirname -- "$LOG_PATH")"

script_spec=$(printf '%q ' "$SCRIPT_PATH" "$INPUT_PATH" "$@")
script_spec="${script_spec% }"

exec "$SCRIPT_DIR/launch_ida_no_network.sh" --idat -- \
  -A \
  -L"$LOG_PATH" \
  -S"$script_spec" \
  "$INPUT_PATH"
