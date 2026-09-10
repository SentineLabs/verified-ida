#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="${IDA_NO_NETWORK_PROFILE:-$SCRIPT_DIR/ida_no_network.sb}"
IDA_APP="${IDA_APP:-/Applications/IDA Professional 9.3.app}"
IDA_PATH="${IDA_PATH:-}"
IDA_LICENSE_FILE="${IDA_LICENSE_FILE:-$HOME/.idapro/ida.hexlic}"
IDA_ISOLATE_USER_STATE="${IDA_ISOLATE_USER_STATE:-1}"
IDA_USER_STATE_SEED="${IDA_USER_STATE_SEED:-$HOME/.idapro}"
MODE="gui"

usage() {
  cat <<'EOF'
Usage:
  scripts/launch_ida_no_network.sh [--gui|--idat] [--ida-app /path/to/IDA.app] [--ida-path /path/to/ida] [--] [ida args...]

Examples:
  scripts/launch_ida_no_network.sh
  scripts/launch_ida_no_network.sh --idat -- -B -Lida.log sample.exe
  IDA_APP="/Applications/IDA Professional 9.2.app" scripts/launch_ida_no_network.sh
  IDA_PATH="/opt/ida-pro-9.3" scripts/launch_ida_no_network.sh --idat -- -B sample.exe
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gui)
      MODE="gui"
      shift
      ;;
    --idat)
      MODE="idat"
      shift
      ;;
    --ida-app)
      IDA_APP="${2:?missing path after --ida-app}"
      shift 2
      ;;
    --ida-path)
      IDA_PATH="${2:?missing path after --ida-path}"
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

if [[ -n "$IDA_PATH" ]]; then
  if [[ "$MODE" == "idat" ]]; then
    IDA_BIN="$IDA_PATH/idat"
  else
    IDA_BIN="$IDA_PATH/ida"
  fi
elif [[ "$MODE" == "idat" ]]; then
  IDA_BIN="$IDA_APP/Contents/MacOS/idat"
else
  IDA_BIN="$IDA_APP/Contents/MacOS/ida"
fi

if [[ ! -x "$IDA_BIN" ]]; then
  echo "IDA binary not found or not executable: $IDA_BIN" >&2
  exit 2
fi

license_arg=()
has_license_arg=0
for arg in "$@"; do
  case "$arg" in
    -Olicense:*|--license-file)
      has_license_arg=1
      ;;
  esac
done

if [[ "$has_license_arg" -eq 0 && -f "$IDA_LICENSE_FILE" ]]; then
  license_arg=("-Olicense:keyfile=$IDA_LICENSE_FILE")
fi

isolated_user_dir=""
if [[ "$IDA_ISOLATE_USER_STATE" == "1" ]]; then
  isolated_user_dir="$(mktemp -d "${TMPDIR:-/tmp}/ida-harness-user.XXXXXX")"
  export IDAUSR="$isolated_user_dir"
  if [[ -f "$IDA_USER_STATE_SEED/ida.reg" ]]; then
    cp -- "$IDA_USER_STATE_SEED/ida.reg" "$isolated_user_dir/ida.reg"
    export IDA_HARNESS_USER_STATE_SEED="license_acceptance_registry_only"
  else
    export IDA_HARNESS_USER_STATE_SEED="none"
  fi
  export IDA_HARNESS_USER_STATE_POLICY="isolated_ephemeral"
else
  export IDA_HARNESS_USER_STATE_POLICY="inherited"
fi
export IDA_HARNESS_NETWORK_POLICY="blocked"
export IDA_HARNESS_LUMINA_POLICY="disabled"

cleanup() {
  if [[ -n "$isolated_user_dir" && -d "$isolated_user_dir" ]]; then
    rm -rf -- "$isolated_user_dir"
  fi
}
trap cleanup EXIT

case "$(uname -s)" in
  Darwin)
    if [[ ! -f "$PROFILE" ]]; then
      echo "sandbox profile not found: $PROFILE" >&2
      exit 2
    fi
    /usr/bin/sandbox-exec -f "$PROFILE" "$IDA_BIN" "${license_arg[@]}" "$@"
    ;;
  Linux)
    if ! command -v unshare >/dev/null 2>&1; then
      echo "unshare is required for Linux no-network execution" >&2
      exit 2
    fi
    unshare --user --map-root-user --net -- "$IDA_BIN" "${license_arg[@]}" "$@"
    ;;
  *)
    echo "unsupported platform for no-network IDA launcher: $(uname -s)" >&2
    exit 2
    ;;
esac
