#!/usr/bin/env bash
# demo/run_test.sh
# Transparent and safe verification test for Redis systemd sandboxing.
#
# This script uses standard `redis-cli` commands to demonstrate:
#  1. Normal operational integrity (PING, SET, legitimate SAVE).
#  2. Attack simulation: Unauthorized snapshot redirection to /root/.ssh.
#  3. Evaluation of the kernel/systemd response (EROFS vs OK).
#
# Safety measures:
#  - Uses an isolated test filename (sysdhardener_test.rdb), never overwriting authorized_keys.
#  - Restores original Redis directory and filename on exit via bash trap.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
TEST_TARGET_DIR="/root/.ssh"
TEST_TARGET_FILE="sysdhardener_test_$$.rdb"

# Optional delegation to Python test runner if explicitly requested
if [[ "${1:-}" == "--python" ]]; then
  shift
  exec python3 "$DIR/run_test.py" "$@"
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --host <host>    Redis host (default: 127.0.0.1)"
  echo "  --port <port>    Redis port (default: 6379)"
  echo "  --python         Run the Python automated test runner instead"
  echo "  -h, --help       Show this help message"
  exit 0
fi

# Parse optional arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) REDIS_HOST="$2"; shift 2 ;;
    --port) REDIS_PORT="$2"; shift 2 ;;
    *) echo "Unknown option: $1 (use --help for options)"; exit 1 ;;
  esac
done

# Check for redis-cli
if ! command -v redis-cli &>/dev/null; then
  echo "Notice: 'redis-cli' is not installed in PATH."
  echo "Falling back to the standalone Python probe..."
  exec python3 "$DIR/run_test.py" --disposable-environment --filesystem-probe
fi

echo "=========================================================="
echo "  sysdhardener Demo: Redis Sandboxing Verification"
echo "  Target: $REDIS_HOST:$REDIS_PORT"
echo "=========================================================="

# Check if Redis is reachable
if ! redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping &>/dev/null; then
  echo ""
  echo "[!] Cannot connect to Redis at $REDIS_HOST:$REDIS_PORT."
  echo ""
  echo "To start Redis for testing:"
  echo "  - Unhardened baseline:"
  echo "      redis-server $DIR/redis.conf"
  echo "  - Hardened with systemd:"
  echo "      sudo systemctl start demo-database.service"
  echo ""
  exit 10
fi

# Query current configuration to enable clean restoration
ORIG_DIR=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get dir | sed -n '2p')
ORIG_FILE=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config get dbfilename | sed -n '2p')

# Setup trap to always restore original Redis configuration
cleanup() {
  local exit_code=$?
  if [[ -n "${ORIG_DIR:-}" && -n "${ORIG_FILE:-}" ]]; then
    echo ""
    echo "Restoring original Redis configuration..."
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config set dir "$ORIG_DIR" >/dev/null 2>&1 || true
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config set dbfilename "$ORIG_FILE" >/dev/null 2>&1 || true
    echo "  dir:        $ORIG_DIR"
    echo "  dbfilename: $ORIG_FILE"
  fi
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

echo ""
echo "[1/3] Testing Legitimate Operational Baseline..."
echo "  > redis-cli ping"
PING_RES=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" ping)
echo "    Response: $PING_RES"

echo "  > redis-cli set test_token \"demo_valid\""
SET_RES=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" set test_token "demo_valid")
echo "    Response: $SET_RES"

echo "  > redis-cli save (to current data directory: $ORIG_DIR)"
SAVE_BASELINE=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" save 2>&1 || true)
echo "    Response: $SAVE_BASELINE"

if [[ "$SAVE_BASELINE" != "OK" ]]; then
  echo "  [!] Warning: Baseline save failed in legitimate directory ($SAVE_BASELINE)."
fi

echo ""
echo "[2/3] Simulating Unauthorized Path Redirection..."
echo "  Attempting to change dump path to protected directory: $TEST_TARGET_DIR"
echo "  > redis-cli config set dir $TEST_TARGET_DIR"
CONFIG_DIR_RES=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config set dir "$TEST_TARGET_DIR" 2>&1 || true)
echo "    Response: $CONFIG_DIR_RES"

echo "  > redis-cli config set dbfilename $TEST_TARGET_FILE"
CONFIG_FILE_RES=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" config set dbfilename "$TEST_TARGET_FILE" 2>&1 || true)
echo "    Response: $CONFIG_FILE_RES"

echo ""
echo "[3/3] Triggering Snapshot Write (SAVE)..."
echo "  > redis-cli save"
SAVE_ATTACK_RES=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" save 2>&1 || true)
echo "    Response: $SAVE_ATTACK_RES"

echo ""
echo "=========================================================="
echo "  Evaluation Result:"
echo "=========================================================="

if [[ "$SAVE_ATTACK_RES" =~ "Read-only file system" ]] || [[ "$SAVE_ATTACK_RES" =~ "EROFS" ]] || [[ "$SAVE_ATTACK_RES" =~ "Permission denied" ]]; then
  echo "  [HARDENED] SUCCESS: Snapshot write was blocked by systemd mount isolation!"
  echo "  Kernel rejected file creation with: $SAVE_ATTACK_RES"
  echo "  Enforcement layer: ProtectHome=read-only / ProtectSystem=strict."
  exit 0
elif [[ "$SAVE_ATTACK_RES" == "OK" ]]; then
  echo "  [UNHARDENED] WARNING: Unauthorized write to $TEST_TARGET_DIR succeeded!"
  echo "  The Redis process is running without systemd filesystem sandboxing."
  # Remove test file if created
  rm -f "$TEST_TARGET_DIR/$TEST_TARGET_FILE" 2>/dev/null || true
  exit 1
else
  echo "  [INCONCLUSIVE] Unexpected response during SAVE: $SAVE_ATTACK_RES"
  echo "  Could not verify whether systemd mount sandboxing was the cause."
  exit 20
fi
