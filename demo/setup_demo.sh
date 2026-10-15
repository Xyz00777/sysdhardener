#!/usr/bin/env bash
# ==============================================================================
# demo/setup_demo.sh
# Automated Installation, Dynamic Configuration & Database Seeding Script
# Designed for Ubuntu 26.04 / Debian / Linux without hardcoded users or paths.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CURRENT_USER="$(id -u -n)"
DATA_DIR="$SCRIPT_DIR/data"
LOGS_DIR="$SCRIPT_DIR/logs"

echo "=================================================================="
echo "  sysdhardener Demo Setup: Installation & Database Seeding"
echo "  Target User: $CURRENT_USER | Repo Root: $REPO_DIR"
echo "=================================================================="

# ------------------------------------------------------------------------------
# 1. Check and Install Required Packages
# ------------------------------------------------------------------------------
echo ""
echo "[Step 1/4] Checking and installing required packages..."

# apt may automatically start the distro Redis service during installation.
# Remember whether Redis was already installed so setup does not interfere with
# an existing administrator-managed service.
REDIS_PREINSTALLED=0
if command -v redis-server >/dev/null 2>&1; then
    REDIS_PREINSTALLED=1
fi

install_packages() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "Detected Debian/Ubuntu package manager (apt-get)."
        echo "Installing redis-server, redis-tools, python3, and curl..."
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update -qq
            apt-get install -y -qq redis-server redis-tools python3 curl
        elif command -v sudo >/dev/null 2>&1; then
            sudo apt-get update -qq
            sudo apt-get install -y -qq redis-server redis-tools python3 curl
        else
            echo "Warning: apt-get found but no sudo or root privileges available."
        fi
    elif command -v pacman >/dev/null 2>&1; then
        echo "Detected Arch Linux package manager (pacman)."
        sudo pacman -Sy --noconfirm redis python curl || true
    elif command -v dnf >/dev/null 2>&1; then
        echo "Detected Fedora/RHEL package manager (dnf)."
        sudo dnf install -y redis python3 curl || true
    elif command -v nix-env >/dev/null 2>&1 || command -v nix >/dev/null 2>&1; then
        echo "Detected Nix environment."
        if ! command -v redis-server >/dev/null 2>&1; then
            echo "Installing redis via nix profile..."
            nix profile install nixpkgs#redis || true
        fi
    fi
}

install_packages

REDIS_SERVER_BIN="$(command -v redis-server || echo "/usr/bin/redis-server")"
REDIS_CLI_BIN="$(command -v redis-cli || echo "/usr/bin/redis-cli")"
PYTHON_BIN="$(command -v python3 || echo "/usr/bin/python3")"
CURL_BIN="$(command -v curl || echo "/usr/bin/curl")"

if [ "$REDIS_PREINSTALLED" -eq 0 ] && command -v systemctl >/dev/null 2>&1; then
    if [ "$(id -u)" -eq 0 ]; then
        systemctl disable --now redis-server.service >/dev/null 2>&1 || true
    elif command -v sudo >/dev/null 2>&1; then
        sudo systemctl disable --now redis-server.service >/dev/null 2>&1 || true
    fi
fi

echo "  -> Python Binary:       $PYTHON_BIN ($($PYTHON_BIN --version 2>&1))"
echo "  -> Redis Server Binary: $REDIS_SERVER_BIN"
if [ -x "$REDIS_SERVER_BIN" ]; then
    echo "     Version: $($REDIS_SERVER_BIN --version 2>&1 | head -n1)"
fi
echo "  -> Redis CLI Binary:    $REDIS_CLI_BIN"

# ------------------------------------------------------------------------------
# 2. Dynamic Configuration (Zero Hardcoded Paths or Users)
# ------------------------------------------------------------------------------
echo ""
echo "[Step 2/4] Generating dynamic configuration and service files..."

mkdir -p "$DATA_DIR" "$LOGS_DIR"

# A. Generate dynamic redis.conf with absolute storage path
cat > "$SCRIPT_DIR/redis.conf" <<EOF
# demo/redis.conf
# Official Redis Server Configuration for sysdhardener Sandbox Testing
# Dynamically generated for user: $CURRENT_USER

port 6379
bind 127.0.0.1
protected-mode no
daemonize no

# The demo intentionally exercises runtime CONFIG SET dir/dbfilename writes.
# Keep Redis bound to localhost and use this only in the isolated demo.
enable-protected-configs yes

# Dedicated directory where Redis writes snapshots (dump.rdb)
dir $DATA_DIR
dbfilename dump.rdb

# Snapshot schedule
save 60 1

# Logging
loglevel notice
logfile ""
EOF
echo "  -> Updated $SCRIPT_DIR/redis.conf (storage path: $DATA_DIR)"

# B. Generate dynamic demo-database.service
cat > "$SCRIPT_DIR/demo-database.service" <<EOF
[Unit]
Description=Official Redis Database Server (sysdhardener demo)
After=network.target

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$REPO_DIR
ExecStart=$REDIS_SERVER_BIN $SCRIPT_DIR/redis.conf
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
echo "  -> Updated $SCRIPT_DIR/demo-database.service (User: $CURRENT_USER)"

# C. Generate dynamic demo-web.service
cat > "$SCRIPT_DIR/demo-web.service" <<EOF
[Unit]
Description=Demo Web Frontend Portal (sysdhardener demo)
After=network.target demo-database.service

[Service]
Type=simple
User=$CURRENT_USER
WorkingDirectory=$REPO_DIR
ExecStart=$PYTHON_BIN $SCRIPT_DIR/web_frontend.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
echo "  -> Updated $SCRIPT_DIR/demo-web.service (User: $CURRENT_USER)"

# ------------------------------------------------------------------------------
# 3. Deploy Test Database & Seed Rich Demo Data
# ------------------------------------------------------------------------------
echo ""
echo "[Step 3/4] Starting temporary Redis instance to seed sample data..."

# Reuse Redis only when it is already configured for this demo. Never seed an
# unrelated Redis instance that happens to be listening on port 6379.
STARTED_TEMP_REDIS=0
REDIS_RUNNING=0
if $PYTHON_BIN -c "import socket; s = socket.socket(); s.settimeout(1); s.connect(('127.0.0.1', 6379)); s.close()" 2>/dev/null; then
    REDIS_RUNNING=1
fi

if [ "$REDIS_RUNNING" -eq 1 ]; then
    CURRENT_REDIS_DIR="$($REDIS_CLI_BIN -h 127.0.0.1 -p 6379 CONFIG GET dir 2>/dev/null | awk 'NR == 2 { print; exit }')"
    if [ "$CURRENT_REDIS_DIR" != "$DATA_DIR" ]; then
        echo "Error: Redis on 127.0.0.1:6379 is not configured for $DATA_DIR." >&2
        echo "Stop that Redis instance or configure the demo to use another port." >&2
        exit 1
    fi
else
    # Remove any pre-existing or incompatible RDB snapshot before seeding fresh data
    rm -f "$DATA_DIR/dump.rdb"
    "$REDIS_SERVER_BIN" "$SCRIPT_DIR/redis.conf" --daemonize yes
    STARTED_TEMP_REDIS=1
    for i in $(seq 1 10); do
        if $PYTHON_BIN -c "import socket; s = socket.socket(); s.settimeout(0.5); s.connect(('127.0.0.1', 6379)); s.close()" 2>/dev/null; then
            break
        fi
        sleep 0.5
    done
fi

echo "  Seeding university security module database records into Redis..."
$PYTHON_BIN - <<'PYEOF'
import socket
import sys

def send_cmd(s, cmd_parts):
    # Encode into RESP Array
    msg = [f"*{len(cmd_parts)}\r\n".encode()]
    for p in cmd_parts:
        bp = str(p).encode('utf-8')
        msg.append(f"${len(bp)}\r\n".encode())
        msg.append(bp + b"\r\n")
    s.sendall(b"".join(msg))
    # Read response
    first = s.recv(1)
    if not first:
        return ""
    if first in (b"+", b"-", b":"):
        buf = bytearray()
        while not buf.endswith(b"\r\n"):
            buf.extend(s.recv(1))
        return buf[:-2].decode()
    elif first == b"$":
        buf = bytearray()
        while not buf.endswith(b"\r\n"):
            buf.extend(s.recv(1))
        length = int(buf[:-2])
        if length == -1:
            return None
        data = s.recv(length)
        s.recv(2) # \r\n
        return data.decode(errors="replace")
    elif first == b"*":
        buf = bytearray()
        while not buf.endswith(b"\r\n"):
            buf.extend(s.recv(1))
        count = int(buf[:-2])
        items = []
        for _ in range(count):
            items.append(send_cmd(s, []))
        return items
    return ""

try:
    s = socket.socket()
    s.settimeout(3.0)
    s.connect(('127.0.0.1', 6379))

    # Clean existing test keys
    send_cmd(s, ["FLUSHDB"])

    # 1. System Metadata & Security Status
    send_cmd(s, ["SET", "system:portal_title", "University Security Lab - Student & Portal Database"])
    send_cmd(s, ["SET", "system:status", "Operational"])
    send_cmd(s, ["SET", "system:sandbox_mode", "Unhardened (Profiling Candidate)"])
    send_cmd(s, ["SET", "system:last_audit", "2026-10-10 03:00 UTC"])

    # 2. Student & Staff Records
    users = [
        ("user:101", "Alice Neumann", "student", "alice@cs.uni.edu", "Computer Science", "CS401,SEC502"),
        ("user:102", "Bob Schmidt", "student", "bob@cs.uni.edu", "Cybersecurity", "CS401"),
        ("user:103", "Clara Fischer", "student", "clara@cs.uni.edu", "Software Engineering", "SEC502"),
        ("user:104", "Prof. Dr. Weber", "faculty", "weber@cs.uni.edu", "Security Dept", "CS401,SEC502"),
        ("user:105", "SysAdmin Operator", "admin", "admin@cs.uni.edu", "IT Infrastructure", "ALL")
    ]
    for uid, name, role, email, dept, courses in users:
        send_cmd(s, ["HSET", uid, "name", name, "role", role, "email", email, "dept", dept, "courses", courses])
        send_cmd(s, ["SADD", "users:all", uid])

    # 3. Courses / Modules
    courses = [
        ("course:CS401", "CS401", "Operating Systems & Sandboxing", "Prof. Dr. Weber", "Lab 0.14", "Fall 2026", "48"),
        ("course:SEC502", "SEC502", "Linux Kernel & eBPF Security", "Prof. Dr. Weber", "Lab 1.02", "Fall 2026", "24"),
        ("course:NET301", "NET301", "Network Protocols & Traffic Analysis", "Dr. Hoffmann", "Audimax B", "Fall 2026", "75")
    ]
    for cid, code, title, instr, room, term, count in courses:
        send_cmd(s, ["HSET", cid, "code", code, "title", title, "instructor", instr, "room", room, "term", term, "enrolled", count])
        send_cmd(s, ["SADD", "courses:all", cid])

    # 4. Active Authentication Sessions
    sessions = [
        ("session:tok_adm_77a9", "105", "SysAdmin Operator", "127.0.0.1", "2026-10-10 03:15:00"),
        ("session:tok_usr_31b4", "101", "Alice Neumann", "192.168.1.42", "2026-10-10 02:45:00"),
        ("session:tok_fac_99c1", "104", "Prof. Dr. Weber", "10.0.2.15", "2026-10-10 01:20:00")
    ]
    for tok, uid, name, ip, time in sessions:
        send_cmd(s, ["HSET", tok, "uid", uid, "username", name, "ip", ip, "login_time", time])
        send_cmd(s, ["SADD", "sessions:all", tok])

    # 5. Flush and write snapshot to disk
    res = send_cmd(s, ["SAVE"])
    print(f"  -> Data snapshot saved: {res}")
    s.close()
except Exception as e:
    print(f"Error seeding database: {e}", file=sys.stderr)
    sys.exit(1)
PYEOF

# If we started a temporary daemon, stop it now so the snapshot is on disk
if [ "$STARTED_TEMP_REDIS" -eq 1 ]; then
    echo "  Shutting down temporary Redis instance..."
    "$REDIS_CLI_BIN" shutdown >/dev/null 2>&1 || true
    sleep 1
fi

# ------------------------------------------------------------------------------
# 4. Verification & Summary
# ------------------------------------------------------------------------------
echo ""
echo "[Step 4/4] Verifying generated data and snapshot..."
if [ -f "$DATA_DIR/dump.rdb" ]; then
    echo "  [SUCCESS] Database snapshot created at: $DATA_DIR/dump.rdb ($(stat -c%s "$DATA_DIR/dump.rdb" 2>/dev/null || stat -f%z "$DATA_DIR/dump.rdb") bytes)"
else
    echo "  [WARNING] $DATA_DIR/dump.rdb not found yet. It will be generated on first SAVE."
fi

echo ""
echo "=================================================================="
echo "  Setup Complete! Ready for Profiling and Web Frontend."
echo "=================================================================="
echo ""
echo "To run the demo now:"
echo "  1. Start Redis in Terminal 1:"
echo "     $REDIS_SERVER_BIN $SCRIPT_DIR/redis.conf"
echo ""
echo "  2. Start Web Frontend in Terminal 2:"
echo "     $PYTHON_BIN $SCRIPT_DIR/web_frontend.py"
echo ""
echo "  3. Open your browser at: http://127.0.0.1:8080"
echo "=================================================================="
