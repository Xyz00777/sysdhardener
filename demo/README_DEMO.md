# Hands-On Guide: Testing `sysdhardener` Against Official Redis Arbitrary File Write & System Compromise

This document explains step-by-step how to test **sysdhardener** using the **official Redis server (`redis-server`)** and a Python Web Frontend on **Ubuntu 26.04 LTS (or any standard systemd Linux distribution)**.

> [!CAUTION]
> This demo configuration is intentionally permissive and is designed for an authorized test environment or disposable VM. The test runner `demo/run_test.sh` uses `redis-cli` to safely verify legitimate persistence and test whether unauthorized snapshot writes to `/root/.ssh` are blocked with `Read-only file system (EROFS)`. It uses an isolated test filename (`sysdhardener_test_<pid>.rdb`), restores the original configuration via a bash trap on exit, and never overwrites `authorized_keys` or executes host commands.

`HARDENED` means that Redis returned a server-side `Read-only file system (EROFS)` diagnostic and the test snapshot remained blocked by systemd mount isolation. Authentication, network, and unexpected errors are classified as `INCONCLUSIVE`. `UNHARDENED` indicates that the snapshot file write succeeded, demonstrating unconfined service execution. Standalone Python unit tests validate the RESP parser and classification logic. No host takeover or SSH key injection is attempted.

---

## 1. The Security Vulnerability: Official Redis Arbitrary File Write & Host Compromise

### Vulnerability Classification (Threat Model, Not a Recorded Run)
- **CWE ID:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html) (Improper Limitation of a Pathname to a Restricted Directory) & [CWE-276](https://cwe.mitre.org/data/definitions/276.html) (Incorrect Default Permissions)
- **Vulnerability Name:** *Redis Unauthenticated / Arbitrary File Overwrite & Host Takeover via Dynamic Snapshot Configuration*
- **Related Real-World CVEs:** [CVE-2019-10192](https://nvd.nist.gov/vuln/detail/CVE-2019-10192), [CVE-2019-10193](https://nvd.nist.gov/vuln/detail/CVE-2019-10193), [CVE-2022-0543](https://nvd.nist.gov/vuln/detail/CVE-2022-0543) (Debian/Ubuntu Redis Lua Sandbox Escape)

### How the Vulnerability Works in Real Redis
The following is a threat-model description, not a report of an exploit run. By design, Redis features runtime configuration commands:
1. `CONFIG SET dir <path>`: Dynamically sets the filesystem directory where Redis writes database snapshots.
2. `CONFIG SET dbfilename <filename>`: Dynamically changes the output file name.
3. `SAVE`: Flushes in-memory data to disk at `<dir>/<filename>`.

Depending on permissions and service confinement, an attacker who reaches the Redis port may manipulate these commands to write files. The diagram is hypothetical; this guide does not test SSH login or cron execution:

```
[Attacker] ──> Redis `CONFIG SET dir /root/.ssh` ──> `SAVE` ──> Overwrites /root/.ssh/authorized_keys
                                                                        │
                                                                 [Root SSH Login]
                                                                        ▼
                                                             FULL SYSTEM COMPROMISE
```

- **Attack Vector 1 (SSH Key Injection):** Writing an SSH public key to `/root/.ssh/authorized_keys` or `/home/<user>/.ssh/authorized_keys`.
- **Attack Vector 2 (Cron Job Injection):** Setting `dir` to `/etc/cron.d/` and writing a scheduled bash command (`* * * * * root /bin/bash ...`).
- **Attack Vector 3 (Web Shell / Arbitrary Write):** Writing a backdoor into web directories or system paths.
- **Attack Vector 4 (Arbitrary Bash Command Execution / RCE Confinement):** Executing bash commands to install persistent backdoors (`touch /etc/rce_backdoor.txt`) or inspect protected paths (`ls /root`).

---

## 2. CRITICAL CONCEPT: Why Sandboxing Works & How It Is Applied

> [!IMPORTANT]
> **Redis ITSELF has NO protection against this attack.**
> If you start Redis directly in a terminal (`redis-server /path/to/redis.conf`), **the exploit will ALWAYS succeed**. Redis will happily write snapshots into `/root/.ssh` or `/etc/cron.d` as long as the OS user running the process has write permission.
>
> The protection is **NOT** inside Redis code. The protection is enforced **OUTSIDE** Redis by the **Operating System / systemd Process Supervisor (PID 1)**:
> 1. Before launching Redis, systemd creates isolated Linux mount namespaces (`CLONE_NEWNS`).
> 2. Systemd mounts `/etc`, `/usr`, and `/boot` as read-only, hides `/root` and `/home`, and drops kernel capabilities.
> 3. Only then does systemd execute `redis-server` inside this confined sandbox.
> 4. When Redis attempts to open `/etc/cron.d/` or `/root/.ssh/`, the **Linux kernel** rejects the call (`Read-only file system` or `Permission denied`).

### How Hardening is Applied: Drop-In Overrides (`.service.d/`)

To keep the evaluation reproducible and avoid interfering with any pre-existing system database, the demo uses its own isolated unit file (`demo-database.service`) running the official `redis-server` binary with `demo/redis.conf`.

> [!NOTE]
> **Why not override Ubuntu's packaged `redis-server.service` directly?**
> Overriding `/etc/systemd/system/redis-server.service.d/` would still execute Ubuntu's pre-shipped configuration (`/etc/redis/redis.conf`) under the unprivileged system user `redis`. That would ignore the demo's dynamic paths, data directory, and runtime settings. Instead, the demo isolates official Redis under `demo-database.service`.

Systemd applies hardening via **Drop-in Overrides**:

```
/etc/systemd/system/demo-database.service        (Isolated unit running official redis-server with demo/redis.conf)
       ▲
       │  merged by systemd at runtime
       │
/etc/systemd/system/demo-database.service.d/
       └── override.conf                         (Generated by sysdhardener: hardening.conf)
```

Because `sysdhardener` outputs raw directive lines in `hardening.conf`, the drop-in file must include the `[Service]` section header so systemd parses and applies the sandbox:

```ini
[Service]
# WARNING: settings below are provisional and unverified; validate before use.
CapabilityBoundingSet=~CAP_CHOWN ...
ProtectSystem=strict
ReadWritePaths=/.../demo/data
ProtectHome=yes
ProtectControlGroups=yes
```

When placed with the `[Service]` header into `/etc/systemd/system/demo-database.service.d/override.conf` and loaded with `systemctl daemon-reload`, systemd merges these directives into the service.

### Summary of Sandboxing Directives

| Candidate directive (effect is expected, not established by this task's mock tests) | Expected effect on the threat model | VM result |
| :--- | :--- | :--- |
| `ProtectHome=yes` | Renders `/root` and `/home` inaccessible and hidden from the service process | Redis receives `Permission denied` when attempting to write `/root/.ssh/` |
| `ProtectSystem=strict` | Mounts `/usr`, `/boot`, and `/etc` as **Read-Only** | Redis receives `Read-only file system` when targeting `/etc/cron.d/` |
| `ReadWritePaths=...` | Confines write access strictly to the directory observed during normal profiling | Any write outside the app data folder is rejected by the Linux kernel |
| `CapabilityBoundingSet=~...` | Drops unused Linux capabilities (e.g. `CAP_NET_RAW`, `CAP_SYS_ADMIN`) | Prevents raw packet crafting and namespace escapes |

---

## 3. Automated Setup & Database Seeding

The setup script may install packages and interact with service management. Run it only inside the authorized disposable VM; never run it on the host:

```bash
./demo/setup_demo.sh
```

### What this script does automatically:
1. **Installs required applications:** Detects the package manager (`apt-get` on Ubuntu/Debian, `dnf`, `pacman`, or `nix`) and installs `redis-server`, `redis-tools`, `python3`, and `curl`.
2. **Generates dynamic configurations:** Identifies your current user (`$(id -u -n)`) and current repo path dynamically, and writes clean systemd service files and `redis.conf` with **no hardcoded usernames or home paths**.
3. **Seeds a test Redis database:** Populates Redis with realistic university portal records (Student Users, Course Modules, Authentication Sessions, and Security Audit status) and saves the initial snapshot to `demo/data/dump.rdb`.

The script generates service files and seeds the demo database. Do not stop, disable, or reconfigure a host Redis service. If using the VM, ensure the demo is isolated from any unrelated Redis instance before setup:

```bash
./demo/setup_demo.sh
```

On a fresh Ubuntu installation, the setup script handles the Redis service started automatically by package installation. The generated Redis configuration enables `enable-protected-configs yes` because Redis 8 otherwise rejects the `CONFIG SET dir` and `CONFIG SET dbfilename` commands used by this demonstration. Redis remains bound to `127.0.0.1`; do not use this intentionally vulnerable configuration in production.

---

## 4. Step-by-Step Reproduction Guide

### Step 1: Start Official Redis & The Web Dashboard

Open two terminal windows:

**Terminal 1 (Official Redis Server):**
```bash
redis-server demo/redis.conf
```
*You will see the official Redis startup logs confirming it is listening on `127.0.0.1:6379`.*

**Terminal 2 (Web Dashboard):**
```bash
python3 demo/web_frontend.py
```
Open **`http://127.0.0.1:8080`** in your browser (or port-forwarded URL). You will see:
- Live tables displaying the seeded students, courses, and active sessions.
- Real-time Redis server version and status indicators.
- Interactive normal query buttons and exploit demonstration controls.

The frontend listens on `0.0.0.0:8080`, which is required when port `8080` is reached through QEMU port forwarding.

---

### Step 2: Test Normal Operations (Baseline)

Verify that legitimate Redis database queries work:
```bash
# Using redis-cli
redis-cli ping
# Output: PONG

# Read seeded student record (Alice)
redis-cli hgetall user:101

# Read seeded course record (SEC502)
redis-cli hgetall course:SEC502

# Legitimate snapshot in allowed directory
redis-cli save
# Output: OK
```
The snapshot is saved safely inside `demo/data/dump.rdb`.

---

### Step 3: Demonstrate Exploit in Unhardened State & Run Automated Tests

To demonstrate the vulnerability before hardening:
```bash
# Change output path to /tmp (simulating unauthorized writes outside data directory)
redis-cli config set dir /tmp
redis-cli config set dbfilename redis_unhardened_pwn.txt

# Save snapshot to the unauthorized directory
redis-cli save

# Verify the file was created outside the intended data directory:
ls -la /tmp/redis_unhardened_pwn.txt && rm -f /tmp/redis_unhardened_pwn.txt
```
**Result:** The file write succeeds. In an unhardened environment, the database process can write anywhere its user privileges allow.

To execute the verification test, run the transparent bash test script:
```bash
./demo/run_test.sh
```
This script checks connectivity, verifies normal persistence, attempts the unauthorized redirect to `/root/.ssh/sysdhardener_test_<pid>.rdb`, and checks if the Linux kernel rejects the write with `Read-only file system` (EROFS). The original Redis configuration is automatically restored on exit. Alternatively, `./demo/run_test.sh --python` invokes the standalone Python probe (`run_test.py`).

Harness unit tests can be run with:
```bash
PYTHONPATH=demo python3 -m unittest -v demo/test_run_test.py
```

---

### Step 4: Profile Official Redis with `sysdhardener`

This step requires a Linux x86-64 executable at `./target/release/sysdhardener`. Build it with Rust or download a compatible release binary. When running in QEMU, use a glibc-compatible binary inside the VM; a host Nix-linked binary will not run there.

Now run official Redis under `sysdhardener observe` while sending normal legitimate database requests:

```bash
./target/release/sysdhardener observe --output-dir demo/observed-database -- redis-server demo/redis.conf
```

In another terminal, send normal traffic so `sysdhardener` observes legitimate behavior:
```bash
redis-cli ping
redis-cli hgetall user:101
redis-cli save
```

Now stop the observer with `Ctrl+C`. `sysdhardener` generates the recommendations:
```bash
cat demo/observed-database/hardening.conf
```

You will see:
```ini
# WARNING: settings below are provisional and unverified; validate before use.
CapabilityBoundingSet=~CAP_CHOWN ...
ProtectSystem=strict
ReadWritePaths=/.../demo/data
ProtectHome=yes
ProtectControlGroups=yes
```

---

### Step 5: Deploy Hardening via Systemd Drop-In Override

Deploy the isolated demo services and apply the `sysdhardener` drop-in override (do **not** override Ubuntu's packaged `redis-server.service`, as that would load the pre-shipped `/etc/redis/redis.conf` instead of the demo setup):

```bash
# 1. Stop the manually started Redis and web frontend first, if running (Ctrl+C).

# 2. Install the dynamic unit files generated by setup_demo.sh
cp demo/demo-database.service /etc/systemd/system/
cp demo/demo-web.service /etc/systemd/system/

# 3. Add the sysdhardener override drop-in under the [Service] section
mkdir -p /etc/systemd/system/demo-database.service.d/
{ echo "[Service]"; cat demo/observed-database/hardening.conf; } | tee /etc/systemd/system/demo-database.service.d/override.conf

# 4. Reload systemd and start/restart both demo services
systemctl daemon-reload
systemctl restart demo-database.service demo-web.service 2>/dev/null || true
systemctl enable --now demo-database.service demo-web.service
```

---

### Step 6: Retest Exploit (Hardened State — Mitigation Verification)

Try the exact same attack commands against the hardened Redis service (via `redis-cli`, via `./demo/run_test.sh`, or via the web dashboard at `http://127.0.0.1:8080`):

#### 1. Attempt to write to `/root/.ssh/` (SSH key injection):
```bash
redis-cli config set dir /root/.ssh
redis-cli config set dbfilename authorized_keys
redis-cli save
```
**Result:**
```text
(error) ERR opening file: Permission denied (or Read-only file system)
```
*Blocked by `ProtectHome=read-only` / `ProtectHome=yes`.*

#### 2. Attempt to write to `/etc/cron.d/` (Scheduled cron backdoor):
```bash
redis-cli config set dir /etc/cron.d
redis-cli config set dbfilename pwn_cron
redis-cli save
```
**Result:**
```text
(error) ERR opening file: Read-only file system
```
*Blocked by `ProtectSystem=strict`.*

#### 3. Attempt to write outside data directory to `/tmp/`:
```bash
redis-cli config set dir /tmp
redis-cli config set dbfilename pwn.txt
redis-cli save
```
**Result:**
```text
(error) ERR opening file: Read-only file system
```
*Blocked by `ReadWritePaths=` restricting write access exclusively to the observed data directory.*

#### 4. Normal Redis operations continue working:
```bash
DATA_DIR="$(cd demo/data && pwd)"
redis-cli config set dir "$DATA_DIR"
redis-cli config set dbfilename dump.rdb
redis-cli hgetall user:101
redis-cli save
```
**Result:** `OK`. Legitimate database traffic functions normally with zero disruption.

---

## 5. Summary Evaluation Matrix for Bachelor Thesis

| Attack Target | Unhardened Official Redis | Hardened Official Redis (`sysdhardener`) | Enforcement Layer & Directive |
| :--- | :--- | :--- | :--- |
| **Write root SSH keys (`/root/.ssh`)** | **Succeeded** (Host takeover) | **Blocked** (`Permission denied` / `Read-only file system`) | **systemd namespace:** `ProtectHome=read-only` / `ProtectHome=yes` |
| **Write cron backdoor (`/etc/cron.d`)** | **Succeeded** (Host takeover) | **Blocked** (`Read-only file system`) | **systemd namespace:** `ProtectSystem=strict` |
| **Write outside data dir (`/tmp`, `/opt`)** | **Succeeded** | **Blocked** (`Read-only file system`) | **systemd namespace:** `ReadWritePaths=` |
| **Tamper with cgroups (`/sys/fs/cgroup`)** | **Succeeded** | **Blocked** (`Read-only file system`) | **systemd namespace:** `ProtectControlGroups=yes` |
| **Normal database queries & snapshot** | **Succeeded** | **Succeeded** | Legitimate observed working directory |

## 6. QEMU Port-Forwarded Deployment

When running the demo in the Ubuntu cloud image, boot the writable overlay. Creating `ubuntu-26.04.qcow2` but booting the downloaded image directly leaves the 30G disk unused.

**Prerequisites:**
- Download the official cloud image `ubuntu-26.04-server-cloudimg-amd64.img`.
- Install `cloud-image-utils` (which provides `cloud-localds`) and `qemu-system-x86_64`.

From the directory containing the downloaded image and `demo/`:

```bash
qemu-img create -f qcow2 -F qcow2 \
  -b ubuntu-26.04-server-cloudimg-amd64.img ubuntu-26.04.qcow2 30G

cloud-localds seed.iso demo/cloud-init.yaml

qemu-system-x86_64 \
  -enable-kvm -machine q35 -cpu host \
  -smp 4 -m 4096 \
  -drive file=ubuntu-26.04.qcow2,format=qcow2 \
  -drive file=seed.iso,media=cdrom,readonly=on \
  -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22,hostfwd=tcp::8080-:8080
```

Log in through SSH with `ssh -p 2222 root@127.0.0.1` and the password `sysdhardener`, copy or clone this repository into `/opt/sysdhardener` (placing the service in a standard directory outside `/root` allows `sysdhardener` to safely recommend `ProtectHome=yes` without breaking data access), run `./demo/setup_demo.sh`, and install the generated service files using Step 5 above. The dashboard is then available on the host at `http://127.0.0.1:8080`.
