# sysdhardener

**Usable Systemcall-Driven Hardening for systemd Services**

`sysdhardener` is a profiling CLI that observes the syscall behavior of Linux applications and automatically derives tailored systemd security directives—such as `RestrictAddressFamilies=`, `CapabilityBoundingSet=`, and filesystem isolation settings (`ProtectSystem=`, `ProtectHome=`, `ReadWritePaths=`).

It acts as a **recommendation engine only**: it derives candidate configurations from observed evidence; it **never applies** changes to host units or system configurations.

---

## Overview & Workflow

```
+------------------+         +------------------+         +-------------------+
|  Target Process  |  ===>   |   sysdhardener   |  ===>   | Output Artifacts  |
| (exec / daemon)  | ptrace  |  Version Gate &  |         | - hardening.conf  |
|                  |         |  Analysis Engine |         | - findings.txt    |
+------------------+         +------------------+         | - report.json     |
                                                          +-------------------+
```

1. **Observe:** The target service runs under `sysdhardener observe` (spawn) or `sysdhardener attach` (attach to existing PID). The tool watches address families (`AF_INET`, `AF_UNIX`, etc.), capability usage, and file path accesses across all child threads and forks.
2. **Analyze & Gate:** The engine aggregates event evidence, queries `systemd --version` on the host, and suppresses directives unsupported by the active systemd version.
3. **Generate:** Outputs drop-in configuration fragments and detailed human-readable audit findings without modifying any system state.

---

## Key Capabilities

- **Live Process Tracing (`observe`):** Spawns your application under a `ptrace` observer, tracking all forks, threads, and child processes to capture network socket creation, Linux capabilities, and filesystem write paths.
- **Process Attachment (`attach`):** Attaches non-invasively via `PTRACE_SEIZE` to an already-running service daemon (or via eBPF cgroup hooks with `--features bpf-observe`).
- **Dynamic Host Version Gating:** Probes the target host's `systemd` version at runtime to omit directives unsupported by your system (for example, `RestrictAddressFamilies=` is available since v211).
- **Two-View Output Sinks:** Emits a provisional drop-in candidate (`hardening.conf`) and a transparent human-readable audit log (`findings.txt`) for review and validation.
- **Structured Uncertainty & Provenance:** Outputs an optional machine-readable JSON report (`report.json`) detailing basis evidence, observation gaps, and unverified edge cases.
- **Deterministic Fixture Replay (`analyze-fixture`):** Allows analyzing pre-captured trace envelopes for reproducible testing and CI pipelines.

---

## Quick Start & Usage

### 1. Observe a Real Service or Command

Profile an executable and its entire child process tree:

```sh
sysdhardener observe --output-dir ./hardening-out -- /usr/bin/<service-binary> <options-of-the-service>
```

- When you stop the service (via `SIGINT` / Ctrl+C, or `SIGTERM` from `systemctl stop`), `sysdhardener` forwards the signal for clean service shutdown, finalizes analysis, and writes the recommendation artifacts.
- Pass `--show-pids` to include per-process (PID) attribution in the detailed findings report.

### 2. Attach to a Running Process

Attach to an existing process PID via `ptrace`:

```sh
sysdhardener attach --output-dir ./hardening-out <process-id>
```

### 3. Analyze a Recorded Fixture Envelope

Analyze deterministic, pre-captured JSON fixtures (useful for CI and regression testing):

```sh
sysdhardener analyze-fixture --output-dir ./hardening-out crates/sysdhardener-core/tests/fixtures/happy.json
```

---

## Output Artifacts

Running `sysdhardener` produces separate, purpose-built files in `--output-dir`:

### 1. `hardening.conf` (Concise systemd Drop-In)
A configuration fragment ready for inspection and placement under `/etc/systemd/system/<unit>.service.d/`:
```ini
# WARNING: settings below are provisional and unverified; validate before use.
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=~CAP_SYS_ADMIN ~CAP_NET_ADMIN
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ReadWritePaths=/var/log/my-service /var/lib/my-service
```
*(This illustrative fragment assumes no observed home-path access; home accesses change the `ProtectHome=` candidate as described below. Systemd drop-in override files like `override.conf` require these directives under a `[Service]` section header.)*

### 2. `findings.txt` (Detailed Audit Report)
A human-readable record listing every proposed directive alongside observed syscall counts, risk levels, and justifications:
- Identifies whether capabilities were actively exercised or absent.
- Explains filesystem path clustering used to form `ReadWritePaths=`.
- Notes host compatibility support based on the active systemd version.

### 3. `report.json` (Optional Machine Envelope)
When `--json <PATH>` is specified, writes the versioned report envelope (see [`docs/schemas.md`](docs/schemas.md)) containing full provenance, timestamps, uncertainty classifications, and known observation gaps.

---

## Scope & Technical Limitations

Understanding what `sysdhardener` is-and is not-capable of is essential for proper evaluation and use:

### Capabilities (In Scope)
- **Derived Directives:** Derives `RestrictAddressFamilies=`, `CapabilityBoundingSet=`, `AmbientCapabilities=`, `ProtectSystem=`, `ProtectHome=`, `ProtectControlGroups=`, and prefix-clustered `ReadWritePaths=`.
- **Dynamic Host Version Gating:** Queries active `systemd --version` to omit unsupported directives on older hosts.
- **Dual Transparency:** Emits both concise drop-in candidates (`hardening.conf`) and evidence audit records (`findings.txt`), plus optional machine envelopes (`report.json`).

### Boundaries & Limitations (Out of Scope)
- **Recommendation Engine Only:** The tool **never applies** hardening directly to running services or unit files. All settings are provisional and unverified candidates that require validation in staging before use.
- **Dynamic Profiling Window:** Observation is strictly dynamic. Syscalls and file paths not exercised during profiling (e.g. error handlers, log rotations, failover routines, periodic maintenance) will not generate events. Absence of evidence is *provisional*, never mathematical proof of non-use.
- **Drop-In Section Header (`[Service]`):** Emitted `hardening.conf` contains raw key=value directives. Systemd drop-in override files (`override.conf`) require the `[Service]` header to be parsed (e.g. `{ echo "[Service]"; cat hardening.conf; } | sudo tee .../override.conf`).
- **Unmodeled Directives:** Does **not** derive `SystemCallFilter=` (seccomp allow/block lists are deferred research), `MemoryDenyWriteExecute=`, `ProtectKernelTunables=`, `ProtectKernelModules=`, `PrivateTmp=`, `PrivateDevices=`, `ProtectClock=`, `RestrictNamespaces=`, or MAC/LSM policies (SELinux/AppArmor).
- **Filesystem Context & Path Placement:** With observed accepted accesses under `/home`, `/root`, or `/run/user`, the candidate is `ProtectHome=read-only` from systemd v214, not `yes`. A candidate write exception is the observed path's parent cluster, not its siblings. On known v214-v230 hosts, a home write has no supported `ReadWritePaths=` exception (available since v231), so `ProtectHome` is omitted rather than blocking that observed write; protection is consequently not provided for that home access. From v231, the read-only candidate is paired with the derived exception when it is safely scoped. In one fresh Ubuntu 26.04/systemd 259.5/Redis 8.0.5 disposable-QEMU run (2026-10-11), `/root/data` writes succeeded and `/root/.ssh` writes failed read-only under a transient unit using the generated candidate. This validates only that case; candidates remain provisional and require validation on the target system.
- **Root Privilege & Visibility:** `sysdhardener` is designed to run as **root** (required for `ptrace` across arbitrary service daemons and eBPF cgroups). Non-root execution is permitted but operates with degraded visibility and warns accordingly.
- **Kernel & Architecture Scope:** Runtime observation derives purely from syscalls. Complex arbitrary mount namespace re-binds and non-syscall LSM audits (e.g. SELinux/AppArmor) are **deferred** research areas.
- **Non-Invasive Execution:** On exit, observers cleanly detach, restoring process execution and signal state without residue.

---

## CLI Exit Codes

The CLI uses distinct, machine-parsable exit codes:

| Code | Meaning | Description |
| :--- | :--- | :--- |
| `0` | Success | Analysis succeeded and all selected output sinks were written. |
| `2` | Usage Error | Invalid CLI arguments (e.g., missing mandatory flags or selecting no sinks). |
| `3` | Invalid Input | Malformed fixture data or unsupported schema version. |
| `4` | Processing Failed | Internal processing failure (e.g. uncreatable output directory). |
| `5` | Partial Sink Failure | One or more file sinks failed to write, but remaining valid outputs were preserved. |

---

## Building and Development

### Download a release

Download the latest Linux x86-64 archive from the [GitHub Releases page](https://github.com/Xyz00777/sysdhardener/releases/latest). Verify it with the accompanying SHA-256 file, then extract and run it:

```sh
sha256sum --check sysdhardener-linux-x86_64.tar.gz.sha256
tar -xzf sysdhardener-linux-x86_64.tar.gz
./sysdhardener --help
```

The archive contains the executable, this README, and the MIT license. The binary is dynamically linked and requires glibc 2.35 or newer; a statically linked musl build is not provided.

### Development Environment (Nix & direnv)

The repository provides a reproducible development environment with Nix flakes:

```sh
direnv allow   # Activates the pinned Nix development shell
```

Both `flake.nix` (pinned by `flake.lock`) and `default.nix` share canonical packages defined in [`nix/dependencies.nix`](nix/dependencies.nix).

### Building with Cargo

You can build and test directly with standard Rust tooling:

```sh
cargo build --release
cargo test
./scripts/ci.sh   # Runs the full 7-gate CI verification suite
```

For coding standards, architectural invariants (including the 250 pure-LOC ceiling), and development guidelines, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

---

## Documentation Index

| Topic | Documentation |
| :--- | :--- |
| **System Architecture** | [`docs/architecture.md`](docs/architecture.md) (arc42 architectural narrative) |
| **C4 Context Diagram** | [`docs/architecture/c4-context.mmd`](docs/architecture/c4-context.mmd) |
| **C4 Container Diagram** | [`docs/architecture/c4-container.mmd`](docs/architecture/c4-container.mmd) |
| **Architectural Decisions** | [`docs/decisions.md`](docs/decisions.md) |
| **Wire & Report Schemas** | [`docs/schemas.md`](docs/schemas.md) |
| **Research Baseline** | [`docs/research.md`](docs/research.md) |
| **Reference Validation** | [`docs/validation.md`](docs/validation.md) |
| **Contribution Guide** | [`CONTRIBUTING.md`](CONTRIBUTING.md) |
